//nolint:revive,testpackage // Package name uses descriptive underscores, testing internal details
package pseudo_reverse_dns

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvironSource(t *testing.T) {
	// Test with current process (should always work)
	source := &EnvironSource{}
	endpoints, err := source.Extract(os.Getpid())
	require.NoError(t, err)

	// Should have at least some environment variables
	assert.NotEmpty(t, endpoints, "Expected at least some environment variables")

	// Check that we got actual values (not empty strings)
	hasNonEmpty := false
	for _, ep := range endpoints {
		if len(ep) > 0 {
			hasNonEmpty = true
			break
		}
	}
	assert.True(t, hasNonEmpty, "All environment values were empty")
}

func TestCmdlineSource(t *testing.T) {
	// Test with current process
	source := &CmdlineSource{}
	endpoints, err := source.Extract(os.Getpid())
	require.NoError(t, err)

	// Should have at least the program name
	assert.NotEmpty(t, endpoints, "Expected at least the program name in cmdline")

	// First argument should contain test or go (running under go test)
	if len(endpoints) > 0 {
		first := strings.ToLower(endpoints[0])
		if !strings.Contains(first, "test") && !strings.Contains(first, "go") {
			t.Logf("First cmdline arg: %s (expected to contain 'test' or 'go')", first)
		}
	}
}

func TestResolverWithStaticSources(t *testing.T) {
	resolver := New()
	resolver.AddStaticSource(&EnvironSource{})
	resolver.AddStaticSource(&CmdlineSource{})

	// Run on current process
	err := resolver.HandleStaticSources(os.Getpid())
	require.NoError(t, err)

	// We should have extracted something (the environment likely has hostnames/IPs)
	if len(resolver.IPToHosts) == 0 && len(resolver.HostToIPs) == 0 {
		t.Log("Warning: No endpoints extracted (may be OK if env has no hostnames)")
	}
}

func TestExtractEndpoints(t *testing.T) {
	resolver := New()

	tests := []struct {
		name     string
		input    string
		wantIPv4 bool
		wantIPv6 bool
		checkDNS bool // Only check DNS resolution if explicitly requested
	}{
		{
			name:     "IPv4 address",
			input:    "DATABASE_URL=postgresql://user:pass@192.168.1.100:5432/db",
			wantIPv4: true,
		},
		{
			name:     "IPv6 address",
			input:    "SERVER=[2001:db8::1]:8080",
			wantIPv6: true,
		},
		{
			name:     "Plain IPv4",
			input:    "10.0.0.5",
			wantIPv4: true,
		},
		{
			name:     "localhost (should resolve)",
			input:    "REDIS_HOST=localhost:6379",
			checkDNS: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset resolver state
			resolver.IPToHosts = make(map[string]*HostMapping)
			resolver.HostToIPs = make(map[string][]string)

			resolver.extractEndpoints(tt.input)

			hasIPv4 := false
			hasIPv6 := false
			for ip := range resolver.IPToHosts {
				if strings.Contains(ip, ".") && !strings.Contains(ip, ":") {
					hasIPv4 = true
				}
				if strings.Contains(ip, ":") {
					hasIPv6 = true
				}
			}

			if tt.wantIPv4 {
				assert.True(t, hasIPv4, "Expected to extract IPv4. IPToHosts: %v", resolver.IPToHosts)
			}
			if tt.wantIPv6 {
				assert.True(t, hasIPv6, "Expected to extract IPv6. IPToHosts: %v", resolver.IPToHosts)
			}
			if tt.checkDNS && len(resolver.HostToIPs) == 0 {
				t.Logf("Note: DNS resolution failed for hostname (may be OK in test environment)")
			}
		})
	}
}

func TestLookup(t *testing.T) {
	resolver := New()

	// Manually add a mapping
	resolver.addIPMapping("192.168.1.1", "gateway.local")
	resolver.addIPMapping("192.168.1.1", "router")

	// Lookup should return both hostnames
	hosts := resolver.Lookup("192.168.1.1")
	assert.Len(t, hosts, 2, "Expected 2 hostnames: %v", hosts)

	// Lookup non-existent IP should return nil
	hosts = resolver.Lookup("1.2.3.4")
	assert.Nil(t, hosts, "Expected nil for non-existent IP")
}

func TestStaticSourceInterface(t *testing.T) {
	// Verify that our sources implement the interface correctly
	var _ StaticSource = &EnvironSource{}
	var _ StaticSource = &CmdlineSource{}
}

func TestHandleDynamicSource(t *testing.T) {
	resolver := New()

	// Create a mock dynamic source
	mockSource := &mockDynamicSource{
		responses: map[string][]string{
			"file_read": {"http://example.com", "192.168.1.50"},
		},
	}

	resolver.AddDynamicSource(mockSource)

	// Process an event
	resolver.HandleDynamicSource(1234, "file_read", []byte("some data"))

	// Check that endpoints were extracted
	hasData := len(resolver.IPToHosts) > 0 || len(resolver.HostToIPs) > 0
	assert.True(t, hasData, "Expected dynamic source to populate resolver")
}

// mockDynamicSource is a test implementation of DynamicSource.
type mockDynamicSource struct {
	responses map[string][]string
}

func (m *mockDynamicSource) OnEvent(pid int, eventType string, data []byte) []string {
	if endpoints, ok := m.responses[eventType]; ok {
		return endpoints
	}
	return nil
}
