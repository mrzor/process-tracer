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

func TestIngestEndpoints(t *testing.T) {
	resolver := New()

	// Simulate eBPF-sourced environment variables and command-line arguments
	envVars := []string{
		"DATABASE_URL=postgresql://user:pass@db.example.com:5432/mydb",
		"REDIS_HOST=cache.internal.net",
		"API_ENDPOINT=https://api.service.local:8080/v1",
		"BACKEND_IP=10.0.0.5",
	}
	args := []string{
		"/usr/bin/curl",
		"http://example.com/api",
		"--host", "192.168.1.100:3000",
	}

	// Ingest all data at once (as would happen from eBPF events)
	envVars = append(envVars, args...)
	resolver.IngestEndpoints(envVars...)

	// Should have extracted hostnames and IPs
	assert.NotEmpty(t, resolver.IPToHosts, "Expected to extract IPs from endpoints")

	// Check that specific IPs were captured
	hosts := resolver.Lookup("10.0.0.5")
	assert.NotNil(t, hosts, "Expected to find IP 10.0.0.5")
	assert.Contains(t, hosts, "10.0.0.5", "Expected IP to map to itself")

	hosts = resolver.Lookup("192.168.1.100")
	assert.NotNil(t, hosts, "Expected to find IP 192.168.1.100")
	assert.Contains(t, hosts, "192.168.1.100", "Expected IP to map to itself")
}

func TestIngestEndpointsWithDNSResolution(t *testing.T) {
	resolver := New()

	// Test with localhost which should resolve to 127.0.0.1
	resolver.IngestEndpoints("REDIS=localhost:6379")

	// Check that localhost was resolved
	hosts := resolver.Lookup("127.0.0.1")
	if hosts != nil {
		assert.Contains(t, hosts, "localhost", "Expected 127.0.0.1 to map to localhost")
	} else {
		t.Log("Note: DNS resolution for localhost failed (may be OK in test environment)")
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
			resolver.processedHosts = make(map[string]bool)

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
			if tt.checkDNS && len(resolver.processedHosts) == 0 {
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
