package pseudo_reverse_dns

import (
	"os"
	"strings"
	"testing"
)

func TestEnvironSource(t *testing.T) {
	// Test with current process (should always work)
	source := &EnvironSource{}
	endpoints, err := source.Extract(os.Getpid())
	if err != nil {
		t.Fatalf("EnvironSource.Extract failed: %v", err)
	}

	// Should have at least some environment variables
	if len(endpoints) == 0 {
		t.Error("Expected at least some environment variables, got none")
	}

	// Check that we got actual values (not empty strings)
	hasNonEmpty := false
	for _, ep := range endpoints {
		if len(ep) > 0 {
			hasNonEmpty = true
			break
		}
	}
	if !hasNonEmpty {
		t.Error("All environment values were empty")
	}
}

func TestCmdlineSource(t *testing.T) {
	// Test with current process
	source := &CmdlineSource{}
	endpoints, err := source.Extract(os.Getpid())
	if err != nil {
		t.Fatalf("CmdlineSource.Extract failed: %v", err)
	}

	// Should have at least the program name
	if len(endpoints) == 0 {
		t.Error("Expected at least the program name in cmdline, got nothing")
	}

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
	if err != nil {
		t.Fatalf("HandleStaticSources failed: %v", err)
	}

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

			if tt.wantIPv4 && !hasIPv4 {
				t.Errorf("Expected to extract IPv4, but didn't. IPToHosts: %v", resolver.IPToHosts)
			}
			if tt.wantIPv6 && !hasIPv6 {
				t.Errorf("Expected to extract IPv6, but didn't. IPToHosts: %v", resolver.IPToHosts)
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
	if len(hosts) != 2 {
		t.Errorf("Expected 2 hostnames, got %d: %v", len(hosts), hosts)
	}

	// Lookup non-existent IP should return nil
	hosts = resolver.Lookup("1.2.3.4")
	if hosts != nil {
		t.Errorf("Expected nil for non-existent IP, got %v", hosts)
	}
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
	if len(resolver.IPToHosts) == 0 && len(resolver.HostToIPs) == 0 {
		t.Error("Expected dynamic source to populate resolver, but it's empty")
	}
}

// mockDynamicSource is a test implementation of DynamicSource
type mockDynamicSource struct {
	responses map[string][]string
}

func (m *mockDynamicSource) OnEvent(pid int, eventType string, data []byte) []string {
	if endpoints, ok := m.responses[eventType]; ok {
		return endpoints
	}
	return nil
}
