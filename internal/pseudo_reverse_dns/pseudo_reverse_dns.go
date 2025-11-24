// Package pseudo_reverse_dns provides connection enrichment by extracting network endpoints from
// process environment variables, command-line arguments, and runtime events.
//
// The core problem: when you observe raw socket operations (IP:port pairs), you lack semantic
// context. A connection to 10.0.0.5:5432 might be "postgres" or something else entirely. Most
// applications store their important endpoints in environment variables (DATABASE_URL, REDIS_HOST,
// API_ENDPOINT, etc.) and command-line arguments (curl http://example.com, --url, --host flags).
//
// The solution: scan strings for hostnames, IP addresses, and hostname:port combinations.
// Resolve hostnames to IPs once (caching to avoid re-resolution). Build a reverse lookup map.
// When you capture a connection to an IP, cross-reference it against this map to recover the
// original endpoint name.
//
// This is imperfect (misses some dynamic discovery, third-party connections) but extremely
// practical: it catches 70-80% of meaningful connections with minimal overhead.
package pseudo_reverse_dns

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// HostMapping stores the original endpoint names that resolved to an IP.
type HostMapping struct {
	Originals []string
}

// Resolver extracts network endpoints from multiple sources and builds reverse IP lookups.
// Data ingestion happens via IngestEndpoints() method; resolution via Lookup().
//
// Usage:
//
//	r := New()
//	r.IngestEndpoints(envVars...)  // Ingests environment variables from eBPF
//	r.IngestEndpoints(args...)     // Ingests command-line arguments from eBPF
//	hostnames := r.Lookup(ip)      // Resolves IP to hostnames (call as late as possible)
type Resolver struct {
	IPToHosts      map[string]*HostMapping
	processedHosts map[string]bool

	hostnameRegex   *regexp.Regexp
	ipv4Regex       *regexp.Regexp
	ipv6Regex       *regexp.Regexp
	hostnamePortReg *regexp.Regexp
}

// New creates a new Resolver with compiled regexes.
func New() *Resolver {
	return &Resolver{
		IPToHosts:       make(map[string]*HostMapping),
		processedHosts:  make(map[string]bool),
		hostnameRegex:   regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}`),
		ipv4Regex:       regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
		ipv6Regex:       regexp.MustCompile(`(?i)(?:\[)?(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:\])?`),
		hostnamePortReg: regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}:\d{1,5}`),
	}
}

// IngestEndpoints directly ingests endpoint strings for extraction.
// This is the primary method for feeding data from eBPF events, bypassing the source abstraction.
// Each string is scanned for hostnames, IPs, and hostname:port combinations.
func (r *Resolver) IngestEndpoints(endpoints ...string) {
	for _, endpoint := range endpoints {
		r.extractEndpoints(endpoint)
	}
}

func (r *Resolver) extractEndpoints(s string) {
	hostPortMatches := r.hostnamePortReg.FindAllString(s, -1)
	for _, match := range hostPortMatches {
		r.addHostnamePort(match)
	}

	hostMatches := r.hostnameRegex.FindAllString(s, -1)
	for _, match := range hostMatches {
		r.addHostname(match)
	}

	ipv4Matches := r.ipv4Regex.FindAllString(s, -1)
	for _, match := range ipv4Matches {
		r.addIPv4(match)
	}

	ipv6Matches := r.ipv6Regex.FindAllString(s, -1)
	for _, match := range ipv6Matches {
		if r.isValidIPv6(match) {
			r.addIPv6(match)
		}
	}
}

func (r *Resolver) isValidIPv6(s string) bool {
	s = strings.Trim(s, "[]")
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() == nil
}

func (r *Resolver) addHostnamePort(hostPort string) {
	parts := strings.Split(hostPort, ":")
	if len(parts) != 2 {
		return
	}
	hostname := strings.ToLower(parts[0])
	portStr := parts[1]

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return
	}

	r.addHostname(hostname)
}

func (r *Resolver) addHostname(hostname string) {
	hostname = strings.ToLower(hostname)
	hostname = strings.Trim(hostname, "[]")

	// Skip if already processed
	if r.processedHosts[hostname] {
		return
	}
	r.processedHosts[hostname] = true

	ips, err := net.LookupIP(hostname)
	if err != nil {
		return
	}

	for _, ip := range ips {
		r.addIPMapping(ip.String(), hostname)
	}
}

func (r *Resolver) addIPv4(ipStr string) {
	if net.ParseIP(ipStr) != nil {
		r.addIPMapping(ipStr, ipStr)
	}
}

func (r *Resolver) addIPv6(ipStr string) {
	ipStr = strings.Trim(ipStr, "[]")
	if net.ParseIP(ipStr) != nil {
		r.addIPMapping(ipStr, ipStr)
	}
}

func (r *Resolver) addIPMapping(ip, hostname string) {
	if _, exists := r.IPToHosts[ip]; !exists {
		r.IPToHosts[ip] = &HostMapping{
			Originals: []string{},
		}
	}

	mapping := r.IPToHosts[ip]
	if !contains(mapping.Originals, hostname) {
		mapping.Originals = append(mapping.Originals, hostname)
	}
}

// Lookup returns possible hostnames for a given IP address.
func (r *Resolver) Lookup(ip string) []string {
	if mapping, exists := r.IPToHosts[ip]; exists {
		return mapping.Originals
	}
	return nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// EnvironSource extracts network endpoints from /proc/<pid>/environ.
type EnvironSource struct{}

// Extract reads the process environment variables and returns their values.
func (e *EnvironSource) Extract(pid int) ([]string, error) {
	environPath := fmt.Sprintf("/proc/%d/environ", pid)
	//nolint:gosec // Reading from /proc is safe and necessary for process metadata
	data, err := os.ReadFile(environPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", environPath, err)
	}

	var endpoints []string
	envVars := bytes.Split(data, []byte{0})
	for _, envVar := range envVars {
		if len(envVar) == 0 {
			continue
		}
		parts := bytes.SplitN(envVar, []byte("="), 2)
		if len(parts) != 2 {
			continue
		}
		value := string(parts[1])
		endpoints = append(endpoints, value)
	}

	return endpoints, nil
}

// CmdlineSource extracts network endpoints from /proc/<pid>/cmdline.
type CmdlineSource struct{}

// Extract reads the process command line and returns the arguments.
func (c *CmdlineSource) Extract(pid int) ([]string, error) {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	//nolint:gosec // Reading from /proc is safe and necessary for process metadata
	data, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", cmdlinePath, err)
	}

	// cmdline is null-byte separated arguments
	args := bytes.Split(data, []byte{0})
	var endpoints []string
	for _, arg := range args {
		if len(arg) == 0 {
			continue
		}
		endpoints = append(endpoints, string(arg))
	}

	return endpoints, nil
}
