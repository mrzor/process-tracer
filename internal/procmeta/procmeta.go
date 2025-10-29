package procmeta

import (
	"errors"
	"fmt"
	"strings"

	"sched_trace/internal/pseudo_reverse_dns"
)

// ProcessMetadata holds structured process information for expression evaluation
type ProcessMetadata struct {
	Environ     map[string]string // Parsed environment variables
	Args        []string          // Command-line arguments
	CmdlineFull string            // Full command line as single string
}

// Collector gathers process metadata from /proc filesystem
type Collector struct {
	environSrc  *pseudo_reverse_dns.EnvironSource
	cmdlineSrc  *pseudo_reverse_dns.CmdlineSource
}

// NewCollector creates a new process metadata collector
func NewCollector() *Collector {
	return &Collector{
		environSrc:  &pseudo_reverse_dns.EnvironSource{},
		cmdlineSrc:  &pseudo_reverse_dns.CmdlineSource{},
	}
}

// Collect gathers all process metadata for a given PID
func (c *Collector) Collect(pid int) (*ProcessMetadata, error) {
	metadata := &ProcessMetadata{
		Environ: make(map[string]string),
	}

	var errs []error

	// Collect environment variables
	environRaw, err := c.environSrc.Extract(pid)
	if err == nil {
		metadata.Environ = parseEnviron(environRaw)
	} else {
		errs = append(errs, fmt.Errorf("environ: %w", err))
	}

	// Collect command-line
	cmdlineRaw, err := c.cmdlineSrc.Extract(pid)
	if err == nil {
		metadata.Args, metadata.CmdlineFull = parseCmdline(cmdlineRaw)
	} else {
		errs = append(errs, fmt.Errorf("cmdline: %w", err))
	}

	// Return partial metadata with error if collection failed
	if len(errs) > 0 {
		return metadata, fmt.Errorf("failed to collect metadata: %w", errors.Join(errs...))
	}

	return metadata, nil
}

// parseEnviron converts raw "KEY=VALUE" strings to a map
func parseEnviron(raw []string) map[string]string {
	result := make(map[string]string, len(raw))
	for _, entry := range raw {
		if idx := strings.IndexByte(entry, '='); idx > 0 {
			key := entry[:idx]
			value := entry[idx+1:]
			result[key] = value
		}
	}
	return result
}

// parseCmdline converts raw command-line arguments to both array and full string
func parseCmdline(raw []string) ([]string, string) {
	if len(raw) == 0 {
		return []string{}, ""
	}
	return raw, strings.Join(raw, " ")
}
