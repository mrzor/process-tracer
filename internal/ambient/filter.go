// Package ambient implements the daemon mode that monitors all process
// execs system-wide and traces matching process trees based on configurable rules.
package ambient

import (
	"path/filepath"
	"strings"

	"github.com/mrzor/process-tracer/internal/config"
)

// FilterEngine evaluates process exec events against configured rules.
type FilterEngine struct {
	rules []config.AmbientRule
}

// NewFilterEngine creates a FilterEngine from the given rules.
func NewFilterEngine(rules []config.AmbientRule) *FilterEngine {
	return &FilterEngine{rules: rules}
}

// Match evaluates a process against all rules, returning the first match or nil.
// comm is the kernel process name (up to 16 chars, null-terminated).
// isContainerInit indicates the process is PID 1 in a non-root PID namespace.
func (f *FilterEngine) Match(comm string, isContainerInit bool) *config.AmbientRule {
	// Trim null bytes from kernel comm
	comm = strings.TrimRight(comm, "\x00")

	for i := range f.rules {
		r := &f.rules[i]

		// Check command glob if configured
		if r.Match.Command != "" {
			matched, err := filepath.Match(r.Match.Command, comm)
			if err != nil || !matched {
				continue
			}
		}

		// Check container init if configured
		if r.Match.IsContainerInit && !isContainerInit {
			continue
		}

		return r
	}
	return nil
}
