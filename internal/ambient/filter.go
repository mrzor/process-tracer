// Package ambient implements the ambient mode daemon that monitors all process
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

// Match evaluates a process's comm against all rules, returning the first match or nil.
// comm is the kernel process name (up to 16 chars, null-terminated).
func (f *FilterEngine) Match(comm string) *config.AmbientRule {
	// Trim null bytes from kernel comm
	comm = strings.TrimRight(comm, "\x00")

	for i := range f.rules {
		r := &f.rules[i]
		matched, err := filepath.Match(r.Match.Command, comm)
		if err != nil {
			continue // invalid pattern, skip rule
		}
		if matched {
			return r
		}
	}
	return nil
}
