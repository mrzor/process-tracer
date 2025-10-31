package envreassembler

import (
	"fmt"
	"strings"
	"time"

	"github.com/mrzor/process-tracer/internal/bpf"
)

// VarCollector holds streaming environment variables from execve events.
type VarCollector struct {
	args         []string
	env          []string
	argIndices   map[uint16]bool
	envIndices   map[uint16]bool
	lastArgIndex uint16
	lastEnvIndex uint16
	complete     bool
	truncated    bool
	lastUpdate   time.Time
}

// StreamingReassembler handles reassembly of streaming environment variable events.
type StreamingReassembler struct {
	collectors map[uint32]*VarCollector // PID -> var collector
}

// NewStreamingReassembler creates a new streaming reassembler.
func NewStreamingReassembler() *StreamingReassembler {
	return &StreamingReassembler{
		collectors: make(map[uint32]*VarCollector),
	}
}

// HandleVar processes a single environment variable event.
// Returns the reassembled data if collection is complete, or nil if more variables are expected.
func (s *StreamingReassembler) HandleVar(envVar *bpf.EnvVarEvent) (*ReassembledData, error) {
	pid := envVar.Pid

	// Initialize collector if needed
	if s.collectors[pid] == nil {
		s.collectors[pid] = &VarCollector{
			args:       make([]string, 0, 64),  // Pre-allocate reasonable size
			env:        make([]string, 0, 256), // Pre-allocate for up to 256 env vars
			argIndices: make(map[uint16]bool),
			envIndices: make(map[uint16]bool),
			lastUpdate: time.Now(),
		}
	}

	collector := s.collectors[pid]
	collector.lastUpdate = time.Now()

	// Extract the variable data
	varData := string(envVar.Data[:envVar.DataSize])

	// Store the variable in the appropriate array
	if envVar.IsArgv != 0 {
		// This is an argument
		// Ensure args slice is large enough
		if int(envVar.VarIndex) >= len(collector.args) {
			// Grow slice to accommodate this index
			newArgs := make([]string, envVar.VarIndex+1)
			copy(newArgs, collector.args)
			collector.args = newArgs
		}
		collector.args[envVar.VarIndex] = varData
		collector.argIndices[envVar.VarIndex] = true
		if envVar.VarIndex > collector.lastArgIndex {
			collector.lastArgIndex = envVar.VarIndex
		}
	} else {
		// This is an environment variable
		// Ensure env slice is large enough
		if int(envVar.VarIndex) >= len(collector.env) {
			// Grow slice to accommodate this index
			newEnv := make([]string, envVar.VarIndex+1)
			copy(newEnv, collector.env)
			collector.env = newEnv
		}
		collector.env[envVar.VarIndex] = varData
		collector.envIndices[envVar.VarIndex] = true
		if envVar.VarIndex > collector.lastEnvIndex {
			collector.lastEnvIndex = envVar.VarIndex
		}
	}

	// Track truncation
	if envVar.Truncated != 0 {
		collector.truncated = true
	}

	// Check if this is the final variable
	if envVar.IsFinal != 0 {
		collector.complete = true
	}

	// If complete, finalize and return
	if collector.complete {
		result := s.finalizeCollection(pid, collector)
		delete(s.collectors, pid) // Clean up
		return result, nil
	}

	return nil, nil
}

// finalizeCollection processes completed environment variable streams.
// This is a pure function that transforms collected variables into structured args and env.
func (s *StreamingReassembler) finalizeCollection(_ uint32, collector *VarCollector) *ReassembledData {
	result := &ReassembledData{
		Env:       make(map[string]string),
		Truncated: collector.truncated,
		Issues:    []string{},
	}

	// Trim args to actual size (remove empty slots at end)
	args := collector.args[:collector.lastArgIndex+1]

	// Filter out empty args (gaps in indices)
	finalArgs := make([]string, 0, len(args))
	for i, arg := range args {
		//nolint:gosec // Bounds check ensures i fits in uint16
		if i < 65536 && collector.argIndices[uint16(i)] {
			finalArgs = append(finalArgs, arg)
		}
	}
	result.Args = finalArgs

	// Trim env to actual size
	envRaw := collector.env[:collector.lastEnvIndex+1]

	// Parse environment variables and filter out gaps
	for i, envStr := range envRaw {
		//nolint:gosec // Bounds check ensures i fits in uint16
		if i >= 65536 || !collector.envIndices[uint16(i)] {
			continue // Skip gaps or out of bounds
		}
		if idx := strings.IndexByte(envStr, '='); idx > 0 {
			key := envStr[:idx]
			value := envStr[idx+1:]
			result.Env[key] = value
		}
	}

	// Add warnings if applicable
	if collector.truncated {
		result.Issues = append(result.Issues, fmt.Sprintf("some variables truncated: captured %d args, %d env vars", len(finalArgs), len(result.Env)))
	}

	return result
}

// Cleanup removes stale collectors that haven't been updated recently.
func (s *StreamingReassembler) Cleanup(maxAge time.Duration) int {
	now := time.Now()
	cleaned := 0

	for pid, collector := range s.collectors {
		if now.Sub(collector.lastUpdate) > maxAge {
			delete(s.collectors, pid)
			cleaned++
		}
	}

	return cleaned
}
