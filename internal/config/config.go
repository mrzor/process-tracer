package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// Config holds the parsed command-line configuration
type Config struct {
	// Command is the executable to run
	Command string
	// Args are the arguments to pass to the command
	Args []string
	// TraceID is the OpenTelemetry trace ID (32 hex chars)
	TraceID string
}

// ParseArgs parses command-line arguments and returns a Config.
// Expected format: program_name [--trace-id <id>] -- <command> [args...]
func ParseArgs(args []string) (*Config, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided")
	}

	programName := args[0]
	var traceID string

	// Find the "--" separator
	cmdStart := -1
	for i := 1; i < len(args); i++ {
		if args[i] == "--" {
			cmdStart = i + 1
			break
		}

		// Parse --trace-id flag
		if args[i] == "--trace-id" {
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--trace-id requires a value")
			}
			traceID = args[i+1]
			i++ // skip the value
		}
	}

	if cmdStart == -1 || cmdStart >= len(args) {
		return nil, fmt.Errorf("Usage: %s [--trace-id <id>] -- <command> [args...]\nExample: %s -- bash -c 'echo hello'",
			programName, programName)
	}

	cmdArgs := args[cmdStart:]

	// Validate or generate trace ID
	if traceID != "" {
		// Validate: must be 32 hex chars
		if len(traceID) != 32 {
			return nil, fmt.Errorf("trace ID must be 32 hex characters, got %d", len(traceID))
		}
		if _, err := hex.DecodeString(traceID); err != nil {
			return nil, fmt.Errorf("trace ID must be valid hex: %v", err)
		}
		traceID = strings.ToLower(traceID)
	} else {
		// Auto-generate random 128-bit trace ID
		var err error
		traceID, err = generateTraceID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate trace ID: %v", err)
		}
	}

	return &Config{
		Command: cmdArgs[0],
		Args:    cmdArgs[1:],
		TraceID: traceID,
	}, nil
}

// generateTraceID generates a random 128-bit trace ID as 32 hex chars
func generateTraceID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// FullCommand returns the command and all its arguments as a slice
func (c *Config) FullCommand() []string {
	return append([]string{c.Command}, c.Args...)
}
