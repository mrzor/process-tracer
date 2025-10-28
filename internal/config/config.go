package config

import (
	"fmt"
)

// Config holds the parsed command-line configuration
type Config struct {
	// Command is the executable to run
	Command string
	// Args are the arguments to pass to the command
	Args []string
}

// ParseArgs parses command-line arguments and returns a Config.
// Expected format: program_name -- <command> [args...]
func ParseArgs(args []string) (*Config, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided")
	}

	programName := args[0]

	// Find the "--" separator
	cmdStart := -1
	for i, arg := range args {
		if arg == "--" {
			cmdStart = i + 1
			break
		}
	}

	if cmdStart == -1 || cmdStart >= len(args) {
		return nil, fmt.Errorf("Usage: %s -- <command> [args...]\nExample: %s -- bash -c 'echo hello'",
			programName, programName)
	}

	cmdArgs := args[cmdStart:]

	return &Config{
		Command: cmdArgs[0],
		Args:    cmdArgs[1:],
	}, nil
}

// FullCommand returns the command and all its arguments as a slice
func (c *Config) FullCommand() []string {
	return append([]string{c.Command}, c.Args...)
}
