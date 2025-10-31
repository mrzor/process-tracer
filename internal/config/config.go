// Package config handles command-line argument parsing and OpenTelemetry configuration.
package config

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/urfave/cli/v3"
)

// CustomAttribute represents a custom span attribute with an expression.
type CustomAttribute struct {
	Name       string
	Expression string
}

// Config holds the parsed command-line configuration.
type Config struct {
	// Command is the executable to run
	Command string
	// Args are the arguments to pass to the command
	Args []string
	// TraceID is the OpenTelemetry trace ID (expr expression or 32 hex chars)
	TraceID string
	// ParentID is the OpenTelemetry parent span ID for the root span (expr expression or 16 hex chars)
	ParentID string
	// CustomAttributes are user-defined span attributes with expressions
	CustomAttributes []CustomAttribute
}

// ParseArgs parses command-line arguments using urfave/cli and returns a Config.
// Expected format: program_name [--trace-id <id>] [--parent-id <id>] [-a name=expr]... -- <command> [args...].
// licenseText is displayed when --license flag is used.
func ParseArgs(args []string, licenseText string) (*Config, error) {
	var traceID string
	var parentID string
	var customAttrs []CustomAttribute
	var attrArgs []string
	var resultCfg *Config

	app := &cli.Command{
		Name:  "process-tracer",
		Usage: "eBPF-based process and network tracer with OpenTelemetry span integration",
		UsageText: "process-tracer [OPTIONS] -- COMMAND [ARGS...]\n\n" +
			"   Use '--' to separate options from the command to trace.\n\n" +
			"EXAMPLES:\n" +
			"   process-tracer -- bash -c 'echo hello'\n" +
			"   process-tracer -t a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 -- ls -la\n" +
			"   process-tracer -a env_name='env[\"ENVIRONMENT\"]' -- command args\n" +
			"   process-tracer -a foo='env[\"FOO\"]' -a bar='args[0]' -- cmd",
		Version: "dev",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "license",
				Usage: "Display license information and exit",
				Action: func(_ context.Context, _ *cli.Command, b bool) error {
					if b {
						fmt.Println(licenseText)
						return cli.Exit("", 0)
					}
					return nil
				},
			},
			&cli.StringFlag{
				Name:    "trace-id",
				Aliases: []string{"t"},
				Usage:   "OpenTelemetry trace ID (expr expression or 32 hex chars, auto-generated if not provided)",
				Action: func(_ context.Context, _ *cli.Command, s string) error {
					if s != "" {
						traceID = s
					}
					return nil
				},
			},
			&cli.StringFlag{
				Name:    "parent-id",
				Aliases: []string{"p"},
				Usage:   "OpenTelemetry parent span ID for root span (expr expression or 16 hex chars, null if not provided)",
				Action: func(_ context.Context, _ *cli.Command, s string) error {
					if s != "" {
						parentID = s
					}
					return nil
				},
			},
			&cli.StringSliceFlag{
				Name:        "a",
				Aliases:     []string{"attribute"},
				Usage:       "Add custom span attribute as NAME=EXPR (repeatable)",
				Destination: &attrArgs,
			},
		},
		UseShortOptionHandling: true,
		Action: func(_ context.Context, cmd *cli.Command) error {
			// Parse custom attributes from -a flags
			for _, attrStr := range attrArgs {
				// Split on first '=' to separate name from expression
				parts := strings.SplitN(attrStr, "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid attribute format %q: expected NAME=EXPR", attrStr)
				}
				name := strings.TrimSpace(parts[0])
				expr := strings.TrimSpace(parts[1])

				if name == "" {
					return fmt.Errorf("attribute name cannot be empty in %q", attrStr)
				}
				if expr == "" {
					return fmt.Errorf("attribute expression cannot be empty in %q", attrStr)
				}

				customAttrs = append(customAttrs, CustomAttribute{
					Name:       name,
					Expression: expr,
				})
			}

			// Get the command and its arguments
			cmdArgs := cmd.Args().Slice()
			if len(cmdArgs) == 0 {
				return fmt.Errorf("no command specified\n\nUse '--' to separate options from the command to trace.\n\nExample: process-tracer -a env_name='env[\"ENVIRONMENT\"]' -- bash -c 'echo hello'")
			}

			// Generate trace ID if not provided
			if traceID == "" {
				var err error
				traceID, err = generateTraceID()
				if err != nil {
					return fmt.Errorf("failed to generate trace ID: %w", err)
				}
			}

			// Store config for return
			resultCfg = &Config{
				Command:          cmdArgs[0],
				Args:             cmdArgs[1:],
				TraceID:          traceID,
				ParentID:         parentID,
				CustomAttributes: customAttrs,
			}

			return nil
		},
	}

	// Run the app
	err := app.Run(context.Background(), args)

	// If help or version was requested, the app exits early - this is expected
	// In that case, resultCfg will be nil and we should return the error
	if err != nil {
		return nil, err
	}

	if resultCfg == nil {
		return nil, fmt.Errorf("failed to parse configuration")
	}

	return resultCfg, nil
}

// generateTraceID generates a random 128-bit trace ID as 32 hex chars.
func generateTraceID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// FullCommand returns the command and all its arguments as a slice.
func (c *Config) FullCommand() []string {
	return append([]string{c.Command}, c.Args...)
}
