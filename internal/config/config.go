// Package config handles command-line argument parsing and OpenTelemetry configuration.
package config

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/caarlos0/env/v11"
	"github.com/urfave/cli/v3"
)

// CustomAttribute represents a custom span attribute.
// Expression holds the raw value: either a literal string or an "expr:"-prefixed expression.
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
	// TraceID is an optional value for the OpenTelemetry trace ID.
	// Literal strings or "expr:"-prefixed expressions are accepted.
	// If empty, the OpenTelemetry SDK will auto-generate a random trace ID.
	TraceID string
	// ParentID is an optional value for the OpenTelemetry parent span ID.
	// Literal strings or "expr:"-prefixed expressions are accepted.
	// If empty, the root span will have no parent.
	ParentID string
	// CustomAttributes are user-defined span attributes (literal or expr:-prefixed values)
	CustomAttributes []CustomAttribute
}

// EnvConfig holds process-tracer configuration from environment variables.
type EnvConfig struct {
	TraceID     string `env:"PROCESS_TRACER_TRACE_ID"`
	ParentID    string `env:"PROCESS_TRACER_PARENT_ID"`
	Attributes  string `env:"PROCESS_TRACER_ATTRIBUTES"`
	Mode        string `env:"PROCESS_TRACER_MODE" envDefault:"auto"`
	ShellBinary string `env:"PROCESS_TRACER_SHELL_BINARY"`
}

// ParseEnvConfig parses process-tracer configuration from environment variables.
func ParseEnvConfig() (*EnvConfig, error) {
	var cfg EnvConfig
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse process-tracer env config: %w", err)
	}
	return &cfg, nil
}

// parseAttribute parses a single "NAME=VALUE" string into a CustomAttribute.
// Returns the attribute and true on success, or zero value and false if invalid
// (with a warning logged).
func parseAttribute(s string) (CustomAttribute, bool) {
	parts := strings.SplitN(s, "=", 2)
	if len(parts) != 2 {
		log.Printf("Warning: skipping attribute with invalid format %q (expected NAME=VALUE)", s)
		return CustomAttribute{}, false
	}

	name := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	if name == "" {
		log.Printf("Warning: skipping attribute with empty name in %q", s)
		return CustomAttribute{}, false
	}
	if value == "" {
		log.Printf("Warning: skipping attribute with empty value in %q", s)
		return CustomAttribute{}, false
	}

	return CustomAttribute{Name: name, Expression: value}, true
}

// ParseAttributeString parses semicolon-separated NAME=VALUE pairs.
// Format: "name1=value1;name2=value2;name3=expr:env[\"FOO\"]".
func ParseAttributeString(attrStr string) ([]CustomAttribute, error) {
	if attrStr == "" {
		return nil, nil
	}

	pairs := strings.Split(attrStr, ";")
	attrs := make([]CustomAttribute, 0, len(pairs))

	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		if attr, ok := parseAttribute(pair); ok {
			attrs = append(attrs, attr)
		}
	}

	return attrs, nil
}

// detectSymlinkMode determines if the binary is invoked via symlink.
// Returns true if symlink mode should be used, false for direct CLI mode.
func detectSymlinkMode(mode string) (bool, error) {
	// Check explicit override
	switch mode {
	case "direct":
		return false, nil
	case "symlink":
		return true, nil
	case "auto":
		// Continue to auto-detection
	case "":
		// Empty string means auto-detect (default)
	default:
		return false, fmt.Errorf("invalid PROCESS_TRACER_MODE: %s (must be auto, direct, or symlink)", mode)
	}

	// Auto-detect: check if os.Args[0] is a symlink to ourselves
	if len(os.Args) == 0 {
		return false, nil
	}

	selfPath, err := os.Executable()
	if err != nil {
		return false, nil // Can't determine, assume direct mode
	}

	argsPath := os.Args[0]
	if !filepath.IsAbs(argsPath) {
		// Make it absolute
		argsPath, err = filepath.Abs(argsPath)
		if err != nil {
			return false, nil
		}
	}

	// Resolve symlinks for os.Args[0]
	resolvedArgs, err := filepath.EvalSymlinks(argsPath)
	if err != nil {
		// Can't resolve, assume direct mode
		return false, nil
	}

	resolvedSelf, err := filepath.EvalSymlinks(selfPath)
	if err != nil {
		return false, nil
	}

	// If they resolve to the same path but os.Args[0] != resolved path, it's a symlink
	if resolvedArgs == resolvedSelf && argsPath != resolvedArgs {
		return true, nil
	}

	return false, nil
}

// isExecutable checks if a file exists and is executable.
func isExecutable(path string) bool {
	info, err := os.Stat(path) //nolint:gosec // Path from internal config resolution
	if err != nil {
		return false
	}
	return !info.IsDir() && info.Mode()&0111 != 0
}

// isSelfBinary checks if the given path points to the current executable.
// Uses os.SameFile to handle symlinks and hardlinks correctly.
func isSelfBinary(path string) (bool, error) {
	selfPath, err := os.Executable()
	if err != nil {
		return false, err
	}

	// Resolve both to absolute paths
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}

	absSelf, err := filepath.Abs(selfPath)
	if err != nil {
		return false, err
	}

	// Get file info for both
	selfInfo, err := os.Stat(absSelf)
	if err != nil {
		return false, err
	}

	pathInfo, err := os.Stat(absPath) //nolint:gosec // Path resolved via filepath.Abs
	if err != nil {
		return false, err
	}

	// Compare using SameFile to handle symlinks/hardlinks
	return os.SameFile(selfInfo, pathInfo), nil
}

// resolveShellBinary determines the actual shell binary to execute when running in shell mode.
// Resolution order:
// 1. PROCESS_TRACER_SHELL_BINARY env var (if set)
// 2. Search PATH for binary matching symlink basename (excluding self)
// 3. Check common locations: /bin/<name>, /usr/bin/<name>, /usr/local/bin/<name>
// Returns absolute path to shell binary, or error if not found.
func resolveShellBinary(symlinkName string, envOverride string) (string, error) {
	basename := filepath.Base(symlinkName)

	// 1. Check environment variable override
	if envOverride != "" {
		if !isExecutable(envOverride) {
			return "", fmt.Errorf("PROCESS_TRACER_SHELL_BINARY=%q is not executable or does not exist", envOverride)
		}
		absPath, err := filepath.Abs(envOverride)
		if err != nil {
			return "", fmt.Errorf("failed to resolve PROCESS_TRACER_SHELL_BINARY path: %w", err)
		}
		return absPath, nil
	}

	// 2. Search PATH for the binary
	pathEnv := os.Getenv("PATH")
	if pathEnv != "" {
		for _, dir := range filepath.SplitList(pathEnv) {
			candidate := filepath.Join(dir, basename)
			if !isExecutable(candidate) {
				continue
			}

			// Skip if it's ourselves
			isSelf, err := isSelfBinary(candidate)
			if err != nil {
				// If we can't determine, skip this candidate
				continue
			}
			if isSelf {
				continue
			}

			// Found a valid binary that's not us
			absPath, err := filepath.Abs(candidate)
			if err != nil {
				continue
			}
			return absPath, nil
		}
	}

	// 3. Try common locations
	commonLocations := []string{
		filepath.Join("/bin", basename),
		filepath.Join("/usr/bin", basename),
		filepath.Join("/usr/local/bin", basename),
	}

	for _, location := range commonLocations {
		if !isExecutable(location) {
			continue
		}

		// Skip if it's ourselves
		isSelf, err := isSelfBinary(location)
		if err != nil || isSelf {
			continue
		}

		return location, nil
	}

	// 4. Not found - return helpful error
	return "", fmt.Errorf("could not resolve shell binary for %q\n\nTried:\n  - PROCESS_TRACER_SHELL_BINARY environment variable (not set)\n  - Searching PATH for %q (excluding process-tracer)\n  - /bin/%s (not found)\n  - /usr/bin/%s (not found)\n  - /usr/local/bin/%s (not found)\n\nTo fix:\n  1. Install %s: apt-get install %s (or equivalent)\n  2. Or set: export PROCESS_TRACER_SHELL_BINARY=/path/to/%s",
		basename, basename, basename, basename, basename, basename, basename, basename)
}

// parseSymlinkMode handles configuration when invoked via symlink.
// Resolves the actual shell binary and passes all args to it.
func parseSymlinkMode(args []string, envCfg *EnvConfig) (*Config, error) {
	symlinkName := args[0]

	// Resolve shell binary
	shellBinary, err := resolveShellBinary(symlinkName, envCfg.ShellBinary)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve shell binary for %q: %w",
			filepath.Base(symlinkName), err)
	}

	// Parse custom attributes from environment
	customAttrs, err := ParseAttributeString(envCfg.Attributes)
	if err != nil {
		return nil, err
	}

	return &Config{
		Command:          shellBinary,
		Args:             args[1:], // ALL args go to shell
		TraceID:          envCfg.TraceID,
		ParentID:         envCfg.ParentID,
		CustomAttributes: customAttrs,
	}, nil
}

// ParseArgs is the main entry point for configuration parsing.
// It handles both symlink mode (env vars only) and direct mode (CLI + env vars).
// Maintained for backward compatibility - new code should use ParseConfig.
func ParseArgs(args []string, licenseText string, version, commit, buildDate string) (*Config, error) {
	return ParseConfig(args, licenseText, version, commit, buildDate)
}

// ParseConfig is the unified configuration parser.
// It handles both symlink mode (env vars only) and direct mode (CLI + env vars).
func ParseConfig(args []string, licenseText string, version, commit, buildDate string) (*Config, error) {
	// Parse environment configuration
	envCfg, err := ParseEnvConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to parse environment config: %w", err)
	}

	// Detect invocation mode
	isSymlinkMode, err := detectSymlinkMode(envCfg.Mode)
	if err != nil {
		return nil, err
	}

	if isSymlinkMode {
		return parseSymlinkMode(args, envCfg)
	}

	return parseDirectMode(args, envCfg, licenseText, version, commit, buildDate)
}

// parseDirectMode handles configuration when invoked directly.
// Parses CLI arguments and merges with environment variables (CLI overrides env).
func parseDirectMode(args []string, envCfg *EnvConfig, licenseText string, version, commit, buildDate string) (*Config, error) {
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
			"   process-tracer -a service.name=my-service -- command args\n" +
			"   process-tracer -a env_name='expr:env[\"ENVIRONMENT\"]' -- command args\n" +
			"   process-tracer -a foo='expr:env[\"FOO\"]' -a bar=literal-val -- cmd",
		Version: formatVersionString(version, commit, buildDate),
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
				Usage:   "OpenTelemetry trace ID: literal hex string or expr:EXPRESSION (SDK auto-generates if not provided)",
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
				Usage:   "OpenTelemetry parent span ID: literal hex string or expr:EXPRESSION (null if not provided)",
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
				Usage:       "Add custom span attribute as NAME=VALUE or NAME=expr:EXPRESSION (repeatable)",
				Destination: &attrArgs,
			},
		},
		UseShortOptionHandling: true,
		Action: func(_ context.Context, cmd *cli.Command) error {
			// Parse custom attributes from -a flags
			for _, attrStr := range attrArgs {
				if attr, ok := parseAttribute(attrStr); ok {
					customAttrs = append(customAttrs, attr)
				}
			}

			// Get the command and its arguments
			cmdArgs := cmd.Args().Slice()
			if len(cmdArgs) == 0 {
				return fmt.Errorf("no command specified\n\nUse '--' to separate options from the command to trace.\n\nExample: process-tracer -a service.name=my-svc -- bash -c 'echo hello'")
			}

			// Merge with environment config (CLI overrides)
			finalTraceID := traceID
			if finalTraceID == "" {
				finalTraceID = envCfg.TraceID
			}

			finalParentID := parentID
			if finalParentID == "" {
				finalParentID = envCfg.ParentID
			}

			// Parse env attributes and prepend (CLI attributes take precedence)
			var finalAttrs []CustomAttribute
			if envCfg.Attributes != "" {
				envAttrs, err := ParseAttributeString(envCfg.Attributes)
				if err != nil {
					return err
				}
				finalAttrs = append(finalAttrs, envAttrs...)
			}
			finalAttrs = append(finalAttrs, customAttrs...)

			resultCfg = &Config{
				Command:          cmdArgs[0],
				Args:             cmdArgs[1:],
				TraceID:          finalTraceID,
				ParentID:         finalParentID,
				CustomAttributes: finalAttrs,
			}

			return nil
		},
	}

	// Run the app
	err := app.Run(context.Background(), args)

	// Handle early-exit flags (--help, --version, --license)
	if err != nil {
		var exitErr cli.ExitCoder
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 0 {
			os.Exit(0)
		}
		return nil, err
	}

	if resultCfg == nil {
		// --help or --version was displayed; exit cleanly
		os.Exit(0)
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

// formatVersionString constructs a formatted version string from components.
func formatVersionString(version, commit, date string) string {
	if version == "" || version == "dev" {
		return "dev"
	}
	return fmt.Sprintf("%s (commit: %s, date: %s)", version, commit, date)
}
