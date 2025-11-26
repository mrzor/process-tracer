package config

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testParentID = "0123456789abcdef"
const testTraceID = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
const testLicenseText = "Test License Text"

func TestParseArgs_BasicCommand(t *testing.T) {

	args := []string{"process-tracer", "--", "echo", "hello"}
	cfg, err := ParseArgs(args, testLicenseText, "", "", "")

	require.NoError(t, err)
	assert.Equal(t, "echo", cfg.Command)
	assert.Equal(t, []string{"hello"}, cfg.Args)
	assert.Empty(t, cfg.TraceID, "trace ID should be empty when not provided (SDK will auto-generate)")
	assert.Empty(t, cfg.CustomAttributes)
}

func TestParseArgs_WithTraceID(t *testing.T) {
	args := []string{"process-tracer", "--trace-id", testTraceID, "--", "ls"}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, testTraceID, cfg.TraceID)
	assert.Equal(t, "ls", cfg.Command)
}

func TestParseArgs_WithTraceIDShortForm(t *testing.T) {
	args := []string{"process-tracer", "-t", testTraceID, "--", "ls"}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, testTraceID, cfg.TraceID)
}

func TestParseArgs_TraceIDAsExpression(t *testing.T) {
	// Trace IDs can now be expressions
	traceIDExpr := `env["TRACE_ID"]`
	args := []string{"process-tracer", "-t", traceIDExpr, "--", "ls"}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, traceIDExpr, cfg.TraceID)
}

func TestParseArgs_TraceIDAsLiteralHex(t *testing.T) {
	// Literal hex strings are still valid (they're also valid expressions)
	traceID := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
	args := []string{"process-tracer", "-t", traceID, "--", "ls"}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, traceID, cfg.TraceID)
}

func TestParseArgs_TraceIDShortString(t *testing.T) {
	// Short strings are now allowed (will be hashed to trace ID at runtime)
	shortID := "abc123"
	args := []string{"process-tracer", "-t", shortID, "--", "ls"}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, shortID, cfg.TraceID)
}

func TestParseArgs_WithParentID(t *testing.T) {
	args := []string{"process-tracer", "--parent-id", testParentID, "--", "ls"}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, testParentID, cfg.ParentID)
	assert.Equal(t, "ls", cfg.Command)
}

func TestParseArgs_WithParentIDShortForm(t *testing.T) {
	args := []string{"process-tracer", "-p", testParentID, "--", "ls"}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, testParentID, cfg.ParentID)
}

func TestParseArgs_ParentIDAsExpression(t *testing.T) {
	parentIDExpr := `env["PARENT_SPAN_ID"]`
	args := []string{"process-tracer", "-p", parentIDExpr, "--", "ls"}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, parentIDExpr, cfg.ParentID)
}

func TestParseArgs_WithTraceIDAndParentID(t *testing.T) {
	args := []string{"process-tracer", "-t", testTraceID, "-p", testParentID, "--", "ls"}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, testTraceID, cfg.TraceID)
	assert.Equal(t, testParentID, cfg.ParentID)
}

func TestParseArgs_SingleCustomAttribute(t *testing.T) {
	args := []string{"process-tracer", "-a", "foo=bar", "--", "echo", "test"}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	require.Len(t, cfg.CustomAttributes, 1)
	assert.Equal(t, "foo", cfg.CustomAttributes[0].Name)
	assert.Equal(t, "bar", cfg.CustomAttributes[0].Expression)
}

func TestParseArgs_MultipleCustomAttributes(t *testing.T) {
	args := []string{
		"process-tracer",
		"-a", "env_name=env[\"ENVIRONMENT\"]",
		"-a", "pod=env[\"POD_NAME\"]",
		"--", "bash", "-c", "echo hello",
	}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	require.Len(t, cfg.CustomAttributes, 2)
	assert.Equal(t, "env_name", cfg.CustomAttributes[0].Name)
	assert.Equal(t, "env[\"ENVIRONMENT\"]", cfg.CustomAttributes[0].Expression)
	assert.Equal(t, "pod", cfg.CustomAttributes[1].Name)
	assert.Equal(t, "env[\"POD_NAME\"]", cfg.CustomAttributes[1].Expression)
}

func TestParseArgs_CustomAttributeLongForm(t *testing.T) {
	args := []string{"process-tracer", "--attribute", "test=value", "--", "ls"}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	require.Len(t, cfg.CustomAttributes, 1)
	assert.Equal(t, "test", cfg.CustomAttributes[0].Name)
}

func TestParseArgs_CustomAttributeWithEquals(t *testing.T) {
	// Expression contains '=' characters
	args := []string{"process-tracer", "-a", "check=foo==\"bar\"", "--", "ls"}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	require.Len(t, cfg.CustomAttributes, 1)
	assert.Equal(t, "check", cfg.CustomAttributes[0].Name)
	assert.Equal(t, "foo==\"bar\"", cfg.CustomAttributes[0].Expression)
}

func TestParseArgs_CustomAttributeInvalidFormat(t *testing.T) {
	args := []string{"process-tracer", "-a", "invalid_no_equals", "--", "ls"}

	_, err := ParseArgs(args, testLicenseText, "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid attribute format")
	assert.Contains(t, err.Error(), "NAME=EXPR")
}

func TestParseArgs_CustomAttributeEmptyName(t *testing.T) {
	args := []string{"process-tracer", "-a", "=value", "--", "ls"}

	_, err := ParseArgs(args, testLicenseText, "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name cannot be empty")
}

func TestParseArgs_CustomAttributeEmptyExpression(t *testing.T) {
	args := []string{"process-tracer", "-a", "name=", "--", "ls"}

	_, err := ParseArgs(args, testLicenseText, "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expression cannot be empty")
}

func TestParseArgs_MissingCommand(t *testing.T) {
	args := []string{"process-tracer", "--"}

	_, err := ParseArgs(args, testLicenseText, "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no command specified")
}

func TestParseArgs_MissingSeparator(t *testing.T) {
	args := []string{"process-tracer"}

	_, err := ParseArgs(args, testLicenseText, "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no command specified")
}

func TestParseArgs_CommandWithMultipleArgs(t *testing.T) {
	args := []string{
		"process-tracer",
		"--", "bash", "-c", "echo hello world",
	}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, "bash", cfg.Command)
	assert.Equal(t, []string{"-c", "echo hello world"}, cfg.Args)
}

func TestParseArgs_ComplexScenario(t *testing.T) {
	traceID := "deadbeefdeadbeefdeadbeefdeadbeef"
	args := []string{
		"process-tracer",
		"-t", traceID,
		"-a", "env_name=env[\"ENV\"]",
		"-a", "cmd=cmdline",
		"-a", "first_arg=args[0]",
		"--", "docker", "run", "-it", "ubuntu", "bash",
	}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, traceID, cfg.TraceID)
	assert.Equal(t, "docker", cfg.Command)
	assert.Equal(t, []string{"run", "-it", "ubuntu", "bash"}, cfg.Args)

	require.Len(t, cfg.CustomAttributes, 3)
	assert.Equal(t, "env_name", cfg.CustomAttributes[0].Name)
	assert.Equal(t, "env[\"ENV\"]", cfg.CustomAttributes[0].Expression)
	assert.Equal(t, "cmd", cfg.CustomAttributes[1].Name)
	assert.Equal(t, "cmdline", cfg.CustomAttributes[1].Expression)
	assert.Equal(t, "first_arg", cfg.CustomAttributes[2].Name)
	assert.Equal(t, "args[0]", cfg.CustomAttributes[2].Expression)
}

func TestParseArgs_FullCommand(t *testing.T) {
	args := []string{"process-tracer", "--", "echo", "hello", "world"}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)

	fullCmd := cfg.FullCommand()
	assert.Equal(t, []string{"echo", "hello", "world"}, fullCmd)
}

func TestParseArgs_DottedAttributeName(t *testing.T) {
	args := []string{"process-tracer", "-a", "extra.attribute.name=env[\"VAR\"]", "--", "ls"}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	require.Len(t, cfg.CustomAttributes, 1)
	assert.Equal(t, "extra.attribute.name", cfg.CustomAttributes[0].Name)
}

func TestParseArgs_WhitespaceInAttribute(t *testing.T) {
	// Test that whitespace around = is trimmed
	args := []string{"process-tracer", "-a", "  name  =  value  ", "--", "ls"}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, "name", cfg.CustomAttributes[0].Name)
	assert.Equal(t, "value", cfg.CustomAttributes[0].Expression)
}

func TestGenerateTraceID(t *testing.T) {
	traceID, err := generateTraceID()
	require.NoError(t, err)
	assert.Len(t, traceID, 32)

	// Verify it's valid hex
	for i, c := range traceID {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
			"trace ID contains invalid hex character at position %d: %c", i, c)
	}

	// Generate multiple IDs to ensure they're random
	traceID2, err := generateTraceID()
	require.NoError(t, err)
	assert.NotEqual(t, traceID, traceID2, "expected different trace IDs on successive calls")
}

// Tests for new environment variable and symlink mode features

func TestParseAttributeString_Valid(t *testing.T) {
	attrStr := "foo=bar;baz=env[\"TEST\"];cmd=cmdline"
	attrs, err := ParseAttributeString(attrStr)

	require.NoError(t, err)
	require.Len(t, attrs, 3)
	assert.Equal(t, "foo", attrs[0].Name)
	assert.Equal(t, "bar", attrs[0].Expression)
	assert.Equal(t, "baz", attrs[1].Name)
	assert.Equal(t, "env[\"TEST\"]", attrs[1].Expression)
	assert.Equal(t, "cmd", attrs[2].Name)
	assert.Equal(t, "cmdline", attrs[2].Expression)
}

func TestParseAttributeString_Empty(t *testing.T) {
	attrs, err := ParseAttributeString("")
	require.NoError(t, err)
	assert.Nil(t, attrs)
}

func TestParseAttributeString_InvalidFormat(t *testing.T) {
	attrStr := "invalid_no_equals"
	_, err := ParseAttributeString(attrStr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid attribute format")
}

func TestParseAttributeString_EmptyName(t *testing.T) {
	attrStr := "=value"
	_, err := ParseAttributeString(attrStr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name cannot be empty")
}

func TestParseAttributeString_EmptyExpression(t *testing.T) {
	attrStr := "name="
	_, err := ParseAttributeString(attrStr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expression cannot be empty")
}

func TestParseAttributeString_Whitespace(t *testing.T) {
	attrStr := "  foo  =  bar  ;  baz  =  qux  "
	attrs, err := ParseAttributeString(attrStr)

	require.NoError(t, err)
	require.Len(t, attrs, 2)
	assert.Equal(t, "foo", attrs[0].Name)
	assert.Equal(t, "bar", attrs[0].Expression)
	assert.Equal(t, "baz", attrs[1].Name)
	assert.Equal(t, "qux", attrs[1].Expression)
}

func TestParseAttributeString_TrailingSemicolon(t *testing.T) {
	attrStr := "foo=bar;"
	attrs, err := ParseAttributeString(attrStr)

	require.NoError(t, err)
	require.Len(t, attrs, 1)
	assert.Equal(t, "foo", attrs[0].Name)
	assert.Equal(t, "bar", attrs[0].Expression)
}

func TestParseAttributeString_EmptySections(t *testing.T) {
	attrStr := "foo=bar;;baz=qux"
	attrs, err := ParseAttributeString(attrStr)

	require.NoError(t, err)
	require.Len(t, attrs, 2)
	assert.Equal(t, "foo", attrs[0].Name)
	assert.Equal(t, "baz", attrs[1].Name)
}

func TestDetectSymlinkMode_Direct(t *testing.T) {
	isSymlink, err := detectSymlinkMode("direct")
	require.NoError(t, err)
	assert.False(t, isSymlink)
}

func TestDetectSymlinkMode_Symlink(t *testing.T) {
	isSymlink, err := detectSymlinkMode("symlink")
	require.NoError(t, err)
	assert.True(t, isSymlink)
}

func TestDetectSymlinkMode_Auto(t *testing.T) {
	isSymlink, err := detectSymlinkMode("auto")
	require.NoError(t, err)
	// Result depends on os.Args[0], but should not error
	assert.NotNil(t, isSymlink) // Just checking it returns something
}

func TestDetectSymlinkMode_Empty(t *testing.T) {
	isSymlink, err := detectSymlinkMode("")
	require.NoError(t, err)
	// Empty string should behave like auto
	assert.NotNil(t, isSymlink)
}

func TestDetectSymlinkMode_Invalid(t *testing.T) {
	_, err := detectSymlinkMode("invalid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid PROCESS_TRACER_MODE")
}

func TestParseSymlinkMode_NoCommand(t *testing.T) {
	// With shell resolution, even no args works (interactive shell)
	envCfg := &EnvConfig{
		ShellBinary: "/bin/sh", // Use override to avoid resolution issues
	}
	cfg, err := parseSymlinkMode([]string{"mybash"}, envCfg)
	require.NoError(t, err)
	assert.Equal(t, "/bin/sh", cfg.Command)
	assert.Empty(t, cfg.Args) // No args for interactive shell
}

func TestParseSymlinkMode_WithCommand(t *testing.T) {
	envCfg := &EnvConfig{
		TraceID:     "trace123",
		ParentID:    "parent456",
		Attributes:  "foo=bar;baz=qux",
		ShellBinary: "/bin/sh", // Use override to make test reliable
	}

	cfg, err := parseSymlinkMode([]string{"mybash", "-c", "echo hello"}, envCfg)
	require.NoError(t, err)
	assert.Equal(t, "/bin/sh", cfg.Command)                 // Should be resolved shell, not first arg
	assert.Equal(t, []string{"-c", "echo hello"}, cfg.Args) // ALL args pass through
	assert.Equal(t, "trace123", cfg.TraceID)
	assert.Equal(t, "parent456", cfg.ParentID)
	require.Len(t, cfg.CustomAttributes, 2)
	assert.Equal(t, "foo", cfg.CustomAttributes[0].Name)
	assert.Equal(t, "bar", cfg.CustomAttributes[0].Expression)
}

func TestParseSymlinkMode_NoAttributes(t *testing.T) {
	envCfg := &EnvConfig{
		TraceID:  "trace789",
		ParentID: "",
	}

	// Use sh which should exist on the system
	cfg, err := parseSymlinkMode([]string{"sh", "ls", "-la"}, envCfg)
	require.NoError(t, err)
	// Command should be resolved sh binary
	assert.Contains(t, cfg.Command, "sh")
	assert.True(t, isExecutable(cfg.Command))
	// Args are everything after symlink name
	assert.Equal(t, []string{"ls", "-la"}, cfg.Args)
	assert.Equal(t, "trace789", cfg.TraceID)
	assert.Empty(t, cfg.ParentID)
	assert.Empty(t, cfg.CustomAttributes)
}

func TestParseSymlinkMode_InvalidAttributes(t *testing.T) {
	envCfg := &EnvConfig{
		Attributes:  "invalid_format",
		ShellBinary: "/bin/sh", // Provide valid shell so we get to attribute parsing
	}

	_, err := parseSymlinkMode([]string{"mybash", "echo", "test"}, envCfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid attribute format")
}

func TestParseEnvConfig(t *testing.T) {
	// Set up environment variables for testing
	t.Setenv("PROCESS_TRACER_TRACE_ID", "test_trace")
	t.Setenv("PROCESS_TRACER_PARENT_ID", "test_parent")
	t.Setenv("PROCESS_TRACER_ATTRIBUTES", "key=value")
	t.Setenv("PROCESS_TRACER_MODE", "direct")

	cfg, err := ParseEnvConfig()
	require.NoError(t, err)
	assert.Equal(t, "test_trace", cfg.TraceID)
	assert.Equal(t, "test_parent", cfg.ParentID)
	assert.Equal(t, "key=value", cfg.Attributes)
	assert.Equal(t, "direct", cfg.Mode)
}

func TestParseEnvConfig_Defaults(t *testing.T) {
	// Clear any environment variables
	t.Setenv("PROCESS_TRACER_TRACE_ID", "")
	t.Setenv("PROCESS_TRACER_PARENT_ID", "")
	t.Setenv("PROCESS_TRACER_ATTRIBUTES", "")
	t.Setenv("PROCESS_TRACER_MODE", "")

	cfg, err := ParseEnvConfig()
	require.NoError(t, err)
	assert.Empty(t, cfg.TraceID)
	assert.Empty(t, cfg.ParentID)
	assert.Empty(t, cfg.Attributes)
	assert.Equal(t, "auto", cfg.Mode) // Should use envDefault
}

func TestParseArgs_EnvVarFallback(t *testing.T) {
	// Set environment variables
	t.Setenv("PROCESS_TRACER_TRACE_ID", "env_trace")
	t.Setenv("PROCESS_TRACER_PARENT_ID", "env_parent")
	t.Setenv("PROCESS_TRACER_ATTRIBUTES", "env_attr=env_value")

	// No CLI flags provided
	args := []string{"process-tracer", "--", "echo", "test"}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, "env_trace", cfg.TraceID)
	assert.Equal(t, "env_parent", cfg.ParentID)
	require.Len(t, cfg.CustomAttributes, 1)
	assert.Equal(t, "env_attr", cfg.CustomAttributes[0].Name)
	assert.Equal(t, "env_value", cfg.CustomAttributes[0].Expression)
}

func TestParseArgs_CLIOverridesEnv(t *testing.T) {
	// Set environment variables
	t.Setenv("PROCESS_TRACER_TRACE_ID", "env_trace")
	t.Setenv("PROCESS_TRACER_PARENT_ID", "env_parent")

	// Provide CLI flags that override
	args := []string{"process-tracer", "-t", "cli_trace", "-p", "cli_parent", "--", "echo", "test"}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, "cli_trace", cfg.TraceID)   // CLI wins
	assert.Equal(t, "cli_parent", cfg.ParentID) // CLI wins
}

func TestParseArgs_AttributesMerge(t *testing.T) {
	// Environment attributes should be prepended, CLI attributes appended
	t.Setenv("PROCESS_TRACER_ATTRIBUTES", "env_attr=env_val")

	args := []string{"process-tracer", "-a", "cli_attr=cli_val", "--", "echo", "test"}

	cfg, err := ParseArgs(args, testLicenseText, "", "", "")
	require.NoError(t, err)
	require.Len(t, cfg.CustomAttributes, 2)
	assert.Equal(t, "env_attr", cfg.CustomAttributes[0].Name) // Env comes first
	assert.Equal(t, "cli_attr", cfg.CustomAttributes[1].Name) // CLI comes second
}

// Tests for shell mode support

func TestIsExecutable_Executable(t *testing.T) {
	// Test with sh which should exist on most systems
	assert.True(t, isExecutable("/bin/sh"))
}

func TestIsExecutable_NotExecutable(t *testing.T) {
	// Test with a directory
	assert.False(t, isExecutable("/tmp"))
}

func TestIsExecutable_NotExist(t *testing.T) {
	assert.False(t, isExecutable("/nonexistent/binary"))
}

func TestIsSelfBinary_True(t *testing.T) {
	// Get our own executable
	self, err := os.Executable()
	require.NoError(t, err)

	isSelf, err := isSelfBinary(self)
	require.NoError(t, err)
	assert.True(t, isSelf)
}

func TestIsSelfBinary_False(t *testing.T) {
	// /bin/sh is definitely not us
	isSelf, err := isSelfBinary("/bin/sh")
	require.NoError(t, err)
	assert.False(t, isSelf)
}

func TestResolveShellBinary_EnvOverride(t *testing.T) {
	// Test that env var takes precedence
	resolved, err := resolveShellBinary("/some/path/bash", "/bin/sh")
	require.NoError(t, err)
	assert.Equal(t, "/bin/sh", resolved)
}

func TestResolveShellBinary_EnvOverride_NotExecutable(t *testing.T) {
	// Test with non-executable path
	_, err := resolveShellBinary("/some/path/bash", "/tmp")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not executable")
}

func TestResolveShellBinary_PathLookup(t *testing.T) {
	// Test PATH lookup - sh should be in PATH on most systems
	resolved, err := resolveShellBinary("sh", "")
	require.NoError(t, err)
	assert.NotEmpty(t, resolved)
	assert.Contains(t, resolved, "sh")

	// Verify it's executable
	assert.True(t, isExecutable(resolved))
}

func TestResolveShellBinary_CommonLocations(t *testing.T) {
	// If sh isn't in PATH, it should still find it in /bin
	// Temporarily clear PATH to force common location fallback
	oldPath := os.Getenv("PATH")
	defer func() { require.NoError(t, os.Setenv("PATH", oldPath)) }()

	require.NoError(t, os.Setenv("PATH", ""))

	resolved, err := resolveShellBinary("sh", "")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(resolved, "/bin/") || strings.HasPrefix(resolved, "/usr/bin/"))
}

func TestResolveShellBinary_NotFound(t *testing.T) {
	// Test with a binary that definitely doesn't exist
	_, err := resolveShellBinary("totally_nonexistent_shell_xyz123", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not resolve shell binary")
	assert.Contains(t, err.Error(), "totally_nonexistent_shell_xyz123")
}

func TestParseSymlinkMode_ShellResolution(t *testing.T) {
	envCfg := &EnvConfig{
		TraceID:    "test_trace",
		Attributes: "foo=bar",
	}

	// Test with sh which should exist
	cfg, err := parseSymlinkMode([]string{"/usr/bin/sh", "-c", "echo hello"}, envCfg)
	require.NoError(t, err)

	// Should resolve to actual sh binary
	assert.Contains(t, cfg.Command, "sh")
	assert.True(t, isExecutable(cfg.Command))

	// Args should be passed through
	assert.Equal(t, []string{"-c", "echo hello"}, cfg.Args)
	assert.Equal(t, "test_trace", cfg.TraceID)
}

func TestParseSymlinkMode_ShellResolution_WithOverride(t *testing.T) {
	envCfg := &EnvConfig{
		ShellBinary: "/bin/sh",
		TraceID:     "test_trace",
	}

	// Even if symlinked as bash, should use sh due to override
	cfg, err := parseSymlinkMode([]string{"/usr/bin/bash", "-c", "echo hello"}, envCfg)
	require.NoError(t, err)

	assert.Equal(t, "/bin/sh", cfg.Command)
	assert.Equal(t, []string{"-c", "echo hello"}, cfg.Args)
}

func TestParseSymlinkMode_ShellResolution_NoArgs(t *testing.T) {
	envCfg := &EnvConfig{}

	// Should work even with no args (interactive shell)
	cfg, err := parseSymlinkMode([]string{"/usr/bin/sh"}, envCfg)
	require.NoError(t, err)

	assert.Contains(t, cfg.Command, "sh")
	assert.Empty(t, cfg.Args)
}
