package config

import (
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
