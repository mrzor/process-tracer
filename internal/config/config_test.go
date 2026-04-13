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

func TestBuildTraceConfig_BasicCommand(t *testing.T) {
	envCfg := &EnvConfig{}
	cfg, err := BuildTraceConfig(envCfg, "", "", nil, false, false, []string{"echo", "hello"})

	require.NoError(t, err)
	assert.Equal(t, "echo", cfg.Command)
	assert.Equal(t, []string{"hello"}, cfg.Args)
	assert.Empty(t, cfg.TraceID)
	assert.Empty(t, cfg.CustomAttributes)
}

func TestBuildTraceConfig_WithTraceID(t *testing.T) {
	envCfg := &EnvConfig{}
	cfg, err := BuildTraceConfig(envCfg, testTraceID, "", nil, false, false, []string{"ls"})

	require.NoError(t, err)
	assert.Equal(t, testTraceID, cfg.TraceID)
	assert.Equal(t, "ls", cfg.Command)
}

func TestBuildTraceConfig_WithParentID(t *testing.T) {
	envCfg := &EnvConfig{}
	cfg, err := BuildTraceConfig(envCfg, "", testParentID, nil, false, false, []string{"ls"})

	require.NoError(t, err)
	assert.Equal(t, testParentID, cfg.ParentID)
}

func TestBuildTraceConfig_WithTraceIDAndParentID(t *testing.T) {
	envCfg := &EnvConfig{}
	cfg, err := BuildTraceConfig(envCfg, testTraceID, testParentID, nil, false, false, []string{"ls"})

	require.NoError(t, err)
	assert.Equal(t, testTraceID, cfg.TraceID)
	assert.Equal(t, testParentID, cfg.ParentID)
}

func TestBuildTraceConfig_CustomAttributes(t *testing.T) {
	envCfg := &EnvConfig{}
	attrs := []CustomAttribute{
		{Name: "foo", Expression: "bar"},
		{Name: "env_name", Expression: "env[\"ENVIRONMENT\"]"},
	}
	cfg, err := BuildTraceConfig(envCfg, "", "", attrs, false, false, []string{"echo", "test"})

	require.NoError(t, err)
	require.Len(t, cfg.CustomAttributes, 2)
	assert.Equal(t, "foo", cfg.CustomAttributes[0].Name)
	assert.Equal(t, "bar", cfg.CustomAttributes[0].Expression)
	assert.Equal(t, "env_name", cfg.CustomAttributes[1].Name)
}

func TestBuildTraceConfig_MissingCommand(t *testing.T) {
	envCfg := &EnvConfig{}
	_, err := BuildTraceConfig(envCfg, "", "", nil, false, false, []string{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no command specified")
}

func TestBuildTraceConfig_EnvVarFallback(t *testing.T) {
	envCfg := &EnvConfig{
		TraceID:    "env_trace",
		ParentID:   "env_parent",
		Attributes: "env_attr=env_value",
	}

	cfg, err := BuildTraceConfig(envCfg, "", "", nil, false, false, []string{"echo", "test"})
	require.NoError(t, err)
	assert.Equal(t, "env_trace", cfg.TraceID)
	assert.Equal(t, "env_parent", cfg.ParentID)
	require.Len(t, cfg.CustomAttributes, 1)
	assert.Equal(t, "env_attr", cfg.CustomAttributes[0].Name)
	assert.Equal(t, "env_value", cfg.CustomAttributes[0].Expression)
}

func TestBuildTraceConfig_CLIOverridesEnv(t *testing.T) {
	envCfg := &EnvConfig{
		TraceID:  "env_trace",
		ParentID: "env_parent",
	}

	cfg, err := BuildTraceConfig(envCfg, "cli_trace", "cli_parent", nil, false, false, []string{"echo", "test"})
	require.NoError(t, err)
	assert.Equal(t, "cli_trace", cfg.TraceID)
	assert.Equal(t, "cli_parent", cfg.ParentID)
}

func TestBuildTraceConfig_AttributesMerge(t *testing.T) {
	envCfg := &EnvConfig{
		Attributes: "env_attr=env_val",
	}
	cliAttrs := []CustomAttribute{
		{Name: "cli_attr", Expression: "cli_val"},
	}

	cfg, err := BuildTraceConfig(envCfg, "", "", cliAttrs, false, false, []string{"echo", "test"})
	require.NoError(t, err)
	require.Len(t, cfg.CustomAttributes, 2)
	assert.Equal(t, "env_attr", cfg.CustomAttributes[0].Name) // Env comes first
	assert.Equal(t, "cli_attr", cfg.CustomAttributes[1].Name) // CLI comes second
}

func TestBuildTraceConfig_SkipEmptyValues(t *testing.T) {
	envCfg := &EnvConfig{}
	cfg, err := BuildTraceConfig(envCfg, "", "", nil, true, false, []string{"echo"})

	require.NoError(t, err)
	assert.True(t, cfg.SkipEmptyValues)
}

func TestBuildTraceConfig_ComplexScenario(t *testing.T) {
	traceID := "deadbeefdeadbeefdeadbeefdeadbeef"
	attrs := []CustomAttribute{
		{Name: "env_name", Expression: "env[\"ENV\"]"},
		{Name: "cmd", Expression: "cmdline"},
		{Name: "first_arg", Expression: "args[0]"},
	}

	envCfg := &EnvConfig{}
	cfg, err := BuildTraceConfig(envCfg, traceID, "", attrs, false, false, []string{"docker", "run", "-it", "ubuntu", "bash"})
	require.NoError(t, err)
	assert.Equal(t, traceID, cfg.TraceID)
	assert.Equal(t, "docker", cfg.Command)
	assert.Equal(t, []string{"run", "-it", "ubuntu", "bash"}, cfg.Args)

	require.Len(t, cfg.CustomAttributes, 3)
	assert.Equal(t, "env_name", cfg.CustomAttributes[0].Name)
	assert.Equal(t, "cmd", cfg.CustomAttributes[1].Name)
	assert.Equal(t, "first_arg", cfg.CustomAttributes[2].Name)
}

func TestParseAttribute_Valid(t *testing.T) {
	attr, ok := ParseAttribute("foo=bar")
	require.True(t, ok)
	assert.Equal(t, "foo", attr.Name)
	assert.Equal(t, "bar", attr.Expression)
}

func TestParseAttribute_WithEquals(t *testing.T) {
	attr, ok := ParseAttribute("check=foo==\"bar\"")
	require.True(t, ok)
	assert.Equal(t, "check", attr.Name)
	assert.Equal(t, "foo==\"bar\"", attr.Expression)
}

func TestParseAttribute_InvalidFormat(t *testing.T) {
	_, ok := ParseAttribute("invalid_no_equals")
	assert.False(t, ok)
}

func TestParseAttribute_EmptyName(t *testing.T) {
	_, ok := ParseAttribute("=value")
	assert.False(t, ok)
}

func TestParseAttribute_EmptyExpression(t *testing.T) {
	_, ok := ParseAttribute("name=")
	assert.False(t, ok)
}

func TestParseAttribute_Whitespace(t *testing.T) {
	attr, ok := ParseAttribute("  name  =  value  ")
	require.True(t, ok)
	assert.Equal(t, "name", attr.Name)
	assert.Equal(t, "value", attr.Expression)
}

func TestParseAttribute_DottedName(t *testing.T) {
	attr, ok := ParseAttribute("extra.attribute.name=env[\"VAR\"]")
	require.True(t, ok)
	assert.Equal(t, "extra.attribute.name", attr.Name)
}

func TestGenerateTraceID(t *testing.T) {
	traceID, err := generateTraceID()
	require.NoError(t, err)
	assert.Len(t, traceID, 32)

	for i, c := range traceID {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
			"trace ID contains invalid hex character at position %d: %c", i, c)
	}

	traceID2, err := generateTraceID()
	require.NoError(t, err)
	assert.NotEqual(t, traceID, traceID2)
}

func TestFullCommand(t *testing.T) {
	cfg := &Config{Command: "echo", Args: []string{"hello", "world"}}
	assert.Equal(t, []string{"echo", "hello", "world"}, cfg.FullCommand())
}

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
	attrs, err := ParseAttributeString("invalid_no_equals")
	require.NoError(t, err)
	assert.Empty(t, attrs, "malformed attribute should be skipped with a warning")
}

func TestParseAttributeString_EmptyName(t *testing.T) {
	attrs, err := ParseAttributeString("=value")
	require.NoError(t, err)
	assert.Empty(t, attrs, "empty-name attribute should be skipped with a warning")
}

func TestParseAttributeString_EmptyExpression(t *testing.T) {
	attrs, err := ParseAttributeString("name=")
	require.NoError(t, err)
	assert.Empty(t, attrs, "empty-expression attribute should be skipped with a warning")
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
	isSymlink, err := DetectSymlinkMode("direct")
	require.NoError(t, err)
	assert.False(t, isSymlink)
}

func TestDetectSymlinkMode_Symlink(t *testing.T) {
	isSymlink, err := DetectSymlinkMode("symlink")
	require.NoError(t, err)
	assert.True(t, isSymlink)
}

func TestDetectSymlinkMode_Auto(t *testing.T) {
	isSymlink, err := DetectSymlinkMode("auto")
	require.NoError(t, err)
	assert.NotNil(t, isSymlink)
}

func TestDetectSymlinkMode_Empty(t *testing.T) {
	isSymlink, err := DetectSymlinkMode("")
	require.NoError(t, err)
	assert.NotNil(t, isSymlink)
}

func TestDetectSymlinkMode_Invalid(t *testing.T) {
	_, err := DetectSymlinkMode("invalid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid PROCESS_TRACER_MODE")
}

func TestParseSymlinkMode_NoCommand(t *testing.T) {
	envCfg := &EnvConfig{
		ShellBinary: "/bin/sh",
	}
	cfg, err := ParseSymlinkMode([]string{"mybash"}, envCfg)
	require.NoError(t, err)
	assert.Equal(t, "/bin/sh", cfg.Command)
	assert.Empty(t, cfg.Args)
}

func TestParseSymlinkMode_WithCommand(t *testing.T) {
	envCfg := &EnvConfig{
		TraceID:     "trace123",
		ParentID:    "parent456",
		Attributes:  "foo=bar;baz=qux",
		ShellBinary: "/bin/sh",
	}

	cfg, err := ParseSymlinkMode([]string{"mybash", "-c", "echo hello"}, envCfg)
	require.NoError(t, err)
	assert.Equal(t, "/bin/sh", cfg.Command)
	assert.Equal(t, []string{"-c", "echo hello"}, cfg.Args)
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

	cfg, err := ParseSymlinkMode([]string{"sh", "ls", "-la"}, envCfg)
	require.NoError(t, err)
	assert.Contains(t, cfg.Command, "sh")
	assert.True(t, isExecutable(cfg.Command))
	assert.Equal(t, []string{"ls", "-la"}, cfg.Args)
	assert.Equal(t, "trace789", cfg.TraceID)
	assert.Empty(t, cfg.ParentID)
	assert.Empty(t, cfg.CustomAttributes)
}

func TestParseSymlinkMode_InvalidAttributes(t *testing.T) {
	envCfg := &EnvConfig{
		Attributes:  "invalid_format",
		ShellBinary: "/bin/sh",
	}

	cfg, err := ParseSymlinkMode([]string{"mybash", "echo", "test"}, envCfg)
	require.NoError(t, err)
	assert.Empty(t, cfg.CustomAttributes, "malformed attribute should be skipped with a warning")
}

func TestParseEnvConfig(t *testing.T) {
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
	t.Setenv("PROCESS_TRACER_TRACE_ID", "")
	t.Setenv("PROCESS_TRACER_PARENT_ID", "")
	t.Setenv("PROCESS_TRACER_ATTRIBUTES", "")
	t.Setenv("PROCESS_TRACER_MODE", "")

	cfg, err := ParseEnvConfig()
	require.NoError(t, err)
	assert.Empty(t, cfg.TraceID)
	assert.Empty(t, cfg.ParentID)
	assert.Empty(t, cfg.Attributes)
	assert.Equal(t, "auto", cfg.Mode)
}

func TestIsExecutable_Executable(t *testing.T) {
	assert.True(t, isExecutable("/bin/sh"))
}

func TestIsExecutable_NotExecutable(t *testing.T) {
	assert.False(t, isExecutable("/tmp"))
}

func TestIsExecutable_NotExist(t *testing.T) {
	assert.False(t, isExecutable("/nonexistent/binary"))
}

func TestIsSelfBinary_True(t *testing.T) {
	self, err := os.Executable()
	require.NoError(t, err)

	isSelf, err := isSelfBinary(self)
	require.NoError(t, err)
	assert.True(t, isSelf)
}

func TestIsSelfBinary_False(t *testing.T) {
	isSelf, err := isSelfBinary("/bin/sh")
	require.NoError(t, err)
	assert.False(t, isSelf)
}

func TestResolveShellBinary_EnvOverride(t *testing.T) {
	resolved, err := resolveShellBinary("/some/path/bash", "/bin/sh")
	require.NoError(t, err)
	assert.Equal(t, "/bin/sh", resolved)
}

func TestResolveShellBinary_EnvOverride_NotExecutable(t *testing.T) {
	_, err := resolveShellBinary("/some/path/bash", "/tmp")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not executable")
}

func TestResolveShellBinary_PathLookup(t *testing.T) {
	resolved, err := resolveShellBinary("sh", "")
	require.NoError(t, err)
	assert.NotEmpty(t, resolved)
	assert.Contains(t, resolved, "sh")
	assert.True(t, isExecutable(resolved))
}

func TestResolveShellBinary_CommonLocations(t *testing.T) {
	oldPath := os.Getenv("PATH")
	defer func() { require.NoError(t, os.Setenv("PATH", oldPath)) }()

	require.NoError(t, os.Setenv("PATH", ""))

	resolved, err := resolveShellBinary("sh", "")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(resolved, "/bin/") || strings.HasPrefix(resolved, "/usr/bin/"))
}

func TestResolveShellBinary_NotFound(t *testing.T) {
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

	cfg, err := ParseSymlinkMode([]string{"/usr/bin/sh", "-c", "echo hello"}, envCfg)
	require.NoError(t, err)

	assert.Contains(t, cfg.Command, "sh")
	assert.True(t, isExecutable(cfg.Command))
	assert.Equal(t, []string{"-c", "echo hello"}, cfg.Args)
	assert.Equal(t, "test_trace", cfg.TraceID)
}

func TestParseSymlinkMode_ShellResolution_WithOverride(t *testing.T) {
	envCfg := &EnvConfig{
		ShellBinary: "/bin/sh",
		TraceID:     "test_trace",
	}

	cfg, err := ParseSymlinkMode([]string{"/usr/bin/bash", "-c", "echo hello"}, envCfg)
	require.NoError(t, err)

	assert.Equal(t, "/bin/sh", cfg.Command)
	assert.Equal(t, []string{"-c", "echo hello"}, cfg.Args)
}

func TestParseSymlinkMode_ShellResolution_NoArgs(t *testing.T) {
	envCfg := &EnvConfig{}

	cfg, err := ParseSymlinkMode([]string{"/usr/bin/sh"}, envCfg)
	require.NoError(t, err)

	assert.Contains(t, cfg.Command, "sh")
	assert.Empty(t, cfg.Args)
}

func TestFormatVersionString(t *testing.T) {
	assert.Equal(t, "dev", FormatVersionString("", "", ""))
	assert.Equal(t, "dev", FormatVersionString("dev", "", ""))
	assert.Equal(t, "v1.0.0 (commit: abc, date: 2024-01-01)", FormatVersionString("v1.0.0", "abc", "2024-01-01"))
}
