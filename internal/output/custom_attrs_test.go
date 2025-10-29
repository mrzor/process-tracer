// Test file for custom_attrs.go functionality.
//
//nolint:testpackage // Testing internal implementation details
package output

import (
	"testing"

	"github.com/mrzor/process-tracer/internal/config"
	"github.com/mrzor/process-tracer/internal/procmeta"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluateCustomAttributes_MissingMetadata(t *testing.T) {
	customAttrs := []config.CustomAttribute{
		{Name: "env_test", Expression: `env["DATABASE_URL"]`},
	}

	compiledExprs, err := compileTestExpressions(customAttrs)
	require.NoError(t, err)

	formatter := &OTELFormatter{
		processMetadata: make(map[uint32]*procmeta.ProcessMetadata),
		customAttrs:     customAttrs,
		compiledExprs:   compiledExprs,
	}

	pid := uint32(12345)
	attrs, err := formatter.evaluateCustomAttributes(pid)

	assert.Empty(t, attrs, "should return no attributes when metadata is missing")
	assert.NoError(t, err, "current behavior: no error on missing metadata")
}

func TestEvaluateCustomAttributes_Success(t *testing.T) {
	customAttrs := []config.CustomAttribute{
		{Name: "db_url", Expression: `env["DATABASE_URL"]`},
		{Name: "env_name", Expression: `env["ENVIRONMENT"]`},
		{Name: "cmdline", Expression: `cmdline`},
	}

	compiledExprs, err := compileTestExpressions(customAttrs)
	require.NoError(t, err)

	formatter := &OTELFormatter{
		processMetadata: make(map[uint32]*procmeta.ProcessMetadata),
		customAttrs:     customAttrs,
		compiledExprs:   compiledExprs,
	}

	pid := uint32(12345)
	formatter.processMetadata[pid] = &procmeta.ProcessMetadata{
		Environ: map[string]string{
			"DATABASE_URL": "postgres://localhost/mydb",
			"ENVIRONMENT":  "production",
		},
		Args:        []string{"myapp", "--port", "8080"},
		CmdlineFull: "myapp --port 8080",
	}

	attrs, err := formatter.evaluateCustomAttributes(pid)
	require.NoError(t, err)
	assert.Len(t, attrs, 3)

	attrMap := make(map[string]string)
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsString()
	}

	assert.Equal(t, "postgres://localhost/mydb", attrMap["db_url"])
	assert.Equal(t, "production", attrMap["env_name"])
	assert.Equal(t, "myapp --port 8080", attrMap["cmdline"])
}

func TestEvaluateCustomAttributes_ActualExpansion(t *testing.T) {
	customAttrs := []config.CustomAttribute{
		{Name: "editor", Expression: `env["EDITOR"]`},
		{Name: "path", Expression: `env["PATH"]`},
		{Name: "first_arg", Expression: `args[0]`},
		{Name: "num_args", Expression: `len(args)`},
	}

	compiledExprs, err := compileTestExpressions(customAttrs)
	require.NoError(t, err)

	formatter := &OTELFormatter{
		processMetadata: make(map[uint32]*procmeta.ProcessMetadata),
		customAttrs:     customAttrs,
		compiledExprs:   compiledExprs,
	}

	pid := uint32(99999)
	formatter.processMetadata[pid] = &procmeta.ProcessMetadata{
		Environ: map[string]string{
			"EDITOR": "/usr/bin/vim",
			"PATH":   "/usr/local/bin:/usr/bin:/bin",
		},
		Args:        []string{"python", "script.py", "--verbose"},
		CmdlineFull: "python script.py --verbose",
	}

	attrs, err := formatter.evaluateCustomAttributes(pid)
	require.NoError(t, err)
	require.Len(t, attrs, 4)

	attrMap := make(map[string]string)
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsString()
	}

	assert.Equal(t, "/usr/bin/vim", attrMap["editor"])
	assert.Equal(t, "/usr/local/bin:/usr/bin:/bin", attrMap["path"])
	assert.Equal(t, "python", attrMap["first_arg"])
	assert.Equal(t, "3", attrMap["num_args"])
}

func TestEvaluateCustomAttributes_MissingEnvVar(t *testing.T) {
	customAttrs := []config.CustomAttribute{
		{Name: "existing", Expression: `env["EDITOR"]`},
		{Name: "missing", Expression: `env["NONEXISTENT"]`},
	}

	compiledExprs, err := compileTestExpressions(customAttrs)
	require.NoError(t, err)

	formatter := &OTELFormatter{
		processMetadata: make(map[uint32]*procmeta.ProcessMetadata),
		customAttrs:     customAttrs,
		compiledExprs:   compiledExprs,
	}

	pid := uint32(99998)
	formatter.processMetadata[pid] = &procmeta.ProcessMetadata{
		Environ: map[string]string{
			"EDITOR": "/usr/bin/nano",
		},
		Args:        []string{"test"},
		CmdlineFull: "test",
	}

	attrs, err := formatter.evaluateCustomAttributes(pid)
	require.NoError(t, err)

	attrMap := make(map[string]string)
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsString()
	}

	assert.Equal(t, "/usr/bin/nano", attrMap["existing"])
	// Missing env var results in empty string (Go map zero value)
	assert.Empty(t, attrMap["missing"])
}

func TestEvaluateCustomAttributes_BasicMapExpansion(t *testing.T) {
	customAttrs := []config.CustomAttribute{
		{Name: "myattr", Expression: `{"a": "AA", "b": "BB"}`},
	}

	compiledExprs, err := compileTestExpressions(customAttrs)
	require.NoError(t, err)

	formatter := &OTELFormatter{
		processMetadata: make(map[uint32]*procmeta.ProcessMetadata),
		customAttrs:     customAttrs,
		compiledExprs:   compiledExprs,
	}

	pid := uint32(10001)
	formatter.processMetadata[pid] = &procmeta.ProcessMetadata{
		Environ:     map[string]string{},
		Args:        []string{},
		CmdlineFull: "",
	}

	attrs, err := formatter.evaluateCustomAttributes(pid)
	require.NoError(t, err)
	assert.Len(t, attrs, 2, "map with 2 keys should expand to 2 attributes")

	attrMap := make(map[string]string)
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsString()
	}

	assert.Equal(t, "AA", attrMap["myattr.a"])
	assert.Equal(t, "BB", attrMap["myattr.b"])
}

func TestEvaluateCustomAttributes_MapKeySanitization(t *testing.T) {
	customAttrs := []config.CustomAttribute{
		{Name: "sanitize", Expression: `{"valid_key": "V1", "key.with.dots": "V2", "key-with-dash": "V3", "key with spaces": "V4"}`},
	}

	compiledExprs, err := compileTestExpressions(customAttrs)
	require.NoError(t, err)

	formatter := &OTELFormatter{
		processMetadata: make(map[uint32]*procmeta.ProcessMetadata),
		customAttrs:     customAttrs,
		compiledExprs:   compiledExprs,
	}

	pid := uint32(10002)
	formatter.processMetadata[pid] = &procmeta.ProcessMetadata{
		Environ:     map[string]string{},
		Args:        []string{},
		CmdlineFull: "",
	}

	attrs, err := formatter.evaluateCustomAttributes(pid)
	require.NoError(t, err)
	assert.Len(t, attrs, 4, "map with 4 keys should expand to 4 attributes")

	attrMap := make(map[string]string)
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsString()
	}

	assert.Equal(t, "V1", attrMap["sanitize.valid_key"])
	assert.Equal(t, "V2", attrMap["sanitize.key_with_dots"], "dots should be replaced with underscores")
	assert.Equal(t, "V3", attrMap["sanitize.key_with_dash"], "dashes should be replaced with underscores")
	assert.Equal(t, "V4", attrMap["sanitize.key_with_spaces"], "spaces should be replaced with underscores")
}

func TestEvaluateCustomAttributes_NestedMapNotExpanded(t *testing.T) {
	customAttrs := []config.CustomAttribute{
		{Name: "nested", Expression: `{"outer": {"inner": "value"}}`},
	}

	compiledExprs, err := compileTestExpressions(customAttrs)
	require.NoError(t, err)

	formatter := &OTELFormatter{
		processMetadata: make(map[uint32]*procmeta.ProcessMetadata),
		customAttrs:     customAttrs,
		compiledExprs:   compiledExprs,
	}

	pid := uint32(10003)
	formatter.processMetadata[pid] = &procmeta.ProcessMetadata{
		Environ:     map[string]string{},
		Args:        []string{},
		CmdlineFull: "",
	}

	attrs, err := formatter.evaluateCustomAttributes(pid)
	require.NoError(t, err)
	assert.Len(t, attrs, 1, "nested map should expand outer key only")

	attrMap := make(map[string]string)
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsString()
	}

	// Nested map should use Go %v format, not be further expanded
	assert.Contains(t, attrMap["nested.outer"], "inner", "nested map should be rendered with Go format")
	assert.Contains(t, attrMap["nested.outer"], "value", "nested map should contain the value")
}

func TestEvaluateCustomAttributes_MapWithArrayValue(t *testing.T) {
	customAttrs := []config.CustomAttribute{
		{Name: "witharray", Expression: `{"simple": "text", "list": ["a", "b", "c"]}`},
	}

	compiledExprs, err := compileTestExpressions(customAttrs)
	require.NoError(t, err)

	formatter := &OTELFormatter{
		processMetadata: make(map[uint32]*procmeta.ProcessMetadata),
		customAttrs:     customAttrs,
		compiledExprs:   compiledExprs,
	}

	pid := uint32(10004)
	formatter.processMetadata[pid] = &procmeta.ProcessMetadata{
		Environ:     map[string]string{},
		Args:        []string{},
		CmdlineFull: "",
	}

	attrs, err := formatter.evaluateCustomAttributes(pid)
	require.NoError(t, err)
	assert.Len(t, attrs, 2, "map with 2 keys should expand to 2 attributes")

	attrMap := make(map[string]string)
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsString()
	}

	assert.Equal(t, "text", attrMap["witharray.simple"])
	// Array value should use Go %v format, not be expanded
	assert.Contains(t, attrMap["witharray.list"], "a", "array should be rendered with Go format")
	assert.Contains(t, attrMap["witharray.list"], "b", "array should contain all elements")
	assert.Contains(t, attrMap["witharray.list"], "c", "array should contain all elements")
}

func TestEvaluateCustomAttributes_FullEnvExpansion(t *testing.T) {
	customAttrs := []config.CustomAttribute{
		{Name: "env", Expression: `env`},
	}

	compiledExprs, err := compileTestExpressions(customAttrs)
	require.NoError(t, err)

	formatter := &OTELFormatter{
		processMetadata: make(map[uint32]*procmeta.ProcessMetadata),
		customAttrs:     customAttrs,
		compiledExprs:   compiledExprs,
	}

	pid := uint32(10005)
	formatter.processMetadata[pid] = &procmeta.ProcessMetadata{
		Environ: map[string]string{
			"PATH":         "/usr/bin:/bin",
			"HOME":         "/home/user",
			"DATABASE_URL": "postgres://localhost/db",
		},
		Args:        []string{},
		CmdlineFull: "",
	}

	attrs, err := formatter.evaluateCustomAttributes(pid)
	require.NoError(t, err)
	assert.Len(t, attrs, 3, "env map with 3 entries should expand to 3 attributes")

	attrMap := make(map[string]string)
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsString()
	}

	assert.Equal(t, "/usr/bin:/bin", attrMap["env.PATH"])
	assert.Equal(t, "/home/user", attrMap["env.HOME"])
	assert.Equal(t, "postgres://localhost/db", attrMap["env.DATABASE_URL"])
}

func TestEvaluateCustomAttributes_TransformedMapViaExpr(t *testing.T) {
	customAttrs := []config.CustomAttribute{
		// Create a new map by selecting specific env vars
		{Name: "db_config", Expression: `{"host": env["DB_HOST"], "port": env["DB_PORT"], "name": env["DB_NAME"]}`},
	}

	compiledExprs, err := compileTestExpressions(customAttrs)
	require.NoError(t, err)

	formatter := &OTELFormatter{
		processMetadata: make(map[uint32]*procmeta.ProcessMetadata),
		customAttrs:     customAttrs,
		compiledExprs:   compiledExprs,
	}

	pid := uint32(10006)
	formatter.processMetadata[pid] = &procmeta.ProcessMetadata{
		Environ: map[string]string{
			"PATH":     "/usr/bin",
			"DB_HOST":  "localhost",
			"DB_PORT":  "5432",
			"DB_NAME":  "mydb",
			"APP_NAME": "myapp",
		},
		Args:        []string{},
		CmdlineFull: "",
	}

	attrs, err := formatter.evaluateCustomAttributes(pid)
	require.NoError(t, err)
	assert.Len(t, attrs, 3, "transformed map should contain 3 selected keys")

	attrMap := make(map[string]string)
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsString()
	}

	assert.Equal(t, "localhost", attrMap["db_config.host"])
	assert.Equal(t, "5432", attrMap["db_config.port"])
	assert.Equal(t, "mydb", attrMap["db_config.name"])
	assert.NotContains(t, attrMap, "db_config.PATH", "PATH should not be included")
	assert.NotContains(t, attrMap, "db_config.APP_NAME", "APP_NAME should not be included")
}

func compileTestExpressions(customAttrs []config.CustomAttribute) ([]*vm.Program, error) {
	compiledExprs := make([]*vm.Program, len(customAttrs))
	for i, attr := range customAttrs {
		env := map[string]interface{}{
			"env":     map[string]string{},
			"args":    []string{},
			"cmdline": "",
		}

		program, err := expr.Compile(attr.Expression, expr.Env(env))
		if err != nil {
			return nil, err
		}
		compiledExprs[i] = program
	}
	return compiledExprs, nil
}
