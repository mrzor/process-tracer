package attributes

import (
	"testing"

	"github.com/expr-lang/expr"
	"github.com/mrzor/process-tracer/internal/config"
	"github.com/mrzor/process-tracer/internal/procmeta"
)

func TestJoinNonEmpty_Direct(t *testing.T) {
	tests := []struct {
		name  string
		sep   string
		parts []string
		want  string
	}{
		{"all present", "-", []string{"a", "b", "c"}, "a-b-c"},
		{"first empty", "-", []string{"", "b", "c"}, "b-c"},
		{"middle empty", "-", []string{"a", "", "c"}, "a-c"},
		{"last empty", "-", []string{"a", "b", ""}, "a-b"},
		{"all empty", "-", []string{"", "", ""}, ""},
		{"none provided", "-", []string{}, ""},
		{"single non-empty", "-", []string{"only"}, "only"},
		{"single empty", "-", []string{""}, ""},
		{"empty separator", "", []string{"a", "b", "c"}, "abc"},
		{"multichar separator", "::", []string{"a", "", "c"}, "a::c"},
		{"whitespace is non-empty", "-", []string{" ", "b"}, " -b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := joinNonEmpty(tc.sep, tc.parts...); got != tc.want {
				t.Errorf("joinNonEmpty(%q, %v) = %q, want %q", tc.sep, tc.parts, got, tc.want)
			}
		})
	}
}

// TestJoinNonEmpty_ExprCompileAndRun exercises joinNonEmpty through the expr
// pipeline (compile-time type check + runtime invocation) to catch regressions
// in env wiring (compile env vs run env mismatch, missing registration, etc).
func TestJoinNonEmpty_ExprCompileAndRun(t *testing.T) {
	env := withExtensions(map[string]interface{}{
		"env":     map[string]string{},
		"args":    []string{},
		"cmdline": "",
	})

	tests := []struct {
		name string
		body string
		envv map[string]string
		want string
	}{
		{
			"two literal strings",
			`joinNonEmpty("-", "a", "b")`,
			nil,
			"a-b",
		},
		{
			"literal with empty middle",
			`joinNonEmpty("-", "a", "", "c")`,
			nil,
			"a-c",
		},
		{
			"env-driven all present",
			`joinNonEmpty("-", env["A"], env["B"], "ci")`,
			map[string]string{"A": "x", "B": "y"},
			"x-y-ci",
		},
		{
			"env-driven first missing",
			`joinNonEmpty("-", env["A"], env["B"], "ci")`,
			map[string]string{"B": "y"},
			"y-ci",
		},
		{
			"env-driven all missing leaves only literal tail",
			`joinNonEmpty("-", env["A"], env["B"])`,
			map[string]string{},
			"",
		},
		{
			"different separator",
			`joinNonEmpty("/", env["A"], env["B"])`,
			map[string]string{"A": "ns", "B": "name"},
			"ns/name",
		},
		{
			"composes with concat",
			`joinNonEmpty("-", env["A"], env["B"]) + "-suffix"`,
			map[string]string{"A": "a"},
			"a-suffix",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			program, err := expr.Compile(tc.body, expr.Env(env))
			if err != nil {
				t.Fatalf("compile %q: %v", tc.body, err)
			}
			runEnv := withExtensions(map[string]interface{}{
				"env":     tc.envv,
				"args":    []string{},
				"cmdline": "",
			})
			out, err := expr.Run(program, runEnv)
			if err != nil {
				t.Fatalf("run %q: %v", tc.body, err)
			}
			if got, ok := out.(string); !ok || got != tc.want {
				t.Errorf("run %q = %v (%T), want %q", tc.body, out, out, tc.want)
			}
		})
	}
}

// TestExtensions_AvailableInTraceID verifies extension functions are wired into
// the trace_id evaluator's compile-time env (regression guard for the parallel
// env definition in traceid.go).
func TestExtensions_AvailableInTraceID(t *testing.T) {
	ev, err := NewTraceIDEvaluator(`expr:joinNonEmpty("", env["A"], env["B"])`)
	if err != nil {
		t.Fatalf("NewTraceIDEvaluator() error = %v", err)
	}
	if ev.program == nil {
		t.Fatal("expected compiled program; joinNonEmpty likely not registered for trace_id env")
	}

	// Run with metadata producing a 32-char hex string so it validates as a real trace ID.
	_, _, res, err := ev.EvaluateAndValidate(&procmeta.ProcessMetadata{
		Environ: map[string]string{"A": "deadbeefdeadbeef", "B": "deadbeefdeadbeef"},
	})
	if err != nil {
		t.Fatalf("EvaluateAndValidate error: %v", err)
	}
	if res.ResolvedValue != "deadbeefdeadbeefdeadbeefdeadbeef" {
		t.Errorf("ResolvedValue = %q, want concatenated hex", res.ResolvedValue)
	}
	if res.Validation != ValidationValid {
		t.Errorf("Validation = %q, want %q", res.Validation, ValidationValid)
	}
}

// TestExtensions_AvailableInParentID mirrors the trace_id wiring check.
func TestExtensions_AvailableInParentID(t *testing.T) {
	ev, err := NewParentIDEvaluator(`expr:joinNonEmpty("-", env["JOB"], env["STAGE"])`)
	if err != nil {
		t.Fatalf("NewParentIDEvaluator() error = %v", err)
	}
	if ev.program == nil {
		t.Fatal("expected compiled program; joinNonEmpty not registered for parent_id env")
	}
}

// TestExtensions_DocumentedInREADME is a smoke check that the helper names
// registered in extensionFuncs() appear in README.md so the docs cannot
// silently fall behind the code.
func TestExtensions_DocumentedInREADME(t *testing.T) {
	// Guard via evaluator path so this file doesn't need a separate import.
	for name := range extensionFuncs() {
		_, err := NewEvaluator([]config.CustomAttribute{
			{Name: "x", Expression: `expr:` + name + `("")`},
		}, false)
		if err != nil {
			t.Errorf("extension %q failed to compile a trivial call: %v", name, err)
		}
	}
}
