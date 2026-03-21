package attributes

import (
	"testing"

	"github.com/mrzor/process-tracer/internal/config"
	"github.com/mrzor/process-tracer/internal/procmeta"
)

func TestParseExprPrefix(t *testing.T) {
	tests := []struct {
		input    string
		wantBody string
		wantExpr bool
	}{
		{"hello", "hello", false},
		{"unknown-unknown-ci", "unknown-unknown-ci", false},
		{"", "", false},
		{`expr:env["FOO"]`, `env["FOO"]`, true},
		{"expr:args[0]", "args[0]", true},
		{"expr:", "", true},              // empty expression body
		{"EXPR:foo", "EXPR:foo", false},  // case sensitive
		{"xexpr:foo", "xexpr:foo", false}, // not a prefix
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			body, isExpr := ParseExprPrefix(tt.input)
			if body != tt.wantBody {
				t.Errorf("ParseExprPrefix(%q) body = %q, want %q", tt.input, body, tt.wantBody)
			}
			if isExpr != tt.wantExpr {
				t.Errorf("ParseExprPrefix(%q) isExpr = %v, want %v", tt.input, isExpr, tt.wantExpr)
			}
		})
	}
}

func TestEvaluator_LiteralValues(t *testing.T) {
	attrs := []config.CustomAttribute{
		{Name: "service.name", Expression: "my-service"},
		{Name: "env.name", Expression: "production"},
		{Name: "with-dashes", Expression: "unknown-unknown-ci"},
	}

	evaluator, err := NewEvaluator(attrs)
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}

	metadata := &procmeta.ProcessMetadata{
		Environ:     map[string]string{},
		Args:        []string{},
		CmdlineFull: "",
	}

	result, err := evaluator.EvaluateCustomAttributes(metadata)
	if err != nil {
		t.Fatalf("EvaluateCustomAttributes() error = %v", err)
	}

	if len(result) != 3 {
		t.Fatalf("Expected 3 attributes, got %d", len(result))
	}

	want := map[string]string{
		"service.name": "my-service",
		"env.name":     "production",
		"with-dashes":  "unknown-unknown-ci",
	}
	for _, attr := range result {
		expected, ok := want[string(attr.Key)]
		if !ok {
			t.Errorf("Unexpected attribute key %q", attr.Key)
			continue
		}
		if attr.Value.AsString() != expected {
			t.Errorf("Attribute %q = %q, want %q", attr.Key, attr.Value.AsString(), expected)
		}
	}
}

func TestEvaluator_ExprValues(t *testing.T) {
	attrs := []config.CustomAttribute{
		{Name: "test.attr", Expression: `expr:env["FOO"]`},
		{Name: "arg.first", Expression: `expr:args[0]`},
	}

	evaluator, err := NewEvaluator(attrs)
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}

	metadata := &procmeta.ProcessMetadata{
		Environ:     map[string]string{"FOO": "bar"},
		Args:        []string{"echo", "hello"},
		CmdlineFull: "echo hello",
	}

	result, err := evaluator.EvaluateCustomAttributes(metadata)
	if err != nil {
		t.Fatalf("EvaluateCustomAttributes() error = %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("Expected 2 attributes, got %d", len(result))
	}

	if result[0].Key != "test.attr" || result[0].Value.AsString() != "bar" {
		t.Errorf("result[0] = (%q, %q), want (test.attr, bar)", result[0].Key, result[0].Value.AsString())
	}
	if result[1].Key != "arg.first" || result[1].Value.AsString() != "echo" {
		t.Errorf("result[1] = (%q, %q), want (arg.first, echo)", result[1].Key, result[1].Value.AsString())
	}
}

func TestEvaluator_MixedLiteralAndExpr(t *testing.T) {
	attrs := []config.CustomAttribute{
		{Name: "literal", Expression: "static-value"},
		{Name: "dynamic", Expression: `expr:env["DYN"]`},
		{Name: "also.literal", Expression: "another-value"},
	}

	evaluator, err := NewEvaluator(attrs)
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}

	metadata := &procmeta.ProcessMetadata{
		Environ:     map[string]string{"DYN": "computed"},
		Args:        []string{},
		CmdlineFull: "",
	}

	result, err := evaluator.EvaluateCustomAttributes(metadata)
	if err != nil {
		t.Fatalf("EvaluateCustomAttributes() error = %v", err)
	}

	if len(result) != 3 {
		t.Fatalf("Expected 3 attributes, got %d", len(result))
	}

	if result[0].Value.AsString() != "static-value" {
		t.Errorf("literal attr = %q, want static-value", result[0].Value.AsString())
	}
	if result[1].Value.AsString() != "computed" {
		t.Errorf("dynamic attr = %q, want computed", result[1].Value.AsString())
	}
	if result[2].Value.AsString() != "another-value" {
		t.Errorf("also.literal attr = %q, want another-value", result[2].Value.AsString())
	}
}

func TestEvaluator_ExprInvalidExpression_WarnAndSkip(t *testing.T) {
	attrs := []config.CustomAttribute{
		{Name: "good", Expression: `expr:env["FOO"]`},
		{Name: "bad", Expression: `expr:invalid syntax here`},
		{Name: "also.good", Expression: "literal-value"},
	}

	evaluator, err := NewEvaluator(attrs)
	if err != nil {
		t.Fatalf("NewEvaluator() should not abort on bad expression, got: %v", err)
	}

	// Only the valid attributes should survive
	if len(evaluator.customAttrs) != 2 {
		t.Fatalf("Expected 2 surviving attributes, got %d", len(evaluator.customAttrs))
	}
	if evaluator.customAttrs[0].Name != "good" {
		t.Errorf("First surviving attr = %q, want good", evaluator.customAttrs[0].Name)
	}
	if evaluator.customAttrs[1].Name != "also.good" {
		t.Errorf("Second surviving attr = %q, want also.good", evaluator.customAttrs[1].Name)
	}
}

func TestEvaluator_MapExpansion(t *testing.T) {
	attrs := []config.CustomAttribute{
		{Name: "expanded", Expression: `expr:env`},
	}

	evaluator, err := NewEvaluator(attrs)
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}

	metadata := &procmeta.ProcessMetadata{
		Environ:     map[string]string{"FOO": "bar", "BAZ": "qux"},
		Args:        []string{},
		CmdlineFull: "",
	}

	result, err := evaluator.EvaluateCustomAttributes(metadata)
	if err != nil {
		t.Fatalf("EvaluateCustomAttributes() error = %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Expected 2 attributes (map expansion), got %d", len(result))
	}

	foundFOO := false
	foundBAZ := false
	for _, attr := range result {
		if attr.Key == "expanded.FOO" && attr.Value.AsString() == "bar" {
			foundFOO = true
		}
		if attr.Key == "expanded.BAZ" && attr.Value.AsString() == "qux" {
			foundBAZ = true
		}
	}

	if !foundFOO {
		t.Error("Missing expanded.FOO attribute")
	}
	if !foundBAZ {
		t.Error("Missing expanded.BAZ attribute")
	}
}

func TestEvaluator_ExprMissingKey(t *testing.T) {
	attrs := []config.CustomAttribute{
		{Name: "exists", Expression: `expr:env["EXISTS"]`},
		{Name: "missing", Expression: `expr:env["MISSING"]`},
	}

	evaluator, err := NewEvaluator(attrs)
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}

	metadata := &procmeta.ProcessMetadata{
		Environ:     map[string]string{"EXISTS": "value"},
		Args:        []string{},
		CmdlineFull: "",
	}

	result, err := evaluator.EvaluateCustomAttributes(metadata)
	if err != nil {
		t.Fatalf("EvaluateCustomAttributes() error = %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Expected 2 attributes, got %d", len(result))
	}
	if result[0].Value.AsString() != "value" {
		t.Errorf("result[0].Value = %q, want value", result[0].Value.AsString())
	}
	if result[1].Value.AsString() != "" {
		t.Errorf("result[1].Value = %q, want empty string", result[1].Value.AsString())
	}
}

func TestEvaluator_NilMetadata(t *testing.T) {
	attrs := []config.CustomAttribute{
		{Name: "test", Expression: `expr:env["FOO"]`},
	}

	evaluator, err := NewEvaluator(attrs)
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}

	result, err := evaluator.EvaluateCustomAttributes(nil)
	if err != nil {
		t.Fatalf("EvaluateCustomAttributes(nil) error = %v", err)
	}

	if result != nil {
		t.Error("Expected nil result for nil metadata")
	}
}

func TestSanitizeAttributeName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{"with-dash", "with_dash"},
		{"with.dot", "with_dot"},
		{"with space", "with_space"},
		{"special!@#$%", "special_____"},
		{"mixed-123.test", "mixed_123_test"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeAttributeName(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeAttributeName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
