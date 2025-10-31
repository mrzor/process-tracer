package attributes

import (
	"testing"

	"github.com/mrzor/process-tracer/internal/config"
	"github.com/mrzor/process-tracer/internal/procmeta"
)

func TestEvaluator_Simple(t *testing.T) {
	attrs := []config.CustomAttribute{
		{Name: "test.attr", Expression: `env["FOO"]`},
		{Name: "arg.first", Expression: `args[0]`},
	}

	evaluator, err := NewEvaluator(attrs)
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}

	metadata := &procmeta.ProcessMetadata{
		Environ:     map[string]string{"FOO": "bar", "BAZ": "qux"},
		Args:        []string{"echo", "hello"},
		CmdlineFull: "echo hello",
	}

	result, err := evaluator.EvaluateCustomAttributes(metadata)
	if err != nil {
		t.Fatalf("EvaluateCustomAttributes() error = %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Expected 2 attributes, got %d", len(result))
	}

	// Check first attribute
	if result[0].Key != "test.attr" {
		t.Errorf("result[0].Key = %q, want test.attr", result[0].Key)
	}
	if result[0].Value.AsString() != "bar" {
		t.Errorf("result[0].Value = %q, want bar", result[0].Value.AsString())
	}

	// Check second attribute
	if result[1].Key != "arg.first" {
		t.Errorf("result[1].Key = %q, want arg.first", result[1].Key)
	}
	if result[1].Value.AsString() != "echo" {
		t.Errorf("result[1].Value = %q, want echo", result[1].Value.AsString())
	}
}

func TestEvaluator_MapExpansion(t *testing.T) {
	attrs := []config.CustomAttribute{
		{Name: "expanded", Expression: `env`},
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

	// Should expand to expanded.FOO and expanded.BAZ
	if len(result) != 2 {
		t.Errorf("Expected 2 attributes (map expansion), got %d", len(result))
	}

	// Check that both keys exist with correct prefix
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

func TestEvaluator_InvalidExpression(t *testing.T) {
	attrs := []config.CustomAttribute{
		{Name: "bad", Expression: `invalid syntax here`},
	}

	_, err := NewEvaluator(attrs)
	if err == nil {
		t.Error("Expected error for invalid expression")
	}
}

func TestEvaluator_EvaluationError(t *testing.T) {
	// Expression that will actually fail at runtime (invalid syntax for expr)
	attrs := []config.CustomAttribute{
		{Name: "good", Expression: `env["EXISTS"]`},
		{Name: "bad", Expression: `invalid_function()`}, // This will fail
	}

	_, err := NewEvaluator(attrs)
	// The bad expression should fail at compile time
	if err == nil {
		t.Fatal("Expected error for invalid expression")
	}
}

func TestEvaluator_MissingKey(t *testing.T) {
	// Accessing missing map keys in expr returns empty string, not an error
	attrs := []config.CustomAttribute{
		{Name: "exists", Expression: `env["EXISTS"]`},
		{Name: "missing", Expression: `env["MISSING"]`},
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

	// Should have both attributes (missing key returns empty string)
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
		{Name: "test", Expression: `env["FOO"]`},
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
