package attributes

import (
	"testing"

	"github.com/mrzor/process-tracer/internal/procmeta"
	"go.opentelemetry.io/otel/trace"
)

// --- TraceID: literal values ---

func TestTraceIDEvaluator_LiteralValidHex(t *testing.T) {
	evaluator, err := NewTraceIDEvaluator("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewTraceIDEvaluator() error = %v", err)
	}

	traceID, warnings, err := evaluator.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if len(warnings) != 0 {
		t.Errorf("Expected no warnings for valid literal trace ID, got %d", len(warnings))
	}

	expected, err := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("TraceIDFromHex() error = %v", err)
	}
	if traceID != expected {
		t.Errorf("traceID = %v, want %v", traceID, expected)
	}
}

func TestTraceIDEvaluator_LiteralInvalidHex(t *testing.T) {
	// Non-hex literal → gets SHA-256 hashed with warnings
	evaluator, err := NewTraceIDEvaluator("my-build-id-123")
	if err != nil {
		t.Fatalf("NewTraceIDEvaluator() error = %v", err)
	}

	traceID, warnings, err := evaluator.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if traceID == (trace.TraceID{}) {
		t.Error("Expected non-zero trace ID (hashed)")
	}

	if len(warnings) != 2 {
		t.Errorf("Expected 2 warnings for invalid literal trace ID, got %d", len(warnings))
	}
}

func TestTraceIDEvaluator_Empty(t *testing.T) {
	evaluator, err := NewTraceIDEvaluator("")
	if err != nil {
		t.Fatalf("NewTraceIDEvaluator(\"\") error = %v", err)
	}

	traceID, warnings, err := evaluator.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if traceID != (trace.TraceID{}) {
		t.Error("Expected zero trace ID when empty")
	}
	if len(warnings) != 0 {
		t.Errorf("Expected no warnings, got %d", len(warnings))
	}
}

// --- TraceID: expr values ---

func TestTraceIDEvaluator_ExprValidHex(t *testing.T) {
	evaluator, err := NewTraceIDEvaluator(`expr:env["TRACE_ID"]`)
	if err != nil {
		t.Fatalf("NewTraceIDEvaluator() error = %v", err)
	}

	metadata := &procmeta.ProcessMetadata{
		Environ:     map[string]string{"TRACE_ID": "0123456789abcdef0123456789abcdef"},
		Args:        []string{},
		CmdlineFull: "",
	}

	traceID, warnings, err := evaluator.EvaluateAndValidate(metadata)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if len(warnings) != 0 {
		t.Errorf("Expected no warnings, got %d", len(warnings))
	}

	expected, err := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("TraceIDFromHex() error = %v", err)
	}
	if traceID != expected {
		t.Errorf("traceID = %v, want %v", traceID, expected)
	}
}

func TestTraceIDEvaluator_ExprInvalidHex(t *testing.T) {
	evaluator, err := NewTraceIDEvaluator(`expr:env["SHORT_ID"]`)
	if err != nil {
		t.Fatalf("NewTraceIDEvaluator() error = %v", err)
	}

	metadata := &procmeta.ProcessMetadata{
		Environ:     map[string]string{"SHORT_ID": "short"},
		Args:        []string{},
		CmdlineFull: "",
	}

	traceID, warnings, err := evaluator.EvaluateAndValidate(metadata)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if traceID == (trace.TraceID{}) {
		t.Error("Expected non-zero trace ID (hashed)")
	}
	if len(warnings) != 2 {
		t.Errorf("Expected 2 warnings, got %d", len(warnings))
	}
}

func TestTraceIDEvaluator_ExprCompileFailure_DefaultsToEmpty(t *testing.T) {
	// Bad expression → warn, behave as if empty (SDK auto-generates)
	evaluator, err := NewTraceIDEvaluator("expr:bad syntax !!!")
	if err != nil {
		t.Fatalf("NewTraceIDEvaluator() should not error, got: %v", err)
	}

	traceID, warnings, err := evaluator.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if traceID != (trace.TraceID{}) {
		t.Error("Expected zero trace ID on compile failure (SDK should auto-generate)")
	}
	if len(warnings) != 0 {
		t.Errorf("Expected no warnings, got %d", len(warnings))
	}
}

// --- ParentID: literal values ---

func TestParentIDEvaluator_LiteralValidHex(t *testing.T) {
	evaluator, err := NewParentIDEvaluator("0123456789abcdef")
	if err != nil {
		t.Fatalf("NewParentIDEvaluator() error = %v", err)
	}

	spanID, warnings, err := evaluator.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if len(warnings) != 0 {
		t.Errorf("Expected no warnings, got %d", len(warnings))
	}

	expected, err := trace.SpanIDFromHex("0123456789abcdef")
	if err != nil {
		t.Fatalf("SpanIDFromHex() error = %v", err)
	}
	if spanID != expected {
		t.Errorf("spanID = %v, want %v", spanID, expected)
	}
}

func TestParentIDEvaluator_LiteralInvalidHex(t *testing.T) {
	evaluator, err := NewParentIDEvaluator("not-valid")
	if err != nil {
		t.Fatalf("NewParentIDEvaluator() error = %v", err)
	}

	spanID, warnings, err := evaluator.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if spanID != (trace.SpanID{}) {
		t.Error("Expected zero span ID for invalid literal")
	}
	if len(warnings) != 2 {
		t.Errorf("Expected 2 warnings, got %d", len(warnings))
	}
}

func TestParentIDEvaluator_Empty(t *testing.T) {
	evaluator, err := NewParentIDEvaluator("")
	if err != nil {
		t.Fatalf("NewParentIDEvaluator(\"\") error = %v", err)
	}

	spanID, warnings, err := evaluator.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if spanID != (trace.SpanID{}) {
		t.Error("Expected zero span ID when empty")
	}
	if len(warnings) != 0 {
		t.Errorf("Expected no warnings, got %d", len(warnings))
	}
}

// --- ParentID: expr values ---

func TestParentIDEvaluator_ExprValidHex(t *testing.T) {
	evaluator, err := NewParentIDEvaluator(`expr:env["PARENT_SPAN_ID"]`)
	if err != nil {
		t.Fatalf("NewParentIDEvaluator() error = %v", err)
	}

	metadata := &procmeta.ProcessMetadata{
		Environ:     map[string]string{"PARENT_SPAN_ID": "0123456789abcdef"},
		Args:        []string{},
		CmdlineFull: "",
	}

	spanID, warnings, err := evaluator.EvaluateAndValidate(metadata)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if len(warnings) != 0 {
		t.Errorf("Expected no warnings, got %d", len(warnings))
	}

	expected, err := trace.SpanIDFromHex("0123456789abcdef")
	if err != nil {
		t.Fatalf("SpanIDFromHex() error = %v", err)
	}
	if spanID != expected {
		t.Errorf("spanID = %v, want %v", spanID, expected)
	}
}

func TestParentIDEvaluator_ExprInvalidHex(t *testing.T) {
	evaluator, err := NewParentIDEvaluator(`expr:env["INVALID_PARENT"]`)
	if err != nil {
		t.Fatalf("NewParentIDEvaluator() error = %v", err)
	}

	metadata := &procmeta.ProcessMetadata{
		Environ:     map[string]string{"INVALID_PARENT": "notvalid"},
		Args:        []string{},
		CmdlineFull: "",
	}

	spanID, warnings, err := evaluator.EvaluateAndValidate(metadata)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if spanID != (trace.SpanID{}) {
		t.Error("Expected zero span ID for invalid parent")
	}
	if len(warnings) != 2 {
		t.Errorf("Expected 2 warnings, got %d", len(warnings))
	}
}

func TestParentIDEvaluator_ExprCompileFailure_DefaultsToEmpty(t *testing.T) {
	// Bad expression → warn, behave as if empty (no parent)
	evaluator, err := NewParentIDEvaluator("expr:bad syntax !!!")
	if err != nil {
		t.Fatalf("NewParentIDEvaluator() should not error, got: %v", err)
	}

	spanID, warnings, err := evaluator.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if spanID != (trace.SpanID{}) {
		t.Error("Expected zero span ID on compile failure")
	}
	if len(warnings) != 0 {
		t.Errorf("Expected no warnings, got %d", len(warnings))
	}
}
