package attributes

import (
	"testing"

	"github.com/mrzor/process-tracer/internal/procmeta"
	"go.opentelemetry.io/otel/trace"
)

func TestTraceIDEvaluator_ValidHex(t *testing.T) {
	evaluator, err := NewTraceIDEvaluator(`env["TRACE_ID"]`)
	if err != nil {
		t.Fatalf("NewTraceIDEvaluator() error = %v", err)
	}

	metadata := &procmeta.ProcessMetadata{
		Environ: map[string]string{
			"TRACE_ID": "0123456789abcdef0123456789abcdef",
		},
		Args:        []string{},
		CmdlineFull: "",
	}

	traceID, warnings, err := evaluator.EvaluateAndValidate(metadata)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	// Should be valid with no warnings
	if len(warnings) != 0 {
		t.Errorf("Expected no warnings for valid trace ID, got %d", len(warnings))
	}

	expectedTraceID, err := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("trace.TraceIDFromHex() error = %v", err)
	}
	if traceID != expectedTraceID {
		t.Errorf("traceID = %v, want %v", traceID, expectedTraceID)
	}
}

func TestTraceIDEvaluator_InvalidHex(t *testing.T) {
	evaluator, err := NewTraceIDEvaluator(`env["SHORT_ID"]`)
	if err != nil {
		t.Fatalf("NewTraceIDEvaluator() error = %v", err)
	}

	metadata := &procmeta.ProcessMetadata{
		Environ: map[string]string{
			"SHORT_ID": "short",
		},
		Args:        []string{},
		CmdlineFull: "",
	}

	traceID, warnings, err := evaluator.EvaluateAndValidate(metadata)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	// Should hash the value and produce warnings
	if len(warnings) != 2 {
		t.Errorf("Expected 2 warnings for invalid trace ID, got %d", len(warnings))
	}

	// Trace ID should not be zero (it's hashed)
	if traceID == (trace.TraceID{}) {
		t.Error("Expected non-zero trace ID (hashed)")
	}

	// Check warnings contain expected keys
	foundResult := false
	foundWarning := false
	for _, w := range warnings {
		if w.Key == "_trace_id_expr_result" {
			foundResult = true
			if w.Value.AsString() != "short" {
				t.Errorf("_trace_id_expr_result = %q, want short", w.Value.AsString())
			}
		}
		if w.Key == "_trace_id_invalid_warning" {
			foundWarning = true
		}
	}
	if !foundResult {
		t.Error("Missing _trace_id_expr_result warning")
	}
	if !foundWarning {
		t.Error("Missing _trace_id_invalid_warning warning")
	}
}

func TestTraceIDEvaluator_NoExpression(t *testing.T) {
	evaluator, err := NewTraceIDEvaluator("")
	if err != nil {
		t.Fatalf("NewTraceIDEvaluator(\"\") error = %v", err)
	}

	metadata := &procmeta.ProcessMetadata{
		Environ:     map[string]string{},
		Args:        []string{},
		CmdlineFull: "",
	}

	traceID, warnings, err := evaluator.EvaluateAndValidate(metadata)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	// Should return zero trace ID (caller will generate random)
	if traceID != (trace.TraceID{}) {
		t.Error("Expected zero trace ID when no expression is configured")
	}

	if len(warnings) != 0 {
		t.Errorf("Expected no warnings, got %d", len(warnings))
	}
}

func TestParentIDEvaluator_ValidHex(t *testing.T) {
	evaluator, err := NewParentIDEvaluator(`env["PARENT_SPAN_ID"]`)
	if err != nil {
		t.Fatalf("NewParentIDEvaluator() error = %v", err)
	}

	metadata := &procmeta.ProcessMetadata{
		Environ: map[string]string{
			"PARENT_SPAN_ID": "0123456789abcdef",
		},
		Args:        []string{},
		CmdlineFull: "",
	}

	spanID, warnings, err := evaluator.EvaluateAndValidate(metadata)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	// Should be valid with no warnings
	if len(warnings) != 0 {
		t.Errorf("Expected no warnings for valid span ID, got %d", len(warnings))
	}

	expectedSpanID, err := trace.SpanIDFromHex("0123456789abcdef")
	if err != nil {
		t.Fatalf("trace.SpanIDFromHex() error = %v", err)
	}
	if spanID != expectedSpanID {
		t.Errorf("spanID = %v, want %v", spanID, expectedSpanID)
	}
}

func TestParentIDEvaluator_InvalidHex(t *testing.T) {
	evaluator, err := NewParentIDEvaluator(`env["INVALID_PARENT"]`)
	if err != nil {
		t.Fatalf("NewParentIDEvaluator() error = %v", err)
	}

	metadata := &procmeta.ProcessMetadata{
		Environ: map[string]string{
			"INVALID_PARENT": "notvalid",
		},
		Args:        []string{},
		CmdlineFull: "",
	}

	spanID, warnings, err := evaluator.EvaluateAndValidate(metadata)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	// Should return zero span ID (no parent) with warnings
	if spanID != (trace.SpanID{}) {
		t.Error("Expected zero span ID for invalid parent")
	}

	if len(warnings) != 2 {
		t.Errorf("Expected 2 warnings for invalid parent ID, got %d", len(warnings))
	}
}

func TestParentIDEvaluator_NoExpression(t *testing.T) {
	evaluator, err := NewParentIDEvaluator("")
	if err != nil {
		t.Fatalf("NewParentIDEvaluator(\"\") error = %v", err)
	}

	metadata := &procmeta.ProcessMetadata{
		Environ:     map[string]string{},
		Args:        []string{},
		CmdlineFull: "",
	}

	spanID, warnings, err := evaluator.EvaluateAndValidate(metadata)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	// Should return zero span ID (no parent)
	if spanID != (trace.SpanID{}) {
		t.Error("Expected zero span ID when no expression is configured")
	}

	if len(warnings) != 0 {
		t.Errorf("Expected no warnings, got %d", len(warnings))
	}
}
