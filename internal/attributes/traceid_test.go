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

	traceID, warnings, res, err := evaluator.EvaluateAndValidate(nil)
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

	if res.Source != SourceLiteral {
		t.Errorf("Source = %q, want %q", res.Source, SourceLiteral)
	}
	if res.Validation != ValidationValid {
		t.Errorf("Validation = %q, want %q", res.Validation, ValidationValid)
	}
	if res.ResolvedValue != "0123456789abcdef0123456789abcdef" {
		t.Errorf("ResolvedValue = %q, want input", res.ResolvedValue)
	}
	if res.Expression != "" {
		t.Errorf("Expression should be empty for literal, got %q", res.Expression)
	}
	if res.Error != "" {
		t.Errorf("Error should be empty, got %q", res.Error)
	}
}

func TestTraceIDEvaluator_LiteralInvalidHex(t *testing.T) {
	// Non-hex literal → gets SHA-256 hashed with warnings
	evaluator, err := NewTraceIDEvaluator("my-build-id-123")
	if err != nil {
		t.Fatalf("NewTraceIDEvaluator() error = %v", err)
	}

	traceID, warnings, res, err := evaluator.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if traceID == (trace.TraceID{}) {
		t.Error("Expected non-zero trace ID (hashed)")
	}

	if len(warnings) != 2 {
		t.Errorf("Expected 2 warnings for invalid literal trace ID, got %d", len(warnings))
	}

	if res.Source != SourceLiteral {
		t.Errorf("Source = %q, want %q", res.Source, SourceLiteral)
	}
	if res.Validation != ValidationHashed {
		t.Errorf("Validation = %q, want %q", res.Validation, ValidationHashed)
	}
	if res.ResolvedValue != "my-build-id-123" {
		t.Errorf("ResolvedValue = %q, want input", res.ResolvedValue)
	}
}

func TestTraceIDEvaluator_LiteralPipelineID(t *testing.T) {
	// Numeric pipeline ID (e.g. GitLab CI_PIPELINE_ID) → SHA-256 hashed to a
	// deterministic 32-char hex trace ID. The expected hash is the first 16
	// bytes of sha256("2775260"), hex-encoded.
	const pipelineID = "2775260"
	const expectedHex = "a65f7926c88f4ab44591d739c425750e"

	evaluator, err := NewTraceIDEvaluator(pipelineID)
	if err != nil {
		t.Fatalf("NewTraceIDEvaluator() error = %v", err)
	}

	traceID, warnings, res, err := evaluator.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	expected, err := trace.TraceIDFromHex(expectedHex)
	if err != nil {
		t.Fatalf("TraceIDFromHex() error = %v", err)
	}
	if traceID != expected {
		t.Errorf("traceID = %s, want %s", traceID, expected)
	}

	if len(warnings) != 2 {
		t.Errorf("Expected 2 warnings for hashed literal, got %d", len(warnings))
	}
	if res.Source != SourceLiteral {
		t.Errorf("Source = %q, want %q", res.Source, SourceLiteral)
	}
	if res.Validation != ValidationHashed {
		t.Errorf("Validation = %q, want %q", res.Validation, ValidationHashed)
	}
	if res.ResolvedValue != pipelineID {
		t.Errorf("ResolvedValue = %q, want %q", res.ResolvedValue, pipelineID)
	}
}

func TestTraceIDEvaluator_ExprResolvesEmptyFallsBackToRandom(t *testing.T) {
	// When an expr trace_id resolves to "", hashing it yields sha256("") and
	// every session collapses onto one poison trace. The fallback path must
	// instead assign a random trace_id, flag the resolution state, and
	// produce warnings pointing at the offending expression.
	evaluator, err := NewTraceIDEvaluator(`expr:env["MISSING_VAR"]`)
	if err != nil {
		t.Fatalf("NewTraceIDEvaluator() error = %v", err)
	}

	meta := &procmeta.ProcessMetadata{Environ: map[string]string{"PATH": "/usr/bin"}}

	tid1, warnings1, res1, err := evaluator.EvaluateAndValidate(meta)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}
	if res1.Validation != ValidationEmptyFallback {
		t.Errorf("Validation = %q, want %q", res1.Validation, ValidationEmptyFallback)
	}
	if res1.ResolvedValue != "" {
		t.Errorf("ResolvedValue = %q, want empty", res1.ResolvedValue)
	}
	if !tid1.IsValid() {
		t.Errorf("expected random trace ID to be valid, got zero")
	}
	// Poison-hash prefix sha256("")[:32] = "e3b0c44298fc1c149afbf4c8996fb924"
	if tid1.String() == "e3b0c44298fc1c149afbf4c8996fb924" {
		t.Errorf("fallback produced the sha256(\"\") collision trace ID")
	}

	foundWarning := false
	foundSource := false
	for _, w := range warnings1 {
		if string(w.Key) == "_trace_id_empty_expr_warning" {
			foundWarning = true
		}
		if string(w.Key) == "_trace_id_source_expr" && w.Value.AsString() == `env["MISSING_VAR"]` {
			foundSource = true
		}
	}
	if !foundWarning || !foundSource {
		t.Errorf("expected warning + source attributes, got %v", warnings1)
	}

	// Distinct calls must produce distinct random IDs (uniqueness across
	// sessions is the whole point of the fallback).
	tid2, _, _, err := evaluator.EvaluateAndValidate(meta)
	if err != nil {
		t.Fatalf("second EvaluateAndValidate() error = %v", err)
	}
	if tid1 == tid2 {
		t.Errorf("two fallback calls produced the same trace ID: %s", tid1)
	}
}

func TestTraceIDEvaluator_Empty(t *testing.T) {
	evaluator, err := NewTraceIDEvaluator("")
	if err != nil {
		t.Fatalf("NewTraceIDEvaluator(\"\") error = %v", err)
	}

	traceID, warnings, res, err := evaluator.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if traceID != (trace.TraceID{}) {
		t.Error("Expected zero trace ID when empty")
	}
	if len(warnings) != 0 {
		t.Errorf("Expected no warnings, got %d", len(warnings))
	}

	if res.Source != SourceUnconfigured {
		t.Errorf("Source = %q, want %q", res.Source, SourceUnconfigured)
	}
	if res.Validation != ValidationNone {
		t.Errorf("Validation = %q, want empty", res.Validation)
	}
	if res.ResolvedValue != "" {
		t.Errorf("ResolvedValue should be empty, got %q", res.ResolvedValue)
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

	traceID, warnings, res, err := evaluator.EvaluateAndValidate(metadata)
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

	if res.Source != SourceExpr {
		t.Errorf("Source = %q, want %q", res.Source, SourceExpr)
	}
	if res.Expression != `env["TRACE_ID"]` {
		t.Errorf("Expression = %q, want the expr body", res.Expression)
	}
	if res.ResolvedValue != "0123456789abcdef0123456789abcdef" {
		t.Errorf("ResolvedValue = %q", res.ResolvedValue)
	}
	if res.Validation != ValidationValid {
		t.Errorf("Validation = %q, want %q", res.Validation, ValidationValid)
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

	traceID, warnings, res, err := evaluator.EvaluateAndValidate(metadata)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if traceID == (trace.TraceID{}) {
		t.Error("Expected non-zero trace ID (hashed)")
	}
	if len(warnings) != 2 {
		t.Errorf("Expected 2 warnings, got %d", len(warnings))
	}

	if res.Source != SourceExpr {
		t.Errorf("Source = %q, want %q", res.Source, SourceExpr)
	}
	if res.Validation != ValidationHashed {
		t.Errorf("Validation = %q, want %q", res.Validation, ValidationHashed)
	}
	if res.ResolvedValue != "short" {
		t.Errorf("ResolvedValue = %q, want %q", res.ResolvedValue, "short")
	}
}

func TestTraceIDEvaluator_ExprRuntimeError(t *testing.T) {
	// Expression that compiles but fails at runtime (nil metadata → no env map).
	evaluator, err := NewTraceIDEvaluator(`expr:env["TRACE_ID"]`)
	if err != nil {
		t.Fatalf("NewTraceIDEvaluator() error = %v", err)
	}

	_, _, res, err := evaluator.EvaluateAndValidate(nil)
	if err == nil {
		t.Fatal("Expected error for nil metadata")
	}
	if res.Source != SourceExpr {
		t.Errorf("Source = %q, want %q", res.Source, SourceExpr)
	}
	if res.Validation != ValidationError {
		t.Errorf("Validation = %q, want %q", res.Validation, ValidationError)
	}
	if res.Error == "" {
		t.Error("Expected non-empty Error field")
	}
}

func TestTraceIDEvaluator_ExprCompileFailure_DefaultsToEmpty(t *testing.T) {
	// Bad expression → warn, behave as if empty (SDK auto-generates)
	evaluator, err := NewTraceIDEvaluator("expr:bad syntax !!!")
	if err != nil {
		t.Fatalf("NewTraceIDEvaluator() should not error, got: %v", err)
	}

	traceID, warnings, res, err := evaluator.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if traceID != (trace.TraceID{}) {
		t.Error("Expected zero trace ID on compile failure (SDK should auto-generate)")
	}
	if len(warnings) != 0 {
		t.Errorf("Expected no warnings, got %d", len(warnings))
	}
	if res.Source != SourceUnconfigured {
		t.Errorf("Source = %q, want %q (compile-failure falls back to empty)", res.Source, SourceUnconfigured)
	}
}

// --- ParentID: literal values ---

func TestParentIDEvaluator_LiteralValidHex(t *testing.T) {
	evaluator, err := NewParentIDEvaluator("0123456789abcdef")
	if err != nil {
		t.Fatalf("NewParentIDEvaluator() error = %v", err)
	}

	spanID, warnings, res, err := evaluator.EvaluateAndValidate(nil)
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

	if res.Source != SourceLiteral {
		t.Errorf("Source = %q, want %q", res.Source, SourceLiteral)
	}
	if res.Validation != ValidationValid {
		t.Errorf("Validation = %q, want %q", res.Validation, ValidationValid)
	}
	if res.ResolvedValue != "0123456789abcdef" {
		t.Errorf("ResolvedValue = %q", res.ResolvedValue)
	}
}

func TestParentIDEvaluator_LiteralInvalidHex(t *testing.T) {
	// Non-hex literal → gets SHA-256 hashed with warnings (like trace ID)
	evaluator, err := NewParentIDEvaluator("not-valid")
	if err != nil {
		t.Fatalf("NewParentIDEvaluator() error = %v", err)
	}

	spanID, warnings, res, err := evaluator.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if spanID == (trace.SpanID{}) {
		t.Error("Expected non-zero span ID (hashed)")
	}
	if len(warnings) != 2 {
		t.Errorf("Expected 2 warnings, got %d", len(warnings))
	}

	if res.Source != SourceLiteral {
		t.Errorf("Source = %q, want %q", res.Source, SourceLiteral)
	}
	if res.Validation != ValidationHashed {
		t.Errorf("Validation = %q, want %q", res.Validation, ValidationHashed)
	}
	if res.ResolvedValue != "not-valid" {
		t.Errorf("ResolvedValue = %q", res.ResolvedValue)
	}
}

func TestParentIDEvaluator_Empty(t *testing.T) {
	evaluator, err := NewParentIDEvaluator("")
	if err != nil {
		t.Fatalf("NewParentIDEvaluator(\"\") error = %v", err)
	}

	spanID, warnings, res, err := evaluator.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if spanID != (trace.SpanID{}) {
		t.Error("Expected zero span ID when empty")
	}
	if len(warnings) != 0 {
		t.Errorf("Expected no warnings, got %d", len(warnings))
	}

	if res.Source != SourceUnconfigured {
		t.Errorf("Source = %q, want %q", res.Source, SourceUnconfigured)
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

	spanID, warnings, res, err := evaluator.EvaluateAndValidate(metadata)
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

	if res.Source != SourceExpr {
		t.Errorf("Source = %q, want %q", res.Source, SourceExpr)
	}
	if res.Expression != `env["PARENT_SPAN_ID"]` {
		t.Errorf("Expression = %q", res.Expression)
	}
	if res.Validation != ValidationValid {
		t.Errorf("Validation = %q, want %q", res.Validation, ValidationValid)
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

	spanID, warnings, res, err := evaluator.EvaluateAndValidate(metadata)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if spanID == (trace.SpanID{}) {
		t.Error("Expected non-zero span ID (hashed)")
	}
	if len(warnings) != 2 {
		t.Errorf("Expected 2 warnings, got %d", len(warnings))
	}

	if res.Validation != ValidationHashed {
		t.Errorf("Validation = %q, want %q", res.Validation, ValidationHashed)
	}
	if res.ResolvedValue != "notvalid" {
		t.Errorf("ResolvedValue = %q", res.ResolvedValue)
	}
}

func TestParentIDEvaluator_ExprRuntimeError(t *testing.T) {
	evaluator, err := NewParentIDEvaluator(`expr:env["PARENT_SPAN_ID"]`)
	if err != nil {
		t.Fatalf("NewParentIDEvaluator() error = %v", err)
	}

	_, _, res, err := evaluator.EvaluateAndValidate(nil)
	if err == nil {
		t.Fatal("Expected error for nil metadata")
	}
	if res.Validation != ValidationError {
		t.Errorf("Validation = %q, want %q", res.Validation, ValidationError)
	}
	if res.Error == "" {
		t.Error("Expected non-empty Error field")
	}
}

func TestParentIDEvaluator_ExprCompileFailure_DefaultsToEmpty(t *testing.T) {
	// Bad expression → warn, behave as if empty (no parent)
	evaluator, err := NewParentIDEvaluator("expr:bad syntax !!!")
	if err != nil {
		t.Fatalf("NewParentIDEvaluator() should not error, got: %v", err)
	}

	spanID, warnings, res, err := evaluator.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if spanID != (trace.SpanID{}) {
		t.Error("Expected zero span ID on compile failure")
	}
	if len(warnings) != 0 {
		t.Errorf("Expected no warnings, got %d", len(warnings))
	}
	if res.Source != SourceUnconfigured {
		t.Errorf("Source = %q, want %q", res.Source, SourceUnconfigured)
	}
}

// --- ParentID: hash fallback behavior ---

func TestParentIDEvaluator_HashDeterminism(t *testing.T) {
	// Same non-hex input evaluated twice must produce identical SpanIDs.
	eval1, err := NewParentIDEvaluator("my-job-id")
	if err != nil {
		t.Fatalf("NewParentIDEvaluator() error = %v", err)
	}
	eval2, err := NewParentIDEvaluator("my-job-id")
	if err != nil {
		t.Fatalf("NewParentIDEvaluator() error = %v", err)
	}

	id1, _, _, err := eval1.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}
	id2, _, _, err := eval2.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if id1 != id2 {
		t.Errorf("hash not deterministic: %v != %v", id1, id2)
	}
	if id1 == (trace.SpanID{}) {
		t.Error("Expected non-zero hashed span ID")
	}
}

func TestParentIDEvaluator_HashExpectedValue(t *testing.T) {
	// Verify the hash of a known input matches sha256("12345")[:8] as hex.
	evaluator, err := NewParentIDEvaluator("12345")
	if err != nil {
		t.Fatalf("NewParentIDEvaluator() error = %v", err)
	}
	spanID, _, res, err := evaluator.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	// sha256("12345") = 5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5
	// first 8 bytes hex = 5994471abb01112a
	expected, err := trace.SpanIDFromHex("5994471abb01112a")
	if err != nil {
		t.Fatalf("SpanIDFromHex() error = %v", err)
	}
	if spanID != expected {
		t.Errorf("spanID = %x, want %x", spanID, expected)
	}
	if res.Validation != ValidationHashed {
		t.Errorf("Validation = %q, want %q", res.Validation, ValidationHashed)
	}
}

func TestParentIDEvaluator_DifferentInputsDifferentHashes(t *testing.T) {
	eval1, err := NewParentIDEvaluator("job-100")
	if err != nil {
		t.Fatalf("NewParentIDEvaluator() error = %v", err)
	}
	eval2, err := NewParentIDEvaluator("job-200")
	if err != nil {
		t.Fatalf("NewParentIDEvaluator() error = %v", err)
	}

	id1, _, _, err := eval1.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}
	id2, _, _, err := eval2.EvaluateAndValidate(nil)
	if err != nil {
		t.Fatalf("EvaluateAndValidate() error = %v", err)
	}

	if id1 == id2 {
		t.Errorf("different inputs produced same hash: %v", id1)
	}
}
