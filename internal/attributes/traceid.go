package attributes

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/mrzor/process-tracer/internal/procmeta"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// exprEnvTemplate is the type-checking environment for expr compilation.
var exprEnvTemplate = map[string]interface{}{
	"env":     map[string]string{},
	"args":    []string{},
	"cmdline": "",
}

// compileExprValue parses a value that may have an "expr:" prefix.
// Returns (program, literal, error):
//   - empty value → (nil, "", nil)
//   - literal → (nil, value, nil)
//   - "expr:..." compiled OK → (program, "", nil)
//   - "expr:..." compile fail → (nil, "", err)
func compileExprValue(value string) (*vm.Program, string, error) {
	if value == "" {
		return nil, "", nil
	}

	body, isExpr := ParseExprPrefix(value)
	if !isExpr {
		return nil, body, nil
	}

	program, err := expr.Compile(body, expr.Env(exprEnvTemplate))
	if err != nil {
		return nil, "", err
	}

	return program, "", nil
}

// evaluateProgram runs a compiled expr program against process metadata.
func evaluateProgram(program *vm.Program, metadata *procmeta.ProcessMetadata) (string, error) {
	if metadata == nil {
		return "", fmt.Errorf("no metadata available")
	}
	env := map[string]interface{}{
		"env":     metadata.Environ,
		"args":    metadata.Args,
		"cmdline": metadata.CmdlineFull,
	}
	output, err := expr.Run(program, env)
	if err != nil {
		return "", err
	}
	return fmt.Sprint(output), nil
}

// TraceIDEvaluator handles evaluation and validation of trace ID values.
// Without the "expr:" prefix, the value is treated as a literal trace ID string.
// With the "expr:" prefix, the value is compiled and evaluated at runtime.
type TraceIDEvaluator struct {
	program *vm.Program // nil when literal or empty
	literal string      // non-empty when using a literal value
}

// NewTraceIDEvaluator creates a new trace ID evaluator.
// Empty string → SDK auto-generates random trace IDs.
// "expr:..." → compile expression; on failure, warn and behave as empty.
// Otherwise → treat as literal trace ID string.
func NewTraceIDEvaluator(value string) (*TraceIDEvaluator, error) {
	program, literal, err := compileExprValue(value)
	if err != nil {
		log.Printf("Warning: failed to compile trace-id expression, using auto-generated trace ID: %v", err)
		return &TraceIDEvaluator{}, nil
	}
	return &TraceIDEvaluator{program: program, literal: literal}, nil
}

// EvaluateAndValidate evaluates the trace-id value and validates the result.
// Returns the trace ID, any warnings to attach to the span, and an error.
// If unconfigured, returns a zero trace ID (caller should generate random).
func (e *TraceIDEvaluator) EvaluateAndValidate(metadata *procmeta.ProcessMetadata) (trace.TraceID, []attribute.KeyValue, error) {
	if e.program == nil && e.literal == "" {
		return trace.TraceID{}, nil, nil
	}

	var resultStr string
	if e.program != nil {
		s, err := evaluateProgram(e.program, metadata)
		if err != nil {
			return trace.TraceID{}, nil, fmt.Errorf("failed to evaluate trace-id expression: %w", err)
		}
		resultStr = s
	} else {
		resultStr = e.literal
	}

	return validateTraceID(resultStr)
}

// validateTraceID checks whether resultStr is a valid 32-char hex trace ID.
// If not, it hashes the string with SHA-256 and returns warnings.
func validateTraceID(resultStr string) (trace.TraceID, []attribute.KeyValue, error) {
	if len(resultStr) == 32 {
		if traceID, err := trace.TraceIDFromHex(resultStr); err == nil {
			return traceID, nil, nil
		}
	}

	// Invalid trace ID — hash with SHA-256
	hash := sha256.Sum256([]byte(resultStr))
	hashedTraceIDStr := hex.EncodeToString(hash[:16])

	traceID, err := trace.TraceIDFromHex(hashedTraceIDStr)
	if err != nil {
		return trace.TraceID{}, nil, fmt.Errorf("failed to create trace ID from hash: %w", err)
	}

	warnings := []attribute.KeyValue{
		attribute.String("_trace_id_expr_result", resultStr),
		attribute.String("_trace_id_invalid_warning", fmt.Sprintf("Value %q is not a valid 32-char hex trace ID, used SHA-256 hash instead", resultStr)),
	}

	return traceID, warnings, nil
}

// ParentIDEvaluator handles evaluation and validation of parent span ID values.
// Without the "expr:" prefix, the value is treated as a literal span ID string.
// With the "expr:" prefix, the value is compiled and evaluated at runtime.
type ParentIDEvaluator struct {
	program *vm.Program // nil when literal or empty
	literal string      // non-empty when using a literal value
}

// NewParentIDEvaluator creates a new parent ID evaluator.
// Empty string → no parent (zero span ID).
// "expr:..." → compile expression; on failure, warn and behave as empty.
// Otherwise → treat as literal span ID string.
func NewParentIDEvaluator(value string) (*ParentIDEvaluator, error) {
	program, literal, err := compileExprValue(value)
	if err != nil {
		log.Printf("Warning: failed to compile parent-id expression, using no parent: %v", err)
		return &ParentIDEvaluator{}, nil
	}
	return &ParentIDEvaluator{program: program, literal: literal}, nil
}

// EvaluateAndValidate evaluates the parent-id value and validates the result.
// Returns the parent span ID, any warnings to attach to the span, and an error.
// If unconfigured or invalid, returns zero span ID (no parent).
func (e *ParentIDEvaluator) EvaluateAndValidate(metadata *procmeta.ProcessMetadata) (trace.SpanID, []attribute.KeyValue, error) {
	if e.program == nil && e.literal == "" {
		return trace.SpanID{}, nil, nil
	}

	var resultStr string
	if e.program != nil {
		s, err := evaluateProgram(e.program, metadata)
		if err != nil {
			return trace.SpanID{}, nil, fmt.Errorf("failed to evaluate parent-id expression: %w", err)
		}
		resultStr = s
	} else {
		resultStr = e.literal
	}

	// Try to parse as valid span ID (16 hex chars)
	if len(resultStr) == 16 {
		if spanID, err := trace.SpanIDFromHex(resultStr); err == nil {
			return spanID, nil, nil
		}
	}

	warnings := []attribute.KeyValue{
		attribute.String("_parent_id_expr_result", resultStr),
		attribute.String("_parent_id_invalid_warning", fmt.Sprintf("Value %q is not a valid 16-char hex span ID, using null parent ID instead", resultStr)),
	}

	return trace.SpanID{}, warnings, nil
}
