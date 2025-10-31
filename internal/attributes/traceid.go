package attributes

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/mrzor/process-tracer/internal/procmeta"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// TraceIDEvaluator handles evaluation and validation of trace ID expressions.
type TraceIDEvaluator struct {
	program *vm.Program
	rawExpr string
}

// NewTraceIDEvaluator creates a new trace ID evaluator.
// If exprStr is empty, the evaluator will generate random trace IDs.
func NewTraceIDEvaluator(exprStr string) (*TraceIDEvaluator, error) {
	if exprStr == "" {
		return &TraceIDEvaluator{
			program: nil,
			rawExpr: "",
		}, nil
	}

	// Define the environment for expression type checking
	exprEnv := map[string]interface{}{
		"env":     map[string]string{},
		"args":    []string{},
		"cmdline": "",
	}

	// Compile the expression
	program, err := expr.Compile(exprStr, expr.Env(exprEnv))
	if err != nil {
		return nil, fmt.Errorf("failed to compile trace-id expression: %w", err)
	}

	return &TraceIDEvaluator{
		program: program,
		rawExpr: exprStr,
	}, nil
}

// EvaluateAndValidate evaluates the trace-id expression and validates the result.
// Returns the trace ID, any warnings to attach to the span, and an error.
// If no expression is configured, returns a zero trace ID (caller should generate random).
func (e *TraceIDEvaluator) EvaluateAndValidate(metadata *procmeta.ProcessMetadata) (trace.TraceID, []attribute.KeyValue, error) {
	if e.program == nil {
		// No expression - return zero trace ID (caller should generate random)
		return trace.TraceID{}, nil, nil
	}

	if metadata == nil {
		return trace.TraceID{}, nil, fmt.Errorf("no metadata available")
	}

	// Build evaluation environment
	env := map[string]interface{}{
		"env":     metadata.Environ,
		"args":    metadata.Args,
		"cmdline": metadata.CmdlineFull,
	}

	// Evaluate the expression
	output, err := expr.Run(e.program, env)
	if err != nil {
		return trace.TraceID{}, nil, fmt.Errorf("failed to evaluate trace-id expression: %w", err)
	}

	// Convert output to string
	resultStr := fmt.Sprint(output)
	var warnings []attribute.KeyValue

	// Try to parse as valid trace ID (32 hex chars)
	if len(resultStr) == 32 {
		if traceID, err := trace.TraceIDFromHex(resultStr); err == nil {
			// Valid trace ID - use it directly
			return traceID, warnings, nil
		}
	}

	// Invalid trace ID - hash it with SHA-256 and use first 32 hex chars
	hash := sha256.Sum256([]byte(resultStr))
	hashedTraceIDStr := hex.EncodeToString(hash[:16]) // Use first 16 bytes = 32 hex chars

	traceID, err := trace.TraceIDFromHex(hashedTraceIDStr)
	if err != nil {
		// This should never happen since we control the hash output
		return trace.TraceID{}, nil, fmt.Errorf("failed to create trace ID from hash: %w", err)
	}

	// Add warnings about the conversion
	warnings = append(warnings,
		attribute.String("_trace_id_expr_result", resultStr),
		attribute.String("_trace_id_invalid_warning", fmt.Sprintf("Expression result %q is not a valid 32-char hex trace ID, used SHA-256 hash instead", resultStr)),
	)

	return traceID, warnings, nil
}

// ParentIDEvaluator handles evaluation and validation of parent span ID expressions.
type ParentIDEvaluator struct {
	program *vm.Program
	rawExpr string
}

// NewParentIDEvaluator creates a new parent ID evaluator.
// If exprStr is empty, the evaluator will return no parent ID (zero span ID).
func NewParentIDEvaluator(exprStr string) (*ParentIDEvaluator, error) {
	if exprStr == "" {
		return &ParentIDEvaluator{
			program: nil,
			rawExpr: "",
		}, nil
	}

	// Define the environment for expression type checking
	exprEnv := map[string]interface{}{
		"env":     map[string]string{},
		"args":    []string{},
		"cmdline": "",
	}

	// Compile the expression
	program, err := expr.Compile(exprStr, expr.Env(exprEnv))
	if err != nil {
		return nil, fmt.Errorf("failed to compile parent-id expression: %w", err)
	}

	return &ParentIDEvaluator{
		program: program,
		rawExpr: exprStr,
	}, nil
}

// EvaluateAndValidate evaluates the parent-id expression and validates the result.
// Returns the parent span ID, any warnings to attach to the span, and an error.
// If no expression is configured or the result is invalid, returns zero span ID (no parent).
func (e *ParentIDEvaluator) EvaluateAndValidate(metadata *procmeta.ProcessMetadata) (trace.SpanID, []attribute.KeyValue, error) {
	if e.program == nil {
		// No parent-id expression - return zero span ID (no parent)
		return trace.SpanID{}, nil, nil
	}

	if metadata == nil {
		return trace.SpanID{}, nil, fmt.Errorf("no metadata available")
	}

	// Build evaluation environment
	env := map[string]interface{}{
		"env":     metadata.Environ,
		"args":    metadata.Args,
		"cmdline": metadata.CmdlineFull,
	}

	// Evaluate the expression
	output, err := expr.Run(e.program, env)
	if err != nil {
		return trace.SpanID{}, nil, fmt.Errorf("failed to evaluate parent-id expression: %w", err)
	}

	// Convert output to string
	resultStr := fmt.Sprint(output)
	var warnings []attribute.KeyValue

	// Try to parse as valid span ID (16 hex chars)
	if len(resultStr) == 16 {
		if spanID, err := trace.SpanIDFromHex(resultStr); err == nil {
			// Valid span ID - use it directly
			return spanID, warnings, nil
		}
	}

	// Invalid span ID - use zero span ID (no parent)
	warnings = append(warnings,
		attribute.String("_parent_id_expr_result", resultStr),
		attribute.String("_parent_id_invalid_warning", fmt.Sprintf("Expression result %q is not a valid 16-char hex span ID, using null parent ID instead", resultStr)),
	)

	return trace.SpanID{}, warnings, nil
}
