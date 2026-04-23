package attributes

import (
	"crypto/rand"
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

// Source values for TraceIDResolution and ParentIDResolution.
const (
	SourceUnconfigured = "unconfigured"
	SourceLiteral      = "literal"
	SourceExpr         = "expr"
)

// Validation values.
const (
	ValidationNone          = ""               // unconfigured
	ValidationValid         = "valid"          // parsed as proper hex ID
	ValidationHashed        = "hashed"         // invalid hex, SHA-256 fallback used (both trace ID and parent ID)
	ValidationInvalid       = "invalid"        // deprecated: parent ID now uses ValidationHashed like trace ID
	ValidationError         = "error"          // expression evaluation failed
	ValidationEmptyFallback = "empty_fallback" // expr evaluated to empty string; random ID assigned to avoid sha256("") collision
)

// TraceIDResolution records how a trace ID was derived, for debugging.
type TraceIDResolution struct {
	Source        string // one of SourceUnconfigured, SourceLiteral, SourceExpr
	Expression    string // expr body (only when Source == SourceExpr)
	ResolvedValue string // post-evaluation, pre-validation string (only when Source != SourceUnconfigured)
	Validation    string // one of ValidationNone, ValidationValid, ValidationHashed, ValidationError
	Error         string // non-empty when Validation == ValidationError
}

// ParentIDResolution records how a parent span ID was derived, for debugging.
type ParentIDResolution struct {
	Source        string // one of SourceUnconfigured, SourceLiteral, SourceExpr
	Expression    string // expr body (only when Source == SourceExpr)
	ResolvedValue string // post-evaluation, pre-validation string (only when Source != SourceUnconfigured)
	Validation    string // one of ValidationNone, ValidationValid, ValidationHashed, ValidationError
	Error         string // non-empty when Validation == ValidationError
}

// exprEnvTemplate is the type-checking environment for expr compilation.
var exprEnvTemplate = map[string]interface{}{
	"env":     map[string]string{},
	"args":    []string{},
	"cmdline": "",
}

// compileExprValue parses a value that may have an "expr:" prefix.
// Returns (program, literal, exprBody, error):
//   - empty value → (nil, "", "", nil)
//   - literal → (nil, value, "", nil)
//   - "expr:..." compiled OK → (program, "", body, nil)
//   - "expr:..." compile fail → (nil, "", body, err)
func compileExprValue(value string) (*vm.Program, string, string, error) {
	if value == "" {
		return nil, "", "", nil
	}

	body, isExpr := ParseExprPrefix(value)
	if !isExpr {
		return nil, body, "", nil
	}

	program, err := expr.Compile(body, expr.Env(exprEnvTemplate))
	if err != nil {
		return nil, "", body, err
	}

	return program, "", body, nil
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
	program    *vm.Program // nil when literal or empty
	literal    string      // non-empty when using a literal value
	expression string      // the raw expr body (non-empty when program != nil)
}

// NewTraceIDEvaluator creates a new trace ID evaluator.
// Empty string → SDK auto-generates random trace IDs.
// "expr:..." → compile expression; on failure, warn and behave as empty.
// Otherwise → treat as literal trace ID string.
func NewTraceIDEvaluator(value string) (*TraceIDEvaluator, error) {
	program, literal, body, err := compileExprValue(value)
	if err != nil {
		log.Printf("Warning: failed to compile trace-id expression, using auto-generated trace ID: %v", err)
		return &TraceIDEvaluator{}, nil
	}
	return &TraceIDEvaluator{program: program, literal: literal, expression: body}, nil
}

// EvaluateAndValidate evaluates the trace-id value and validates the result.
// Returns the trace ID, any warnings to attach to the span, a Resolution describing
// how the ID was derived (for debug attributes), and an error.
// If unconfigured, returns a zero trace ID (caller should generate random).
func (e *TraceIDEvaluator) EvaluateAndValidate(metadata *procmeta.ProcessMetadata) (trace.TraceID, []attribute.KeyValue, TraceIDResolution, error) {
	if e.program == nil && e.literal == "" {
		return trace.TraceID{}, nil, TraceIDResolution{Source: SourceUnconfigured}, nil
	}

	var resultStr string
	var res TraceIDResolution
	if e.program != nil {
		res.Source = SourceExpr
		res.Expression = e.expression
		s, err := evaluateProgram(e.program, metadata)
		if err != nil {
			res.Validation = ValidationError
			res.Error = err.Error()
			return trace.TraceID{}, nil, res, fmt.Errorf("failed to evaluate trace-id expression: %w", err)
		}
		resultStr = s
	} else {
		res.Source = SourceLiteral
		resultStr = e.literal
	}
	res.ResolvedValue = resultStr

	// Empty-expr safety net: if the expression ran but produced "", hashing
	// it yields a well-known collision (sha256("")) that would collapse every
	// such session into one poisoned trace. Instead, generate a random trace
	// ID so each session lands in its own orphan trace and is greppable via
	// the warning attributes we attach. Literal empty strings fall through to
	// the old hashing behavior — that's a direct rule-author decision.
	if resultStr == "" && e.program != nil {
		tid, warnings, emptyErr := randomTraceIDForEmptyExpr(e.expression)
		if emptyErr != nil {
			res.Validation = ValidationError
			res.Error = emptyErr.Error()
			return trace.TraceID{}, nil, res, emptyErr
		}
		res.Validation = ValidationEmptyFallback
		return tid, warnings, res, nil
	}

	traceID, warnings, err := validateTraceID(resultStr)
	if err != nil {
		res.Validation = ValidationError
		res.Error = err.Error()
		return traceID, warnings, res, err
	}
	if len(warnings) > 0 {
		res.Validation = ValidationHashed
	} else {
		res.Validation = ValidationValid
	}
	return traceID, warnings, res, nil
}

// randomTraceIDForEmptyExpr generates a random 16-byte trace ID for the case
// where an expr-based trace_id resolved to the empty string. Returns warning
// attributes that identify the offending expression so operators can find the
// misconfigured rule from any span in the resulting (orphaned) trace.
func randomTraceIDForEmptyExpr(expression string) (trace.TraceID, []attribute.KeyValue, error) {
	var tid trace.TraceID
	if _, err := rand.Read(tid[:]); err != nil {
		return trace.TraceID{}, nil, fmt.Errorf("randomizing fallback trace ID: %w", err)
	}
	warnings := []attribute.KeyValue{
		attribute.String("_trace_id_empty_expr_warning",
			fmt.Sprintf("expression %q resolved to empty string; random trace_id assigned to avoid sha256(\"\") collision", expression)),
		attribute.String("_trace_id_source_expr", expression),
	}
	return tid, warnings, nil
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
	program    *vm.Program // nil when literal or empty
	literal    string      // non-empty when using a literal value
	expression string      // the raw expr body (non-empty when program != nil)
}

// NewParentIDEvaluator creates a new parent ID evaluator.
// Empty string → no parent (zero span ID).
// "expr:..." → compile expression; on failure, warn and behave as empty.
// Otherwise → treat as literal span ID string.
func NewParentIDEvaluator(value string) (*ParentIDEvaluator, error) {
	program, literal, body, err := compileExprValue(value)
	if err != nil {
		log.Printf("Warning: failed to compile parent-id expression, using no parent: %v", err)
		return &ParentIDEvaluator{}, nil
	}
	return &ParentIDEvaluator{program: program, literal: literal, expression: body}, nil
}

// EvaluateAndValidate evaluates the parent-id value and validates the result.
// Returns the parent span ID, any warnings to attach to the span, a Resolution
// describing how the ID was derived (for debug attributes), and an error.
// If unconfigured, returns zero span ID (no parent). If the value is not valid
// 16-char hex, it is SHA-256 hashed to produce a deterministic SpanID.
func (e *ParentIDEvaluator) EvaluateAndValidate(metadata *procmeta.ProcessMetadata) (trace.SpanID, []attribute.KeyValue, ParentIDResolution, error) {
	if e.program == nil && e.literal == "" {
		return trace.SpanID{}, nil, ParentIDResolution{Source: SourceUnconfigured}, nil
	}

	var resultStr string
	var res ParentIDResolution
	if e.program != nil {
		res.Source = SourceExpr
		res.Expression = e.expression
		s, err := evaluateProgram(e.program, metadata)
		if err != nil {
			res.Validation = ValidationError
			res.Error = err.Error()
			return trace.SpanID{}, nil, res, fmt.Errorf("failed to evaluate parent-id expression: %w", err)
		}
		resultStr = s
	} else {
		res.Source = SourceLiteral
		resultStr = e.literal
	}
	res.ResolvedValue = resultStr

	spanID, warnings, err := validateParentID(resultStr)
	if err != nil {
		res.Validation = ValidationError
		res.Error = err.Error()
		return spanID, warnings, res, err
	}
	if len(warnings) > 0 {
		res.Validation = ValidationHashed
	} else {
		res.Validation = ValidationValid
	}
	return spanID, warnings, res, nil
}

// validateParentID checks whether resultStr is a valid 16-char hex span ID.
// If not, it hashes the string with SHA-256 and returns warnings.
func validateParentID(resultStr string) (trace.SpanID, []attribute.KeyValue, error) {
	if len(resultStr) == 16 {
		if spanID, err := trace.SpanIDFromHex(resultStr); err == nil {
			return spanID, nil, nil
		}
	}

	// Invalid span ID — hash with SHA-256
	hash := sha256.Sum256([]byte(resultStr))
	hashedSpanIDStr := hex.EncodeToString(hash[:8])

	spanID, err := trace.SpanIDFromHex(hashedSpanIDStr)
	if err != nil {
		return trace.SpanID{}, nil, fmt.Errorf("failed to create span ID from hash: %w", err)
	}

	warnings := []attribute.KeyValue{
		attribute.String("_parent_id_expr_result", resultStr),
		attribute.String("_parent_id_invalid_warning", fmt.Sprintf("Value %q is not a valid 16-char hex span ID, used SHA-256 hash instead", resultStr)),
	}

	return spanID, warnings, nil
}
