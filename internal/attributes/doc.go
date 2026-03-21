// Package attributes provides expression evaluation and validation for custom
// attributes, trace IDs, and parent span IDs.
//
// Values are treated as literal strings by default. To use a dynamic expression
// evaluated against process metadata, prefix the value with "expr:".
//
// Examples:
//
//	"my-service"          → literal string "my-service"
//	"expr:env[\"SVC\"]"   → evaluates env["SVC"] at runtime
//
// Expressions use the [expr] language with the following environment:
//   - env: map[string]string of process environment variables
//   - args: []string of command-line arguments
//   - cmdline: string of the full command line
//
// Three evaluators:
//   - Evaluator: Evaluates custom attribute values (literal or expr)
//   - TraceIDEvaluator: Evaluates and validates trace ID values (32 hex chars)
//   - ParentIDEvaluator: Evaluates and validates parent span ID values (16 hex chars)
//
// Invalid trace IDs are automatically hashed with SHA-256 to produce valid IDs.
// Invalid parent IDs result in a null parent (zero span ID).
//
// [expr]: https://expr-lang.org/
package attributes
