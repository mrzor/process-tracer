// Package attributes provides expression evaluation and validation for custom
// attributes, trace IDs, and parent span IDs.
//
// Expressions are evaluated against process metadata (environment variables,
// command-line arguments) using the expr language.
//
// Three evaluators:
//   - Evaluator: Evaluates custom attribute expressions
//   - TraceIDEvaluator: Evaluates and validates trace ID expressions (32 hex chars)
//   - ParentIDEvaluator: Evaluates and validates parent span ID expressions (16 hex chars)
//
// Invalid trace IDs are automatically hashed with SHA-256 to produce valid IDs.
// Invalid parent IDs result in a null parent (zero span ID).
package attributes
