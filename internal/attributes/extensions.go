package attributes

import "strings"

// Expr extension functions exposed to user-authored expressions in
// trace_id / parent_id / attribute values. Keep this set small and
// orthogonal: every name added here becomes part of the public config
// surface and document it in README.md (Values and Expressions section).
//
// Conventions:
//   - lowerCamelCase names
//   - prefer string-in / string-out signatures so they compose with `env[...]`
//   - keep semantics obvious from the name; do not overload

// joinNonEmpty joins parts with sep, dropping empty strings. Useful when
// composing an attribute from optional env vars without a leading or
// trailing separator artifact.
//
//	expr:joinNonEmpty("-", env["PROJECT_TYPE"], env["PROJECT_NAME"], "ci")
//	  PROJECT_TYPE="api", PROJECT_NAME="billing" -> "api-billing-ci"
//	  PROJECT_TYPE="",    PROJECT_NAME="billing" -> "billing-ci"
//	  PROJECT_TYPE="",    PROJECT_NAME=""        -> "ci"
func joinNonEmpty(sep string, parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, sep)
}

// extensionFuncs returns the helper functions exposed to expr expressions.
// Merged into both the compile-time env (for type checking) and the
// runtime env (for evaluation) so the same set is visible everywhere.
func extensionFuncs() map[string]interface{} {
	return map[string]interface{}{
		"joinNonEmpty": joinNonEmpty,
	}
}

// withExtensions merges the extension functions into env and returns it.
// Mutates and returns env for ergonomic chaining at the call site.
func withExtensions(env map[string]interface{}) map[string]interface{} {
	for k, v := range extensionFuncs() {
		env[k] = v
	}
	return env
}
