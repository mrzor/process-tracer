package attributes

import (
	"fmt"
	"reflect"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/mrzor/process-tracer/internal/config"
	"github.com/mrzor/process-tracer/internal/procmeta"
	"go.opentelemetry.io/otel/attribute"
)

// Evaluator handles compilation and evaluation of custom attribute expressions.
type Evaluator struct {
	customAttrs   []config.CustomAttribute
	compiledExprs []*vm.Program
}

// NewEvaluator creates a new attribute evaluator.
// It pre-compiles all custom attribute expressions for efficiency.
func NewEvaluator(customAttrs []config.CustomAttribute) (*Evaluator, error) {
	// Define the environment for expression type checking
	exprEnv := map[string]interface{}{
		"env":     map[string]string{},
		"args":    []string{},
		"cmdline": "",
	}

	// Pre-compile custom attribute expressions
	compiledExprs := make([]*vm.Program, len(customAttrs))
	for i, attr := range customAttrs {
		program, err := expr.Compile(attr.Expression, expr.Env(exprEnv))
		if err != nil {
			return nil, fmt.Errorf("failed to compile expression for attribute %q: %w", attr.Name, err)
		}
		compiledExprs[i] = program
	}

	return &Evaluator{
		customAttrs:   customAttrs,
		compiledExprs: compiledExprs,
	}, nil
}

// EvaluateCustomAttributes evaluates custom attribute expressions for a given process metadata.
// This is a pure function that takes immutable metadata and returns evaluated attributes.
func (e *Evaluator) EvaluateCustomAttributes(metadata *procmeta.ProcessMetadata) ([]attribute.KeyValue, error) {
	if len(e.customAttrs) == 0 {
		return nil, nil
	}

	if metadata == nil {
		// No metadata available - return empty
		return nil, nil
	}

	// Build evaluation environment
	env := map[string]interface{}{
		"env":     metadata.Environ,
		"args":    metadata.Args,
		"cmdline": metadata.CmdlineFull,
	}

	var attrs []attribute.KeyValue
	for i, customAttr := range e.customAttrs {
		// Run the pre-compiled program
		output, err := expr.Run(e.compiledExprs[i], env)
		if err != nil {
			// Log error but continue with other attributes
			fmt.Printf("Warning: failed to evaluate expression for attribute %q: %v\n", customAttr.Name, err)
			continue
		}

		// Check if output is a map - if so, expand it into multiple attributes
		outputValue := reflect.ValueOf(output)
		if outputValue.Kind() == reflect.Map {
			// Expand map into separate attributes with dot notation
			for _, key := range outputValue.MapKeys() {
				// Convert key to string and sanitize
				keyStr := fmt.Sprintf("%v", key.Interface())
				sanitizedKey := sanitizeAttributeName(keyStr)
				attrName := customAttr.Name + "." + sanitizedKey

				// Get the value
				value := outputValue.MapIndex(key).Interface()

				// Check if value is a nested map or slice - if so, use %v format
				valueReflect := reflect.ValueOf(value)
				if valueReflect.Kind() == reflect.Map || valueReflect.Kind() == reflect.Slice || valueReflect.Kind() == reflect.Array {
					// Nested structure - use default Go format
					attrs = append(attrs, attribute.String(attrName, fmt.Sprintf("%v", value)))
				} else {
					// Simple value - convert to string
					attrs = append(attrs, attribute.String(attrName, fmt.Sprint(value)))
				}
			}
		} else {
			// Not a map - convert output to string attribute as before
			attrValue := fmt.Sprint(output)
			attrs = append(attrs, attribute.String(customAttr.Name, attrValue))
		}
	}

	return attrs, nil
}

// sanitizeAttributeName replaces non-alphanumeric characters with underscores.
// This ensures attribute names are safe for OpenTelemetry.
func sanitizeAttributeName(name string) string {
	result := make([]byte, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			result[i] = c
		} else {
			result[i] = '_'
		}
	}
	return string(result)
}
