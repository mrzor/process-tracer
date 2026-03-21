package attributes

import (
	"fmt"
	"log"
	"reflect"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/mrzor/process-tracer/internal/config"
	"github.com/mrzor/process-tracer/internal/procmeta"
	"go.opentelemetry.io/otel/attribute"
)

const exprPrefix = "expr:"

// ParseExprPrefix checks whether s starts with "expr:" and returns the
// expression body and a boolean indicating expression mode.
// If s does not start with "expr:", it is treated as a literal value.
func ParseExprPrefix(s string) (body string, isExpr bool) {
	if strings.HasPrefix(s, exprPrefix) {
		return s[len(exprPrefix):], true
	}
	return s, false
}

// Evaluator handles compilation and evaluation of custom attribute values.
// Values without the "expr:" prefix are used as literal strings.
// Values with the "expr:" prefix are compiled and evaluated at runtime.
type Evaluator struct {
	customAttrs   []config.CustomAttribute
	compiledExprs []*vm.Program // nil entry = literal value
}

// NewEvaluator creates a new attribute evaluator.
// Literal values (no "expr:" prefix) are stored as-is.
// Expressions ("expr:" prefix) are pre-compiled; invalid ones are warned and skipped.
func NewEvaluator(customAttrs []config.CustomAttribute) (*Evaluator, error) {
	exprEnv := map[string]interface{}{
		"env":     map[string]string{},
		"args":    []string{},
		"cmdline": "",
	}

	var validAttrs []config.CustomAttribute
	var compiledExprs []*vm.Program

	for _, attr := range customAttrs {
		body, isExpr := ParseExprPrefix(attr.Expression)
		if !isExpr {
			// Literal value — no compilation needed
			validAttrs = append(validAttrs, attr)
			compiledExprs = append(compiledExprs, nil)
			continue
		}

		program, err := expr.Compile(body, expr.Env(exprEnv))
		if err != nil {
			log.Printf("Warning: skipping attribute %q: failed to compile expression %q: %v", attr.Name, body, err)
			continue
		}
		validAttrs = append(validAttrs, attr)
		compiledExprs = append(compiledExprs, program)
	}

	return &Evaluator{
		customAttrs:   validAttrs,
		compiledExprs: compiledExprs,
	}, nil
}

// EvaluateCustomAttributes evaluates custom attribute values for a given process metadata.
// Literal attributes are returned as-is. Expression attributes are evaluated at runtime.
func (e *Evaluator) EvaluateCustomAttributes(metadata *procmeta.ProcessMetadata) ([]attribute.KeyValue, error) {
	if len(e.customAttrs) == 0 {
		return nil, nil
	}

	if metadata == nil {
		return nil, nil
	}

	env := map[string]interface{}{
		"env":     metadata.Environ,
		"args":    metadata.Args,
		"cmdline": metadata.CmdlineFull,
	}

	var attrs []attribute.KeyValue
	for i, customAttr := range e.customAttrs {
		program := e.compiledExprs[i]

		if program == nil {
			// Literal value — use the raw expression string (without prefix)
			attrs = append(attrs, attribute.String(customAttr.Name, customAttr.Expression))
			continue
		}

		output, err := expr.Run(program, env)
		if err != nil {
			log.Printf("Warning: failed to evaluate expression for attribute %q: %v", customAttr.Name, err)
			continue
		}

		attrs = appendOutputAttrs(attrs, customAttr.Name, output)
	}

	return attrs, nil
}

// appendOutputAttrs converts an expression output to span attributes.
// Maps are expanded into dot-notation keys; scalars become a single attribute.
func appendOutputAttrs(attrs []attribute.KeyValue, name string, output interface{}) []attribute.KeyValue {
	outputValue := reflect.ValueOf(output)
	if outputValue.Kind() == reflect.Map {
		for _, key := range outputValue.MapKeys() {
			keyStr := fmt.Sprintf("%v", key.Interface())
			sanitizedKey := sanitizeAttributeName(keyStr)
			attrName := name + "." + sanitizedKey

			value := outputValue.MapIndex(key).Interface()
			valueReflect := reflect.ValueOf(value)
			if valueReflect.Kind() == reflect.Map || valueReflect.Kind() == reflect.Slice || valueReflect.Kind() == reflect.Array {
				attrs = append(attrs, attribute.String(attrName, fmt.Sprintf("%v", value)))
			} else {
				attrs = append(attrs, attribute.String(attrName, fmt.Sprint(value)))
			}
		}
	} else {
		attrs = append(attrs, attribute.String(name, fmt.Sprint(output)))
	}
	return attrs
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
