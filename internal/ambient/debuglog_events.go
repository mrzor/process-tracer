package ambient

import (
	"time"

	"github.com/mrzor/process-tracer/internal/attributes"
	"github.com/mrzor/process-tracer/internal/config"
	"github.com/mrzor/process-tracer/internal/envreassembler"
	"github.com/mrzor/process-tracer/internal/procmeta"
	"go.uber.org/zap"
)

// sessionLogFields packages the fields common to every diagnostic event that
// references an existing session. Keep field names stable — downstream jq
// queries depend on them.
//
// session_age_ms is measured from CreatedAt in *this* daemon process. It says
// nothing about prior daemon runs or the backend-observed trace age; a trace
// that's been alive for days in the APM will show a small session_age_ms
// here if the daemon restarted recently. Use trace_expr_value (cross-run
// stable) as the real correlation key; session_age_ms is only useful for
// distinguishing fresh vs. long-lived sessions *within this daemon run*.
func sessionLogFields(s *TraceSession) []zap.Field {
	if s == nil {
		return nil
	}
	ageMs := time.Since(s.CreatedAt).Milliseconds()
	rule := ""
	if s.Rule != nil {
		rule = s.Rule.Name
	}
	return []zap.Field{
		zap.String("session", s.ID),
		zap.String("rule", rule),
		zap.String("trace_id", s.ResolvedTraceID()),
		zap.String("trace_src", s.ResolvedTraceSource()),
		zap.String("trace_expr_value", s.ResolvedTraceExprValue()),
		zap.Int64("session_age_ms", ageMs),
	}
}

// evalRuleTraceIDFromEnv evaluates the given rule's trace_id expression
// against the supplied env snapshot and returns the resolved 32-char hex
// trace ID plus the raw pre-hash value. ok=false means the expression
// couldn't be evaluated (unconfigured, literal, or eval error) — caller
// should skip mismatch logging. Diagnostic-only; errors are swallowed.
func evalRuleTraceIDFromEnv(rule *config.AmbientRule, env *envreassembler.ReassembledData) (traceID, exprValue string, ok bool) {
	if rule == nil || env == nil || rule.TraceID == "" {
		return "", "", false
	}
	evaluator, err := attributes.NewTraceIDEvaluator(rule.TraceID)
	if err != nil {
		return "", "", false
	}
	meta := &procmeta.ProcessMetadata{
		Environ: env.Env,
		Args:    env.Args,
	}
	tid, _, res, err := evaluator.EvaluateAndValidate(meta)
	if err != nil {
		return "", "", false
	}
	if res.Source == attributes.SourceUnconfigured {
		return "", "", false
	}
	if !tid.IsValid() {
		return "", res.ResolvedValue, false
	}
	return tid.String(), res.ResolvedValue, true
}
