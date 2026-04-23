package ambient

import (
	"sort"
	"strings"
	"time"

	"github.com/mrzor/process-tracer/internal/attributes"
	"github.com/mrzor/process-tracer/internal/config"
	"github.com/mrzor/process-tracer/internal/envreassembler"
	"github.com/mrzor/process-tracer/internal/procmeta"
	"go.uber.org/zap"
)

// enrichExecUnclaimed returns zap fields that describe the exec payload
// for a process that fell through every ambient-routing path. Caller
// must have already pulled envData from pendingEnv; nil env is a no-op.
// Values are bounded to prevent debug-log bloat on long argv / envp.
func enrichExecUnclaimed(envData *envreassembler.ReassembledData) []zap.Field {
	if envData == nil {
		return nil
	}
	const maxArgs = 8
	const maxEnvKeys = 32

	args := envData.Args
	if len(args) > maxArgs {
		args = args[:maxArgs]
	}
	var exe string
	if len(envData.Args) > 0 {
		exe = envData.Args[0]
	}

	envKeys := make([]string, 0, maxEnvKeys)
	for k := range envData.Env {
		envKeys = append(envKeys, k)
		if len(envKeys) >= maxEnvKeys {
			break
		}
	}
	sort.Strings(envKeys)

	return []zap.Field{
		zap.String("exe", exe),
		zap.Strings("args", args),
		zap.Int("argc_total", len(envData.Args)),
		zap.Int("env_key_count", len(envData.Env)),
		zap.Strings("env_keys", envKeys),
	}
}

// decodeCloneFlags returns a sorted slice of the human-readable names
// for flags set in a clone() / clone3() flags bitmask. Unknown high
// bits are ignored — only the commonly-interesting flags are decoded
// (the full CLONE_* space is 30+ and most are noise for this
// investigation). Intended for the clone_syscall debug-log event.
func decodeCloneFlags(flags uint64) []string {
	// Values match include/uapi/linux/sched.h. Stable kernel ABI.
	known := []struct {
		bit  uint64
		name string
	}{
		{0x00000100, "CLONE_VM"},
		{0x00000200, "CLONE_FS"},
		{0x00000400, "CLONE_FILES"},
		{0x00000800, "CLONE_SIGHAND"},
		{0x00002000, "CLONE_PTRACE"},
		{0x00004000, "CLONE_VFORK"},
		{0x00008000, "CLONE_PARENT"},
		{0x00010000, "CLONE_THREAD"},
		{0x00020000, "CLONE_NEWNS"},
		{0x00040000, "CLONE_SYSVSEM"},
		{0x00080000, "CLONE_SETTLS"},
		{0x00100000, "CLONE_PARENT_SETTID"},
		{0x00200000, "CLONE_CHILD_CLEARTID"},
		{0x00400000, "CLONE_DETACHED"},
		{0x00800000, "CLONE_UNTRACED"},
		{0x01000000, "CLONE_CHILD_SETTID"},
		{0x02000000, "CLONE_NEWCGROUP"},
		{0x04000000, "CLONE_NEWUTS"},
		{0x08000000, "CLONE_NEWIPC"},
		{0x10000000, "CLONE_NEWUSER"},
		{0x20000000, "CLONE_NEWPID"},
		{0x40000000, "CLONE_NEWNET"},
		{0x80000000, "CLONE_IO"},
	}
	out := make([]string, 0, 4)
	for _, k := range known {
		if flags&k.bit != 0 {
			out = append(out, k.name)
		}
	}
	return out
}

// commString extracts a null-terminated task comm from the fixed-size byte
// array BPF events carry. Safe to call on empty/zero input (returns "").
func commString(b []byte) string {
	if len(b) == 0 || b[0] == 0 {
		return ""
	}
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}

// envKeysWithPrefix returns a sorted list of env keys matching the given
// prefix. Diagnostic-only: caps at maxKeys to bound log size, values are
// never included (PII / volume).
func envKeysWithPrefix(env map[string]string, prefix string, maxKeys int) []string {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if maxKeys > 0 && len(keys) > maxKeys {
		keys = keys[:maxKeys]
	}
	return keys
}

// attrProbeEntry is one attribute's resolved name + value length, for logging
// without leaking the value itself.
type attrProbeEntry struct {
	Name     string `json:"name"`
	ValueLen int    `json:"value_len"`
}

// probeAttributes evaluates the given attribute evaluator and returns entries
// describing each attribute's resolution. When nonEmptyOnly=true, entries with
// empty values are dropped. Silently returns nil on evaluator error.
func probeAttributes(ev *attributes.Evaluator, meta *procmeta.ProcessMetadata, nonEmptyOnly bool) []attrProbeEntry {
	if ev == nil || meta == nil {
		return nil
	}
	attrs, err := ev.EvaluateCustomAttributes(meta)
	if err != nil {
		return nil
	}
	out := make([]attrProbeEntry, 0, len(attrs))
	for _, a := range attrs {
		v := a.Value.AsString()
		if nonEmptyOnly && v == "" {
			continue
		}
		out = append(out, attrProbeEntry{Name: string(a.Key), ValueLen: len(v)})
	}
	return out
}

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
