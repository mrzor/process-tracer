package ambient

import (
	"fmt"
	"log"
	"time"

	"github.com/mrzor/process-tracer/internal/attributes"
	"github.com/mrzor/process-tracer/internal/config"
	"github.com/mrzor/process-tracer/internal/debuglog"
	"github.com/mrzor/process-tracer/internal/procmeta"
	"go.uber.org/zap"
)

// bufferedDescendantExec holds the exec event data for a descendant we stashed
// while its pending context-starved session waits for a context-ful arrival.
type bufferedDescendantExec struct {
	pid       uint32
	ppid      uint32
	uid       uint32
	timestamp uint64
	metadata  *procmeta.ProcessMetadata
}

// pendingStarvedSession is the transient state held between a context-starved
// rule matching at EXEC_CANDIDATE and the first descendant whose metadata
// actually resolves the rule's Expr expressions. Once any Expr resolves
// non-empty, materialize() converts this into a real TraceSession.
type pendingStarvedSession struct {
	rootPid   uint32
	rule      *config.AmbientRule
	rootMeta  *procmeta.ProcessMetadata
	createdAt time.Time

	// Descendants buffered so far, in execve order. Replayed onto the
	// TraceSession when materialization fires.
	descendants []bufferedDescendantExec

	// Probe evaluators — cached so we don't recompile the rule's Expr every
	// time a descendant arrives. Built with skipEmptyValues=false so we see
	// every attribute's resolved value (the probe needs to inspect empties).
	probeAttr   *attributes.Evaluator
	probeTrace  *attributes.TraceIDEvaluator
	probeParent *attributes.ParentIDEvaluator
}

// materializationReady reports whether this descendant's metadata carries
// enough signal to promote the pending session into a real one. The gate
// follows the rule author's declared correlation key:
//
//  1. If rule.TraceID is expr-configured, that expression MUST resolve
//     non-empty. The trace is keyed on it; creating the session before it
//     resolves risks collapsing unrelated pipelines onto the same trace
//     (e.g. every empty-expr session hashing to sha256("")).
//  2. If rule.TraceID is a literal or unconfigured, the trace_id doesn't
//     depend on env — fall back to the attribute signal: at least one
//     expr-backed attribute must resolve non-empty. Literal attributes are
//     ignored because they resolve non-empty unconditionally and cannot
//     distinguish "env ready" from "first exec."
//
// A rule where both (1) is absent and (2) has no expr-backed attributes has
// a dead gate — warned about at load time in CreatePendingStarved.
func (p *pendingStarvedSession) materializationReady(meta *procmeta.ProcessMetadata) bool {
	if meta == nil {
		return false
	}
	if p.rule.TraceID != "" {
		if _, isExpr := attributes.ParseExprPrefix(p.rule.TraceID); isExpr {
			_, _, res, err := p.probeTrace.EvaluateAndValidate(meta)
			return err == nil && res.ResolvedValue != ""
		}
	}
	return p.probeAttr.AnyExprAttributeNonEmpty(meta)
}

// CreatePendingStarved registers a pending context-starved session for the
// injector (rootPid). No OTEL span is started yet; materialization is
// deferred until a descendant's metadata resolves at least one of the rule's
// Expr expressions to a non-empty value.
//
// Returns nil if session limits are already exhausted — in that case the
// caller should treat the match as dropped.
func (m *SessionManager) CreatePendingStarved(rootPid uint32, rule *config.AmbientRule, rootMeta *procmeta.ProcessMetadata) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.sessions)+len(m.pendingStarved) >= m.limits.MaxConcurrentSessions {
		return fmt.Errorf("max concurrent sessions (%d) reached", m.limits.MaxConcurrentSessions)
	}

	customAttrs := config.CustomAttributesForRule(rule)
	probeAttr, err := attributes.NewEvaluator(customAttrs, false)
	if err != nil {
		return fmt.Errorf("compiling attribute probe for rule %q: %w", rule.Name, err)
	}
	probeTrace, err := attributes.NewTraceIDEvaluator(rule.TraceID)
	if err != nil {
		return fmt.Errorf("compiling trace_id probe for rule %q: %w", rule.Name, err)
	}
	probeParent, err := attributes.NewParentIDEvaluator(rule.ParentID)
	if err != nil {
		return fmt.Errorf("compiling parent_id probe for rule %q: %w", rule.Name, err)
	}

	// Dead-gate warning: if neither the trace_id nor any attribute is
	// expr-backed, materializationReady can never wait on env — it would
	// either fire immediately or never. Either way, context_starved is
	// providing no value; rule author likely misconfigured.
	traceIDIsExpr := false
	if rule.TraceID != "" {
		_, traceIDIsExpr = attributes.ParseExprPrefix(rule.TraceID)
	}
	if !traceIDIsExpr && !probeAttr.HasExprAttributes() {
		log.Printf("warning: context_starved rule %q has no expr-based trace_id or attributes; materialization gate is inert — consider removing context_starved or adding an expr-based signal", rule.Name)
	}

	pending := &pendingStarvedSession{
		rootPid:     rootPid,
		rule:        rule,
		rootMeta:    rootMeta,
		createdAt:   time.Now(),
		probeAttr:   probeAttr,
		probeTrace:  probeTrace,
		probeParent: probeParent,
	}
	m.pendingStarved[rootPid] = pending
	m.pendingStarvedByPid[rootPid] = rootPid

	// Track the injector PID in BPF so the kernel tagging catches its
	// descendants' exec events as EXEC (not EXEC_CANDIDATE) — the same
	// machinery non-starved sessions already rely on.
	if err := m.loader.TrackPID(int(rootPid)); err != nil {
		log.Printf("warning: failed to track pending-starved PID %d in BPF: %v", rootPid, err)
	}

	log.Printf("pending-starved %s: watching PID %d (rule %q) for context-ful descendant", rule.Name, rootPid, rule.Name)

	fields := []zap.Field{
		zap.Uint32("pid", rootPid),
		zap.String("rule", rule.Name),
		zap.String("candidate_path", "starved_pending"),
	}
	if debuglog.Enabled() {
		envCount := 0
		if rootMeta != nil && rootMeta.Environ != nil {
			envCount = len(rootMeta.Environ)
		}
		fields = append(fields,
			zap.Int("injector_env_key_count", envCount),
			zap.Any("injector_attr_nonempty", probeAttributes(probeAttr, rootMeta, true)),
		)
	}
	debuglog.L.Info("session_start", fields...)
	return nil
}

// PendingStarvedRootByPid returns the root PID of a pending starved session
// that `pid` belongs to (directly or as a buffered descendant), or 0 if none.
func (m *SessionManager) PendingStarvedRootByPid(pid uint32) uint32 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pendingStarvedByPid[pid]
}

// HandleStarvedDescendantExec routes a descendant's exec event when its
// ancestor is a pending starved session. Returns:
//   - (session, false): materialization just happened; caller should
//     invoke session.HandleProcessExec for this descendant.
//   - (nil, true): buffered; the caller should treat the exec as handled.
//   - (nil, false): no pending starved ancestor; fall through to normal routing.
func (m *SessionManager) HandleStarvedDescendantExec(pid, ppid, uid uint32, timestamp uint64, metadata *procmeta.ProcessMetadata) (*TraceSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rootPid, ok := m.pendingStarvedByPid[ppid]
	if !ok {
		return nil, false
	}
	pending, ok := m.pendingStarved[rootPid]
	if !ok {
		// Inconsistent state — shouldn't happen. Clean up the stale by-pid entry.
		delete(m.pendingStarvedByPid, ppid)
		return nil, false
	}

	if pending.materializationReady(metadata) {
		session, err := m.materializeStarvedLocked(pending, metadata)
		if err != nil {
			log.Printf("pending-starved %s: materialization failed: %v", pending.rule.Name, err)
			m.dropPendingStarvedLocked(pending)
			return nil, false
		}
		// Route this triggering descendant into the session as a new
		// descendant — the caller will call HandleProcessExec.
		m.addDescendantLocked(session, pid, ppid)
		return session, false
	}

	// Not context-ful yet — buffer and map its PID so its own children
	// route through the pending session too.
	pending.descendants = append(pending.descendants, bufferedDescendantExec{
		pid:       pid,
		ppid:      ppid,
		uid:       uid,
		timestamp: timestamp,
		metadata:  metadata,
	})
	m.pendingStarvedByPid[pid] = rootPid

	if debuglog.Enabled() {
		envCount := 0
		if metadata != nil && metadata.Environ != nil {
			envCount = len(metadata.Environ)
		}
		debuglog.L.Info("starved_buffer",
			zap.String("rule", pending.rule.Name),
			zap.Uint32("root_pid", rootPid),
			zap.Uint32("pid", pid),
			zap.Uint32("ppid", ppid),
			zap.Int("buffered_count", len(pending.descendants)),
			zap.Int("env_key_count", envCount),
			zap.Any("attr_resolved", probeAttributes(pending.probeAttr, metadata, false)),
		)
	}
	return nil, true
}

// HandleStarvedDescendantFork registers a fork'd child whose parent is in
// a pending starved session, so the child's later exec finds the pending
// session via pendingStarvedByPid lookup. Returns true if the child was
// associated with a pending starved session (caller should skip the
// normal descendant routing).
func (m *SessionManager) HandleStarvedDescendantFork(childPid, parentPid uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	rootPid, ok := m.pendingStarvedByPid[parentPid]
	if !ok {
		return false
	}
	if _, ok := m.pendingStarved[rootPid]; !ok {
		delete(m.pendingStarvedByPid, parentPid)
		return false
	}
	m.pendingStarvedByPid[childPid] = rootPid
	return true
}

// materializeStarvedLocked promotes a pending starved session to a real
// TraceSession using the given context-ful descendant metadata for Expr
// evaluation (merged with the root's args so process.command reflects the
// injector). Buffered descendants are replayed onto the new session in
// execve order. Must be called with m.mu held.
func (m *SessionManager) materializeStarvedLocked(pending *pendingStarvedSession, descMeta *procmeta.ProcessMetadata) (*TraceSession, error) {
	if len(m.sessions) >= m.limits.MaxConcurrentSessions {
		return nil, fmt.Errorf("max concurrent sessions (%d) reached", m.limits.MaxConcurrentSessions)
	}
	if m.totalPIDs >= m.limits.MaxTotalPIDs {
		return nil, fmt.Errorf("max total PIDs (%d) reached", m.limits.MaxTotalPIDs)
	}

	// Merge: args from the injector (so process.command on the tree root
	// reflects the injector), env from the context-ful descendant (so the
	// rule's Expr — e.g. env["CI_JOB_ID"] — resolves against real data).
	merged := mergeMetadataForMaterialization(pending.rootMeta, descMeta)

	if debuglog.Enabled() {
		resolvedLen := 0
		if pending.probeTrace != nil {
			if _, _, res, err := pending.probeTrace.EvaluateAndValidate(merged); err == nil {
				resolvedLen = len(res.ResolvedValue)
			}
		}
		envCount := 0
		var ciKeys []string
		if merged != nil && merged.Environ != nil {
			envCount = len(merged.Environ)
			ciKeys = envKeysWithPrefix(merged.Environ, "CI_", 32)
		}
		debuglog.L.Info("starved_env_probe",
			zap.String("rule", pending.rule.Name),
			zap.Uint32("root_pid", pending.rootPid),
			zap.String("trace_id_expr_source", pending.rule.TraceID),
			zap.Int("trace_id_resolved_value_len", resolvedLen),
			zap.Int("env_key_count", envCount),
			zap.Strings("env_keys_prefix_ci", ciKeys),
			zap.Any("attr_nonempty", probeAttributes(pending.probeAttr, merged, true)),
		)
	}

	// Drop pending state atomically before calling CreateSession's
	// storeMetadata path, which would otherwise overwrite probe state.
	rootPid := pending.rootPid
	rule := pending.rule
	descendants := pending.descendants
	delete(m.pendingStarved, rootPid)
	// Clear pendingStarvedByPid entries that pointed at this root.
	for pid, r := range m.pendingStarvedByPid {
		if r == rootPid {
			delete(m.pendingStarvedByPid, pid)
		}
	}

	session, err := m.createSessionLocked(rootPid, rule, merged)
	if err != nil {
		return nil, err
	}

	log.Printf("session %s: materialized from pending-starved %q with %d buffered descendants", session.ID, rule.Name, len(descendants))

	debuglog.L.Info("starved_materialize",
		append(sessionLogFields(session),
			zap.Uint32("root_pid", rootPid),
			zap.Int("buffered_descendants", len(descendants)),
		)...)

	// Replay buffered descendants in order. Each was already observed by
	// BPF's exec tracking; we just need to produce the Go-side session
	// routing and the process.exec spans.
	for _, d := range descendants {
		m.addDescendantLocked(session, d.pid, d.ppid)
		debuglog.L.Info("descendant_join",
			append(sessionLogFields(session),
				zap.Uint32("pid", d.pid),
				zap.Uint32("ppid", d.ppid),
				zap.String("via", "starved_replay"),
			)...)
		if err := session.HandleProcessExec(d.pid, d.ppid, d.uid, d.timestamp, d.metadata); err != nil {
			log.Printf("session %s: replay exec for PID %d failed: %v", session.ID, d.pid, err)
		}
	}

	return session, nil
}

// DropPendingStarved removes pending state and untracks the root PID.
// Safe to call on a non-existent root (no-op).
func (m *SessionManager) DropPendingStarved(rootPid uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pending, ok := m.pendingStarved[rootPid]
	if !ok {
		return
	}
	m.dropPendingStarvedLocked(pending)
}

// dropPendingStarvedLocked removes pending state without taking the lock.
// Must be called with m.mu held.
func (m *SessionManager) dropPendingStarvedLocked(pending *pendingStarvedSession) {
	rootPid := pending.rootPid
	delete(m.pendingStarved, rootPid)
	for pid, r := range m.pendingStarvedByPid {
		if r == rootPid {
			delete(m.pendingStarvedByPid, pid)
			_ = m.loader.UntrackPID(int(pid)) //nolint:errcheck // best-effort cleanup
		}
	}
	log.Printf("pending-starved %s: dropped (root PID %d, %d buffered descendants never resolved context)",
		pending.rule.Name, rootPid, len(pending.descendants))

	debuglog.L.Info("starved_drop",
		zap.Uint32("root_pid", rootPid),
		zap.String("rule", pending.rule.Name),
		zap.Int("buffered_descendants", len(pending.descendants)),
		zap.Int64("pending_age_ms", time.Since(pending.createdAt).Milliseconds()),
	)
}

// cleanupStalePendingStarvedLocked drops pending sessions older than the
// session timeout. Must be called with m.mu held.
func (m *SessionManager) cleanupStalePendingStarvedLocked(now time.Time) {
	for rootPid, pending := range m.pendingStarved {
		if now.Sub(pending.createdAt) > m.limits.SessionTimeout {
			log.Printf("pending-starved %s: timed out after %v", pending.rule.Name, m.limits.SessionTimeout)
			_ = rootPid
			m.dropPendingStarvedLocked(pending)
		}
	}
}

// mergeMetadataForMaterialization combines the injector's args with the
// context-ful descendant's environ. Either side may be nil.
func mergeMetadataForMaterialization(root, desc *procmeta.ProcessMetadata) *procmeta.ProcessMetadata {
	merged := &procmeta.ProcessMetadata{}
	if root != nil {
		merged.Args = root.Args
		merged.CmdlineFull = root.CmdlineFull
	}
	if desc != nil {
		merged.Environ = desc.Environ
		if merged.Args == nil {
			merged.Args = desc.Args
			merged.CmdlineFull = desc.CmdlineFull
		}
	}
	if merged.Environ == nil {
		merged.Environ = map[string]string{}
	}
	return merged
}
