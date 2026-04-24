package ambient

import (
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrzor/process-tracer/internal/bpf"
	"github.com/mrzor/process-tracer/internal/debuglog"
	"github.com/mrzor/process-tracer/internal/envreassembler"
	"github.com/mrzor/process-tracer/internal/procmeta"
	"go.uber.org/zap"
)

// Processor routes BPF events to the appropriate trace sessions in daemon mode.
// It implements the eventprocessor.EventHandler interface.
type Processor struct {
	filter  *FilterEngine
	manager *SessionManager

	// Pending env data for processes not yet matched to a session.
	// Keyed by PID. Populated by env chunks that arrive before the EXEC_CANDIDATE event.
	mu                   sync.Mutex
	pendingEnv           map[uint32]*envreassembler.ReassembledData
	pendingChunks        map[uint32]*envreassembler.ChunkReassembler
	pendingExit          map[uint32]*pendingExitInfo
	chunkReassembler     *envreassembler.ChunkReassembler
	streamingReassembler *envreassembler.StreamingReassembler

	// Debug-log coverage sampler: when >0, log every Nth exec that no
	// rule matched (exec_unmatched event) so operators can see which
	// binaries exist but aren't being captured. coverageCounter wraps
	// around to avoid overflow and is a plain counter — we don't need
	// strict determinism, just a steady 1/N rate.
	coverageRate    int
	coverageCounter uint64
}

// SetDebugCoverageSampling configures the exec_unmatched sampling rate.
// rate=0 disables, rate=N logs every Nth unmatched exec. Safe to call
// before Start(); not safe to change while the daemon is running.
func (p *Processor) SetDebugCoverageSampling(rate int) {
	p.coverageRate = rate
}

type pendingExitInfo struct {
	pid, ppid, uid uint32
	exitCode       uint32
	timestamp      uint64
	comm           []byte
	receivedAt     time.Time
}

// NewProcessor creates a new daemon mode event processor.
func NewProcessor(filter *FilterEngine, manager *SessionManager) *Processor {
	return &Processor{
		filter:               filter,
		manager:              manager,
		pendingEnv:           make(map[uint32]*envreassembler.ReassembledData),
		pendingChunks:        make(map[uint32]*envreassembler.ChunkReassembler),
		pendingExit:          make(map[uint32]*pendingExitInfo),
		chunkReassembler:     envreassembler.NewChunkReassembler(),
		streamingReassembler: envreassembler.NewStreamingReassembler(),
	}
}

// HandleCloneSyscall logs a clone/clone3 syscall with its flags decoded
// into human-readable names. Correlate with sched_process_fork by
// (tgid, timestamp) to see the flags that produced a given fork.
// No-op unless debug-log is active — the tracepoints themselves are
// ambient-mode-gated at the BPF level, but the log volume can still be
// high; we skip the field-prep work when nobody's listening.
func (p *Processor) HandleCloneSyscall(ev *bpf.CloneSyscallEvent) error {
	if !debuglog.Enabled() {
		return nil
	}
	variant := "clone"
	if ev.Variant == 1 {
		variant = "clone3"
	}
	debuglog.L.Info("clone_syscall",
		zap.Uint32("tgid", ev.Tgid),
		zap.Uint64("flags", ev.Flags),
		zap.Strings("flag_names", decodeCloneFlags(ev.Flags)),
		zap.String("variant", variant),
		zap.Uint64("timestamp_ns", ev.Timestamp),
		zap.String("comm", commString(ev.Comm[:])),
	)
	return nil
}

// HandleAncestorTrace logs BPF's 16-level real_parent walk when no
// tracked ancestor was found. Correlate with the subsequent
// exec_unclaimed / weld_fail event by (pid, timestamp). One event per
// unclaimed exec or unclaimed fork — rare, so the log volume is bounded.
func (p *Processor) HandleAncestorTrace(ev *bpf.AncestorTraceEvent) error {
	if !debuglog.Enabled() {
		return nil
	}
	hops := make([]map[string]any, 0, ev.NumHops)
	for i := 0; i < int(ev.NumHops) && i < len(ev.Hops); i++ {
		h := ev.Hops[i]
		hops = append(hops, map[string]any{
			"tgid":        h.Tgid,
			"comm":        commString(h.Comm[:]),
			"pid_ns_inum": h.PidNsInum,
			"tracked":     h.Tracked != 0,
		})
	}
	reason := "exec_no_ancestor"
	if ev.Reason == 1 {
		reason = "fork_no_ancestor"
	}
	debuglog.L.Info("ancestor_trace",
		zap.Uint32("pid", ev.Pid),
		zap.Uint32("ppid", ev.Ppid),
		zap.String("reason", reason),
		zap.Uint64("timestamp_ns", ev.Timestamp),
		zap.Int("num_hops", int(ev.NumHops)),
		zap.Any("hops", hops),
	)
	return nil
}

// HandleEvent routes regular events (EXEC, EXIT, TCP, EXEC_CANDIDATE).
func (p *Processor) HandleEvent(event *bpf.Event) error {
	switch event.Type {
	case bpf.EVENT_EXEC_CANDIDATE:
		return p.handleExecCandidate(event)
	case bpf.EVENT_EXEC:
		return p.handleExec(event)
	case bpf.EVENT_FORK:
		return p.handleFork(event)
	case bpf.EVENT_EXIT:
		return p.handleExit(event)
	case bpf.EVENT_TCP_CONNECT:
		return p.handleTCPConnect(event)
	case bpf.EVENT_TCP_CLOSE:
		return p.handleTCPClose(event)
	default:
		return nil
	}
}

// HandleEnvChunk buffers environment chunks for pending processes or routes to sessions.
func (p *Processor) HandleEnvChunk(chunk *bpf.EnvChunkEvent) error {
	pid := chunk.Pid

	// If this PID is already in a session, route the env data there
	if session := p.manager.RouteByPID(pid); session != nil {
		result, err := p.chunkReassembler.HandleChunk(chunk)
		if err != nil {
			return err
		}
		if result != nil {
			p.storeMetadata(pid, result)
		}
		return nil
	}

	// Buffer for pending filter evaluation
	p.mu.Lock()
	defer p.mu.Unlock()

	reassembler, ok := p.pendingChunks[pid]
	if !ok {
		reassembler = envreassembler.NewChunkReassembler()
		p.pendingChunks[pid] = reassembler
	}

	result, err := reassembler.HandleChunk(chunk)
	if err != nil {
		return err
	}
	if result != nil {
		p.pendingEnv[pid] = result
		delete(p.pendingChunks, pid)
	}
	return nil
}

// HandleEnvVar buffers individual env var events for pending processes or routes to sessions.
func (p *Processor) HandleEnvVar(envVar *bpf.EnvVarEvent) error {
	pid := envVar.Pid

	// If this PID is already in a session, route to shared reassembler
	if session := p.manager.RouteByPID(pid); session != nil {
		result, err := p.streamingReassembler.HandleVar(envVar)
		if err != nil {
			return err
		}
		if result != nil {
			p.storeMetadata(pid, result)
		}
		return nil
	}

	// Buffer for pending filter evaluation (use shared reassembler, keyed by PID internally)
	result, err := p.streamingReassembler.HandleVar(envVar)
	if err != nil {
		return err
	}
	if result != nil {
		p.mu.Lock()
		p.pendingEnv[pid] = result
		p.mu.Unlock()
	}
	return nil
}

// handleExecCandidate evaluates a new unmatched process against filter rules.
func (p *Processor) handleExecCandidate(event *bpf.Event) error {
	pid := event.Pid
	procData := event.ProcessData()
	if procData == nil {
		return nil
	}

	comm := string(procData.Comm[:])

	// Match against rules
	rule := p.filter.Match(comm, procData.IsContainerInit == 1)
	if rule == nil {
		// No match — optionally sample the exec for coverage
		// diagnostics before discarding the buffered env.
		if p.coverageRate > 0 && debuglog.Enabled() {
			n := atomic.AddUint64(&p.coverageCounter, 1)
			if n%uint64(p.coverageRate) == 0 {
				p.emitExecUnmatched(event.Pid, event.Ppid, event.UID, procData, comm)
			}
		}
		p.cleanupPending(pid)
		return nil
	}

	// Build metadata from buffered env data
	p.mu.Lock()
	envData := p.pendingEnv[pid]
	delete(p.pendingEnv, pid)
	delete(p.pendingChunks, pid)
	p.mu.Unlock()

	var metadata *procmeta.ProcessMetadata
	if envData != nil {
		metadata = &procmeta.ProcessMetadata{
			Environ:     envData.Env,
			Args:        envData.Args,
			CmdlineFull: strings.Join(envData.Args, " "),
		}
	}

	// Context-starved rules don't materialize an OTEL session on their own —
	// the injector itself (e.g. `runc exec`) has no useful env; we stash
	// a pending session and wait for a descendant whose metadata actually
	// resolves the rule's Expr expressions.
	if rule.ContextStarved {
		if err := p.manager.CreatePendingStarved(pid, rule, metadata); err != nil {
			log.Printf("failed to create pending-starved session for PID %d (rule %q): %v", pid, rule.Name, err)
		}
		return nil
	}

	// Create a new session
	session, err := p.manager.CreateSession(pid, rule, metadata)
	if err != nil {
		log.Printf("failed to create session for PID %d (rule %q): %v", pid, rule.Name, err)
		return nil
	}

	// Send the exec event to the new session's formatter
	if err := session.HandleProcessExec(pid, event.Ppid, event.UID, event.Timestamp, metadata); err != nil {
		log.Printf("session %s: error handling exec for PID %d: %v", session.ID, pid, err)
	}

	// Check if we have a buffered exit for this PID (short-lived process)
	p.mu.Lock()
	exitInfo := p.pendingExit[pid]
	delete(p.pendingExit, pid)
	p.mu.Unlock()

	if exitInfo != nil {
		return p.processExit(session, exitInfo.pid, exitInfo.ppid, exitInfo.uid, exitInfo.exitCode, exitInfo.timestamp, exitInfo.comm)
	}

	return nil
}

// handleFork handles EVENT_FORK for fork/clone of tracked processes.
// No span is emitted — this purely maintains PID-to-session routing so that
// when the forked child later execs, handleExec finds it in the correct session.
// BPF already added the child to tracked_pids before emitting this event.
func (p *Processor) handleFork(event *bpf.Event) error {
	childPid := event.Pid
	parentPid := event.Ppid

	// If the parent belongs to a pending context-starved session, register
	// the child there too so its later exec is routed through the
	// materialization check.
	if p.manager.HandleStarvedDescendantFork(childPid, parentPid) {
		return nil
	}

	var forkComm string
	var forkNsInum uint32
	if procData := event.ProcessData(); procData != nil {
		forkComm = commString(procData.Comm[:])
		forkNsInum = procData.PidNsInum
	}

	session := p.manager.AddDescendant(childPid, parentPid)
	if session != nil {
		debuglog.L.Info("descendant_join",
			append(sessionLogFields(session),
				zap.Uint32("pid", childPid),
				zap.Uint32("ppid", parentPid),
				zap.Uint32("pid_ns_inum", forkNsInum),
				zap.String("via", "fork"),
				zap.String("comm", forkComm),
			)...)
	}
	if session == nil {
		// Parent not in any session — try the tracked ancestor from BPF's
		// ancestor walk (covers fork-without-exec intermediaries).
		if procData := event.ProcessData(); procData != nil && procData.TrackedAncestor != 0 {
			// First add the parent (fork-only intermediate) to the session
			parentSession := p.manager.AddDescendant(parentPid, procData.TrackedAncestor)
			// Then add the child
			session = p.manager.AddDescendant(childPid, parentPid)

			if session != nil {
				debuglog.L.Info("ancestor_weld",
					append(sessionLogFields(session),
						zap.Uint32("pid", childPid),
						zap.Uint32("ppid", parentPid),
						zap.Uint32("tracked_ancestor", procData.TrackedAncestor),
						zap.Uint32("pid_ns_inum", forkNsInum),
						zap.String("via", "fork"),
						zap.String("comm", forkComm),
					)...)
			} else {
				debuglog.L.Info("weld_fail",
					zap.Uint32("pid", childPid),
					zap.Uint32("ppid", parentPid),
					zap.Uint32("tracked_ancestor", procData.TrackedAncestor),
					zap.Uint32("pid_ns_inum", forkNsInum),
					zap.Bool("parent_joined", parentSession != nil),
					zap.String("via", "fork"),
					zap.String("comm", forkComm),
				)
			}
		}
	}
	return nil
}

// handleExec handles EVENT_EXEC for processes whose parent is already tracked.
func (p *Processor) handleExec(event *bpf.Event) error {
	pid := event.Pid
	ppid := event.Ppid

	var execComm string
	var trackedAncestor uint32
	var pidNsInum uint32
	if procData := event.ProcessData(); procData != nil {
		execComm = commString(procData.Comm[:])
		trackedAncestor = procData.TrackedAncestor
		pidNsInum = procData.PidNsInum
	}

	// Pull pending env/metadata up front — both the starved path and the
	// normal path need it.
	p.mu.Lock()
	envData := p.pendingEnv[pid]
	delete(p.pendingEnv, pid)
	delete(p.pendingChunks, pid)
	p.mu.Unlock()

	var metadata *procmeta.ProcessMetadata
	if envData != nil {
		metadata = &procmeta.ProcessMetadata{
			Environ:     envData.Env,
			Args:        envData.Args,
			CmdlineFull: strings.Join(envData.Args, " "),
		}
		// Store in metadata manager so formatter can use it
		existing := p.manager.MetadataManager().GetOrCreate(pid)
		existing.Environ = envData.Env
		existing.Args = envData.Args
		existing.CmdlineFull = metadata.CmdlineFull
	} else {
		metadata = p.manager.MetadataManager().Get(pid)
	}

	// Pending-starved path: if the parent (or a buffered ancestor) belongs
	// to a pending context-starved session, either this exec triggers
	// materialization (we still emit its process.exec span) or it gets
	// buffered for later replay.
	if session, buffered := p.manager.HandleStarvedDescendantExec(pid, ppid, event.UID, event.Timestamp, metadata, execComm); session != nil {
		return p.runProcessExec(session, pid, ppid, event.UID, event.Timestamp, execComm, metadata)
	} else if buffered {
		return nil
	}

	// Add descendant to parent's session
	session := p.manager.AddDescendant(pid, ppid)
	welded := false
	if session == nil {
		// Parent not in any session — try the tracked ancestor from BPF's
		// ancestor walk (covers fork-without-exec intermediaries).
		if trackedAncestor != 0 {
			// First add the immediate parent (fork-only intermediate) to the session
			parentSession := p.manager.AddDescendant(ppid, trackedAncestor)
			// Then add this process
			session = p.manager.AddDescendant(pid, ppid)

			if session != nil {
				welded = true
				debuglog.L.Info("ancestor_weld",
					append(sessionLogFields(session),
						zap.Uint32("pid", pid),
						zap.Uint32("ppid", ppid),
						zap.Uint32("tracked_ancestor", trackedAncestor),
						zap.Uint32("pid_ns_inum", pidNsInum),
						zap.String("via", "exec"),
						zap.String("comm", execComm),
					)...)
			} else {
				debuglog.L.Info("weld_fail",
					zap.Uint32("pid", pid),
					zap.Uint32("ppid", ppid),
					zap.Uint32("tracked_ancestor", trackedAncestor),
					zap.Uint32("pid_ns_inum", pidNsInum),
					zap.Bool("parent_joined", parentSession != nil),
					zap.String("via", "exec"),
					zap.String("comm", execComm),
				)
			}
		}
		if session == nil {
			// Exec event with no pending-starved pending, no parent in any
			// session, and no tracked ancestor — nothing claims this PID.
			// Silent today; log so we can distinguish "sleep never joined
			// because no one owned its parent" from other theories.
			//
			// envData was already pulled at the top of this function and
			// would otherwise be discarded. Reuse it to enrich the log with
			// the exe's argv[0] (cheapest proxy for full exe path) plus
			// first-N args and env keys (names only — values could be PII).
			fields := []zap.Field{
				zap.Uint32("pid", pid),
				zap.Uint32("ppid", ppid),
				zap.Uint32("tracked_ancestor", trackedAncestor),
				zap.Uint32("pid_ns_inum", pidNsInum),
				zap.String("comm", execComm),
			}
			if envData != nil {
				fields = append(fields, enrichExecUnclaimed(envData)...)
			}
			debuglog.L.Info("exec_unclaimed", fields...)
			return nil
		}
	} else {
		debuglog.L.Info("descendant_join",
			append(sessionLogFields(session),
				zap.Uint32("pid", pid),
				zap.Uint32("ppid", ppid),
				zap.Uint32("pid_ns_inum", pidNsInum),
				zap.String("via", "exec"),
				zap.String("comm", execComm),
			)...)
	}

	// Trace-id mismatch probe: if this pid has its own env buffered, evaluate
	// the session's rule trace_id expression against it and compare to the
	// session's resolved value. A mismatch is a probable bug instance.
	p.logTraceIDMismatchIfAny(session, pid, ppid, welded, envData)

	return p.runProcessExec(session, pid, ppid, event.UID, event.Timestamp, execComm, metadata)
}

// runProcessExec dispatches to session.HandleProcessExec and structures any
// error into a session_exec_error debug event — previously errors only went
// to the main log, which isn't jq-grepable. Returns the original error so
// existing callers' error semantics are unchanged.
func (p *Processor) runProcessExec(session *TraceSession, pid, ppid, uid uint32, timestamp uint64, comm string, metadata *procmeta.ProcessMetadata) error {
	err := session.HandleProcessExec(pid, ppid, uid, timestamp, metadata)
	if err != nil {
		debuglog.L.Info("session_exec_error",
			append(sessionLogFields(session),
				zap.Uint32("pid", pid),
				zap.Uint32("ppid", ppid),
				zap.String("comm", comm),
				zap.String("error", err.Error()),
			)...)
	}
	return err
}

// emitExecUnmatched logs a sampled exec_unmatched event when an
// EXEC_CANDIDATE doesn't match any rule. Reuses buffered env data (if
// any) from pendingEnv to enrich the log the same way exec_unclaimed
// does — exe/argv/env_keys. Called under coverageRate sampling.
func (p *Processor) emitExecUnmatched(pid, ppid, uid uint32, procData *bpf.ProcessEventData, comm string) {
	p.mu.Lock()
	envData := p.pendingEnv[pid]
	p.mu.Unlock()

	fields := []zap.Field{
		zap.Uint32("pid", pid),
		zap.Uint32("ppid", ppid),
		zap.Uint32("uid", uid),
		zap.Uint32("pid_ns_inum", procData.PidNsInum),
		zap.Bool("is_container_init", procData.IsContainerInit == 1),
		zap.Uint32("ns_level", procData.NsLevel),
		zap.String("comm", strings.TrimRight(comm, "\x00")),
	}
	if envData != nil {
		fields = append(fields, enrichExecUnclaimed(envData)...)
	}
	debuglog.L.Info("exec_unmatched", fields...)
}

// logTraceIDMismatchIfAny emits a trace_id_mismatch event when envData (the
// joining pid's own env) resolves the session's rule trace_id expression to
// a value different from the session's resolved trace-id. Diagnostic-only;
// silently no-ops on any error.
func (p *Processor) logTraceIDMismatchIfAny(session *TraceSession, pid, ppid uint32, welded bool, envData *envreassembler.ReassembledData) {
	if !debuglog.Enabled() {
		return
	}
	if session == nil || session.Rule == nil || envData == nil {
		return
	}
	selfID, selfExpr, ok := evalRuleTraceIDFromEnv(session.Rule, envData)
	if !ok {
		return
	}
	if selfID == session.ResolvedTraceID() {
		return
	}
	debuglog.L.Info("trace_id_mismatch",
		append(sessionLogFields(session),
			zap.Uint32("pid", pid),
			zap.Uint32("ppid", ppid),
			zap.Bool("via_weld", welded),
			zap.String("self_trace_id", selfID),
			zap.String("self_trace_expr_value", selfExpr),
		)...)
}

// handleExit handles EXIT events.
func (p *Processor) handleExit(event *bpf.Event) error {
	pid := event.Pid
	procData := event.ProcessData()
	if procData == nil {
		return nil
	}

	session, completed := p.manager.HandleExit(pid)
	if session == nil {
		// Not in any live session. First try the pending-starved path:
		// if this pid is currently in pendingStarvedByPid, the manager
		// records the exit against its pending entry (for exec-buffered
		// descendants) or drops the record (for fork-only descendants).
		// This prevents a dead pid from being claimed into session.pids
		// at materialization and holding the session open indefinitely.
		// See verify-traces-runc-starved.py's session-completion test.
		if p.manager.HandleStarvedDescendantExit(pid, procData.ExitCode, event.Timestamp, procData.Comm[:]) {
			if debuglog.Enabled() {
				debuglog.L.Info("starved_pending_exit",
					zap.Uint32("pid", pid),
					zap.Uint32("ppid", event.Ppid),
					zap.Uint32("exit_code", procData.ExitCode),
					zap.String("comm", commString(procData.Comm[:])),
				)
			}
			return nil
		}
		// Not pending-starved either — buffer briefly in case EXEC_CANDIDATE
		// hasn't arrived yet (short-lived process race).
		p.mu.Lock()
		p.pendingExit[pid] = &pendingExitInfo{
			pid:        pid,
			ppid:       event.Ppid,
			uid:        event.UID,
			exitCode:   procData.ExitCode,
			timestamp:  event.Timestamp,
			comm:       append([]byte(nil), procData.Comm[:]...),
			receivedAt: time.Now(),
		}
		p.mu.Unlock()
		return nil
	}

	if debuglog.Enabled() {
		debuglog.L.Info("pid_exit",
			append(sessionLogFields(session),
				zap.Uint32("pid", pid),
				zap.Uint32("ppid", event.Ppid),
				zap.Uint32("exit_code", procData.ExitCode),
				zap.String("comm", commString(procData.Comm[:])),
				zap.Bool("session_completed", completed),
			)...)
	}

	err := p.processExit(session, pid, event.Ppid, event.UID, procData.ExitCode, event.Timestamp, procData.Comm[:])
	if completed {
		// Session complete - no further cleanup needed, manager already removed it
		_ = completed
	}
	return err
}

func (p *Processor) processExit(session *TraceSession, pid, ppid, uid, exitCode uint32, timestamp uint64, comm []byte) error {
	return session.HandleProcessExit(pid, ppid, uid, exitCode, timestamp, comm)
}

// handleTCPConnect routes TCP connect events to the appropriate session.
func (p *Processor) handleTCPConnect(event *bpf.Event) error {
	session := p.manager.RouteByPID(event.Pid)
	if session == nil {
		return nil
	}
	tcpData := event.TCPData()
	if tcpData == nil {
		return nil
	}
	return session.HandleTCPConnect(event.Pid, tcpData.Skaddr, tcpData.Saddr[:], tcpData.Daddr[:], tcpData.Sport, tcpData.Dport, tcpData.Family, event.Timestamp)
}

// handleTCPClose routes TCP close events to the appropriate session.
func (p *Processor) handleTCPClose(event *bpf.Event) error {
	session := p.manager.RouteByPID(event.Pid)
	if session == nil {
		return nil
	}
	tcpData := event.TCPData()
	if tcpData == nil {
		return nil
	}
	return session.HandleTCPClose(event.Pid, tcpData.Skaddr, tcpData.Saddr[:], tcpData.Daddr[:], tcpData.Sport, tcpData.Dport, tcpData.Family, event.Timestamp)
}

// cleanupPending removes buffered data for a PID that didn't match any rule.
func (p *Processor) cleanupPending(pid uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pendingEnv, pid)
	delete(p.pendingChunks, pid)
}

func (p *Processor) storeMetadata(pid uint32, result *envreassembler.ReassembledData) {
	metadata := p.manager.MetadataManager().GetOrCreate(pid)
	metadata.Environ = result.Env
	metadata.Args = result.Args
	metadata.CmdlineFull = strings.Join(result.Args, " ")
}

// CleanupStalePending removes pending env/exit data older than the given threshold.
func (p *Processor) CleanupStalePending(maxAge time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	for pid, info := range p.pendingExit {
		if now.Sub(info.receivedAt) > maxAge {
			delete(p.pendingExit, pid)
		}
	}
	// pendingEnv entries without timestamps are cleaned up when they're accessed
	// and found to have no corresponding EXEC_CANDIDATE. For now, cap size.
	if len(p.pendingEnv) > 10000 {
		// Emergency cleanup: drop oldest half (no ordering, just reduce pressure)
		count := 0
		for pid := range p.pendingEnv {
			if count >= len(p.pendingEnv)/2 {
				break
			}
			delete(p.pendingEnv, pid)
			delete(p.pendingChunks, pid)
			count++
		}
	}
}
