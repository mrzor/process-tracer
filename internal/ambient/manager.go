package ambient

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mrzor/process-tracer/internal/config"
	"github.com/mrzor/process-tracer/internal/output"
	"github.com/mrzor/process-tracer/internal/procmeta"
	"github.com/mrzor/process-tracer/internal/reversedns"
	"github.com/mrzor/process-tracer/internal/timesync"
	"go.opentelemetry.io/otel/trace"
)

// PIDTracker abstracts BPF PID tracking operations for testability.
type PIDTracker interface {
	TrackPID(pid int) error
	UntrackPID(pid int) error
}

// SessionManager manages the lifecycle of trace sessions in daemon mode.
type SessionManager struct {
	loader          PIDTracker
	tracer          trace.Tracer
	converter       *timesync.Converter
	resolver        *reversedns.Resolver
	metadataManager *procmeta.Manager
	limits          config.AmbientLimits

	mu           sync.RWMutex
	pidToSession map[uint32]*TraceSession
	sessions     map[string]*TraceSession
	totalPIDs    int
	nextID       int

	// Pending context-starved sessions: matched at EXEC_CANDIDATE but
	// waiting for a descendant whose metadata actually resolves the rule's
	// Expr expressions. Keyed by the injector's (root) PID. The byPid map
	// lets a buffered descendant's own fork/exec find the pending root.
	pendingStarved      map[uint32]*pendingStarvedSession
	pendingStarvedByPid map[uint32]uint32
}

// NewSessionManager creates a new session manager.
func NewSessionManager(
	loader PIDTracker,
	tracer trace.Tracer,
	converter *timesync.Converter,
	resolver *reversedns.Resolver,
	metadataManager *procmeta.Manager,
	limits config.AmbientLimits,
) *SessionManager {
	return &SessionManager{
		loader:              loader,
		tracer:              tracer,
		converter:           converter,
		resolver:            resolver,
		metadataManager:     metadataManager,
		limits:              limits,
		pidToSession:        make(map[uint32]*TraceSession),
		sessions:            make(map[string]*TraceSession),
		pendingStarved:      make(map[uint32]*pendingStarvedSession),
		pendingStarvedByPid: make(map[uint32]uint32),
	}
}

// CreateSession creates a new trace session for a matched process.
func (m *SessionManager) CreateSession(pid uint32, rule *config.AmbientRule, metadata *procmeta.ProcessMetadata) (*TraceSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.createSessionLocked(pid, rule, metadata)
}

// createSessionLocked is the lock-free body of CreateSession. It's also used
// by the context-starved materialization path, which already holds m.mu.
func (m *SessionManager) createSessionLocked(pid uint32, rule *config.AmbientRule, metadata *procmeta.ProcessMetadata) (*TraceSession, error) {
	// Enforce limits
	if len(m.sessions) >= m.limits.MaxConcurrentSessions {
		return nil, fmt.Errorf("max concurrent sessions (%d) reached", m.limits.MaxConcurrentSessions)
	}
	if m.totalPIDs >= m.limits.MaxTotalPIDs {
		return nil, fmt.Errorf("max total PIDs (%d) reached", m.limits.MaxTotalPIDs)
	}

	// Store metadata so the formatter can find it
	if metadata != nil {
		existing := m.metadataManager.GetOrCreate(pid)
		existing.Environ = metadata.Environ
		existing.Args = metadata.Args
		existing.CmdlineFull = metadata.CmdlineFull
	}

	// Create an OTELFormatter for this session
	customAttrs := config.CustomAttributesForRule(rule)
	formatter, err := output.NewOTELFormatter(
		m.tracer,
		m.converter,
		m.resolver,
		m.metadataManager,
		customAttrs,
		rule.SkipEmptyValues,
		rule.TraceID,
		rule.ParentID,
		rule.AddDebugAttributes,
	)
	if err != nil {
		return nil, fmt.Errorf("creating formatter: %w", err)
	}

	// Generate session ID
	m.nextID++
	sessionID := fmt.Sprintf("session-%d", m.nextID)

	session := NewTraceSession(sessionID, rule, pid, formatter)
	m.sessions[sessionID] = session
	m.pidToSession[pid] = session
	m.totalPIDs++

	// Start the synthetic "process.tree" root span for this session. All
	// process.exec spans observed within this session will hang under it.
	session.StartSession(context.Background(), metadata, time.Now())

	// Track the PID in BPF so descendants are auto-tracked. The
	// context-starved path already called TrackPID at pending-creation time;
	// calling it again here is a safe no-op for already-tracked PIDs.
	if err := m.loader.TrackPID(int(pid)); err != nil {
		log.Printf("warning: failed to track PID %d in BPF: %v", pid, err)
	}

	// Catch-up scan: between BPF emitting EXEC_CANDIDATE and the TrackPID call
	// above, the process may have already forked children that the BPF fork
	// handler missed (parent wasn't in tracked_pids yet). Scan procfs to
	// retroactively add any such children.
	m.catchUpChildren(pid, session)

	log.Printf("session %s: started tracing PID %d (rule %q)", sessionID, pid, rule.Name)
	return session, nil
}

// RouteByPID returns the session for the given PID, or nil.
func (m *SessionManager) RouteByPID(pid uint32) *TraceSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pidToSession[pid]
}

// AddDescendant adds a child PID to its parent's session.
func (m *SessionManager) AddDescendant(pid, ppid uint32) *TraceSession {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.pidToSession[ppid]
	if !ok {
		return nil
	}
	return m.addDescendantLocked(session, pid, ppid)
}

// addDescendantLocked associates pid with an existing session. Must be called
// with m.mu held. Returns the session on success, or nil if limits were
// exhausted (caller should treat as a dropped descendant).
func (m *SessionManager) addDescendantLocked(session *TraceSession, pid, ppid uint32) *TraceSession {
	_ = ppid // ppid kept in signature for symmetry with AddDescendant

	// Enforce per-session PID limit
	if session.PIDs() >= m.limits.MaxPIDsPerSession {
		log.Printf("session %s: max PIDs per session (%d) reached, not tracking PID %d", session.ID, m.limits.MaxPIDsPerSession, pid)
		return nil
	}
	if m.totalPIDs >= m.limits.MaxTotalPIDs {
		log.Printf("session %s: max total PIDs (%d) reached, not tracking PID %d", session.ID, m.limits.MaxTotalPIDs, pid)
		return nil
	}

	session.AddPID(pid)
	m.pidToSession[pid] = session
	m.totalPIDs++
	return session
}

// HandleExit processes a PID exit, cleaning up session state.
// Returns true if the session is now complete (no more PIDs).
func (m *SessionManager) HandleExit(pid uint32) (*TraceSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.pidToSession[pid]
	if !ok {
		return nil, false
	}

	delete(m.pidToSession, pid)
	m.totalPIDs--

	empty := session.RemovePID(pid)
	if empty {
		// Close the synthetic "process.tree" root span; the session is done.
		session.EndSession(time.Now())
		delete(m.sessions, session.ID)
		log.Printf("session %s: completed (root PID %d)", session.ID, session.RootPID)
	}

	return session, empty
}

// CleanupStale removes sessions that have exceeded the timeout.
func (m *SessionManager) CleanupStale() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	m.cleanupStalePendingStarvedLocked(now)
	for id, session := range m.sessions {
		if now.Sub(session.CreatedAt) > m.limits.SessionTimeout {
			log.Printf("session %s: timed out after %v, cleaning up", id, m.limits.SessionTimeout)
			// Remove all PIDs belonging to this session
			for pid := range m.pidToSession {
				if m.pidToSession[pid] == session {
					delete(m.pidToSession, pid)
					m.totalPIDs--
					// Best-effort untrack from BPF
					_ = m.loader.UntrackPID(int(pid)) //nolint:errcheck // best-effort cleanup
				}
			}
			// Close the synthetic "process.tree" root span for the timed-out session.
			session.EndSession(now)
			delete(m.sessions, id)
		}
	}
}

// catchUpChildren reads /proc/<pid>/task/<pid>/children and adds any existing
// children to the session and BPF tracked_pids map. This closes the race window
// between EXEC_CANDIDATE emission and TrackPID completion: children forked in
// that window won't have been caught by the BPF fork handler.
// Must be called with m.mu held.
func (m *SessionManager) catchUpChildren(pid uint32, session *TraceSession) {
	path := fmt.Sprintf("/proc/%d/task/%d/children", pid, pid)
	data, err := os.ReadFile(path) //nolint:gosec // path is constructed from a validated PID, not user input
	if err != nil {
		// Process may have already exited, or kernel doesn't expose children file
		return
	}

	fields := strings.Fields(string(data))
	for _, field := range fields {
		childPID, err := strconv.ParseUint(field, 10, 32)
		if err != nil {
			continue
		}
		cpid := uint32(childPID)

		// Skip if already tracked
		if _, ok := m.pidToSession[cpid]; ok {
			continue
		}

		// Enforce limits
		if session.PIDs() >= m.limits.MaxPIDsPerSession || m.totalPIDs >= m.limits.MaxTotalPIDs {
			break
		}

		session.AddPID(cpid)
		m.pidToSession[cpid] = session
		m.totalPIDs++

		if err := m.loader.TrackPID(int(cpid)); err != nil {
			log.Printf("session %s: catch-up TrackPID(%d) failed: %v", session.ID, cpid, err)
		}
	}
}

// MetadataManager returns the metadata manager used by this session manager.
func (m *SessionManager) MetadataManager() *procmeta.Manager {
	return m.metadataManager
}

// ActiveSessions returns the count of active sessions.
func (m *SessionManager) ActiveSessions() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// CloseAllSessions ends every active session's synthetic process.tree span
// and drops pending-starved sessions. Intended for daemon shutdown: without
// this, the OTEL BatchSpanProcessor's Shutdown only drains already-ended
// spans, and any still-active root span would be silently dropped.
func (m *SessionManager) CloseAllSessions() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	closed := 0
	for id, session := range m.sessions {
		session.EndSession(now)
		delete(m.sessions, id)
		closed++
	}
	// Also drop any pending-starved sessions (no span to end — just
	// release BPF tracking and state).
	for _, pending := range m.pendingStarved {
		m.dropPendingStarvedLocked(pending)
	}
	// Forget PID routing — we're going away.
	m.pidToSession = map[uint32]*TraceSession{}
	m.totalPIDs = 0
	return closed
}
