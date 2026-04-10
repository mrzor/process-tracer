package ambient

import (
	"fmt"
	"log"
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
		loader:          loader,
		tracer:          tracer,
		converter:       converter,
		resolver:        resolver,
		metadataManager: metadataManager,
		limits:          limits,
		pidToSession:    make(map[uint32]*TraceSession),
		sessions:        make(map[string]*TraceSession),
	}
}

// CreateSession creates a new trace session for a matched process.
func (m *SessionManager) CreateSession(pid uint32, rule *config.AmbientRule, metadata *procmeta.ProcessMetadata) (*TraceSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

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

	// Track the PID in BPF so descendants are auto-tracked
	if err := m.loader.TrackPID(int(pid)); err != nil {
		log.Printf("warning: failed to track PID %d in BPF: %v", pid, err)
	}

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
			delete(m.sessions, id)
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
