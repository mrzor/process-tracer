package ambient

import (
	"context"
	"sync"
	"time"

	"github.com/mrzor/process-tracer/internal/config"
	"github.com/mrzor/process-tracer/internal/output"
	"github.com/mrzor/process-tracer/internal/procmeta"
)

// TraceSession represents a single traced process tree in daemon mode.
type TraceSession struct {
	ID        string
	Rule      *config.AmbientRule
	RootPID   uint32
	CreatedAt time.Time
	Draining  bool // root has exited, waiting for descendants

	pids      map[uint32]bool
	formatter *output.OTELFormatter
	mu        sync.Mutex
}

// NewTraceSession creates a new trace session for the given root PID.
func NewTraceSession(id string, rule *config.AmbientRule, rootPID uint32, formatter *output.OTELFormatter) *TraceSession {
	pids := map[uint32]bool{rootPID: true}
	return &TraceSession{
		ID:        id,
		Rule:      rule,
		RootPID:   rootPID,
		CreatedAt: time.Now(),
		pids:      pids,
		formatter: formatter,
	}
}

// AddPID adds a descendant PID to this session.
func (s *TraceSession) AddPID(pid uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pids[pid] = true
}

// RemovePID removes a PID and returns true if the session has no more PIDs.
func (s *TraceSession) RemovePID(pid uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pids, pid)
	if pid == s.RootPID {
		s.Draining = true
	}
	return len(s.pids) == 0
}

// PIDs returns the number of PIDs in this session.
func (s *TraceSession) PIDs() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pids)
}

// PIDList returns a snapshot of every PID currently in this session. Safe
// to call concurrently — returns a copy.
func (s *TraceSession) PIDList() []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]uint32, 0, len(s.pids))
	for pid := range s.pids {
		out = append(out, pid)
	}
	return out
}

// HasPID returns whether the given PID belongs to this session.
func (s *TraceSession) HasPID(pid uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pids[pid]
}

// StartSession initializes the formatter's root "process.tree" span for this session.
func (s *TraceSession) StartSession(ctx context.Context, metadata *procmeta.ProcessMetadata, startTime time.Time) {
	s.formatter.StartSession(ctx, metadata, startTime)
}

// EndSession finalizes the formatter's root "process.tree" span for this session.
func (s *TraceSession) EndSession(endTime time.Time) {
	s.formatter.EndSession(endTime)
}

// ResolvedTraceID returns the 32-char hex trace ID applied at StartSession,
// or "" if auto-generated. Diagnostic use only.
func (s *TraceSession) ResolvedTraceID() string {
	return s.formatter.ResolvedTraceID()
}

// ResolvedTraceExprValue returns the raw pre-hash value of the trace_id
// expression (or literal) at session creation. Diagnostic use only.
func (s *TraceSession) ResolvedTraceExprValue() string {
	return s.formatter.ResolvedTraceExprValue()
}

// ResolvedTraceSource returns one of attributes.Source* describing how the
// trace_id was derived. Diagnostic use only.
func (s *TraceSession) ResolvedTraceSource() string {
	return s.formatter.ResolvedTraceSource()
}

// HandleProcessExec delegates to the session's formatter.
func (s *TraceSession) HandleProcessExec(pid, ppid, uid uint32, timestamp uint64, metadata *procmeta.ProcessMetadata) error {
	return s.formatter.HandleProcessExec(pid, ppid, uid, timestamp, metadata)
}

// HandleProcessExit delegates to the session's formatter.
func (s *TraceSession) HandleProcessExit(pid, ppid, uid uint32, exitCode uint32, timestamp uint64, comm []byte) error {
	return s.formatter.HandleProcessExit(pid, ppid, uid, exitCode, timestamp, comm)
}

// HandleTCPConnect delegates to the session's formatter.
func (s *TraceSession) HandleTCPConnect(pid uint32, skaddr uint64, saddr, daddr []byte, sport, dport, family uint16, timestamp uint64) error {
	return s.formatter.HandleTCPConnect(pid, skaddr, saddr, daddr, sport, dport, family, timestamp)
}

// HandleTCPClose delegates to the session's formatter.
func (s *TraceSession) HandleTCPClose(pid uint32, skaddr uint64, saddr, daddr []byte, sport, dport, family uint16, timestamp uint64) error {
	return s.formatter.HandleTCPClose(pid, skaddr, saddr, daddr, sport, dport, family, timestamp)
}
