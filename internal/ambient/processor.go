package ambient

import (
	"log"
	"strings"
	"sync"
	"time"

	"github.com/mrzor/process-tracer/internal/bpf"
	"github.com/mrzor/process-tracer/internal/envreassembler"
	"github.com/mrzor/process-tracer/internal/procmeta"
)

// Processor routes BPF events to the appropriate trace sessions in ambient mode.
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
}

type pendingExitInfo struct {
	pid, ppid, uid uint32
	exitCode       uint32
	timestamp      uint64
	comm           []byte
	receivedAt     time.Time
}

// NewProcessor creates a new ambient mode event processor.
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

// HandleEvent routes regular events (EXEC, EXIT, TCP, EXEC_CANDIDATE).
func (p *Processor) HandleEvent(event *bpf.Event) error {
	switch event.Type {
	case bpf.EVENT_EXEC_CANDIDATE:
		return p.handleExecCandidate(event)
	case bpf.EVENT_EXEC:
		return p.handleExec(event)
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
	rule := p.filter.Match(comm)
	if rule == nil {
		// No match - clean up any buffered env data
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

// handleExec handles EVENT_EXEC for processes whose parent is already tracked.
func (p *Processor) handleExec(event *bpf.Event) error {
	pid := event.Pid
	ppid := event.Ppid

	// Add descendant to parent's session
	session := p.manager.AddDescendant(pid, ppid)
	if session == nil {
		return nil
	}

	// Get metadata if available
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

	return session.HandleProcessExec(pid, ppid, event.UID, event.Timestamp, metadata)
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
		// Not in any session - buffer briefly in case EXEC_CANDIDATE hasn't arrived yet
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
