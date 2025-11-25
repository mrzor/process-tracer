package eventprocessor

import (
	"strings"

	"github.com/mrzor/process-tracer/internal/bpf"
	"github.com/mrzor/process-tracer/internal/envreassembler"
	"github.com/mrzor/process-tracer/internal/procmeta"
	"github.com/mrzor/process-tracer/internal/reversedns"
)

// EventHandler is the interface for handling BPF events from the ring buffer.
type EventHandler interface {
	HandleEvent(event *bpf.Event) error
	HandleEnvChunk(chunk *bpf.EnvChunkEvent) error
	HandleEnvVar(envVar *bpf.EnvVarEvent) error
}

// ProcessEventHandler handles processed process events.
type ProcessEventHandler interface {
	HandleProcessExec(pid, ppid, uid uint32, timestamp uint64, metadata *procmeta.ProcessMetadata) error
	HandleProcessExit(pid, ppid, uid uint32, exitCode uint32, timestamp uint64, comm []byte) error
}

// TCPEventHandler handles processed TCP events.
type TCPEventHandler interface {
	HandleTCPConnect(pid uint32, skaddr uint64, saddr, daddr []byte, sport, dport, family uint16, timestamp uint64) error
	HandleTCPClose(pid uint32, skaddr uint64, saddr, daddr []byte, sport, dport, family uint16, timestamp uint64) error
}

// Processor coordinates event processing.
// It routes events to specialized handlers and manages data reassembly.
type Processor struct {
	chunkReassembler     *envreassembler.ChunkReassembler
	streamingReassembler *envreassembler.StreamingReassembler
	metadataManager      *procmeta.Manager
	resolver             *reversedns.Resolver
	processHandler       ProcessEventHandler
	tcpHandler           TCPEventHandler
}

// NewProcessor creates a new event processor.
func NewProcessor(
	metadataManager *procmeta.Manager,
	resolver *reversedns.Resolver,
	processHandler ProcessEventHandler,
	tcpHandler TCPEventHandler,
) *Processor {
	return &Processor{
		chunkReassembler:     envreassembler.NewChunkReassembler(),
		streamingReassembler: envreassembler.NewStreamingReassembler(),
		metadataManager:      metadataManager,
		resolver:             resolver,
		processHandler:       processHandler,
		tcpHandler:           tcpHandler,
	}
}

// HandleEvent routes events by type to specialized handlers.
func (p *Processor) HandleEvent(event *bpf.Event) error {
	switch event.Type {
	case bpf.EVENT_EXEC:
		return p.handleExec(event)
	case bpf.EVENT_EXIT:
		return p.handleExit(event)
	case bpf.EVENT_TCP_CONNECT:
		return p.handleTCPConnect(event)
	case bpf.EVENT_TCP_CLOSE:
		return p.handleTCPClose(event)
	default:
		// Unknown event type - ignore
		return nil
	}
}

// HandleEnvChunk processes environment variable chunks from execve events.
func (p *Processor) HandleEnvChunk(chunk *bpf.EnvChunkEvent) error {
	result, err := p.chunkReassembler.HandleChunk(chunk)
	if err != nil {
		return err
	}

	// If reassembly is complete, store the metadata
	if result != nil {
		p.storeReassembledData(chunk.Pid, result)
	}

	return nil
}

// HandleEnvVar processes individual environment variable events from streaming execve.
func (p *Processor) HandleEnvVar(envVar *bpf.EnvVarEvent) error {
	result, err := p.streamingReassembler.HandleVar(envVar)
	if err != nil {
		return err
	}

	// If collection is complete, store the metadata
	if result != nil {
		p.storeReassembledData(envVar.Pid, result)
	}

	return nil
}

// storeReassembledData stores reassembled args and env in the metadata manager.
func (p *Processor) storeReassembledData(pid uint32, result *envreassembler.ReassembledData) {
	// Get or create metadata
	metadata := p.metadataManager.GetOrCreate(pid)

	// Store the captured environment and args
	metadata.Environ = result.Env
	metadata.Args = result.Args
	metadata.CmdlineFull = strings.Join(result.Args, " ")

	// Feed environment and args to pseudo reverse DNS resolver
	endpoints := make([]string, 0, len(result.Env)+len(result.Args))
	for _, value := range result.Env {
		endpoints = append(endpoints, value)
	}
	endpoints = append(endpoints, result.Args...)
	p.resolver.IngestEndpoints(endpoints...)

	// Add any issues from reassembly
	if len(result.Issues) > 0 {
		p.metadataManager.AddIssues(pid, result.Issues)
	}
}

// handleExec processes EXEC events.
func (p *Processor) handleExec(event *bpf.Event) error {
	pid := event.Pid
	metadata := p.metadataManager.Get(pid)

	// If we don't have metadata yet, it will be provided via env chunks/vars
	// For now, just delegate to the process handler
	return p.processHandler.HandleProcessExec(event.Pid, event.Ppid, event.UID, event.Timestamp, metadata)
}

// handleExit processes EXIT events.
func (p *Processor) handleExit(event *bpf.Event) error {
	processData := event.ProcessData()
	if processData == nil {
		return nil
	}

	return p.processHandler.HandleProcessExit(event.Pid, event.Ppid, event.UID, processData.ExitCode, event.Timestamp, processData.Comm[:])
}

// handleTCPConnect processes TCP CONNECT events.
func (p *Processor) handleTCPConnect(event *bpf.Event) error {
	tcpData := event.TCPData()
	if tcpData == nil {
		return nil
	}

	return p.tcpHandler.HandleTCPConnect(
		event.Pid,
		tcpData.Skaddr,
		tcpData.Saddr[:],
		tcpData.Daddr[:],
		tcpData.Sport,
		tcpData.Dport,
		tcpData.Family,
		event.Timestamp,
	)
}

// handleTCPClose processes TCP CLOSE events.
func (p *Processor) handleTCPClose(event *bpf.Event) error {
	tcpData := event.TCPData()
	if tcpData == nil {
		return nil
	}

	return p.tcpHandler.HandleTCPClose(
		event.Pid,
		tcpData.Skaddr,
		tcpData.Saddr[:],
		tcpData.Daddr[:],
		tcpData.Sport,
		tcpData.Dport,
		tcpData.Family,
		event.Timestamp,
	)
}
