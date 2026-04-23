// Package eventstream manages the processing of eBPF ring buffer events.
package eventstream

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"

	"github.com/mrzor/process-tracer/internal/bpf"
	"github.com/mrzor/process-tracer/internal/eventprocessor"

	"github.com/cilium/ebpf/ringbuf"
)

// Stream reads events from a ringbuffer and dispatches them to a handler.
type Stream struct {
	reader  *ringbuf.Reader
	handler eventprocessor.EventHandler
	stopCh  chan struct{}
}

// New creates a new Stream with the given ringbuffer reader and event handler.
func New(reader *ringbuf.Reader, handler eventprocessor.EventHandler) *Stream {
	return &Stream{
		reader:  reader,
		handler: handler,
		stopCh:  make(chan struct{}),
	}
}

// Start begins reading events from the ringbuffer in a goroutine
// It returns immediately and processes events in the background until
// the context is canceled or Stop is called.
func (s *Stream) Start(ctx context.Context) error {
	go s.processEvents(ctx)
	return nil
}

// Stop signals the event processing goroutine to stop.
func (s *Stream) Stop() error {
	close(s.stopCh)
	return nil
}

// processEvents is the main event loop that reads and processes events.
func (s *Stream) processEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		default:
			record, err := s.reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("reading from ring buffer: %v", err)
				continue
			}
			s.dispatchRecord(record.RawSample)
		}
	}
}

// dispatchRecord peeks at the type byte of a raw ring-buffer sample and routes
// it to the right parser + handler. The Event struct has Type at offset 24
// (after Pid, Ppid, Uid, Pad1, Timestamp) and variant events share that layout.
func (s *Stream) dispatchRecord(raw []byte) {
	if len(raw) < 25 {
		log.Printf("record too short: %d bytes", len(raw))
		return
	}
	switch raw[24] {
	case bpf.EVENT_EXEC_ENV_CHUNK:
		var e bpf.EnvChunkEvent
		decodeAndHandle(raw, &e, "env chunk", s.handler.HandleEnvChunk)
	case bpf.EVENT_ENV_VAR:
		var e bpf.EnvVarEvent
		decodeAndHandle(raw, &e, "env var", s.handler.HandleEnvVar)
	case bpf.EVENT_ANCESTOR_TRACE:
		// Full 16-level real_parent dump emitted when BPF's tracking walk
		// couldn't find a tracked ancestor. Logged as debug-log for post-mortem.
		var e bpf.AncestorTraceEvent
		decodeAndHandle(raw, &e, "ancestor trace", s.handler.HandleAncestorTrace)
	case bpf.EVENT_CLONE_SYSCALL:
		// clone/clone3 syscall entry — correlate with sched_process_fork by
		// (tgid, timestamp).
		var e bpf.CloneSyscallEvent
		decodeAndHandle(raw, &e, "clone syscall", s.handler.HandleCloneSyscall)
	default:
		var e bpf.Event
		decodeAndHandle(raw, &e, "event", s.handler.HandleEvent)
	}
}

func decodeAndHandle[T any](raw []byte, out *T, label string, handle func(*T) error) {
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, out); err != nil {
		log.Printf("parsing %s event: %v", label, err)
		return
	}
	if err := handle(out); err != nil {
		log.Printf("handling %s: %v", label, err)
	}
}
