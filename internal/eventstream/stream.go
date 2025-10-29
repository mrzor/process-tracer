package eventstream

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"

	"sched_trace/internal/bpf"
	"sched_trace/internal/output"

	"github.com/cilium/ebpf/ringbuf"
)

// Stream reads events from a ringbuffer and dispatches them to a handler.
type Stream struct {
	reader  *ringbuf.Reader
	handler output.EventHandler
	stopCh  chan struct{}
}

// New creates a new Stream with the given ringbuffer reader and event handler.
func New(reader *ringbuf.Reader, handler output.EventHandler) *Stream {
	return &Stream{
		reader:  reader,
		handler: handler,
		stopCh:  make(chan struct{}),
	}
}

// Start begins reading events from the ringbuffer in a goroutine
// It returns immediately and processes events in the background until
// the context is cancelled or Stop is called.
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

			var event bpf.Event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing event: %v", err)
				continue
			}

			if err := s.handler.HandleEvent(&event); err != nil {
				log.Printf("handling event: %v", err)
			}
		}
	}
}
