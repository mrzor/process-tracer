package output

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"sched_trace/internal/bpf"
)

// EventHandler is the interface for handling BPF events
type EventHandler interface {
	HandleEvent(event *bpf.Event) error
}

// SpanInfo holds OpenTelemetry span information for a process
type SpanInfo struct {
	SpanID       uint64
	ParentSpanID uint64
	StartTime    uint64
}

// ConsoleFormatter formats events for console output
type ConsoleFormatter struct {
	// Map to track PID to span information
	spans   map[uint32]*SpanInfo
	traceID string // 32 hex chars
}

// NewConsoleFormatter creates a new ConsoleFormatter
func NewConsoleFormatter(traceID string) *ConsoleFormatter {
	return &ConsoleFormatter{
		spans:   make(map[uint32]*SpanInfo),
		traceID: traceID,
	}
}

// generateSpanID generates a random 64-bit span ID
func generateSpanID() (uint64, error) {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

// HandleEvent formats and prints an event to stdout
func (f *ConsoleFormatter) HandleEvent(event *bpf.Event) error {
	// Convert comm to string (null-terminated)
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

	switch event.Type {
	case bpf.EVENT_EXEC:
		// Generate span ID for this process
		spanID, err := generateSpanID()
		if err != nil {
			return fmt.Errorf("failed to generate span ID: %v", err)
		}

		// Determine parent span ID by looking up parent PID
		parentSpanID := uint64(0) // default to root span
		if parentSpan, exists := f.spans[event.Ppid]; exists {
			parentSpanID = parentSpan.SpanID
		}

		// Store span info for this PID
		f.spans[event.Pid] = &SpanInfo{
			SpanID:       spanID,
			ParentSpanID: parentSpanID,
			StartTime:    event.Timestamp,
		}

	case bpf.EVENT_EXIT:
		// Retrieve span info
		spanInfo, ok := f.spans[event.Pid]
		if ok {
			duration := event.Timestamp - spanInfo.StartTime

			// Convert trace ID to bytes for formatting
			traceIDBytes, err := hex.DecodeString(f.traceID)
			if err != nil {
				return fmt.Errorf("invalid trace ID: %v", err)
			}

			fmt.Printf("pid=%d ppid=%d uid=%d comm=%s duration=%dns span_id=%016x parent_span_id=%016x trace_id=%s\n",
				event.Pid, event.Ppid, event.Uid, comm, duration,
				spanInfo.SpanID, spanInfo.ParentSpanID, hex.EncodeToString(traceIDBytes))

			// Clean up the span entry
			delete(f.spans, event.Pid)
		} else {
			// No span info found (shouldn't happen in normal operation)
			fmt.Printf("pid=%d ppid=%d uid=%d comm=%s duration=unknown span_id=unknown parent_span_id=unknown trace_id=%s\n",
				event.Pid, event.Ppid, event.Uid, comm, f.traceID)
		}
	default:
		return fmt.Errorf("unknown event type: %d", event.Type)
	}

	return nil
}
