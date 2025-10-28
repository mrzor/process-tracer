package output

import (
	"bytes"
	"fmt"

	"sched_trace/internal/bpf"
)

// EventHandler is the interface for handling BPF events
type EventHandler interface {
	HandleEvent(event *bpf.Event) error
}

// ConsoleFormatter formats events for console output
type ConsoleFormatter struct {
	// Map to track PID to start timestamp for duration calculation
	startTimes map[uint32]uint64
}

// NewConsoleFormatter creates a new ConsoleFormatter
func NewConsoleFormatter() *ConsoleFormatter {
	return &ConsoleFormatter{
		startTimes: make(map[uint32]uint64),
	}
}

// HandleEvent formats and prints an event to stdout
func (f *ConsoleFormatter) HandleEvent(event *bpf.Event) error {
	// Convert comm to string (null-terminated)
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

	switch event.Type {
	case bpf.EVENT_EXEC:
		// Store the start timestamp for this PID
		f.startTimes[event.Pid] = event.Timestamp
	case bpf.EVENT_EXIT:
		// Calculate duration if we have a start time
		startTime, ok := f.startTimes[event.Pid]
		if ok {
			duration := event.Timestamp - startTime
			fmt.Printf("pid=%d ppid=%d uid=%d comm=%s duration=%dns\n",
				event.Pid, event.Ppid, event.Uid, comm, duration)
			// Clean up the map entry
			delete(f.startTimes, event.Pid)
		} else {
			// No start time found (shouldn't happen in normal operation)
			fmt.Printf("pid=%d ppid=%d uid=%d comm=%s duration=unknown\n",
				event.Pid, event.Ppid, event.Uid, comm)
		}
	default:
		return fmt.Errorf("unknown event type: %d", event.Type)
	}

	return nil
}
