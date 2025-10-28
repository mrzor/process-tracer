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
type ConsoleFormatter struct{}

// NewConsoleFormatter creates a new ConsoleFormatter
func NewConsoleFormatter() *ConsoleFormatter {
	return &ConsoleFormatter{}
}

// HandleEvent formats and prints an event to stdout
func (f *ConsoleFormatter) HandleEvent(event *bpf.Event) error {
	// Convert comm to string (null-terminated)
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

	switch event.Type {
	case bpf.EVENT_EXEC:
		fmt.Printf("EXEC: pid=%d ppid=%d uid=%d comm=%s\n",
			event.Pid, event.Ppid, event.Uid, comm)
	case bpf.EVENT_EXIT:
		fmt.Printf("EXIT: pid=%d ppid=%d uid=%d exit_code=%d comm=%s\n",
			event.Pid, event.Ppid, event.Uid, event.ExitCode, comm)
	default:
		return fmt.Errorf("unknown event type: %d", event.Type)
	}

	return nil
}
