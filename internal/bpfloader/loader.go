package bpfloader

import (
	"errors"
	"fmt"

	"sched_trace/internal/bpf"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Loader manages the lifecycle of BPF programs and their attachments
type Loader struct {
	objs               bpf.SchedTraceObjects
	execLink           link.Link
	exitLink           link.Link
	tcpCloseLink       link.Link
	tcpV4ConnectEntry  link.Link
	tcpV4ConnectExit   link.Link
	tcpV6ConnectEntry  link.Link
	tcpV6ConnectExit   link.Link
}

// New creates a new Loader and loads the BPF objects into the kernel
func New() (*Loader, error) {
	l := &Loader{}

	if err := bpf.LoadSchedTraceObjects(&l.objs, nil); err != nil {
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	return l, nil
}

// Attach attaches the BPF programs to their tracepoints
func (l *Loader) Attach() error {
	var err error

	// Attach to sched_process_exec tracepoint
	l.execLink, err = link.Tracepoint("sched", "sched_process_exec", l.objs.HandleExec, nil)
	if err != nil {
		return fmt.Errorf("attaching exec tracepoint: %w", err)
	}

	// Attach to sched_process_exit tracepoint
	l.exitLink, err = link.Tracepoint("sched", "sched_process_exit", l.objs.HandleExit, nil)
	if err != nil {
		// Clean up exec link if exit attachment fails
		l.execLink.Close()
		return fmt.Errorf("attaching exit tracepoint: %w", err)
	}

	// Attach kprobes for TCP connect tracking
	l.tcpV4ConnectEntry, err = link.Kprobe("tcp_v4_connect", l.objs.TcpV4ConnectEntry, nil)
	if err != nil {
		l.exitLink.Close()
		l.execLink.Close()
		return fmt.Errorf("attaching tcp_v4_connect kprobe: %w", err)
	}

	l.tcpV4ConnectExit, err = link.Kretprobe("tcp_v4_connect", l.objs.TcpV4ConnectExit, nil)
	if err != nil {
		l.tcpV4ConnectEntry.Close()
		l.exitLink.Close()
		l.execLink.Close()
		return fmt.Errorf("attaching tcp_v4_connect kretprobe: %w", err)
	}

	l.tcpV6ConnectEntry, err = link.Kprobe("tcp_v6_connect", l.objs.TcpV6ConnectEntry, nil)
	if err != nil {
		l.tcpV4ConnectExit.Close()
		l.tcpV4ConnectEntry.Close()
		l.exitLink.Close()
		l.execLink.Close()
		return fmt.Errorf("attaching tcp_v6_connect kprobe: %w", err)
	}

	l.tcpV6ConnectExit, err = link.Kretprobe("tcp_v6_connect", l.objs.TcpV6ConnectExit, nil)
	if err != nil {
		l.tcpV6ConnectEntry.Close()
		l.tcpV4ConnectExit.Close()
		l.tcpV4ConnectEntry.Close()
		l.exitLink.Close()
		l.execLink.Close()
		return fmt.Errorf("attaching tcp_v6_connect kretprobe: %w", err)
	}

	// Attach inet_sock_set_state tracepoint for TCP close tracking
	l.tcpCloseLink, err = link.Tracepoint("sock", "inet_sock_set_state", l.objs.HandleInetSockSetState, nil)
	if err != nil {
		l.tcpV6ConnectExit.Close()
		l.tcpV6ConnectEntry.Close()
		l.tcpV4ConnectExit.Close()
		l.tcpV4ConnectEntry.Close()
		l.exitLink.Close()
		l.execLink.Close()
		return fmt.Errorf("attaching TCP close tracepoint: %w", err)
	}

	return nil
}

// OpenRingBuffer opens and returns a ring buffer reader for receiving events
func (l *Loader) OpenRingBuffer() (*ringbuf.Reader, error) {
	rd, err := ringbuf.NewReader(l.objs.Rb)
	if err != nil {
		return nil, fmt.Errorf("opening ring buffer: %w", err)
	}
	return rd, nil
}

// TrackPID adds a PID to the tracked_pids map in the BPF program
func (l *Loader) TrackPID(pid int) error {
	pidKey := uint32(pid)
	val := uint8(1)
	if err := l.objs.TrackedPids.Put(&pidKey, &val); err != nil {
		return fmt.Errorf("adding PID %d to tracked map: %w", pid, err)
	}
	return nil
}

// Close releases all BPF resources including links and loaded objects
func (l *Loader) Close() error {
	var errs []error

	if l.tcpCloseLink != nil {
		if err := l.tcpCloseLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing TCP close link: %w", err))
		}
	}

	if l.tcpV6ConnectExit != nil {
		if err := l.tcpV6ConnectExit.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing TCP v6 connect exit link: %w", err))
		}
	}

	if l.tcpV6ConnectEntry != nil {
		if err := l.tcpV6ConnectEntry.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing TCP v6 connect entry link: %w", err))
		}
	}

	if l.tcpV4ConnectExit != nil {
		if err := l.tcpV4ConnectExit.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing TCP v4 connect exit link: %w", err))
		}
	}

	if l.tcpV4ConnectEntry != nil {
		if err := l.tcpV4ConnectEntry.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing TCP v4 connect entry link: %w", err))
		}
	}

	if l.exitLink != nil {
		if err := l.exitLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing exit link: %w", err))
		}
	}

	if l.execLink != nil {
		if err := l.execLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing exec link: %w", err))
		}
	}

	if err := l.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing BPF objects: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during cleanup: %v", errors.Join(errs...))
	}

	return nil
}
