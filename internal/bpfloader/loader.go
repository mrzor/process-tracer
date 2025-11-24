// Package bpfloader manages the lifecycle of eBPF programs and their kernel attachments.
package bpfloader

import (
	"errors"
	"fmt"

	"github.com/mrzor/process-tracer/internal/bpf"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Loader manages the lifecycle of BPF programs and their attachments.
type Loader struct {
	objs              bpf.ProcessTracerObjects
	execLink          link.Link
	execveEnterLink   link.Link
	exitLink          link.Link
	tcpCloseLink      link.Link
	tcpV4ConnectEntry link.Link
	tcpV4ConnectExit  link.Link
	tcpV6ConnectEntry link.Link
	tcpV6ConnectExit  link.Link
}

// New creates a new Loader and loads the BPF objects into the kernel.
func New() (*Loader, error) {
	l := &Loader{}

	if err := bpf.LoadProcessTracerObjects(&l.objs, nil); err != nil {
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	return l, nil
}

// closeErrorf closes all attached links and returns a formatted error.
func (l *Loader) closeErrorf(errstr string, e error) error {
	// Close all links that may have been attached (nil-safe)
	// We intentionally ignore errors during cleanup here since we're already in an error path
	if l.tcpCloseLink != nil {
		_ = l.tcpCloseLink.Close() //nolint:errcheck // Best-effort cleanup in error path
	}
	if l.tcpV6ConnectExit != nil {
		_ = l.tcpV6ConnectExit.Close() //nolint:errcheck // Best-effort cleanup in error path
	}
	if l.tcpV6ConnectEntry != nil {
		_ = l.tcpV6ConnectEntry.Close() //nolint:errcheck // Best-effort cleanup in error path
	}
	if l.tcpV4ConnectExit != nil {
		_ = l.tcpV4ConnectExit.Close() //nolint:errcheck // Best-effort cleanup in error path
	}
	if l.tcpV4ConnectEntry != nil {
		_ = l.tcpV4ConnectEntry.Close() //nolint:errcheck // Best-effort cleanup in error path
	}
	if l.exitLink != nil {
		_ = l.exitLink.Close() //nolint:errcheck // Best-effort cleanup in error path
	}
	if l.execLink != nil {
		_ = l.execLink.Close() //nolint:errcheck // Best-effort cleanup in error path
	}
	if l.execveEnterLink != nil {
		_ = l.execveEnterLink.Close() //nolint:errcheck // Best-effort cleanup in error path
	}
	return fmt.Errorf("%s: %w", errstr, e)
}

// Attach attaches the BPF programs to their tracepoints.
func (l *Loader) Attach() error {
	var err error

	// Attach to sched_process_exec tracepoint
	l.execLink, err = link.Tracepoint("sched", "sched_process_exec", l.objs.HandleExec, nil)
	if err != nil {
		return l.closeErrorf("attaching exec tracepoint", err)
	}

	// Attach to sys_enter_execve tracepoint for argv/envp capture
	l.execveEnterLink, err = link.Tracepoint("syscalls", "sys_enter_execve", l.objs.TraceExecveEnter, nil)
	if err != nil {
		return l.closeErrorf("attaching sys_enter_execve tracepoint", err)
	}

	// Attach to sched_process_exit tracepoint
	l.exitLink, err = link.Tracepoint("sched", "sched_process_exit", l.objs.HandleExit, nil)
	if err != nil {
		return l.closeErrorf("attaching exit tracepoint", err)
	}

	// Attach kprobes for TCP connect tracking
	l.tcpV4ConnectEntry, err = link.Kprobe("tcp_v4_connect", l.objs.TcpV4ConnectEntry, nil)
	if err != nil {
		return l.closeErrorf("attaching tcp_v4_connect kprobe", err)
	}

	l.tcpV4ConnectExit, err = link.Kretprobe("tcp_v4_connect", l.objs.TcpV4ConnectExit, nil)
	if err != nil {
		return l.closeErrorf("attaching tcp_v4_connect kretprobe", err)
	}

	l.tcpV6ConnectEntry, err = link.Kprobe("tcp_v6_connect", l.objs.TcpV6ConnectEntry, nil)
	if err != nil {
		return l.closeErrorf("attaching tcp_v6_connect kprobe", err)
	}

	l.tcpV6ConnectExit, err = link.Kretprobe("tcp_v6_connect", l.objs.TcpV6ConnectExit, nil)
	if err != nil {
		return l.closeErrorf("attaching tcp_v6_connect kretprobe", err)
	}

	// Attach inet_sock_set_state tracepoint for TCP close tracking
	l.tcpCloseLink, err = link.Tracepoint("sock", "inet_sock_set_state", l.objs.HandleInetSockSetState, nil)
	if err != nil {
		return l.closeErrorf("attaching TCP close tracepoint", err)
	}

	return nil
}

// OpenRingBuffer opens and returns a ring buffer reader for receiving events.
func (l *Loader) OpenRingBuffer() (*ringbuf.Reader, error) {
	rd, err := ringbuf.NewReader(l.objs.Rb)
	if err != nil {
		return nil, fmt.Errorf("opening ring buffer: %w", err)
	}
	return rd, nil
}

// TrackPID adds a PID to the tracked_pids map in the BPF program.
func (l *Loader) TrackPID(pid int) error {
	//nolint:gosec // int to uint32 conversion required for BPF map key type
	pidKey := uint32(pid)
	val := uint8(1)
	if err := l.objs.TrackedPids.Put(&pidKey, &val); err != nil {
		return fmt.Errorf("adding PID %d to tracked map: %w", pid, err)
	}
	return nil
}

// Close releases all BPF resources including links and loaded objects.
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

	if l.execveEnterLink != nil {
		if err := l.execveEnterLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing execve enter link: %w", err))
		}
	}

	if err := l.objs.Close(); err != nil {
		errs = append(errs, fmt.Errorf("closing BPF objects: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during cleanup: %w", errors.Join(errs...))
	}

	return nil
}
