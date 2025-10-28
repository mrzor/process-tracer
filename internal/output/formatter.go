package output

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"sched_trace/internal/bpf"
	"sched_trace/internal/pseudo_reverse_dns"
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

// TCPSpanInfo holds OpenTelemetry span information for a TCP connection
type TCPSpanInfo struct {
	StartTime    uint64
	Pid          uint32
	ParentSpanID uint64 // Store parent span ID at connect time
}

// ConsoleFormatter formats events for console output
type ConsoleFormatter struct {
	// Map to track PID to span information
	spans    map[uint32]*SpanInfo
	tcpSpans map[uint64]*TCPSpanInfo // keyed by socket address
	traceID  string                  // 32 hex chars
	resolver *pseudo_reverse_dns.Resolver
	bootTime time.Time // System boot time for converting monotonic timestamps to wall-clock
}

// NewConsoleFormatter creates a new ConsoleFormatter
func NewConsoleFormatter(traceID string, resolver *pseudo_reverse_dns.Resolver) *ConsoleFormatter {
	bootTime, err := getSystemBootTime()
	if err != nil {
		// Fallback: estimate boot time from current time - uptime
		// This is less accurate but allows the tracer to continue
		bootTime = time.Now().Add(-time.Hour) // Conservative fallback
	}

	return &ConsoleFormatter{
		spans:    make(map[uint32]*SpanInfo),
		tcpSpans: make(map[uint64]*TCPSpanInfo),
		traceID:  traceID,
		resolver: resolver,
		bootTime: bootTime,
	}
}

// getSystemBootTime reads the system boot time from /proc/stat
func getSystemBootTime() (time.Time, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to open /proc/stat: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "btime ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				bootTimeSec, err := strconv.ParseInt(fields[1], 10, 64)
				if err != nil {
					return time.Time{}, fmt.Errorf("failed to parse btime: %w", err)
				}
				return time.Unix(bootTimeSec, 0), nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return time.Time{}, fmt.Errorf("error reading /proc/stat: %w", err)
	}

	return time.Time{}, fmt.Errorf("btime not found in /proc/stat")
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

// monotonicToWallClock converts a monotonic timestamp (nanoseconds since boot) to wall-clock time
func (f *ConsoleFormatter) monotonicToWallClock(monotonicNanos uint64) time.Time {
	return f.bootTime.Add(time.Duration(monotonicNanos))
}

// HandleEvent formats and prints an event to stdout
func (f *ConsoleFormatter) HandleEvent(event *bpf.Event) error {
	switch event.Type {
	case bpf.EVENT_EXEC:
		return f.handleProcessExec(event)
	case bpf.EVENT_EXIT:
		return f.handleProcessExit(event)
	case bpf.EVENT_TCP_CONNECT:
		return f.handleTCPConnect(event)
	case bpf.EVENT_TCP_CLOSE:
		return f.handleTCPClose(event)
	default:
		return fmt.Errorf("unknown event type: %d", event.Type)
	}
}

func (f *ConsoleFormatter) handleProcessExec(event *bpf.Event) error {
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

	// Ingest static sources for this PID (environ, cmdline)
	f.resolver.HandleStaticSources(int(event.Pid))

	return nil
}

func (f *ConsoleFormatter) handleProcessExit(event *bpf.Event) error {
	procData := event.ProcessData()
	if procData == nil {
		return fmt.Errorf("invalid process data for EXIT event")
	}

	comm := string(bytes.TrimRight(procData.Comm[:], "\x00"))

	// Retrieve span info
	spanInfo, ok := f.spans[event.Pid]
	if ok {
		duration := event.Timestamp - spanInfo.StartTime
		startTime := f.monotonicToWallClock(spanInfo.StartTime)
		endTime := f.monotonicToWallClock(event.Timestamp)

		fmt.Printf("type=process pid=%d ppid=%d uid=%d comm=%s start_time=%s end_time=%s duration=%dns span_id=%016x parent_span_id=%016x trace_id=%s\n",
			event.Pid, event.Ppid, event.Uid, comm,
			startTime.Format(time.RFC3339Nano), endTime.Format(time.RFC3339Nano), duration,
			spanInfo.SpanID, spanInfo.ParentSpanID, f.traceID)

		// Don't delete the span immediately - TCP CLOSE events may arrive after process exit
		// We'll let them accumulate (in a real system, we'd need periodic cleanup)
	} else {
		// No span info found (shouldn't happen in normal operation)
		fmt.Printf("type=process pid=%d ppid=%d uid=%d comm=%s start_time=unknown end_time=unknown duration=unknown span_id=unknown parent_span_id=unknown trace_id=%s\n",
			event.Pid, event.Ppid, event.Uid, comm, f.traceID)
	}

	return nil
}

func (f *ConsoleFormatter) handleTCPConnect(event *bpf.Event) error {
	tcpData := event.TCPData()
	if tcpData == nil {
		return fmt.Errorf("invalid TCP data for CONNECT event")
	}

	// Get parent span ID now, before the process exits
	parentSpanID := uint64(0)
	if procSpan, exists := f.spans[event.Pid]; exists {
		parentSpanID = procSpan.SpanID
	}

	// Store TCP span info using socket address as key
	f.tcpSpans[tcpData.Skaddr] = &TCPSpanInfo{
		StartTime:    event.Timestamp,
		Pid:          event.Pid,
		ParentSpanID: parentSpanID,
	}

	return nil
}

func (f *ConsoleFormatter) handleTCPClose(event *bpf.Event) error {
	tcpData := event.TCPData()
	if tcpData == nil {
		return fmt.Errorf("invalid TCP data for CLOSE event")
	}

	// Retrieve TCP span info
	tcpSpanInfo, ok := f.tcpSpans[tcpData.Skaddr]
	if !ok {
		// Connection wasn't tracked (e.g., started before tracing)
		return nil
	}

	duration := event.Timestamp - tcpSpanInfo.StartTime
	startTime := f.monotonicToWallClock(tcpSpanInfo.StartTime)
	endTime := f.monotonicToWallClock(event.Timestamp)

	// Format IP address based on family
	var destIP, srcIP string
	if tcpData.Family == 2 { // AF_INET (IPv4)
		destIP = net.IP(tcpData.Daddr[:4]).String()
		srcIP = net.IP(tcpData.Saddr[:4]).String()
	} else if tcpData.Family == 10 { // AF_INET6
		destIP = net.IP(tcpData.Daddr[:]).String()
		srcIP = net.IP(tcpData.Saddr[:]).String()
	} else {
		destIP = fmt.Sprintf("unknown_family_%d", tcpData.Family)
		srcIP = fmt.Sprintf("unknown_family_%d", tcpData.Family)
	}

	// Resolve hostnames (late resolution - called only when formatting output)
	var destHostField, srcHostField string
	if destHosts := f.resolver.Lookup(destIP); len(destHosts) > 0 {
		destHostField = fmt.Sprintf(" dest_host=%s", strings.Join(destHosts, ","))
	}
	if srcHosts := f.resolver.Lookup(srcIP); len(srcHosts) > 0 {
		srcHostField = fmt.Sprintf(" src_host=%s", strings.Join(srcHosts, ","))
	}

	fmt.Printf("type=tcp pid=%d dest_ip=%s dest_port=%d%s src_ip=%s src_port=%d%s family=%d start_time=%s end_time=%s duration=%dns tcp_span_id=%016x parent_span_id=%016x trace_id=%s\n",
		tcpSpanInfo.Pid, destIP, tcpData.Dport, destHostField, srcIP, tcpData.Sport, srcHostField, tcpData.Family,
		startTime.Format(time.RFC3339Nano), endTime.Format(time.RFC3339Nano), duration,
		tcpData.Skaddr, tcpSpanInfo.ParentSpanID, f.traceID)

	// Clean up TCP span entry
	delete(f.tcpSpans, tcpData.Skaddr)

	return nil
}
