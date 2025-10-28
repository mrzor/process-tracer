package output

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"time"

	"sched_trace/internal/bpf"
	"sched_trace/internal/pseudo_reverse_dns"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// OTELSpanInfo holds span and timing information
type OTELSpanInfo struct {
	Span      trace.Span
	SpanCtx   trace.SpanContext
	StartTime uint64 // monotonic timestamp in nanoseconds
}

// OTELFormatter formats events as OpenTelemetry spans
type OTELFormatter struct {
	tracer     trace.Tracer
	spans      map[uint32]*OTELSpanInfo // PID -> span info
	tcpSpans   map[uint64]trace.Span    // socket addr -> TCP span
	tcpStartTs map[uint64]uint64        // socket addr -> start timestamp
	traceID    trace.TraceID
	resolver   *pseudo_reverse_dns.Resolver
	bootTime   time.Time
}

// NewOTELFormatter creates a new OTELFormatter
func NewOTELFormatter(tracer trace.Tracer, traceIDHex string, resolver *pseudo_reverse_dns.Resolver) (*OTELFormatter, error) {
	bootTime, err := getSystemBootTime()
	if err != nil {
		// Fallback: estimate boot time from current time - uptime
		// This is less accurate but allows the tracer to continue
		bootTime = time.Now().Add(-time.Hour) // Conservative fallback
	}

	// Parse trace ID from hex string
	traceID, err := trace.TraceIDFromHex(traceIDHex)
	if err != nil {
		return nil, fmt.Errorf("invalid trace ID: %w", err)
	}

	return &OTELFormatter{
		tracer:     tracer,
		spans:      make(map[uint32]*OTELSpanInfo),
		tcpSpans:   make(map[uint64]trace.Span),
		tcpStartTs: make(map[uint64]uint64),
		traceID:    traceID,
		resolver:   resolver,
		bootTime:   bootTime,
	}, nil
}

// monotonicToWallClock converts a monotonic timestamp (nanoseconds since boot) to wall-clock time
func (f *OTELFormatter) monotonicToWallClock(monotonicNanos uint64) time.Time {
	return f.bootTime.Add(time.Duration(monotonicNanos))
}

// HandleEvent formats events as OpenTelemetry spans
func (f *OTELFormatter) HandleEvent(event *bpf.Event) error {
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

func (f *OTELFormatter) handleProcessExec(event *bpf.Event) error {
	// Determine parent span context by looking up parent PID
	var parentSpanCtx trace.SpanContext
	if parent, exists := f.spans[event.Ppid]; exists {
		parentSpanCtx = parent.SpanCtx
	}

	// Create context with parent if it exists
	ctx := context.Background()
	if parentSpanCtx.IsValid() {
		ctx = trace.ContextWithSpanContext(ctx, parentSpanCtx)
	}

	// Convert monotonic timestamp to wall clock for span start time
	startTime := f.monotonicToWallClock(event.Timestamp)

	// Start span with explicit start time
	ctx, span := f.tracer.Start(ctx, "process.exec",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithTimestamp(startTime),
	)

	// Store span info for this PID
	f.spans[event.Pid] = &OTELSpanInfo{
		Span:      span,
		SpanCtx:   span.SpanContext(),
		StartTime: event.Timestamp,
	}

	// Ingest static sources for this PID (environ, cmdline)
	f.resolver.HandleStaticSources(int(event.Pid))

	return nil
}

func (f *OTELFormatter) handleProcessExit(event *bpf.Event) error {
	procData := event.ProcessData()
	if procData == nil {
		return fmt.Errorf("invalid process data for EXIT event")
	}

	comm := string(bytes.TrimRight(procData.Comm[:], "\x00"))

	// Retrieve span info for this PID
	spanInfo, ok := f.spans[event.Pid]
	if !ok {
		// No span found - process started before tracing
		return nil
	}

	// Convert monotonic timestamp to wall clock for span end time
	endTime := f.monotonicToWallClock(event.Timestamp)

	// Calculate duration
	duration := event.Timestamp - spanInfo.StartTime

	// Set span attributes
	spanInfo.Span.SetAttributes(
		attribute.Int("process.pid", int(event.Pid)),
		attribute.Int("process.parent_pid", int(event.Ppid)),
		attribute.Int("process.owner.uid", int(event.Uid)),
		attribute.String("process.command", comm),
		attribute.Int64("process.duration_ns", int64(duration)),
	)

	// End span with explicit end time
	spanInfo.Span.End(trace.WithTimestamp(endTime))

	// Clean up - but keep spanInfo for late TCP events that may reference this PID
	delete(f.spans, event.Pid)

	return nil
}

func (f *OTELFormatter) handleTCPConnect(event *bpf.Event) error {
	tcpData := event.TCPData()
	if tcpData == nil {
		return fmt.Errorf("invalid TCP data for CONNECT event")
	}

	// Get parent span context from the process
	var parentSpanCtx trace.SpanContext
	if procSpanInfo, exists := f.spans[event.Pid]; exists {
		parentSpanCtx = procSpanInfo.SpanCtx
	}

	// Create context with parent
	ctx := context.Background()
	if parentSpanCtx.IsValid() {
		ctx = trace.ContextWithSpanContext(ctx, parentSpanCtx)
	}

	// Convert monotonic timestamp to wall clock for span start time
	startTime := f.monotonicToWallClock(event.Timestamp)

	// Start TCP connection span as child of process span
	ctx, span := f.tracer.Start(ctx, "tcp.connect",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithTimestamp(startTime),
	)

	// Store TCP span and start timestamp using socket address as key
	f.tcpSpans[tcpData.Skaddr] = span
	f.tcpStartTs[tcpData.Skaddr] = event.Timestamp

	return nil
}

func (f *OTELFormatter) handleTCPClose(event *bpf.Event) error {
	tcpData := event.TCPData()
	if tcpData == nil {
		return fmt.Errorf("invalid TCP data for CLOSE event")
	}

	// Retrieve TCP span
	span, ok := f.tcpSpans[tcpData.Skaddr]
	if !ok {
		// Connection wasn't tracked (e.g., started before tracing)
		return nil
	}

	// Convert monotonic timestamp to wall clock for span end time
	endTime := f.monotonicToWallClock(event.Timestamp)

	// Calculate duration
	var duration uint64
	if startTs, ok := f.tcpStartTs[tcpData.Skaddr]; ok {
		duration = event.Timestamp - startTs
	}

	// Format IP addresses based on family
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

	// Set span attributes using semantic conventions
	attrs := []attribute.KeyValue{
		attribute.Int("process.pid", int(event.Pid)),
		attribute.String("net.peer.ip", destIP),
		attribute.Int("net.peer.port", int(tcpData.Dport)),
		attribute.String("net.host.ip", srcIP),
		attribute.Int("net.host.port", int(tcpData.Sport)),
		attribute.String("net.transport", "tcp"),
		attribute.Int("net.family", int(tcpData.Family)),
		attribute.Int64("net.connection.duration_ns", int64(duration)),
	}

	// Add pseudo reverse DNS hostnames if available
	if destHosts := f.resolver.Lookup(destIP); len(destHosts) > 0 {
		attrs = append(attrs, attribute.String("network.pseudo_reverse_dns.dest_host", strings.Join(destHosts, ",")))
	}
	if srcHosts := f.resolver.Lookup(srcIP); len(srcHosts) > 0 {
		attrs = append(attrs, attribute.String("network.pseudo_reverse_dns.src_host", strings.Join(srcHosts, ",")))
	}

	span.SetAttributes(attrs...)
	span.SetStatus(codes.Ok, "Connection closed")

	// End span with explicit end time
	span.End(trace.WithTimestamp(endTime))

	// Clean up TCP span and start timestamp
	delete(f.tcpSpans, tcpData.Skaddr)
	delete(f.tcpStartTs, tcpData.Skaddr)

	return nil
}

// generateOTELSpanID generates a random 8-byte span ID
func generateOTELSpanID() trace.SpanID {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return trace.SpanID(b)
}
