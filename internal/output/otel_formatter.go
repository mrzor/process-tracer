package output

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/mrzor/process-tracer/internal/attributes"
	"github.com/mrzor/process-tracer/internal/config"
	"github.com/mrzor/process-tracer/internal/procmeta"
	"github.com/mrzor/process-tracer/internal/pseudo_reverse_dns"
	"github.com/mrzor/process-tracer/internal/timesync"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// processSpanInfo holds span information for a process.
type processSpanInfo struct {
	Span      trace.Span
	SpanCtx   trace.SpanContext
	StartTime uint64 // monotonic timestamp
}

// tcpSpanInfo holds span information for a TCP connection.
type tcpSpanInfo struct {
	Span      trace.Span
	StartTime uint64 // monotonic timestamp
}

// OTELFormatter formats processed data as OpenTelemetry spans.
// This is a pure formatting layer - it receives pre-processed data and creates spans.
type OTELFormatter struct {
	tracer            trace.Tracer
	converter         *timesync.Converter
	resolver          *pseudo_reverse_dns.Resolver
	metadataManager   *procmeta.Manager
	attrEvaluator     *attributes.Evaluator
	traceIDEvaluator  *attributes.TraceIDEvaluator
	parentIDEvaluator *attributes.ParentIDEvaluator

	// Span tracking
	spans            map[uint32]*processSpanInfo // PID -> span info
	tcpSpans         map[uint64]*tcpSpanInfo     // socket addr -> TCP span info
	traceID          trace.TraceID               // root trace ID
	rootSpanPID      uint32                      // PID of the root span (0 if not set)
	rootSpanWarnings []attribute.KeyValue        // warnings to attach to root span
}

// NewOTELFormatter creates a new OTEL formatter.
func NewOTELFormatter(
	tracer trace.Tracer,
	converter *timesync.Converter,
	resolver *pseudo_reverse_dns.Resolver,
	metadataManager *procmeta.Manager,
	customAttrs []config.CustomAttribute,
	traceIDExpr string,
	parentIDExpr string,
) (*OTELFormatter, error) {
	// Create attribute evaluator
	attrEvaluator, err := attributes.NewEvaluator(customAttrs)
	if err != nil {
		return nil, err
	}

	// Create trace ID evaluator
	traceIDEvaluator, err := attributes.NewTraceIDEvaluator(traceIDExpr)
	if err != nil {
		return nil, err
	}

	// Create parent ID evaluator
	parentIDEvaluator, err := attributes.NewParentIDEvaluator(parentIDExpr)
	if err != nil {
		return nil, err
	}

	return &OTELFormatter{
		tracer:            tracer,
		converter:         converter,
		resolver:          resolver,
		metadataManager:   metadataManager,
		attrEvaluator:     attrEvaluator,
		traceIDEvaluator:  traceIDEvaluator,
		parentIDEvaluator: parentIDEvaluator,
		spans:             make(map[uint32]*processSpanInfo),
		tcpSpans:          make(map[uint64]*tcpSpanInfo),
		rootSpanPID:       0,
		rootSpanWarnings:  nil,
	}, nil
}

// HandleProcessExec creates a new process span.
func (f *OTELFormatter) HandleProcessExec(pid, ppid, _ uint32, timestamp uint64, metadata *procmeta.ProcessMetadata) error {
	// Determine if this is the root span (first process with no tracked parent)
	isRootSpan := false
	var parentSpanCtx trace.SpanContext
	if parent, exists := f.spans[ppid]; exists {
		parentSpanCtx = parent.SpanCtx
	} else if f.rootSpanPID == 0 {
		// No parent tracked and no root span set yet - this is the root
		isRootSpan = true
		f.rootSpanPID = pid
	}

	// Create context - for root span, try to inject custom trace ID and parent ID
	ctx := context.Background()

	if isRootSpan {
		ctx, _ = f.createRootSpanContext(ctx, pid, metadata) //nolint:errcheck // XXX: Consider logging custom trace ID injection failures
	} else if parentSpanCtx.IsValid() {
		ctx = trace.ContextWithSpanContext(ctx, parentSpanCtx)
	}

	// Convert monotonic timestamp to wall clock for span start time
	startTime := f.converter.MonotonicToWallClock(timestamp)

	// Start span with explicit start time
	_, span := f.tracer.Start(ctx, "process.exec",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithTimestamp(startTime),
	)

	// Store span info for this PID
	f.spans[pid] = &processSpanInfo{
		Span:      span,
		SpanCtx:   span.SpanContext(),
		StartTime: timestamp,
	}

	return nil
}

// createRootSpanContext creates a span context for the root span with custom trace/parent IDs.
func (f *OTELFormatter) createRootSpanContext(ctx context.Context, _ uint32, metadata *procmeta.ProcessMetadata) (context.Context, error) {
	var customTraceID trace.TraceID
	var customParentID trace.SpanID
	var allWarnings []attribute.KeyValue

	// Evaluate trace-id if expression is provided
	if metadata != nil {
		traceID, warnings, err := f.traceIDEvaluator.EvaluateAndValidate(metadata)
		if err != nil {
			// Metadata not available yet or evaluation failed
			allWarnings = append(allWarnings,
				attribute.String("_trace_id_evaluation_error", fmt.Sprintf("Failed to evaluate trace-id expression: %v", err)),
			)
		} else {
			customTraceID = traceID
			allWarnings = append(allWarnings, warnings...)
		}

		// Evaluate parent-id if expression is provided
		parentID, warnings, err := f.parentIDEvaluator.EvaluateAndValidate(metadata)
		if err != nil {
			// Metadata not available yet or evaluation failed - use zero span ID
			allWarnings = append(allWarnings,
				attribute.String("_parent_id_evaluation_error", fmt.Sprintf("Failed to evaluate parent-id expression: %v", err)),
			)
		} else {
			customParentID = parentID
			allWarnings = append(allWarnings, warnings...)
		}
	}

	// Store warnings to add to the span later
	if len(allWarnings) > 0 {
		f.rootSpanWarnings = allWarnings
	}

	// Create custom span context to inject trace ID and/or parent ID
	if customTraceID.IsValid() || customParentID.IsValid() {
		// Use custom trace ID if provided, otherwise generate one
		traceIDToUse := customTraceID
		if !traceIDToUse.IsValid() {
			traceIDToUse = f.traceID
		}

		// Create parent span context with custom trace ID and parent span ID
		spanCtxConfig := trace.SpanContextConfig{
			TraceID:    traceIDToUse,
			SpanID:     customParentID, // This becomes the parent span ID for the new span
			TraceFlags: trace.FlagsSampled,
			Remote:     true, // Mark as remote to indicate this is a parent from another service
		}

		customSpanCtx := trace.NewSpanContext(spanCtxConfig)
		if customSpanCtx.IsValid() {
			ctx = trace.ContextWithSpanContext(ctx, customSpanCtx)
		}

		// Store the trace ID for later spans to inherit
		if customTraceID.IsValid() {
			f.traceID = customTraceID
		}
	}

	return ctx, nil
}

// HandleProcessExit finalizes a process span.
func (f *OTELFormatter) HandleProcessExit(pid, ppid, uid uint32, _ uint32, timestamp uint64, comm []byte) error {
	// Retrieve span info for this PID
	spanInfo, ok := f.spans[pid]
	if !ok {
		// No span found - process started before tracing
		return nil
	}

	// Get metadata
	metadata := f.metadataManager.Get(pid)

	// Convert monotonic timestamp to wall clock for span end time
	endTime := f.converter.MonotonicToWallClock(timestamp)

	// Calculate duration
	duration := timestamp - spanInfo.StartTime

	// Evaluate custom attributes
	var customAttrs []attribute.KeyValue
	if metadata != nil {
		customAttrs, _ = f.attrEvaluator.EvaluateCustomAttributes(metadata) //nolint:errcheck // XXX: Consider logging custom attribute evaluation failures
	}

	// Extract comm string
	commStr := string(bytes.TrimRight(comm, "\x00"))

	// Set span attributes
	//nolint:gosec // uint64 to int64 conversion for duration is safe
	spanInfo.Span.SetAttributes(
		attribute.Int("process.pid", int(pid)),
		attribute.Int("process.parent_pid", int(ppid)),
		attribute.Int("process.owner.uid", int(uid)),
		attribute.String("process.command", commStr),
		attribute.Int64("process.duration_ns", int64(duration)),
	)

	// Add custom attributes if any
	if len(customAttrs) > 0 {
		spanInfo.Span.SetAttributes(customAttrs...)
	}

	// Add metadata collection errors as span attributes if any
	if metaErr := f.metadataManager.GetError(pid); metaErr != nil {
		spanInfo.Span.SetAttributes(
			attribute.String("_tracing_error_0", metaErr.Error()),
		)
	}

	// Add environment capture issues as span attributes if any
	if envIssues := f.metadataManager.GetIssues(pid); len(envIssues) > 0 {
		for i, issue := range envIssues {
			spanInfo.Span.SetAttributes(
				attribute.String(fmt.Sprintf("_tracing_warning_%d", i), issue),
			)
		}
	}

	// Add root span warnings if this is the root span
	if pid == f.rootSpanPID && len(f.rootSpanWarnings) > 0 {
		spanInfo.Span.SetAttributes(f.rootSpanWarnings...)
	}

	// End span with explicit end time
	spanInfo.Span.End(trace.WithTimestamp(endTime))

	// Clean up metadata and span info
	f.metadataManager.Delete(pid)
	delete(f.spans, pid)

	return nil
}

// HandleTCPConnect creates a new TCP connection span.
func (f *OTELFormatter) HandleTCPConnect(pid uint32, skaddr uint64, _, _ []byte, _, _, _ uint16, timestamp uint64) error {
	// Get parent span context from the process
	var parentSpanCtx trace.SpanContext
	if procSpanInfo, exists := f.spans[pid]; exists {
		parentSpanCtx = procSpanInfo.SpanCtx
	}

	// Create context with parent
	ctx := context.Background()
	if parentSpanCtx.IsValid() {
		ctx = trace.ContextWithSpanContext(ctx, parentSpanCtx)
	}

	// Convert monotonic timestamp to wall clock for span start time
	startTime := f.converter.MonotonicToWallClock(timestamp)

	// Start TCP connection span as child of process span
	_, span := f.tracer.Start(ctx, "tcp.connect",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithTimestamp(startTime),
	)

	// Store TCP span and start timestamp using socket address as key
	f.tcpSpans[skaddr] = &tcpSpanInfo{
		Span:      span,
		StartTime: timestamp,
	}

	return nil
}

// HandleTCPClose finalizes a TCP connection span.
func (f *OTELFormatter) HandleTCPClose(pid uint32, skaddr uint64, saddr, daddr []byte, sport, dport, family uint16, timestamp uint64) error {
	// Retrieve TCP span
	spanInfo, ok := f.tcpSpans[skaddr]
	if !ok {
		// Connection wasn't tracked (e.g., started before tracing)
		return nil
	}

	// Convert monotonic timestamp to wall clock for span end time
	endTime := f.converter.MonotonicToWallClock(timestamp)

	// Calculate duration
	duration := timestamp - spanInfo.StartTime

	// Format IP addresses based on family
	var destIP, srcIP string
	switch family {
	case 2: // AF_INET (IPv4)
		destIP = net.IP(daddr[:4]).String()
		srcIP = net.IP(saddr[:4]).String()
	case 10: // AF_INET6
		destIP = net.IP(daddr).String()
		srcIP = net.IP(saddr).String()
	default:
		destIP = fmt.Sprintf("unknown_family_%d", family)
		srcIP = fmt.Sprintf("unknown_family_%d", family)
	}

	// Set span attributes using semantic conventions
	//nolint:gosec // uint64 to int64 conversion for duration is safe
	attrs := []attribute.KeyValue{
		attribute.Int("process.pid", int(pid)),
		attribute.String("net.peer.ip", destIP),
		attribute.Int("net.peer.port", int(dport)),
		attribute.String("net.host.ip", srcIP),
		attribute.Int("net.host.port", int(sport)),
		attribute.String("net.transport", "tcp"),
		attribute.Int("net.family", int(family)),
		attribute.Int64("net.connection.duration_ns", int64(duration)),
	}

	// Add pseudo reverse DNS hostnames if available
	if destHosts := f.resolver.Lookup(destIP); len(destHosts) > 0 {
		attrs = append(attrs, attribute.String("network.pseudo_reverse_dns.dest_host", strings.Join(destHosts, ",")))
	}
	if srcHosts := f.resolver.Lookup(srcIP); len(srcHosts) > 0 {
		attrs = append(attrs, attribute.String("network.pseudo_reverse_dns.src_host", strings.Join(srcHosts, ",")))
	}

	spanInfo.Span.SetAttributes(attrs...)
	spanInfo.Span.SetStatus(codes.Ok, "Connection closed")

	// End span with explicit end time
	spanInfo.Span.End(trace.WithTimestamp(endTime))

	// Clean up TCP span
	delete(f.tcpSpans, skaddr)

	return nil
}
