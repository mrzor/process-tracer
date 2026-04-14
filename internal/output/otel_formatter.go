package output

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mrzor/process-tracer/internal/attributes"
	"github.com/mrzor/process-tracer/internal/config"
	"github.com/mrzor/process-tracer/internal/procmeta"
	"github.com/mrzor/process-tracer/internal/reversedns"
	"github.com/mrzor/process-tracer/internal/timesync"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// processSpanInfo holds span information for a process.
type processSpanInfo struct {
	Span      trace.Span
	SpanCtx   trace.SpanContext
	ParentCtx trace.SpanContext // parent's context, preserved for exec-replacement
	StartTime uint64           // monotonic timestamp
}

// tcpSpanInfo holds span information for a TCP connection.
type tcpSpanInfo struct {
	Span      trace.Span
	StartTime uint64 // monotonic timestamp
}

// OTELFormatter formats processed data as OpenTelemetry spans.
// This is a pure formatting layer - it receives pre-processed data and creates spans.
//
// A single invocation of process-tracer produces one "process.tree" root span
// (created by StartSession, ended by EndSession) under which all process.exec
// spans hang. If a process.exec's ppid span isn't tracked, the span falls back
// to the process.tree root — orphans are never allowed to start a new trace.
type OTELFormatter struct {
	tracer             trace.Tracer
	converter          *timesync.Converter
	resolver           *reversedns.Resolver
	metadataManager    *procmeta.Manager
	attrEvaluator      *attributes.Evaluator
	traceIDEvaluator   *attributes.TraceIDEvaluator
	parentIDEvaluator  *attributes.ParentIDEvaluator
	addDebugAttributes bool

	// Span tracking
	spans    map[uint32]*processSpanInfo // PID -> span info
	tcpSpans map[uint64]*tcpSpanInfo     // socket addr -> TCP span info

	// Session root: the "process.tree" span that covers this invocation.
	sessionRootSpan trace.Span
	sessionRootCtx  trace.SpanContext
}

// NewOTELFormatter creates a new OTEL formatter.
func NewOTELFormatter(
	tracer trace.Tracer,
	converter *timesync.Converter,
	resolver *reversedns.Resolver,
	metadataManager *procmeta.Manager,
	customAttrs []config.CustomAttribute,
	skipEmptyValues bool,
	traceIDExpr string,
	parentIDExpr string,
	addDebugAttributes bool,
) (*OTELFormatter, error) {
	// Create attribute evaluator
	attrEvaluator, err := attributes.NewEvaluator(customAttrs, skipEmptyValues)
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
		tracer:             tracer,
		converter:          converter,
		resolver:           resolver,
		metadataManager:    metadataManager,
		attrEvaluator:      attrEvaluator,
		traceIDEvaluator:   traceIDEvaluator,
		parentIDEvaluator:  parentIDEvaluator,
		addDebugAttributes: addDebugAttributes,
		spans:              make(map[uint32]*processSpanInfo),
		tcpSpans:           make(map[uint64]*tcpSpanInfo),
	}, nil
}

// StartSession creates the synthetic "process.tree" root span for this invocation.
// Must be called before any Handle* methods so that children can be parented under it.
//
// metadata describes the invocation context used to resolve trace_id/parent_id
// expressions (typically the matched process in daemon mode, or a synthetic
// representation of the traced command in trace mode). May be nil, in which
// case trace_id/parent_id expressions are evaluated against empty state.
func (f *OTELFormatter) StartSession(ctx context.Context, metadata *procmeta.ProcessMetadata, startTime time.Time) {
	customTraceID, customParentID, warnings, debugAttrs := f.resolveRootIDs(metadata)

	// Build a parent SpanContext that carries the desired trace_id (and real
	// parent span id if configured). When trace_id is configured but parent_id
	// isn't, we synthesize a random SpanID for the virtual parent so that
	// trace.NewSpanContext(...).IsValid() returns true — the OTEL SDK needs a
	// non-zero SpanID to honor a parent context.
	if customTraceID.IsValid() {
		spanID := customParentID
		if !spanID.IsValid() {
			if _, err := rand.Read(spanID[:]); err != nil {
				log.Printf("warning: rand.Read for virtual parent span ID failed: %v", err)
			}
		}
		if spanID.IsValid() {
			parentCtx := trace.NewSpanContext(trace.SpanContextConfig{
				TraceID:    customTraceID,
				SpanID:     spanID,
				TraceFlags: trace.FlagsSampled,
				Remote:     true,
			})
			if parentCtx.IsValid() {
				ctx = trace.ContextWithSpanContext(ctx, parentCtx)
			}
		}
	}

	_, span := f.tracer.Start(ctx, "process.tree",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithTimestamp(startTime),
	)

	f.sessionRootSpan = span
	f.sessionRootCtx = span.SpanContext()

	// Attach process identity attributes from the matched process metadata.
	if metadata != nil && len(metadata.Args) > 0 {
		span.SetAttributes(
			attribute.String("process.command", filepath.Base(metadata.Args[0])),
		)
		if metadata.CmdlineFull != "" {
			span.SetAttributes(
				attribute.String("process.command_line", metadata.CmdlineFull),
			)
		}
	}

	// Attach root-only attributes: warnings, debug provenance, and custom attrs.
	if len(warnings) > 0 {
		span.SetAttributes(warnings...)
	}
	if len(debugAttrs) > 0 {
		span.SetAttributes(debugAttrs...)
	}
	if f.addDebugAttributes && metadata != nil {
		if len(metadata.Args) > 0 {
			span.SetAttributes(attribute.StringSlice("debug.argv", metadata.Args))
		}
		if len(metadata.Environ) > 0 {
			span.SetAttributes(attribute.StringSlice("debug.environ", environToSlice(metadata.Environ)))
		}
	}
	if metadata != nil {
		if customAttrs, err := f.attrEvaluator.EvaluateCustomAttributes(metadata); err == nil && len(customAttrs) > 0 {
			span.SetAttributes(customAttrs...)
		}
	}
}

// EndSession finalizes the "process.tree" root span. Safe to call more than once.
func (f *OTELFormatter) EndSession(endTime time.Time) {
	if f.sessionRootSpan == nil {
		return
	}
	f.sessionRootSpan.End(trace.WithTimestamp(endTime))
	f.sessionRootSpan = nil
}

// resolveRootIDs evaluates the trace-id and parent-id expressions against metadata.
// Returns the resolved IDs plus any warnings / debug attrs to attach to the root span.
func (f *OTELFormatter) resolveRootIDs(metadata *procmeta.ProcessMetadata) (
	trace.TraceID, trace.SpanID, []attribute.KeyValue, []attribute.KeyValue,
) {
	var customTraceID trace.TraceID
	var customParentID trace.SpanID
	var warnings []attribute.KeyValue
	var debugAttrs []attribute.KeyValue

	if metadata == nil {
		return customTraceID, customParentID, warnings, debugAttrs
	}

	traceID, traceWarnings, traceRes, err := f.traceIDEvaluator.EvaluateAndValidate(metadata)
	if err != nil {
		warnings = append(warnings,
			attribute.String("_trace_id_evaluation_error", fmt.Sprintf("Failed to evaluate trace-id expression: %v", err)),
		)
	} else {
		customTraceID = traceID
		warnings = append(warnings, traceWarnings...)
	}

	parentID, parentWarnings, parentRes, err := f.parentIDEvaluator.EvaluateAndValidate(metadata)
	if err != nil {
		warnings = append(warnings,
			attribute.String("_parent_id_evaluation_error", fmt.Sprintf("Failed to evaluate parent-id expression: %v", err)),
		)
	} else {
		customParentID = parentID
		warnings = append(warnings, parentWarnings...)
	}

	if f.addDebugAttributes {
		debugAttrs = append(debugAttrs, traceIDResolutionAttrs(traceRes)...)
		debugAttrs = append(debugAttrs, parentIDResolutionAttrs(parentRes)...)
	}

	return customTraceID, customParentID, warnings, debugAttrs
}

// HandleProcessExec creates a new process span.
func (f *OTELFormatter) HandleProcessExec(pid, ppid, _ uint32, timestamp uint64, _ *procmeta.ProcessMetadata) error {
	// Handle exec-replacement: if this PID already has a span (e.g. sh exec'd
	// into bash, same PID), keep the existing span. HandleProcessExit will
	// finalize it with the correct final command name and attributes. Children
	// that were forked from the intermediate shell already reference this span
	// as their parent, so keeping it avoids orphans.
	if _, ok := f.spans[pid]; ok {
		return nil
	}

	// Parent selection: prefer tracked ppid's span, fall back to the session root.
	// We never allow ctx to remain empty — that would start a new trace for orphans.
	var parentSpanCtx trace.SpanContext
	if parent, exists := f.spans[ppid]; exists {
		parentSpanCtx = parent.SpanCtx
	} else if f.sessionRootCtx.IsValid() {
		parentSpanCtx = f.sessionRootCtx
	}

	ctx := context.Background()
	if parentSpanCtx.IsValid() {
		ctx = trace.ContextWithSpanContext(ctx, parentSpanCtx)
	}

	// Convert monotonic timestamp to wall clock for span start time
	startTime := f.converter.MonotonicToWallClock(timestamp)

	// Start span with explicit start time. Set process.pid immediately so
	// exec-replaced spans (ended early, before HandleProcessExit) still carry it.
	_, span := f.tracer.Start(ctx, "process.exec",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithTimestamp(startTime),
		trace.WithAttributes(
			attribute.Int("process.pid", int(pid)),
			attribute.Int("process.parent_pid", int(ppid)),
		),
	)

	// Store span info for this PID
	f.spans[pid] = &processSpanInfo{
		Span:      span,
		SpanCtx:   span.SpanContext(),
		ParentCtx: parentSpanCtx,
		StartTime: timestamp,
	}

	return nil
}

// environToSlice converts an env map to a sorted []string of "KEY=VALUE" entries.
// Sorted so that repeated runs produce stable output, easing diffing.
func environToSlice(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// traceIDResolutionAttrs converts a TraceIDResolution into debug.trace_id.* attributes.
func traceIDResolutionAttrs(res attributes.TraceIDResolution) []attribute.KeyValue {
	return resolutionAttrs("debug.trace_id.", res.Source, res.Expression, res.ResolvedValue, res.Validation, res.Error)
}

// parentIDResolutionAttrs converts a ParentIDResolution into debug.parent_id.* attributes.
func parentIDResolutionAttrs(res attributes.ParentIDResolution) []attribute.KeyValue {
	return resolutionAttrs("debug.parent_id.", res.Source, res.Expression, res.ResolvedValue, res.Validation, res.Error)
}

// resolutionAttrs builds the shared debug.* attribute set used for both
// trace ID and parent ID resolution records.
func resolutionAttrs(prefix, source, expression, resolvedValue, validation, errMsg string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{attribute.String(prefix+"source", source)}
	if expression != "" {
		attrs = append(attrs, attribute.String(prefix+"expression", expression))
	}
	if source != attributes.SourceUnconfigured {
		attrs = append(attrs, attribute.String(prefix+"resolved_value", resolvedValue))
	}
	if validation != attributes.ValidationNone {
		attrs = append(attrs, attribute.String(prefix+"validation", validation))
	}
	if errMsg != "" {
		attrs = append(attrs, attribute.String(prefix+"error", errMsg))
	}
	return attrs
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

	// Add debug attributes (argv + environ) to every span when enabled.
	// These may contain sensitive information and are gated behind an opt-in flag.
	if f.addDebugAttributes && metadata != nil {
		spanInfo.Span.SetAttributes(
			attribute.StringSlice("debug.argv", metadata.Args),
			attribute.StringSlice("debug.environ", environToSlice(metadata.Environ)),
		)
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

	// End span with explicit end time
	spanInfo.Span.End(trace.WithTimestamp(endTime))

	// Clean up metadata and span info
	f.metadataManager.Delete(pid)
	delete(f.spans, pid)

	return nil
}

// HandleTCPConnect creates a new TCP connection span.
func (f *OTELFormatter) HandleTCPConnect(pid uint32, skaddr uint64, _, _ []byte, _, _, _ uint16, timestamp uint64) error {
	// Parent selection: prefer the process's span, fall back to the session root.
	var parentSpanCtx trace.SpanContext
	if procSpanInfo, exists := f.spans[pid]; exists {
		parentSpanCtx = procSpanInfo.SpanCtx
	} else if f.sessionRootCtx.IsValid() {
		parentSpanCtx = f.sessionRootCtx
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

	// Evaluate custom attributes (e.g. service.name) from the owning process's metadata.
	if metadata := f.metadataManager.Get(pid); metadata != nil {
		if customAttrs, err := f.attrEvaluator.EvaluateCustomAttributes(metadata); err == nil && len(customAttrs) > 0 {
			attrs = append(attrs, customAttrs...)
		}
	}

	spanInfo.Span.SetAttributes(attrs...)
	spanInfo.Span.SetStatus(codes.Ok, "Connection closed")

	// End span with explicit end time
	spanInfo.Span.End(trace.WithTimestamp(endTime))

	// Clean up TCP span
	delete(f.tcpSpans, skaddr)

	return nil
}
