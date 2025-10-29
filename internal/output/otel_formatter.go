package output

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"

	"sched_trace/internal/bpf"
	"sched_trace/internal/config"
	"sched_trace/internal/procmeta"
	"sched_trace/internal/pseudo_reverse_dns"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// OTELSpanInfo holds span and timing information.
type OTELSpanInfo struct {
	Span      trace.Span
	SpanCtx   trace.SpanContext
	StartTime uint64 // monotonic timestamp in nanoseconds
}

// OTELFormatter formats events as OpenTelemetry spans.
type OTELFormatter struct {
	tracer          trace.Tracer
	spans           map[uint32]*OTELSpanInfo // PID -> span info
	tcpSpans        map[uint64]trace.Span    // socket addr -> TCP span
	tcpStartTs      map[uint64]uint64        // socket addr -> start timestamp
	traceID         trace.TraceID
	resolver        *pseudo_reverse_dns.Resolver
	bootTime        time.Time
	processMetadata map[uint32]*procmeta.ProcessMetadata // PID -> process metadata
	metadataErrors  map[uint32]error                     // PID -> metadata collection errors
	customAttrs     []config.CustomAttribute             // custom attribute definitions
	compiledExprs   []*vm.Program                        // pre-compiled expressions
	metaCollector   *procmeta.Collector                  // process metadata collector
}

// NewOTELFormatter creates a new OTELFormatter.
func NewOTELFormatter(tracer trace.Tracer, traceIDHex string, resolver *pseudo_reverse_dns.Resolver, customAttrs []config.CustomAttribute) (*OTELFormatter, error) {
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

	// Pre-compile custom attribute expressions
	compiledExprs := make([]*vm.Program, len(customAttrs))
	for i, attr := range customAttrs {
		// Define the environment for type checking
		env := map[string]interface{}{
			"env":     map[string]string{},
			"args":    []string{},
			"cmdline": "",
		}

		program, err := expr.Compile(attr.Expression, expr.Env(env))
		if err != nil {
			return nil, fmt.Errorf("failed to compile expression for attribute %q: %w", attr.Name, err)
		}
		compiledExprs[i] = program
	}

	return &OTELFormatter{
		tracer:          tracer,
		spans:           make(map[uint32]*OTELSpanInfo),
		tcpSpans:        make(map[uint64]trace.Span),
		tcpStartTs:      make(map[uint64]uint64),
		traceID:         traceID,
		resolver:        resolver,
		bootTime:        bootTime,
		processMetadata: make(map[uint32]*procmeta.ProcessMetadata),
		metadataErrors:  make(map[uint32]error),
		customAttrs:     customAttrs,
		compiledExprs:   compiledExprs,
		metaCollector:   procmeta.NewCollector(),
	}, nil
}

// monotonicToWallClock converts a monotonic timestamp (nanoseconds since boot) to wall-clock time.
func (f *OTELFormatter) monotonicToWallClock(monotonicNanos uint64) time.Time {
	//nolint:gosec // uint64 to int64 conversion for time.Duration is safe for reasonable timestamps
	return f.bootTime.Add(time.Duration(monotonicNanos))
}

// HandleEvent formats events as OpenTelemetry spans.
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
	_, span := f.tracer.Start(ctx, "process.exec",
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
	_ = f.resolver.HandleStaticSources(int(event.Pid))

	// Collect process metadata for custom attributes
	if len(f.customAttrs) > 0 {
		metadata, err := f.metaCollector.Collect(int(event.Pid))
		if err != nil {
			// Store error to add as span attribute later
			f.metadataErrors[event.Pid] = err
		}
		// Store metadata even if partial (some custom attributes may still work)
		if metadata != nil {
			f.processMetadata[event.Pid] = metadata
		}
	}

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

	// Evaluate custom attributes
	customAttrs, _ := f.evaluateCustomAttributes(event.Pid)

	// Set span attributes
	//nolint:gosec // uint64 to int64 conversion for duration is safe
	spanInfo.Span.SetAttributes(
		attribute.Int("process.pid", int(event.Pid)),
		attribute.Int("process.parent_pid", int(event.Ppid)),
		attribute.Int("process.owner.uid", int(event.Uid)),
		attribute.String("process.command", comm),
		attribute.Int64("process.duration_ns", int64(duration)),
	)

	// Add custom attributes if any
	if len(customAttrs) > 0 {
		spanInfo.Span.SetAttributes(customAttrs...)
	}

	// Add metadata collection errors as span attributes if any
	if metaErr, hasErr := f.metadataErrors[event.Pid]; hasErr {
		spanInfo.Span.SetAttributes(
			attribute.String("_tracing_error_0", metaErr.Error()),
		)
		delete(f.metadataErrors, event.Pid)
	}

	// End span with explicit end time
	spanInfo.Span.End(trace.WithTimestamp(endTime))

	// Clean up metadata and span info
	delete(f.processMetadata, event.Pid)
	delete(f.spans, event.Pid)

	return nil
}

// sanitizeAttributeName replaces any character not in [a-zA-Z0-9_] with underscore.
func sanitizeAttributeName(name string) string {
	result := make([]byte, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			result[i] = c
		} else {
			result[i] = '_'
		}
	}
	return string(result)
}

// evaluateCustomAttributes evaluates custom attribute expressions for a given PID.
func (f *OTELFormatter) evaluateCustomAttributes(pid uint32) ([]attribute.KeyValue, error) {
	if len(f.customAttrs) == 0 {
		return nil, nil
	}

	metadata := f.processMetadata[pid]
	if metadata == nil {
		// No metadata available - return empty
		return nil, nil
	}

	// Build evaluation environment
	env := map[string]interface{}{
		"env":     metadata.Environ,
		"args":    metadata.Args,
		"cmdline": metadata.CmdlineFull,
	}

	var attrs []attribute.KeyValue
	for i, customAttr := range f.customAttrs {
		// Run the pre-compiled program
		output, err := expr.Run(f.compiledExprs[i], env)
		if err != nil {
			// Log error but continue with other attributes
			fmt.Printf("Warning: failed to evaluate expression for attribute %q: %v\n", customAttr.Name, err)
			continue
		}

		// Check if output is a map - if so, expand it into multiple attributes
		outputValue := reflect.ValueOf(output)
		if outputValue.Kind() == reflect.Map {
			// Expand map into separate attributes with dot notation
			for _, key := range outputValue.MapKeys() {
				// Convert key to string and sanitize
				keyStr := fmt.Sprintf("%v", key.Interface())
				sanitizedKey := sanitizeAttributeName(keyStr)
				attrName := customAttr.Name + "." + sanitizedKey

				// Get the value
				value := outputValue.MapIndex(key).Interface()

				// Check if value is a nested map or slice - if so, use %v format
				valueReflect := reflect.ValueOf(value)
				if valueReflect.Kind() == reflect.Map || valueReflect.Kind() == reflect.Slice || valueReflect.Kind() == reflect.Array {
					// Nested structure - use default Go format
					attrs = append(attrs, attribute.String(attrName, fmt.Sprintf("%v", value)))
				} else {
					// Simple value - convert to string
					attrs = append(attrs, attribute.String(attrName, fmt.Sprint(value)))
				}
			}
		} else {
			// Not a map - convert output to string attribute as before
			attrValue := fmt.Sprint(output)
			attrs = append(attrs, attribute.String(customAttr.Name, attrValue))
		}
	}

	return attrs, nil
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
	_, span := f.tracer.Start(ctx, "tcp.connect",
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
	switch tcpData.Family {
	case 2: // AF_INET (IPv4)
		destIP = net.IP(tcpData.Daddr[:4]).String()
		srcIP = net.IP(tcpData.Saddr[:4]).String()
	case 10: // AF_INET6
		destIP = net.IP(tcpData.Daddr[:]).String()
		srcIP = net.IP(tcpData.Saddr[:]).String()
	default:
		destIP = fmt.Sprintf("unknown_family_%d", tcpData.Family)
		srcIP = fmt.Sprintf("unknown_family_%d", tcpData.Family)
	}

	// Set span attributes using semantic conventions
	//nolint:gosec // uint64 to int64 conversion for duration is safe
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
