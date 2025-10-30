package output

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/mrzor/process-tracer/internal/bpf"
	"github.com/mrzor/process-tracer/internal/config"
	"github.com/mrzor/process-tracer/internal/procmeta"
	"github.com/mrzor/process-tracer/internal/pseudo_reverse_dns"

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

// EnvChunkBuffer holds incomplete environment chunk sequences.
type EnvChunkBuffer struct {
	chunks        map[uint32][]byte // chunk_id -> data
	receivedFinal bool
	truncated     bool
	lastUpdate    time.Time
}

// EnvVarCollector holds streaming environment variables from execve events.
type EnvVarCollector struct {
	args         []string        // Collected argv
	env          []string        // Collected env vars (raw KEY=VALUE format)
	argIndices   map[uint16]bool // Track which arg indices we've seen
	envIndices   map[uint16]bool // Track which env indices we've seen
	lastArgIndex uint16          // Highest arg index seen
	lastEnvIndex uint16          // Highest env index seen
	complete     bool            // Received is_final marker
	truncated    bool            // Any var was truncated
	lastUpdate   time.Time       // Last event received
}

// OTELFormatter formats events as OpenTelemetry spans.
type OTELFormatter struct {
	tracer           trace.Tracer
	spans            map[uint32]*OTELSpanInfo // PID -> span info
	tcpSpans         map[uint64]trace.Span    // socket addr -> TCP span
	tcpStartTs       map[uint64]uint64        // socket addr -> start timestamp
	traceID          trace.TraceID
	resolver         *pseudo_reverse_dns.Resolver
	bootTime         time.Time
	processMetadata  map[uint32]*procmeta.ProcessMetadata // PID -> process metadata
	metadataErrors   map[uint32]error                     // PID -> metadata collection errors
	customAttrs      []config.CustomAttribute             // custom attribute definitions
	compiledExprs    []*vm.Program                        // pre-compiled expressions
	envChunks        map[uint32]*EnvChunkBuffer           // PID -> environment chunk buffer
	envVarCollectors map[uint32]*EnvVarCollector          // PID -> streaming env var collector
	envCaptureIssues map[uint32][]string                  // PID -> list of warnings/issues
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
		tracer:           tracer,
		spans:            make(map[uint32]*OTELSpanInfo),
		tcpSpans:         make(map[uint64]trace.Span),
		tcpStartTs:       make(map[uint64]uint64),
		traceID:          traceID,
		resolver:         resolver,
		bootTime:         bootTime,
		processMetadata:  make(map[uint32]*procmeta.ProcessMetadata),
		metadataErrors:   make(map[uint32]error),
		customAttrs:      customAttrs,
		compiledExprs:    compiledExprs,
		envChunks:        make(map[uint32]*EnvChunkBuffer),
		envVarCollectors: make(map[uint32]*EnvVarCollector),
		envCaptureIssues: make(map[uint32][]string),
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

// HandleEnvChunk processes environment variable chunks from execve events.
func (f *OTELFormatter) HandleEnvChunk(chunk *bpf.EnvChunkEvent) error {
	pid := chunk.Pid

	fmt.Printf("[DEBUG] HandleEnvChunk: PID=%d ChunkID=%d DataSize=%d IsFinal=%d Truncated=%d Argc=%d\n",
		pid, chunk.ChunkID, chunk.DataSize, chunk.IsFinal, chunk.Truncated, chunk.Argc)

	// Initialize chunk buffer if needed
	if f.envChunks[pid] == nil {
		f.envChunks[pid] = &EnvChunkBuffer{
			chunks:     make(map[uint32][]byte),
			lastUpdate: time.Now(),
		}
		fmt.Printf("[DEBUG] Created new chunk buffer for PID %d\n", pid)
	}

	buffer := f.envChunks[pid]
	buffer.lastUpdate = time.Now()

	// Store this chunk's data
	if chunk.DataSize > 0 {
		buffer.chunks[chunk.ChunkID] = make([]byte, chunk.DataSize)
		copy(buffer.chunks[chunk.ChunkID], chunk.Data[:chunk.DataSize])
		fmt.Printf("[DEBUG] Stored chunk %d with %d bytes for PID %d\n", chunk.ChunkID, chunk.DataSize, pid)
	} else {
		fmt.Printf("[DEBUG] WARNING: Chunk %d for PID %d has DataSize=0\n", chunk.ChunkID, pid)
	}

	// Check if this is the final chunk
	if chunk.IsFinal != 0 {
		buffer.receivedFinal = true
		if chunk.Truncated != 0 {
			buffer.truncated = true
		}
	}

	// If we've received the final chunk, reassemble argv and environment
	if buffer.receivedFinal {
		fmt.Printf("[DEBUG] PID %d: Reassembling from %d chunks\n", pid, len(buffer.chunks))
		args, env := f.reassembleArgsAndEnvironment(pid, buffer)
		fmt.Printf("[DEBUG] PID %d: Reassembled %d args, %d env vars\n", pid, len(args), len(env))

		// Create ProcessMetadata if needed
		if f.processMetadata[pid] == nil {
			f.processMetadata[pid] = &procmeta.ProcessMetadata{
				Environ: make(map[string]string),
			}
		}

		// Store the captured environment and args
		f.processMetadata[pid].Environ = env
		f.processMetadata[pid].Args = args
		f.processMetadata[pid].CmdlineFull = strings.Join(args, " ")

		// Feed environment and args to pseudo reverse DNS resolver
		// Collect all values to ingest
		endpoints := make([]string, 0, len(env)+len(args))
		for _, value := range env {
			endpoints = append(endpoints, value)
		}
		endpoints = append(endpoints, args...)
		f.resolver.IngestEndpoints(endpoints...)

		// Add warning if truncated
		if buffer.truncated {
			f.addEnvIssue(pid, fmt.Sprintf("data truncated: captured %d args, %d env vars", len(args), len(env)))
		}

		// Clean up chunk buffer
		delete(f.envChunks, pid)
	}

	return nil
}

// reassembleArgsAndEnvironment reconstructs argv and environment from chunks.
func (f *OTELFormatter) reassembleArgsAndEnvironment(pid uint32, buffer *EnvChunkBuffer) ([]string, map[string]string) {
	// Reconstruct the full data in chunk order
	var fullData []byte
	numChunks := len(buffer.chunks)
	//nolint:gosec // numChunks is bounded by map size, conversion is safe
	for i := uint32(0); i < uint32(numChunks); i++ {
		if chunkData, exists := buffer.chunks[i]; exists {
			fullData = append(fullData, chunkData...)
		} else {
			// Missing chunk - add issue
			f.addEnvIssue(pid, fmt.Sprintf("data incomplete: missing chunk %d", i))
			break
		}
	}

	// Parse null-terminated strings
	// Args come first (no '='), then env vars (KEY=VALUE)
	var args []string
	env := make(map[string]string)
	offset := 0

	for offset < len(fullData) {
		// Find the null terminator
		end := offset
		for end < len(fullData) && fullData[end] != 0 {
			end++
		}

		if end == offset {
			// Empty string or end of data
			break
		}

		str := string(fullData[offset:end])

		// Check if this is an environment variable (contains '=')
		if idx := strings.IndexByte(str, '='); idx > 0 {
			// This is an env var
			key := str[:idx]
			value := str[idx+1:]
			env[key] = value
		} else {
			// This is a command-line argument (no '=')
			args = append(args, str)
		}

		offset = end + 1 // Skip the null terminator
	}

	return args, env
}

// addEnvIssue adds an environment capture issue for a PID.
func (f *OTELFormatter) addEnvIssue(pid uint32, issue string) {
	f.envCaptureIssues[pid] = append(f.envCaptureIssues[pid], issue)
}

// HandleEnvVar processes individual environment variable events from streaming execve.
func (f *OTELFormatter) HandleEnvVar(envVar *bpf.EnvVarEvent) error {
	pid := envVar.Pid

	// Initialize collector if needed
	if f.envVarCollectors[pid] == nil {
		f.envVarCollectors[pid] = &EnvVarCollector{
			args:       make([]string, 0, 64),  // Pre-allocate reasonable size
			env:        make([]string, 0, 256), // Pre-allocate for up to 256 env vars
			argIndices: make(map[uint16]bool),
			envIndices: make(map[uint16]bool),
			lastUpdate: time.Now(),
		}
	}

	collector := f.envVarCollectors[pid]
	collector.lastUpdate = time.Now()

	// Extract the variable data
	varData := string(envVar.Data[:envVar.DataSize])

	// Store the variable in the appropriate array
	if envVar.IsArgv != 0 {
		// This is an argument
		// Ensure args slice is large enough
		if int(envVar.VarIndex) >= len(collector.args) {
			// Grow slice to accommodate this index
			newArgs := make([]string, envVar.VarIndex+1)
			copy(newArgs, collector.args)
			collector.args = newArgs
		}
		collector.args[envVar.VarIndex] = varData
		collector.argIndices[envVar.VarIndex] = true
		if envVar.VarIndex > collector.lastArgIndex {
			collector.lastArgIndex = envVar.VarIndex
		}
	} else {
		// This is an environment variable
		// Ensure env slice is large enough
		if int(envVar.VarIndex) >= len(collector.env) {
			// Grow slice to accommodate this index
			newEnv := make([]string, envVar.VarIndex+1)
			copy(newEnv, collector.env)
			collector.env = newEnv
		}
		collector.env[envVar.VarIndex] = varData
		collector.envIndices[envVar.VarIndex] = true
		if envVar.VarIndex > collector.lastEnvIndex {
			collector.lastEnvIndex = envVar.VarIndex
		}
	}

	// Track truncation
	if envVar.Truncated != 0 {
		collector.truncated = true
	}

	// Check if this is the final variable
	if envVar.IsFinal != 0 {
		collector.complete = true
	}

	// If complete, process the collected variables
	if collector.complete {
		f.finalizeEnvVarCollection(pid, collector)
	}

	return nil
}

// finalizeEnvVarCollection processes completed environment variable streams.
func (f *OTELFormatter) finalizeEnvVarCollection(pid uint32, collector *EnvVarCollector) {
	// Trim args to actual size (remove empty slots at end)
	args := collector.args[:collector.lastArgIndex+1]

	// Filter out empty args (gaps in indices)
	finalArgs := make([]string, 0, len(args))
	for i, arg := range args {
		//nolint:gosec // Bounds check ensures i fits in uint16
		if i < 65536 && collector.argIndices[uint16(i)] {
			finalArgs = append(finalArgs, arg)
		}
	}

	// Trim env to actual size
	envRaw := collector.env[:collector.lastEnvIndex+1]

	// Parse environment variables and filter out gaps
	env := make(map[string]string)
	for i, envStr := range envRaw {
		//nolint:gosec // Bounds check ensures i fits in uint16
		if i >= 65536 || !collector.envIndices[uint16(i)] {
			continue // Skip gaps or out of bounds
		}
		if idx := strings.IndexByte(envStr, '='); idx > 0 {
			key := envStr[:idx]
			value := envStr[idx+1:]
			env[key] = value
		}
	}

	// Create ProcessMetadata if needed
	if f.processMetadata[pid] == nil {
		f.processMetadata[pid] = &procmeta.ProcessMetadata{
			Environ: make(map[string]string),
		}
	}

	// Store the captured environment and args
	f.processMetadata[pid].Environ = env
	f.processMetadata[pid].Args = finalArgs
	f.processMetadata[pid].CmdlineFull = strings.Join(finalArgs, " ")

	// Feed environment and args to pseudo reverse DNS resolver
	// Collect all values to ingest
	endpoints := make([]string, 0, len(env)+len(finalArgs))
	for _, value := range env {
		endpoints = append(endpoints, value)
	}
	endpoints = append(endpoints, finalArgs...)
	f.resolver.IngestEndpoints(endpoints...)

	// Add warnings if applicable
	if collector.truncated {
		f.addEnvIssue(pid, fmt.Sprintf("some variables truncated: captured %d args, %d env vars", len(finalArgs), len(env)))
	}

	// Log completion for debugging
	// fmt.Printf("PID %d: collected %d args, %d env vars\n", pid, len(finalArgs), len(env))

	// Clean up collector
	delete(f.envVarCollectors, pid)
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

	// Add environment capture issues as span attributes if any
	if envIssues, hasIssues := f.envCaptureIssues[event.Pid]; hasIssues {
		for i, issue := range envIssues {
			spanInfo.Span.SetAttributes(
				attribute.String(fmt.Sprintf("_tracing_warning_%d", i), issue),
			)
		}
		delete(f.envCaptureIssues, event.Pid)
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
