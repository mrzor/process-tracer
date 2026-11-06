// Package otlpjson provides an OpenTelemetry span exporter that writes spans as
// canonical OTLP JSON to an io.Writer, one ExportTraceServiceRequest document
// per export batch (JSONL). The output is byte-format-compatible with the
// OpenTelemetry Collector's file exporter, so it can be consumed by any tool
// that reads OTLP JSON (including this project's ambient-e2e/verify-traces*.py).
//
// It is built on top of the SDK's otlptrace.Client seam: the SDK performs the
// ReadOnlySpan -> OTLP protobuf transform, and this client only marshals the
// resulting protobuf to JSON. That keeps timestamp/attribute/resource fidelity
// identical to the OTLP/HTTP path with no hand-written transform of our own.
package otlpjson

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// idFields are the OTLP JSON keys whose values are trace/span identifiers.
// protojson encodes proto `bytes` fields as base64, but the OTLP JSON spec (and
// the Collector's file exporter, and this project's verify-traces scripts)
// require these specific fields to be lowercase hex. hexEncodeIDs fixes that.
var idFields = map[string]bool{
	"traceId":      true,
	"spanId":       true,
	"parentSpanId": true,
}

// client implements otlptrace.Client, marshaling transformed spans to OTLP JSON.
type client struct {
	mu sync.Mutex
	w  io.Writer
	c  io.Closer // optional; closed on Stop
}

// Start is a no-op: the writer is opened by the caller so open errors surface
// before the exporter is constructed.
func (cl *client) Start(context.Context) error { return nil }

// Stop closes the underlying writer if it is a Closer.
func (cl *client) Stop(context.Context) error {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.c != nil {
		return cl.c.Close()
	}
	return nil
}

// UploadTraces marshals a batch of already-transformed spans to a single OTLP
// JSON ExportTraceServiceRequest and writes it as one line. May be called
// concurrently, hence the mutex.
func (cl *client) UploadTraces(_ context.Context, protoSpans []*tracepb.ResourceSpans) error {
	if len(protoSpans) == 0 {
		return nil
	}

	req := &coltracepb.ExportTraceServiceRequest{ResourceSpans: protoSpans}
	b, err := protojson.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshaling OTLP JSON: %w", err)
	}
	b, err = hexEncodeIDs(b)
	if err != nil {
		return fmt.Errorf("hex-encoding OTLP JSON ids: %w", err)
	}

	cl.mu.Lock()
	defer cl.mu.Unlock()
	if _, err := cl.w.Write(b); err != nil {
		return fmt.Errorf("writing OTLP JSON: %w", err)
	}
	if _, err := cl.w.Write([]byte("\n")); err != nil {
		return fmt.Errorf("writing OTLP JSON newline: %w", err)
	}
	return nil
}

// hexEncodeIDs rewrites the base64-encoded trace/span id fields produced by
// protojson into lowercase hex, matching the OTLP JSON wire format that
// collectors and OTLP tooling expect. It round-trips the document through a
// generic decode; key ordering is not preserved, which is irrelevant for JSONL
// consumers.
func hexEncodeIDs(b []byte) ([]byte, error) {
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if err := walkIDs(doc); err != nil {
		return nil, err
	}
	return json.Marshal(doc)
}

// walkIDs recursively converts any string value under an id field key from
// base64 to hex.
func walkIDs(v any) error {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if s, ok := val.(string); ok && idFields[k] {
				raw, err := base64.StdEncoding.DecodeString(s)
				if err != nil {
					return fmt.Errorf("decoding %s: %w", k, err)
				}
				t[k] = hex.EncodeToString(raw)
				continue
			}
			if err := walkIDs(val); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range t {
			if err := walkIDs(item); err != nil {
				return err
			}
		}
	}
	return nil
}

// New returns a span exporter that writes OTLP JSON to w. If c is non-nil it is
// closed when the exporter shuts down (pass the same *os.File as both w and c to
// have the file closed on flush).
func New(w io.Writer, c io.Closer) (sdktrace.SpanExporter, error) {
	return otlptrace.New(context.Background(), &client{w: w, c: c})
}
