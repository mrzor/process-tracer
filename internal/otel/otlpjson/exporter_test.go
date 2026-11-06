package otlpjson

import (
	"bytes"
	"context"
	"strings"
	"testing"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// sampleResourceSpans builds a minimal but realistic OTLP ResourceSpans batch.
func sampleResourceSpans(name string) []*tracepb.ResourceSpans {
	return []*tracepb.ResourceSpans{
		{
			ScopeSpans: []*tracepb.ScopeSpans{
				{
					Scope: &commonpb.InstrumentationScope{Name: "process-tracer"},
					Spans: []*tracepb.Span{
						{
							TraceId:           []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
							SpanId:            []byte{0, 1, 2, 3, 4, 5, 6, 7},
							Name:              name,
							StartTimeUnixNano: 1000,
							EndTimeUnixNano:   2000,
						},
					},
				},
			},
		},
	}
}

func TestUploadTracesWritesOTLPJSONLine(t *testing.T) {
	var buf bytes.Buffer
	cl := &client{w: &buf}

	if err := cl.UploadTraces(context.Background(), sampleResourceSpans("process.exec")); err != nil {
		t.Fatalf("UploadTraces: %v", err)
	}

	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("expected trailing newline, got %q", out)
	}
	if strings.Count(strings.TrimRight(out, "\n"), "\n") != 0 {
		t.Fatalf("expected a single JSONL line, got %q", out)
	}

	// Round-trip: the line must parse back to an ExportTraceServiceRequest.
	var req coltracepb.ExportTraceServiceRequest
	if err := protojson.Unmarshal([]byte(out), &req); err != nil {
		t.Fatalf("unmarshal OTLP JSON: %v", err)
	}
	spans := req.GetResourceSpans()[0].GetScopeSpans()[0].GetSpans()
	if len(spans) != 1 || spans[0].GetName() != "process.exec" {
		t.Fatalf("round-trip mismatch: %+v", spans)
	}

	// IDs must be lowercase hex (OTLP JSON wire format), not protojson base64.
	if !strings.Contains(out, `"traceId":"000102030405060708090a0b0c0d0e0f"`) {
		t.Fatalf("traceId not hex-encoded in output: %s", out)
	}
	if !strings.Contains(out, `"spanId":"0001020304050607"`) {
		t.Fatalf("spanId not hex-encoded in output: %s", out)
	}
}

func TestUploadTracesEmptyBatchWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	cl := &client{w: &buf}

	if err := cl.UploadTraces(context.Background(), nil); err != nil {
		t.Fatalf("UploadTraces(nil): %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected no output for empty batch, got %q", buf.String())
	}
}

// stubCloser records whether Close was called.
type stubCloser struct{ closed bool }

func (s *stubCloser) Close() error { s.closed = true; return nil }

func TestStopClosesWriter(t *testing.T) {
	c := &stubCloser{}
	cl := &client{w: &bytes.Buffer{}, c: c}
	if err := cl.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !c.closed {
		t.Fatal("expected Stop to close the writer")
	}
}
