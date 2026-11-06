package otel

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mrzor/process-tracer/internal/config"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// TestInitProviderJSONFile drives the full JSON-file export path end-to-end:
// InitProvider builds a real TracerProvider backed by the OTLP JSON exporter,
// spans are emitted through the batch processor, and ShutdownProvider flushes
// and closes the file. The resulting file must be valid OTLP JSONL.
func TestInitProviderJSONFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "traces.jsonl")

	cfg := &config.OTELConfig{ServiceName: "test-svc", JSONFile: path}

	tp, err := InitProvider(cfg, "test")
	if err != nil {
		t.Fatalf("InitProvider: %v", err)
	}

	tracer := tp.Tracer("process-tracer-test")
	_, span := tracer.Start(context.Background(), "process.exec")
	span.End()

	// Shutdown flushes the batcher and closes the file via the client's Stop.
	if err := ShutdownProvider(tp, context.Background()); err != nil {
		t.Fatalf("ShutdownProvider: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading JSON output: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("JSON output file is empty")
	}

	// Every line must parse as an OTLP ExportTraceServiceRequest, and at least
	// one span named "process.exec" with our service.name resource attr must appear.
	found := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req coltracepb.ExportTraceServiceRequest
		if err := protojson.Unmarshal(line, &req); err != nil {
			t.Fatalf("line is not valid OTLP JSON: %v\nline: %s", err, line)
		}
		for _, rs := range req.GetResourceSpans() {
			for _, ss := range rs.GetScopeSpans() {
				for _, s := range ss.GetSpans() {
					if s.GetName() == "process.exec" {
						found = true
					}
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scanning JSON output: %v", err)
	}
	if !found {
		t.Fatalf("did not find expected span in output:\n%s", data)
	}
}
