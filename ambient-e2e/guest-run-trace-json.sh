#!/usr/bin/env bash
set -euo pipefail

HOST="http://10.0.2.2:9999"
COLLECTOR="http://10.0.2.2:14318/v1/traces"

echo "[guest] Downloading files from host..."
curl -sf "$HOST/process-tracer" -o /tmp/process-tracer
curl -sf "$HOST/Makefile.pipeline" -o /tmp/Makefile.pipeline
chmod +x /tmp/process-tracer

echo "[guest] Running traced parallel make with --otel-json-file (no network export)..."
# Identical workload to guest-run-trace.sh, but spans are written locally as
# OTLP JSON (JSONL) instead of exported over the network. This exercises the
# --otel-json-file path end-to-end.
export BUILD_ID="make-run-42"
/tmp/process-tracer trace \
  --otel-json-file /tmp/traces.jsonl \
  --add-debug-attributes \
  -t 'expr:env["BUILD_ID"]' \
  -a service.name=trace-e2e-make \
  -a build.id=make-run-42 \
  -- make -f /tmp/Makefile.pipeline test-parallel -j3

echo "[guest] Produced $(wc -l </tmp/traces.jsonl) OTLP JSON line(s)"

# Replay the OTLP JSON back through the host collector. Each JSONL line is one
# ExportTraceServiceRequest, exactly what the collector's OTLP/HTTP receiver
# accepts as application/json — proving the output is genuinely OTLP-consumable.
echo "[guest] Replaying OTLP JSON into collector at $COLLECTOR..."
while IFS= read -r line; do
    [ -z "$line" ] && continue
    curl -sf -X POST "$COLLECTOR" \
        -H 'Content-Type: application/json' \
        --data-binary "$line" >/dev/null
done </tmp/traces.jsonl

echo "[guest] Done"
