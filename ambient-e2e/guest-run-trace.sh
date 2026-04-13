#!/usr/bin/env bash
set -euo pipefail

HOST="http://10.0.2.2:9999"

echo "[guest] Downloading files from host..."
curl -sf "$HOST/process-tracer" -o /tmp/process-tracer
curl -sf "$HOST/Makefile.test" -o /tmp/Makefile.test
chmod +x /tmp/process-tracer

echo "[guest] Running traced make..."
OTEL_EXPORTER_OTLP_ENDPOINT="http://10.0.2.2:4318" \
  /tmp/process-tracer trace \
    --add-debug-attributes \
    -a service.name=trace-e2e-make \
    -a build.id=make-run-42 \
    -- make -f /tmp/Makefile.test

echo "[guest] Done"
