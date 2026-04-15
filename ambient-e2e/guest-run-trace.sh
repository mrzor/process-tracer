#!/usr/bin/env bash
set -euo pipefail

HOST="http://10.0.2.2:9999"

echo "[guest] Downloading files from host..."
curl -sf "$HOST/process-tracer" -o /tmp/process-tracer
curl -sf "$HOST/Makefile.pipeline" -o /tmp/Makefile.pipeline
chmod +x /tmp/process-tracer

echo "[guest] Running traced parallel make..."
# BUILD_ID is read by the -t expression and is not valid 32-char hex, so
# this exercises the SHA-256-hashed fallback in trace-id validation.
# Trace mode is one invocation so we use the parallel target directly to
# exercise concurrent siblings + the no-orphan invariant within one tree.
export BUILD_ID="make-run-42"
OTEL_EXPORTER_OTLP_ENDPOINT="http://10.0.2.2:14318" \
  /tmp/process-tracer trace \
    --add-debug-attributes \
    -t 'expr:env["BUILD_ID"]' \
    -a service.name=trace-e2e-make \
    -a build.id=make-run-42 \
    -- make -f /tmp/Makefile.pipeline test-parallel -j3

echo "[guest] Done"
