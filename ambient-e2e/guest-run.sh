#!/usr/bin/env bash
set -euo pipefail

HOST="http://10.0.2.2:9999"

echo "[guest] Downloading files from host..."
curl -sf "$HOST/process-tracer" -o /tmp/process-tracer
curl -sf "$HOST/ambient-test.yaml" -o /tmp/ambient-test.yaml
curl -sf "$HOST/Makefile.pipeline" -o /tmp/Makefile.pipeline
chmod +x /tmp/process-tracer

echo "[guest] Starting process-tracer daemon..."
PROCESS_TRACER_SHUTDOWN_TIMEOUT_MS=5000 /tmp/process-tracer daemon -c /tmp/ambient-test.yaml &
DAEMON_PID=$!

# Give eBPF probes time to attach
sleep 2

# --- Workload 1: unmatched noise (should NOT produce spans) ---
echo "[guest] Running unmatched processes..."
find /tmp -maxdepth 1 -type f > /dev/null 2>&1 || true
dd if=/dev/zero of=/dev/null bs=1k count=10 2>/dev/null
ls /usr > /dev/null

# --- Workload 2: 3-step "pipeline" matched by "e2e-make" rule.
# All three invocations share BUILD_ID, so their trace_ids match (sha256
# fallback), making the three process.tree spans siblings under one trace.
# Sequential happens-before across steps is guaranteed by the shell:
# step N+1 only starts after step N exits.
echo "[guest] Running pipeline (3 make invocations sharing BUILD_ID)..."
export BUILD_ID="make-run-42"
export BUILD_REGION="us-east-1"
make -f /tmp/Makefile.pipeline build
make -f /tmp/Makefile.pipeline test-parallel -j3
make -f /tmp/Makefile.pipeline deploy

# --- Workload 3: more unmatched noise ---
echo "[guest] Running more unmatched processes..."
cat /etc/hostname > /dev/null
wc -l /etc/passwd > /dev/null

# --- Workload 4: matched by "e2e-perl" rule ---
echo "[guest] Running perl (matched)..."
export JOB_ID="perl-job-99"
export JOB_TIER="critical"
perl -e 'system("echo perl-child"); system("sleep 0.1"); system("uname -m")'

echo "[guest] Stopping daemon (PID $DAEMON_PID)..."
kill -TERM "$DAEMON_PID" 2>/dev/null || true
# Wait for graceful shutdown (OTEL batch flush)
wait "$DAEMON_PID" 2>/dev/null || true

echo "[guest] Done"
