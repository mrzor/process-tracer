#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
STAGING="$SCRIPT_DIR/staging"
CACHE="$SCRIPT_DIR/.cache"
TIMEOUT=300
HTTP_PORT=9999

# --- Check host dependencies ---

missing=()
for cmd in qemu-system-x86_64 qemu-img jq go curl python3; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
done

# Need one of these for ISO creation
ISO_CMD=""
for cmd in genisoimage mkisofs xorrisofs; do
    if command -v "$cmd" &>/dev/null; then
        ISO_CMD="$cmd"
        break
    fi
done
[[ -z "$ISO_CMD" ]] && missing+=("genisoimage|mkisofs|xorrisofs")

if (( ${#missing[@]} > 0 )); then
    echo "ERROR: Missing required tools: ${missing[*]}"
    echo "Install them and retry."
    exit 1
fi

# --- Cleanup on exit ---

cleanup() {
    local pids=("${HTTP_PID:-}" "${OTELCOL_PID:-}" "${QEMU_PID:-}")
    for pid in "${pids[@]}"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    # rm -rf "$STAGING"  # uncomment to clean up after run
}
trap cleanup EXIT

# --- Fetch dependencies ---

bash "$SCRIPT_DIR/fetch-deps.sh"

# --- Build daemon ---

echo "[build] Building process-tracer-daemon..."
mkdir -p "$STAGING"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$STAGING/process-tracer-daemon" "$PROJECT_ROOT/cmd/process-tracer-daemon"
echo "[build] Done"

# --- Stage files ---

cp "$SCRIPT_DIR/guest-run.sh" "$STAGING/"
cp "$SCRIPT_DIR/Makefile.test" "$STAGING/"
cp "$SCRIPT_DIR/ambient-test.yaml" "$STAGING/"

# --- Start HTTP server (serves staging/ to VM) ---

echo "[http] Starting file server on :${HTTP_PORT}..."
python3 -m http.server "$HTTP_PORT" -d "$STAGING" &>/dev/null &
HTTP_PID=$!

# --- Start OTLP collector on host ---

echo "[otel] Starting otelcol-contrib on host..."
"$CACHE/otelcol-contrib" --config "$SCRIPT_DIR/otelcol.yaml" &>/dev/null &
OTELCOL_PID=$!

# Wait for collector to be ready (OTLP endpoint returns 405 for GET)
for i in $(seq 1 15); do
    HTTP_CODE=$(curl -so /dev/null -w '%{http_code}' http://localhost:4318/ 2>/dev/null || true)
    if [[ "$HTTP_CODE" =~ ^(200|404|405)$ ]]; then
        echo "[otel] Collector ready after ${i}s"
        break
    fi
    if (( i == 15 )); then
        echo "[otel] ERROR: collector not ready after 15s"
        exit 1
    fi
    sleep 1
done

# --- Create cloud-init seed ISO ---
# NoCloud datasource expects files named exactly "user-data" and "meta-data"

echo "[iso] Creating seed ISO..."
cp "$SCRIPT_DIR/cloud-init-user-data" "$STAGING/user-data"
cp "$SCRIPT_DIR/cloud-init-meta-data" "$STAGING/meta-data"
"$ISO_CMD" -output "$STAGING/seed.iso" -volid cidata -joliet -rock \
    "$STAGING/user-data" "$STAGING/meta-data" \
    2>/dev/null
echo "[iso] Done"

# --- Create overlay qcow2 ---

qemu-img create -f qcow2 \
    -b "$CACHE/debian-13-genericcloud-amd64.qcow2" -F qcow2 \
    "$STAGING/overlay.qcow2" \
    >/dev/null

# --- Start QEMU ---

KVM_FLAG=""
if [[ -w /dev/kvm ]]; then
    KVM_FLAG="-enable-kvm"
    echo "[vm] Starting QEMU (KVM enabled)..."
else
    echo "[vm] WARNING: /dev/kvm not available, running without KVM (slow)"
    echo "[vm] Starting QEMU..."
fi

qemu-system-x86_64 \
    -m 2048 -smp 2 $KVM_FLAG \
    -display none \
    -monitor none \
    -drive file="$STAGING/overlay.qcow2",format=qcow2 \
    -drive file="$STAGING/seed.iso",format=raw \
    -netdev user,id=net0 \
    -device virtio-net-pci,netdev=net0 \
    -serial file:"$STAGING/serial.log" &
QEMU_PID=$!

# --- Wait for VM to finish ---

echo "[vm] Waiting for VM (timeout ${TIMEOUT}s, PID $QEMU_PID)..."
SECONDS=0
while kill -0 "$QEMU_PID" 2>/dev/null; do
    if (( SECONDS >= TIMEOUT )); then
        echo "[vm] ERROR: VM timed out after ${TIMEOUT}s"
        echo ""
        echo "=== Last 30 lines of serial.log ==="
        tail -30 "$STAGING/serial.log" 2>/dev/null || echo "(no serial log)"
        exit 1
    fi
    sleep 2
done

wait "$QEMU_PID" 2>/dev/null || true
unset QEMU_PID
echo "[vm] VM completed in ${SECONDS}s"

# --- Give collector a moment to flush ---

sleep 2

# --- Stop host services ---

echo "[otel] Stopping collector..."
kill -TERM "$OTELCOL_PID" 2>/dev/null || true
wait "$OTELCOL_PID" 2>/dev/null || true
unset OTELCOL_PID

kill "$HTTP_PID" 2>/dev/null || true
wait "$HTTP_PID" 2>/dev/null || true
unset HTTP_PID

# --- Verify traces ---

echo ""
bash "$SCRIPT_DIR/verify-traces.sh" "$STAGING/traces.jsonl"
