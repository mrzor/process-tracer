#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
STAGING="$SCRIPT_DIR/staging"
CACHE="$SCRIPT_DIR/.cache"
TIMEOUT=300
HTTP_PORT=9999
REBUILD_BASE=false

# --- Parse flags ---

for arg in "$@"; do
    case "$arg" in
        --rebuild-base|--force-rebuild) REBUILD_BASE=true ;;
        *) echo "Unknown flag: $arg"; exit 1 ;;
    esac
done

# --- Colors (disabled if not a terminal) ---

if [[ -t 1 ]]; then
    DIM=$'\033[2m'
    BOLD=$'\033[1m'
    RED=$'\033[31m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    CYAN=$'\033[36m'
    RESET=$'\033[0m'
else
    DIM='' BOLD='' RED='' GREEN='' YELLOW='' CYAN='' RESET=''
fi

log()  { echo -e "${DIM}[$1]${RESET} $2"; }
ok()   { echo -e "${GREEN}${BOLD}[$1]${RESET} $2"; }
warn() { echo -e "${YELLOW}[$1]${RESET} $2"; }
err()  { echo -e "${RED}${BOLD}[$1]${RESET} $2"; }

# --- Check host dependencies ---

missing=()
for cmd in qemu-system-x86_64 qemu-img uv go curl python3; do
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
    err "deps" "Missing required tools: ${missing[*]}"
    echo "Install them and retry."
    exit 1
fi

# --- Helper: detect KVM ---

KVM_FLAG=""
if [[ -w /dev/kvm ]]; then
    KVM_FLAG="-enable-kvm"
fi

# --- Helper: create a cloud-init seed ISO ---

make_seed_iso() {
    local userdata="$1" output="$2" metadata="${3:-$SCRIPT_DIR/cloud-init-meta-data}"
    local tmpdir
    tmpdir=$(mktemp -d)
    cp "$userdata" "$tmpdir/user-data"
    cp "$metadata" "$tmpdir/meta-data"
    "$ISO_CMD" -output "$output" -volid cidata -joliet -rock \
        "$tmpdir/user-data" "$tmpdir/meta-data" \
        2>/dev/null
    rm -rf "$tmpdir"
}

# --- Cleanup on exit ---

cleanup() {
    local pids=("${TAIL_PID:-}" "${HTTP_PID:-}" "${OTELCOL_PID:-}" "${QEMU_PID:-}")
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

# --- Prepare base image (bake make into upstream image) ---

UPSTREAM="$CACHE/debian-13-genericcloud-amd64.qcow2"
BASE_PREPARED="$CACHE/base-prepared.qcow2"

if [[ "$REBUILD_BASE" == true ]] && [[ -f "$BASE_PREPARED" ]]; then
    log "host/base" "Removing existing prepared image (--rebuild-base)"
    rm -f "$BASE_PREPARED"
fi

if [[ ! -f "$BASE_PREPARED" ]]; then
    log "host/base" "Preparing base image (installing make)..."

    local_prep=$(mktemp -d)
    trap "rm -rf $local_prep; $(trap -p EXIT | sed "s/.*'\\(.*\\)'.*/\\1/")" EXIT

    # Create a temporary overlay for the preparation boot
    qemu-img create -f qcow2 -b "$UPSTREAM" -F qcow2 "$local_prep/prep-overlay.qcow2" >/dev/null
    make_seed_iso "$SCRIPT_DIR/cloud-init-prepare-data" "$local_prep/seed.iso" "$SCRIPT_DIR/cloud-init-prepare-meta-data"

    # Stream serial output during base preparation
    touch "$local_prep/serial.log"
    tail -f "$local_prep/serial.log" | sed -u -e 's/\x1b\[[0-9;]*[HJK]//g' -e 's/\r//g' -e "s/^/  ${DIM}[host\/base]${RESET} /" &
    PREP_TAIL_PID=$!

    qemu-system-x86_64 \
        -m 2048 -smp 2 $KVM_FLAG \
        -display none \
        -monitor none \
        -drive file="$local_prep/prep-overlay.qcow2",format=qcow2 \
        -drive file="$local_prep/seed.iso",format=raw \
        -netdev user,id=net0 \
        -device virtio-net-pci,netdev=net0 \
        -serial file:"$local_prep/serial.log"

    # Stop serial tail
    kill "$PREP_TAIL_PID" 2>/dev/null || true
    wait "$PREP_TAIL_PID" 2>/dev/null || true

    # Flatten overlay into a standalone image
    log "host/base" "Flattening prepared image..."
    qemu-img convert -O qcow2 "$local_prep/prep-overlay.qcow2" "$BASE_PREPARED"
    rm -rf "$local_prep"

    ok "host/base" "Base image ready ($(stat -c%s "$BASE_PREPARED" 2>/dev/null | awk '{printf "%.0f MB", $1/1048576}')"
else
    ok "host/base" "Prepared image cached"
fi

# --- Build daemon ---

log "host/build" "Compiling process-tracer (linux/amd64, static)..."
mkdir -p "$STAGING"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$STAGING/process-tracer" "$PROJECT_ROOT/cmd/process-tracer"
ok "host/build" "Done"

# --- Stage files ---

cp "$SCRIPT_DIR/guest-run.sh" "$STAGING/"
cp "$SCRIPT_DIR/Makefile.test" "$STAGING/"
cp "$SCRIPT_DIR/ambient-test.yaml" "$STAGING/"

# --- Start HTTP server (serves staging/ to VM) ---

log "host/http" "File server on :${HTTP_PORT}"
python3 -m http.server "$HTTP_PORT" -d "$STAGING" &>/dev/null &
HTTP_PID=$!

# --- Start OTLP collector on host ---

log "host/otel" "Starting otelcol-contrib..."
"$CACHE/otelcol-contrib" --config "$SCRIPT_DIR/otelcol.yaml" &>/dev/null &
OTELCOL_PID=$!

# Wait for collector to be ready
for i in $(seq 1 15); do
    HTTP_CODE=$(curl -so /dev/null -w '%{http_code}' http://localhost:4318/ 2>/dev/null || true)
    if [[ "$HTTP_CODE" =~ ^(200|404|405)$ ]]; then
        ok "host/otel" "Collector ready (${i}s)"
        break
    fi
    if (( i == 15 )); then
        err "host/otel" "Collector not ready after 15s"
        exit 1
    fi
    sleep 1
done

# --- Create cloud-init seed ISO ---

log "host/iso" "Creating cloud-init seed ISO..."
make_seed_iso "$SCRIPT_DIR/cloud-init-user-data" "$STAGING/seed.iso"

# --- Create overlay qcow2 ---

log "host/qcow" "Creating overlay from prepared base..."
qemu-img create -f qcow2 \
    -b "$BASE_PREPARED" -F qcow2 \
    "$STAGING/overlay.qcow2" \
    >/dev/null

# --- Start QEMU ---

if [[ -n "$KVM_FLAG" ]]; then
    ok "vm" "Starting QEMU (KVM enabled)"
else
    warn "vm" "Starting QEMU without KVM (slow — /dev/kvm not writable)"
fi

# Stream serial console in real-time (prefixed, dimmed)
touch "$STAGING/serial.log"
tail -f "$STAGING/serial.log" | sed -u -e 's/\x1b\[[0-9;]*[HJK]//g' -e 's/\r//g' -e "s/^/  ${DIM}[vm\/serial]${RESET} /" &
TAIL_PID=$!

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

log "vm" "Waiting (timeout ${TIMEOUT}s)..."
SECONDS=0
while kill -0 "$QEMU_PID" 2>/dev/null; do
    if (( SECONDS >= TIMEOUT )); then
        err "vm" "Timed out after ${TIMEOUT}s"
        exit 1
    fi
    sleep 2
done

wait "$QEMU_PID" 2>/dev/null || true
unset QEMU_PID

# Stop serial tail
kill "$TAIL_PID" 2>/dev/null || true
wait "$TAIL_PID" 2>/dev/null || true
unset TAIL_PID

ok "vm" "Completed in ${SECONDS}s"

# --- Give collector a moment to flush ---

sleep 2

# --- Stop host services ---

log "host/otel" "Stopping collector"
kill -TERM "$OTELCOL_PID" 2>/dev/null || true
wait "$OTELCOL_PID" 2>/dev/null || true
unset OTELCOL_PID

kill "$HTTP_PID" 2>/dev/null || true
wait "$HTTP_PID" 2>/dev/null || true
unset HTTP_PID

# --- Verify traces ---

echo ""
uv run --script "$SCRIPT_DIR/verify-traces.py" "$STAGING/traces.jsonl"
