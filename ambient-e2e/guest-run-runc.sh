#!/usr/bin/env bash
# Runc-injection experiment workload.
#
# Starts a real runc container, then injects a command into its namespaces
# with `runc exec`. The kernel sets the injected process's real_parent to
# the host-side runc, NOT the container's PID 1 — so tools matching on
# `is_container_init` miss the injected payload entirely.
#
# See ambient-e2e/verify-traces-runc.py for the assertions.
set -euo pipefail

HOST="http://10.0.2.2:9999"
CTR_DIR=/tmp/runc-ctr
CTR_ID=e2e-testctr

echo "[guest] Downloading files from host..."
curl -sf "$HOST/process-tracer" -o /tmp/process-tracer
curl -sf "$HOST/ambient-runc.yaml" -o /tmp/ambient-runc.yaml
chmod +x /tmp/process-tracer

echo "[guest] Starting process-tracer daemon..."
PROCESS_TRACER_SHUTDOWN_TIMEOUT_MS=5000 /tmp/process-tracer daemon -c /tmp/ambient-runc.yaml &
DAEMON_PID=$!

# Give eBPF probes time to attach
sleep 2

# --- Build a minimal OCI rootfs with busybox --------------------------------
echo "[guest] Building rootfs at $CTR_DIR/rootfs..."
rm -rf "$CTR_DIR"
mkdir -p "$CTR_DIR/rootfs"/{bin,dev,etc,proc,sys,tmp,root,usr/bin}

cp /usr/bin/busybox "$CTR_DIR/rootfs/bin/busybox"
for cmd in sh whoami id sleep env cat ls echo true; do
    ln -sf busybox "$CTR_DIR/rootfs/bin/$cmd"
done

# busybox whoami reads /etc/passwd to resolve uid 0 → "root".
cat > "$CTR_DIR/rootfs/etc/passwd" <<EOF
root:x:0:0:root:/root:/bin/sh
EOF
cat > "$CTR_DIR/rootfs/etc/group" <<EOF
root:x:0:
EOF

# --- OCI config.json --------------------------------------------------------
# Drops the network namespace so `runc exec` doesn't need extra setup.
#
# Container PID 1 runs an infinite sleep loop — this is deliberate: a
# simple `sh -c "whoami; sleep 10"` would let busybox ash exec-replace
# itself to sleep as its last command (a known BPF-side gap where re-exec
# of a tracked session-root emits a spurious EXEC_CANDIDATE). The
# `while :; do sleep 1; done` form keeps PID 1 as `sh` throughout, so
# every `sleep` is a clean fork-exec child.
cat > "$CTR_DIR/config.json" <<'EOF'
{
  "ociVersion": "1.0.2-dev",
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["sh", "-c", "whoami; while :; do sleep 1; done"],
    "env": ["PATH=/bin", "HOME=/root", "TERM=xterm"],
    "cwd": "/",
    "capabilities": {
      "bounding": ["CAP_AUDIT_WRITE", "CAP_KILL"],
      "effective": ["CAP_AUDIT_WRITE", "CAP_KILL"],
      "permitted": ["CAP_AUDIT_WRITE", "CAP_KILL"]
    },
    "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}],
    "noNewPrivileges": true
  },
  "root": {"path": "rootfs", "readonly": true},
  "hostname": "runc-e2e",
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
     "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
    {"destination": "/sys", "type": "sysfs", "source": "sysfs",
     "options": ["nosuid", "noexec", "nodev", "ro"]},
    {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
     "options": ["nosuid", "nodev"]}
  ],
  "linux": {
    "namespaces": [
      {"type": "pid"},
      {"type": "mount"},
      {"type": "ipc"},
      {"type": "uts"}
    ]
  }
}
EOF

# --- Run container in background -------------------------------------------
# Redirect stdio to a log file so killing the container doesn't leave
# runc's stdio attached to ttyS0, which can cause `wait` to hang on exit.
echo "[guest] Starting runc container ($CTR_ID)..."
cd "$CTR_DIR"
runc run "$CTR_ID" </dev/null >/tmp/runc-run.log 2>&1 &
RUNC_RUN_PID=$!

# Wait until container is in "running" state before execing into it.
for i in $(seq 1 25); do
    if runc state "$CTR_ID" 2>/dev/null | grep -q '"status": "running"'; then
        echo "[guest] Container running (${i} checks)"
        break
    fi
    if (( i == 25 )); then
        echo "[guest] ERROR: container did not reach running state"
        runc state "$CTR_ID" 2>&1 || true
        cat /tmp/runc-run.log 2>/dev/null || true
        break
    fi
    sleep 0.2
done

# Give PID-1 sh time to fork whoami and at least one sleep so those exec
# spans enter the container-init session (positive control).
sleep 1.2

# --- Inject `id` via runc exec --------------------------------------------
# This is the analog of `docker exec`: runc forks on the host and the child
# enters the container's PID namespace before execve. The injected process's
# kernel real_parent is the host-side runc — NOT the container PID 1.
echo "[guest] Injecting 'id' via runc exec..."
runc exec "$CTR_ID" /bin/id || echo "[guest] runc exec failed"

# Let BPF events propagate
sleep 0.5

# --- Cleanup --------------------------------------------------------------
echo "[guest] Killing container..."
runc kill "$CTR_ID" KILL 2>/dev/null || true

# Poll for runc run to exit, but don't wait forever — just force it.
for i in $(seq 1 15); do
    if ! kill -0 "$RUNC_RUN_PID" 2>/dev/null; then break; fi
    sleep 0.2
done
kill -9 "$RUNC_RUN_PID" 2>/dev/null || true
wait "$RUNC_RUN_PID" 2>/dev/null || true

# --force makes delete return even if state is inconsistent.
runc delete --force "$CTR_ID" 2>/dev/null || true

echo "[guest] Stopping daemon (PID $DAEMON_PID)..."
kill -TERM "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true

echo "[guest] Done"
