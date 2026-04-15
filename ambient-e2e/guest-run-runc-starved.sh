#!/usr/bin/env bash
# Runc context-starved materialization experiment.
#
# Mirrors guest-run-runc.sh's setup but uses a context_starved rule on
# `command: "runc"`. Two injections probe the materialization machinery:
#
#   A. Immediate-child context-ful descendant:
#      `runc exec -e CI_JOB_ID=42 -e CI_PROJECT_NAME=demo testctr /bin/id`
#      `id`'s envp carries the CI_* — materializes on the first descendant exec.
#
#   B. Grandchild context-ful descendant (GitLab-like: CI_* set at runtime):
#      `runc exec testctr /bin/sh -c 'export CI_*=...; /bin/id'`
#      `sh`'s envp has no CI_* (runc passes a minimal env), so it's starved
#      and buffered. The exported CI_* reach `/bin/id`'s exec envp via fork
#      inheritance — materializes on the grandchild.
#
# `runc run` itself also matches the rule, so its container-init subtree
# enters a pending-starved session that never resolves. It either drops at
# session_timeout or is simply never materialized; the verifier just asserts
# it never produces a process.tree.
#
# See ambient-e2e/verify-traces-runc-starved.py for the assertions.
set -euo pipefail

HOST="http://10.0.2.2:9999"
CTR_DIR=/tmp/runc-ctr
CTR_ID=e2e-testctr

echo "[guest] Downloading files from host..."
curl -sf "$HOST/process-tracer" -o /tmp/process-tracer
curl -sf "$HOST/ambient-runc-starved.yaml" -o /tmp/ambient-runc-starved.yaml
chmod +x /tmp/process-tracer

echo "[guest] Starting process-tracer daemon..."
PROCESS_TRACER_SHUTDOWN_TIMEOUT_MS=5000 /tmp/process-tracer daemon -c /tmp/ambient-runc-starved.yaml &
DAEMON_PID=$!

# Safety net: if this script exits for any reason (error, hang timeout,
# signal) the daemon still receives SIGTERM so OTEL gets a chance to flush
# its BatchSpanProcessor. Without this, an early exit leaves the daemon
# alive until VM poweroff SIGKILLs it, dropping every un-ended span.
trap 'kill -TERM "$DAEMON_PID" 2>/dev/null || true; wait "$DAEMON_PID" 2>/dev/null || true' EXIT

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

cat > "$CTR_DIR/rootfs/etc/passwd" <<EOF
root:x:0:0:root:/root:/bin/sh
EOF
cat > "$CTR_DIR/rootfs/etc/group" <<EOF
root:x:0:
EOF

# --- OCI config.json --------------------------------------------------------
# Container PID 1 is a minimal sleep loop so we have time to inject into it.
cat > "$CTR_DIR/config.json" <<'EOF'
{
  "ociVersion": "1.0.2-dev",
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["sh", "-c", "while :; do sleep 1; done"],
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
echo "[guest] Starting runc container ($CTR_ID)..."
cd "$CTR_DIR"
runc run "$CTR_ID" </dev/null >/tmp/runc-run.log 2>&1 &
RUNC_RUN_PID=$!

# Wait until container is running
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

sleep 0.5

# --- Variant A: CI_* passed via runc exec -e (immediate child context-ful) --
echo "[guest] Variant A: runc exec -e CI_JOB_ID=42 CI_PROJECT_NAME=demo ... /bin/id"
runc exec \
    -e CI_JOB_ID=42 \
    -e CI_PROJECT_NAME=demo \
    "$CTR_ID" /bin/id || echo "[guest] variant A runc exec failed"

sleep 0.5

# --- Variant B: CI_* set at runtime in sh (context-ful grandchild) ---------
# `sh` is starved at its exec (runc's envp has no CI_*); the exported vars
# live in sh's env table and are inherited by the child that execve's `id`,
# so `/bin/id`'s envp carries them → materialization fires on the grandchild.
echo "[guest] Variant B: runc exec ... sh -c 'export CI_*=runtime; /bin/id'"
runc exec "$CTR_ID" /bin/sh -c \
    'export CI_PIPELINE_ID=99 CI_JOB_ID=100 CI_PROJECT_NAME=runtime; /bin/id' \
    || echo "[guest] variant B runc exec failed"

# Let BPF events propagate
sleep 1

# --- Stop daemon FIRST ----------------------------------------------------
# The daemon needs SIGTERM + a clean flush window to get OTEL spans out.
# BPF events from variants A/B are already captured in the ring buffer by
# now, so the daemon doesn't need the container alive to do its work.
# Doing this BEFORE container cleanup matters because:
#   - cloud-init's runcmd fires `echo o > /proc/sysrq-trigger` the instant
#     this script exits, giving any EXIT trap no breathing room;
#   - runc cleanup occasionally hangs here, which would eat the flush
#     window entirely if the daemon stop came last.
echo "[guest] Stopping daemon (PID $DAEMON_PID)..."
kill -TERM "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true
echo "[guest] Daemon stopped"

# --- Cleanup container ----------------------------------------------------
echo "[guest] Killing container..."
runc kill "$CTR_ID" KILL 2>/dev/null || true
echo "[guest] waited on container kill"

for i in $(seq 1 15); do
    if ! kill -0 "$RUNC_RUN_PID" 2>/dev/null; then break; fi
    sleep 0.2
done
echo "[guest] runc-run loop done"
kill -9 "$RUNC_RUN_PID" 2>/dev/null || true
wait "$RUNC_RUN_PID" 2>/dev/null || true
echo "[guest] runc-run reaped"

runc delete --force "$CTR_ID" 2>/dev/null || true
echo "[guest] runc delete done"

echo "[guest] Done"
