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
DBG_LOG=/tmp/process-tracer-debug.log
PROCESS_TRACER_SHUTDOWN_TIMEOUT_MS=5000 /tmp/process-tracer daemon \
    -c /tmp/ambient-runc-starved.yaml \
    --debug-log="$DBG_LOG" &
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

sleep 0.5

# --- Variant D: detached subshell — sleeps reparented to container init ---
# Probes the production failure mode: a descendant chain whose real_parent
# chain no longer reaches any tracked PID. The outer sh materialises, then
# spawns a subshell that *itself* backgrounds a grandchild loop and exits.
# The grandchild is orphaned → reparented to the container's init (PID 1
# inside the container) which is NOT in any materialised session. BPF's
# sched_process_fork ancestor walk from a subsequent sleep will follow
# real_parent → init → give up within 8 hops, and emit tracked_ancestor=0.
# That's exactly the shape we saw in production for the GitLab bash step
# script's sleep chain.
#
# The outer runc exec `wait`s only on the first-level child (which exits
# quickly), so runc returns fast. We then `sleep 8` after this variant to
# hold the container alive long enough for the detached grandchild's
# sleeps to complete — otherwise the container-kill would cut them off.
echo "[guest] Variant D: runc exec ... (detached subshell, sleeps reparented)"
runc exec "$CTR_ID" /bin/sh -c 'export CI_PIPELINE_ID=333 CI_JOB_ID=444 CI_PROJECT_NAME=detached; /bin/id; ( ( for i in 1 2 3 4; do /bin/sleep 1; done ) & )' \
    || echo "[guest] variant D runc exec failed"

# Hold the container alive so the detached grandchild can finish its sleeps.
sleep 8

# --- Variant C: long-lived sh materialises, then forks a sleep chain ------
# sh is starved at its exec (no CI_* in execve envp). It exports CI_* then
# execs /bin/id (materialisation trigger — id's envp inherits the exports).
# sh then continues, forking four child processes that exec /bin/sleep.
# In a healthy world, the materialised session captures /bin/id and all
# four sleeps. In the buggy world (v0.8.4), /bin/id attaches but
# post-materialisation forks from sh are silent — BPF stops emitting fork
# events for the sh/sleep subtree once the materialise race closes. This
# variant is the regression shape pulled from a production GitLab runner
# pipeline that executed `sleep 10; sleep 20; sleep 10; sleep 20`.
echo "[guest] Variant C: runc exec ... sh -c 'export CI_*=longlived; id; sleep×4'"
runc exec "$CTR_ID" /bin/sh -c 'export CI_PIPELINE_ID=111 CI_JOB_ID=222 CI_PROJECT_NAME=longlived; /bin/id; for i in 1 2 3 4; do /bin/sleep 1; done' \
    || echo "[guest] variant C runc exec failed"

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

# --- Emit debug-log to dedicated serial port ------------------------------
# QEMU's second serial (-serial file:.../debug.log) is wired to /dev/ttyS1
# inside the VM. We cat the daemon's structured diagnostic log there so
# the host captures it directly, without contention with the main ttyS0
# serial (which has getty and escape sequences interleaved). Moved ahead
# of container cleanup because `runc kill` / `runc delete` can hang for
# seconds, and cloud-init's post-runcmd poweroff races the script tail.
# Daemon stop above already drained the zap sink (Sync in cleanup()), so
# the file is complete when we cat it here.
if [[ -r "$DBG_LOG" ]]; then
    cat "$DBG_LOG" > /dev/ttyS1 || true
    echo "[guest] Debug log ($(wc -l <"$DBG_LOG") events) piped to /dev/ttyS1"
else
    echo "[guest] Debug log not produced at $DBG_LOG"
fi

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
