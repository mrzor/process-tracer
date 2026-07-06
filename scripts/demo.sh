#!/usr/bin/env bash
#
# demo.sh — one-shot tmux demo for process-tracer direct mode.
#
# Lays out three panes in a tmux session:
#
#   +----------------------+---------------------------+
#   |                      |  mitmproxy  (:8080)       |  inspect the OTLP
#   |                      |  reverse proxy in front   |  telemetry the tracer
#   |  otel-tui  (:4318)   |  of otel-tui              |  emits (POST /v1/traces)
#   |  process + TCP spans +---------------------------+
#   |  from process-tracer |  runner: tracer + workload|  the demo driver
#   |                      |  (direct mode)            |
#   +----------------------+---------------------------+
#
# Telemetry path:
#
#   process-tracer ──OTLP/HTTP──▶ mitmproxy(:8080) ──reverse──▶ otel-tui(:4318)
#
#   - otel-tui receives OTLP/HTTP on :4318 (its default) and gRPC on :4317.
#   - mitmproxy runs as a REVERSE proxy (`-m reverse:http://localhost:4318`),
#     listening on :8080 and forwarding to otel-tui. Every span batch the
#     tracer exports shows up as a POST /v1/traces flow you can inspect.
#   - process-tracer exports to localhost:8080 (this repo's default OTLP
#     endpoint), i.e. straight at mitmproxy. Plain HTTP (OTEL_..._INSECURE).
#
# The workload itself runs normally — its curls go straight to the internet;
# mitmproxy here is watching the telemetry pipeline, not the workload traffic.
#
# Usage:
#   scripts/demo.sh          # build layout and attach
#   scripts/demo.sh stop     # tear the session down
#   scripts/demo.sh run      # (from the runner pane) re-run tracer+workload
#   PT_DEMO_NO_ATTACH=1 scripts/demo.sh   # set up detached (don't attach)
#
# Env overrides: PT_DEMO_SESSION, PT_MITM_PORT, PT_OTLP_PORT, PT_OTLP_GRPC_PORT.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SELF="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"

# --- Configuration (deterministic so every re-entry agrees) ------------------
SESSION="${PT_DEMO_SESSION:-pt-demo}"
OTLP_HTTP_PORT="${PT_OTLP_PORT:-4318}"        # otel-tui HTTP OTLP receiver
OTLP_GRPC_PORT="${PT_OTLP_GRPC_PORT:-4317}"   # otel-tui gRPC OTLP receiver
MITM_PORT="${PT_MITM_PORT:-8080}"             # mitmproxy reverse-proxy listen port
PT_BIN="$REPO_ROOT/process-tracer"
WORKLOAD="$REPO_ROOT/test_workload.sh"

log()  { printf '\033[1;36m[demo]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[demo] WARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[demo] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# Wait until a TCP port accepts connections (or time out).
wait_tcp() {
  local port="$1" tries="${2:-100}"
  for _ in $(seq 1 "$tries"); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then exec 3>&- 3<&-; return 0; fi
    sleep 0.2
  done
  return 1
}

# True if anything is LISTENing on the given local port (any address family).
port_bound() {
  ss -ltnH "sport = :$1" 2>/dev/null | grep -q LISTEN
}

# otel-tui ignores the SIGHUP that `tmux kill-session` sends, so it (and
# mitmproxy) outlive the panes and keep holding the ports — which makes the
# NEXT otel-tui fail to bind and vanish instantly. Kill our own instances
# explicitly, matched by the exact argv this script launches.
kill_strays() {
  pkill -TERM -f "otel-tui --http ${OTLP_HTTP_PORT} --grpc ${OTLP_GRPC_PORT}" 2>/dev/null || true
  pkill -TERM -f "mitmproxy -p ${MITM_PORT} -m reverse:" 2>/dev/null || true
  # Give them a moment to release the ports.
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    port_bound "$OTLP_HTTP_PORT" || port_bound "$MITM_PORT" || break
    sleep 0.2
  done
}

# Build the argv used to launch the tracer, honoring caps-or-sudo.
tracer_cmd() {
  if getcap "$PT_BIN" 2>/dev/null | grep -q 'cap_bpf'; then
    printf '%s\0' "$PT_BIN"
  else
    warn "no eBPF capabilities on $PT_BIN — falling back to 'sudo -E' (may prompt for a password in the runner pane)."
    warn "tip: 'mise run setcap' grants caps once so no sudo is needed."
    printf '%s\0' sudo -E "$PT_BIN"
  fi
}

# =============================================================================
# Subcommands run inside the tmux panes.
# =============================================================================

cmd_otel() {
  exec otel-tui --http "$OTLP_HTTP_PORT" --grpc "$OTLP_GRPC_PORT"
}

cmd_mitm() {
  # Reverse proxy: listen on $MITM_PORT, forward every request to otel-tui.
  exec mitmproxy -p "$MITM_PORT" -m "reverse:http://localhost:${OTLP_HTTP_PORT}"
}

cmd_run() {
  log "waiting for otel-tui (:$OTLP_HTTP_PORT) and mitmproxy (:$MITM_PORT)..."
  wait_tcp "$OTLP_HTTP_PORT" || die "otel-tui did not come up on :$OTLP_HTTP_PORT"
  wait_tcp "$MITM_PORT"      || die "mitmproxy did not come up on :$MITM_PORT"
  log "both up. tracing the workload in direct mode..."
  echo

  # Export OTLP at mitmproxy, which forwards to otel-tui. Plain HTTP.
  export OTEL_EXPORTER_OTLP_ENDPOINT="localhost:${MITM_PORT}"
  export OTEL_EXPORTER_OTLP_INSECURE=true
  export OTEL_SERVICE_NAME="pt-demo"

  # Read the caps-or-sudo argv back from the NUL-delimited helper.
  local -a tracer=()
  while IFS= read -r -d '' arg; do tracer+=("$arg"); done < <(tracer_cmd)

  set +e
  "${tracer[@]}" trace -a demo.name=pt-demo -- bash "$WORKLOAD"
  local rc=$?
  set -e

  echo
  log "workload finished (exit $rc)."
  log "→ otel-tui (left): open the single trace to see the process tree + tcp.connect spans."
  log "→ mitmproxy (top-right): the POST /v1/traces flows are the OTLP batches this tracer emitted."
  log "re-run just the workload:  '$SELF' run"
  echo
  exec "${SHELL:-bash}" -i
}

# =============================================================================
# Main: preflight + build the tmux layout.
# =============================================================================

cmd_stop() {
  if tmux has-session -t "$SESSION" 2>/dev/null; then
    tmux kill-session -t "$SESSION"
    log "killed tmux session '$SESSION'."
  else
    log "no tmux session '$SESSION'."
  fi
  # The pane processes outlive the session (see kill_strays); reap them too.
  kill_strays
  log "cleaned up otel-tui / mitmproxy instances."
}

preflight() {
  for c in tmux otel-tui mitmproxy getcap ss; do
    command -v "$c" >/dev/null 2>&1 || die "missing required tool: $c"
  done
  [ -x "$PT_BIN" ]   || die "process-tracer binary not found at $PT_BIN — build it with 'mise run go-build'."
  [ -f "$WORKLOAD" ] || die "workload not found at $WORKLOAD"
}

cmd_up() {
  preflight

  if tmux has-session -t "$SESSION" 2>/dev/null; then
    warn "tmux session '$SESSION' already exists — replacing it."
    tmux kill-session -t "$SESSION"
  fi

  # Reap any stragglers from a previous run, then confirm the ports are free.
  # A port held by something else would make otel-tui/mitmproxy vanish on start.
  kill_strays
  for pp in "OTLP:$OTLP_HTTP_PORT" "gRPC:$OTLP_GRPC_PORT" "mitmproxy:$MITM_PORT"; do
    if port_bound "${pp#*:}"; then
      die "port ${pp#*:} (${pp%:*}) is already in use by another process — free it or override the port (see env overrides in the header)."
    fi
  done

  # Pane 0 = left (otel-tui), 1 = top-right (mitmproxy), 2 = bottom-right (runner).
  tmux new-session -d -s "$SESSION" -x "${PT_DEMO_COLS:-230}" -y "${PT_DEMO_ROWS:-52}"
  tmux split-window -h -t "$SESSION"    -l 48%
  tmux split-window -v -t "$SESSION".1  -l 55%

  tmux send-keys -t "$SESSION".0 "exec '$SELF' __otel" C-m
  tmux send-keys -t "$SESSION".1 "exec '$SELF' __mitm" C-m
  tmux send-keys -t "$SESSION".2 "'$SELF' __run" C-m
  tmux select-pane -t "$SESSION".2

  if [ "${PT_DEMO_NO_ATTACH:-0}" = "1" ] || [ ! -t 1 ]; then
    log "session '$SESSION' is up (detached). attach with:  tmux attach -t $SESSION"
    log "tear down with:  '$SELF' stop"
  else
    exec tmux attach -t "$SESSION"
  fi
}

case "${1:-up}" in
  up|"")   cmd_up ;;
  run)     cmd_run ;;     # re-run tracer+workload from inside an existing runner pane
  stop)    cmd_stop ;;
  __otel)  cmd_otel ;;    # internal: pane entrypoints
  __mitm)  cmd_mitm ;;
  __run)   cmd_run ;;
  *)       die "unknown subcommand: $1 (use: up | run | stop)" ;;
esac
