#!/bin/sh
# usage: [SPY_TARGET=/path/to/script] sudo -E demo/ambient-mode-on-a-script/spy.sh   (Ctrl-C to stop; flushes spans on shutdown)
# Traces only $SPY_TARGET (default /usr/sbin/spy.sh), system-wide, into /tmp as OTLP JSONL.
# Needs `sudo -E` (or `sudo SPY_TARGET=...`) so the variable survives into root's environment.
# Set PROCESS_TRACER to use a binary other than ./process-tracer (build: go build -o process-tracer ./cmd/process-tracer).
SPY_TARGET=${SPY_TARGET:-/usr/sbin/spy.sh}
# Kernel comm = first 15 chars of the exec'd file's basename; that is what the rule matches.
COMM=$(basename "$SPY_TARGET" | cut -c1-15)
DIR=$(cd "$(dirname "$0")" && pwd)
# Normalised on purpose: ".." in argv0 used to trip symlink-mode detection.
ROOT=$(cd "$DIR/../.." && pwd)
BIN=${PROCESS_TRACER:-$ROOT/process-tracer}
# Try repo root (../..), then PATH (root's PATH under sudo may be minimal).
[ -x "$BIN" ] || BIN=$(command -v process-tracer) || {
  echo "process-tracer not found at $DIR/../../process-tracer or on PATH; build it or set PROCESS_TRACER" >&2; exit 1; }
STAMP=$(date +%Y%m%dT%H%M%S)
OUT=/tmp/spy-spans-$STAMP.jsonl
CONF=/tmp/spy-conf-$STAMP.yaml
sed "s|@COMM@|$COMM|" "$DIR/spy.yaml" > "$CONF" || exit 1
echo "target comm: $COMM ($SPY_TARGET)"
echo "writing $OUT"
# The daemon (root) must create $OUT itself: fs.protected_regular forbids root from
# opening a user-owned file we pre-created in sticky /tmp. Once it appears, hand it to the
# invoking user; env data inside is sensitive, so 0600.
( until [ -e "$OUT" ]; do sleep 0.1; done
  chown "${SUDO_UID:-$(id -u)}:${SUDO_GID:-$(id -g)}" "$OUT"; chmod 600 "$OUT" ) &
PROCESS_TRACER_OTEL_JSON_FILE=$OUT PROCESS_TRACER_SHUTDOWN_TIMEOUT_MS=2000 \
  exec "$BIN" daemon -c "$CONF"
