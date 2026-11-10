#!/bin/sh
# usage: jaegerize.sh FILE.jsonl      (Ctrl-C stops and removes the container)
# Starts Jaeger, then follows FILE (from the start, survives truncation) and posts each
# OTLP-JSON line to it. Works on a finished file or one the tracer is still writing.
set -eu
FILE=${1:?usage: jaegerize.sh FILE.jsonl}
IMAGE=${JAEGER_IMAGE:-docker.io/jaegertracing/all-in-one:latest}
NAME=jaegerize
RT=$(command -v docker || command -v podman) || { echo "need docker or podman" >&2; exit 1; }

"$RT" rm -f "$NAME" >/dev/null 2>&1 || true
# Loopback only: spans may carry debug.environ.
"$RT" run -d --rm --name "$NAME" -p 127.0.0.1:16686:16686 -p 127.0.0.1:4318:4318 "$IMAGE" >/dev/null
trap '"$RT" rm -f "$NAME" >/dev/null 2>&1; kill 0 2>/dev/null || true' EXIT INT TERM

printf 'waiting for Jaeger'
until curl -s -o /dev/null http://127.0.0.1:16686/; do printf .; sleep 1; done
echo; echo "UI: http://127.0.0.1:16686  (service: spy-target)"

# --data-binary @- : lines are ~100KB+, too big for an argv string.
tail -n +1 -F "$FILE" 2>/dev/null | while IFS= read -r line; do
  [ -n "$line" ] || continue
  printf '%s' "$line" | curl -s -o /dev/null -w '.' -H 'content-type: application/json' \
    --data-binary @- http://127.0.0.1:4318/v1/traces || printf 'x'
done
