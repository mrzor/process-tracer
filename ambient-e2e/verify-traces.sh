#!/usr/bin/env bash
set -euo pipefail

TRACES="${1:-staging/traces.jsonl}"
FAILURES=0

pass() { echo "[verify] $1: PASS"; }
fail() { echo "[verify] $1: FAIL — $2"; FAILURES=$((FAILURES + 1)); }

# --- Basics ---

if [[ ! -s "$TRACES" ]]; then
    fail "traces.jsonl exists" "file missing or empty"
    echo "RESULT: FAIL ($((FAILURES)) check(s) failed)"
    exit 1
fi
pass "traces.jsonl exists ($(wc -l < "$TRACES") lines)"

if jq -e '.' "$TRACES" > /dev/null 2>&1; then
    pass "valid JSONL"
else
    fail "valid JSONL" "jq parse error"
fi

ALL_SPANS=$(jq -s '[.[].resourceSpans[]?.scopeSpans[]?.spans[]?]' "$TRACES" 2>/dev/null || echo "[]")
SPAN_COUNT=$(echo "$ALL_SPANS" | jq 'length')

# Helper: extract spans for a given service.name attribute value
spans_by_svc() {
    echo "$ALL_SPANS" | jq --arg svc "$1" \
        '[.[] | select(.attributes[]? | .key == "service.name" and .value.stringValue == $svc)]'
}

# --- All spans are process.exec ---

NON_EXEC=$(echo "$ALL_SPANS" | jq '[.[] | select(.name != "process.exec")] | length')
if (( NON_EXEC == 0 )); then
    pass "all spans are process.exec"
else
    fail "all spans are process.exec" "$NON_EXEC span(s) have unexpected name"
fi

# ============================================================
# Session 1: make (matched by "e2e-make" rule)
# ============================================================

MAKE_SPANS=$(spans_by_svc "ambient-e2e-make")
MAKE_COUNT=$(echo "$MAKE_SPANS" | jq 'length')

if (( MAKE_COUNT >= 4 )); then
    pass "make session: span count ($MAKE_COUNT >= 4)"
else
    fail "make session: span count" "expected >= 4, got $MAKE_COUNT"
fi

# Root span is make
MAKE_ROOT=$(echo "$MAKE_SPANS" | jq '[.[] | select(.parentSpanId == "" or .parentSpanId == null)] | first // empty')
MAKE_ROOT_CMD=$(echo "$MAKE_ROOT" | jq -r '[.attributes[] | select(.key == "process.command")] | first | .value.stringValue // empty')
if [[ "$MAKE_ROOT_CMD" == "make" ]]; then
    pass "make session: root span is 'make'"
else
    fail "make session: root span" "got '$MAKE_ROOT_CMD'"
fi

# Single traceId within make session
MAKE_TRACES=$(echo "$MAKE_SPANS" | jq '[.[].traceId] | unique | length')
if (( MAKE_TRACES == 1 )); then
    pass "make session: single traceId"
else
    fail "make session: single traceId" "found $MAKE_TRACES distinct traceIds"
fi

# Expected child commands from Makefile.test: sleep, hostname, uname
MAKE_CMDS=$(echo "$MAKE_SPANS" | jq -r '[.[].attributes[] | select(.key == "process.command") | .value.stringValue] | unique | .[]')
MISSING=""
for cmd in sleep hostname uname; do
    if ! echo "$MAKE_CMDS" | grep -qx "$cmd"; then
        MISSING="$MISSING $cmd"
    fi
done
if [[ -z "$MISSING" ]]; then
    pass "make session: expected children (sleep, hostname, uname)"
else
    fail "make session: expected children" "missing:$MISSING"
fi

# Parent-child linkage
MAKE_ROOT_ID=$(echo "$MAKE_ROOT" | jq -r '.spanId // empty')
if [[ -n "$MAKE_ROOT_ID" ]]; then
    MAKE_CHILDREN=$(echo "$MAKE_SPANS" | jq --arg rsid "$MAKE_ROOT_ID" \
        '[.[] | select(.parentSpanId == $rsid)] | length')
    if (( MAKE_CHILDREN >= 2 )); then
        pass "make session: parent-child linkage ($MAKE_CHILDREN direct children)"
    else
        fail "make session: parent-child linkage" "expected >= 2 children, got $MAKE_CHILDREN"
    fi
fi

# Duration sanity: sleep 0.2 should take >= 150ms
MAKE_SLEEP=$(echo "$MAKE_SPANS" | jq -r '
  [.[] | select(.attributes[] | .key == "process.command" and .value.stringValue == "sleep")
       | [.attributes[] | select(.key == "process.duration_ns") | (.value.intValue // (.value.stringValue | tonumber? // 0))][0]]
  | max // 0')
if (( MAKE_SLEEP >= 150000000 )); then
    pass "make session: sleep duration ($(( MAKE_SLEEP / 1000000 ))ms >= 150ms)"
else
    fail "make session: sleep duration" "$(( MAKE_SLEEP / 1000000 ))ms, expected >= 150ms"
fi

# ============================================================
# Session 2: perl (matched by "e2e-perl" rule)
# ============================================================

PERL_SPANS=$(spans_by_svc "ambient-e2e-perl")
PERL_COUNT=$(echo "$PERL_SPANS" | jq 'length')

if (( PERL_COUNT >= 2 )); then
    pass "perl session: span count ($PERL_COUNT >= 2)"
else
    fail "perl session: span count" "expected >= 2, got $PERL_COUNT"
fi

# Root span is perl
PERL_ROOT=$(echo "$PERL_SPANS" | jq '[.[] | select(.parentSpanId == "" or .parentSpanId == null)] | first // empty')
PERL_ROOT_CMD=$(echo "$PERL_ROOT" | jq -r '[.attributes[] | select(.key == "process.command")] | first | .value.stringValue // empty')
if [[ "$PERL_ROOT_CMD" == "perl" ]]; then
    pass "perl session: root span is 'perl'"
else
    fail "perl session: root span" "got '$PERL_ROOT_CMD'"
fi

# Single traceId within perl session
PERL_TRACES=$(echo "$PERL_SPANS" | jq '[.[].traceId] | unique | length')
if (( PERL_TRACES == 1 )); then
    pass "perl session: single traceId"
else
    fail "perl session: single traceId" "found $PERL_TRACES distinct traceIds"
fi

# Perl spawns echo, sleep, uname via system() — at least one child
PERL_ROOT_ID=$(echo "$PERL_ROOT" | jq -r '.spanId // empty')
if [[ -n "$PERL_ROOT_ID" ]]; then
    PERL_CHILDREN=$(echo "$PERL_SPANS" | jq --arg rsid "$PERL_ROOT_ID" \
        '[.[] | select(.parentSpanId == $rsid)] | length')
    if (( PERL_CHILDREN >= 1 )); then
        pass "perl session: has children ($PERL_CHILDREN)"
    else
        fail "perl session: has children" "no child spans found"
    fi
fi

# ============================================================
# Two distinct sessions (different traceIds)
# ============================================================

MAKE_TRACE_ID=$(echo "$MAKE_SPANS" | jq -r '.[0].traceId // empty')
PERL_TRACE_ID=$(echo "$PERL_SPANS" | jq -r '.[0].traceId // empty')
if [[ -n "$MAKE_TRACE_ID" && -n "$PERL_TRACE_ID" && "$MAKE_TRACE_ID" != "$PERL_TRACE_ID" ]]; then
    pass "sessions have distinct traceIds"
else
    fail "sessions have distinct traceIds" "make=$MAKE_TRACE_ID perl=$PERL_TRACE_ID"
fi

# ============================================================
# Negative: unmatched processes must NOT appear
# ============================================================

# We ran: find, dd, ls, cat, wc — none should produce spans
UNMATCHED="find dd ls cat wc"
LEAKED=""
for cmd in $UNMATCHED; do
    FOUND=$(echo "$ALL_SPANS" | jq --arg c "$cmd" \
        '[.[] | select(.attributes[]? | .key == "process.command" and .value.stringValue == $c)] | length')
    if (( FOUND > 0 )); then
        LEAKED="$LEAKED $cmd($FOUND)"
    fi
done
if [[ -z "$LEAKED" ]]; then
    pass "unmatched processes not traced ($UNMATCHED)"
else
    fail "unmatched processes not traced" "leaked:$LEAKED"
fi

# ============================================================
# Attribute completeness (all spans)
# ============================================================

REQUIRED_ATTRS="process.pid process.parent_pid process.command process.duration_ns process.owner.uid"
ATTR_MISSING=""
for attr in $REQUIRED_ATTRS; do
    SPANS_WITH=$(echo "$ALL_SPANS" | jq --arg a "$attr" \
        '[.[] | select(.attributes[] | .key == $a)] | length')
    if (( SPANS_WITH != SPAN_COUNT )); then
        ATTR_MISSING="$ATTR_MISSING $attr($SPANS_WITH/$SPAN_COUNT)"
    fi
done
if [[ -z "$ATTR_MISSING" ]]; then
    pass "required attributes on all spans ($SPAN_COUNT/$SPAN_COUNT)"
else
    fail "required attributes" "incomplete:$ATTR_MISSING"
fi

# Resource-level service.name matches daemon config
RESOURCE_SVC=$(jq -s '[.[].resourceSpans[].resource.attributes[] | select(.key == "service.name") | .value.stringValue] | unique | .[]' "$TRACES" 2>/dev/null)
if [[ "$RESOURCE_SVC" == '"ambient-e2e-daemon"' ]]; then
    pass "resource service.name = ambient-e2e-daemon"
else
    fail "resource service.name" "expected 'ambient-e2e-daemon', got $RESOURCE_SVC"
fi

# --- Summary ---

echo ""
if (( FAILURES == 0 )); then
    echo "ALL CHECKS PASSED ($SPAN_COUNT spans across 2 sessions)"
    exit 0
else
    echo "RESULT: FAIL ($FAILURES check(s) failed)"
    exit 1
fi
