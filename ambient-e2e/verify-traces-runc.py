#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["pytest"]
# ///
"""Verify the runc-injection A/B experiment traces.

Hypothesis under test: a process injected into a container's namespaces via
`runc exec` (analog of `docker exec`) has its kernel real_parent set to the
injector on the host, NOT the container's PID 1 — so `is_container_init`
matching misses docker-exec payloads.

The workload (guest-run-runc.sh) runs:
  - `runc run testctr` with PID-1 command `sh -c "whoami; sleep 10"`
  - `runc exec testctr /bin/id`

Two rules are active (ambient-runc.yaml):
  - e2e-container-init (is_container_init: true)
  - e2e-id-witness     (command: "id")    — witness that the exec happened

Expected if the hypothesis holds:
  * e2e-container-init session contains: sh (PID 1 in ns) and whoami
  * The injected `id` does NOT appear in the container-init session
  * `id` shows up only in the e2e-id-witness session

Run with: uv run --script verify-traces-runc.py [traces.jsonl]
"""

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest


# -- Data model (minimal copy from verify-traces.py) --


@dataclass
class Span:
    name: str
    trace_id: str
    span_id: str
    parent_span_id: str
    start_unix_nano: int = 0
    end_unix_nano: int = 0
    attrs: dict = field(default_factory=dict)


def _parse_attr_value(v: dict):
    if "stringValue" in v:
        return v["stringValue"]
    if "intValue" in v:
        return int(v["intValue"])
    if "arrayValue" in v:
        return [_parse_attr_value(item) for item in v["arrayValue"].get("values", [])]
    return str(v)


def parse_traces(path: Path) -> list[Span]:
    spans: list[Span] = []
    for line in path.read_text().splitlines():
        doc = json.loads(line)
        for rs in doc.get("resourceSpans", []):
            for ss in rs.get("scopeSpans", []):
                for s in ss.get("spans", []):
                    attrs = {
                        a["key"]: _parse_attr_value(a["value"])
                        for a in s.get("attributes", [])
                    }
                    spans.append(Span(
                        name=s.get("name", ""),
                        trace_id=s.get("traceId", ""),
                        span_id=s.get("spanId", ""),
                        parent_span_id=s.get("parentSpanId", ""),
                        start_unix_nano=int(s.get("startTimeUnixNano", 0)),
                        end_unix_nano=int(s.get("endTimeUnixNano", 0)),
                        attrs=attrs,
                    ))
    return spans


# -- Fixtures --


TRACES_PATH: Path | None = None


@pytest.fixture(scope="session")
def all_spans():
    path = TRACES_PATH or Path("staging/traces.jsonl")
    assert path.is_file() and path.stat().st_size > 0, \
        f"traces.jsonl missing or empty: {path}"
    spans = parse_traces(path)
    assert spans, "no spans in traces"
    return spans


def _by_svc(spans, svc):
    return [s for s in spans if s.attrs.get("service.name") == svc]


def _descendants_of(spans, root):
    by_parent: dict = {}
    for s in spans:
        by_parent.setdefault(s.parent_span_id, []).append(s)
    out = [root]
    stack = [root.span_id]
    while stack:
        pid = stack.pop()
        for child in by_parent.get(pid, []):
            out.append(child)
            stack.append(child.span_id)
    return out


@pytest.fixture(scope="session")
def container_init_sessions(all_spans):
    """List of (tree, descendants) for each container-init process.tree."""
    trees = [s for s in _by_svc(all_spans, "ambient-e2e-container-init")
             if s.name == "process.tree"]
    return [(t, _descendants_of(all_spans, t)) for t in trees]


@pytest.fixture(scope="session")
def id_witness_sessions(all_spans):
    trees = [s for s in _by_svc(all_spans, "ambient-e2e-id-witness")
             if s.name == "process.tree"]
    return [(t, _descendants_of(all_spans, t)) for t in trees]


# -- Sanity invariants --


def test_some_spans_exported(all_spans):
    assert len(all_spans) > 0


def test_no_orphan_spans(all_spans):
    """Every non-process.tree span's parent must resolve within the export."""
    by_id = {s.span_id: s for s in all_spans}
    for s in all_spans:
        if s.name == "process.tree":
            continue
        parent = by_id.get(s.parent_span_id)
        assert parent is not None, (
            f"orphan: {s.attrs.get('process.command')!r} span {s.span_id} "
            f"parent_span_id={s.parent_span_id!r} not in export"
        )


# -- The A/B experiment --


class TestRuncInjection:
    """Core hypothesis test: `runc exec` payloads are invisible to
    `is_container_init` matching because their kernel real_parent is the
    host-side runc, not the container PID 1."""

    def test_container_init_session_exists(self, container_init_sessions):
        """The container's PID-1 sh must be caught by is_container_init."""
        assert len(container_init_sessions) >= 1, (
            "no process.tree with service.name=ambient-e2e-container-init — "
            "is_container_init detection failed to fire for the runc PID 1"
        )

    def test_container_init_session_captures_descendants(self, container_init_sessions):
        """Positive control: sh (container PID 1) fork-execs children inside
        the container (`whoami` once, then `sleep` repeatedly from the
        `while :; do sleep 1; done` loop). At least one non-sh descendant
        MUST appear in the container-init session — otherwise the BPF
        pipeline itself is broken and "id missing later" would be meaningless.

        Note: we accept any intra-container descendant rather than demanding
        `whoami` specifically. `whoami` fires the instant sh starts and can
        race with the daemon's TrackPID call; the subsequent sleep forks
        (after a 1s delay) are reliable."""
        _, members = container_init_sessions[0]
        cmds = [s.attrs.get("process.command") for s in members
                if s.name == "process.exec"]
        non_root_cmds = [c for c in cmds if c != "sh"]
        assert non_root_cmds, (
            f"container-init session has NO intra-container descendants — "
            f"only got: {cmds}. BPF-side descendant tracking is broken; "
            f"any downstream 'missing id' finding would be meaningless."
        )

    def test_container_init_session_missing_injected_id(self, container_init_sessions):
        """THE KEY ASSERTION. `id` was injected via `runc exec` — if the
        kernel real_parent pointed to container PID 1, `id` would be a
        descendant of the container-init session. It must NOT be, because
        runc exec's real_parent is the host-side runc."""
        _, members = container_init_sessions[0]
        id_in_session = [s for s in members
                         if s.attrs.get("process.command") == "id"]
        assert not id_in_session, (
            f"HYPOTHESIS DISPROVEN: `id` injected via runc exec appeared in "
            f"container-init session ({len(id_in_session)} span(s)). This means "
            f"the kernel real_parent chain DOES reach container PID 1 — "
            f"is_container_init matching is NOT the reason GitLab CI drops "
            f"docker-exec payloads."
        )

    def test_id_witness_session_exists(self, id_witness_sessions):
        """Witness: the injected `id` did exec — it just went to a DIFFERENT
        session because its parent chain is rooted at host-side runc.
        Without this assertion, 'id not in container-init' could mean either
        'exec never happened' or 'parent chain broken'. The witness pins it
        to the latter."""
        assert len(id_witness_sessions) >= 1, (
            "no process.tree with service.name=ambient-e2e-id-witness — "
            "did `runc exec` fail to start the `id` process? Check serial.log."
        )

    def test_id_witness_is_separate_trace(self, container_init_sessions, id_witness_sessions):
        """The witness session's trace_id must differ from the container-init
        trace_id. Both rules lack custom trace_id, so each session generates
        a fresh random trace root — confirming the two sessions are
        structurally unlinked in the kernel's view."""
        ci_trace, _ = container_init_sessions[0]
        id_trace, _ = id_witness_sessions[0]
        assert ci_trace.trace_id != id_trace.trace_id, (
            f"container-init and id-witness share trace_id {ci_trace.trace_id} — "
            f"unexpected: they should be unrelated sessions."
        )


# -- Entry point --


if __name__ == "__main__":
    args = sys.argv[1:]
    pytest_args: list[str] = []
    traces_arg: str | None = None

    if "--" in args:
        idx = args.index("--")
        if idx > 0:
            traces_arg = args[0]
        pytest_args = args[idx + 1:]
    elif args and not args[0].startswith("-"):
        traces_arg = args[0]
        pytest_args = args[1:]
    else:
        pytest_args = args

    if traces_arg:
        TRACES_PATH = Path(traces_arg)

    sys.exit(pytest.main([__file__, "-v", "--tb=short", *pytest_args]))
