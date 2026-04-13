#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["pytest"]
# ///
"""Verify OTLP trace output from the daemon mode E2E test.

Run with: uv run --script verify-traces.py [traces.jsonl]
Accepts pytest flags: uv run --script verify-traces.py -- -v
"""

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest


# ── Data model ──────────────────────────────────────────────


@dataclass
class Span:
    name: str
    trace_id: str
    span_id: str
    parent_span_id: str
    attrs: dict[str, str | int | list] = field(default_factory=dict)


def _parse_attr_value(v: dict) -> str | int | list:
    if "stringValue" in v:
        return v["stringValue"]
    if "intValue" in v:
        return int(v["intValue"])
    if "arrayValue" in v:
        return [_parse_attr_value(item) for item in v["arrayValue"].get("values", [])]
    return str(v)


def parse_traces(path: Path) -> tuple[list[Span], list[dict]]:
    """Parse JSONL trace file, return (flat span list, raw resource spans)."""
    spans: list[Span] = []
    resource_spans: list[dict] = []
    for line in path.read_text().splitlines():
        doc = json.loads(line)
        for rs in doc.get("resourceSpans", []):
            resource_spans.append(rs)
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
                        attrs=attrs,
                    ))
    return spans, resource_spans


# ── Fixtures ────────────────────────────────────────────────


TRACES_PATH: Path | None = None


def _resolve_traces_path() -> Path:
    if TRACES_PATH is not None:
        return TRACES_PATH
    return Path("staging/traces.jsonl")


@pytest.fixture(scope="session")
def traces_path():
    return _resolve_traces_path()


@pytest.fixture(scope="session")
def parsed(traces_path):
    assert traces_path.is_file() and traces_path.stat().st_size > 0, \
        f"traces.jsonl missing or empty: {traces_path}"
    spans, resource_spans = parse_traces(traces_path)
    assert len(spans) > 0, "no spans found in traces"
    return spans, resource_spans


@pytest.fixture(scope="session")
def all_spans(parsed):
    return parsed[0]


@pytest.fixture(scope="session")
def resource_spans(parsed):
    return parsed[1]


def _spans_by_svc(spans: list[Span], svc: str) -> list[Span]:
    return [s for s in spans if s.attrs.get("service.name") == svc]


def _root_span(spans: list[Span]) -> Span | None:
    roots = [s for s in spans if not s.parent_span_id]
    return roots[0] if roots else None


@pytest.fixture(scope="session")
def make_spans(all_spans):
    return _spans_by_svc(all_spans, "ambient-e2e-make")


@pytest.fixture(scope="session")
def perl_spans(all_spans):
    return _spans_by_svc(all_spans, "ambient-e2e-perl")


# ── Tests ───────────────────────────────────────────────────


def test_all_spans_are_process_exec(all_spans):
    bad = [s.name for s in all_spans if s.name != "process.exec"]
    assert not bad, f"unexpected span names: {bad}"


# -- Make session --


class TestMakeSession:
    def test_span_count(self, make_spans):
        assert len(make_spans) >= 4, f"got {len(make_spans)}"

    def test_root_is_make(self, make_spans):
        root = _root_span(make_spans)
        assert root is not None, "no root span"
        assert root.attrs.get("process.command") == "make"

    def test_single_trace_id(self, make_spans):
        ids = set(s.trace_id for s in make_spans)
        assert len(ids) == 1, f"found {len(ids)} traceIds: {ids}"

    def test_expected_children(self, make_spans):
        cmds = {s.attrs.get("process.command") for s in make_spans}
        for expected in ("sleep", "hostname", "uname"):
            assert expected in cmds, f"missing child command: {expected}"

    def test_parent_child_linkage(self, make_spans):
        root = _root_span(make_spans)
        assert root is not None
        children = [s for s in make_spans if s.parent_span_id == root.span_id]
        assert len(children) >= 2, f"expected >= 2 direct children, got {len(children)}"

    def test_env_attributes(self, make_spans):
        for s in make_spans:
            assert s.attrs.get("build.id") == "make-run-42", \
                f"span {s.span_id} build.id={s.attrs.get('build.id')}"
            assert s.attrs.get("build.region") == "us-east-1", \
                f"span {s.span_id} build.region={s.attrs.get('build.region')}"

    def test_sleep_duration(self, make_spans):
        durations = [
            int(s.attrs.get("process.duration_ns", 0))
            for s in make_spans
            if s.attrs.get("process.command") == "sleep"
        ]
        assert durations, "no sleep spans found"
        assert max(durations) >= 150_000_000, \
            f"longest sleep was {max(durations) // 1_000_000}ms, expected >= 150ms"

    # --- Debug attributes (add_debug_attributes: true on this rule) ---

    def test_debug_argv_on_every_span(self, make_spans):
        """debug.argv should be present on every span when add_debug_attributes is enabled."""
        for s in make_spans:
            argv = s.attrs.get("debug.argv")
            assert isinstance(argv, list) and len(argv) > 0, \
                f"span {s.span_id} ({s.attrs.get('process.command')}) missing debug.argv, got: {argv!r}"

    def test_debug_environ_contains_build_id(self, make_spans):
        """debug.environ should include BUILD_ID=make-run-42 on every span."""
        for s in make_spans:
            environ = s.attrs.get("debug.environ")
            assert isinstance(environ, list) and len(environ) > 0, \
                f"span {s.span_id} missing debug.environ"
            assert "BUILD_ID=make-run-42" in environ, \
                f"span {s.span_id} debug.environ missing BUILD_ID entry"

    def test_root_debug_trace_id_unconfigured(self, make_spans):
        """No trace_id set on this rule → source=unconfigured on the root span."""
        root = _root_span(make_spans)
        assert root is not None
        assert root.attrs.get("debug.trace_id.source") == "unconfigured", \
            f"got {root.attrs.get('debug.trace_id.source')!r}"

    def test_root_debug_parent_id_unconfigured(self, make_spans):
        """No parent_id expression → source=unconfigured."""
        root = _root_span(make_spans)
        assert root is not None
        assert root.attrs.get("debug.parent_id.source") == "unconfigured", \
            f"got {root.attrs.get('debug.parent_id.source')!r}"

    def test_non_root_spans_lack_root_debug_attrs(self, make_spans):
        """debug.trace_id.*/debug.parent_id.* should only be on the root span."""
        root = _root_span(make_spans)
        assert root is not None
        for s in make_spans:
            if s.span_id == root.span_id:
                continue
            assert "debug.trace_id.source" not in s.attrs, \
                f"non-root span {s.span_id} has debug.trace_id.source"
            assert "debug.parent_id.source" not in s.attrs, \
                f"non-root span {s.span_id} has debug.parent_id.source"


# -- Perl session --


class TestPerlSession:
    def test_span_count(self, perl_spans):
        assert len(perl_spans) >= 2, f"got {len(perl_spans)}"

    def test_root_is_perl(self, perl_spans):
        root = _root_span(perl_spans)
        assert root is not None, "no root span"
        assert root.attrs.get("process.command") == "perl"

    def test_single_trace_id(self, perl_spans):
        ids = set(s.trace_id for s in perl_spans)
        assert len(ids) == 1, f"found {len(ids)} traceIds: {ids}"

    def test_env_attributes(self, perl_spans):
        for s in perl_spans:
            assert s.attrs.get("job.id") == "perl-job-99", \
                f"span {s.span_id} job.id={s.attrs.get('job.id')}"
            assert s.attrs.get("job.tier") == "critical", \
                f"span {s.span_id} job.tier={s.attrs.get('job.tier')}"

    def test_has_children(self, perl_spans):
        root = _root_span(perl_spans)
        assert root is not None
        children = [s for s in perl_spans if s.parent_span_id == root.span_id]
        assert len(children) >= 1, "no child spans"

    def test_no_debug_attrs_on_unenabled_rule(self, perl_spans):
        """e2e-perl rule does NOT set add_debug_attributes — debug.* must be absent."""
        for s in perl_spans:
            leaked = [k for k in s.attrs if k.startswith("debug.")]
            assert not leaked, \
                f"span {s.span_id} (perl rule) leaked debug attrs: {leaked}"


# -- Cross-session --


def test_sessions_have_distinct_trace_ids(make_spans, perl_spans):
    make_ids = {s.trace_id for s in make_spans}
    perl_ids = {s.trace_id for s in perl_spans}
    assert make_ids and perl_ids, "one or both sessions empty"
    assert make_ids.isdisjoint(perl_ids), \
        f"sessions share traceIds: {make_ids & perl_ids}"


def test_unmatched_processes_not_traced(all_spans):
    """find, dd, ls, cat, wc ran in the VM but should not produce spans."""
    unmatched = ("find", "dd", "ls", "cat", "wc")
    leaked = [
        cmd for cmd in unmatched
        if any(s.attrs.get("process.command") == cmd for s in all_spans)
    ]
    assert not leaked, f"unmatched commands leaked into traces: {leaked}"


def test_required_attributes(all_spans):
    required = ("process.pid", "process.parent_pid", "process.command",
                "process.duration_ns", "process.owner.uid")
    for attr in required:
        missing = [s for s in all_spans if attr not in s.attrs]
        assert not missing, \
            f"{attr} missing on {len(missing)}/{len(all_spans)} spans"


def test_resource_service_name(resource_spans):
    names = set()
    for rs in resource_spans:
        for a in rs.get("resource", {}).get("attributes", []):
            if a["key"] == "service.name":
                names.add(a["value"].get("stringValue", ""))
    assert names == {"ambient-e2e-daemon"}, f"got {names}"


# ── Entry point ─────────────────────────────────────────────


if __name__ == "__main__":
    # Split args: everything before "--" is our traces path,
    # everything after is forwarded to pytest.
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
