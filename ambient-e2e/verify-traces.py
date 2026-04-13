#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["pytest"]
# ///
"""Verify OTLP trace output from the daemon mode E2E test.

Run with: uv run --script verify-traces.py [traces.jsonl]
Accepts pytest flags: uv run --script verify-traces.py -- -v
"""

import hashlib
import json
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


def _process_tree(spans: list[Span]) -> Span | None:
    """The synthetic root span emitted once per session."""
    trees = [s for s in spans if s.name == "process.tree"]
    return trees[0] if trees else None


def _exec_spans(spans: list[Span]) -> list[Span]:
    return [s for s in spans if s.name == "process.exec"]


def _first_exec(spans: list[Span]) -> Span | None:
    """The first observed process.exec — child of the session's process.tree span."""
    tree = _process_tree(spans)
    if tree is None:
        return None
    children = [s for s in _exec_spans(spans) if s.parent_span_id == tree.span_id]
    return children[0] if children else None


@pytest.fixture(scope="session")
def make_spans(all_spans):
    return _spans_by_svc(all_spans, "ambient-e2e-make")


@pytest.fixture(scope="session")
def perl_spans(all_spans):
    return _spans_by_svc(all_spans, "ambient-e2e-perl")


# ── Tests ───────────────────────────────────────────────────


def test_span_names(all_spans):
    """Every span is either a process.tree session root or a process.exec."""
    allowed = {"process.tree", "process.exec"}
    bad = [s.name for s in all_spans if s.name not in allowed]
    assert not bad, f"unexpected span names: {bad}"


# -- Make session --


class TestMakeSession:
    def test_span_count(self, make_spans):
        assert len(make_spans) >= 4, f"got {len(make_spans)}"

    def test_process_tree_is_session_root(self, make_spans):
        """process.tree sits at the top of the session. When custom trace_id is
        configured (this rule uses BUILD_ID), StartSession synthesizes a virtual
        parent SpanID so OTEL honors the injected trace_id — that virtual parent
        does NOT exist as a real span in the export. No other session span may
        be process.tree's parent."""
        tree = _process_tree(make_spans)
        assert tree is not None, "no process.tree span"
        session_span_ids = {s.span_id for s in make_spans}
        assert tree.parent_span_id not in session_span_ids, \
            f"process.tree parented by another session span: {tree.parent_span_id!r}"

    def test_first_exec_is_make(self, make_spans):
        first = _first_exec(make_spans)
        assert first is not None, "no first exec under process.tree"
        assert first.attrs.get("process.command") == "make"

    def test_first_exec_child_of_process_tree(self, make_spans):
        tree = _process_tree(make_spans)
        first = _first_exec(make_spans)
        assert tree is not None and first is not None
        assert first.parent_span_id == tree.span_id, \
            f"first exec parent={first.parent_span_id!r}, tree={tree.span_id!r}"

    def test_single_trace_id(self, make_spans):
        ids = set(s.trace_id for s in make_spans)
        assert len(ids) == 1, f"found {len(ids)} traceIds: {ids}"

    def test_expected_children(self, make_spans):
        cmds = {s.attrs.get("process.command") for s in make_spans}
        for expected in ("sleep", "hostname", "uname"):
            assert expected in cmds, f"missing child command: {expected}"

    def test_make_has_children(self, make_spans):
        first = _first_exec(make_spans)
        assert first is not None
        children = [s for s in make_spans if s.parent_span_id == first.span_id]
        assert len(children) >= 2, f"expected >= 2 direct children of make, got {len(children)}"

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

    def test_debug_argv_on_every_exec_span(self, make_spans):
        """debug.argv should be present on every process.exec span when add_debug_attributes is enabled."""
        for s in _exec_spans(make_spans):
            argv = s.attrs.get("debug.argv")
            assert isinstance(argv, list) and len(argv) > 0, \
                f"span {s.span_id} ({s.attrs.get('process.command')}) missing debug.argv, got: {argv!r}"

    def test_debug_environ_contains_build_id(self, make_spans):
        """debug.environ should include BUILD_ID=make-run-42 on every process.exec span."""
        for s in _exec_spans(make_spans):
            environ = s.attrs.get("debug.environ")
            assert isinstance(environ, list) and len(environ) > 0, \
                f"span {s.span_id} missing debug.environ"
            assert "BUILD_ID=make-run-42" in environ, \
                f"span {s.span_id} debug.environ missing BUILD_ID entry"

    def test_root_debug_trace_id_provenance(self, make_spans):
        """process.tree span should show trace_id came from expr + hashed fallback (BUILD_ID is not hex)."""
        root = _process_tree(make_spans)
        assert root is not None
        assert root.attrs.get("debug.trace_id.source") == "expr", \
            f"got {root.attrs.get('debug.trace_id.source')!r}"
        assert root.attrs.get("debug.trace_id.expression") == 'env["BUILD_ID"]', \
            f"got {root.attrs.get('debug.trace_id.expression')!r}"
        assert root.attrs.get("debug.trace_id.resolved_value") == "make-run-42", \
            f"got {root.attrs.get('debug.trace_id.resolved_value')!r}"
        # "make-run-42" is not valid 32-char hex → hashed fallback
        assert root.attrs.get("debug.trace_id.validation") == "hashed", \
            f"got {root.attrs.get('debug.trace_id.validation')!r}"

    def test_root_debug_parent_id_unconfigured(self, make_spans):
        """No parent_id expression → source=unconfigured."""
        root = _process_tree(make_spans)
        assert root is not None
        assert root.attrs.get("debug.parent_id.source") == "unconfigured", \
            f"got {root.attrs.get('debug.parent_id.source')!r}"

    def test_non_root_spans_lack_root_debug_attrs(self, make_spans):
        """debug.trace_id.*/debug.parent_id.* should only be on the process.tree root span."""
        root = _process_tree(make_spans)
        assert root is not None
        for s in make_spans:
            if s.span_id == root.span_id:
                continue
            assert "debug.trace_id.source" not in s.attrs, \
                f"non-root span {s.span_id} has debug.trace_id.source"
            assert "debug.parent_id.source" not in s.attrs, \
                f"non-root span {s.span_id} has debug.parent_id.source"

    def test_wire_trace_id_matches_expected_hash(self, make_spans):
        """Wire trace_id should equal sha256("make-run-42")[:16] (hashed fallback result).

        If this fails, the custom trace_id is being dropped before span creation —
        likely because SpanContext.IsValid() rejects a context with a zero parent
        SpanID. The debug provenance attrs still record the intent, but the actual
        trace on the wire is a random SDK-generated one.
        """
        expected = hashlib.sha256(b"make-run-42").hexdigest()[:32]
        ids = {s.trace_id for s in make_spans}
        assert ids == {expected}, \
            f"expected trace_id {expected}, got {ids}"


# -- Perl session --


class TestPerlSession:
    def test_span_count(self, perl_spans):
        assert len(perl_spans) >= 2, f"got {len(perl_spans)}"

    def test_process_tree_is_session_root(self, perl_spans):
        """perl rule has no custom trace_id → process.tree is a real trace root (no parent)."""
        tree = _process_tree(perl_spans)
        assert tree is not None, "no process.tree span"
        assert tree.parent_span_id == "", \
            f"process.tree should be root, got parent={tree.parent_span_id!r}"

    def test_first_exec_is_perl(self, perl_spans):
        first = _first_exec(perl_spans)
        assert first is not None, "no first exec under process.tree"
        assert first.attrs.get("process.command") == "perl"

    def test_first_exec_child_of_process_tree(self, perl_spans):
        tree = _process_tree(perl_spans)
        first = _first_exec(perl_spans)
        assert tree is not None and first is not None
        assert first.parent_span_id == tree.span_id, \
            f"first exec parent={first.parent_span_id!r}, tree={tree.span_id!r}"

    def test_single_trace_id(self, perl_spans):
        ids = set(s.trace_id for s in perl_spans)
        assert len(ids) == 1, f"found {len(ids)} traceIds: {ids}"

    def test_env_attributes(self, perl_spans):
        for s in perl_spans:
            assert s.attrs.get("job.id") == "perl-job-99", \
                f"span {s.span_id} job.id={s.attrs.get('job.id')}"
            assert s.attrs.get("job.tier") == "critical", \
                f"span {s.span_id} job.tier={s.attrs.get('job.tier')}"

    def test_perl_has_children(self, perl_spans):
        first = _first_exec(perl_spans)
        assert first is not None
        children = [s for s in perl_spans if s.parent_span_id == first.span_id]
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
    """BPF-derived attrs are required on process.exec spans (not on synthetic process.tree)."""
    exec_spans = _exec_spans(all_spans)
    required = ("process.pid", "process.parent_pid", "process.command",
                "process.duration_ns", "process.owner.uid")
    for attr in required:
        missing = [s for s in exec_spans if attr not in s.attrs]
        assert not missing, \
            f"{attr} missing on {len(missing)}/{len(exec_spans)} exec spans"


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
