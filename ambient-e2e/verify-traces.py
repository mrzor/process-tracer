#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["pytest"]
# ///
"""Verify OTLP trace output from the daemon mode E2E test.

The daemon-mode workload is now pipeline-shaped: three sequential `make`
invocations sharing one BUILD_ID. Each invocation produces one
`process.tree` span; all three share the same trace_id (sha256 fallback
on the non-hex BUILD_ID), so they appear as siblings under one trace.

Run with: uv run --script verify-traces.py [traces.jsonl]
Accepts pytest flags: uv run --script verify-traces.py -- -v
"""

import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest


# -- Data model --


@dataclass
class Span:
    name: str
    trace_id: str
    span_id: str
    parent_span_id: str
    start_unix_nano: int = 0
    end_unix_nano: int = 0
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
                        start_unix_nano=int(s.get("startTimeUnixNano", 0)),
                        end_unix_nano=int(s.get("endTimeUnixNano", 0)),
                        attrs=attrs,
                    ))
    return spans, resource_spans


# -- Fixtures --


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


# -- Helpers --


def _spans_by_svc(spans: list[Span], svc: str) -> list[Span]:
    return [s for s in spans if s.attrs.get("service.name") == svc]


def _exec_spans(spans: list[Span]) -> list[Span]:
    return [s for s in spans if s.name == "process.exec"]


def _trees_in_order(spans: list[Span]) -> list[Span]:
    """All process.tree spans, sorted by start time."""
    trees = [s for s in spans if s.name == "process.tree"]
    return sorted(trees, key=lambda s: s.start_unix_nano)


def _descendants_of(spans: list[Span], root: Span) -> list[Span]:
    """All spans transitively reachable from `root` via parent_span_id chains.
    Includes `root` itself."""
    by_parent: dict[str, list[Span]] = {}
    for s in spans:
        by_parent.setdefault(s.parent_span_id, []).append(s)
    out: list[Span] = [root]
    stack = [root.span_id]
    while stack:
        pid = stack.pop()
        for child in by_parent.get(pid, []):
            out.append(child)
            stack.append(child.span_id)
    return out


def _first_direct_exec(members: list[Span], tree: Span) -> Span | None:
    """First process.exec that's a direct child of `tree`."""
    children = [
        s for s in _exec_spans(members)
        if s.parent_span_id == tree.span_id
    ]
    return children[0] if children else None


@pytest.fixture(scope="session")
def make_trees(all_spans):
    """Pipeline trees in chronological order (make rule)."""
    return [
        t for t in _trees_in_order(all_spans)
        if t.attrs.get("service.name") == "ambient-e2e-make"
    ]


@pytest.fixture(scope="session")
def make_sessions(all_spans, make_trees):
    """[(tree, members)] for each make invocation, in pipeline order."""
    return [(t, _descendants_of(all_spans, t)) for t in make_trees]


@pytest.fixture(scope="session")
def make_spans(make_sessions):
    """Flat list of all spans across all make sessions."""
    out: list[Span] = []
    for _, members in make_sessions:
        out.extend(members)
    return out


@pytest.fixture(scope="session")
def perl_spans(all_spans):
    return _spans_by_svc(all_spans, "ambient-e2e-perl")


# -- Module-level invariants --


def test_span_names(all_spans):
    """Every span is either a process.tree session root or a process.exec."""
    allowed = {"process.tree", "process.exec"}
    bad = [s.name for s in all_spans if s.name not in allowed]
    assert not bad, f"unexpected span names: {bad}"


def test_process_tree_has_process_command(all_spans):
    """Every process.tree span carries process.command from the matched process metadata."""
    trees = [s for s in all_spans if s.name == "process.tree"]
    assert trees, "no process.tree spans found"
    for t in trees:
        cmd = t.attrs.get("process.command")
        assert cmd is not None, \
            f"tree {t.span_id} missing process.command"
        svc = t.attrs.get("service.name", "")
        if "make" in svc:
            assert cmd == "make", \
                f"make tree {t.span_id} process.command={cmd!r}"
        elif "perl" in svc:
            assert cmd == "perl", \
                f"perl tree {t.span_id} process.command={cmd!r}"


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


def test_unmatched_processes_not_traced(all_spans):
    """find, dd, ls, cat, wc ran in the VM but should not produce spans."""
    unmatched = ("find", "dd", "ls", "cat", "wc")
    leaked = [
        cmd for cmd in unmatched
        if any(s.attrs.get("process.command") == cmd for s in all_spans)
    ]
    assert not leaked, f"unmatched commands leaked into traces: {leaked}"


# -- No-orphan invariant (regression guard for the orphan-fallback fix) --


def test_no_orphan_spans(all_spans):
    """Every non-process.tree span's parent_span_id must resolve to some span
    in the same trace. Before the orphan-fallback fix, descendants whose ppid
    wasn't tracked silently started new one-span traces — this test would have
    flagged that regression."""
    by_id = {s.span_id: s for s in all_spans}
    for s in all_spans:
        if s.name == "process.tree":
            continue  # tree's parent is the synthetic virtual SpanID, not a real span
        parent = by_id.get(s.parent_span_id)
        assert parent is not None, (
            f"orphan: span {s.span_id} ({s.attrs.get('process.command')}) "
            f"parent_span_id {s.parent_span_id!r} not present in export"
        )
        assert parent.trace_id == s.trace_id, (
            f"cross-trace parent: span {s.span_id} in trace {s.trace_id}, "
            f"parent in trace {parent.trace_id}"
        )


def test_every_non_tree_span_has_a_tree_ancestor(all_spans):
    """Walking parent_span_id from any non-tree span must reach a process.tree."""
    by_id = {s.span_id: s for s in all_spans}
    for s in all_spans:
        if s.name == "process.tree":
            continue
        cur = s
        reached_tree = False
        for _ in range(len(all_spans) + 1):  # bounded to break cycles
            parent = by_id.get(cur.parent_span_id)
            assert parent is not None, \
                f"span {s.span_id} chain broke at {cur.span_id} " \
                f"(parent_span_id {cur.parent_span_id!r} not in export)"
            if parent.name == "process.tree":
                reached_tree = True
                break
            cur = parent
        assert reached_tree, \
            f"span {s.span_id} parent chain did not reach a process.tree (cycle?)"


# -- Pipeline shape (three make invocations sharing trace_id) --


class TestPipelineShape:
    def test_three_pipeline_steps(self, make_trees):
        assert len(make_trees) == 3, \
            f"expected 3 process.tree spans (build/test-parallel/deploy), got {len(make_trees)}"

    def test_shared_trace_id(self, make_trees):
        """All three pipeline steps share the BUILD_ID-derived trace_id."""
        ids = {t.trace_id for t in make_trees}
        assert len(ids) == 1, f"pipeline split across traces: {ids}"
        expected = hashlib.sha256(b"make-run-42").hexdigest()[:32]
        assert ids == {expected}, f"trace_id mismatch: got {ids}, expected {{{expected}}}"

    def test_distinct_tree_span_ids(self, make_trees):
        """Regression: random SpanID per session means no collision even
        when BUILD_ID (and hence trace_id) is shared. A naive sha256-derived
        SpanID would collide across all three steps."""
        ids = {t.span_id for t in make_trees}
        assert len(ids) == 3, f"process.tree spans collided on span_id: {ids}"

    def test_shared_parent_id(self, make_trees):
        """All pipeline steps share a hashed parent SpanID from CI_JOB_ID.
        sha256("make-job-1")[:8] as hex → deterministic shared parent."""
        parents = {t.parent_span_id for t in make_trees}
        assert len(parents) == 1, f"trees have different parents: {parents}"
        expected = hashlib.sha256(b"make-job-1").hexdigest()[:16]
        assert parents == {expected}, \
            f"parent_span_id mismatch: got {parents}, expected {{{expected}}}"

    def test_happens_before_across_steps(self, make_trees):
        """end(step_N) <= start(step_N+1). Hard invariant — the next `make`
        invocation only starts after the previous one exits (shell semantics)."""
        for prev, curr in zip(make_trees, make_trees[1:]):
            assert prev.end_unix_nano <= curr.start_unix_nano, (
                f"step {prev.span_id} ended {prev.end_unix_nano} but "
                f"step {curr.span_id} started {curr.start_unix_nano}"
            )

    def test_trees_are_session_roots(self, make_trees, all_spans):
        """No exported span may be a process.tree's parent (the parent is the
        synthetic virtual SpanID that doesn't exist in the export)."""
        all_ids = {s.span_id for s in all_spans}
        for tree in make_trees:
            assert tree.parent_span_id not in all_ids, \
                f"tree {tree.span_id} parented by another span: {tree.parent_span_id!r}"


# -- Per-step shape --


class TestPipelineSteps:
    """Per-step assertions, indexed by pipeline order: 0=build, 1=test-parallel, 2=deploy."""

    def test_each_first_exec_is_make(self, make_sessions):
        for idx, (tree, members) in enumerate(make_sessions):
            first = _first_direct_exec(members, tree)
            assert first is not None, f"step {idx}: no direct exec under tree"
            assert first.attrs.get("process.command") == "make", \
                f"step {idx} first exec is {first.attrs.get('process.command')}, not make"

    def test_build_step_commands(self, make_sessions):
        _, members = make_sessions[0]
        cmds = {s.attrs.get("process.command") for s in members}
        for expected in ("make", "hostname", "sleep", "uname", "touch"):
            assert expected in cmds, f"build step missing {expected!r}; got {cmds}"

    def test_test_parallel_step_has_three_sleeps(self, make_sessions):
        _, members = make_sessions[1]
        sleeps = [s for s in members if s.attrs.get("process.command") == "sleep"]
        assert len(sleeps) >= 3, \
            f"test-parallel: expected >=3 sleep spans, got {len(sleeps)}"

    def test_deploy_step_has_nested_subshell(self, make_sessions):
        """The deploy recipe runs `bash -c '...; uname -m'`. On Debian, make
        executes recipes via /bin/sh, and the comm captured at exec entry may
        be `sh` (before the sh→bash exec re-exec). Accept either as evidence
        of a sub-shell, and require `uname` as proof the inner commands ran."""
        _, members = make_sessions[2]
        cmds = {s.attrs.get("process.command") for s in members}
        assert cmds & {"bash", "sh"}, f"deploy step missing sub-shell; got {cmds}"
        assert "uname" in cmds, f"deploy step missing inner uname; got {cmds}"


# -- Parallelism within the test-parallel step --


class TestParallelism:
    """The three sleep recipes under `make test-parallel -j3` should run
    concurrently — their lifetimes must overlap (max(starts) < min(ends))."""

    def test_sleep_siblings_overlap(self, make_sessions):
        _, members = make_sessions[1]
        sleeps = [s for s in members if s.attrs.get("process.command") == "sleep"]
        assert len(sleeps) >= 3, f"need >=3 sleeps, got {len(sleeps)}"
        # Sort by start to make the failure message readable.
        sleeps = sorted(sleeps, key=lambda s: s.start_unix_nano)[:3]
        starts = [s.start_unix_nano for s in sleeps]
        ends = [s.end_unix_nano for s in sleeps]
        assert max(starts) < min(ends), (
            f"sleep spans don't overlap (not parallel): "
            f"max(starts)={max(starts)}, min(ends)={min(ends)}"
        )

    def test_sleep_durations_meet_expected(self, make_sessions):
        _, members = make_sessions[1]
        durations = [
            int(s.attrs.get("process.duration_ns", 0))
            for s in members
            if s.attrs.get("process.command") == "sleep"
        ]
        assert durations, "no sleep spans in test-parallel step"
        # Each sleep is 0.2s. Allow some slack for scheduling jitter.
        assert min(durations) >= 150_000_000, \
            f"shortest sleep was {min(durations) // 1_000_000}ms, expected >= 150ms"


# -- Cross-cutting attribute checks (apply to every make-session span) --


class TestMakeAttributes:
    def test_env_attributes(self, make_spans):
        for s in make_spans:
            assert s.attrs.get("build.id") == "make-run-42", \
                f"span {s.span_id} build.id={s.attrs.get('build.id')}"
            assert s.attrs.get("build.region") == "us-east-1", \
                f"span {s.span_id} build.region={s.attrs.get('build.region')}"

    def test_debug_argv_on_every_exec_span(self, make_spans):
        for s in _exec_spans(make_spans):
            argv = s.attrs.get("debug.argv")
            assert isinstance(argv, list) and len(argv) > 0, \
                f"span {s.span_id} ({s.attrs.get('process.command')}) missing debug.argv, got: {argv!r}"

    def test_debug_environ_contains_build_id(self, make_spans):
        for s in _exec_spans(make_spans):
            environ = s.attrs.get("debug.environ")
            assert isinstance(environ, list) and len(environ) > 0, \
                f"span {s.span_id} missing debug.environ"
            assert "BUILD_ID=make-run-42" in environ, \
                f"span {s.span_id} debug.environ missing BUILD_ID entry"

    def test_debug_argv_on_process_tree(self, make_trees):
        """process.tree spans also get debug.argv when add_debug_attributes is enabled."""
        for t in make_trees:
            argv = t.attrs.get("debug.argv")
            assert isinstance(argv, list) and len(argv) > 0, \
                f"tree {t.span_id} missing debug.argv, got: {argv!r}"

    def test_debug_environ_on_process_tree(self, make_trees):
        """process.tree spans also get debug.environ when add_debug_attributes is enabled."""
        for t in make_trees:
            environ = t.attrs.get("debug.environ")
            assert isinstance(environ, list) and len(environ) > 0, \
                f"tree {t.span_id} missing debug.environ, got: {environ!r}"
            assert "BUILD_ID=make-run-42" in environ, \
                f"tree {t.span_id} debug.environ missing BUILD_ID entry"


class TestArgvContent:
    """Verify that debug.argv captures the full argument vector, not just
    the command name. Each assertion checks that known multi-arg invocations
    carry the right elements in the right order."""

    def test_build_make_argv(self, make_sessions):
        """First exec of the build step is 'make -f /tmp/Makefile.pipeline build'."""
        tree, members = make_sessions[0]
        first = _first_direct_exec(members, tree)
        assert first is not None
        argv = first.attrs.get("debug.argv")
        assert argv == ["make", "-f", "/tmp/Makefile.pipeline", "build"], \
            f"build step make argv mismatch: {argv!r}"

    def test_test_parallel_make_argv(self, make_sessions):
        """First exec of the test-parallel step is 'make -f /tmp/Makefile.pipeline test-parallel -j3'."""
        tree, members = make_sessions[1]
        first = _first_direct_exec(members, tree)
        assert first is not None
        argv = first.attrs.get("debug.argv")
        assert argv == ["make", "-f", "/tmp/Makefile.pipeline", "test-parallel", "-j3"], \
            f"test-parallel step make argv mismatch: {argv!r}"

    def test_deploy_make_argv(self, make_sessions):
        """First exec of the deploy step is 'make -f /tmp/Makefile.pipeline deploy'."""
        tree, members = make_sessions[2]
        first = _first_direct_exec(members, tree)
        assert first is not None
        argv = first.attrs.get("debug.argv")
        assert argv == ["make", "-f", "/tmp/Makefile.pipeline", "deploy"], \
            f"deploy step make argv mismatch: {argv!r}"

    def test_touch_multi_arg(self, make_sessions):
        """touch in the build step has 5 argv elements (command + 4 file paths)."""
        _, members = make_sessions[0]
        touch_spans = [s for s in _exec_spans(members)
                       if s.attrs.get("process.command") == "touch"]
        assert touch_spans, "no touch span in build step"
        argv = touch_spans[0].attrs.get("debug.argv")
        assert argv == ["touch", "/tmp/e2e-a", "/tmp/e2e-b", "/tmp/e2e-c", "/tmp/e2e-d"], \
            f"touch argv mismatch: {argv!r}"

    def test_sleep_argv(self, make_sessions):
        """Every sleep span carries argv=['sleep', '<duration>']."""
        for _, members in make_sessions:
            for s in _exec_spans(members):
                if s.attrs.get("process.command") != "sleep":
                    continue
                argv = s.attrs.get("debug.argv")
                assert isinstance(argv, list) and len(argv) == 2, \
                    f"sleep argv should be 2 elements, got: {argv!r}"
                assert argv[0] == "sleep", f"sleep argv[0]={argv[0]!r}"
                # Duration is either "0.2" (parallel tasks) or "0.05" (build/deploy).
                assert argv[1] in ("0.2", "0.05"), \
                    f"sleep argv[1]={argv[1]!r}, expected '0.2' or '0.05'"

    def test_uname_argv(self, make_sessions):
        """uname spans carry argv=['uname', '-r'] or ['uname', '-m']."""
        uname_spans = []
        for _, members in make_sessions:
            uname_spans.extend(
                s for s in _exec_spans(members)
                if s.attrs.get("process.command") == "uname"
            )
        assert uname_spans, "no uname spans found"
        for s in uname_spans:
            argv = s.attrs.get("debug.argv")
            assert isinstance(argv, list) and len(argv) == 2, \
                f"uname argv should be 2 elements, got: {argv!r}"
            assert argv[0] == "uname", f"uname argv[0]={argv[0]!r}"
            assert argv[1] in ("-r", "-m"), f"uname argv[1]={argv[1]!r}"


class TestMakeRootDebugProvenance:
    """Each pipeline step's process.tree gets the trace_id/parent_id provenance
    debug attrs. These should *not* leak onto descendant spans."""

    def test_each_tree_has_expected_provenance(self, make_trees):
        for tree in make_trees:
            assert tree.attrs.get("debug.trace_id.source") == "expr", \
                f"tree {tree.span_id} debug.trace_id.source={tree.attrs.get('debug.trace_id.source')!r}"
            assert tree.attrs.get("debug.trace_id.expression") == 'env["BUILD_ID"]', \
                f"tree {tree.span_id} debug.trace_id.expression={tree.attrs.get('debug.trace_id.expression')!r}"
            assert tree.attrs.get("debug.trace_id.resolved_value") == "make-run-42", \
                f"tree {tree.span_id} debug.trace_id.resolved_value={tree.attrs.get('debug.trace_id.resolved_value')!r}"
            # "make-run-42" is not valid 32-char hex → hashed fallback.
            assert tree.attrs.get("debug.trace_id.validation") == "hashed", \
                f"tree {tree.span_id} debug.trace_id.validation={tree.attrs.get('debug.trace_id.validation')!r}"
            assert tree.attrs.get("debug.parent_id.source") == "expr", \
                f"tree {tree.span_id} debug.parent_id.source={tree.attrs.get('debug.parent_id.source')!r}"
            assert tree.attrs.get("debug.parent_id.expression") == 'env["CI_JOB_ID"]', \
                f"tree {tree.span_id} debug.parent_id.expression={tree.attrs.get('debug.parent_id.expression')!r}"
            assert tree.attrs.get("debug.parent_id.resolved_value") == "make-job-1", \
                f"tree {tree.span_id} debug.parent_id.resolved_value={tree.attrs.get('debug.parent_id.resolved_value')!r}"
            # "make-job-1" is not valid 16-char hex → hashed fallback.
            assert tree.attrs.get("debug.parent_id.validation") == "hashed", \
                f"tree {tree.span_id} debug.parent_id.validation={tree.attrs.get('debug.parent_id.validation')!r}"

    def test_non_root_spans_lack_root_debug_attrs(self, make_spans, make_trees):
        tree_ids = {t.span_id for t in make_trees}
        for s in make_spans:
            if s.span_id in tree_ids:
                continue
            assert "debug.trace_id.source" not in s.attrs, \
                f"non-root span {s.span_id} has debug.trace_id.source"
            assert "debug.parent_id.source" not in s.attrs, \
                f"non-root span {s.span_id} has debug.parent_id.source"


# -- Perl session (single invocation, different rule, different trace_id) --


class TestPerlSession:
    def test_span_count(self, perl_spans):
        assert len(perl_spans) >= 2, f"got {len(perl_spans)}"

    def test_process_tree_is_session_root(self, perl_spans):
        """perl rule has no custom trace_id → process.tree is a real trace root (no parent)."""
        trees = [s for s in perl_spans if s.name == "process.tree"]
        assert len(trees) == 1, f"expected 1 perl tree, got {len(trees)}"
        assert trees[0].parent_span_id == "", \
            f"process.tree should be root, got parent={trees[0].parent_span_id!r}"

    def test_first_exec_is_perl(self, perl_spans):
        trees = [s for s in perl_spans if s.name == "process.tree"]
        tree = trees[0]
        first = _first_direct_exec(perl_spans, tree)
        assert first is not None, "no first exec under perl tree"
        assert first.attrs.get("process.command") == "perl"

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
        trees = [s for s in perl_spans if s.name == "process.tree"]
        first = _first_direct_exec(perl_spans, trees[0])
        assert first is not None
        children = [s for s in perl_spans if s.parent_span_id == first.span_id]
        assert len(children) >= 1, "no child spans"

    def test_no_debug_attrs_on_unenabled_rule(self, perl_spans):
        """e2e-perl rule does NOT set add_debug_attributes — debug.* must be absent."""
        for s in perl_spans:
            leaked = [k for k in s.attrs if k.startswith("debug.")]
            assert not leaked, \
                f"span {s.span_id} (perl rule) leaked debug attrs: {leaked}"


# -- Cross-rule --


def test_make_and_perl_have_different_trace_ids(make_trees, perl_spans):
    make_ids = {t.trace_id for t in make_trees}
    perl_ids = {s.trace_id for s in perl_spans}
    assert make_ids and perl_ids, "one or both rule outputs empty"
    assert make_ids.isdisjoint(perl_ids), \
        f"rules share traceIds: {make_ids & perl_ids}"


# -- Entry point --


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
