#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["pytest"]
# ///
"""Verify context-starved runc materialization traces.

Hypothesis under test: a `context_starved: true` rule matching on the
injector (`runc`) defers session materialization until a descendant's
envp resolves at least one of the rule's Expr expressions. Two injection
shapes exercise the mechanism:

  A. `runc exec -e CI_JOB_ID=42 -e CI_PROJECT_NAME=demo testctr /bin/id`
     → `id` child is immediately context-ful → materialize with
       service.name="demo", ci.job.id="42".

  B. `runc exec testctr /bin/sh -c 'export CI_PIPELINE_ID=99 CI_JOB_ID=100 \
                                     CI_PROJECT_NAME=runtime; /bin/id'`
     → `sh` child has no CI_* in execve envp (starved, buffered).
       Grandchild `id` inherits exported CI_* → materialize with
       service.name="runtime", ci.pipeline.id="99", ci.job.id="100".

We also assert `runc run` (container PID 1 subtree, no CI_* anywhere)
never produces a materialized process.tree — it stays pending-starved
and eventually times out. Absence is the positive signal here.

Run with: uv run --script verify-traces-runc-starved.py [traces.jsonl]
"""

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest


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


TRACES_PATH: Path | None = None


@pytest.fixture(scope="session")
def all_spans():
    path = TRACES_PATH or Path("staging/traces.jsonl")
    assert path.is_file() and path.stat().st_size > 0, \
        f"traces.jsonl missing or empty: {path}"
    spans = parse_traces(path)
    assert spans, "no spans in traces"
    return spans


@pytest.fixture(scope="session")
def debug_events():
    """Loads the daemon's --debug-log JSON-lines file produced by the guest
    VM. Co-located with traces.jsonl (same staging/ directory)."""
    traces_path = TRACES_PATH or Path("staging/traces.jsonl")
    debug_path = traces_path.parent / "debug.log"
    if not debug_path.is_file():
        return []
    events = []
    for line in debug_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


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


def _trees_by_service(spans, svc):
    return [s for s in spans
            if s.name == "process.tree" and s.attrs.get("service.name") == svc]


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


# -- The context-starved materialization assertions --


class TestContextStarvedMaterialization:
    """Each injection must materialize exactly one process.tree whose attrs
    come from the descendant's env, not the starved runc's."""

    def test_variant_a_immediate_child(self, all_spans):
        """Variant A: CI_* passed via `runc exec -e`. The `id` child's
        envp carries them → materialize on the first descendant exec."""
        trees = _trees_by_service(all_spans, "demo")
        assert len(trees) == 1, (
            f"expected exactly one process.tree with service.name=demo, "
            f"got {len(trees)}: "
            f"{[t.attrs.get('ci.job.id') for t in trees]}"
        )
        tree = trees[0]
        assert tree.attrs.get("ci.job.id") == "42", (
            f"ci.job.id mismatch on demo tree: {tree.attrs.get('ci.job.id')!r}"
        )

        # The `id` exec must be a descendant of this tree.
        descendants = _descendants_of(all_spans, tree)
        commands = [s.attrs.get("process.command") for s in descendants
                    if s.name == "process.exec"]
        assert "id" in commands, (
            f"variant A: /bin/id not found in demo tree descendants: {commands}"
        )

    def test_variant_b_grandchild_via_starved_shell(self, all_spans):
        """Variant B: `sh` has no CI_* in envp (starved), grandchild `id`
        inherits runtime-exported CI_* → materialize on the grandchild."""
        trees = _trees_by_service(all_spans, "runtime")
        assert len(trees) == 1, (
            f"expected exactly one process.tree with service.name=runtime, "
            f"got {len(trees)}"
        )
        tree = trees[0]
        assert tree.attrs.get("ci.pipeline.id") == "99", (
            f"ci.pipeline.id mismatch on runtime tree: "
            f"{tree.attrs.get('ci.pipeline.id')!r}"
        )
        assert tree.attrs.get("ci.job.id") == "100", (
            f"ci.job.id mismatch on runtime tree: "
            f"{tree.attrs.get('ci.job.id')!r}"
        )

        descendants = _descendants_of(all_spans, tree)
        commands = [s.attrs.get("process.command") for s in descendants
                    if s.name == "process.exec"]
        # The context-ful `id` exec must be a descendant of this tree.
        #
        # The starved `sh` *was* buffered and replayed (see daemon logs:
        # "replaying buffered descendant pid=N comm=/bin/sh") — but busybox
        # ash execs /bin/id as the last statement of `sh -c '…; /bin/id'`
        # *in-place* (no fork), so sh and id share a PID. The formatter's
        # exec-replacement handling (otel_formatter.go:238) keeps the first
        # span and finalizes it under the final comm (`id`), collapsing the
        # two execs into one span. That's desired behavior — the meaningful
        # signal for this test is that materialization *used the
        # grandchild's runtime-exported CI_* env*, which is already proven
        # by the ci.pipeline.id / ci.job.id assertions above.
        assert "id" in commands, (
            f"variant B: /bin/id grandchild not in runtime tree: {commands}"
        )

    def test_variants_a_and_b_are_separate_traces(self, all_spans):
        """Each `runc exec` invocation is its own pending-starved session,
        materialized independently → distinct trace_ids."""
        a = _trees_by_service(all_spans, "demo")[0]
        b = _trees_by_service(all_spans, "runtime")[0]
        assert a.trace_id != b.trace_id, (
            f"variant A and B share trace_id {a.trace_id} — they must be "
            f"materialized into separate traces."
        )

    def test_variant_d_detached_sleeps_visible(self, all_spans):
        """Variant D: materialise, then detach a subshell (outer-inner-
        background-exit pattern) that forks sleeps. The subshell gets
        reparented to the container's init, breaking BPF's real_parent
        chain back to the materialised session's tracked root.

        This is the intended production repro. On v0.8.4 it should fail:
        the 4 sleeps' exec events have tracked_ancestor=0 and never
        attach to the `detached` tree. If this test passes, either the
        reparenting didn't happen as expected, or BPF's fork tracking
        is more robust than the production evidence suggests — in which
        case production's failure mode is somewhere else entirely."""
        trees = _trees_by_service(all_spans, "detached")
        assert len(trees) == 1, (
            f"expected exactly one process.tree with service.name=detached, "
            f"got {len(trees)}"
        )
        tree = trees[0]
        descendants = _descendants_of(all_spans, tree)
        commands = [s.attrs.get("process.command") for s in descendants
                    if s.name == "process.exec"]
        sleep_count = sum(1 for c in commands if c == "sleep")
        assert sleep_count == 4, (
            f"variant D: expected 4 detached sleep execs in detached tree, "
            f"got {sleep_count}. commands={commands}"
        )

    def test_variant_e_fork_only_subshell_leaked(self, all_spans):
        """Variant E: the hypothesised repro for the production "where's
        my sleep?" bug. The outer sh is exec'd (so it lands in
        pending.descendants). It forks a subshell that never exec's
        anything new — that subshell pid is registered only in
        pendingStarvedByPid (via HandleStarvedDescendantFork) and is
        NOT in pending.descendants. The outer sh then triggers
        materialisation via /bin/id with CI_* in env.

        At materialisation, pending.descendants is replayed into the
        session but the subshell pid is silently dropped because it was
        only in pendingStarvedByPid. It stays in BPF tracked_pids (no
        UntrackPID call) but is invisible to Go. Its subsequent sleep
        children hit EVENT_EXEC with tracked_ancestor=0 (BPF sees the
        subshell as a directly-tracked parent) and Go's handleExec
        silently drops them as exec_unclaimed.

        Pre-materialisation sleeps forked by the subshell DO get
        buffered normally (via HandleStarvedDescendantExec's buffer
        branch) and show up in the tree. Post-materialisation sleeps
        from the same subshell are lost. The split depends on scheduling
        timing (how many sleeps the subshell manages to fork before
        /bin/id's env-stream + exec reaches materialisation); empirically
        it's 2-pre / 3-post. The invariant is that the total must be 5.
        Post-fix: all 5 in the tree. Today: fewer than 5 (the missing
        ones appear as exec_unclaimed with tracked_ancestor=0 in the
        debug log)."""
        trees = _trees_by_service(all_spans, "leaked")
        assert len(trees) == 1, (
            f"expected exactly one process.tree with service.name=leaked, "
            f"got {len(trees)}"
        )
        tree = trees[0]
        assert tree.attrs.get("ci.pipeline.id") == "555"
        assert tree.attrs.get("ci.job.id") == "666"

        descendants = _descendants_of(all_spans, tree)
        commands = [s.attrs.get("process.command") for s in descendants
                    if s.name == "process.exec"]

        sleep_count = sum(1 for c in commands if c == "sleep")
        assert sleep_count == 5, (
            f"variant E (fork-only leak): expected 5 sleep execs in leaked "
            f"tree (1 pre-materialisation sleep from the subshell that was "
            f"buffered normally + 4 post-materialisation sleeps from the "
            f"orphaned subshell). got {sleep_count}. Missing post-mat sleeps "
            f"indicate materializeStarvedLocked drops fork-only entries from "
            f"pendingStarvedByPid without adding them to pidToSession or "
            f"untracking them in BPF. commands={commands}"
        )

    def test_variant_c_materialised_and_sleeps_visible(self, all_spans):
        """Variant C: long-lived sh materialises via /bin/id, then spawns
        four /bin/sleep children. The materialised tree must include
        /bin/id AND all four sleeps.

        Intended as a regression anchor for the production bug (v0.8.4)
        where post-materialisation forks from a starved-buffered shell
        were invisible to BPF — a 60s GitLab pipeline of four sleeps
        produced zero sleep spans. The simple runc-exec container shape
        here doesn't fully reproduce that bug (production's GitLab runner
        chain is deeper and crosses more PID-namespace boundaries), but
        this test catches the basic "post-materialisation fork tracking
        works at all" invariant. A future variant with a multi-hop
        container setup should pin the production shape."""
        trees = _trees_by_service(all_spans, "longlived")
        assert len(trees) == 1, (
            f"expected exactly one process.tree with service.name=longlived, "
            f"got {len(trees)}"
        )
        tree = trees[0]
        assert tree.attrs.get("ci.pipeline.id") == "111", (
            f"ci.pipeline.id mismatch on longlived tree: "
            f"{tree.attrs.get('ci.pipeline.id')!r}"
        )
        assert tree.attrs.get("ci.job.id") == "222", (
            f"ci.job.id mismatch on longlived tree: "
            f"{tree.attrs.get('ci.job.id')!r}"
        )

        descendants = _descendants_of(all_spans, tree)
        commands = [s.attrs.get("process.command") for s in descendants
                    if s.name == "process.exec"]

        # Materialisation trigger must be visible (same shape as variant B).
        assert "id" in commands, (
            f"variant C: /bin/id trigger not in longlived tree: {commands}"
        )

        # All four sleeps must attach to the same tree. Count rather than
        # membership — losing even one means the fork-gap is partially
        # present and the bug isn't fully fixed.
        sleep_count = sum(1 for c in commands if c == "sleep")
        assert sleep_count == 4, (
            f"variant C: expected 4 sleep execs in longlived tree, "
            f"got {sleep_count}. commands={commands}"
        )

    def test_sessions_complete_before_daemon_shutdown(self, debug_events):
        """At least one materialized session must emit a `session_end`
        event with reason=completed before the daemon shuts down. This
        proves the session-completion path works: every pid the session
        tracked was accounted for and the root process.tree span closed
        naturally (as opposed to being force-closed by CloseAllSessions
        at daemon stop, which produces no session_end event at all).

        Without this, stuck sessions hold their process.tree span open
        until the daemon restarts — in production that means the
        overarching CI-job span never reaches the APM. This assertion
        is the regression guard for that class of bug."""
        if not debug_events:
            pytest.skip("debug.log not available (daemon --debug-log not enabled)")
        session_ends = [e for e in debug_events if e.get("event") == "session_end"]
        completed = [e for e in session_ends if e.get("reason") == "completed"]
        assert completed, (
            f"no session_end with reason=completed in debug.log. "
            f"All materialized sessions stayed open until daemon shutdown, "
            f"meaning session.pids never drained. Total session_end events: "
            f"{len(session_ends)} (by reason: "
            f"{sorted({e.get('reason') for e in session_ends})})."
        )

    def test_container_init_subtree_never_materializes(self, all_spans):
        """`runc run` also matches `command: runc` but its subtree (sh,
        sleep) carries no CI_* env, so the rule's Expr never resolves.
        That pending session must never become an OTEL process.tree.

        We assert this by checking that no process.tree exists with a
        service.name outside the three expected variants. The
        context-starved `runc run` session either drops at session_timeout
        or is simply never materialized — both outcomes are OK; what
        matters is the absence of a spurious tree."""
        trees = [s for s in all_spans if s.name == "process.tree"]
        unexpected = [t for t in trees
                      if t.attrs.get("service.name") not in ("demo", "runtime", "longlived", "detached", "leaked")]
        assert not unexpected, (
            f"unexpected process.tree(s) materialized: "
            f"{[(t.attrs.get('service.name'), t.attrs.get('ci.job.id')) for t in unexpected]}"
        )


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
