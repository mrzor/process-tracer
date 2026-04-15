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

    def test_container_init_subtree_never_materializes(self, all_spans):
        """`runc run` also matches `command: runc` but its subtree (sh,
        sleep) carries no CI_* env, so the rule's Expr never resolves.
        That pending session must never become an OTEL process.tree.

        We assert this by checking that no process.tree exists with a
        service.name outside the two expected values. The context-starved
        `runc run` session either drops at session_timeout or is simply
        never materialized — both outcomes are OK; what matters is the
        absence of a spurious tree."""
        trees = [s for s in all_spans if s.name == "process.tree"]
        unexpected = [t for t in trees
                      if t.attrs.get("service.name") not in ("demo", "runtime")]
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
