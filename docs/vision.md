# Vision: from per-process spans to holistic CI performance debugging

> **Document status.** Forward-looking design note, not a description of
> what the code does today. The other docs in this directory document the
> implementation; this one describes where we're heading and why. Update
> when the direction changes; expect the implementation docs to catch up
> piecemeal.

## What this tool is becoming

The original spec was naive: *one process = one context = one span.* That
shape worked while we were proving the eBPF capture worked. It is no
longer the right framing.

What process-tracer actually is, today: an eBPF-driven recorder of CI
process trees, configurable enough to attach external trace context
(GitLab pipeline IDs, job IDs) and emit OTEL traces that an APM can
ingest. What it's *becoming*: a programmable trace transformer whose
core job is to turn an exhaustive, low-level event stream into a curated,
actionable trace that answers — for the operator looking at a 12-minute
CI pipeline two hours after it ran — *where did the time actually go?*

Three properties of the data we produce, each tensioned against the
others:

- **Exhaustive.** We capture every exec, every fork, every exit. Already
  largely done. This is non-negotiable: the value of post-hoc analysis
  collapses if data is missing.
- **Not overwhelming.** A pipeline that forks 5,000 trivial helpers
  should not emit 5,000 spans the operator has to scroll past. Today it
  does.
- **Actionable.** Spans must carry names and attributes that mean
  something to the operator. `process.exec` and `process.tree` are
  technically accurate and operationally useless. Today they're
  hardcoded.

These three properties are A, B, and C in the rest of this document, in
priority order.

The design implication: we are *not* a live-monitor tool. CI has other
channels for real-time progress feedback. We can be late, we can buffer,
we can defer reification — what we cannot do is arrive with the wrong
shape of data after the run is done.

## Domain shape: facts and reification

### Facts as the unit of data

Every observation we make is a *fact*: a timestamped, attributable
record of something that happened. `clone(parent=X, child=Y)` is a fact.
`exec(pid=X, args=[...], env={...})` is a fact. `rule R matched pid P`
is a fact. A future uprobe firing inside runc with an OCI image
reference would be a fact.

Facts have two properties that matter:

1. **They arrive out of order.** Cross-CPU eBPF events race; procmeta
   fetches are async; env chunks reassemble over time; late context
   (today's context-starved-materialization, future uprobe-derived
   image refs) arrives long after the process tree has started.
2. **They accumulate over time for the same subject.** The fact set
   about pid X grows as we learn more — args, env, exit code, parent
   relationships. Not strictly append-only — procmeta is patched as env
   chunks land — but additive in spirit: we never *un-know* something.

The codebase already operates this way; it just doesn't say so.
`procmeta.Manager`, `SessionManager.pidToSession`, and
`pendingStarvedSession.descendants` are three implicit fact stores
serving slightly different purposes. The vision is not to add a fourth
parallel store but to recognize what they collectively are and design
the rest of the system around the shape we already have.

### Spans are a reified view, not the storage model

A span, in the OTEL sense, is what we *show* to the APM. It is not what
we *know*. The job of producing spans from facts — *reification* —
answers two questions:

- **What spans exist.** Today: one `process.exec` per pid, one
  `process.tree` per session. Configurably: drop trivial spans, merge
  repetitive sibling chains, possibly split or relabel.
- **When to emit them.** Today: at exit (process.exec), at session
  end (process.tree). Configurably: at end-of-merge-window, after a
  late-context fact arrives, after a quiescence threshold.

Reification is the layer where user configuration meets the fact stream.
It is the only place expressions execute. Everything below it
(eBPF capture, fact storage, late-context attachment) is mechanical.

### Why this framing is useful even where it leaks

Calling our state "facts" is partially aspirational. Procmeta is mutable.
"Append-only" is too strong a claim. The framing is still useful
because it names what the system *should* converge toward and makes the
out-of-order property a design feature instead of an implementation
nuisance. We will not enforce immutability dogmatically; we will use
the framing as a north star and accept exceptions where the cost of
purity exceeds its benefit.

## The three problems driving the next phase

### A. Span name (operation.name) — highest priority

Hardcoded `process.exec` and `process.tree` are operationally
worthless. APMs aggregate metrics by span name; today every duration
histogram collapses into one bucket. The fix is a per-rule expr that
produces the span name at end-of-span, evaluated against the same
input view as the cached attribute evaluation.

`service.name` is already expr-driven via the per-rule cached
attribute evaluation we shipped this week — no new mechanism needed.
Span name is the missing axis.

A is the highest-leverage change in this document because it unlocks
APM-side queryability. Until A ships, B's "average duration is
meaningless" complaint is a symptom; A largely cures it.

### B. Curating the trace — drop and merge

Even with good span names, a single CI job can produce thousands of
spans, most carrying no useful signal. Two parallel reification actions
address this:

- **Drop.** A predicate over the assembled span data; matching spans
  never reach the OTEL SDK. Cheapest. Loses duration accounting for
  dropped subtrees but that is the operator's explicit choice.
- **Merge.** A sibling-grouping rule. Spans matching the predicate get
  buffered under their common parent and reified as one merged span
  with count and aggregate duration. Preserves histograms.
  Implementation cost is real: requires holding siblings until the
  merge window closes (typically: parent process exit).

Both are opt-in per rule. Default behavior remains "emit every span as
its own OTEL span." An operator who configures neither gets today's
behavior.

Span-as-metric (emit duration to a histogram instead of a span) is a
**non-goal** for this phase. It's a different axis with its own ingest
costs and tooling implications.

### C. External context — pending feasibility

The last fix made attributes tree-scope, evaluated once at session
materialization. That's correct as far as it goes. It still misses
context that lives *outside* the process tree we observe:

- The OCI image reference behind a runc bundle (today: opaque hashed
  bundle ID, no operator value).
- The k8s pod / namespace / container metadata behind a cgroup.
- Workload identity from systemd-run, runner-side metadata, anything
  that an operator would mentally use to *name* a chunk of execution.

C is not postponed indefinitely; it is *pending feasibility*. A runc
uprobe to capture image refs is non-trivial (kernel/runc API
volatility; uprobe lifecycle vs. runc binary churn). Cgroup-based k8s
correlation is more tractable but still real engineering. We will not
design the C abstraction in detail until at least one concrete
late-context source is implementable.

What the architecture must preserve, even before C ships: reification
must be able to read from a fact-book that continues to accumulate
*after* `StartSession`. The current "evaluate once at StartSession,
freeze the result" pattern is fine for A and B but is the wrong shape
for C. The reifier extraction (next section) leaves room for the
fact-book to grow late without requiring re-architecture.

## How the code gets there

### Step 1: extract the reifier

The smallest move that earns its place: pull the "given facts, produce
spans" logic out of `otel_formatter.go` into a named component — a
per-session reifier — that owns the fact-book and the OTEL SDK call
sites. The formatter becomes a fact-recorder. v1 reifier behavior is
exactly current behavior; no user-visible change.

This is bigger than a 60-line patch (estimated ~200-400 lines moved or
restructured). It's justified now because:

- Merge (B) requires buffering siblings before deciding what to emit.
  The current eager-emit-at-exit flow cannot host that without
  contortion.
- A's name expr needs a typed input that includes accumulated facts,
  not whatever the formatter happens to expose.
- C's late-context attachment needs a hook between fact accumulation
  and OTEL emission. Step 1 creates that hook.

It is *not* justified by speculative future flexibility. If merge were
out of scope and C were truly indefinite, A and drop would ship
in-place and we'd skip this. Both are true here.

The reifier should not become a god-object. Likely internal split:

- **Fact-aggregator.** Owns buffering and eviction. Knows when a
  span's facts are "complete enough" to reify.
- **Span-shaper.** Owns expr evaluation (name, drop, merge predicates),
  attribute composition, OTEL SDK invocation.

The boundary may shift as we implement; the principle is to keep
*when* reification happens separate from *what* the reified span
looks like.

### Step 2: A — operation.name expr

Add `name:` to the rule schema. Compile at config load against a
documented input schema. Evaluate at end-of-span in the span-shaper
before SDK emission. Same treatment for tcp.connect spans.

### Step 3: B — drop and merge

Drop ships first as the cheaper path: a predicate evaluated at the same
point as `name`, returning a "drop" verdict that bypasses emission.
Merge ships second and adds the sibling-buffering logic to the
fact-aggregator. Group key and merge predicate are exprs; merged-span
attributes are derived (count, aggregate duration, first-seen
exemplar).

### Step 4: C — when feasibility allows

Defer until one concrete late-context source is implementable. The
reifier and its fact-book are in place from step 1; C's incremental
work is the side-channel capture (uprobe / procfs / etc.) and the
fact-book accumulation rules for late facts, not architectural
surgery.

## Operating principles

- **Pure expressions; harness owns mutation.** Each expr takes a typed
  input and returns a value. State changes happen in the harness when
  it applies the return value. No side-effecting expr.
- **Document inputs before adding functions.** Each new expr surface
  (name, drop, merge key, future C) requires a written input schema
  before any function additions are considered. The user's point 7
  in the conversation that produced this doc is binding here.
- **Don't preemptively refactor.** Step 1 is justified by B and C
  *together*; if either disappears, revisit.
- **Curated emission over eager streaming.** Reification can defer
  arbitrarily within a session's lifetime. Operators who want live
  feedback have other tools.
- **Combinatorial test burden is the cost of doing this well.**
  Configurable name × drop × merge × out-of-order arrival × late
  context produces a test surface that benefits from property-based
  testing. We accept this.

## Non-goals

- Span-as-metric emission.
- Turing-complete or side-effecting expressions.
- An open-ended function library — extensions follow input schemas.
- Updating or rewriting already-emitted spans.
- Live-monitor performance characteristics or guarantees.
- Generalizing to non-CI workloads before we have a second concrete
  workload to validate against.

## Open questions

These are acknowledged, not answered:

- **Reification timing.** Which set of triggers — at-exit, at-session-end,
  at-merge-window-close, on-late-fact — and how do they interact when
  multiple rules apply?
- **Memory bounds.** How long do unreified facts live? Worst case for a
  long-running pipeline with merge windows that don't close cleanly.
- **Parent-link timing.** Today's `f.spans[ppid]` lookup at child exec
  works because parent's span exists eagerly. Deferred reification
  forces a choice: pre-allocate span IDs at exec, or use internal fact-
  cluster IDs and resolve to OTEL contexts at reification time.
- **Procmeta's mutable accumulation.** It's the largest existing
  exception to "facts are append-only." Reconcile or carve out
  explicitly?
- **Three implicit fact stores.** Consolidate into the reifier's
  fact-book, or keep separate with documented purposes? Migration cost
  vs. coherence benefit.

## Lexicon

Used precisely throughout this document; the implementation should
adopt the same vocabulary as the abstractions land.

- **Fact.** A timestamped, attributable record of something we
  observed. Examples: a `clone` event, an `exec` with args/env, a
  procmeta entry, a rule match, a future uprobe-derived OCI image
  reference. Facts arrive out of order and accumulate over time for
  the same subject.
- **Subject.** What a fact is about — typically a pid, sometimes a
  session, a connection, or a container.
- **Fact-book.** The per-session collection of facts. Today implicit,
  spread across `procmeta.Manager`, `SessionManager.pidToSession`, and
  `pendingStarvedSession.descendants`; intended to become a single
  named structure owned by the reifier.
- **Reify / reification.** Producing a span (or zero spans, or a
  merged span) from a set of facts. Answers two questions: which
  spans exist, and at what point in time they exist as span objects.
- **Emit / emission.** Handing a finished span to the OTEL SDK.
  Distinct from reification: a span object can be reified and held
  briefly before emission (e.g., during a merge window). Once
  emitted, it is out of our hands.
- **Reifier.** The named component that performs reification. Owns
  the fact-book and the OTEL SDK call sites for one session.
  Internally split into:
  - **Fact-aggregator.** Holds facts, evicts when allowed, decides
    when a span's facts are complete enough to reify.
  - **Span-shaper.** Evaluates exprs, composes attributes, calls the
    OTEL SDK to materialize and emit the span.
- **Session.** Existing code term. The tracking context for one
  process tree (a root and its descendants), bracketed by a rule
  match and the root's exit (or a timeout).
- **Rule.** Existing code term. A config-level matcher carrying
  `match`, `trace_id`, `attributes`, and (post-this-vision) `name`,
  drop, and merge expressions.
- **Expr.** A compiled expression in the tool's small DSL. Pure: takes
  an *input view*, returns a value. No side effects.
- **Input view.** The typed input passed to an expr at evaluation
  time. Each expr surface (attribute, name, drop, merge key) has its
  own documented input schema.
- **Predicate.** An expr that returns a boolean — used for drop and
  merge inclusion. Returns a *verdict* the harness acts on.
- **Cached evaluation.** An expr that runs once at a defined moment;
  the result is stored and reused for the life of the session
  (today: rule attributes evaluated at session start, reused on every
  span). Not invalidated, not recomputed — strictly one-shot.
- **Harness.** The Go code surrounding expr evaluation; receives the
  expr's return value and acts on it. Mutation lives here, never in
  expr.
- **Tree-scope.** Applies uniformly to every span in one process tree
  (= one session). Attributes are tree-scope by design.
- **Late context.** A fact that arrives after the session has started,
  possibly after some of its spans have already been reified.
  Distinct from *context-starved*, which describes a session that
  hasn't matched its rule yet.
- **Merge window.** The period during which sibling facts matching a
  merge predicate are buffered before being reified into a single
  merged span. Closes on a defined event (typically: the parent
  process's exit).

## What this document is not

It is not a spec. It is not a commitment to ship A, B, and C on a
timeline. It does not authorize a refactor by virtue of existing. It
records what we currently believe the right shape is, so the next
contributor (or the next conversation) does not start from the
"one process = one span" frame the codebase has already outgrown.
