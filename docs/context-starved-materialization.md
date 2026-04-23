# Context-starved rules and late materialization

## The problem this solves

process-tracer's ambient mode watches for processes whose `comm` matches a
rule, reads their env at exec time, and opens an OTEL session keyed on values
derived from that env (attributes, and — critically — `trace_id` and
`parent_id`). For most rules this works at the first exec we see: the
process already carries the correlation keys we care about.

But some injectors are *context-starved*. The most common case in production
is GitLab Runner's `runc exec` / `docker exec`: the host-side injector
(`runc` / `docker`) that wraps the container step script has almost none of
the CI environment variables. Those variables live inside the container,
several exec hops deeper. If we key a session on the injector's env, the
`trace_id` expression (e.g. `expr:env["CI_PIPELINE_ID"]`) resolves to `""`,
and every pipeline collapses onto the same trace because `sha256("")` is a
fixed, well-known string. That poisoning is the failure mode this whole
machinery exists to prevent.

## The two layers of defense

1. **Late materialization (the gate).** When a rule is marked
   `context_starved: true`, matching the rule at EXEC_CANDIDATE time doesn't
   create an OTEL session. It creates a *pending* session that watches the
   injector's descendants. Each descendant exec is evaluated against a gate;
   the first descendant whose metadata is "ready enough" promotes the
   pending session into a real one (materialization). Earlier descendants
   are buffered and replayed onto the newly-created session so their
   `process.exec` spans aren't lost.

2. **Empty-expr safety net.** At trace-id resolution time, if an `expr:`
   trace_id evaluates to the empty string, we do *not* hash it to the
   `sha256("")` poison value. Instead we generate a random trace ID and
   attach warning attributes (`_trace_id_empty_expr_warning`,
   `_trace_id_source_expr`) so the resulting orphan trace is greppable.
   Literal empty `trace_id`s — a direct rule-author choice — still take the
   old hashing path.

Both layers are load-bearing. The gate prevents the bad case for
`context_starved` rules. The safety net contains the damage for non-starved
rules, for `context_starved` rules whose gate is bypassed by
misconfiguration, and for any future path that reaches trace-id resolution
with a well-formed-but-empty expr result.

## The gate in detail

Implemented in `internal/ambient/manager_starved.go` as
`pendingStarvedSession.materializationReady(meta)`.

```
if rule.TraceID is expr-configured:
    materialize iff rule.TraceID expression resolves non-empty on meta
else:
    materialize iff at least one expr-backed attribute resolves non-empty on meta
```

Rationale:

- **Trace_id is the correlation key.** If the trace is keyed on an env
  expression, that expression is the *ground truth* for "is this descendant
  the one carrying real context yet?" There is no point widening the check
  to other signals when trace_id itself is what we're waiting on — widening
  only risks materializing too early.
- **Literal attributes are ignored.** A rule that declares
  `service.name: "gitlab"` has a literal, and literals always resolve
  non-empty. If the gate counted literals, the first descendant with any
  env at all would flip it — defeating the whole point of waiting. Only
  `expr:`-backed attributes (which can produce `""` against an unready env)
  carry signal.
- **Attribute fallback exists for rules without an expr trace_id.** If the
  rule's trace_id is literal or unconfigured, the trace-id's correctness
  doesn't depend on env readiness. In that case, any expr-backed attribute
  resolving non-empty is a reasonable readiness proxy and the caller's
  declared notion of "context-ful."
- **Rules with neither an expr trace_id nor any expr attribute have a dead
  gate.** `CreatePendingStarved` logs a warning at rule-load time. That
  configuration is almost certainly a mistake: `context_starved` is
  providing no wait semantics, but also the rule's trace grouping is
  env-independent anyway, so the rule author probably didn't need
  `context_starved` in the first place.

## Lifecycle of a pending starved session

```
┌─────────────────────────────────────────────────────────────┐
│ EXEC_CANDIDATE: injector exec (e.g. `runc exec`) matches a  │
│ context_starved rule.                                       │
│                                                             │
│ CreatePendingStarved — stash rootPid, rule, rootMeta.       │
│ pendingStarvedByPid[rootPid] = rootPid                      │
│ Kernel: TrackPID(rootPid) so descendants tag as EXEC (not   │
│ EXEC_CANDIDATE).                                            │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Descendant EXEC arrives:                                    │
│ HandleStarvedDescendantExec(pid, ppid, metadata)            │
│                                                             │
│ if materializationReady(metadata):                          │
│     → materializeStarvedLocked                              │
│ else:                                                       │
│     buffer descendant; pendingStarvedByPid[pid] = root      │
│     (so this descendant's own children also route here)     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ materializeStarvedLocked:                                   │
│  - merge metadata: args from injector, env from triggering  │
│    descendant (so process.command on the tree root shows    │
│    the injector, but trace_id resolves against real env)    │
│  - createSessionLocked — now a real TraceSession exists     │
│  - replay every buffered descendant onto the session in     │
│    execve order (AddDescendant + HandleProcessExec)         │
│  - clear pendingStarved + pendingStarvedByPid               │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ OR: timeout / drop path                                     │
│                                                             │
│ cleanupStalePendingStarvedLocked runs periodically; any     │
│ pending whose age exceeds SessionTimeout is dropped via     │
│ dropPendingStarvedLocked — buffered descendants discarded,  │
│ BPF tracking removed. A `starved_drop` debuglog event is    │
│ emitted.                                                    │
└─────────────────────────────────────────────────────────────┘
```

## Fork handling

`HandleStarvedDescendantFork(childPid, parentPid)`: when a process inside a
pending chain forks, the child is mapped to the same pending root *without*
buffering the fork itself — fork events aren't replayed. Only the eventual
exec event is. This matches how regular sessions treat fork: the BPF side
tracks the PID; Go emits a `process.exec` span at exec.

## Metadata merge

`mergeMetadataForMaterialization` combines:
- **Args** from the injector (so the `process.command` on the tree root
  reflects `runc exec ...`, which is what a human operator expects to see).
- **Environ** from the context-ful descendant (so the rule's expressions
  resolve against real CI env rather than the nearly-empty injector env).

## Safety net in detail

Implemented in `internal/attributes/traceid.go`
(`EvaluateAndValidate` + `randomTraceIDForEmptyExpr`).

Triggers when:
- The trace_id is expr-backed (`e.program != nil`), and
- The expression ran without error but produced `""`.

Behavior:
- A fresh 16-byte random trace ID is generated via `crypto/rand`.
- `TraceIDResolution.Validation = ValidationEmptyFallback` — distinguishable
  from `ValidationHashed`, `ValidationValid`, and `ValidationError` in
  debug logs.
- Two warning attributes are attached to the resulting span:
  - `_trace_id_empty_expr_warning` — human-readable explanation.
  - `_trace_id_source_expr` — the raw expr body, for greppability across
    misconfigured rules.

What this *doesn't* do: it does not make the trace correlated across the
pipeline. Each session that hits the fallback gets its own random trace. The
point is to make the misconfiguration **visible** (orphan traces with
warning attrs) rather than **invisible** (all sessions silently welded onto
one poisoned mega-trace).

## Diagnostic events

With `--debug-log=<path>` set, the following events specifically illuminate
this code path (see also `debuglog` package for the full catalog):

- `session_start` with `candidate_path: "starved_pending"` — pending
  session created. Enriched fields when debuglog is enabled:
  `injector_env_key_count`, `injector_attr_nonempty` (which literals /
  exprs already resolve against the injector itself).
- `starved_buffer` — a descendant arrived but failed the gate and was
  buffered. Includes `comm`, `attr_resolved` (all attributes, including
  empties), `env_key_count` — so you can see *why* the gate held and what
  process was doing the failing exec.
- `starved_env_probe` — one event per materialization, at the moment the
  gate flipped. Includes `trigger_comm`, `trace_id_expr_source`,
  `trace_id_resolved_value_len`, `env_key_count`, `env_keys_prefix_ci`,
  `attr_nonempty`. This is the single most useful event for answering "did
  the trace_id actually resolve to something useful?"
- `starved_materialize` — session successfully materialized;
  `buffered_descendants` tells you how many got replayed.
- `descendant_join` — regular exec/fork attaching to a live session.
  Fields include `comm` and `via` (`"exec"`, `"fork"`, or
  `"starved_replay"`). Grep by `comm` to confirm a specific process
  actually joined a session.
- `ancestor_weld` — exec/fork whose immediate parent isn't in a session,
  but BPF's `TrackedAncestor` points at one. Includes `comm`.
- `weld_fail` — same setup as `ancestor_weld` but attaching to the
  ancestor's session failed (limits hit). Includes `comm`.
- `exec_unclaimed` — exec event that no session / pending-starved /
  tracked-ancestor claimed. Previously a silent drop. Includes `comm` and
  `tracked_ancestor` (0 when absent). Use to rule out "the process never
  reached any session" vs "it joined but the span silently failed."
- `session_exec_error` — `HandleProcessExec` returned an error after the
  PID was attached. Separates "joined but span emit failed" from the
  other theories.
- `starved_drop` — pending session timed out without ever flipping the
  gate. `buffered_descendants` and `pending_age_ms` quantify the loss.
- `session_dump` / `pending_starved_dump` — emitted once per active
  session at daemon shutdown. `session_dump` includes `pid_count` and
  `pids_by_cmd` (a histogram of `argv[0]` across the session's PIDs) so
  you can answer "did process X ever belong to any session?" from the
  log alone.

## Known limits and edge cases

- **No retry after materialization.** Once a session is created, its
  `trace_id` is final. If a deeper descendant later would have produced a
  better trace_id, we don't re-key. This is a deliberate trade — session
  identity must be stable for span parenting to work.
- **No cross-daemon memory.** Pending state lives in-process. A daemon
  restart loses all pending-starved state; ongoing pipelines may see a
  jarring switch from "pre-restart trace_id" to "post-restart trace_id"
  even though nothing changed in the pipeline.
- **Buffered descendants cost memory.** A pending session that never
  materializes still accumulates descendants until `SessionTimeout`.
  `MaxConcurrentSessions` counts pending-starved entries, so the usual
  limit applies.

## End-to-end regression tests

`./ambient-e2e/run-test.sh --mode=runc-starved` exercises three variants:

- **A** — `runc exec -e CI_*=... /bin/id`. Immediate-child descendant
  carries CI env. Tests "materialise on first context-ful exec."
- **B** — `runc exec ... sh -c 'export CI_*; /bin/id'`. Starved sh,
  grandchild `id` materialises via inherited env. Tests "buffer → replay."
- **C** — `runc exec ... sh -c 'export CI_*; /bin/id; sleep×4'`.
  Long-lived sh materialises and then continues forking sleep children.
  Regression test for the "post-materialisation forks are lost" bug seen
  in production (all four sleeps must show up in the tree).

The same run emits the daemon's `--debug-log` JSON-lines to
`staging/debug.log` via a serial-console bridge, so failures can be
diagnosed with the same `jq` queries used in production captures.

## References in code

- `internal/ambient/manager_starved.go` — pending lifecycle, gate,
  materialization, drop.
- `internal/ambient/processor.go` —
  `handleExec` → `HandleStarvedDescendantExec`,
  `handleFork` → `HandleStarvedDescendantFork`.
- `internal/attributes/traceid.go` — `EvaluateAndValidate` + empty-fallback.
- `internal/attributes/evaluator.go` — `HasExprAttributes`,
  `AnyExprAttributeNonEmpty`.
- `internal/debuglog/` — structured diagnostic sink the events above use.
