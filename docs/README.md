# Implementation notes

Long-form documentation for non-obvious implementation choices that outlive a
single PR description.

- [context-starved-materialization.md](context-starved-materialization.md) —
  Why some ambient rules defer session creation, how the gate decides when
  to materialize, and the empty-expr safety net for trace IDs.
- [env-streaming.md](env-streaming.md) — How environment variables are
  streamed out of the BPF program (tail-calls + per-var events) to overcome
  the eBPF verifier's loop-unrolling limits.

These documents describe what the code *actually* does. See `AGENTS.md` for
the rule on keeping them in sync with the implementation.
