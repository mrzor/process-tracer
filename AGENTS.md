# Agent Guidelines for process-tracer

## Core Principle: Be Permissive, Not Pedantic

process-tracer is interposed into **everything** — it wraps shells, CI pipelines, build
systems. It does not get to be the reason something fails. When encountering malformed,
incomplete, or nonsensical input (bad attribute expressions, empty values, weird env vars),
the correct response is:

1. Log a warning so the user knows something is off
2. Skip the bad input
3. Keep working

Never abort or return an error for something that is merely misconfigured but not
fundamentally broken. The traced command must always run.

## Docs must reflect the code

Long-form design/implementation notes live in `docs/` (see `docs/README.md`
for the index). These documents describe what the code actually does, not
what it once did or what it might become. Rules when touching them:

1. If you change behavior that a `docs/` document describes, update the
   document in the same change. A doc that contradicts the code is worse
   than no doc — it actively misleads readers.
2. If a `docs/` document references a symbol (function name, file path,
   event name, constant), verify the symbol still exists before relying on
   it; update or remove the reference if it drifted.
3. New long-form docs go in `docs/`, not the repo root. The root holds
   `README.md` (user-facing) and `AGENTS.md` (this file) only.
