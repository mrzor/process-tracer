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
