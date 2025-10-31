// Package eventprocessor coordinates event processing and routes eBPF events to specialized handlers.
//
// Architecture:
//
//	┌─────────────────────────────────────────┐
//	│      eBPF Ring Buffer Events            │
//	└─────────────────┬───────────────────────┘
//	                  │
//	                  ▼
//	┌─────────────────────────────────────────┐
//	│   eventprocessor                        │  ← Event routing
//	│   - Routes by event type                │
//	│   - Delegates to handlers                │
//	└─────────┬───────────────────────────────┘
//	          │
//	          ├──→ EnvChunkEvent ──→ envreassembler
//	          │                      - Buffers chunks
//	          │                      - Parses null-terminated strings
//	          │                      - Produces Args + Env
//	          │
//	          ├──→ EnvVarEvent ────→ envreassembler
//	          │                      - Collects streaming variables
//	          │                      - Produces Args + Env
//	          │
//	          ├──→ Reassembled ───→ procmeta.Manager
//	          │    data             - Stores metadata per PID
//	          │                      - Tracks lifecycle
//	          │
//	          ├──→ EXEC/EXIT ─────→ ProcessEventHandler
//	          │                      - Creates/finalizes spans
//	          │                      - Uses attributes evaluator
//	          │                      - Uses timesync converter
//	          │
//	          └──→ TCP events ────→ TCPEventHandler
//	                                - Creates/finalizes TCP spans
//
// The processor delegates to ProcessEventHandler and TCPEventHandler interfaces,
// typically implemented by the output formatter.
package eventprocessor
