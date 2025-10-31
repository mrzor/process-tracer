// Package envreassembler handles reassembly of environment variable data from eBPF events.
//
// eBPF sends environment and argument data in two ways:
//  1. Chunk-based: Large data split into multiple EnvChunkEvent messages
//  2. Streaming: Individual variables sent as EnvVarEvent messages
//
// State Machine (ChunkReassembler):
//
//	┌─────────┐
//	│  Start  │
//	└────┬────┘
//	     │
//	     │ EnvChunkEvent (IsFinal=0)
//	     ▼
//	┌──────────┐
//	│Buffering │ ◄──┐
//	└────┬─────┘    │ More chunks
//	     │          │
//	     │ EnvChunkEvent (IsFinal=1)
//	     ▼          │
//	┌──────────┐    │
//	│ Reassemble│    │
//	└────┬─────┘    │
//	     │          │
//	     ▼          │
//	┌──────────┐    │
//	│ Complete │    │
//	└──────────┘    │
//
// State Machine (StreamingReassembler):
//
//	┌─────────┐
//	│  Start  │
//	└────┬────┘
//	     │
//	     │ EnvVarEvent (IsFinal=0)
//	     ▼
//	┌───────────┐
//	│Collecting │ ◄──┐
//	└────┬──────┘    │ More variables
//	     │           │
//	     │ EnvVarEvent (IsFinal=1)
//	     ▼           │
//	┌──────────┐     │
//	│ Finalize │     │
//	└────┬─────┘     │
//	     │           │
//	     ▼           │
//	┌──────────┐     │
//	│ Complete │     │
//	└──────────┘     │
//
// Both produce ReassembledData containing:
//   - Args: []string - Command-line arguments
//   - Env: map[string]string - Environment variables
//   - Issues: []string - Warnings about truncation or missing data
package envreassembler
