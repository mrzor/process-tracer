// Package output provides formatters for converting processed events into output formats.
//
// OTELFormatter is a pure formatting layer that:
//   - Receives pre-processed event data
//   - Creates OpenTelemetry spans
//   - Sets span attributes from prepared data
//
// It does NOT:
//   - Handle raw eBPF events
//   - Reassemble data chunks
//   - Evaluate expressions
//   - Manage process metadata lifecycle
//
// All data processing is delegated to specialized packages:
//   - timesync: Monotonic timestamp conversion
//   - attributes: Expression evaluation
//   - procmeta: Metadata storage and retrieval
//
// The formatter receives fully-processed data through the ProcessEventHandler
// and TCPEventHandler interfaces.
package output
