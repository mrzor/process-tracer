// Package bpf provides Go bindings for the eBPF process tracer.
package bpf

import (
	"unsafe"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 processTracer ./process_tracer.bpf.c -- -I. -I/usr/include

// Event type constants matching kernel/C conventions.
//
//nolint:revive,staticcheck // ALL_CAPS naming matches C/kernel conventions
const (
	EVENT_EXEC           = 1
	EVENT_EXIT           = 2
	EVENT_TCP_CONNECT    = 3
	EVENT_TCP_CLOSE      = 4
	EVENT_EXEC_ENV_CHUNK = 5
	EVENT_ENV_VAR        = 6
)

// Event matches the C struct from process_tracer.h.
// Using explicit struct layout to match C union.
type Event struct {
	Pid       uint32
	Ppid      uint32
	Uid       uint32 //nolint:revive // Matches kernel struct field naming
	Pad1      uint32 // Padding before timestamp to maintain 8-byte alignment
	Timestamp uint64
	Type      uint8
	Pad2      [7]byte // Padding to align Data field
	Data      EventData
}

// EventData is a union type matching the C union.
type EventData struct {
	// This will overlay both process and TCP data
	// The actual interpretation depends on Event.Type
	Raw [48]byte // Sized to fit the largest union member
}

// ProcessData extracts process event fields.
func (e *Event) ProcessData() *ProcessEventData {
	if e.Type != EVENT_EXEC && e.Type != EVENT_EXIT {
		return nil
	}
	//nolint:gosec // Unsafe required for eBPF C struct interop
	return (*ProcessEventData)(unsafe.Pointer(&e.Data))
}

// TCPData extracts TCP event fields.
func (e *Event) TCPData() *TCPEventData {
	if e.Type != EVENT_TCP_CONNECT && e.Type != EVENT_TCP_CLOSE {
		return nil
	}
	//nolint:gosec // Unsafe required for eBPF C struct interop
	return (*TCPEventData)(unsafe.Pointer(&e.Data))
}

// ProcessEventData matches the proc struct in the C union.
type ProcessEventData struct {
	ExitCode uint32
	Comm     [16]byte
}

// TCPEventData matches the tcp struct in the C union.
type TCPEventData struct {
	Skaddr uint64
	Saddr  [16]byte
	Daddr  [16]byte
	Sport  uint16
	Dport  uint16
	Family uint16
	_      uint16 // Padding
}

// EnvChunkEvent represents a chunk of argv and environment variables from execve.
// This is a separate event type that doesn't fit in the fixed-size Event union.
// Header fields match Event struct for consistent type detection at offset 24.
type EnvChunkEvent struct {
	Pid       uint32
	Ppid      uint32  // Not used, but keeps layout consistent
	Uid       uint32  //nolint:revive // Matches C struct field naming
	Pad1      uint32  // Padding before timestamp (matches Event struct)
	Timestamp uint64  // Not used, but keeps layout consistent
	Type      uint8   // EVENT_EXEC_ENV_CHUNK
	_         [7]byte // Padding (matches Event struct)
	ChunkID   uint32
	DataSize  uint32
	Argc      uint32 // Number of argv strings at start of Data
	IsFinal   uint8
	Truncated uint8
	_         [2]byte // Padding
	Data      [15000]byte
}

// EnvVarEvent represents a single environment variable or argument from execve.
// Used for streaming large numbers of variables (1024-2048+).
// Header fields match Event struct for consistent type detection.
type EnvVarEvent struct {
	Pid       uint32
	Ppid      uint32
	Uid       uint32 //nolint:revive // Matches C struct field naming
	Pad1      uint32 // Padding before timestamp
	Timestamp uint64
	Type      uint8   // EVENT_ENV_VAR
	_         [7]byte // Padding (matches Event struct)
	VarIndex  uint16  // Position in argv/envp array (0-2047)
	TotalVars uint16  // Total count (0 = unknown yet)
	IsArgv    uint8   // 0=env, 1=argv
	IsFinal   uint8   // 1 if this is last variable
	Truncated uint8   // 1 if variable was truncated
	_         uint8   // Padding
	DataSize  uint16  // Actual data length
	_         uint16  // Padding to align to 8 bytes
	Data      [512]byte
}

// ProcessTracerObjects provides access to the loaded BPF objects.
type ProcessTracerObjects = processTracerObjects

// ProcessTracerPrograms provides access to the BPF programs.
type ProcessTracerPrograms = processTracerPrograms

// ProcessTracerMaps provides access to the BPF maps.
type ProcessTracerMaps = processTracerMaps

// LoadProcessTracerObjects loads the BPF programs and maps.
func LoadProcessTracerObjects(obj *processTracerObjects, opts *ebpf.CollectionOptions) error {
	return loadProcessTracerObjects(obj, opts)
}
