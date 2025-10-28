package bpf

import (
	"unsafe"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 schedTrace ./sched_trace.bpf.c -- -I. -I/usr/include

const (
	EVENT_EXEC        = 1
	EVENT_EXIT        = 2
	EVENT_TCP_CONNECT = 3
	EVENT_TCP_CLOSE   = 4
)

// Event matches the C struct from sched_trace.h
// Using explicit struct layout to match C union
type Event struct {
	Pid       uint32
	Ppid      uint32
	Uid       uint32
	Pad1      uint32  // Padding before timestamp to maintain 8-byte alignment
	Timestamp uint64
	Type      uint8
	Pad2      [7]byte // Padding to align Data field
	Data      EventData
}

// EventData is a union type matching the C union
type EventData struct {
	// This will overlay both process and TCP data
	// The actual interpretation depends on Event.Type
	Raw [48]byte // Sized to fit the largest union member
}

// ProcessData extracts process event fields
func (e *Event) ProcessData() *ProcessEventData {
	if e.Type != EVENT_EXEC && e.Type != EVENT_EXIT {
		return nil
	}
	return (*ProcessEventData)(unsafe.Pointer(&e.Data))
}

// TCPData extracts TCP event fields
func (e *Event) TCPData() *TCPEventData {
	if e.Type != EVENT_TCP_CONNECT && e.Type != EVENT_TCP_CLOSE {
		return nil
	}
	return (*TCPEventData)(unsafe.Pointer(&e.Data))
}

// ProcessEventData matches the proc struct in the C union
type ProcessEventData struct {
	ExitCode uint32
	Comm     [16]byte
}

// TCPEventData matches the tcp struct in the C union
type TCPEventData struct {
	Skaddr uint64
	Saddr  [16]byte
	Daddr  [16]byte
	Sport  uint16
	Dport  uint16
	Family uint16
	_      uint16 // Padding
}

// Exported wrapper types
type (
	SchedTraceObjects  = schedTraceObjects
	SchedTracePrograms = schedTracePrograms
	SchedTraceMaps     = schedTraceMaps
)

// LoadSchedTraceObjects loads the BPF programs and maps
func LoadSchedTraceObjects(obj *schedTraceObjects, opts *ebpf.CollectionOptions) error {
	return loadSchedTraceObjects(obj, opts)
}

