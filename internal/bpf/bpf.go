package bpf

import "github.com/cilium/ebpf"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go schedTrace ./sched_trace.bpf.c -- -I. -I/usr/include

const (
	EVENT_EXEC = 1
	EVENT_EXIT = 2
)

// Event matches the C struct from sched_trace.h
type Event struct {
	Pid      uint32
	Ppid     uint32
	Uid      uint32
	ExitCode uint32
	Type     uint8
	Comm     [16]byte
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

