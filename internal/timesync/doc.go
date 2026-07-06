// Package timesync provides time conversion utilities for converting kernel
// boot-clock timestamps from eBPF events to wall-clock time.
//
// eBPF events are stamped with bpf_ktime_get_boot_ns() (CLOCK_BOOTTIME):
// nanoseconds since system boot, including time spent suspended. This package
// converts them to absolute wall-clock time by adding the boot instant, which
// it derives from a paired CLOCK_REALTIME/CLOCK_BOOTTIME reading (falling back
// to /proc/stat btime).
//
// CLOCK_BOOTTIME rather than CLOCK_MONOTONIC is deliberate: CLOCK_MONOTONIC
// freezes across suspend, which would drift these spans behind the wall-clock
// (CLOCK_REALTIME) root span by the host's cumulative suspend time.
package timesync
