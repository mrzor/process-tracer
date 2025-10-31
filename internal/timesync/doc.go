// Package timesync provides time conversion utilities for converting monotonic
// timestamps from eBPF events to wall-clock time.
//
// eBPF events use monotonic timestamps (nanoseconds since system boot).
// This package converts them to absolute wall-clock time by reading the
// system boot time from /proc/stat and adding the monotonic offset.
package timesync
