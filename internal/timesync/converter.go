package timesync

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Converter handles conversion from kernel boot-clock timestamps to wall-clock time.
//
// eBPF events are stamped with bpf_ktime_get_boot_ns() (CLOCK_BOOTTIME): nanoseconds
// since boot, INCLUDING time spent suspended. We reconstruct wall-clock as
// bootTime + boottime_ns, where bootTime is the wall-clock instant of boot.
//
// The distinction from CLOCK_MONOTONIC matters: CLOCK_MONOTONIC freezes across
// suspend, so btime + monotonic_ns drifts behind real wall-clock by the host's
// cumulative suspend time. That desynced these spans from the process.tree root
// span (stamped with the userspace CLOCK_REALTIME clock) and inflated the
// rendered trace duration by hours on any machine that had suspended.
type Converter struct {
	bootTime time.Time
}

// NewConverter creates a new time converter.
//
// Primary path: anchor on a paired reading of CLOCK_REALTIME and CLOCK_BOOTTIME
// captured together, so bootTime = realtimeNow - boottimeElapsed. This is
// sub-second accurate, tracks any NTP adjustments to realtime since boot (which
// keeps us consistent with the time.Now() used for the root span), and needs no
// /proc parsing.
//
// Fallback: /proc/stat btime (integer-second boot wall time). This is still
// correct for CLOCK_BOOTTIME-domain events (btime + boottime_ns ≈ realtime),
// just coarser. Last resort is a conservative estimate.
func NewConverter() (*Converter, error) {
	bootTime, err := bootTimeFromClocks()
	if err == nil {
		return &Converter{bootTime: bootTime}, nil
	}
	log.Printf("WARN: CLOCK_BOOTTIME anchor unavailable (%v); falling back to /proc/stat btime", err)

	bootTime, err = getSystemBootTime()
	if err != nil {
		log.Printf("WARN: falling back to estimated timestamps, cause: %v", err)

		// Fallback: estimate boot time from current time - uptime
		// This is less accurate but allows the tracer to continue
		bootTime = time.Now().Add(-time.Hour) // Conservative fallback
	}

	return &Converter{
		bootTime: bootTime,
	}, nil
}

// BootNanosToWallClock converts a CLOCK_BOOTTIME timestamp (nanoseconds since
// boot, including suspend) to wall-clock time. Pure function over the boot time
// captured at initialization.
func (c *Converter) BootNanosToWallClock(bootNanos uint64) time.Time {
	//nolint:gosec // uint64 to int64 conversion for time.Duration is safe for reasonable timestamps
	return c.bootTime.Add(time.Duration(bootNanos))
}

// BootTime returns the system boot time used for conversions.
func (c *Converter) BootTime() time.Time {
	return c.bootTime
}

// bootTimeFromClocks derives the wall-clock instant of boot from a paired
// reading of CLOCK_REALTIME (via time.Now) and CLOCK_BOOTTIME. Read boottime as
// close as possible to now so the subtraction is a coherent instant.
func bootTimeFromClocks() (time.Time, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return time.Time{}, fmt.Errorf("clock_gettime(CLOCK_BOOTTIME): %w", err)
	}
	now := time.Now()
	return now.Add(-time.Duration(ts.Nano())), nil
}

// getSystemBootTime reads the system boot time from /proc/stat.
// Returns the boot time as a time.Time value, or an error if reading fails.
func getSystemBootTime() (time.Time, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to open /proc/stat: %w", err)
	}
	defer func() {
		_ = file.Close() //nolint:errcheck // Read-only file, defer cleanup
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "btime ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				bootTimeSec, err := strconv.ParseInt(fields[1], 10, 64)
				if err != nil {
					return time.Time{}, fmt.Errorf("failed to parse btime: %w", err)
				}
				return time.Unix(bootTimeSec, 0), nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return time.Time{}, fmt.Errorf("error reading /proc/stat: %w", err)
	}

	return time.Time{}, fmt.Errorf("btime not found in /proc/stat")
}
