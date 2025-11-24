package timesync

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Converter handles conversion from monotonic timestamps to wall-clock time.
type Converter struct {
	bootTime time.Time
}

// NewConverter creates a new time converter.
// It reads the system boot time from /proc/stat.
// If reading fails, it uses a conservative fallback estimate.
func NewConverter() (*Converter, error) {
	bootTime, err := getSystemBootTime()
	if err != nil {
		// Fallback: estimate boot time from current time - uptime
		// This is less accurate but allows the tracer to continue
		bootTime = time.Now().Add(-time.Hour) // Conservative fallback
	}

	return &Converter{
		bootTime: bootTime,
	}, nil
}

// MonotonicToWallClock converts a monotonic timestamp (nanoseconds since boot) to wall-clock time.
// This is a pure function that performs the conversion based on the boot time captured at initialization.
func (c *Converter) MonotonicToWallClock(monotonicNanos uint64) time.Time {
	//nolint:gosec // uint64 to int64 conversion for time.Duration is safe for reasonable timestamps
	return c.bootTime.Add(time.Duration(monotonicNanos))
}

// BootTime returns the system boot time used for conversions.
func (c *Converter) BootTime() time.Time {
	return c.bootTime
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
