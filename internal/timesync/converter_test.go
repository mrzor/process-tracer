package timesync

import (
	"testing"
	"time"
)

func TestConverter_MonotonicToWallClock(t *testing.T) {
	// Create a converter with a known boot time
	bootTime := time.Unix(1000000000, 0) // 2001-09-09 01:46:40 UTC
	converter := &Converter{
		bootTime: bootTime,
	}

	tests := []struct {
		name           string
		monotonicNanos uint64
		want           time.Time
	}{
		{
			name:           "zero nanoseconds",
			monotonicNanos: 0,
			want:           bootTime,
		},
		{
			name:           "one second",
			monotonicNanos: 1_000_000_000,
			want:           bootTime.Add(1 * time.Second),
		},
		{
			name:           "one hour",
			monotonicNanos: 3_600_000_000_000,
			want:           bootTime.Add(1 * time.Hour),
		},
		{
			name:           "mixed time",
			monotonicNanos: 123_456_789_000,
			want:           bootTime.Add(123*time.Second + 456*time.Millisecond + 789*time.Microsecond),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := converter.MonotonicToWallClock(tt.monotonicNanos)
			if !got.Equal(tt.want) {
				t.Errorf("MonotonicToWallClock() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConverter_BootTime(t *testing.T) {
	bootTime := time.Unix(1000000000, 0)
	converter := &Converter{
		bootTime: bootTime,
	}

	got := converter.BootTime()
	if !got.Equal(bootTime) {
		t.Errorf("BootTime() = %v, want %v", got, bootTime)
	}
}

func TestNewConverter(t *testing.T) {
	// This test verifies that NewConverter doesn't fail
	// We can't easily test the actual boot time reading without mocking /proc/stat
	converter, err := NewConverter()
	if err != nil {
		t.Fatalf("NewConverter() error = %v", err)
	}

	if converter == nil {
		t.Fatal("NewConverter() returned nil converter")
	}

	// Verify boot time is reasonable (not zero, not in the future)
	bootTime := converter.BootTime()
	if bootTime.IsZero() {
		t.Error("BootTime() is zero")
	}

	if bootTime.After(time.Now()) {
		t.Error("BootTime() is in the future")
	}

	// Boot time should be relatively recent (within last year for most tests)
	oneYearAgo := time.Now().Add(-365 * 24 * time.Hour)
	if bootTime.Before(oneYearAgo) {
		t.Logf("Warning: BootTime() is more than a year ago: %v", bootTime)
	}
}
