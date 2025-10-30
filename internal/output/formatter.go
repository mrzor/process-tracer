package output

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mrzor/process-tracer/internal/bpf"
)

// EventHandler is the interface for handling BPF events.
type EventHandler interface {
	HandleEvent(event *bpf.Event) error
	HandleEnvChunk(chunk *bpf.EnvChunkEvent) error
	HandleEnvVar(envVar *bpf.EnvVarEvent) error
}

// getSystemBootTime reads the system boot time from /proc/stat.
func getSystemBootTime() (time.Time, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to open /proc/stat: %w", err)
	}
	defer func() {
		_ = file.Close()
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
