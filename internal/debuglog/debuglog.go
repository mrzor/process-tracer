// Package debuglog provides a process-wide structured debug-event sink used
// to diagnose daemon-mode routing decisions (session creation, descendant
// joins, ancestor-walk welds, trace-id mismatches, etc.).
//
// The sink is off by default: L is a Nop logger and all call sites are
// effectively free. Callers enable it by calling Init with a file path —
// typically from a CLI flag (--debug-log) or PROCESS_TRACER_DEBUG_LOG env var.
// When enabled, every event is written as one JSON object per line, suitable
// for jq / spreadsheet analysis.
package debuglog

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// L is the process-wide debug logger. Starts as a Nop; Init redirects it to
// a file. Zap's Nop core discards fields cheaply so call sites are safe to
// leave in hot paths.
var L *zap.Logger = zap.NewNop()

// Enabled reports whether L is currently writing (i.e. Init was called with
// a non-empty path and cleanup hasn't run). Call sites that want to skip
// expensive field preparation can guard on this. Zap itself no-ops on Nop,
// so cheap log calls don't need the guard.
func Enabled() bool {
	return L.Core().Enabled(zapcore.InfoLevel)
}

// Init opens path for append-only writes and replaces L with a JSON-encoded
// zap logger. An empty path leaves L as Nop and returns a no-op cleanup.
// Intended to be called once, early in daemon startup.
func Init(path string) (cleanup func(), err error) {
	if path == "" {
		return func() {}, nil
	}

	// Append-only, create if missing. Debug runs are typically short; no
	// rotation logic here — operator rotates externally if needed.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint:gosec // operator-provided diagnostic path
	if err != nil {
		return func() {}, fmt.Errorf("open debug log %q: %w", path, err)
	}

	encoderCfg := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		MessageKey:     "event",
		NameKey:        "logger",
		CallerKey:      "",
		StacktraceKey:  "",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderCfg),
		zapcore.AddSync(f),
		zapcore.InfoLevel,
	)
	L = zap.New(core)

	cleanup = func() {
		if err := L.Sync(); err != nil {
			// Sync failures on ordinary files aren't actionable at shutdown;
			// log to stderr and move on so Close still runs.
			fmt.Fprintf(os.Stderr, "debuglog: sync failed: %v\n", err)
		}
		if err := f.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "debuglog: close failed: %v\n", err)
		}
		L = zap.NewNop()
	}
	return cleanup, nil
}
