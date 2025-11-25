// process-tracer is an eBPF-based process and network tracer with OpenTelemetry span integration.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/mrzor/process-tracer/internal/bpfloader"
	"github.com/mrzor/process-tracer/internal/config"
	"github.com/mrzor/process-tracer/internal/eventprocessor"
	"github.com/mrzor/process-tracer/internal/eventstream"
	"github.com/mrzor/process-tracer/internal/otel"
	"github.com/mrzor/process-tracer/internal/output"
	"github.com/mrzor/process-tracer/internal/procmeta"
	"github.com/mrzor/process-tracer/internal/reversedns"
	"github.com/mrzor/process-tracer/internal/timesync"
	"go.opentelemetry.io/otel/trace"
)

//go:embed LICENSE
var licenseText string

// Version information injected by GoReleaser at build time.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

// getTCPFinTimeout reads net.ipv4.tcp_fin_timeout from sysctl
// Returns timeout in seconds, defaults to 60 if unable to read.
func getTCPFinTimeout() int {
	data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_fin_timeout")
	if err != nil {
		return 60 // Default value
	}

	timeout, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 60
	}

	return timeout
}

// setupOTEL initializes the OTEL provider and returns a tracer and cleanup function.
func setupOTEL(versionInfo string) (trace.Tracer, func(), error) {
	// Parse OTEL configuration from environment
	otelCfg, err := config.ParseOTELConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse OTEL config: %w", err)
	}

	// Initialize OTEL provider and establish connection
	tp, err := otel.InitProvider(otelCfg, versionInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("ABORT: failed to initialize OTEL provider: %w", err)
	}

	cleanup := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := otel.ShutdownProvider(tp, shutdownCtx); err != nil {
			log.Printf("Error shutting down OTEL provider: %v", err)
		}
	}

	return tp.Tracer("process-tracer"), cleanup, nil
}

// setupBPF loads the BPF program, attaches tracepoints, and opens ring buffer.
// Returns loader, ring buffer reader, and cleanup function.
func setupBPF() (*bpfloader.Loader, *ringbuf.Reader, func(), error) {
	loader, err := bpfloader.New()
	if err != nil {
		return nil, nil, nil, err
	}

	if err := loader.Attach(); err != nil {
		if closeErr := loader.Close(); closeErr != nil {
			log.Printf("Error closing loader after attach failure: %v", closeErr)
		}
		return nil, nil, nil, err
	}

	rd, err := loader.OpenRingBuffer()
	if err != nil {
		if closeErr := loader.Close(); closeErr != nil {
			log.Printf("Error closing loader after ring buffer open failure: %v", closeErr)
		}
		return nil, nil, nil, err
	}

	cleanup := func() {
		if err := rd.Close(); err != nil {
			log.Printf("Error closing ring buffer: %v", err)
		}
		if err := loader.Close(); err != nil {
			log.Printf("Error closing loader: %v", err)
		}
	}

	return loader, rd, cleanup, nil
}

// setupComponents initializes all tracing components and returns the event stream.
func setupComponents(cfg *config.Config, tracer trace.Tracer, rd *ringbuf.Reader) (*eventstream.Stream, error) {
	converter, err := timesync.NewConverter()
	if err != nil {
		return nil, fmt.Errorf("failed to create time converter: %w", err)
	}

	metadataManager := procmeta.NewManager()
	resolver := reversedns.New()

	formatter, err := output.NewOTELFormatter(
		tracer,
		converter,
		resolver,
		metadataManager,
		cfg.CustomAttributes,
		cfg.TraceID,
		cfg.ParentID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTEL formatter: %w", err)
	}

	processor := eventprocessor.NewProcessor(
		metadataManager,
		resolver,
		formatter,
		formatter,
	)

	return eventstream.New(rd, processor), nil
}

// executeCommand starts the target command and monitors it until completion.
// Returns when the command exits or a signal is received.
func executeCommand(cfg *config.Config, loader *bpfloader.Loader) error {
	//nolint:gosec // This is a tracer tool - launching subprocesses is its purpose
	cmd := exec.Command(cfg.Command, cfg.Args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Add our PID to tracked map before starting child
	if err := loader.TrackPID(os.Getpid()); err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting command: %w", err)
	}

	// Add child PID to tracked map
	childPid := cmd.Process.Pid
	if err := loader.TrackPID(childPid); err != nil {
		_ = cmd.Process.Kill() //nolint:errcheck // Best-effort cleanup in error path
		return err
	}

	fmt.Printf("Tracing process tree starting from PID %d...\n", childPid)

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Monitor child process completion
	childDone := make(chan error, 1)
	go func() {
		childDone <- cmd.Wait()
	}()

	// Wait for completion or signal
	select {
	case <-sigCh:
		log.Println("Received signal, terminating...")
		_ = cmd.Process.Signal(syscall.SIGTERM) //nolint:errcheck // Best-effort graceful shutdown; Kill() follows
		// Give it a moment to exit gracefully
		time.Sleep(100 * time.Millisecond)
		_ = cmd.Process.Kill() //nolint:errcheck // Best-effort cleanup during shutdown
	case err := <-childDone:
		if err != nil {
			log.Printf("Child process exited with error: %v", err)
		}
	}

	return nil
}

// calculateDrainTimeout computes the timeout for draining late TCP events.
// Uses a fraction of tcp_fin_timeout with bounds of 500ms to 2s.
func calculateDrainTimeout() time.Duration {
	tcpFinTimeout := getTCPFinTimeout()
	// Use 1% of tcp_fin_timeout with a minimum of 500ms and maximum of 2s
	drainTimeout := time.Duration(tcpFinTimeout*10) * time.Millisecond
	if drainTimeout < 500*time.Millisecond {
		drainTimeout = 500 * time.Millisecond
	}
	if drainTimeout > 2*time.Second {
		drainTimeout = 2 * time.Second
	}
	return drainTimeout
}

func run() error {
	// Parse command line arguments
	cfg, err := config.ParseArgs(os.Args, licenseText, version, commit, date)
	if err != nil {
		return err
	}

	// Log version information
	log.Printf("Starting process-tracer %s (commit: %s, built: %s)", version, commit, date)

	// Initialize OTEL provider
	versionInfo := fmt.Sprintf("%s (%s)", version, commit)
	tracer, cleanupOTEL, err := setupOTEL(versionInfo)
	if err != nil {
		return err
	}
	defer cleanupOTEL()

	// Load BPF program and open ring buffer
	loader, rd, cleanupBPF, err := setupBPF()
	if err != nil {
		return err
	}
	defer cleanupBPF()

	// Initialize components and create event stream
	stream, err := setupComponents(cfg, tracer, rd)
	if err != nil {
		return err
	}

	// Start event stream
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := stream.Start(ctx); err != nil {
		return err
	}
	defer func() {
		if err := stream.Stop(); err != nil {
			log.Printf("Error stopping stream: %v", err)
		}
	}()

	// Execute target command and wait for completion
	if err := executeCommand(cfg, loader); err != nil {
		return err
	}

	// Give ring buffer time to drain and catch late TCP CLOSE events
	time.Sleep(calculateDrainTimeout())

	return nil
}
