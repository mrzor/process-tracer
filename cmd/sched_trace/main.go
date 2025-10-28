package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sched_trace/internal/bpfloader"
	"sched_trace/internal/config"
	"sched_trace/internal/eventstream"
	"sched_trace/internal/otel"
	"sched_trace/internal/output"
	"sched_trace/internal/pseudo_reverse_dns"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

// getTCPFinTimeout reads net.ipv4.tcp_fin_timeout from sysctl
// Returns timeout in seconds, defaults to 60 if unable to read
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

func run() error {
	// Parse command line arguments
	cfg, err := config.ParseArgs(os.Args)
	if err != nil {
		return err
	}

	// Parse OTEL configuration from environment
	otelCfg, err := config.ParseOTELConfig()
	if err != nil {
		return fmt.Errorf("failed to parse OTEL config: %w", err)
	}

	// Initialize OTEL provider and establish connection
	// This MUST succeed before we proceed - abort on failure
	// Sends a test span with the trace ID to verify end-to-end connectivity
	tp, err := otel.InitProvider(otelCfg, cfg.TraceID)
	if err != nil {
		return fmt.Errorf("ABORT: failed to initialize OTEL provider: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := otel.ShutdownProvider(tp, shutdownCtx); err != nil {
			log.Printf("Error shutting down OTEL provider: %v", err)
		}
	}()

	// Create tracer
	tracer := tp.Tracer("sched_trace")

	// Load BPF program
	loader, err := bpfloader.New()
	if err != nil {
		return err
	}
	defer loader.Close()

	// Attach tracepoints
	if err := loader.Attach(); err != nil {
		return err
	}

	// Open ring buffer reader
	rd, err := loader.OpenRingBuffer()
	if err != nil {
		return err
	}
	defer rd.Close()

	// Initialize pseudo reverse DNS resolver
	resolver := pseudo_reverse_dns.New()
	resolver.AddStaticSource(&pseudo_reverse_dns.EnvironSource{})
	resolver.AddStaticSource(&pseudo_reverse_dns.CmdlineSource{})

	// Create event stream with OTEL formatter
	formatter, err := output.NewOTELFormatter(tracer, cfg.TraceID, resolver)
	if err != nil {
		return fmt.Errorf("failed to create OTEL formatter: %w", err)
	}
	stream := eventstream.New(rd, formatter)

	// Create context for event stream
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start event stream
	if err := stream.Start(ctx); err != nil {
		return err
	}
	defer stream.Stop()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Fork and exec the target command
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
		cmd.Process.Kill()
		return err
	}

	fmt.Printf("Tracing process tree starting from PID %d...\n", childPid)

	// Monitor child process completion
	childDone := make(chan error, 1)
	go func() {
		childDone <- cmd.Wait()
	}()

	// Wait for completion or signal
	select {
	case <-sigCh:
		log.Println("Received signal, terminating...")
		cmd.Process.Signal(syscall.SIGTERM)
		// Give it a moment to exit gracefully
		time.Sleep(100 * time.Millisecond)
		cmd.Process.Kill()
	case err := <-childDone:
		if err != nil {
			log.Printf("Child process exited with error: %v", err)
		}
	}

	// Give ring buffer time to drain and catch late TCP CLOSE events
	// TCP connections may linger in FIN_WAIT or TIME_WAIT states before transitioning to CLOSE
	// We use a fraction of tcp_fin_timeout as our drain period
	tcpFinTimeout := getTCPFinTimeout()
	// Use 1% of tcp_fin_timeout with a minimum of 500ms and maximum of 2s
	drainTimeout := time.Duration(tcpFinTimeout*10) * time.Millisecond
	if drainTimeout < 500*time.Millisecond {
		drainTimeout = 500 * time.Millisecond
	}
	if drainTimeout > 2*time.Second {
		drainTimeout = 2 * time.Second
	}

	time.Sleep(drainTimeout)

	return nil
}
