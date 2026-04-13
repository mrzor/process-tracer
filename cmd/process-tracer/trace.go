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
	"sync"
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
	"github.com/urfave/cli/v3"
	"go.opentelemetry.io/otel/trace"
)

func traceCommand() *cli.Command {
	var traceID string
	var parentID string
	var skipEmptyValues bool
	var addDebugAttributes bool
	var attrArgs []string

	return &cli.Command{
		Name:  "trace",
		Usage: "Trace a command and its process tree",
		UsageText: "process-tracer trace [OPTIONS] -- COMMAND [ARGS...]\n\n" +
			"   Use '--' to separate options from the command to trace.\n\n" +
			"EXAMPLES:\n" +
			"   process-tracer trace -- bash -c 'echo hello'\n" +
			"   process-tracer trace -t a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 -- ls -la\n" +
			"   process-tracer trace -a service.name=my-service -- command args\n" +
			"   process-tracer trace -a env_name='expr:env[\"ENVIRONMENT\"]' -- command args\n" +
			"   process-tracer trace -a foo='expr:env[\"FOO\"]' -a bar=literal-val -- cmd",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "trace-id",
				Aliases: []string{"t"},
				Usage:   "OpenTelemetry trace ID: literal hex string or expr:EXPRESSION (SDK auto-generates if not provided)",
				Action: func(_ context.Context, _ *cli.Command, s string) error {
					if s != "" {
						traceID = s
					}
					return nil
				},
			},
			&cli.StringFlag{
				Name:    "parent-id",
				Aliases: []string{"p"},
				Usage:   "OpenTelemetry parent span ID: literal hex string or expr:EXPRESSION (null if not provided)",
				Action: func(_ context.Context, _ *cli.Command, s string) error {
					if s != "" {
						parentID = s
					}
					return nil
				},
			},
			&cli.StringSliceFlag{
				Name:        "a",
				Aliases:     []string{"attribute"},
				Usage:       "Add custom span attribute as NAME=VALUE or NAME=expr:EXPRESSION (repeatable)",
				Destination: &attrArgs,
			},
			&cli.BoolFlag{
				Name:        "skip-empty-values",
				Usage:       "Omit custom attributes whose value evaluates to an empty string",
				Destination: &skipEmptyValues,
			},
			&cli.BoolFlag{
				Name:        "add-debug-attributes",
				Usage:       "Add debug.* span attributes (argv, environ, trace/parent-id provenance). May leak secrets.",
				Destination: &addDebugAttributes,
			},
		},
		UseShortOptionHandling: true,
		Action: func(_ context.Context, cmd *cli.Command) error {
			envCfg, err := config.ParseEnvConfig()
			if err != nil {
				return fmt.Errorf("failed to parse environment config: %w", err)
			}

			// Parse custom attributes from -a flags
			var customAttrs []config.CustomAttribute
			for _, attrStr := range attrArgs {
				if attr, ok := config.ParseAttribute(attrStr); ok {
					customAttrs = append(customAttrs, attr)
				}
			}

			cfg, err := config.BuildTraceConfig(envCfg, traceID, parentID, customAttrs, skipEmptyValues, addDebugAttributes, cmd.Args().Slice())
			if err != nil {
				return fmt.Errorf("%w\n\nUse '--' to separate options from the command to trace.\n\nExample: process-tracer trace -a service.name=my-svc -- bash -c 'echo hello'", err)
			}

			return runTrace(cfg)
		},
	}
}

func runTrace(cfg *config.Config) error {
	log.Printf("Starting process-tracer %s (commit: %s, built: %s)", version, commit, date)

	versionInfo := fmt.Sprintf("%s (%s)", version, commit)
	tracer, cleanupOTEL, err := setupTraceOTEL(versionInfo)
	if err != nil {
		return err
	}

	loader, rd, cleanupBPF, err := setupTraceBPF()
	if err != nil {
		cleanupOTEL()
		return err
	}

	defer func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); cleanupBPF() }()
		go func() { defer wg.Done(); cleanupOTEL() }()
		wg.Wait()
	}()

	stream, formatter, err := setupComponents(cfg, tracer, rd)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Open the synthetic "process.tree" root span before any process events flow.
	// All process.exec spans observed during this invocation will hang under it.
	rootMetadata := buildTraceModeMetadata(cfg.Command, cfg.Args)
	formatter.StartSession(ctx, rootMetadata, time.Now())
	defer func() { formatter.EndSession(time.Now()) }()

	if err := stream.Start(ctx); err != nil {
		return err
	}
	defer func() {
		if err := stream.Stop(); err != nil {
			log.Printf("Error stopping stream: %v", err)
		}
	}()

	if err := executeCommand(cfg, loader); err != nil {
		return err
	}

	time.Sleep(calculateDrainTimeout())

	return nil
}

// getTCPFinTimeout reads net.ipv4.tcp_fin_timeout from sysctl.
// Returns timeout in seconds, defaults to 60 if unable to read.
func getTCPFinTimeout() int {
	data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_fin_timeout")
	if err != nil {
		return 60
	}

	timeout, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 60
	}

	return timeout
}

func setupTraceOTEL(versionInfo string) (trace.Tracer, func(), error) {
	otelCfg, err := config.ParseOTELConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse OTEL config: %w", err)
	}

	tp, err := otel.InitProvider(otelCfg, versionInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("ABORT: failed to initialize OTEL provider: %w", err)
	}

	cleanup := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), otelCfg.ShutdownTimeout())
		defer cancel()
		if err := otel.ShutdownProvider(tp, shutdownCtx); err != nil {
			log.Printf("Error shutting down OTEL provider: %v", err)
		}
	}

	return tp.Tracer("process-tracer"), cleanup, nil
}

func setupTraceBPF() (*bpfloader.Loader, *ringbuf.Reader, func(), error) {
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

func setupComponents(cfg *config.Config, tracer trace.Tracer, rd *ringbuf.Reader) (*eventstream.Stream, *output.OTELFormatter, error) {
	converter, err := timesync.NewConverter()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create time converter: %w", err)
	}

	metadataManager := procmeta.NewManager()
	resolver := reversedns.New()

	formatter, err := output.NewOTELFormatter(
		tracer,
		converter,
		resolver,
		metadataManager,
		cfg.CustomAttributes,
		cfg.SkipEmptyValues,
		cfg.TraceID,
		cfg.ParentID,
		cfg.AddDebugAttributes,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OTEL formatter: %w", err)
	}

	processor := eventprocessor.NewProcessor(
		metadataManager,
		resolver,
		formatter,
		formatter,
	)

	return eventstream.New(rd, processor), formatter, nil
}

// buildTraceModeMetadata synthesizes a ProcessMetadata representing the traced
// command. Used by the formatter's trace_id/parent_id evaluators at session start.
// The traced command inherits process-tracer's environment, so os.Environ() is
// the right source for env lookups.
func buildTraceModeMetadata(command string, args []string) *procmeta.ProcessMetadata {
	environ := make(map[string]string, len(os.Environ()))
	for _, kv := range os.Environ() {
		if idx := strings.IndexByte(kv, '='); idx > 0 {
			environ[kv[:idx]] = kv[idx+1:]
		}
	}
	cmdArgs := append([]string{command}, args...)
	return &procmeta.ProcessMetadata{
		Environ:     environ,
		Args:        cmdArgs,
		CmdlineFull: strings.Join(cmdArgs, " "),
	}
}

func executeCommand(cfg *config.Config, loader *bpfloader.Loader) error {
	//nolint:gosec // This is a tracer tool - launching subprocesses is its purpose
	cmd := exec.Command(cfg.Command, cfg.Args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := loader.TrackPID(os.Getpid()); err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting command: %w", err)
	}

	childPid := cmd.Process.Pid
	if err := loader.TrackPID(childPid); err != nil {
		_ = cmd.Process.Kill() //nolint:errcheck // Best-effort cleanup in error path
		return err
	}

	fmt.Printf("Tracing process tree starting from PID %d...\n", childPid)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	childDone := make(chan error, 1)
	go func() {
		childDone <- cmd.Wait()
	}()

	select {
	case <-sigCh:
		log.Println("Received signal, terminating...")
		_ = cmd.Process.Signal(syscall.SIGTERM) //nolint:errcheck // Best-effort graceful shutdown; Kill() follows
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
func calculateDrainTimeout() time.Duration {
	tcpFinTimeout := getTCPFinTimeout()
	drainTimeout := time.Duration(tcpFinTimeout*2) * time.Millisecond
	if drainTimeout < 50*time.Millisecond {
		drainTimeout = 50 * time.Millisecond
	}
	if drainTimeout > 500*time.Millisecond {
		drainTimeout = 500 * time.Millisecond
	}
	return drainTimeout
}
