package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/mrzor/process-tracer/internal/ambient"
	"github.com/mrzor/process-tracer/internal/bpfloader"
	"github.com/mrzor/process-tracer/internal/config"
	"github.com/mrzor/process-tracer/internal/debuglog"
	"github.com/mrzor/process-tracer/internal/eventstream"
	"github.com/mrzor/process-tracer/internal/otel"
	"github.com/mrzor/process-tracer/internal/procmeta"
	"github.com/mrzor/process-tracer/internal/reversedns"
	"github.com/mrzor/process-tracer/internal/timesync"
	"github.com/urfave/cli/v3"
	"go.opentelemetry.io/otel/trace"
)

func daemonCommand() *cli.Command {
	var configPath string
	var debugLogPath string
	var debugLogCoverage int

	return &cli.Command{
		Name:  "daemon",
		Usage: "Run as a daemon, tracing process trees system-wide based on configurable rules",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "config",
				Aliases:     []string{"c"},
				Usage:       "Path to the daemon mode YAML configuration file",
				Destination: &configPath,
				Sources:     cli.EnvVars("PROCESS_TRACER_DAEMON_CONFIG"),
				Required:    true,
			},
			&cli.StringFlag{
				Name:        "debug-log",
				Usage:       "Write detailed routing-diagnostic events (JSON lines) to this file. Disabled when empty.",
				Destination: &debugLogPath,
				Sources:     cli.EnvVars("PROCESS_TRACER_DEBUG_LOG"),
			},
			&cli.IntFlag{
				Name:        "debug-log-coverage",
				Usage:       "Sample every Nth exec that no rule matches and log an exec_unmatched debug event (0 = off). Useful for finding binaries the rule should also match.",
				Destination: &debugLogCoverage,
				Sources:     cli.EnvVars("PROCESS_TRACER_DEBUG_LOG_COVERAGE"),
			},
		},
		Action: func(_ context.Context, _ *cli.Command) error {
			return runDaemon(configPath, debugLogPath, debugLogCoverage)
		},
	}
}

func runDaemon(configPath, debugLogPath string, debugLogCoverage int) error {
	cfg, err := config.LoadAmbientConfig(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	log.Printf("process-tracer daemon %s (commit %s, built %s)", version, commit, date)
	log.Printf("loaded %d rules", len(cfg.Rules))

	dbgCleanup, err := debuglog.Init(debugLogPath)
	if err != nil {
		return fmt.Errorf("opening debug log: %w", err)
	}
	defer dbgCleanup()
	if debugLogPath != "" {
		log.Printf("debug-log: writing routing diagnostics to %s", debugLogPath)
	}

	versionInfo := fmt.Sprintf("%s (%s)", version, commit)
	tracer, otelCleanup, err := setupDaemonOTEL(cfg, versionInfo)
	if err != nil {
		return err
	}
	defer otelCleanup()

	loader, rd, bpfCleanup, err := setupDaemonBPF(cfg.Limits.RingBufferSize)
	if err != nil {
		return err
	}
	defer bpfCleanup()

	converter, err := timesync.NewConverter()
	if err != nil {
		return fmt.Errorf("creating time converter: %w", err)
	}

	metadataManager := procmeta.NewManager()
	resolver := reversedns.New()

	filter := ambient.NewFilterEngine(cfg.Rules)
	manager := ambient.NewSessionManager(
		loader, tracer, converter, resolver, metadataManager, cfg.Limits,
	)
	processor := ambient.NewProcessor(filter, manager)
	processor.SetDebugCoverageSampling(debugLogCoverage)

	stream := eventstream.New(rd, processor)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := stream.Start(ctx); err != nil {
		return fmt.Errorf("starting event stream: %w", err)
	}

	log.Printf("daemon started, monitoring all process execs")

	go runPeriodicCleanup(ctx, manager, processor)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	log.Printf("received %v, shutting down...", sig)
	cancel()

	if err := stream.Stop(); err != nil {
		log.Printf("error stopping event stream: %v", err)
	}

	// Close every still-active session's process.tree root span before
	// OTEL shutdown — otherwise the BatchSpanProcessor has nothing to flush
	// for those sessions and their trees are dropped.
	closed := manager.CloseAllSessions()
	log.Printf("shutdown complete (%d active sessions closed)", closed)
	return nil
}

func setupDaemonOTEL(cfg *config.AmbientConfig, versionInfo string) (trace.Tracer, func(), error) {
	if cfg.OTEL.ServiceName != "" {
		if err := os.Setenv("OTEL_SERVICE_NAME", cfg.OTEL.ServiceName); err != nil {
			log.Printf("warning: failed to set OTEL_SERVICE_NAME: %v", err)
		}
	}
	if cfg.OTEL.Endpoint != "" {
		if err := os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", cfg.OTEL.Endpoint); err != nil {
			log.Printf("warning: failed to set OTEL_EXPORTER_OTLP_ENDPOINT: %v", err)
		}
	}

	otelCfg, err := config.ParseOTELConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("parsing OTEL config: %w", err)
	}

	tp, err := otel.InitProvider(otelCfg, versionInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("initializing OTEL provider: %w", err)
	}

	cleanup := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), otelCfg.ShutdownTimeout())
		defer cancel()
		start := time.Now()
		log.Printf("OTEL shutdown: starting (timeout %v)", otelCfg.ShutdownTimeout())
		if err := otel.ShutdownProvider(tp, shutdownCtx); err != nil {
			log.Printf("error shutting down OTEL provider (took %v): %v", time.Since(start), err)
			return
		}
		log.Printf("OTEL shutdown: completed in %v", time.Since(start))
	}

	return tp.Tracer("process-tracer-daemon"), cleanup, nil
}

func setupDaemonBPF(ringBufferSize int) (*bpfloader.Loader, *ringbuf.Reader, func(), error) {
	loader, err := bpfloader.NewWithOptions(bpfloader.LoaderOptions{
		AmbientMode:    true,
		RingBufferSize: ringBufferSize,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading BPF: %w", err)
	}

	if err := loader.Attach(); err != nil {
		if closeErr := loader.Close(); closeErr != nil {
			log.Printf("error closing loader after attach failure: %v", closeErr)
		}
		return nil, nil, nil, fmt.Errorf("attaching BPF: %w", err)
	}

	rd, err := loader.OpenRingBuffer()
	if err != nil {
		if closeErr := loader.Close(); closeErr != nil {
			log.Printf("error closing loader after ring buffer failure: %v", closeErr)
		}
		return nil, nil, nil, fmt.Errorf("opening ring buffer: %w", err)
	}

	cleanup := func() {
		if err := rd.Close(); err != nil {
			log.Printf("error closing ring buffer: %v", err)
		}
		if err := loader.Close(); err != nil {
			log.Printf("error closing BPF: %v", err)
		}
	}

	return loader, rd, cleanup, nil
}

func runPeriodicCleanup(ctx context.Context, manager *ambient.SessionManager, processor *ambient.Processor) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			manager.CleanupStale()
			processor.CleanupStalePending(5 * time.Second)
		}
	}
}
