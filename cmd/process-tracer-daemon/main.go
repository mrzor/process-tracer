// process-tracer-daemon is the ambient mode daemon that monitors all process execs
// and traces matching process trees based on configurable rules.
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
	"github.com/mrzor/process-tracer/internal/eventstream"
	"github.com/mrzor/process-tracer/internal/otel"
	"github.com/mrzor/process-tracer/internal/procmeta"
	"github.com/mrzor/process-tracer/internal/reversedns"
	"github.com/mrzor/process-tracer/internal/timesync"
	"go.opentelemetry.io/otel/trace"
)

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

func run() error {
	// Parse config file path from args or env
	configPath := os.Getenv("PROCESS_TRACER_DAEMON_CONFIG")
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}
	if configPath == "" {
		return fmt.Errorf("usage: %s <config.yaml>\n  or set PROCESS_TRACER_DAEMON_CONFIG", os.Args[0])
	}

	// Load ambient config
	cfg, err := config.LoadAmbientConfig(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	log.Printf("process-tracer-daemon %s (commit %s, built %s)", version, commit, date)
	log.Printf("loaded %d rules", len(cfg.Rules)) //nolint:gosec // integer from config, not tainted

	// Initialize OTEL
	versionInfo := fmt.Sprintf("%s (%s)", version, commit)
	tracer, otelCleanup, err := setupOTEL(cfg, versionInfo)
	if err != nil {
		return err
	}
	defer otelCleanup()

	// Load BPF in ambient mode
	loader, rd, bpfCleanup, err := setupBPF(cfg.Limits.RingBufferSize)
	if err != nil {
		return err
	}
	defer bpfCleanup()

	// Create shared components
	converter, err := timesync.NewConverter()
	if err != nil {
		return fmt.Errorf("creating time converter: %w", err)
	}

	metadataManager := procmeta.NewManager()
	resolver := reversedns.New()

	// Create ambient mode components
	filter := ambient.NewFilterEngine(cfg.Rules)
	manager := ambient.NewSessionManager(
		loader, tracer, converter, resolver, metadataManager, cfg.Limits,
	)
	processor := ambient.NewProcessor(filter, manager)

	// Start event stream
	stream := eventstream.New(rd, processor)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := stream.Start(ctx); err != nil {
		return fmt.Errorf("starting event stream: %w", err)
	}

	log.Printf("daemon started, monitoring all process execs")

	// Start periodic cleanup
	go runPeriodicCleanup(ctx, manager, processor)

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	log.Printf("received %v, shutting down...", sig)
	cancel()

	if err := stream.Stop(); err != nil {
		log.Printf("error stopping event stream: %v", err)
	}

	log.Printf("shutdown complete (%d sessions were active)", manager.ActiveSessions()) //nolint:gosec // integer, not tainted
	return nil
}

func setupOTEL(cfg *config.AmbientConfig, versionInfo string) (trace.Tracer, func(), error) {
	// Apply OTEL overrides from config before parsing env
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
		if err := otel.ShutdownProvider(tp, shutdownCtx); err != nil {
			log.Printf("error shutting down OTEL provider: %v", err)
		}
	}

	return tp.Tracer("process-tracer-daemon"), cleanup, nil
}

func setupBPF(ringBufferSize int) (*bpfloader.Loader, *ringbuf.Reader, func(), error) {
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
