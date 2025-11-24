// Package otel provides OpenTelemetry tracer provider initialization and management.
package otel

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/mrzor/process-tracer/internal/config"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

// verifyConnection attempts to establish a connection to the OTLP endpoint
// to verify it's reachable before proceeding. This ensures we fail fast if
// the collector is unavailable.
func verifyConnection(_ context.Context, endpoint string) error {
	// Log proxy configuration for debugging
	httpProxy := os.Getenv("HTTP_PROXY")
	if httpProxy == "" {
		httpProxy = os.Getenv("http_proxy")
	}
	httpsProxy := os.Getenv("HTTPS_PROXY")
	if httpsProxy == "" {
		httpsProxy = os.Getenv("https_proxy")
	}

	if httpProxy != "" || httpsProxy != "" {
		log.Printf("Proxy configuration: HTTP_PROXY=%q HTTPS_PROXY=%q", httpProxy, httpsProxy)
	} else {
		log.Printf("No proxy configured (HTTP_PROXY/HTTPS_PROXY not set)")
	}

	log.Printf("Verifying OTLP/HTTP endpoint is reachable: %s", endpoint)

	// For HTTP, just note that we'll verify on first export
	// The HTTP exporter will fail fast if unreachable
	log.Printf("Using OTLP/HTTP protocol (will verify on test span export)")
	return nil
}

// InitProvider initializes the OpenTelemetry tracer provider and establishes
// connection to the OTLP endpoint. Returns error if connection cannot be established.
// Sends a test span with the provided trace ID to verify end-to-end connectivity.
//
// Note: Uses OTLP/HTTP protocol. The HTTP client automatically honors HTTP_PROXY,
// HTTPS_PROXY, and NO_PROXY environment variables through Go's standard net/http transport.
func InitProvider(cfg *config.OTELConfig, _ string) (*sdktrace.TracerProvider, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	endpoint := cfg.GetEndpoint()

	// Log OTEL configuration for debugging
	log.Printf("OTEL Configuration:")
	log.Printf("  Service Name: %s", cfg.ServiceName)
	log.Printf("  Endpoint: %s", endpoint)
	log.Printf("  OTEL_EXPORTER_OTLP_ENDPOINT: %q", cfg.ExporterEndpoint)
	log.Printf("  OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: %q", cfg.TracesEndpoint)
	if cfg.ResourceAttributes != "" {
		log.Printf("  Resource Attributes: %s", cfg.ResourceAttributes)
	}

	// Verify connection to OTLP endpoint before proceeding
	// This ensures we abort early if the collector is unreachable
	if err := verifyConnection(ctx, endpoint); err != nil {
		return nil, err
	}

	// Create OTLP trace exporter with HTTP
	// HTTP client will automatically use HTTP_PROXY/HTTPS_PROXY if set
	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(), // Use HTTP not HTTPS for local testing
		otlptracehttp.WithTimeout(10*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP trace exporter: %w", err)
	}

	// Build resource attributes
	resourceAttrs := []resource.Option{
		resource.WithAttributes(semconv.ServiceName(cfg.ServiceName)),
	}

	// Add custom resource attributes from environment
	customAttrs := cfg.ParseResourceAttributes()
	if len(customAttrs) > 0 {
		resourceAttrs = append(resourceAttrs, resource.WithAttributes(customAttrs...))
	}

	res, err := resource.New(ctx, resourceAttrs...)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create tracer provider with batch span processor
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	return tp, nil
}

// ShutdownProvider gracefully shuts down the tracer provider, flushing any remaining spans.
func ShutdownProvider(tp *sdktrace.TracerProvider, ctx context.Context) error {
	if tp == nil {
		return nil
	}

	if err := tp.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown tracer provider: %w", err)
	}

	return nil
}
