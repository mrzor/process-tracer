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

// logConnectionInfo logs proxy and TLS configuration for debugging.
func logConnectionInfo(cfg *config.OTELConfig) {
	httpProxy := os.Getenv("HTTP_PROXY")
	if httpProxy == "" {
		httpProxy = os.Getenv("http_proxy")
	}
	httpsProxy := os.Getenv("HTTPS_PROXY")
	if httpsProxy == "" {
		httpsProxy = os.Getenv("https_proxy")
	}

	if httpProxy != "" || httpsProxy != "" {
		log.Printf("Proxy configuration: HTTP_PROXY=%q HTTPS_PROXY=%q", httpProxy, httpsProxy) //nolint:gosec // Values from environment, not user input
	} else {
		log.Printf("No proxy configured (HTTP_PROXY/HTTPS_PROXY not set)")
	}

	if cfg.IsInsecure() {
		log.Printf("TLS: disabled (reason: %s)", cfg.InsecureReason())
	} else {
		log.Printf("TLS: enabled (reason: %s)", cfg.InsecureReason())
		// Note useful TLS env vars if they're set
		if cert := os.Getenv("OTEL_EXPORTER_OTLP_CERTIFICATE"); cert != "" {
			log.Printf("  CA certificate: %s", cert) //nolint:gosec // File path from environment, not user input
		}
		if clientCert := os.Getenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE"); clientCert != "" {
			log.Printf("  Client certificate: %s (mTLS)", clientCert) //nolint:gosec // File path from environment, not user input
		}
	}
}

// InitProvider initializes the OpenTelemetry tracer provider and establishes
// connection to the OTLP endpoint. Returns error if initialization fails.
//
// Uses OTLP/HTTP protocol. The HTTP client automatically honors HTTP_PROXY,
// HTTPS_PROXY, and NO_PROXY environment variables through Go's standard net/http transport.
//
// TLS behavior: HTTPS by default for non-localhost endpoints. Set OTEL_EXPORTER_OTLP_INSECURE=true
// to force plain HTTP, or use an http:// scheme in the endpoint URL. Localhost endpoints
// default to insecure for convenience. TLS certificates, mTLS, headers, compression,
// and timeout are all configurable via standard OTEL_EXPORTER_OTLP_* env vars
// handled natively by the otlptracehttp library (see OTELConfig doc comment for full list).
func InitProvider(cfg *config.OTELConfig, versionInfo string) (*sdktrace.TracerProvider, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	endpoint := cfg.GetEndpoint()

	// Log OTEL configuration for debugging
	log.Printf("OTEL Configuration:")
	log.Printf("  Service Name: %s", cfg.ServiceName)
	log.Printf("  Endpoint: %s", endpoint)
	if cfg.ResourceAttributes != "" {
		log.Printf("  Resource Attributes: %s", cfg.ResourceAttributes)
	}

	logConnectionInfo(cfg)

	// Create OTLP trace exporter
	// Endpoint and TLS options are derived from config; timeout, headers,
	// compression, and certificates are handled by the library's own env var parsing.
	opts := cfg.EndpointOptions()
	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP trace exporter: %w", err)
	}

	// Build resource attributes
	resourceAttrs := []resource.Option{
		resource.WithAttributes(semconv.ServiceName(cfg.ServiceName)),
	}

	// Add service version if available
	if versionInfo != "" && versionInfo != "dev" {
		resourceAttrs = append(resourceAttrs,
			resource.WithAttributes(
				semconv.ServiceVersion(versionInfo),
			),
		)
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
