package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/caarlos0/env/v11"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
)

// OTELConfig holds OpenTelemetry configuration from environment variables.
//
// The following env vars are parsed and managed by us:
//
//   - OTEL_SERVICE_NAME           — service name (default: "sched_trace")
//   - OTEL_RESOURCE_ATTRIBUTES    — comma-separated key=value resource attributes
//   - OTEL_EXPORTER_OTLP_ENDPOINT — base endpoint URL or host:port (default: localhost:4318)
//   - OTEL_EXPORTER_OTLP_INSECURE — force plain HTTP when "true" (default: auto-detect from endpoint)
//
// The following env vars are handled natively by the otlptracehttp library.
// We do not parse them, but they are effective at runtime:
//
//   - OTEL_EXPORTER_OTLP_TRACES_ENDPOINT               — traces-specific endpoint (overrides OTEL_EXPORTER_OTLP_ENDPOINT)
//   - OTEL_EXPORTER_OTLP_HEADERS / _TRACES_HEADERS     — request headers (W3C Baggage format)
//   - OTEL_EXPORTER_OTLP_TIMEOUT / _TRACES_TIMEOUT     — export timeout in ms (default: 10000)
//   - OTEL_EXPORTER_OTLP_COMPRESSION / _TRACES_COMPRESSION — "gzip" to enable compression
//   - OTEL_EXPORTER_OTLP_CERTIFICATE / _TRACES_CERTIFICATE — path to server CA certificate (TLS)
//   - OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE / _TRACES_CLIENT_CERTIFICATE — client cert for mTLS
//   - OTEL_EXPORTER_OTLP_CLIENT_KEY / _TRACES_CLIENT_KEY — client private key for mTLS
type OTELConfig struct {
	ServiceName        string `env:"OTEL_SERVICE_NAME" envDefault:"sched_trace"`
	ResourceAttributes string `env:"OTEL_RESOURCE_ATTRIBUTES" envDefault:""`
	ExporterEndpoint   string `env:"OTEL_EXPORTER_OTLP_ENDPOINT" envDefault:""`
	Insecure           string `env:"OTEL_EXPORTER_OTLP_INSECURE" envDefault:""`
}

// ParseOTELConfig parses OTEL configuration from environment variables.
func ParseOTELConfig() (*OTELConfig, error) {
	var cfg OTELConfig
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse OTEL config: %w", err)
	}
	return &cfg, nil
}

// GetEndpoint returns the configured endpoint string, or the default.
func (c *OTELConfig) GetEndpoint() string {
	if c.ExporterEndpoint != "" {
		return c.ExporterEndpoint
	}
	return "localhost:4318"
}

// isLocalhostHost returns true if the host part is a loopback address.
func isLocalhostHost(host string) bool {
	// Strip port if present
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host // no port
	}
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// IsInsecure determines whether to use plain HTTP based on configuration.
// Priority: explicit OTEL_EXPORTER_OTLP_INSECURE > endpoint scheme > localhost heuristic.
func (c *OTELConfig) IsInsecure() bool {
	// Explicit override
	if strings.EqualFold(c.Insecure, "true") {
		return true
	}
	if strings.EqualFold(c.Insecure, "false") {
		return false
	}

	endpoint := c.GetEndpoint()

	// Scheme-based detection
	if strings.HasPrefix(endpoint, "http://") {
		return true
	}
	if strings.HasPrefix(endpoint, "https://") {
		return false
	}

	// No scheme — localhost defaults to insecure for convenience
	return isLocalhostHost(endpoint)
}

// InsecureReason returns a human-readable reason for the TLS mode decision.
func (c *OTELConfig) InsecureReason() string {
	if strings.EqualFold(c.Insecure, "true") {
		return "OTEL_EXPORTER_OTLP_INSECURE=true"
	}
	if strings.EqualFold(c.Insecure, "false") {
		return "OTEL_EXPORTER_OTLP_INSECURE=false"
	}

	endpoint := c.GetEndpoint()
	if strings.HasPrefix(endpoint, "http://") {
		return "endpoint has http:// scheme"
	}
	if strings.HasPrefix(endpoint, "https://") {
		return "endpoint has https:// scheme"
	}
	if isLocalhostHost(endpoint) {
		return "localhost endpoint defaults to insecure"
	}
	return "non-localhost endpoint defaults to HTTPS"
}

// EndpointOptions returns the otlptracehttp options for endpoint and TLS configuration.
func (c *OTELConfig) EndpointOptions() []otlptracehttp.Option {
	endpoint := c.GetEndpoint()
	var opts []otlptracehttp.Option

	// If the endpoint has a scheme, use WithEndpointURL to preserve it.
	// Otherwise use WithEndpoint for bare host:port.
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		opts = append(opts, otlptracehttp.WithEndpointURL(endpoint))
	} else {
		opts = append(opts, otlptracehttp.WithEndpoint(endpoint))
	}

	if c.IsInsecure() {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	return opts
}

// ParseResourceAttributes parses the OTEL_RESOURCE_ATTRIBUTES string.
// Format: key1=value1,key2=value2.
func (c *OTELConfig) ParseResourceAttributes() []attribute.KeyValue {
	if c.ResourceAttributes == "" {
		return nil
	}

	var attrs []attribute.KeyValue
	pairs := strings.Split(c.ResourceAttributes, ",")
	for _, pair := range pairs {
		kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(kv) == 2 {
			key := strings.TrimSpace(kv[0])
			value := strings.TrimSpace(kv[1])
			if key != "" {
				attrs = append(attrs, attribute.String(key, value))
			}
		}
	}
	return attrs
}

// EndpointHost extracts just the host (without scheme/port) for display purposes.
func (c *OTELConfig) EndpointHost() string {
	endpoint := c.GetEndpoint()
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		if u, err := url.Parse(endpoint); err == nil {
			return u.Host
		}
	}
	return endpoint
}
