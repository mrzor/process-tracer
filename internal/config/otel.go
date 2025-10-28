package config

import (
	"fmt"
	"strings"

	"github.com/caarlos0/env/v11"
	"go.opentelemetry.io/otel/attribute"
)

// OTELConfig holds OpenTelemetry configuration from environment variables
type OTELConfig struct {
	ServiceName        string `env:"OTEL_SERVICE_NAME" envDefault:"sched_trace"`
	ResourceAttributes string `env:"OTEL_RESOURCE_ATTRIBUTES" envDefault:""`
	ExporterEndpoint   string `env:"OTEL_EXPORTER_OTLP_ENDPOINT" envDefault:""`
	TracesEndpoint     string `env:"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT" envDefault:""`
}

// ParseOTELConfig parses OTEL configuration from environment variables
func ParseOTELConfig() (*OTELConfig, error) {
	var cfg OTELConfig
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse OTEL config: %w", err)
	}
	return &cfg, nil
}

// GetEndpoint returns the appropriate endpoint for traces
// Priority: OTEL_EXPORTER_OTLP_TRACES_ENDPOINT > OTEL_EXPORTER_OTLP_ENDPOINT > default
func (c *OTELConfig) GetEndpoint() string {
	if c.TracesEndpoint != "" {
		return c.TracesEndpoint
	}
	if c.ExporterEndpoint != "" {
		return c.ExporterEndpoint
	}
	return "localhost:4317"
}

// ParseResourceAttributes parses the OTEL_RESOURCE_ATTRIBUTES string
// Format: key1=value1,key2=value2
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
