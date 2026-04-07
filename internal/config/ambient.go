package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// AmbientConfig holds the configuration for ambient (daemon) mode.
type AmbientConfig struct {
	Rules  []AmbientRule  `yaml:"rules"`
	Limits AmbientLimits  `yaml:"limits"`
	OTEL   AmbientOTEL    `yaml:"otel"`
}

// AmbientRule defines a process matching rule and its tracing configuration.
type AmbientRule struct {
	Name       string            `yaml:"name"`
	Match      AmbientMatch      `yaml:"match"`
	Attributes map[string]string `yaml:"attributes"`
	TraceID    string            `yaml:"trace_id"`
	ParentID   string            `yaml:"parent_id"`
}

// AmbientMatch defines the criteria for matching a process.
type AmbientMatch struct {
	Command string `yaml:"command"` // glob pattern matched against comm (16-char kernel name)
}

// AmbientLimits defines resource limits for the daemon.
type AmbientLimits struct {
	MaxConcurrentSessions int           `yaml:"max_concurrent_sessions"`
	MaxPIDsPerSession     int           `yaml:"max_pids_per_session"`
	MaxTotalPIDs          int           `yaml:"max_total_pids"`
	SessionTimeout        time.Duration `yaml:"session_timeout"`
	RingBufferSize        int           `yaml:"ring_buffer_size"`
}

// AmbientOTEL allows overriding OTEL settings in the config file.
type AmbientOTEL struct {
	Endpoint    string `yaml:"endpoint"`
	ServiceName string `yaml:"service_name"`
}

// ambientDefaults returns an AmbientConfig with sensible defaults.
func ambientDefaults() AmbientConfig {
	return AmbientConfig{
		Limits: AmbientLimits{
			MaxConcurrentSessions: 100,
			MaxPIDsPerSession:     1000,
			MaxTotalPIDs:          8000,
			SessionTimeout:        1 * time.Hour,
			RingBufferSize:        8 * 1024 * 1024, // 8MB
		},
	}
}

// LoadAmbientConfig loads and validates an ambient mode config from a YAML file.
func LoadAmbientConfig(path string) (*AmbientConfig, error) {
	data, err := os.ReadFile(path) //nolint:gosec // config file path is intentionally user-provided
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := ambientDefaults()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

func (c *AmbientConfig) validate() error {
	if len(c.Rules) == 0 {
		return fmt.Errorf("at least one rule is required")
	}
	for i, r := range c.Rules {
		if r.Name == "" {
			return fmt.Errorf("rule %d: name is required", i)
		}
		if r.Match.Command == "" {
			return fmt.Errorf("rule %q: match.command is required", r.Name)
		}
	}
	if c.Limits.MaxTotalPIDs > 10240 {
		return fmt.Errorf("max_total_pids cannot exceed BPF map size (10240)")
	}
	return nil
}

// CustomAttributesForRule converts a rule's attributes map to CustomAttribute slice.
func CustomAttributesForRule(r *AmbientRule) []CustomAttribute {
	attrs := make([]CustomAttribute, 0, len(r.Attributes))
	for name, value := range r.Attributes {
		attrs = append(attrs, CustomAttribute{Name: name, Expression: value})
	}
	return attrs
}
