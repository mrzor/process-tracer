package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// AmbientConfig holds the configuration for daemon mode.
type AmbientConfig struct {
	Rules  []AmbientRule  `yaml:"rules"`
	Limits AmbientLimits  `yaml:"limits"`
	OTEL   AmbientOTEL    `yaml:"otel"`
}

// AmbientRule defines a process matching rule and its tracing configuration.
type AmbientRule struct {
	Name               string            `yaml:"name"`
	Match              AmbientMatch      `yaml:"match"`
	Attributes         map[string]string `yaml:"attributes"`
	SkipEmptyValues    bool              `yaml:"skip_empty_values"`
	TraceID            string            `yaml:"trace_id"`
	ParentID           string            `yaml:"parent_id"`
	AddDebugAttributes bool              `yaml:"add_debug_attributes"`

	// ContextStarved marks this rule's root process as unable to carry useful
	// context on its own (e.g. `runc exec`: the injector's execve envp lacks
	// the CI_* variables we want for trace_id/attrs — those live on some
	// descendant's exec event, potentially several levels below).
	//
	// When true, a match does NOT start an OTEL session immediately. Instead,
	// a pending session is held; every descendant exec (at any depth) is
	// tried against the rule's Expr expressions (trace_id / parent_id /
	// attributes), and the session materializes at the first descendant
	// whose metadata makes any expression resolve to a non-empty value.
	// If no descendant resolves before session_timeout, the pending session
	// is dropped.
	ContextStarved bool `yaml:"context_starved"`
}

// AmbientMatch defines the criteria for matching a process.
// At least one of Command or IsContainerInit must be set.
// When both are set, both must match.
type AmbientMatch struct {
	Command         string `yaml:"command"`           // glob pattern matched against comm (16-char kernel name)
	IsContainerInit bool   `yaml:"is_container_init"` // match processes that are PID 1 in a non-root PID namespace
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

// LoadAmbientConfig loads and validates a daemon mode config from a YAML file.
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
		if r.Match.Command == "" && !r.Match.IsContainerInit {
			return fmt.Errorf("rule %q: at least one of match.command or match.is_container_init is required", r.Name)
		}
		if r.ContextStarved && r.TraceID == "" && r.ParentID == "" && len(r.Attributes) == 0 {
			return fmt.Errorf("rule %q: context_starved requires at least one of trace_id, parent_id, or attributes to define what 'context-ful' means for materialization", r.Name)
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
