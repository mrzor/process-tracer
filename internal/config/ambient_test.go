package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadAmbientConfig_FullScenario(t *testing.T) {
	yaml := `
rules:
  - name: "ci-builds"
    match:
      command: "make"
    attributes:
      service.name: "ci"
      build.id: 'expr:env["BUILD_ID"]'
    trace_id: 'expr:env["BUILD_ID"]'
  - name: "deploys"
    match:
      command: "deploy-*"
    attributes:
      service.name: "deploy"
otel:
  endpoint: "collector:4318"
  service_name: "my-daemon"
limits:
  max_concurrent_sessions: 50
  max_pids_per_session: 500
  max_total_pids: 5000
  session_timeout: 30m
  ring_buffer_size: 4194304
`
	path := writeTemp(t, yaml)
	cfg, err := LoadAmbientConfig(path)
	require.NoError(t, err)

	// Rules parsed correctly
	require.Len(t, cfg.Rules, 2)
	assert.Equal(t, "ci-builds", cfg.Rules[0].Name)
	assert.Equal(t, "make", cfg.Rules[0].Match.Command)
	assert.Equal(t, `expr:env["BUILD_ID"]`, cfg.Rules[0].Attributes["build.id"])
	assert.Equal(t, `expr:env["BUILD_ID"]`, cfg.Rules[0].TraceID)
	assert.Equal(t, "deploy-*", cfg.Rules[1].Match.Command)

	// OTEL overrides
	assert.Equal(t, "collector:4318", cfg.OTEL.Endpoint)
	assert.Equal(t, "my-daemon", cfg.OTEL.ServiceName)

	// Explicit limits override defaults
	assert.Equal(t, 50, cfg.Limits.MaxConcurrentSessions)
	assert.Equal(t, 500, cfg.Limits.MaxPIDsPerSession)
	assert.Equal(t, 5000, cfg.Limits.MaxTotalPIDs)
	assert.Equal(t, 30*time.Minute, cfg.Limits.SessionTimeout)
	assert.Equal(t, 4194304, cfg.Limits.RingBufferSize)
}

func TestLoadAmbientConfig_DefaultsApplied(t *testing.T) {
	// Minimal config: just one rule, everything else uses defaults
	yaml := `
rules:
  - name: "test"
    match:
      command: "echo"
`
	path := writeTemp(t, yaml)
	cfg, err := LoadAmbientConfig(path)
	require.NoError(t, err)

	assert.Equal(t, 100, cfg.Limits.MaxConcurrentSessions)
	assert.Equal(t, 1000, cfg.Limits.MaxPIDsPerSession)
	assert.Equal(t, 8000, cfg.Limits.MaxTotalPIDs)
	assert.Equal(t, time.Hour, cfg.Limits.SessionTimeout)
	assert.Equal(t, 8*1024*1024, cfg.Limits.RingBufferSize)
}

func TestLoadAmbientConfig_ValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string // substring expected in error
	}{
		{
			name: "no rules",
			yaml: `rules: []`,
			want: "at least one rule",
		},
		{
			name: "rule without name",
			yaml: `
rules:
  - match:
      command: "echo"`,
			want: "name is required",
		},
		{
			name: "rule without any match criterion",
			yaml: `
rules:
  - name: "broken"
    match: {}`,
			want: "at least one of match.command or match.is_container_init is required",
		},
		{
			name: "total PIDs exceed BPF map",
			yaml: `
rules:
  - name: "test"
    match:
      command: "echo"
limits:
  max_total_pids: 20000`,
			want: "cannot exceed BPF map size",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTemp(t, tc.yaml)
			_, err := LoadAmbientConfig(path)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestLoadAmbientConfig_ContainerInit(t *testing.T) {
	yaml := `
rules:
  - name: "containers"
    match:
      is_container_init: true
    attributes:
      service.name: "container"
  - name: "container-bash"
    match:
      command: "bash"
      is_container_init: true
`
	path := writeTemp(t, yaml)
	cfg, err := LoadAmbientConfig(path)
	require.NoError(t, err)

	require.Len(t, cfg.Rules, 2)

	// is_container_init only (no command)
	assert.Empty(t, cfg.Rules[0].Match.Command)
	assert.True(t, cfg.Rules[0].Match.IsContainerInit)

	// Both command and is_container_init
	assert.Equal(t, "bash", cfg.Rules[1].Match.Command)
	assert.True(t, cfg.Rules[1].Match.IsContainerInit)
}

func TestCustomAttributesForRule(t *testing.T) {
	rule := &AmbientRule{
		Attributes: map[string]string{
			"service.name": "ci",
			"build.id":     `expr:env["BUILD_ID"]`,
		},
	}

	attrs := CustomAttributesForRule(rule)
	assert.Len(t, attrs, 2)

	// Map iteration order isn't guaranteed, so check by name
	byName := map[string]string{}
	for _, a := range attrs {
		byName[a.Name] = a.Expression
	}
	assert.Equal(t, "ci", byName["service.name"])
	assert.Equal(t, `expr:env["BUILD_ID"]`, byName["build.id"])
}

func TestLoadAmbientConfig_SkipEmptyValues(t *testing.T) {
	yaml := `
rules:
  - name: "with-skip"
    match:
      command: "make"
    skip_empty_values: true
    attributes:
      service.name: "ci"
  - name: "without-skip"
    match:
      command: "echo"
    attributes:
      service.name: "test"
`
	path := writeTemp(t, yaml)
	cfg, err := LoadAmbientConfig(path)
	require.NoError(t, err)

	require.Len(t, cfg.Rules, 2)
	assert.True(t, cfg.Rules[0].SkipEmptyValues)
	assert.False(t, cfg.Rules[1].SkipEmptyValues)
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	return path
}
