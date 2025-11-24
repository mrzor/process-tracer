package envreassembler

import (
	"testing"

	"github.com/mrzor/process-tracer/internal/bpf"
)

func TestStreamingReassembler_HandleVar(t *testing.T) {
	s := NewStreamingReassembler()

	// First arg
	arg0 := &bpf.EnvVarEvent{
		Pid:      1234,
		VarIndex: 0,
		IsArgv:   1,
		IsFinal:  0,
		DataSize: 4,
	}
	copy(arg0.Data[:], []byte("echo"))

	result, err := s.HandleVar(arg0)
	if err != nil {
		t.Fatalf("HandleVar() error = %v", err)
	}
	if result != nil {
		t.Error("Expected nil result for non-final var")
	}

	// Second arg
	arg1 := &bpf.EnvVarEvent{
		Pid:      1234,
		VarIndex: 1,
		IsArgv:   1,
		IsFinal:  0,
		DataSize: 5,
	}
	copy(arg1.Data[:], []byte("hello"))

	result, _ = s.HandleVar(arg1) //nolint:errcheck // Test setup - intentionally ignoring non-final var
	if result != nil {
		t.Error("Expected nil result for non-final var")
	}

	// Environment variable
	env0 := &bpf.EnvVarEvent{
		Pid:      1234,
		VarIndex: 0,
		IsArgv:   0,
		IsFinal:  0,
		DataSize: 13,
	}
	copy(env0.Data[:], []byte("PATH=/usr/bin"))

	result, _ = s.HandleVar(env0) //nolint:errcheck // Test setup - intentionally ignoring non-final var
	if result != nil {
		t.Error("Expected nil result for non-final var")
	}

	// Final marker
	final := &bpf.EnvVarEvent{
		Pid:      1234,
		VarIndex: 1,
		IsArgv:   0,
		IsFinal:  1,
		DataSize: 10,
	}
	copy(final.Data[:], []byte("USER=admin"))

	result, err = s.HandleVar(final)
	if err != nil {
		t.Fatalf("HandleVar() error = %v", err)
	}
	if result == nil {
		t.Fatal("Expected result for final var")
	}

	// Verify result
	if len(result.Args) != 2 {
		t.Errorf("args count = %d, want 2", len(result.Args))
	}
	if result.Args[0] != "echo" || result.Args[1] != "hello" {
		t.Errorf("args = %v, want [echo hello]", result.Args)
	}

	if len(result.Env) != 2 {
		t.Errorf("env count = %d, want 2", len(result.Env))
	}
	if result.Env["PATH"] != "/usr/bin" {
		t.Errorf("env[PATH] = %q, want /usr/bin", result.Env["PATH"])
	}
	if result.Env["USER"] != "admin" {
		t.Errorf("env[USER] = %q, want admin", result.Env["USER"])
	}
}

func TestStreamingReassembler_GappedIndices(t *testing.T) {
	s := NewStreamingReassembler()

	// Send args at indices 0 and 2 (skip 1)
	arg0 := &bpf.EnvVarEvent{
		Pid:      1234,
		VarIndex: 0,
		IsArgv:   1,
		DataSize: 2,
	}
	copy(arg0.Data[:], []byte("ls"))

	_, _ = s.HandleVar(arg0) //nolint:errcheck // Test setup - sending first arg before testing gap handling

	arg2 := &bpf.EnvVarEvent{
		Pid:      1234,
		VarIndex: 2,
		IsArgv:   1,
		IsFinal:  1,
		DataSize: 4,
	}
	copy(arg2.Data[:], []byte("/tmp"))

	result, err := s.HandleVar(arg2)
	if err != nil {
		t.Fatalf("HandleVar() error = %v", err)
	}

	// Should only have 2 args (indices 0 and 2), not 3
	if len(result.Args) != 2 {
		t.Errorf("args count = %d, want 2 (gapped indices should be filtered)", len(result.Args))
	}
	if result.Args[0] != "ls" {
		t.Errorf("args[0] = %q, want ls", result.Args[0])
	}
	if result.Args[1] != "/tmp" {
		t.Errorf("args[1] = %q, want /tmp", result.Args[1])
	}
}

func TestStreamingReassembler_Truncated(t *testing.T) {
	s := NewStreamingReassembler()

	arg := &bpf.EnvVarEvent{
		Pid:       1234,
		VarIndex:  0,
		IsArgv:    1,
		IsFinal:   1,
		Truncated: 1,
		DataSize:  4,
	}
	copy(arg.Data[:], []byte("echo"))

	result, err := s.HandleVar(arg)
	if err != nil {
		t.Fatalf("HandleVar() error = %v", err)
	}

	if !result.Truncated {
		t.Error("Expected Truncated flag to be set")
	}

	// Should have truncation warning in issues
	found := false
	for _, issue := range result.Issues {
		if issue == "some variables truncated: captured 1 args, 0 env vars" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected truncation issue, got: %v", result.Issues)
	}
}

func TestStreamingReassembler_EnvParsing(t *testing.T) {
	s := NewStreamingReassembler()

	// Env var with equals sign in value
	env0 := &bpf.EnvVarEvent{
		Pid:      1234,
		VarIndex: 0,
		IsArgv:   0,
		IsFinal:  1,
		DataSize: 11,
	}
	copy(env0.Data[:], []byte("FOO=bar=baz"))

	result, err := s.HandleVar(env0)
	if err != nil {
		t.Fatalf("HandleVar() error = %v", err)
	}

	// Should parse as FOO -> bar=baz (only first = is the separator)
	if result.Env["FOO"] != "bar=baz" {
		t.Errorf("env[FOO] = %q, want bar=baz", result.Env["FOO"])
	}
}
