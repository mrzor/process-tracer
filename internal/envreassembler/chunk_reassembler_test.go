package envreassembler

import (
	"testing"

	"github.com/mrzor/process-tracer/internal/bpf"
)

func TestParseNullTerminatedStrings(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantArgs []string
		wantEnv  map[string]string
	}{
		{
			name:     "empty data",
			data:     []byte{},
			wantArgs: []string{},
			wantEnv:  map[string]string{},
		},
		{
			name:     "only args",
			data:     []byte("ls\x00-la\x00/tmp\x00"),
			wantArgs: []string{"ls", "-la", "/tmp"},
			wantEnv:  map[string]string{},
		},
		{
			name:     "only env",
			data:     []byte("PATH=/usr/bin\x00HOME=/home/user\x00"),
			wantArgs: []string{},
			wantEnv:  map[string]string{"PATH": "/usr/bin", "HOME": "/home/user"},
		},
		{
			name:     "args and env mixed",
			data:     []byte("echo\x00hello\x00PATH=/bin\x00USER=test\x00"),
			wantArgs: []string{"echo", "hello"},
			wantEnv:  map[string]string{"PATH": "/bin", "USER": "test"},
		},
		{
			name:     "env with empty value",
			data:     []byte("EMPTY=\x00"),
			wantArgs: []string{},
			wantEnv:  map[string]string{"EMPTY": ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotArgs, gotEnv := parseNullTerminatedStrings(tt.data)

			// Check args
			if len(gotArgs) != len(tt.wantArgs) {
				t.Errorf("args count = %d, want %d", len(gotArgs), len(tt.wantArgs))
			}
			for i, arg := range tt.wantArgs {
				if i >= len(gotArgs) || gotArgs[i] != arg {
					t.Errorf("args[%d] = %q, want %q", i, gotArgs[i], arg)
				}
			}

			// Check env
			if len(gotEnv) != len(tt.wantEnv) {
				t.Errorf("env count = %d, want %d", len(gotEnv), len(tt.wantEnv))
			}
			for key, val := range tt.wantEnv {
				if gotEnv[key] != val {
					t.Errorf("env[%q] = %q, want %q", key, gotEnv[key], val)
				}
			}
		})
	}
}

func TestChunkReassembler_HandleChunk(t *testing.T) {
	r := NewChunkReassembler()

	// First chunk
	chunk1 := &bpf.EnvChunkEvent{
		Pid:      1234,
		ChunkID:  0,
		DataSize: 11,
		IsFinal:  0,
	}
	copy(chunk1.Data[:], []byte("echo\x00hello\x00"))

	result, err := r.HandleChunk(chunk1)
	if err != nil {
		t.Fatalf("HandleChunk() error = %v", err)
	}
	if result != nil {
		t.Error("Expected nil result for non-final chunk")
	}

	// Second chunk (final)
	chunk2 := &bpf.EnvChunkEvent{
		Pid:      1234,
		ChunkID:  1,
		DataSize: 10,
		IsFinal:  1,
	}
	copy(chunk2.Data[:], []byte("PATH=/bin\x00"))

	result, err = r.HandleChunk(chunk2)
	if err != nil {
		t.Fatalf("HandleChunk() error = %v", err)
	}
	if result == nil {
		t.Fatal("Expected result for final chunk")
	}

	// Verify result
	if len(result.Args) != 2 {
		t.Errorf("args count = %d, want 2", len(result.Args))
	}
	if len(result.Env) != 1 {
		t.Errorf("env count = %d, want 1", len(result.Env))
	}
	if result.Env["PATH"] != "/bin" {
		t.Errorf("env[PATH] = %q, want /bin", result.Env["PATH"])
	}
}

func TestChunkReassembler_MissingChunk(t *testing.T) {
	r := NewChunkReassembler()

	// First chunk
	chunk1 := &bpf.EnvChunkEvent{
		Pid:      1234,
		ChunkID:  0,
		DataSize: 5,
		IsFinal:  0,
	}
	copy(chunk1.Data[:], []byte("echo\x00"))

	_, _ = r.HandleChunk(chunk1) //nolint:errcheck // Test setup - intentionally ignoring non-final chunk

	// Skip chunk 1, send chunk 2 as final
	chunk3 := &bpf.EnvChunkEvent{
		Pid:      1234,
		ChunkID:  2,
		DataSize: 10,
		IsFinal:  1,
	}
	copy(chunk3.Data[:], []byte("PATH=/bin\x00"))

	result, err := r.HandleChunk(chunk3)
	if err != nil {
		t.Fatalf("HandleChunk() error = %v", err)
	}

	// Should have an issue about missing chunk
	if len(result.Issues) == 0 {
		t.Error("Expected issues for missing chunk")
	}
	found := false
	for _, issue := range result.Issues {
		if issue == "data incomplete: missing chunk 1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'missing chunk 1' issue")
	}
}

func TestChunkReassembler_Truncated(t *testing.T) {
	r := NewChunkReassembler()

	chunk := &bpf.EnvChunkEvent{
		Pid:       1234,
		ChunkID:   0,
		DataSize:  5,
		IsFinal:   1,
		Truncated: 1,
	}
	copy(chunk.Data[:], []byte("echo\x00"))

	result, err := r.HandleChunk(chunk)
	if err != nil {
		t.Fatalf("HandleChunk() error = %v", err)
	}

	if !result.Truncated {
		t.Error("Expected Truncated flag to be set")
	}

	// Should have truncation warning in issues
	found := false
	for _, issue := range result.Issues {
		if issue == "data truncated: captured 1 args, 0 env vars" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected truncation issue, got: %v", result.Issues)
	}
}
