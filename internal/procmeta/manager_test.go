package procmeta

import (
	"errors"
	"testing"
)

func TestManager_SetAndGet(t *testing.T) {
	m := NewManager()

	metadata := &ProcessMetadata{
		Environ:     map[string]string{"FOO": "bar"},
		Args:        []string{"echo", "hello"},
		CmdlineFull: "echo hello",
	}

	m.Set(1234, metadata)

	got := m.Get(1234)
	if got == nil {
		t.Fatal("Get() returned nil")
	}

	if got.Environ["FOO"] != "bar" {
		t.Errorf("metadata.Environ[FOO] = %q, want bar", got.Environ["FOO"])
	}
}

func TestManager_GetNonExistent(t *testing.T) {
	m := NewManager()

	got := m.Get(9999)
	if got != nil {
		t.Error("Expected nil for non-existent PID")
	}
}

func TestManager_SetError(t *testing.T) {
	m := NewManager()

	testErr := errors.New("test error")
	m.SetError(1234, testErr)

	got := m.GetError(1234)
	if got == nil {
		t.Fatal("GetError() returned nil")
	}

	if got.Error() != "test error" {
		t.Errorf("GetError() = %q, want test error", got.Error())
	}
}

func TestManager_AddIssue(t *testing.T) {
	m := NewManager()

	m.AddIssue(1234, "issue 1")
	m.AddIssue(1234, "issue 2")

	issues := m.GetIssues(1234)
	if len(issues) != 2 {
		t.Errorf("GetIssues() length = %d, want 2", len(issues))
	}

	if issues[0] != "issue 1" || issues[1] != "issue 2" {
		t.Errorf("GetIssues() = %v, want [issue 1, issue 2]", issues)
	}
}

func TestManager_AddIssues(t *testing.T) {
	m := NewManager()

	m.AddIssues(1234, []string{"issue 1", "issue 2"})

	issues := m.GetIssues(1234)
	if len(issues) != 2 {
		t.Errorf("GetIssues() length = %d, want 2", len(issues))
	}
}

func TestManager_Delete(t *testing.T) {
	m := NewManager()

	metadata := &ProcessMetadata{
		Environ: map[string]string{"FOO": "bar"},
	}
	testErr := errors.New("test error")

	m.Set(1234, metadata)
	m.SetError(1234, testErr)
	m.AddIssue(1234, "issue 1")

	// Verify data exists
	if m.Get(1234) == nil {
		t.Error("Metadata should exist before delete")
	}
	if m.GetError(1234) == nil {
		t.Error("Error should exist before delete")
	}
	if len(m.GetIssues(1234)) == 0 {
		t.Error("Issues should exist before delete")
	}

	// Delete
	m.Delete(1234)

	// Verify data is gone
	if m.Get(1234) != nil {
		t.Error("Metadata should be nil after delete")
	}
	if m.GetError(1234) != nil {
		t.Error("Error should be nil after delete")
	}
	if m.GetIssues(1234) != nil {
		t.Error("Issues should be nil after delete")
	}
}

func TestManager_GetOrCreate(t *testing.T) {
	m := NewManager()

	// Should create new metadata
	metadata := m.GetOrCreate(1234)
	if metadata == nil {
		t.Fatal("GetOrCreate() returned nil")
	}

	if metadata.Environ == nil {
		t.Error("Environ map should be initialized")
	}

	// Should return existing metadata
	metadata.Environ["TEST"] = "value"
	metadata2 := m.GetOrCreate(1234)

	if metadata2.Environ["TEST"] != "value" {
		t.Error("GetOrCreate() should return existing metadata")
	}

	// Verify same instance
	if metadata != metadata2 {
		t.Error("GetOrCreate() should return same instance")
	}
}

func TestManager_Concurrent(_ *testing.T) {
	m := NewManager()

	// Test concurrent access
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 100; i++ {
			metadata := &ProcessMetadata{
				Environ: map[string]string{"key": "value"},
			}
			//nolint:gosec // Test loop with bounded range
			m.Set(uint32(i), metadata)
			m.AddIssue(uint32(i), "issue")
		}
		done <- true
	}()

	// Reader goroutine
	//nolint:gosec // Test loop with bounded range
	go func() {
		for i := 0; i < 100; i++ {
			_ = m.Get(uint32(i))
			_ = m.GetIssues(uint32(i))
		}
		done <- true
	}()

	// Wait for both goroutines
	<-done
	<-done
}
