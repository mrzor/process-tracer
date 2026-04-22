package debuglog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestInit_EmptyPathLeavesNop(t *testing.T) {
	before := L
	cleanup, err := Init("")
	if err != nil {
		t.Fatalf("Init(\"\") error = %v", err)
	}
	t.Cleanup(cleanup)
	if L != before {
		t.Errorf("Init(\"\") should leave L unchanged")
	}
	// Sanity: emitting through a Nop should not panic.
	L.Info("noop_event", zap.Int("pid", 1))
}

func TestInit_WritesJSONLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "debug.json")

	cleanup, err := Init(path)
	if err != nil {
		t.Fatalf("Init error = %v", err)
	}

	L.Info("session_start", zap.Int("pid", 42), zap.String("rule", "test-rule"))
	L.Info("ancestor_weld", zap.Int("pid", 99), zap.Int("tracked_ancestor", 42))

	cleanup()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading debug log: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), string(data))
	}

	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line 1 not valid JSON: %v — %q", err, lines[0])
	}
	if first["event"] != "session_start" {
		t.Errorf("line 1 event = %v, want session_start", first["event"])
	}
	if first["rule"] != "test-rule" {
		t.Errorf("line 1 rule = %v, want test-rule", first["rule"])
	}
	pidVal, ok := first["pid"].(float64)
	if !ok || pidVal != 42 {
		t.Errorf("line 1 pid = %v, want 42", first["pid"])
	}

	// After cleanup, L should be Nop again.
	L.Info("after_cleanup_should_discard")
	data2, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("re-reading debug log: %v", err)
	}
	if string(data2) != string(data) {
		t.Errorf("write after cleanup landed in file: %q", string(data2))
	}
}
