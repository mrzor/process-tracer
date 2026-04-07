package ambient

import (
	"testing"
	"time"

	"github.com/mrzor/process-tracer/internal/config"
	"github.com/mrzor/process-tracer/internal/procmeta"
	"github.com/mrzor/process-tracer/internal/reversedns"
	"github.com/mrzor/process-tracer/internal/timesync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// --- mock PID tracker ---

type mockTracker struct {
	tracked map[int]bool
}

func newMockTracker() *mockTracker {
	return &mockTracker{tracked: make(map[int]bool)}
}

func (m *mockTracker) TrackPID(pid int) error {
	m.tracked[pid] = true
	return nil
}

func (m *mockTracker) UntrackPID(pid int) error {
	delete(m.tracked, pid)
	return nil
}

// --- FilterEngine ---

func TestFilterEngine_MatchingScenarios(t *testing.T) {
	engine := NewFilterEngine([]config.AmbientRule{
		{Name: "builds", Match: config.AmbientMatch{Command: "make"}},
		{Name: "deploys", Match: config.AmbientMatch{Command: "deploy-*"}},
		{Name: "shells", Match: config.AmbientMatch{Command: "bash"}},
	})

	// Exact match
	r := engine.Match("make")
	require.NotNil(t, r)
	assert.Equal(t, "builds", r.Name)

	// Glob match
	r = engine.Match("deploy-staging")
	require.NotNil(t, r)
	assert.Equal(t, "deploys", r.Name)

	// Kernel comm is null-padded to 16 bytes
	r = engine.Match("bash\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	require.NotNil(t, r)
	assert.Equal(t, "shells", r.Name)

	// No match
	assert.Nil(t, engine.Match("python"))

	// First-match wins: if a comm matched two rules, we get the first
	engine2 := NewFilterEngine([]config.AmbientRule{
		{Name: "first", Match: config.AmbientMatch{Command: "make*"}},
		{Name: "second", Match: config.AmbientMatch{Command: "make"}},
	})
	r = engine2.Match("make")
	require.NotNil(t, r)
	assert.Equal(t, "first", r.Name)
}

// --- SessionManager ---

func newTestManager(t *testing.T, tracker *mockTracker, limits config.AmbientLimits) *SessionManager {
	t.Helper()
	tracer := tracenoop.NewTracerProvider().Tracer("test")
	converter, err := timesync.NewConverter()
	require.NoError(t, err)
	return NewSessionManager(
		tracker, tracer, converter, reversedns.New(), procmeta.NewManager(), limits,
	)
}

func defaultLimits() config.AmbientLimits {
	return config.AmbientLimits{
		MaxConcurrentSessions: 100,
		MaxPIDsPerSession:     100,
		MaxTotalPIDs:          1000,
		SessionTimeout:        time.Hour,
	}
}

var testRule = &config.AmbientRule{Name: "test", Match: config.AmbientMatch{Command: "make"}}

func TestSessionManager_SessionLifecycle(t *testing.T) {
	// Scenario: a process tree spawns (root -> child -> grandchild), all exit in reverse order,
	// and the session is cleaned up when the last PID exits.
	tracker := newMockTracker()
	mgr := newTestManager(t, tracker, defaultLimits())

	// Root process is created
	session, err := mgr.CreateSession(100, testRule, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, mgr.ActiveSessions())
	assert.True(t, tracker.tracked[100], "root PID should be tracked in BPF")

	// Route check
	assert.Equal(t, session, mgr.RouteByPID(100))
	assert.Nil(t, mgr.RouteByPID(999), "unknown PID should not route")

	// Child spawns (BPF auto-tracks it, Go adds it to the session)
	childSession := mgr.AddDescendant(101, 100)
	assert.Equal(t, session, childSession)

	// Grandchild spawns
	grandchildSession := mgr.AddDescendant(102, 101)
	assert.Equal(t, session, grandchildSession)

	// All three PIDs route to the same session
	assert.Equal(t, session, mgr.RouteByPID(100))
	assert.Equal(t, session, mgr.RouteByPID(101))
	assert.Equal(t, session, mgr.RouteByPID(102))

	// Grandchild exits - session still alive
	s, complete := mgr.HandleExit(102)
	assert.Equal(t, session, s)
	assert.False(t, complete)
	assert.Equal(t, 1, mgr.ActiveSessions())

	// Root exits - session draining but child still alive
	s, complete = mgr.HandleExit(100)
	assert.Equal(t, session, s)
	assert.False(t, complete)
	assert.True(t, session.Draining)
	assert.Equal(t, 1, mgr.ActiveSessions())

	// Last child exits - session complete
	s, complete = mgr.HandleExit(101)
	assert.Equal(t, session, s)
	assert.True(t, complete)
	assert.Equal(t, 0, mgr.ActiveSessions())
}

func TestSessionManager_ConcurrentSessionLimit(t *testing.T) {
	tracker := newMockTracker()
	limits := defaultLimits()
	limits.MaxConcurrentSessions = 2
	mgr := newTestManager(t, tracker, limits)

	_, err := mgr.CreateSession(100, testRule, nil)
	require.NoError(t, err)

	_, err = mgr.CreateSession(200, testRule, nil)
	require.NoError(t, err)

	// Third session is rejected
	_, err = mgr.CreateSession(300, testRule, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max concurrent sessions")
	assert.Equal(t, 2, mgr.ActiveSessions())

	// After one session completes, a new one can be created
	mgr.HandleExit(100)
	_, err = mgr.CreateSession(300, testRule, nil)
	require.NoError(t, err)
}

func TestSessionManager_PerSessionPIDLimit(t *testing.T) {
	tracker := newMockTracker()
	limits := defaultLimits()
	limits.MaxPIDsPerSession = 3 // root + 2 descendants
	mgr := newTestManager(t, tracker, limits)

	_, err := mgr.CreateSession(100, testRule, nil)
	require.NoError(t, err)

	assert.NotNil(t, mgr.AddDescendant(101, 100))
	assert.NotNil(t, mgr.AddDescendant(102, 100))

	// Fourth PID in this session is rejected
	assert.Nil(t, mgr.AddDescendant(103, 100))
}

func TestSessionManager_TotalPIDLimit(t *testing.T) {
	// Two sessions competing for a shared PID pool of 4
	tracker := newMockTracker()
	limits := defaultLimits()
	limits.MaxTotalPIDs = 4
	mgr := newTestManager(t, tracker, limits)

	_, err := mgr.CreateSession(100, testRule, nil) // total: 1
	require.NoError(t, err)
	mgr.AddDescendant(101, 100) // total: 2

	_, err = mgr.CreateSession(200, testRule, nil) // total: 3
	require.NoError(t, err)
	mgr.AddDescendant(201, 200) // total: 4

	// Both sessions hit the global ceiling
	assert.Nil(t, mgr.AddDescendant(102, 100))
	assert.Nil(t, mgr.AddDescendant(202, 200))

	// Freeing a PID opens a slot
	mgr.HandleExit(101) // total: 3
	assert.NotNil(t, mgr.AddDescendant(203, 200))
}

func TestSessionManager_StaleSessionCleanup(t *testing.T) {
	tracker := newMockTracker()
	limits := defaultLimits()
	limits.SessionTimeout = 50 * time.Millisecond
	mgr := newTestManager(t, tracker, limits)

	_, err := mgr.CreateSession(100, testRule, nil)
	require.NoError(t, err)
	mgr.AddDescendant(101, 100)

	assert.True(t, tracker.tracked[100])
	assert.Equal(t, 1, mgr.ActiveSessions())

	// Wait for session to become stale
	time.Sleep(60 * time.Millisecond)
	mgr.CleanupStale()

	assert.Equal(t, 0, mgr.ActiveSessions())
	assert.Nil(t, mgr.RouteByPID(100))
	assert.Nil(t, mgr.RouteByPID(101))
}

func TestSessionManager_UnknownExitIsIgnored(t *testing.T) {
	tracker := newMockTracker()
	mgr := newTestManager(t, tracker, defaultLimits())

	// EXIT for a PID not in any session - should not panic
	s, complete := mgr.HandleExit(999)
	assert.Nil(t, s)
	assert.False(t, complete)
}
