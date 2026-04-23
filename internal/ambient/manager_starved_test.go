package ambient

import (
	"testing"
	"time"

	"github.com/mrzor/process-tracer/internal/config"
	"github.com/mrzor/process-tracer/internal/procmeta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// starvedRule returns a context-starved rule whose "context-ful" signal is
// the presence of CI_JOB_ID in the process env.
func starvedRule() *config.AmbientRule {
	return &config.AmbientRule{
		Name:           "ci-starved",
		Match:          config.AmbientMatch{Command: "runc"},
		ContextStarved: true,
		Attributes: map[string]string{
			"ci.job.id": `expr:env["CI_JOB_ID"]`,
		},
	}
}

func starvedMeta(env map[string]string, args ...string) *procmeta.ProcessMetadata {
	if env == nil {
		env = map[string]string{}
	}
	return &procmeta.ProcessMetadata{Environ: env, Args: args}
}

func TestContextStarved_EmptyResolveStaysPending(t *testing.T) {
	// A descendant whose env does NOT contain CI_JOB_ID must be buffered,
	// not materialized.
	tracker := newMockTracker()
	mgr := newTestManager(t, tracker, defaultLimits())
	rule := starvedRule()

	require.NoError(t, mgr.CreatePendingStarved(100, rule, starvedMeta(nil, "runc", "exec")))
	assert.Equal(t, 0, mgr.ActiveSessions(), "pending should not count as active session")
	assert.True(t, tracker.tracked[100], "root PID is tracked in BPF while pending")

	session, buffered := mgr.HandleStarvedDescendantExec(
		101, 100, 1000, 1,
		starvedMeta(map[string]string{"PATH": "/usr/bin"}), // no CI_JOB_ID
	)
	assert.Nil(t, session, "no materialization without context-ful env")
	assert.True(t, buffered, "descendant must be buffered")
	assert.Equal(t, 0, mgr.ActiveSessions())
	assert.Equal(t, uint32(100), mgr.PendingStarvedRootByPid(101),
		"buffered descendant maps back to its pending root")
}

func TestContextStarved_NonEmptyResolveMaterializes(t *testing.T) {
	// First descendant whose env contains CI_JOB_ID triggers materialization.
	tracker := newMockTracker()
	mgr := newTestManager(t, tracker, defaultLimits())
	rule := starvedRule()

	require.NoError(t, mgr.CreatePendingStarved(100, rule, starvedMeta(nil, "runc", "exec", "ctr")))

	session, buffered := mgr.HandleStarvedDescendantExec(
		101, 100, 1000, 1,
		starvedMeta(map[string]string{"CI_JOB_ID": "42"}),
	)
	require.NotNil(t, session, "context-ful descendant must materialize the session")
	assert.False(t, buffered)
	assert.Equal(t, 1, mgr.ActiveSessions())

	// Root pid belongs to the materialized session; so does the
	// context-ful descendant added by materialization.
	assert.Equal(t, session, mgr.RouteByPID(100))
	assert.Equal(t, session, mgr.RouteByPID(101))

	// No lingering pending state.
	assert.Equal(t, uint32(0), mgr.PendingStarvedRootByPid(100))
	assert.Equal(t, uint32(0), mgr.PendingStarvedRootByPid(101))
}

func TestContextStarved_BufferedDescendantsReplayedInOrder(t *testing.T) {
	// Several descendants buffer with empty env; when a later one resolves
	// non-empty, all previously-buffered descendants are routed into the
	// materialized session.
	tracker := newMockTracker()
	mgr := newTestManager(t, tracker, defaultLimits())
	rule := starvedRule()

	require.NoError(t, mgr.CreatePendingStarved(100, rule, starvedMeta(nil, "runc")))

	// Two starved descendants (no CI_JOB_ID).
	_, buffered := mgr.HandleStarvedDescendantExec(101, 100, 1000, 1, starvedMeta(map[string]string{"PATH": "/usr/bin"}))
	assert.True(t, buffered)
	_, buffered = mgr.HandleStarvedDescendantExec(102, 101, 1000, 2, starvedMeta(map[string]string{"PATH": "/usr/bin"}))
	assert.True(t, buffered)

	// Third descendant resolves → materialize.
	session, _ := mgr.HandleStarvedDescendantExec(
		103, 102, 1000, 3,
		starvedMeta(map[string]string{"CI_JOB_ID": "42"}),
	)
	require.NotNil(t, session)

	// All PIDs (root + buffered + triggering) route to the session.
	for _, pid := range []uint32{100, 101, 102, 103} {
		assert.Equal(t, session, mgr.RouteByPID(pid), "PID %d should route to materialized session", pid)
	}
}

func TestContextStarved_DeepChainViaFork(t *testing.T) {
	// GitLab-like chain: runc exec → bash (starved child) →
	// pipe-subshell fork (no exec) → user-cmd (context-ful grandchild).
	// The fork registration on the pipe-subshell must let the grandchild's
	// exec find the pending root.
	tracker := newMockTracker()
	mgr := newTestManager(t, tracker, defaultLimits())
	rule := starvedRule()

	require.NoError(t, mgr.CreatePendingStarved(100, rule, starvedMeta(nil, "runc")))

	// Child bash execs, starved (no CI_JOB_ID in envp — GitLab pattern).
	_, buffered := mgr.HandleStarvedDescendantExec(
		101, 100, 1000, 1,
		starvedMeta(map[string]string{"PATH": "/usr/bin"}),
	)
	assert.True(t, buffered)

	// Pipe subshell fork — no exec event. Register it so its child's later
	// exec finds the pending root.
	assert.True(t, mgr.HandleStarvedDescendantFork(102, 101),
		"fork of a pending-starved PID should be tracked")
	assert.Equal(t, uint32(100), mgr.PendingStarvedRootByPid(102))

	// User command exec — context-ful.
	session, _ := mgr.HandleStarvedDescendantExec(
		103, 102, 1000, 2,
		starvedMeta(map[string]string{"CI_JOB_ID": "99"}),
	)
	require.NotNil(t, session, "grandchild through fork-only intermediary must materialize")
	for _, pid := range []uint32{100, 101, 103} {
		assert.Equal(t, session, mgr.RouteByPID(pid), "PID %d should route to materialized session", pid)
	}
}

func TestContextStarved_ForkOnUnknownParentIsNoop(t *testing.T) {
	// Fork whose parent isn't pending must not be claimed by the
	// context-starved path (caller falls through to normal routing).
	tracker := newMockTracker()
	mgr := newTestManager(t, tracker, defaultLimits())

	assert.False(t, mgr.HandleStarvedDescendantFork(200, 199),
		"unknown parent should not be claimed as pending-starved")
}

func TestContextStarved_ExecOnUnknownParentFallsThrough(t *testing.T) {
	// Exec whose parent isn't pending: (nil, false) means "not my
	// problem" so the processor falls through to normal AddDescendant.
	tracker := newMockTracker()
	mgr := newTestManager(t, tracker, defaultLimits())

	session, buffered := mgr.HandleStarvedDescendantExec(
		201, 200, 1000, 1,
		starvedMeta(map[string]string{"CI_JOB_ID": "1"}),
	)
	assert.Nil(t, session)
	assert.False(t, buffered)
}

func TestContextStarved_StaleTimeoutDropsPending(t *testing.T) {
	// A pending session that never sees a context-ful descendant is
	// dropped after session_timeout.
	tracker := newMockTracker()
	limits := defaultLimits()
	limits.SessionTimeout = 30 * time.Millisecond
	mgr := newTestManager(t, tracker, limits)
	rule := starvedRule()

	require.NoError(t, mgr.CreatePendingStarved(100, rule, starvedMeta(nil, "runc")))
	// Buffer a starved descendant so we can assert its mapping disappears.
	_, buffered := mgr.HandleStarvedDescendantExec(101, 100, 1000, 1, starvedMeta(map[string]string{"PATH": "/usr/bin"}))
	require.True(t, buffered)

	time.Sleep(50 * time.Millisecond)
	mgr.CleanupStale()

	assert.Equal(t, uint32(0), mgr.PendingStarvedRootByPid(100), "pending root should be dropped")
	assert.Equal(t, uint32(0), mgr.PendingStarvedRootByPid(101), "buffered descendant mapping should be dropped")
	assert.Equal(t, 0, mgr.ActiveSessions())
}

func TestContextStarved_DropPendingStarvedExplicit(t *testing.T) {
	tracker := newMockTracker()
	mgr := newTestManager(t, tracker, defaultLimits())
	rule := starvedRule()

	require.NoError(t, mgr.CreatePendingStarved(100, rule, starvedMeta(nil, "runc")))
	_, _ = mgr.HandleStarvedDescendantExec(101, 100, 1000, 1, starvedMeta(map[string]string{}))

	mgr.DropPendingStarved(100)
	assert.Equal(t, uint32(0), mgr.PendingStarvedRootByPid(100))
	assert.Equal(t, uint32(0), mgr.PendingStarvedRootByPid(101))

	// Dropping a non-existent root is a no-op.
	mgr.DropPendingStarved(9999)
}

func TestContextStarved_PendingCountsAgainstSessionLimit(t *testing.T) {
	// Pending sessions count against max_concurrent_sessions so a flood of
	// starved matches cannot starve active sessions indefinitely.
	tracker := newMockTracker()
	limits := defaultLimits()
	limits.MaxConcurrentSessions = 2
	mgr := newTestManager(t, tracker, limits)
	rule := starvedRule()

	require.NoError(t, mgr.CreatePendingStarved(100, rule, starvedMeta(nil, "runc")))
	require.NoError(t, mgr.CreatePendingStarved(200, rule, starvedMeta(nil, "runc")))

	err := mgr.CreatePendingStarved(300, rule, starvedMeta(nil, "runc"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max concurrent sessions")
}

func TestContextStarved_LiteralAttributeDoesNotDefeatGate(t *testing.T) {
	// A context-starved rule whose only attribute is a literal cannot use
	// attribute resolution as a readiness signal — literals resolve non-empty
	// unconditionally and carry no env-readiness information. With no
	// expr-based trace_id either, the gate is inert and each descendant
	// buffers until timeout (load-time warning already flags the misconfig).
	tracker := newMockTracker()
	mgr := newTestManager(t, tracker, defaultLimits())
	rule := &config.AmbientRule{
		Name:           "literal-starved",
		Match:          config.AmbientMatch{Command: "runc"},
		ContextStarved: true,
		Attributes: map[string]string{
			"service.name": "always-on", // literal → ignored by gate
		},
	}

	require.NoError(t, mgr.CreatePendingStarved(100, rule, starvedMeta(nil, "runc")))

	session, buffered := mgr.HandleStarvedDescendantExec(
		101, 100, 1000, 1,
		starvedMeta(map[string]string{}),
	)
	assert.Nil(t, session, "literal-only rule must not materialize on first descendant")
	assert.True(t, buffered, "descendant should buffer while the gate waits")
}

func TestContextStarved_TraceIDExprGatesMaterialization(t *testing.T) {
	// With an expr-based trace_id, materialization must wait for that
	// expression to resolve non-empty — even if an expr-based attribute is
	// already resolving. The trace_id is the correlation key; creating a
	// session before it resolves risks collision on sha256("").
	tracker := newMockTracker()
	mgr := newTestManager(t, tracker, defaultLimits())
	rule := &config.AmbientRule{
		Name:           "ci-traceid-starved",
		Match:          config.AmbientMatch{Command: "runc"},
		ContextStarved: true,
		TraceID:        `expr:env["CI_PIPELINE_ID"]`,
		Attributes: map[string]string{
			"ci.job.id": `expr:env["CI_JOB_ID"]`,
		},
	}

	require.NoError(t, mgr.CreatePendingStarved(100, rule, starvedMeta(nil, "runc")))

	// CI_JOB_ID is set but CI_PIPELINE_ID is not → gate must hold.
	session, buffered := mgr.HandleStarvedDescendantExec(
		101, 100, 1000, 1,
		starvedMeta(map[string]string{"CI_JOB_ID": "42"}),
	)
	assert.Nil(t, session, "CI_PIPELINE_ID absent — must not materialize")
	assert.True(t, buffered)

	// Now CI_PIPELINE_ID shows up → materialize.
	session, _ = mgr.HandleStarvedDescendantExec(
		102, 101, 1000, 2,
		starvedMeta(map[string]string{"CI_JOB_ID": "42", "CI_PIPELINE_ID": "7"}),
	)
	require.NotNil(t, session, "CI_PIPELINE_ID present — must materialize")
}
