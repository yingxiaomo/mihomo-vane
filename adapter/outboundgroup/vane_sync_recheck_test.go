package outboundgroup

// SYNC-RECHECK: a policy action must re-check flow recovery at execution
// time. A fast window between the action's creation and its execution resets
// the low-window streak, and a recovered flow must not be closed. The queued
// path (pendingAction -> drainPendingAbort) and the immediate path run the
// same closure, so flow-level tests cover both — noted per the guide's
// downgrade clause for 03.

import (
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func newSyncRecheckFlow(t *testing.T) (*Vane, *vaneConnTestClock, *vaneMediaFlow, vaneMediaPlan) {
	t.Helper()
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.delay = 20
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	chain01ProductionValues(t, group, 2_000_000)
	metadata := &C.Metadata{Host: "rr-recheck.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	suppressColdPickProbeForTest(t, group, metadata)

	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, "alpha", decision.proxy.Name())
	flow := newVaneMediaFlow(group, decision.proxy.Name(), metadata)
	require.NotNil(t, flow)
	flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
	// CHAIN-01: the challenger needs fresh throughput evidence above the
	// close bar for prepare to admit it.
	now := clock.Now()
	group.mu.Lock()
	group.learning.mu.Lock()
	group.ensureProxyNodeLocked(beta, now)
	group.nodeControls[beta.Name()].recentTCPThroughput = vaneRecentThroughput{
		bitsPerSecond: 12_000_000, observedAt: now,
	}
	group.learning.mu.Unlock()
	group.mu.Unlock()

	key := group.mediaTargetKey(metadata.Host, metadata.DstPort)
	plan, reason := group.prepareMediaReconnectForNodeDetailed(
		key, metadata.Host, metadata.DstPort, decision.proxy.Name(), decision.identity, decision.nodeEpoch, 629_146)
	require.Empty(t, reason)
	plan.totalBytes = 8 * 1024 * 1024
	plan.age = 30 * time.Second
	plan.lowWindows = 3
	return group, clock, flow, plan
}

func syncRecheckSample() vaneThroughputObservation {
	return vaneThroughputObservation{
		BitsPerSecond: 629_146, TotalBytes: 8 * 1024 * 1024, Age: 30 * time.Second,
	}
}

// SYNC-RECHECK-01: recovery between action creation and execution vetoes the
// close, records reconnect-rejected reason=recovered, and leaves the flow
// alive.
func TestVaneSyncRecheckRecoveredVetoesClose(t *testing.T) {
	group, _, flow, plan := newSyncRecheckFlow(t)
	action := flow.policyActionForPlan(plan, syncRecheckSample(), 3, false)
	require.NotNil(t, action)

	// The flow is mid-streak when the action is created (the veto premise).
	flow.mu.Lock()
	flow.lowWindows = 3
	flow.mu.Unlock()
	// The flow recovers before execution: a real fast window through observe()
	// resets the streak (and clears the race token, RACE-06).
	flow.observe(vaneThroughputObservation{
		BitsPerSecond: 12_000_000, TotalBytes: 8 * 1024 * 1024, Age: 60 * time.Second,
	})
	flow.mu.Lock()
	lowAfter := flow.lowWindows
	flow.mu.Unlock()
	require.Zero(t, lowAfter, "the fast window must reset the streak")

	require.False(t, action(), "a recovered flow must not be closed")
	group.mu.Lock()
	_, hinted := group.mediaHints[plan.targetKey]
	budget := group.mediaBudgets[plan.targetKey]
	group.mu.Unlock()
	require.False(t, hinted, "a rejected close must not leave a handoff hint")
	require.Zero(t, budget.count, "a rejected close must not consume budget")
	snapshot := group.VaneDiagnostics()
	require.Equal(t, uint64(1), snapshot.Counters.ReconnectRejected)
	require.Equal(t, uint64(1), snapshot.Rejections["recovered"])
}

// SYNC-RECHECK-02: a flow that stays slow executes the close as before.
func TestVaneSyncRecheckStillSlowExecutes(t *testing.T) {
	group, _, flow, plan := newSyncRecheckFlow(t)
	action := flow.policyActionForPlan(plan, syncRecheckSample(), 3, false)
	require.NotNil(t, action)

	// No recovery: lowWindows stays at/above the threshold.
	flow.mu.Lock()
	flow.lowWindows = 3
	flow.mu.Unlock()

	require.True(t, action())
	snapshot := group.VaneDiagnostics()
	require.Zero(t, snapshot.Counters.ReconnectRejected)
	group.mu.Lock()
	hint := group.mediaHints[plan.targetKey]
	group.mu.Unlock()
	require.Equal(t, plan.challenger, hint.candidate)
}

// SYNC-RECHECK-03 (flow-level, guide's downgrade clause): the queued path
// (pendingAction -> drainPendingAbort) runs this same closure, so a queued-
// then-recovered action is rejected exactly like SYNC-RECHECK-01.
func TestVaneSyncRecheckQueuedRecoveredRejected(t *testing.T) {
	group, _, flow, plan := newSyncRecheckFlow(t)
	action := flow.policyActionForPlan(plan, syncRecheckSample(), 3, false)
	require.NotNil(t, action)

	// The queued action sits while the flow recovers (real fast window).
	flow.mu.Lock()
	flow.lowWindows = 3
	flow.mu.Unlock()
	flow.observe(vaneThroughputObservation{
		BitsPerSecond: 12_000_000, TotalBytes: 8 * 1024 * 1024, Age: 60 * time.Second,
	})
	flow.mu.Lock()
	require.Zero(t, flow.lowWindows)
	flow.mu.Unlock()

	require.False(t, action())
	snapshot := group.VaneDiagnostics()
	require.Equal(t, uint64(1), snapshot.Rejections["recovered"])
	_ = group
}
