package outboundgroup

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// FANOUT-01: closing one flow on a slow node must close its siblings on the
// same (target, node) too, while leaving flows on other nodes alone.
func TestVaneFlowSiblingFlowsCloseTogether(t *testing.T) {
	group, _, alpha, beta, metadata := newTargetGroupForTest(t)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	key := group.targetScopeKey(metadata.Host, metadata.DstPort)

	f1 := newVaneFlow(group, alpha.Name(), metadata, nil)
	f2 := newVaneFlow(group, alpha.Name(), metadata, nil)
	f3 := newVaneFlow(group, alpha.Name(), metadata, nil)
	require.NotNil(t, f1)
	require.NotNil(t, f2)
	require.NotNil(t, f3)
	t.Cleanup(func() {
		f1.releaseActiveFlowCount()
		f2.releaseActiveFlowCount()
		f3.releaseActiveFlowCount()
	})

	// Same target, different node: must never be treated as a sibling.
	fb := newVaneFlow(group, beta.Name(), metadata, nil)
	require.NotNil(t, fb)
	t.Cleanup(func() { fb.releaseActiveFlowCount() })

	siblings := group.siblingFlows(key, alpha.Name(), f1)
	require.Len(t, siblings, 2)
	for _, sib := range siblings {
		require.NotSame(t, f1, sib, "the tripping flow must be excluded")
		require.NotSame(t, fb, sib, "a flow on another node must be excluded")
	}

	plan := vaneReconnectPlan{targetKey: key, current: alpha.Name(), challenger: beta.Name()}
	sample := vaneThroughputObservation{BitsPerSecond: 1_000_000}
	require.True(t, f2.siblingCloseAction(plan, sample)())
	require.True(t, f2.policyAborted())
	require.False(t, f2.siblingCloseAction(plan, sample)(), "sibling close must be idempotent")
}

// NODE-COOLDOWN-01: a switch cools the node it left, not the target, so the
// other nodes of the same target stay eligible. The budget, in contrast, is
// per target: every node behind that target shares it.
func TestVaneNodeCooldownDoesNotFreezeTheTarget(t *testing.T) {
	group, clock, alpha, beta, metadata := newTargetGroupForTest(t)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	key := group.targetScopeKey(metadata.Host, metadata.DstPort)
	now := clock.Now()

	group.mu.Lock()
	group.coolNodeLocked(alpha.Name(), now.Add(vaneSwitchAwayCooldown), true)
	alphaCooling := group.nodeCoolingLocked(alpha.Name(), now)
	betaCooling := group.nodeCoolingLocked(beta.Name(), now)
	group.mu.Unlock()

	require.True(t, alphaCooling)
	require.False(t, betaCooling, "a cooldown on one node must not block another node")
	require.False(t, group.nodeCoolingLocked(alpha.Name(), now.Add(vaneSwitchAwayCooldown+time.Second)),
		"the node cooldown expires on its own")

	group.mu.Lock()
	group.ledger[key] = vaneSwitchLedger{windowFrom: now, count: vaneSwitchBudgetMax, lastSwitch: now.Add(-vaneSwitchThrottle)}
	reason := group.ledgerThrottleReasonLocked(key, false, now)
	group.mu.Unlock()
	require.Equal(t, "target-budget", reason, "the budget is shared by every node behind the target")
}

// PROBE-GAP-01: a race probe that reads far above a node's real throughput
// must be lowered to the observed rate, while a probe close to reality stays.
func TestVaneProbeCapabilityDemotedByRealTraffic(t *testing.T) {
	group, clock, _, beta, _ := newTargetGroupForTest(t)
	lease := vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: 1}
	now := clock.Now()
	group.racingRuntime.mu.Lock()
	group.racingRuntime.capabilities[lease] = vaneCapabilityRecord{lowerBoundBPS: 38_000_000, bytes: 4 << 20, observedAt: now}
	group.racingRuntime.mu.Unlock()

	group.observeThroughputEpochIdentity(beta.Name(), beta.identity, 1, vaneTransportTCP, now, 1_000_000)

	group.racingRuntime.mu.Lock()
	got := group.racingRuntime.capabilities[lease].lowerBoundBPS
	group.racingRuntime.mu.Unlock()
	require.Equal(t, float64(1_000_000), got, "a probe far above reality must be lowered to the real rate")

	group.racingRuntime.mu.Lock()
	group.racingRuntime.capabilities[lease] = vaneCapabilityRecord{lowerBoundBPS: 38_000_000, bytes: 4 << 20, observedAt: now}
	group.racingRuntime.mu.Unlock()
	group.observeThroughputEpochIdentity(beta.Name(), beta.identity, 1, vaneTransportTCP, now.Add(time.Second), 20_000_000)
	group.racingRuntime.mu.Lock()
	got2 := group.racingRuntime.capabilities[lease].lowerBoundBPS
	group.racingRuntime.mu.Unlock()
	require.Equal(t, float64(38_000_000), got2, "a real rate near the probe claim keeps it")
}

// TEST-FANOUT-DEADLOCK-01: two sibling conns whose policy actions submit a
// delivered policy action to each other must both complete. requestAbort used
// to run the action while holding lifecycleMu, so two sibling commits that
// fanned out to each other cross-waited on the two lifecycleMu locks forever.
func TestVaneRequestAbortCrossFanoutCompletes(t *testing.T) {
	clock := newVaneConnTestClock()
	mkConn := func() *vaneObservedConn {
		return newVaneControlledConnWithNative(&vaneConnTestConn{}, clock, nil, nil, nil, nil, nil, nil, nil).(*vaneObservedConn)
	}
	ca := mkConn()
	cb := mkConn()

	var aRuns, bRuns atomic.Int32
	inside := make(chan struct{}, 2)
	proceed := make(chan struct{})
	doneA := make(chan struct{})
	doneB := make(chan struct{})

	actionA := func() bool {
		aRuns.Add(1)
		inside <- struct{}{}
		<-proceed
		cb.submitPolicyAction(func() bool { return true }, true)
		return true
	}
	actionB := func() bool {
		bRuns.Add(1)
		inside <- struct{}{}
		<-proceed
		ca.submitPolicyAction(func() bool { return true }, true)
		return true
	}

	go func() { ca.requestAbort(actionA); close(doneA) }()
	go func() { cb.requestAbort(actionB); close(doneB) }()
	<-inside
	<-inside
	close(proceed)

	select {
	case <-doneA:
	case <-time.After(5 * time.Second):
		t.Fatal("requestAbort A never returned: cross-fanout deadlock")
	}
	select {
	case <-doneB:
	case <-time.After(5 * time.Second):
		t.Fatal("requestAbort B never returned: cross-fanout deadlock")
	}
	if aRuns.Load() != 1 || bRuns.Load() != 1 {
		t.Fatalf("policy actions must run exactly once: a=%d b=%d", aRuns.Load(), bRuns.Load())
	}
}
