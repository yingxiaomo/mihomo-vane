package outboundgroup

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// FANOUT-01: closing one flow on a slow node must close its siblings on the
// same (target, node) too, while leaving flows on other nodes alone.
func TestVaneMediaSiblingFlowsCloseTogether(t *testing.T) {
	group, _, alpha, beta, metadata := newTargetGroupForTest(t)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	key := group.mediaTargetKey(metadata.Host, metadata.DstPort)

	f1 := newVaneMediaFlow(group, alpha.Name(), metadata, nil)
	f2 := newVaneMediaFlow(group, alpha.Name(), metadata, nil)
	f3 := newVaneMediaFlow(group, alpha.Name(), metadata, nil)
	require.NotNil(t, f1)
	require.NotNil(t, f2)
	require.NotNil(t, f3)
	t.Cleanup(func() {
		f1.releaseActiveFlowCount()
		f2.releaseActiveFlowCount()
		f3.releaseActiveFlowCount()
	})

	// Same target, different node: must never be treated as a sibling.
	fb := newVaneMediaFlow(group, beta.Name(), metadata, nil)
	require.NotNil(t, fb)
	t.Cleanup(func() { fb.releaseActiveFlowCount() })

	siblings := group.mediaSiblingFlows(key, alpha.Name(), f1)
	require.Len(t, siblings, 2)
	for _, sib := range siblings {
		require.NotSame(t, f1, sib, "the tripping flow must be excluded")
		require.NotSame(t, fb, sib, "a flow on another node must be excluded")
	}

	plan := vaneMediaPlan{targetKey: key, current: alpha.Name(), challenger: beta.Name()}
	sample := vaneThroughputObservation{BitsPerSecond: 1_000_000}
	require.True(t, f2.siblingCloseAction(plan, sample)())
	require.True(t, f2.policyAborted())
	require.False(t, f2.siblingCloseAction(plan, sample)(), "sibling close must be idempotent")
}

// NODESCOPE-01: a reconnect cooldown and budget belong to one (target, node),
// so a slow node must not freeze another node on the same target.
func TestVaneMediaBudgetScopedPerNode(t *testing.T) {
	group, clock, alpha, beta, metadata := newTargetGroupForTest(t)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	group.media.reconnectCooldown = 10 * time.Minute
	key := group.mediaTargetKey(metadata.Host, metadata.DstPort)
	now := clock.Now()

	group.mu.Lock()
	group.mediaBudgets[vaneMediaNodeKeyFor(key, alpha.Name())] = vaneMediaBudget{
		startedAt: now, count: group.media.budgetMax,
	}
	group.mediaReconnects[vaneMediaNodeKeyFor(key, alpha.Name())] = now.Add(group.media.reconnectCooldown)
	group.mu.Unlock()

	group.mu.Lock()
	alphaBlocked := group.mediaCooldownBlocksLocked(vaneMediaNodeKeyFor(key, alpha.Name()), 1, now)
	betaBlocked := group.mediaCooldownBlocksLocked(vaneMediaNodeKeyFor(key, beta.Name()), 1, now)
	alphaBudget := group.mediaBudgets[vaneMediaNodeKeyFor(key, alpha.Name())].count
	betaBudget := group.mediaBudgets[vaneMediaNodeKeyFor(key, beta.Name())].count
	group.mu.Unlock()

	require.True(t, alphaBlocked)
	require.False(t, betaBlocked, "a cooldown on one node must not block another node")
	require.Equal(t, group.media.budgetMax, alphaBudget)
	require.Zero(t, betaBudget)

	// After the break window a starving node is allowed one retry again.
	require.True(t, group.mediaCooldownBlocksLocked(
		vaneMediaNodeKeyFor(key, alpha.Name()), 1, now.Add(vaneMediaBreakWindow-time.Second)))
	require.False(t, group.mediaCooldownBlocksLocked(
		vaneMediaNodeKeyFor(key, alpha.Name()), 1, now.Add(vaneMediaBreakWindow+time.Second)))
}

// PROBE-GAP-01: a race probe that reads far above a node's real throughput
// must be lowered to the observed rate, while a probe close to reality stays.
func TestVaneProbeCapabilityDemotedByRealTraffic(t *testing.T) {
	group, clock, _, beta, _ := newTargetGroupForTest(t)
	lease := vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: 1}
	now := clock.Now()
	group.racingRuntime.mu.Lock()
	group.racingRuntime.capabilities[lease] = vaneCapabilityRecord{member: lease, lowerBoundBPS: 38_000_000, bytes: 4 << 20, observedAt: now}
	group.racingRuntime.mu.Unlock()

	group.observeThroughputEpochIdentity(beta.Name(), beta.identity, 1, vaneTransportTCP, now, 1_000_000)

	group.racingRuntime.mu.Lock()
	got := group.racingRuntime.capabilities[lease].lowerBoundBPS
	group.racingRuntime.mu.Unlock()
	require.Equal(t, float64(1_000_000), got, "a probe far above reality must be lowered to the real rate")

	group.racingRuntime.mu.Lock()
	group.racingRuntime.capabilities[lease] = vaneCapabilityRecord{member: lease, lowerBoundBPS: 38_000_000, bytes: 4 << 20, observedAt: now}
	group.racingRuntime.mu.Unlock()
	group.observeThroughputEpochIdentity(beta.Name(), beta.identity, 1, vaneTransportTCP, now.Add(time.Second), 20_000_000)
	group.racingRuntime.mu.Lock()
	got2 := group.racingRuntime.capabilities[lease].lowerBoundBPS
	group.racingRuntime.mu.Unlock()
	require.Equal(t, float64(38_000_000), got2, "a real rate near the probe claim keeps it")
}
