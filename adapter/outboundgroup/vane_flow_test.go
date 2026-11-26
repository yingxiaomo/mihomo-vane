package outboundgroup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	RP "github.com/metacubex/mihomo/rules/provider"
	"github.com/metacubex/mihomo/tunnel"
	SBufio "github.com/metacubex/sing/common/bufio"

	"github.com/stretchr/testify/require"
)

func configureVaneFlowForTest(t *testing.T, group *Vane, rules ...string) {
	t.Helper()
	parsed, err := parseVaneFamilyRules(rules)
	require.NoError(t, err)
	group.rules = parsed
	group.flow = defaultVaneFlowConfig()
	group.flow.enabled = true
	group.flow.domains = []string{"googlevideo.com"}
	group.flow.lowThroughputBPS = 3_000_000
	group.flow.lowWindows = 3
	group.flow.maxLowWindows = 6
	group.flow.minAge = 10 * time.Second
	group.flow.minBytes = 512 * 1024
	group.flow.demandBPS = 1
	group.flow.bufferGuard = 0
	group.flow.reconnectCooldown = 2 * time.Minute
	group.flow.slowCooldown = 5 * time.Minute
	group.flow.hintTTL = 15 * time.Second
}

func readVaneLowWindows(t *testing.T, conn C.Conn, clock *vaneConnTestClock, windows int) {
	t.Helper()
	observed := conn.(*vaneObservedConn)
	reader, counters := observed.UnwrapReader()
	payload := make([]byte, 64*1024)
	reads := windows * 6
	for i := 0; i < reads; i++ {
		if i > 0 {
			clock.Advance(time.Second)
		}
		n, err := reader.Read(payload)
		require.NoError(t, err)
		require.Equal(t, len(payload), n)
		for _, counter := range counters {
			counter(int64(n))
		}
	}
}

// RACE-HANDOFF-001 + TARGET-LEASE-001: close-once with a prepared winner handoff.
func TestVaneFlowReconnectClosesOnceAndHandsOffTarget(t *testing.T) {
	clock := newVaneConnTestClock()
	alphaConn := &vaneConnTestConn{readFunc: func(payload []byte) (int, error) {
		for i := range payload {
			payload[i] = 1
		}
		return len(payload), nil
	}}
	betaConn := &vaneConnTestConn{}
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.delay = 20
	alpha.dialConn = alphaConn
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	beta.dialConn = betaConn
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	// CHAIN-01: beta needs fresh throughput evidence above the close bar;
	// the test drives real traffic only through alpha's flow.
	group.ensureNodeLocked(beta.Name(), clock.Now())
	group.ensureNodeControlLocked(beta.Name(), clock.Now()).recentTCPThroughput = vaneRecentThroughput{
		bitsPerSecond: 5_000_000, observedAt: clock.Now(),
	}
	metadata := &C.Metadata{Host: "rr1.googlevideo.com", DstPort: 443, NetWork: C.TCP}

	conn, err := group.DialContext(t.Context(), metadata)
	require.NoError(t, err)
	anchorKey := vaneAnchorKey{transport: vaneTransportTCP}
	group.mu.Lock()
	selected := group.anchors[anchorKey].name
	group.mu.Unlock()
	require.Equal(t, "alpha", selected)

	readVaneLowWindows(t, conn, clock, 3)
	alphaConn.mu.Lock()
	closeCalls := alphaConn.closeCalls
	alphaConn.mu.Unlock()
	require.Equal(t, 1, closeCalls, "the last positive payload must be delivered before one policy close")

	group.mu.Lock()
	stateKey, ok := group.targetScopeForKey(metadata.Host, metadata.DstPort)
	require.True(t, ok)
	lease := group.targetHandoffs[stateKey]
	slow := group.nodeCoolingLocked("alpha", clock.Now())
	group.mu.Unlock()
	require.Equal(t, "beta", lease.to.name)
	require.True(t, slow)

	require.Equal(t, "beta", group.pick(metadata, vaneTransportTCP, false, true).Name(), "the reconnect must follow the family handoff")
	group.mu.Lock()
	_, hintStillPresent := group.targetHandoffs[stateKey]
	group.mu.Unlock()
	require.True(t, hintStillPresent, "the short sticky hint cannot be stolen by one concurrent connection")

	require.NoError(t, conn.Close())
	alphaConn.mu.Lock()
	closeCalls = alphaConn.closeCalls
	alphaConn.mu.Unlock()
	require.Equal(t, 1, closeCalls, "outer cleanup must not close the same logical stream twice")

	snapshot := group.nodes["alpha"].snapshot(vaneTransportTCP, clock.Now())
	require.True(t, snapshot.failure.valid)
	require.InDelta(t, 0, snapshot.failure.value, 1e-12, "policy reconnect is not a node failure")
}

// TARGET-BOUND-001: a replaced node's old flow cannot cool down the replacement.
func TestVaneFlowOldFlowCannotCoolDownSameNameReplacement(t *testing.T) {
	clock := newVaneConnTestClock()
	oldConn := &vaneConnTestConn{readFunc: func(payload []byte) (int, error) {
		for i := range payload {
			payload[i] = 1
		}
		return len(payload), nil
	}}
	oldAlpha := newVaneTestProxy("alpha", true, true)
	oldAlpha.identity = "alpha-old"
	oldAlpha.delay = 20
	oldAlpha.dialConn = oldConn
	beta := newVaneTestProxy("beta", true, true)
	beta.identity = "beta"
	beta.delay = 10
	group, provider := newVaneGroupForTest(clock, 10, time.Hour, oldAlpha, beta)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	metadata := &C.Metadata{Host: "rr-old.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	conn, err := group.DialContext(t.Context(), metadata)
	require.NoError(t, err)

	newAlpha := newVaneTestProxy("alpha", true, true)
	newAlpha.identity = "alpha-new"
	newAlpha.delay = 20
	provider.setProxies(newAlpha, beta)
	readVaneLowWindows(t, conn, clock, 3)

	key := vaneFlowKey{target: "googlevideo.com", port: 443}
	group.mu.Lock()
	slowed := group.nodeCoolingLocked("alpha", clock.Now())
	_, hinted := group.hints[key]
	group.mu.Unlock()
	require.False(t, slowed)
	require.False(t, hinted)
	oldConn.mu.Lock()
	closeCalls := oldConn.closeCalls
	oldConn.mu.Unlock()
	require.Zero(t, closeCalls, "stale flow policy must not close the old stream or control the replacement")
	require.NoError(t, conn.Close())
}

// TARGET-BOUND-001: prepared plans reject same-name replacements.
func TestVaneFlowPreparedPlanRejectsSameNameReplacement(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.identity = "alpha-old"
	alpha.delay = 20
	beta := newVaneTestProxy("beta", true, true)
	beta.identity = "beta"
	beta.delay = 10
	group, provider := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	// CHAIN-01: beta needs fresh throughput evidence above the close bar.
	group.ensureNodeLocked(beta.Name(), clock.Now())
	group.ensureNodeControlLocked(beta.Name(), clock.Now()).recentTCPThroughput = vaneRecentThroughput{
		bitsPerSecond: 5_000_000, observedAt: clock.Now(),
	}
	metadata := &C.Metadata{Host: "rr-plan.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
	group.mu.Lock()
	state := group.nodes["alpha"]
	identity, epoch := state.identity, state.epoch
	group.mu.Unlock()
	key := group.targetScopeKey(metadata.Host, metadata.DstPort)
	plan, reason := group.prepareReconnectForNodeDetailed(key, metadata.Host, metadata.DstPort, "alpha", identity, epoch, 2_000_000)
	require.Empty(t, reason)

	newAlpha := newVaneTestProxy("alpha", true, true)
	newAlpha.identity = "alpha-new"
	newAlpha.delay = 20
	provider.setProxies(newAlpha, beta)
	require.Equal(t, "stale-node-identity", group.commitReconnectDetailed(plan))
}

// TARGET-BOUND-001: commits reject replacements observed during health check.
func TestVaneFlowCommitRejectsReplacementDuringHealthCheck(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.identity = "alpha-old"
	alpha.delay = 20
	beta := newVaneTestProxy("beta", true, true)
	beta.identity = "beta"
	beta.delay = 10
	group, provider := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	// CHAIN-01: beta needs fresh throughput evidence above the close bar.
	group.ensureNodeLocked(beta.Name(), clock.Now())
	group.ensureNodeControlLocked(beta.Name(), clock.Now()).recentTCPThroughput = vaneRecentThroughput{
		bitsPerSecond: 5_000_000, observedAt: clock.Now(),
	}
	metadata := &C.Metadata{Host: "rr-commit-race.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
	group.mu.Lock()
	state := group.nodes["alpha"]
	identity, epoch := state.identity, state.epoch
	group.mu.Unlock()
	key := group.targetScopeKey(metadata.Host, metadata.DstPort)
	plan, reason := group.prepareReconnectForNodeDetailed(key, metadata.Host, metadata.DstPort, "alpha", identity, epoch, 2_000_000)
	require.Empty(t, reason)

	newAlpha := newVaneTestProxy("alpha", true, true)
	newAlpha.identity = "alpha-new"
	newAlpha.delay = 20
	var replace sync.Once
	beta.aliveHook = func() { replace.Do(func() { provider.setProxies(newAlpha, beta) }) }
	require.Equal(t, "stale-node-identity", group.commitReconnectDetailed(plan))
}

// BASELINE-COOLDOWN-001: the progressive target backoff gates the baseline
// reconnect path the same way it gates the racing snapshot — a challenger that
// failed a handoff for this target must not be re-picked by the baseline, and
// a block written between prepare and commit must reject the commit.
func TestVaneBaselineReconnectRespectsTargetBlock(t *testing.T) {
	newBlockedGroup := func(t *testing.T) (*Vane, *vaneConnTestClock, *vaneTestProxy, *vaneTestProxy, *vaneTestProxy, *C.Metadata, vaneFlowKey) {
		t.Helper()
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		alpha.identity = "alpha-old"
		alpha.delay = 20
		beta := newVaneTestProxy("beta", true, true)
		beta.identity = "beta"
		beta.delay = 10
		gamma := newVaneTestProxy("gamma", true, true)
		gamma.identity = "gamma"
		gamma.delay = 30
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta, gamma)
		configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
		// CHAIN-01: both challengers need fresh throughput evidence.
		for _, challenger := range []C.Proxy{beta, gamma} {
			group.ensureNodeLocked(challenger.Name(), clock.Now())
			group.ensureNodeControlLocked(challenger.Name(), clock.Now()).recentTCPThroughput = vaneRecentThroughput{
				bitsPerSecond: 5_000_000, observedAt: clock.Now(),
			}
		}
		metadata := &C.Metadata{Host: "rr-block.googlevideo.com", DstPort: 443, NetWork: C.TCP}
		key := group.targetScopeKey(metadata.Host, metadata.DstPort)
		return group, clock, alpha, beta, gamma, metadata, key
	}

	t.Run("prepare skips a challenger inside its target block", func(t *testing.T) {
		group, clock, _, beta, _, metadata, key := newBlockedGroup(t)
		require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
		group.mu.Lock()
		state := group.nodes["alpha"]
		identity, epoch := state.identity, state.epoch
		group.mu.Unlock()

		// Without the block the baseline picks beta (better delay, name order).
		plan, reason := group.prepareReconnectForNodeDetailed(key, metadata.Host, metadata.DstPort, "alpha", identity, epoch, 2_000_000)
		require.Empty(t, reason)
		require.Equal(t, "beta", plan.challenger)

		// Seed the progressive block the way a failed handoff leaves it.
		group.mu.Lock()
		targetKey, _ := group.targetScopeForKey(metadata.Host, metadata.DstPort)
		member := group.memberLeaseLocked(beta.Name(), beta.identity)
		group.targetFailures[vaneTargetFailureKey{target: targetKey, member: member}] = vaneTargetFailureState{
			streak: 1, blockUntil: clock.Now().Add(30 * time.Second), lastFailureAt: clock.Now(),
		}
		group.mu.Unlock()

		blockedPlan, reason := group.prepareReconnectForNodeDetailed(key, metadata.Host, metadata.DstPort, "alpha", identity, epoch, 2_000_000)
		require.Empty(t, reason)
		require.Equal(t, "gamma", blockedPlan.challenger, "the blocked challenger must be skipped for the idle one")
	})

	t.Run("commit rejects a challenger blocked after prepare", func(t *testing.T) {
		group, clock, _, beta, _, metadata, key := newBlockedGroup(t)
		require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
		group.mu.Lock()
		state := group.nodes["alpha"]
		identity, epoch := state.identity, state.epoch
		group.mu.Unlock()
		plan, reason := group.prepareReconnectForNodeDetailed(key, metadata.Host, metadata.DstPort, "alpha", identity, epoch, 2_000_000)
		require.Empty(t, reason)
		require.Equal(t, "beta", plan.challenger)

		// The block appears after prepare — as if a handoff failed while the
		// plan was in flight — and the commit must not land on it.
		group.mu.Lock()
		member := group.memberLeaseLocked(beta.Name(), beta.identity)
		group.targetFailures[vaneTargetFailureKey{target: plan.targetStateKey, member: member}] = vaneTargetFailureState{
			streak: 1, blockUntil: clock.Now().Add(30 * time.Second), lastFailureAt: clock.Now(),
		}
		group.mu.Unlock()
		require.Equal(t, "candidate-blocked", group.commitReconnectDetailed(plan))

		// A commit without the block still goes through on the same plan shape.
		group.mu.Lock()
		delete(group.targetFailures, vaneTargetFailureKey{target: plan.targetStateKey, member: member})
		group.mu.Unlock()
		freshPlan, reason := group.prepareReconnectForNodeDetailed(key, metadata.Host, metadata.DstPort, "alpha", identity, epoch, 2_000_000)
		require.Empty(t, reason)
		require.Equal(t, "beta", freshPlan.challenger)
		require.Empty(t, group.commitReconnectDetailed(freshPlan))
	})
}

// TARGET-LEASE-001: repeated provider entries deduplicate to one lease.
func TestVaneFlowProviderLeaseDeduplicatesRepeatedProvider(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	group, provider := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	group.providers = append(group.providers, group.providers[0])
	release, ok := group.lockVaneIdentities(map[string]string{"alpha": alpha.identity})
	require.True(t, ok)
	release()
	provider.mu.Lock()
	calls := provider.snapshotCalls
	provider.mu.Unlock()
	require.Equal(t, 1, calls)
}

// TARGET-BOUND-001: a delayed failure cooldown does not contaminate the replacement.
func TestVaneDelayedFailureCooldownDoesNotAffectSameNameReplacement(t *testing.T) {
	clock := newVaneConnTestClock()
	oldAlpha := newVaneTestProxy("alpha", true, true)
	oldAlpha.identity = "alpha-old"
	beta := newVaneTestProxy("beta", true, true)
	group, provider := newVaneGroupForTest(clock, 10, time.Hour, oldAlpha, beta)
	metadata := &C.Metadata{Host: "example.com", DstPort: 443, NetWork: C.TCP}
	decision := group.pickInternalDecision(context.Background(), metadata, vaneTransportTCP, false, true, false)
	require.Equal(t, "alpha", decision.proxy.Name())

	newAlpha := newVaneTestProxy("alpha", true, true)
	newAlpha.identity = "alpha-new"
	provider.setProxies(newAlpha, beta)
	group.recordDialFailureEpoch(t.Context(), metadata, vaneTransportTCP, oldAlpha, decision.identity, decision.nodeEpoch, errors.New("late dial failure"), clock.Now())

	require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
	group.mu.Lock()
	_, oldCooling := group.cooldowns[vaneCooldownKey{transport: vaneTransportTCP, target: "example.com", port: 443, candidate: "alpha", identity: "alpha-old"}]
	_, newCooling := group.cooldowns[vaneCooldownKey{transport: vaneTransportTCP, target: "example.com", port: 443, candidate: "alpha", identity: "alpha-new"}]
	group.mu.Unlock()
	require.True(t, oldCooling)
	require.False(t, newCooling)
}

// TARGET-BOUND-001: hints reject same-name challenger replacements.
func TestVaneFlowHintRejectsSameNameChallengerReplacement(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.identity = "alpha"
	alpha.delay = 20
	beta := newVaneTestProxy("beta", true, true)
	beta.identity = "beta-old"
	beta.delay = 10
	group, provider := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	// CHAIN-01: beta needs fresh throughput evidence above the close bar.
	group.ensureNodeLocked(beta.Name(), clock.Now())
	group.ensureNodeControlLocked(beta.Name(), clock.Now()).recentTCPThroughput = vaneRecentThroughput{
		bitsPerSecond: 5_000_000, observedAt: clock.Now(),
	}
	metadata := &C.Metadata{Host: "rr-hint-race.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
	group.mu.Lock()
	state := group.nodes["alpha"]
	identity, epoch := state.identity, state.epoch
	group.mu.Unlock()
	key := group.targetScopeKey(metadata.Host, metadata.DstPort)
	plan, reason := group.prepareReconnectForNodeDetailed(key, metadata.Host, metadata.DstPort, "alpha", identity, epoch, 2_000_000)
	require.Empty(t, reason)
	require.Empty(t, group.commitReconnectDetailed(plan))

	newAlpha := newVaneTestProxy("alpha", true, true)
	newAlpha.identity = "alpha-new"
	newBeta := newVaneTestProxy("beta", true, true)
	newBeta.identity = "beta-new"
	provider.setProxies(newAlpha, newBeta)
	group.mu.Lock()
	hinted, handoff := group.takeHintLocked(metadata.Host, metadata.DstPort, []C.Proxy{newAlpha, newBeta}, clock.Now(), true)
	newAlphaCooldown := group.cooldownUntilLockedWithCleanup(metadata.Host, metadata.DstPort, "alpha", newAlpha.identity, clock.Now(), false)
	group.mu.Unlock()
	require.Nil(t, hinted)
	require.Nil(t, handoff)
	require.True(t, newAlphaCooldown.IsZero())
}

// TARGET-SCOPE-001: reconnect never cuts web or small traffic.
func TestVaneFlowReconnectNeverCutsWebOrSmallTraffic(t *testing.T) {
	tests := []struct {
		name  string
		rules []string
		host  string
	}{
		{name: "default webpage", rules: []string{"DOMAIN-SUFFIX,googlevideo.com"}, host: "www.youtube.com"},
		{name: "interactive webpage", rules: []string{"DOMAIN-SUFFIX,youtube.com"}, host: "www.youtube.com"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := newVaneConnTestClock()
			underlying := &vaneConnTestConn{readFunc: func(payload []byte) (int, error) { return len(payload), nil }}
			alpha := newVaneTestProxy("alpha", true, true)
			alpha.dialConn = underlying
			beta := newVaneTestProxy("beta", true, true)
			beta.delay = 1
			group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
			configureVaneFlowForTest(t, group, test.rules...)
			metadata := &C.Metadata{Host: test.host, DstPort: 443, NetWork: C.TCP}

			conn, err := group.DialContext(t.Context(), metadata)
			require.NoError(t, err)
			readVaneLowWindows(t, conn, clock, 4)
			underlying.mu.Lock()
			closeCalls := underlying.closeCalls
			underlying.mu.Unlock()
			require.Zero(t, closeCalls, "untargeted traffic must never be policy-closed")
			require.NoError(t, conn.Close())
		})
	}
}

// RACE-HANDOFF-001: reconnect safety gates hold before any close.
func TestVaneFlowReconnectSafetyGates(t *testing.T) {
	t.Run("no health-qualified challenger", func(t *testing.T) {
		clock := newVaneConnTestClock()
		underlying := &vaneConnTestConn{readFunc: func(payload []byte) (int, error) { return len(payload), nil }}
		alpha := newVaneTestProxy("alpha", true, true)
		alpha.dialConn = underlying
		beta := newVaneTestProxy("beta", true, true)
		beta.delay = 0
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
		conn, err := group.DialContext(t.Context(), &C.Metadata{Host: "rr2.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		require.NoError(t, err)
		readVaneLowWindows(t, conn, clock, 4)
		underlying.mu.Lock()
		closeCalls := underlying.closeCalls
		underlying.mu.Unlock()
		require.Zero(t, closeCalls)
		require.NoError(t, conn.Close())
	})

	t.Run("good window decays consecutive low count", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
		flow := newVaneFlow(group, "alpha", &C.Metadata{Host: "rr3.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		require.NotNil(t, flow)
		low := vaneThroughputObservation{BitsPerSecond: 1_000_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second}
		high := vaneThroughputObservation{BitsPerSecond: 10_000_000, TotalBytes: 5 * 1024 * 1024, Age: 25 * time.Second}
		require.Nil(t, flow.observe(low))
		require.Nil(t, flow.observe(low))
		require.Nil(t, flow.observe(high))
		// P1 grace: lows within 30s of the fast sample are graced; past the
		// grace the streak accumulates again. A fast window decays the streak
		// by one instead of resetting it, so a pulsing node still converges
		// (STALL-STREAK).
		clock.Advance(vaneFastGrace + time.Second)
		require.Nil(t, flow.observe(low))
		require.Nil(t, flow.observe(low))
		flow.mu.Lock()
		count := flow.lowWindows
		flow.mu.Unlock()
		require.Equal(t, 3, count, "two lows, one decayed by the fast window, two more lows")
	})
}

// RACE-ATOMIC-001: concurrent close is exactly once.
func TestVaneControlledConnConcurrentCloseIsExactlyOnce(t *testing.T) {
	clock := newVaneConnTestClock()
	underlying := &vaneConnTestConn{}
	wrapped := newVaneControlledConn(underlying, clock, nil, nil, func(vaneThroughputObservation) vanePolicyAction {
		return func() bool { return true }
	})
	observed := wrapped.(*vaneObservedConn)
	observed.requestAbort(func() bool { return true })

	const workers = 32
	var wait sync.WaitGroup
	wait.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wait.Done()
			require.NoError(t, wrapped.Close())
		}()
	}
	wait.Wait()
	underlying.mu.Lock()
	closeCalls := underlying.closeCalls
	underlying.mu.Unlock()
	require.Equal(t, 1, closeCalls)
}

// RACE-DELIVERY-001: direct reads never policy-close before delivery.
func TestVaneControlledConnDirectReadNeverPolicyClosesBeforeDelivery(t *testing.T) {
	clock := newVaneConnTestClock()
	underlying := &vaneConnTestConn{readFunc: func(payload []byte) (int, error) { return len(payload), nil }}
	var prepared, committed int
	wrapped := newVaneControlledConn(underlying, clock, nil, nil, func(vaneThroughputObservation) vanePolicyAction {
		prepared++
		return func() bool { committed++; return true }
	})
	payload := make([]byte, 64*1024)
	for i := 0; i < 18; i++ {
		if i > 0 {
			clock.Advance(time.Second)
		}
		n, err := wrapped.Read(payload)
		require.NoError(t, err)
		require.Equal(t, len(payload), n)
	}
	require.Zero(t, prepared)
	require.Zero(t, committed)
	underlying.mu.Lock()
	closeCalls := underlying.closeCalls
	underlying.mu.Unlock()
	require.Zero(t, closeCalls)
	require.NoError(t, wrapped.Close())
}

// RACE-ATOMIC-001: natural close cancels the policy transaction.
func TestVaneControlledConnNaturalCloseCancelsPolicyTransaction(t *testing.T) {
	clock := newVaneConnTestClock()
	underlying := &vaneConnTestConn{}
	wrapped := newVaneControlledConn(underlying, clock, nil, nil, nil)
	observed := wrapped.(*vaneObservedConn)
	require.Same(t, underlying, observed.Upstream())
	require.NoError(t, wrapped.Close())
	committed := 0
	observed.requestAbort(func() bool { committed++; return true })
	require.Zero(t, committed)
	underlying.mu.Lock()
	closeCalls := underlying.closeCalls
	underlying.mu.Unlock()
	require.Equal(t, 1, closeCalls)
}

// RACE-DELIVERY-001: sing-copy closes only after payload delivery.
func TestVaneControlledConnSingCopyClosesOnlyAfterPayloadDelivery(t *testing.T) {
	clock := newVaneConnTestClock()
	payload := bytes.Repeat([]byte{1}, 64*1024)
	reads := make([]vaneConnTestRead, 0, 19)
	for i := 0; i < 18; i++ {
		reads = append(reads, vaneConnTestRead{payload: payload})
	}
	reads = append(reads, vaneConnTestRead{err: io.EOF})
	var delivered atomic.Int32
	var deliveredBytes atomic.Int64
	underlying := &vaneConnTestConn{reads: reads}
	underlying.closeFunc = func() error {
		require.Equal(t, int32(18), delivered.Load(), "policy close must follow delivery of the triggering chunk")
		return nil
	}
	windows := 0
	wrapped := newVaneControlledConn(underlying, clock, nil, nil, func(vaneThroughputObservation) vanePolicyAction {
		windows++
		if windows < 3 {
			return nil
		}
		return func() bool { return true }
	})
	destination := &vaneConnTestConn{
		writeFunc: func(payload []byte) (int, error) {
			delivered.Add(1)
			deliveredBytes.Add(int64(len(payload)))
			clock.Advance(time.Second)
			return len(payload), nil
		},
		writeBufFunc: func(buffer *buf.Buffer) error {
			delivered.Add(1)
			deliveredBytes.Add(int64(buffer.Len()))
			clock.Advance(time.Second)
			return nil
		},
	}
	copied, err := SBufio.Copy(destination, wrapped)
	require.NoError(t, err)
	require.Equal(t, deliveredBytes.Load(), copied)
	underlying.mu.Lock()
	closeCalls := underlying.closeCalls
	underlying.mu.Unlock()
	require.Equal(t, 1, closeCalls)
}

// RACE-HANDOFF-001: buffer credit defers reconnect until the escape limit.
func TestVaneFlowBufferCreditEventuallyDefersToEscapeLimit(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	// CHAIN-01: beta needs fresh throughput evidence above the close bar.
	group.ensureNodeLocked(beta.Name(), clock.Now())
	group.ensureNodeControlLocked(beta.Name(), clock.Now()).recentTCPThroughput = vaneRecentThroughput{
		bitsPerSecond: 5_000_000, observedAt: clock.Now(),
	}
	group.flow.lowThroughputBPS = 5_000_000
	group.flow.lowWindows = 3
	group.flow.maxLowWindows = 6
	group.flow.demandBPS = 2_000_000
	group.flow.bufferGuard = 5 * time.Second
	metadata := &C.Metadata{Host: "rr6.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	flow := newVaneFlow(group, decision.proxy.Name(), metadata)
	flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
	require.NotNil(t, flow)
	for window := 1; window < 6; window++ {
		sample := vaneThroughputObservation{BitsPerSecond: 2_000_000, TotalBytes: int64(window) * 1_250_000, Age: time.Duration(window*5) * time.Second}
		require.Nil(t, flow.observe(sample))
	}
	sample := vaneThroughputObservation{BitsPerSecond: 2_000_000, TotalBytes: 7_500_000, Age: 30 * time.Second}
	action := flow.observe(sample)
	require.NotNil(t, action)
	require.True(t, action())
	require.True(t, flow.policyAborted())
	var nilFlow *vaneFlow
	require.False(t, nilFlow.policyAborted())
}

// TARGET-FEEDBACK-001: fresh evidence of a slower challenger blocks the handoff.
func TestVaneFlowRejectsFreshKnownSlowerChallenger(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	for i := 0; i < 100; i++ {
		group.observeThroughput("beta", vaneTransportTCP, clock.Now(), 20_000_000)
	}
	group.observeThroughput("beta", vaneTransportTCP, clock.Now(), 500_000)
	flow := newVaneFlow(group, "alpha", &C.Metadata{Host: "rr7.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	require.NotNil(t, flow)
	sample := vaneThroughputObservation{BitsPerSecond: 2_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second}
	require.Nil(t, flow.observe(sample))
	require.Nil(t, flow.observe(sample))
	require.Nil(t, flow.observe(sample))
}

// RACE-ATOMIC-001: commits reject challengers that failed after prepare.
func TestVaneFlowCommitRejectsChallengerThatFailedAfterPrepare(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	// CHAIN-01: beta needs fresh throughput evidence above the close bar.
	group.ensureNodeLocked(beta.Name(), clock.Now())
	group.ensureNodeControlLocked(beta.Name(), clock.Now()).recentTCPThroughput = vaneRecentThroughput{
		bitsPerSecond: 5_000_000, observedAt: clock.Now(),
	}
	metadata := &C.Metadata{Host: "rr10.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	key := group.targetScopeKey(metadata.Host, metadata.DstPort)
	plan, ok := group.prepareReconnect(key, metadata.Host, metadata.DstPort, "alpha", 2_000_000)
	require.True(t, ok)
	group.recordDialFailure(t.Context(), metadata, vaneTransportTCP, beta, errors.New("challenger failed"), clock.Now())
	require.False(t, group.commitReconnect(plan))
	group.mu.Lock()
	_, hinted := group.hints[key]
	slowed := group.nodeCoolingLocked("alpha", clock.Now())
	budget := group.ledger[key]
	group.mu.Unlock()
	require.False(t, hinted)
	require.False(t, slowed)
	require.Zero(t, budget.count)
}

func TestVaneFlowReconnectBudgetIsBounded(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	// CHAIN-01: beta needs fresh throughput evidence above the close bar.
	group.ensureNodeLocked(beta.Name(), clock.Now())
	group.ensureNodeControlLocked(beta.Name(), clock.Now()).recentTCPThroughput = vaneRecentThroughput{
		bitsPerSecond: 5_000_000, observedAt: clock.Now(),
	}
	group.flow.reconnectCooldown = time.Second
	group.flow.slowCooldown = time.Second
	group.flow.budgetMax = 2
	group.flow.budgetWindow = time.Hour
	key := group.targetScopeKey("rr8.googlevideo.com", 443)
	for i := 0; i < 2; i++ {
		plan, ok := group.prepareReconnect(key, "rr8.googlevideo.com", 443, "alpha", 2_000_000)
		require.True(t, ok)
		require.True(t, group.commitReconnect(plan))
		clock.Advance(61 * time.Second)
	}
	_, ok := group.prepareReconnect(key, "rr8.googlevideo.com", 443, "alpha", 2_000_000)
	require.False(t, ok)
}

// TARGET-BOUND-001: candidate cooldowns prune expired entries.
func TestVaneFlowCandidateCooldownPrunesExpiredEntries(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	vaneCoolNodeForTest(group, "alpha", clock.Now().Add(time.Second))
	require.True(t, group.flowCandidateCoolingLocked("alpha", clock.Now()))
	clock.Advance(2 * time.Second)
	require.False(t, group.flowCandidateCoolingLocked("alpha", clock.Now()))
	require.Empty(t, vaneCooledNodes(group))
}

func TestVaneFlowFixedPolicyBoundaries(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	defer group.Close()
	rules, err := parseVaneFamilyRules([]string{"DOMAIN-SUFFIX,googlevideo.com"})
	require.NoError(t, err)
	group.rules = rules
	group.flow, err = newVaneFlowConfig(VaneOption{Reconnect: true, DemandBPS: 5_000_000})
	require.NoError(t, err)
	flow := vaneFlow{group: group}
	require.Equal(t, float64(5_000_000), flow.raceRequest(vaneThroughputObservation{BitsPerSecond: 2_000_000}, 3).requiredBPS)

	now := clock.Now()
	host := "rr9.googlevideo.com"
	key := group.targetScopeKey(host, 443)
	require.NotEmpty(t, key.target)
	group.hints[key] = vaneHint{expiresAt: now}
	group.ledger[key] = vaneSwitchLedger{windowFrom: now.Add(-vaneSwitchBudgetWindow), count: vaneSwitchBudgetMax}
	vaneCoolNodeForTest(group, "alpha", now)
	require.True(t, group.flowCooldownUntilLocked(host, 443, "alpha", now).IsZero())
	require.False(t, group.nodeCoolingLocked("alpha", now))
	group.pruneFlowStateLocked(now)
	require.NotContains(t, group.hints, key)
	require.NotContains(t, group.ledger, key)
}

func TestVaneFlowConfigValidation(t *testing.T) {
	fallback := newVaneTestProxy("fallback", true, false)
	group, err := NewVane(GroupCommonOption{Name: "vane"}, VaneOption{
		Reconnect:        true,
		DemandBPS:        2_000_000,
		ReconnectDomains: []string{"GoogleVideo.Com."},
	}, fallback, nil)
	require.NoError(t, err)
	require.True(t, group.flow.enabled)
	require.Equal(t, float64(5_000_000), group.flow.lowThroughputBPS)
	require.Equal(t, vaneDefaultLowWindows, group.flow.lowWindows)
	require.Equal(t, vaneDefaultMaxLowWindows, group.flow.maxLowWindows)
	require.Equal(t, []string{"googlevideo.com"}, group.flow.domains)
	require.Equal(t, vaneDefaultMinAge, group.flow.minAge)
	require.Equal(t, vaneDefaultMinBytes, group.flow.minBytes)
	require.Equal(t, float64(2_000_000), group.flow.demandBPS)
	require.Equal(t, 5*time.Second, group.flow.bufferGuard)
	require.Equal(t, vaneDefaultReconnectDelay, group.flow.reconnectCooldown)
	require.Equal(t, vaneDefaultSlowCooldown, group.flow.slowCooldown)
	require.Equal(t, vaneDefaultHintTTL, group.flow.hintTTL)
	require.Equal(t, vaneDefaultChallengerRatio, group.flow.challengerRatio)
	require.Equal(t, vaneDefaultBudgetMax, group.flow.budgetMax)
	require.Equal(t, vaneDefaultBudgetWindow, group.flow.budgetWindow)

	invalid := []VaneOption{
		{DemandBPS: vaneBandwidth(-1)},
		{DemandBPS: vaneBandwidth(vaneMaximumThroughputBPS + 1)},
		{ReconnectDomains: []string{".."}},
		{ReconnectDomains: []string{".googlevideo.com"}},
		{ReconnectDomains: []string{"rr..googlevideo.com"}},
		{ReconnectDomains: []string{"googlevideo.com.."}},
	}
	for _, option := range invalid {
		_, err := NewVane(GroupCommonOption{Name: "vane"}, option, fallback, nil)
		require.Error(t, err)
	}
}

// DEMAND-01: demand-bps sets the per-flow demand the watchdog compares against.
func TestVaneDemandBPSSetsDemand(t *testing.T) {
	fallback := newVaneTestProxy("fallback", true, false)

	newGroup := func(option VaneOption) *Vane {
		option.Reconnect = true
		group, err := NewVane(GroupCommonOption{Name: "vane"}, option, fallback, nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = group.Close() })
		return group
	}

	require.Equal(t, float64(8_000_000), newGroup(VaneOption{DemandBPS: 8_000_000}).flow.demandBPS,
		"demand-bps sets the demand")
	require.Equal(t, float64(1_000_000), newGroup(VaneOption{}).flow.demandBPS,
		"the default demand is unchanged")
}

// TARGET-SCOPE-001: hints expire and only apply to allowed domains.
func TestVaneFlowHintExpiresAndOnlyAffectsAllowedDomain(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	key := vaneFlowKey{target: "googlevideo.com", port: 443}
	group.hints[key] = vaneHint{candidate: "beta", expiresAt: clock.Now().Add(5 * time.Second)}

	other := &C.Metadata{Host: "www.youtube.com", DstPort: 443, NetWork: C.TCP}
	require.Equal(t, "alpha", group.pick(other, vaneTransportTCP, false, true).Name())
	family := &C.Metadata{Host: "rr5.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	require.Equal(t, "beta", group.pick(family, vaneTransportTCP, false, true).Name())
	clock.Advance(6 * time.Second)
	require.Equal(t, "alpha", group.pick(family, vaneTransportTCP, false, true).Name())
	group.mu.Lock()
	_, exists := group.hints[key]
	group.mu.Unlock()
	require.False(t, exists)
}

// RULESET-GATE-001: reconnect-domains accepts RULE-SET entries. The
// entry parser is three-state (rule-set / plain domain / error at
// construction), the gate checks rule sets after plain domains, and a hit
// scopes by the provider name.
func TestVaneFlowRuleSetGate(t *testing.T) {
	t.Run("entry parser is three-state", func(t *testing.T) {
		name, isRuleSet, err := parseVaneRuleSetEntry("RULE-SET,streaming")
		require.NoError(t, err)
		require.True(t, isRuleSet)
		require.Equal(t, "streaming", name)
		name, isRuleSet, err = parseVaneRuleSetEntry("rule-set,streaming")
		require.NoError(t, err, "the prefix is case-insensitive")
		require.True(t, isRuleSet)
		require.Equal(t, "streaming", name, "the provider name is kept verbatim")
		_, isRuleSet, err = parseVaneRuleSetEntry("example.com")
		require.NoError(t, err)
		require.False(t, isRuleSet)
		for _, bad := range []string{"RULE-SET,", "RULE-SET,a,b", "RULE-SET, ,"} {
			_, _, err = parseVaneRuleSetEntry(bad)
			require.Error(t, err, "%q must fail at construction", bad)
		}
	})

	t.Run("config splits domains and rule sets", func(t *testing.T) {
		config, err := newVaneFlowConfig(VaneOption{
			ReconnectDomains: []string{"example.com", "RULE-SET,streaming"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{"example.com"}, config.domains)
		require.Equal(t, []string{"streaming"}, config.ruleSets)
		_, err = newVaneFlowConfig(VaneOption{ReconnectDomains: []string{"RULE-SET,"}})
		require.Error(t, err)
	})

	t.Run("gate scopes by provider name after plain domains", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
		configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
		group.flow.domains = []string{"plain.example"}
		group.flow.ruleSets = []string{"streaming", "missing"}

		oldProviders := tunnel.RuleProviders()
		oldRules := tunnel.Rules()
		provider := RP.NewRuleSetProvider("streaming", P.Domain, P.YamlRule, 0, nil,
			[]string{"+.streaming-provider.test"}, nil, nil)
		tunnel.UpdateRules(nil, nil, map[string]P.RuleProvider{"streaming": provider})
		defer tunnel.UpdateRules(oldRules, nil, oldProviders)

		require.Equal(t, vaneFlowKey{target: "plain.example", port: 443},
			group.targetScopeKey("media.plain.example", 443), "plain domains keep priority")
		require.Equal(t, vaneFlowKey{target: "streaming", port: 443},
			group.targetScopeKey("media.streaming-provider.test", 443), "the scope is the provider name")
		require.Equal(t, vaneFlowKey{port: 443},
			group.targetScopeKey("outside.test", 443), "hosts outside every entry stay out of the gate")
	})
}

// GEOSITE-GATE-001: reconnect-domains accepts GEOSITE entries — the
// gate resolves against the shared GeoSite database (no extra download) and
// scopes a hit by the category name. Fail-closed in a database-less sandbox.
func TestVaneFlowGeoSiteGate(t *testing.T) {
	t.Run("entry parser is three-state", func(t *testing.T) {
		category, isGeoSite, err := parseVaneGeoSiteEntry("GEOSITE,telegram")
		require.NoError(t, err)
		require.True(t, isGeoSite)
		require.Equal(t, "telegram", category)
		category, isGeoSite, err = parseVaneGeoSiteEntry("geosite,telegram@cn")
		require.NoError(t, err, "the prefix is case-insensitive")
		require.True(t, isGeoSite)
		require.Equal(t, "telegram@cn", category, "attr suffixes pass through verbatim")
		_, isGeoSite, err = parseVaneGeoSiteEntry("example.com")
		require.NoError(t, err)
		require.False(t, isGeoSite)
		for _, bad := range []string{"GEOSITE,", "GEOSITE,a,b"} {
			_, _, err = parseVaneGeoSiteEntry(bad)
			require.Error(t, err, "%q must fail at construction", bad)
		}
	})

	t.Run("config splits domains, rule sets and geosites", func(t *testing.T) {
		config, err := newVaneFlowConfig(VaneOption{
			ReconnectDomains: []string{"example.com", "RULE-SET,streaming", "GEOSITE,telegram"},
		})
		require.NoError(t, err)
		require.Equal(t, []string{"example.com"}, config.domains)
		require.Equal(t, []string{"streaming"}, config.ruleSets)
		require.Equal(t, []string{"telegram"}, config.geoSites)
		_, err = newVaneFlowConfig(VaneOption{ReconnectDomains: []string{"GEOSITE,"}})
		require.Error(t, err)
	})

	t.Run("gate is fail-closed without a database and keeps plain priority", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
		configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
		group.flow.domains = []string{"plain.example"}
		group.flow.ruleSets = nil
		group.flow.geoSites = []string{"telegram", "youtube"}

		// No GeoSite database in the sandbox: the geosite entries never match,
		// quietly, and plain domains keep working.
		require.Equal(t, vaneFlowKey{target: "plain.example", port: 443},
			group.targetScopeKey("media.plain.example", 443))
		require.Equal(t, vaneFlowKey{port: 443},
			group.targetScopeKey("api.telegram.org", 443))
		require.Equal(t, vaneFlowKey{port: 443},
			group.targetScopeKey("www.youtube.com", 443))
	})
}

// TEST-WRAP-001: test-only convenience, moved out of vane_media.go.
func (a *Vane) prepareReconnect(targetKey vaneFlowKey, target string, port uint16, current string, currentBPS float64) (vaneReconnectPlan, bool) {
	plan, reason := a.prepareReconnectDetailed(targetKey, target, port, current, currentBPS)
	return plan, reason == ""
}

// SWITCH-BUDGET: a target must not ping-pong across nodes forever. Four
// switches within the window are allowed; the fifth is refused.
func TestVaneTargetSwitchBudgetStopsPingPong(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	key := group.targetScopeKey("rr-budget.googlevideo.com", 443)
	now := clock.Now()
	group.mu.Lock()
	defer group.mu.Unlock()
	for i := 0; i < vaneSwitchBudgetMax; i++ {
		require.Empty(t, group.ledgerThrottleReasonLocked(key, now))
		group.noteSwitchLocked(key, "alpha", now)
		now = now.Add(vaneSwitchThrottle + time.Second)
	}
	require.Equal(t, "target-budget", group.ledgerThrottleReasonLocked(key, now))
}

// Observe window: a fresh switch gets 60s to prove itself before it may be
// judged and switched again.
func TestVaneSwitchObserveWindowBlocksImmediateReswitch(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	key := group.targetScopeKey("rr-observe.googlevideo.com", 443)
	now := clock.Now()
	group.mu.Lock()
	defer group.mu.Unlock()
	group.noteSwitchLocked(key, "alpha", now)
	require.Equal(t, "switch-observing", group.ledgerThrottleReasonLocked(key, now.Add(10*time.Second)))
	require.Empty(t, group.ledgerThrottleReasonLocked(key, now.Add(vaneSwitchThrottle+time.Second)))
}

// PHASE2: a non-flow must still carry a concrete state scope, else the
// commit path answered "invalid-target" and burned race budget for nothing.
func TestVaneUntargetedFlowHasStateScope(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	md := &C.Metadata{Host: "api.example.com", DstPort: 443, NetWork: C.TCP}
	flow := newVaneFlow(group, "alpha", md)
	require.NotNil(t, flow)
	require.False(t, flow.targetScoped)
	require.Equal(t, "api.example.com", flow.targetStateKey.targetScope)
	flow.releaseActiveFlowCount()
}

// VERIFY: a landing is judged on the bytes the flow actually moves, not on the
// probe. A node that keeps tripping the low-window counter right after the
// switch is put on cooldown; a node we never landed on is untouched, and the
// same node is excused once the observe window has passed.
func TestVaneVerifyPenaltyCoolsSlowLanding(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	key := group.targetScopeKey("rr-verify.googlevideo.com", 443)
	now := clock.Now()

	group.mu.Lock()
	group.noteSwitchLocked(key, "beta", now)
	group.mu.Unlock()

	// A node we did not land on must not be cooled by this target's landing.
	group.penalizeSlowLanding(key, "alpha", now.Add(10*time.Second))
	group.mu.Lock()
	require.Empty(t, vaneCooledNodesLocked(group))
	group.mu.Unlock()

	// The node we did land on is cooled for the penalty duration.
	group.penalizeSlowLanding(key, "beta", now.Add(10*time.Second))
	group.mu.Lock()
	cooled := len(vaneCooledNodesLocked(group))
	group.mu.Unlock()
	require.Equal(t, 1, cooled)

	// Past the observe window the landing is no longer judged.
	other := vaneFlowKey{target: "rr-verify2.example", port: 443}
	group.mu.Lock()
	group.noteSwitchLocked(other, "beta", now)
	group.mu.Unlock()
	group.penalizeSlowLanding(other, "beta", now.Add(vaneSwitchThrottle+time.Second))
	group.mu.Lock()
	stillOne := len(vaneCooledNodesLocked(group))
	group.mu.Unlock()
	require.Equal(t, 1, stillOne)
}

func TestVanePruneDropsExpiredTargetScopedState(t *testing.T) {
	group, clock, _ := newVaneObservationRig(t, vaneSwitchLive)
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	now := clock.Now()
	key := vaneFlowKey{target: "rr-prune.example", port: 443}
	stickyKey := vaneStickyKeyFor("rr-prune.example", 443)
	group.mu.Lock()
	group.ledger[key] = vaneSwitchLedger{windowFrom: now.Add(-2 * vaneSwitchBudgetWindow), lastSwitch: now.Add(-time.Hour), count: 3}
	group.stickiness[stickyKey] = vaneStickyChoice{name: "alpha", expiresAt: now.Add(-time.Second)}
	group.lastPickProbeAt["rr-prune.example"] = now.Add(-3 * vaneRacingCapabilityTTL)
	group.pruneFlowStateLocked(now)
	_, hasSwitch := group.ledger[key]
	_, hasSticky := group.stickiness[stickyKey]
	_, hasProbe := group.lastPickProbeAt["rr-prune.example"]
	group.mu.Unlock()
	require.False(t, hasSwitch, "expired target switch budget must be pruned")
	require.False(t, hasSticky, "expired sticky choice must be pruned")
	require.False(t, hasProbe, "stale cold-pick timestamp must be pruned")
}

// AUDIT-LOW-LINE: an out-of-range low-throughput-bps is rejected at
// construction instead of silently turning every window into a low one.
func TestVaneLowThroughputBPSRange(t *testing.T) {
	fallback := newVaneTestProxy("fallback", true, false)
	_, err := NewVane(GroupCommonOption{Name: "vane"}, VaneOption{
		Reconnect:        true,
		LowThroughputBPS: vaneBandwidth(vaneMaximumThroughputBPS + 1),
	}, fallback, nil)
	require.ErrorContains(t, err, "low-throughput-bps must be between 0 and")
}

// AUDIT-FLOOR: the rescue floor follows the configured slow line, so a pool
// tuned to 20M never hands a stalled flow to a 5M node.
func TestVaneReconnectFloorFollowsTheSlowLine(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	require.Equal(t, float64(5_000_000), group.reconnectFloorLocked(),
		"the default slow line is the floor")
	group.flow.lowThroughputBPS = 20_000_000
	require.Equal(t, float64(20_000_000), group.reconnectFloorLocked(),
		"a configured slow line raises the floor")
	group.flow.lowThroughputBPS = 1_000_000
	require.Equal(t, float64(5_000_000), group.reconnectFloorLocked(),
		"a slow line below the default never lowers the floor")
}

// AUDIT-INFLIGHT: a leaked cold-pick in-flight flag is pruned like the other
// per-scope maps instead of holding its scope forever.
func TestVanePruneDropsStaleInflightProbe(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	now := clock.Now()
	group.pickProbeInflight["stale.example"] = now.Add(-3 * vaneRacingCapabilityTTL)
	group.pickProbeInflight["fresh.example"] = now

	group.pruneFlowStateLocked(now)

	_, stale := group.pickProbeInflight["stale.example"]
	_, fresh := group.pickProbeInflight["fresh.example"]
	require.False(t, stale, "stale in-flight flag is pruned")
	require.True(t, fresh, "a fresh in-flight flag survives")
}

// NODE-COOL-IDENTITY: a cooldown belongs to the endpoint that earned it, not to
// the display name. A subscription reload can reuse a name for a different
// endpoint, and that new endpoint must not start out cooled.
func TestVaneNodeCooldownDoesNotFollowAReusedName(t *testing.T) {
	group, clock, _, _, _ := newTargetGroupForTest(t)
	now := clock.Now()

	group.mu.Lock()
	group.nodeIdentities["beta"] = "endpoint-a"
	group.ensureNodeIdentityLocked("beta", "endpoint-a", now)
	group.coolNodeLocked("beta", now.Add(time.Minute))
	held := group.nodeCoolingLocked("beta", now)
	group.nodeIdentities["beta"] = "endpoint-b"
	group.ensureNodeIdentityLocked("beta", "endpoint-b", now)
	reused := group.nodeCoolingLocked("beta", now)
	group.mu.Unlock()

	require.True(t, held, "the cooldown holds for the endpoint that earned it")
	require.False(t, reused, "a different endpoint under the same name must not inherit it")
}

// LOW-VOLUME-01: a phone video can stall below the min-bytes gate and never
// reach it. Once the socket has been fully silent long enough the flow must
// still be judged, otherwise the screen sits on a spinner forever.
func TestVaneLowVolumeStallStillJudged(t *testing.T) {
	group, _, flow := newVaneObservationRig(t, vaneSwitchLive)
	dropVaneRecordedEvents(group)
	t.Cleanup(func() { dropVaneRecordedEvents(group) })

	response := flow.observe(vaneThroughputObservation{
		BitsPerSecond: 1,
		untrusted:     true,
		synthetic:     true,
		TotalBytes:    512 * 1024,
		Age:           60 * time.Second,
	})
	require.NotZero(t, countVaneEvents(group, "race-scheduled", "")+countVaneEvents(group, "reconnect-suppressed", ""),
		"a silent low-volume flow must still reach the switch decision, action=%v", response)
}

// LOW-VOLUME-02: the exemption is for a socket that went silent, not for any
// small flow. A live SSE heartbeat must not be judged on volume alone, so the
// synthetic flag is part of the condition.
func TestVaneLowVolumeNeedsASyntheticWindow(t *testing.T) {
	group, _, flow := newVaneObservationRig(t, vaneSwitchLive)
	dropVaneRecordedEvents(group)
	t.Cleanup(func() { dropVaneRecordedEvents(group) })

	// Four windows also clear the credit gate, so the min-bytes gate is the
	// only thing left that can refuse this flow.
	for i := 0; i < 4; i++ {
		flow.observe(vaneThroughputObservation{
			BitsPerSecond: 1,
			untrusted:     true,
			TotalBytes:    512 * 1024,
			Age:           60 * time.Second,
		})
	}
	require.Zero(t, countVaneEvents(group, "race-scheduled", "")+countVaneEvents(group, "reconnect-suppressed", ""),
		"a live small flow must stay below the min-bytes gate")
}
