package outboundgroup

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	C "github.com/metacubex/mihomo/constant"
	SBufio "github.com/metacubex/sing/common/bufio"

	"github.com/stretchr/testify/require"
)

func configureVaneMediaForTest(t *testing.T, group *Vane, rules ...string) {
	t.Helper()
	parsed, err := parseVaneSceneRules(rules)
	require.NoError(t, err)
	group.rules = parsed
	group.media = defaultVaneMediaConfig()
	group.media.enabled = true
	group.media.domains = []string{"googlevideo.com"}
	group.media.lowThroughputBPS = 3_000_000
	group.media.lowWindows = 3
	group.media.maxLowWindows = 6
	group.media.minAge = 10 * time.Second
	group.media.minBytes = 512 * 1024
	group.media.demandBPS = 1
	group.media.bufferGuard = 0
	group.media.reconnectCooldown = 2 * time.Minute
	group.media.slowCooldown = 5 * time.Minute
	group.media.hintTTL = 15 * time.Second
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
func TestVaneMediaReconnectClosesOnceAndHandsOffTarget(t *testing.T) {
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
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	metadata := &C.Metadata{Host: "rr1.googlevideo.com", DstPort: 443, NetWork: C.TCP}

	conn, err := group.DialContext(t.Context(), metadata)
	require.NoError(t, err)
	anchorKey := vaneAnchorKey{transport: vaneTransportTCP, scene: vaneSceneMedia}
	group.mu.Lock()
	selected := group.anchors[anchorKey].name
	group.mu.Unlock()
	require.Equal(t, "alpha", selected)

	readVaneLowWindows(t, conn, clock, 3)
	alphaConn.mu.Lock()
	closeCalls := alphaConn.closeCalls
	alphaConn.mu.Unlock()
	require.Equal(t, 1, closeCalls, "the last positive payload must be delivered before one policy close")

	key := vaneMediaTargetKey{target: "googlevideo.com", port: 443}
	group.mu.Lock()
	hint := group.mediaHints[key]
	_, slow := group.mediaSlowCooldowns[vaneMediaCandidateKey{vaneMediaTargetKey: key, candidate: "alpha", identity: alpha.identity}]
	group.mu.Unlock()
	require.Equal(t, "beta", hint.candidate)
	require.True(t, slow)

	require.Equal(t, "beta", group.pick(metadata, vaneTransportTCP, false, true).Name(), "the reconnect must follow the media-domain handoff")
	group.mu.Lock()
	_, hintStillPresent := group.mediaHints[key]
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
func TestVaneMediaOldFlowCannotCoolDownSameNameReplacement(t *testing.T) {
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
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	metadata := &C.Metadata{Host: "rr-old.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	conn, err := group.DialContext(t.Context(), metadata)
	require.NoError(t, err)

	newAlpha := newVaneTestProxy("alpha", true, true)
	newAlpha.identity = "alpha-new"
	newAlpha.delay = 20
	provider.setProxies(newAlpha, beta)
	readVaneLowWindows(t, conn, clock, 3)

	key := vaneMediaTargetKey{target: "googlevideo.com", port: 443}
	group.mu.Lock()
	_, slowed := group.mediaSlowCooldowns[vaneMediaCandidateKey{vaneMediaTargetKey: key, candidate: "alpha"}]
	_, hinted := group.mediaHints[key]
	group.mu.Unlock()
	require.False(t, slowed)
	require.False(t, hinted)
	oldConn.mu.Lock()
	closeCalls := oldConn.closeCalls
	oldConn.mu.Unlock()
	require.Zero(t, closeCalls, "stale media policy must not close the old stream or control the replacement")
	require.NoError(t, conn.Close())
}

// TARGET-BOUND-001: prepared plans reject same-name replacements.
func TestVaneMediaPreparedPlanRejectsSameNameReplacement(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.identity = "alpha-old"
	alpha.delay = 20
	beta := newVaneTestProxy("beta", true, true)
	beta.identity = "beta"
	beta.delay = 10
	group, provider := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	metadata := &C.Metadata{Host: "rr-plan.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
	group.mu.Lock()
	state := group.nodes["alpha"]
	identity, epoch := state.identity, state.epoch
	group.mu.Unlock()
	key := group.mediaTargetKey(metadata.Host, metadata.DstPort)
	plan, reason := group.prepareMediaReconnectForNodeDetailed(key, metadata.Host, metadata.DstPort, "alpha", identity, epoch, 2_000_000)
	require.Empty(t, reason)

	newAlpha := newVaneTestProxy("alpha", true, true)
	newAlpha.identity = "alpha-new"
	newAlpha.delay = 20
	provider.setProxies(newAlpha, beta)
	require.Equal(t, "stale-node-identity", group.commitMediaReconnectDetailed(plan))
}

// TARGET-BOUND-001: commits reject replacements observed during health check.
func TestVaneMediaCommitRejectsReplacementDuringHealthCheck(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.identity = "alpha-old"
	alpha.delay = 20
	beta := newVaneTestProxy("beta", true, true)
	beta.identity = "beta"
	beta.delay = 10
	group, provider := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	metadata := &C.Metadata{Host: "rr-commit-race.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
	group.mu.Lock()
	state := group.nodes["alpha"]
	identity, epoch := state.identity, state.epoch
	group.mu.Unlock()
	key := group.mediaTargetKey(metadata.Host, metadata.DstPort)
	plan, reason := group.prepareMediaReconnectForNodeDetailed(key, metadata.Host, metadata.DstPort, "alpha", identity, epoch, 2_000_000)
	require.Empty(t, reason)

	newAlpha := newVaneTestProxy("alpha", true, true)
	newAlpha.identity = "alpha-new"
	newAlpha.delay = 20
	var replace sync.Once
	beta.aliveHook = func() { replace.Do(func() { provider.setProxies(newAlpha, beta) }) }
	require.Equal(t, "stale-node-identity", group.commitMediaReconnectDetailed(plan))
}

// TARGET-LEASE-001: repeated provider entries deduplicate to one lease.
func TestVaneMediaProviderLeaseDeduplicatesRepeatedProvider(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	group, provider := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	group.providers = append(group.providers, group.providers[0])
	release, ok := group.lockVaneMediaIdentities(map[string]string{"alpha": alpha.identity})
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
	decision := group.pickInternalDecision(metadata, vaneTransportTCP, false, true, false)
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
func TestVaneMediaHintRejectsSameNameChallengerReplacement(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.identity = "alpha"
	alpha.delay = 20
	beta := newVaneTestProxy("beta", true, true)
	beta.identity = "beta-old"
	beta.delay = 10
	group, provider := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	metadata := &C.Metadata{Host: "rr-hint-race.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
	group.mu.Lock()
	state := group.nodes["alpha"]
	identity, epoch := state.identity, state.epoch
	group.mu.Unlock()
	key := group.mediaTargetKey(metadata.Host, metadata.DstPort)
	plan, reason := group.prepareMediaReconnectForNodeDetailed(key, metadata.Host, metadata.DstPort, "alpha", identity, epoch, 2_000_000)
	require.Empty(t, reason)
	require.Empty(t, group.commitMediaReconnectDetailed(plan))

	newAlpha := newVaneTestProxy("alpha", true, true)
	newAlpha.identity = "alpha-new"
	newBeta := newVaneTestProxy("beta", true, true)
	newBeta.identity = "beta-new"
	provider.setProxies(newAlpha, newBeta)
	group.mu.Lock()
	hinted, handoff := group.takeMediaHintLocked(metadata.Host, metadata.DstPort, []C.Proxy{newAlpha, newBeta}, clock.Now(), true)
	newAlphaCooldown := group.mediaCooldownUntilLockedWithCleanup(metadata.Host, metadata.DstPort, "alpha", newAlpha.identity, clock.Now(), false)
	group.mu.Unlock()
	require.Nil(t, hinted)
	require.Nil(t, handoff)
	require.True(t, newAlphaCooldown.IsZero())
}

// TARGET-SCOPE-001: reconnect never cuts web or small traffic.
func TestVaneMediaReconnectNeverCutsWebOrSmallTraffic(t *testing.T) {
	tests := []struct {
		name  string
		rules []string
		host  string
	}{
		{name: "default webpage", rules: []string{"DOMAIN-SUFFIX,googlevideo.com,media"}, host: "www.youtube.com"},
		{name: "interactive webpage", rules: []string{"DOMAIN-SUFFIX,youtube.com,interactive"}, host: "www.youtube.com"},
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
			configureVaneMediaForTest(t, group, test.rules...)
			metadata := &C.Metadata{Host: test.host, DstPort: 443, NetWork: C.TCP}

			conn, err := group.DialContext(t.Context(), metadata)
			require.NoError(t, err)
			readVaneLowWindows(t, conn, clock, 4)
			underlying.mu.Lock()
			closeCalls := underlying.closeCalls
			underlying.mu.Unlock()
			require.Zero(t, closeCalls, "non-media traffic must never be policy-closed")
			require.NoError(t, conn.Close())
		})
	}
}

// RACE-HANDOFF-001: reconnect safety gates hold before any close.
func TestVaneMediaReconnectSafetyGates(t *testing.T) {
	t.Run("no health-qualified challenger", func(t *testing.T) {
		clock := newVaneConnTestClock()
		underlying := &vaneConnTestConn{readFunc: func(payload []byte) (int, error) { return len(payload), nil }}
		alpha := newVaneTestProxy("alpha", true, true)
		alpha.dialConn = underlying
		beta := newVaneTestProxy("beta", true, true)
		beta.delay = 0
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		conn, err := group.DialContext(t.Context(), &C.Metadata{Host: "rr2.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		require.NoError(t, err)
		readVaneLowWindows(t, conn, clock, 4)
		underlying.mu.Lock()
		closeCalls := underlying.closeCalls
		underlying.mu.Unlock()
		require.Zero(t, closeCalls)
		require.NoError(t, conn.Close())
	})

	t.Run("good window resets consecutive low count", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		flow := newVaneMediaFlow(group, "alpha", &C.Metadata{Host: "rr3.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		require.NotNil(t, flow)
		low := vaneThroughputObservation{BitsPerSecond: 1_000_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second}
		high := vaneThroughputObservation{BitsPerSecond: 10_000_000, TotalBytes: 5 * 1024 * 1024, Age: 25 * time.Second}
		require.Nil(t, flow.observe(low))
		require.Nil(t, flow.observe(low))
		require.Nil(t, flow.observe(high))
		require.Nil(t, flow.observe(low))
		require.Nil(t, flow.observe(low))
		flow.mu.Lock()
		count := flow.lowWindows
		flow.mu.Unlock()
		require.Equal(t, 2, count)
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
func TestVaneMediaBufferCreditEventuallyDefersToEscapeLimit(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	group.media.lowThroughputBPS = 5_000_000
	group.media.lowWindows = 3
	group.media.maxLowWindows = 6
	group.media.demandBPS = 2_000_000
	group.media.bufferGuard = 5 * time.Second
	flow := newVaneMediaFlow(group, "alpha", &C.Metadata{Host: "rr6.googlevideo.com", DstPort: 443, NetWork: C.TCP})
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
	var nilFlow *vaneMediaFlow
	require.False(t, nilFlow.policyAborted())
}

// TARGET-FEEDBACK-001: fresh evidence of a slower challenger blocks the handoff.
func TestVaneMediaRejectsFreshKnownSlowerChallenger(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	for i := 0; i < 100; i++ {
		group.observeThroughput("beta", vaneTransportTCP, clock.Now(), 20_000_000)
	}
	group.observeThroughput("beta", vaneTransportTCP, clock.Now(), 500_000)
	flow := newVaneMediaFlow(group, "alpha", &C.Metadata{Host: "rr7.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	require.NotNil(t, flow)
	sample := vaneThroughputObservation{BitsPerSecond: 2_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second}
	require.Nil(t, flow.observe(sample))
	require.Nil(t, flow.observe(sample))
	require.Nil(t, flow.observe(sample))
}

// RACE-ATOMIC-001: commits reject challengers that failed after prepare.
func TestVaneMediaCommitRejectsChallengerThatFailedAfterPrepare(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	metadata := &C.Metadata{Host: "rr10.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	key := group.mediaTargetKey(metadata.Host, metadata.DstPort)
	plan, ok := group.prepareMediaReconnect(key, metadata.Host, metadata.DstPort, "alpha", 2_000_000)
	require.True(t, ok)
	group.recordDialFailure(t.Context(), metadata, vaneTransportTCP, beta, errors.New("challenger failed"), clock.Now())
	require.False(t, group.commitMediaReconnect(plan))
	group.mu.Lock()
	_, hinted := group.mediaHints[key]
	_, slowed := group.mediaSlowCooldowns[vaneMediaCandidateKey{vaneMediaTargetKey: key, candidate: "alpha"}]
	budget := group.mediaBudgets[key]
	group.mu.Unlock()
	require.False(t, hinted)
	require.False(t, slowed)
	require.Zero(t, budget.count)
}

func TestVaneMediaReconnectBudgetIsBounded(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	group.media.reconnectCooldown = time.Second
	group.media.slowCooldown = time.Second
	group.media.budgetMax = 2
	group.media.budgetWindow = time.Hour
	key := group.mediaTargetKey("rr8.googlevideo.com", 443)
	for i := 0; i < 2; i++ {
		plan, ok := group.prepareMediaReconnect(key, "rr8.googlevideo.com", 443, "alpha", 2_000_000)
		require.True(t, ok)
		require.True(t, group.commitMediaReconnect(plan))
		clock.Advance(2 * time.Second)
	}
	_, ok := group.prepareMediaReconnect(key, "rr8.googlevideo.com", 443, "alpha", 2_000_000)
	require.False(t, ok)
}

// TARGET-BOUND-001: candidate cooldowns prune expired entries.
func TestVaneMediaCandidateCooldownPrunesExpiredEntries(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	key := vaneMediaCandidateKey{vaneMediaTargetKey: group.mediaTargetKey("rr9.googlevideo.com", 443), candidate: "alpha"}
	group.mediaSlowCooldowns[key] = clock.Now().Add(time.Second)
	require.True(t, group.mediaCandidateCoolingLocked("alpha", clock.Now()))
	clock.Advance(2 * time.Second)
	require.False(t, group.mediaCandidateCoolingLocked("alpha", clock.Now()))
	require.Empty(t, group.mediaSlowCooldowns)
}

func TestVaneMediaConfigValidation(t *testing.T) {
	fallback := newVaneTestProxy("fallback", true, false)
	group, err := NewVane(GroupCommonOption{Name: "vane"}, VaneOption{
		MediaReconnect:         true,
		MediaReconnectDomains:  []string{"GoogleVideo.Com."},
		MediaLowThroughput:     5_000_000,
		MediaLowWindows:        4,
		MediaMaxLowWindows:     8,
		MediaMinAge:            20,
		MediaMinBytes:          8 * 1024 * 1024,
		MediaDemandBPS:         2_000_000,
		MediaBufferGuard:       5,
		MediaReconnectCooldown: 180,
		MediaSlowCooldown:      600,
		MediaHintTTL:           10,
		MediaChallengerRatio:   1.5,
		MediaReconnectBudget:   2,
		MediaBudgetWindow:      900,
	}, fallback, nil)
	require.NoError(t, err)
	require.True(t, group.media.enabled)
	require.Equal(t, float64(5_000_000), group.media.lowThroughputBPS)
	require.Equal(t, 4, group.media.lowWindows)
	require.Equal(t, 8, group.media.maxLowWindows)
	require.Equal(t, []string{"googlevideo.com"}, group.media.domains)
	require.Equal(t, 20*time.Second, group.media.minAge)
	require.Equal(t, int64(8*1024*1024), group.media.minBytes)
	require.Equal(t, float64(2_000_000), group.media.demandBPS)
	require.Equal(t, 5*time.Second, group.media.bufferGuard)
	require.Equal(t, 180*time.Second, group.media.reconnectCooldown)
	require.Equal(t, 600*time.Second, group.media.slowCooldown)
	require.Equal(t, 10*time.Second, group.media.hintTTL)
	require.Equal(t, 1.5, group.media.challengerRatio)
	require.Equal(t, 2, group.media.budgetMax)
	require.Equal(t, 900*time.Second, group.media.budgetWindow)

	invalid := []VaneOption{
		{MediaLowThroughput: -1},
		{MediaLowWindows: -1},
		{MediaMaxLowWindows: -1},
		{MediaLowWindows: 4, MediaMaxLowWindows: 3},
		{MediaMinAge: -1},
		{MediaMinBytes: -1},
		{MediaDemandBPS: -1},
		{MediaBufferGuard: -1},
		{MediaReconnectCooldown: -1},
		{MediaSlowCooldown: -1},
		{MediaHintTTL: -1},
		{MediaChallengerRatio: 0.5},
		{MediaReconnectBudget: -1},
		{MediaBudgetWindow: -1},
		{MediaReconnectDomains: []string{".."}},
		{MediaReconnectDomains: []string{".googlevideo.com"}},
		{MediaReconnectDomains: []string{"rr..googlevideo.com"}},
		{MediaReconnectDomains: []string{"googlevideo.com.."}},
	}
	for _, option := range invalid {
		_, err := NewVane(GroupCommonOption{Name: "vane"}, option, fallback, nil)
		require.Error(t, err)
	}
}

// TARGET-SCOPE-001: hints expire and only apply to allowed domains.
func TestVaneMediaHintExpiresAndOnlyAffectsAllowedDomain(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	key := vaneMediaTargetKey{target: "googlevideo.com", port: 443}
	group.mediaHints[key] = vaneMediaHint{candidate: "beta", expiresAt: clock.Now().Add(5 * time.Second)}

	other := &C.Metadata{Host: "www.youtube.com", DstPort: 443, NetWork: C.TCP}
	require.Equal(t, "alpha", group.pick(other, vaneTransportTCP, false, true).Name())
	family := &C.Metadata{Host: "rr5.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	require.Equal(t, "beta", group.pick(family, vaneTransportTCP, false, true).Name())
	clock.Advance(6 * time.Second)
	require.Equal(t, "alpha", group.pick(family, vaneTransportTCP, false, true).Name())
	group.mu.Lock()
	_, exists := group.mediaHints[key]
	group.mu.Unlock()
	require.False(t, exists)
}
