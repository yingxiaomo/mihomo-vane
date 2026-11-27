package outboundgroup

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func newVaneFlowFixRig(t *testing.T, host string) (*Vane, *vaneConnTestClock, *C.Metadata, *vaneObservedConn, *vaneConnTestConn) {
	t.Helper()
	clock := newVaneConnTestClock()
	read := func(payload []byte) (int, error) { return len(payload), nil }
	slow := &vaneConnTestConn{readFunc: read}
	fast := &vaneConnTestConn{readFunc: read}
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.dialConn = slow
	beta := newVaneTestProxy("beta", true, true)
	beta.dialConn = fast
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	chain01ProductionValues(t, group, 1_000_000)
	configureVaneSwitchForTest(t, group, vaneSwitchLive)
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		return vaneProbeResult{reason: "test-no-network"}
	}
	t.Cleanup(func() { require.NoError(t, group.Close()) })
	metadata := &C.Metadata{Host: host, DstPort: 443, NetWork: C.TCP}
	conn, err := group.DialContext(context.Background(), metadata)
	require.NoError(t, err)
	observed := conn.(*vaneObservedConn)
	require.Same(t, slow, observed.Conn, "the cold ranking starts on alpha")
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	seedChain01Traffic(t, group, beta.Name(), clock.Now(), 40_000_000)
	return group, clock, metadata, observed, slow
}

func readVaneFlowFix(t *testing.T, observed *vaneObservedConn, size int) {
	t.Helper()
	reader, counters := observed.UnwrapReader()
	n, err := reader.Read(make([]byte, size))
	require.NoError(t, err)
	require.Equal(t, size, n)
	for _, counter := range counters {
		counter(int64(n))
	}
}

func vaneFlowFixCloseCount(conn *vaneConnTestConn) int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.closeCalls
}

func TestVaneFlowRescueFamilyOrHostEndToEnd(t *testing.T) {
	for _, tc := range []struct {
		name, host       string
		large, wantClose bool
	}{
		{"family-large", "rr.googlevideo.com", true, true},
		{"host-large", "download.example.org", true, true},
		{"family-small", "rr.googlevideo.com", false, true},
		{"host-small-protected", "api.example.org", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			group, clock, metadata, first, raw := newVaneFlowFixRig(t, tc.host)
			reads, size := 10, 64
			if tc.large {
				reads, size = 20, 512<<10
			}
			for i := 0; i < reads; i++ {
				clock.Advance(time.Second)
				readVaneFlowFix(t, first, size)
			}
			require.Zero(t, vaneFlowFixCloseCount(raw), "active traffic must not be cut")
			clock.Advance(2 * time.Minute)
			group.runFlowWatchdogTick(clock.Now())
			if !tc.wantClose {
				require.Zero(t, vaneFlowFixCloseCount(raw), "unconfigured hosts retain their 8 MiB protection")
				require.Zero(t, group.VaneDiagnostics().Counters.HandoffCommitted)
				return
			}
			require.Equal(t, 1, vaneFlowFixCloseCount(raw), "eligible silent flows must reach commit and Close")
			require.Zero(t, countVaneEvents(group, "reconnect-rejected", "invalid-target"))

			second, err := group.DialContext(context.Background(), metadata)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, second.Close()) })
			key := vaneTargetKey{transport: vaneTransportTCP, targetScope: tc.host, port: 443}
			if scoped, ok := group.targetScopeForKey(tc.host, 443); ok {
				key = scoped
			}
			group.mu.Lock()
			lease, leased := group.targetHandoffs[key]
			group.mu.Unlock()
			require.True(t, leased, "reconnect must find the same family-or-host lease that commit wrote")
			require.True(t, lease.claimed, "the new connection must claim the winner, not merely rank it first")
			require.Equal(t, "beta", lease.to.name)
			for i := 0; i < 6; i++ {
				if i > 0 {
					clock.Advance(time.Second)
				}
				readVaneFlowFix(t, second.(*vaneObservedConn), 2<<20)
			}
			group.mu.Lock()
			preference, preferred := group.targetPreferences[key]
			_, pending := group.targetHandoffs[key]
			ledger := group.ledger[vaneFlowKey{target: key.targetScope, port: key.port}]
			group.mu.Unlock()
			require.Equal(t, uint64(1), group.VaneDiagnostics().Counters.HandoffImproved)
			require.True(t, preferred, "the real fast landing must settle even for a non-family host")
			require.Equal(t, "beta", preference.to.name)
			require.False(t, pending)
			require.Empty(t, ledger.verifyNode, "a proven winner must no longer be marked unverified")

			// A later preferred connection has no handoff token. Its real low
			// window must still invalidate this same family-or-host preference.
			third, err := group.DialContext(context.Background(), metadata)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, third.Close()) })
			for i := 0; i < 6; i++ {
				if i > 0 {
					clock.Advance(time.Second)
				}
				readVaneFlowFix(t, third.(*vaneObservedConn), 32<<10)
			}
			group.mu.Lock()
			_, preferred = group.targetPreferences[key]
			group.mu.Unlock()
			require.False(t, preferred, "a new slow connection must invalidate a stale preference without a token")
		})
	}
}

func TestVaneFlowSmallHeartbeatRequiresActualSilence(t *testing.T) {
	for _, silence := range []time.Duration{11 * time.Second, 13 * time.Second, 30 * time.Second, 44 * time.Second, 45 * time.Second, 46 * time.Second} {
		t.Run(silence.String(), func(t *testing.T) {
			group, clock, _, observed, raw := newVaneFlowFixRig(t, "api.googlevideo.com")
			for i := 0; i < 12; i++ {
				clock.Advance(10 * time.Second)
				readVaneFlowFix(t, observed, 64)
			}
			clock.Advance(silence)
			group.runFlowWatchdogTick(clock.Now())
			require.Equal(t, silence >= 45*time.Second, vaneFlowFixCloseCount(raw) > 0,
				"connection lifetime exceeds two minutes, but only actual silence may clear the small-flow gate")
		})
	}
	t.Run("successive-watchdog-ticks", func(t *testing.T) {
		group, clock, _, observed, raw := newVaneFlowFixRig(t, "api.googlevideo.com")
		for i := 0; i < 12; i++ {
			clock.Advance(10 * time.Second)
			readVaneFlowFix(t, observed, 64)
		}
		lastRead := clock.Now()
		for _, silence := range []time.Duration{13 * time.Second, 30 * time.Second, 44 * time.Second, 45 * time.Second} {
			clock.Advance(lastRead.Add(silence).Sub(clock.Now()))
			group.runFlowWatchdogTick(clock.Now())
			require.Equal(t, silence >= 45*time.Second, vaneFlowFixCloseCount(raw) > 0,
				"an earlier synthetic tick must not reset the real last-byte clock")
		}
	})
}

func TestVaneFlowSyntheticKeepsRealSampleClock(t *testing.T) {
	group, clock, flow := newVaneObservationRig(t, vaneSwitchObserve)
	original := vaneObservationLowSample()
	flow.observe(original)
	sampledAt := clock.Now()
	seedChain01Traffic(t, group, "beta", sampledAt, 40_000_000)
	var latest vaneDiagnosticRecord
	group.diagnostics.mu.Lock()
	previousSink := group.diagnostics.sink
	group.diagnostics.sink = func(record vaneDiagnosticRecord) {
		previousSink(record)
		if record.kind == "handoff-would-commit" {
			latest = record
		}
	}
	group.diagnostics.mu.Unlock()
	tolerance := stallToleranceForTest(t, flow)
	for _, silence := range []time.Duration{tolerance + time.Second, tolerance + 6*time.Second} {
		clock.Advance(sampledAt.Add(silence).Sub(clock.Now()))
		group.runFlowWatchdogTick(clock.Now())
		flow.mu.Lock()
		last, lastAt, hasSample := flow.lastSample, flow.lastSampleAt, flow.hasSample
		flow.mu.Unlock()
		require.True(t, hasSample)
		require.Equal(t, original, last, "large flows must retain real bytes and age for the next watchdog tick")
		require.Equal(t, sampledAt, lastAt)
		group.diagnostics.mu.Lock()
		event := latest
		group.diagnostics.mu.Unlock()
		require.Equal(t, float64(1), event.bps, "watchdog must still feed a near-zero policy window")
		require.Equal(t, original.TotalBytes, event.totalBytes)
		require.Equal(t, original.Age+silence, event.age, "synthetic age must advance from the real sample, not from the previous tick")
	}
}

func TestVaneFlowZeroByteRetainsNinetySecondPatience(t *testing.T) {
	for _, silence := range []time.Duration{89 * time.Second, 90 * time.Second, 91 * time.Second} {
		t.Run(silence.String(), func(t *testing.T) {
			group, clock, _, _, raw := newVaneFlowFixRig(t, "rr.googlevideo.com")
			clock.Advance(silence)
			group.runFlowWatchdogTick(clock.Now())
			require.Equal(t, silence >= 90*time.Second, vaneFlowFixCloseCount(raw) > 0)
		})
	}
}

func TestVaneFlowLandingRetainsTokenUntilTrustedVerdict(t *testing.T) {
	for _, first := range []string{"trusted-control", "client-backlog", "short-window"} {
		t.Run(first, func(t *testing.T) {
			group, clock, _, beta, metadata := newTargetGroupForTest(t)
			t.Cleanup(func() { require.NoError(t, group.Close()) })
			chain01ProductionValues(t, group, 1_000_000)
			plan := prepareTargetHandoffForTest(t, group, metadata, beta)
			require.Empty(t, group.commitTargetHandoff(plan))
			decision := group.pickDecision(context.Background(), metadata, vaneTransportTCP, false, true)
			require.NotNil(t, decision.handoff)
			flow := newVaneFlow(group, decision.proxy.Name(), metadata, decision.handoff)
			flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
			observed := newVaneControlledConnWithNative(&vaneConnTestConn{}, clock, nil, nil, flow.observe, nil,
				func(vaneConnectionCloseObservation) { flow.releaseActiveFlowCount() }, nil, flow.markClosed).(*vaneObservedConn)
			observed.enableDirectPolicy()
			t.Cleanup(func() { require.NoError(t, observed.Close()) })
			started := clock.Now()
			switch first {
			case "client-backlog":
				flow.setBacklogFunc(func() int64 { return 1 << 20 })
				flow.noteBacklog(clock.Now())
				for i := 0; i < 6; i++ {
					if i > 0 {
						clock.Advance(time.Second)
					}
					observed.observeRead(clock.Now(), 32<<10, true)
				}
				flow.setBacklogFunc(func() int64 { return 0 })
			case "short-window":
				// Qualified connection windows are normally longer. Exercise the
				// policy boundary explicitly so future shorter windows stay safe.
				flow.observe(vaneThroughputObservation{BitsPerSecond: 50_000_000, Age: 200 * time.Millisecond})
			}
			if first != "trusted-control" {
				flow.mu.Lock()
				pending := flow.handoff
				flow.mu.Unlock()
				require.Same(t, decision.handoff, pending, "an inconclusive first window must retain the flow token")
				group.mu.Lock()
				_, pendingLease := group.targetHandoffs[plan.targetStateKey]
				group.mu.Unlock()
				require.True(t, pendingLease, "an inconclusive window must retain the target lease")
			}
			clock.Advance(started.Add(6 * time.Second).Sub(clock.Now()))
			for i := 0; i < 6; i++ {
				if i > 0 {
					clock.Advance(time.Second)
				}
				observed.observeRead(clock.Now(), 2<<20, true)
			}
			group.mu.Lock()
			preference, preferred := group.targetPreferences[plan.targetStateKey]
			ledger := group.ledger[plan.targetKey]
			group.mu.Unlock()
			require.Equal(t, uint64(1), group.VaneDiagnostics().Counters.HandoffImproved)
			require.True(t, preferred)
			require.Equal(t, beta.Name(), preference.to.name)
			require.Empty(t, ledger.verifyNode)
			// Past backlog and fast grace, two low windows still must not apply
			// the stale ten-minute landing penalty to a proven winner.
			clock.Advance(started.Add(100 * time.Second).Sub(clock.Now()))
			for i := 0; i < 12; i++ {
				if i > 0 {
					clock.Advance(time.Second)
				}
				observed.observeRead(clock.Now(), 32<<10, true)
			}
			group.mu.Lock()
			cooling := group.nodeCoolingLocked(beta.Name(), clock.Now())
			group.mu.Unlock()
			require.False(t, cooling, "successful settlement must prevent the stale verification penalty")
		})
	}
}

func TestVaneFlowGapBurstDoesNotConsumeLanding(t *testing.T) {
	group, clock, _, beta, metadata := newTargetGroupForTest(t)
	t.Cleanup(func() { require.NoError(t, group.Close()) })
	plan := prepareTargetHandoffForTest(t, group, metadata, beta)
	require.Empty(t, group.commitTargetHandoff(plan))
	decision := group.pickDecision(context.Background(), metadata, vaneTransportTCP, false, true)
	require.NotNil(t, decision.handoff)
	flow := newVaneFlow(group, decision.proxy.Name(), metadata, decision.handoff)
	flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
	observed := newVaneControlledConnWithNative(&vaneConnTestConn{}, clock, nil, nil, flow.observe, nil,
		func(vaneConnectionCloseObservation) { flow.releaseActiveFlowCount() }, nil, flow.markClosed).(*vaneObservedConn)
	observed.enableDirectPolicy()
	t.Cleanup(func() { require.NoError(t, observed.Close()) })
	observed.observeRead(clock.Now(), 2<<20, true)
	clock.Advance(time.Second)
	observed.observeRead(clock.Now(), 2<<20, true)
	clock.Advance(3 * time.Second)
	observed.observeRead(clock.Now(), 2<<20, true)
	flow.mu.Lock()
	last, pending := flow.lastSample, flow.handoff
	flow.mu.Unlock()
	require.Equal(t, time.Second, last.Duration)
	require.Equal(t, 4*time.Second, last.Age)
	require.Same(t, decision.handoff, pending, "one-second burst is not a verdict merely because the connection is four seconds old")
	group.mu.Lock()
	_, leased := group.targetHandoffs[plan.targetStateKey]
	group.mu.Unlock()
	require.True(t, leased)
	for i := 0; i < 5; i++ {
		clock.Advance(time.Second)
		observed.observeRead(clock.Now(), 2<<20, true)
	}
	require.Equal(t, uint64(1), group.VaneDiagnostics().Counters.HandoffImproved)
}

func TestVaneFlowShortLowWindowsDoNotPenalizeLanding(t *testing.T) {
	for _, payloadBytes := range []int64{32 << 10, 512 << 10} {
		t.Run(fmt.Sprint(payloadBytes), func(t *testing.T) {
			group, clock, _, beta, metadata := newTargetGroupForTest(t)
			t.Cleanup(func() { require.NoError(t, group.Close()) })
			chain01ProductionValues(t, group, 10_000_000)
			plan := prepareTargetHandoffForTest(t, group, metadata, beta)
			require.Empty(t, group.commitTargetHandoff(plan))
			decision := group.pickDecision(context.Background(), metadata, vaneTransportTCP, false, true)
			require.NotNil(t, decision.handoff)
			flow := newVaneFlow(group, decision.proxy.Name(), metadata, decision.handoff)
			flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
			observed := newVaneControlledConnWithNative(&vaneConnTestConn{}, clock, nil, nil, flow.observe, nil,
				func(vaneConnectionCloseObservation) { flow.releaseActiveFlowCount() }, nil, flow.markClosed).(*vaneObservedConn)
			observed.enableDirectPolicy()
			t.Cleanup(func() { require.NoError(t, observed.Close()) })
			for _, elapsed := range []time.Duration{0, 1900 * time.Millisecond, 3 * time.Second, 1900 * time.Millisecond, 3 * time.Second} {
				clock.Advance(elapsed)
				observed.observeRead(clock.Now(), payloadBytes, true)
			}
			flow.mu.Lock()
			last, lowWindows, pending := flow.lastSample, flow.lowWindows, flow.handoff
			flow.mu.Unlock()
			require.Equal(t, 1900*time.Millisecond, last.Duration)
			require.Equal(t, 9800*time.Millisecond, last.Age)
			require.GreaterOrEqual(t, lowWindows, vaneVerifyPenaltyLowWindows)
			require.Same(t, decision.handoff, pending)
			group.mu.Lock()
			cooling := group.nodeCoolingLocked(beta.Name(), clock.Now())
			group.mu.Unlock()
			require.False(t, cooling, "short low windows are not a sustained landing verdict even above minBytes")
			for i := 0; i < 5; i++ {
				clock.Advance(time.Second)
				observed.observeRead(clock.Now(), 2<<20, true)
			}
			require.Equal(t, uint64(1), group.VaneDiagnostics().Counters.HandoffImproved)
			group.mu.Lock()
			cooling = group.nodeCoolingLocked(beta.Name(), clock.Now())
			group.mu.Unlock()
			require.False(t, cooling, "the later valid fast verdict must not inherit a false ten-minute penalty")
		})
	}
}

func TestVaneFlowLandingSmallSilenceDoesNotPenalizeEarly(t *testing.T) {
	group, clock, _, beta, metadata := newTargetGroupForTest(t)
	t.Cleanup(func() { require.NoError(t, group.Close()) })
	chain01ProductionValues(t, group, 1_000_000)
	plan := prepareTargetHandoffForTest(t, group, metadata, beta)
	require.Empty(t, group.commitTargetHandoff(plan))
	decision := group.pickDecision(context.Background(), metadata, vaneTransportTCP, false, true)
	require.NotNil(t, decision.handoff)
	flow := newVaneFlow(group, decision.proxy.Name(), metadata, decision.handoff)
	flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
	observed := newVaneControlledConnWithNative(&vaneConnTestConn{}, clock, nil, nil, flow.observe, nil,
		func(vaneConnectionCloseObservation) { flow.releaseActiveFlowCount() }, nil, flow.markClosed).(*vaneObservedConn)
	observed.enableDirectPolicy()
	flow.setLastReadFunc(observed.lastReadTime)
	t.Cleanup(func() { require.NoError(t, observed.Close()) })
	clock.Advance(time.Second)
	observed.observeRead(clock.Now(), 64, true)
	lastRead := clock.Now()
	for _, silence := range []time.Duration{13 * time.Second, 30 * time.Second, 44 * time.Second, 45 * time.Second} {
		clock.Advance(lastRead.Add(silence).Sub(clock.Now()))
		flow.observeSyntheticStall(clock.Now())
		group.mu.Lock()
		cooling := group.nodeCoolingLocked(beta.Name(), clock.Now())
		group.mu.Unlock()
		require.Equal(t, silence >= vaneLowVolumeAge, cooling, "the 45-second small-flow gate must apply before a global landing penalty")
	}
}

func TestVaneFlowShortTargetVerdictRetainsLease(t *testing.T) {
	group, _, _, beta, metadata := newTargetGroupForTest(t)
	t.Cleanup(func() { require.NoError(t, group.Close()) })
	plan := prepareTargetHandoffForTest(t, group, metadata, beta)
	require.Empty(t, group.commitTargetHandoff(plan))
	decision := group.pickDecision(context.Background(), metadata, vaneTransportTCP, false, true)
	require.NotNil(t, decision.handoff)
	group.settleTargetHandoff(decision.handoff, decision.handoff.toLease, vaneThroughputObservation{
		BitsPerSecond: 50_000_000, Duration: time.Second, Age: 4 * time.Second,
	})
	group.mu.Lock()
	_, pending := group.targetHandoffs[plan.targetStateKey]
	group.mu.Unlock()
	require.True(t, pending, "short verdict must not consume the target lease")
	group.settleTargetHandoff(decision.handoff, decision.handoff.toLease, vaneThroughputObservation{
		BitsPerSecond: 40_000_000, Age: 5 * time.Second,
	})
	require.Equal(t, uint64(1), group.VaneDiagnostics().Counters.HandoffImproved)
}
