package outboundgroup

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func enableVaneExplorationForTest(group *Vane, interval int) {
	group.exploration = vaneExplorationConfig{enabled: true, interval: uint64(interval)}
	group.explorationSince = group.clock.Now().UTC()
}

func vaneExplorationMetadata(host string, network C.NetWork) *C.Metadata {
	return &C.Metadata{Host: host, DstPort: 443, NetWork: network}
}

func TestVaneExplorationCadenceFairnessAndAnchorIsolation(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	gamma := newVaneTestProxy("gamma", true, true)
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, gamma, beta, alpha)
	enableVaneExplorationForTest(group, 3)
	metadata := vaneExplorationMetadata("example.com", C.TCP)

	// The first committed selection establishes the anchor and is not an
	// exploration opportunity.
	require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
	anchorKey := vaneAnchorKey{transport: vaneTransportTCP, scene: vaneSceneDefault}
	require.Equal(t, "alpha", group.anchors[anchorKey].name)

	want := []string{"alpha", "alpha", "beta", "alpha", "alpha", "gamma"}
	for _, expected := range want {
		require.Equal(t, expected, group.pick(metadata, vaneTransportTCP, false, true).Name())
		require.Equal(t, "alpha", group.anchors[anchorKey].name, "exploration must never replace the baseline anchor")
	}

	scope := group.explorationScopes[vaneExplorationScopeIndex(vaneTransportTCP, vaneSceneDefault)]
	require.Equal(t, uint64(6), scope.eligibleSelections)
	require.Equal(t, uint64(2), scope.explorationSelections)
	require.Zero(t, scope.sinceLastExploration)

	snapshot := group.VaneDiagnostics()
	require.True(t, snapshot.Config.ExplorationEnabled)
	require.Equal(t, 3, snapshot.Config.ExplorationInterval)
	require.Equal(t, vaneExplorationScopeCount, len(snapshot.Runtime.ExplorationScopes))
	tcpDefault := snapshot.Runtime.ExplorationScopes[vaneExplorationScopeIndex(vaneTransportTCP, vaneSceneDefault)]
	require.Equal(t, uint64(6), tcpDefault.EligibleSelections)
	require.Equal(t, uint64(2), tcpDefault.ExplorationSelections)
	require.Equal(t, uint64(3), tcpDefault.NextIn)
}

func TestVaneExplorationDisabledIsBaselineEquivalent(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, beta, alpha)
	metadata := vaneExplorationMetadata("example.com", C.TCP)

	for i := 0; i < 64; i++ {
		require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
	}
	require.Empty(t, group.explorationScopes)
	require.Zero(t, group.VaneDiagnostics().Counters.ExplorationSelections)
}

func TestVaneExplorationEligibilityDoesNotAccumulateDebt(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
	enableVaneExplorationForTest(group, 2)
	metadata := vaneExplorationMetadata("example.com", C.TCP)

	require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
	beta.alive = false
	for i := 0; i < 5; i++ {
		require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
	}

	beta.alive = true
	require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
	require.Equal(t, "beta", group.pick(metadata, vaneTransportTCP, false, true).Name())

	scope := group.explorationScopes[vaneExplorationScopeIndex(vaneTransportTCP, vaneSceneDefault)]
	require.Equal(t, uint64(2), scope.eligibleSelections)
	require.Equal(t, uint64(1), scope.explorationSelections)
}

func TestVaneExplorationSkipsControlTrafficAndReadOnlySelectors(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
	enableVaneExplorationForTest(group, 2)
	metadata := vaneExplorationMetadata("example.com", C.TCP)

	require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
	for i := 0; i < 4; i++ {
		require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, false).Name())
		_ = group.Now()
		_ = group.Unwrap(metadata, false)
		_ = group.IsL3Protocol(metadata)
		_ = group.VaneDiagnostics()
	}
	inner := vaneExplorationMetadata("dns.example", C.TCP)
	inner.Type = C.INNER
	for i := 0; i < 4; i++ {
		require.Equal(t, "alpha", group.pick(inner, vaneTransportTCP, false, true).Name())
	}

	require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
	require.Equal(t, "beta", group.pick(metadata, vaneTransportTCP, false, true).Name())
}

func TestVaneExplorationTransportAndSceneScopesAreIndependent(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
	group.rules = []vaneSceneRule{{kind: vaneRuleDomainSuffix, value: "video.example", scene: vaneSceneMedia}}
	enableVaneExplorationForTest(group, 2)

	defaultTCP := vaneExplorationMetadata("api.example", C.TCP)
	mediaTCP := vaneExplorationMetadata("cdn.video.example", C.TCP)
	defaultUDP := vaneExplorationMetadata("api.example", C.UDP)

	// Establish one anchor per closed scope.
	require.Equal(t, "alpha", group.pick(defaultTCP, vaneTransportTCP, false, true).Name())
	require.Equal(t, "alpha", group.pick(mediaTCP, vaneTransportTCP, false, true).Name())
	require.Equal(t, "alpha", group.pick(defaultUDP, vaneTransportUDP, false, true).Name())

	for _, tc := range []struct {
		metadata  *C.Metadata
		transport vaneTransport
	}{
		{defaultTCP, vaneTransportTCP},
		{mediaTCP, vaneTransportTCP},
		{defaultUDP, vaneTransportUDP},
	} {
		require.Equal(t, "alpha", group.pick(tc.metadata, tc.transport, false, true).Name())
		require.Equal(t, "beta", group.pick(tc.metadata, tc.transport, false, true).Name())
	}
}

func TestVaneExplorationMediaHandoffAlwaysWinsWithoutAdvancingCadence(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	enableVaneExplorationForTest(group, 2)
	metadata := vaneExplorationMetadata("rr1.googlevideo.com", C.TCP)

	require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
	key := group.mediaTargetKey(metadata.Host, metadata.DstPort)
	group.mediaHints[key] = vaneMediaHint{candidate: "beta", expiresAt: clock.Now().Add(time.Minute)}
	require.Equal(t, "beta", group.pick(metadata, vaneTransportTCP, false, true).Name())

	scopeIndex := vaneExplorationScopeIndex(vaneTransportTCP, vaneSceneMedia)
	require.Zero(t, group.explorationScopes[scopeIndex].eligibleSelections)
	delete(group.mediaHints, key)
	require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
	require.Equal(t, "beta", group.pick(metadata, vaneTransportTCP, false, true).Name())
}

func TestVaneExplorationOutcomesAreAttributedExactlyOnce(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	alpha.dialConn = &vaneConnTestConn{}
	beta.dialConn = &vaneConnTestConn{}
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
	enableVaneExplorationForTest(group, 2)
	metadata := vaneExplorationMetadata("example.com", C.TCP)

	conn, err := group.DialContext(context.Background(), metadata)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	conn, err = group.DialContext(context.Background(), metadata)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	conn, err = group.DialContext(context.Background(), metadata)
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	snapshot := group.VaneDiagnostics()
	require.Equal(t, uint64(1), snapshot.Counters.ExplorationSelections)
	require.Equal(t, uint64(1), snapshot.Counters.ExplorationSucceeded)
	require.Zero(t, snapshot.Counters.ExplorationFailed)
	require.Zero(t, snapshot.Counters.ExplorationNeutral)

	var selectedID uint64
	for _, event := range snapshot.RecentEvents {
		switch event.Kind {
		case "exploration-selected":
			selectedID = event.ExplorationID
			require.Equal(t, "alpha", event.From)
			require.Equal(t, "beta", event.To)
		case "exploration-succeeded":
			require.Equal(t, selectedID, event.ExplorationID)
		}
	}
	require.NotZero(t, selectedID)
}

func TestVaneExplorationFailureAndNeutralOutcomeContracts(t *testing.T) {
	for _, tc := range []struct {
		name        string
		err         error
		wantFailed  uint64
		wantNeutral uint64
		wantCooling bool
	}{
		{name: "failure", err: errors.New("dial failed"), wantFailed: 1, wantCooling: true},
		{name: "neutral cancellation", err: context.Canceled, wantNeutral: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := newVaneConnTestClock()
			alpha := newVaneTestProxy("alpha", true, true)
			beta := newVaneTestProxy("beta", true, true)
			alpha.dialConn = &vaneConnTestConn{}
			beta.dialErr = tc.err
			group, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
			enableVaneExplorationForTest(group, 2)
			metadata := vaneExplorationMetadata("example.com", C.TCP)

			conn, err := group.DialContext(context.Background(), metadata)
			require.NoError(t, err)
			require.NoError(t, conn.Close())
			conn, err = group.DialContext(context.Background(), metadata)
			require.NoError(t, err)
			require.NoError(t, conn.Close())
			_, err = group.DialContext(context.Background(), metadata)
			require.ErrorIs(t, err, tc.err)

			snapshot := group.VaneDiagnostics()
			require.Equal(t, uint64(1), snapshot.Counters.ExplorationSelections)
			require.Equal(t, tc.wantFailed, snapshot.Counters.ExplorationFailed)
			require.Equal(t, tc.wantNeutral, snapshot.Counters.ExplorationNeutral)
			key := vaneCooldownKey{transport: vaneTransportTCP, target: "example.com", port: 443, candidate: "beta", identity: beta.identity}
			_, cooling := group.cooldowns[key]
			require.Equal(t, tc.wantCooling, cooling)
		})
	}
}

func TestVaneExplorationDeferredTCPAndUDPSettleOnPositiveTraffic(t *testing.T) {
	t.Run("deferred TCP waits for first positive write", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		alpha.dialConn = &vaneConnTestConn{}
		beta.dialConn = &vaneEarlyTestConn{vaneConnTestConn: &vaneConnTestConn{}}
		group, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
		enableVaneExplorationForTest(group, 2)
		metadata := vaneExplorationMetadata("example.com", C.TCP)

		for i := 0; i < 2; i++ {
			conn, err := group.DialContext(context.Background(), metadata)
			require.NoError(t, err)
			require.NoError(t, conn.Close())
		}
		conn, err := group.DialContext(context.Background(), metadata)
		require.NoError(t, err)
		require.Equal(t, uint64(1), group.VaneDiagnostics().Counters.ExplorationSelections)
		require.Zero(t, group.VaneDiagnostics().Counters.ExplorationSucceeded)
		_, err = conn.Write([]byte("request"))
		require.NoError(t, err)
		_, err = conn.Write([]byte("again"))
		require.NoError(t, err)
		require.Equal(t, uint64(1), group.VaneDiagnostics().Counters.ExplorationSucceeded)
		require.NoError(t, conn.Close())
	})

	t.Run("UDP waits for first positive datagram", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		alpha.packetConn = &vanePacketConnTestFake{}
		beta.packetConn = &vanePacketConnTestFake{}
		group, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
		enableVaneExplorationForTest(group, 2)
		metadata := vaneExplorationMetadata("example.com", C.UDP)

		for i := 0; i < 3; i++ {
			packetConn, err := group.ListenPacketContext(context.Background(), metadata)
			require.NoError(t, err)
			if i == 2 {
				require.Equal(t, uint64(1), group.VaneDiagnostics().Counters.ExplorationSelections)
				require.Zero(t, group.VaneDiagnostics().Counters.ExplorationSucceeded)
			}
			_, err = packetConn.WriteTo([]byte("datagram"), vaneConnTestAddr("remote"))
			require.NoError(t, err)
			require.NoError(t, packetConn.Close())
		}
		require.Equal(t, uint64(1), group.VaneDiagnostics().Counters.ExplorationSucceeded)
	})
}

func TestVaneExplorationCloseBeforePositiveTrafficSettlesNeutral(t *testing.T) {
	t.Run("deferred TCP close", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		alpha.dialConn = &vaneConnTestConn{}
		beta.dialConn = &vaneEarlyTestConn{vaneConnTestConn: &vaneConnTestConn{}}
		group, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
		enableVaneExplorationForTest(group, 2)
		metadata := vaneExplorationMetadata("example.com", C.TCP)

		for i := 0; i < 3; i++ {
			conn, err := group.DialContext(context.Background(), metadata)
			require.NoError(t, err)
			require.NoError(t, conn.Close())
		}
		snapshot := group.VaneDiagnostics()
		require.Equal(t, uint64(1), snapshot.Counters.ExplorationSelections)
		require.Equal(t, uint64(1), snapshot.Counters.ExplorationNeutral)
		require.Equal(t, snapshot.Counters.ExplorationSelections,
			snapshot.Counters.ExplorationSucceeded+snapshot.Counters.ExplorationFailed+snapshot.Counters.ExplorationNeutral)
	})

	t.Run("UDP close", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		alpha.packetConn = &vanePacketConnTestFake{}
		beta.packetConn = &vanePacketConnTestFake{}
		group, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
		enableVaneExplorationForTest(group, 2)
		metadata := vaneExplorationMetadata("example.com", C.UDP)

		for i := 0; i < 3; i++ {
			packetConn, err := group.ListenPacketContext(context.Background(), metadata)
			require.NoError(t, err)
			require.NoError(t, packetConn.Close())
		}
		snapshot := group.VaneDiagnostics()
		require.Equal(t, uint64(1), snapshot.Counters.ExplorationSelections)
		require.Equal(t, uint64(1), snapshot.Counters.ExplorationNeutral)
		require.Equal(t, snapshot.Counters.ExplorationSelections,
			snapshot.Counters.ExplorationSucceeded+snapshot.Counters.ExplorationFailed+snapshot.Counters.ExplorationNeutral)
	})
}

func TestVaneEvidenceCoverageMatchesTransportObservability(t *testing.T) {
	throughputOnly := vaneMetricsSnapshot{
		throughput: vaneMetricEstimate{valid: true, confidence: 1},
	}
	require.Zero(t, vaneEvidenceCoverageMicros(throughputOnly, vaneTransportUDP, vaneSceneMedia), "UDP cannot observe throughput")
	require.Equal(t, int64(350_000), vaneEvidenceCoverageMicros(throughputOnly, vaneTransportTCP, vaneSceneMedia))

	udpObservable := vaneMetricsSnapshot{
		failure: vaneMetricEstimate{valid: true, confidence: 1},
		connect: vaneMetricEstimate{valid: true, confidence: 1},
	}
	require.Equal(t, int64(857_143), vaneEvidenceCoverageMicros(udpObservable, vaneTransportUDP, vaneSceneBulk))
	udpObservable.jitter = vaneMetricEstimate{valid: true, confidence: 1}
	require.Equal(t, int64(1_000_000), vaneEvidenceCoverageMicros(udpObservable, vaneTransportUDP, vaneSceneBulk))
}

func TestVaneExplorationRespectsHealthProtocolAndCooldownBoundaries(t *testing.T) {
	t.Run("exact candidate cooldown leaves another challenger eligible", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		gamma := newVaneTestProxy("gamma", true, true)
		group, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta, gamma)
		enableVaneExplorationForTest(group, 2)
		metadata := vaneExplorationMetadata("example.com", C.TCP)
		require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
		group.cooldowns[vaneCooldownKey{transport: vaneTransportTCP, target: "example.com", port: 443, candidate: "beta"}] = clock.Now().Add(time.Minute)
		require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
		require.Equal(t, "gamma", group.pick(metadata, vaneTransportTCP, false, true).Name())
	})

	t.Run("all unhealthy fallback is never labeled exploration", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		group, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
		enableVaneExplorationForTest(group, 2)
		metadata := vaneExplorationMetadata("example.com", C.TCP)
		require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
		alpha.alive, beta.alive = false, false
		for i := 0; i < 8; i++ {
			require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
		}
		scope := group.explorationScopes[vaneExplorationScopeIndex(vaneTransportTCP, vaneSceneDefault)]
		require.Zero(t, scope.eligibleSelections)
		require.Zero(t, group.VaneDiagnostics().Counters.ExplorationSelections)
	})

	t.Run("UDP incompatible candidate is never explored", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, false)
		gamma := newVaneTestProxy("gamma", true, true)
		group, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta, gamma)
		enableVaneExplorationForTest(group, 2)
		metadata := vaneExplorationMetadata("example.com", C.UDP)
		require.Equal(t, "alpha", group.pick(metadata, vaneTransportUDP, false, true).Name())
		require.Equal(t, "alpha", group.pick(metadata, vaneTransportUDP, false, true).Name())
		require.Equal(t, "gamma", group.pick(metadata, vaneTransportUDP, false, true).Name())
	})

	t.Run("anchor cooling on another target suppresses exploration", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		group, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
		enableVaneExplorationForTest(group, 2)
		metadata := vaneExplorationMetadata("example.com", C.TCP)
		require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
		group.cooldowns[vaneCooldownKey{transport: vaneTransportTCP, target: "other.example", port: 443, candidate: "alpha"}] = clock.Now().Add(time.Minute)
		for i := 0; i < 8; i++ {
			require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
		}
		scope := group.explorationScopes[vaneExplorationScopeIndex(vaneTransportTCP, vaneSceneDefault)]
		require.Zero(t, scope.eligibleSelections)
	})
}

func TestVaneReadOnlySelectorsDoNotPruneExpiredCooldowns(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	metadata := vaneExplorationMetadata("rr1.googlevideo.com", C.TCP)
	require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())

	dialKey := vaneCooldownKey{transport: vaneTransportTCP, target: "rr1.googlevideo.com", port: 443, candidate: "beta"}
	mediaKey := vaneMediaCandidateKey{vaneMediaTargetKey: group.mediaTargetKey(metadata.Host, metadata.DstPort), candidate: "beta"}
	group.cooldowns[dialKey] = clock.Now().Add(-time.Second)
	group.mediaSlowCooldowns[mediaKey] = clock.Now().Add(-time.Second)

	require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, false).Name())
	require.Contains(t, group.cooldowns, dialKey)
	require.Contains(t, group.mediaSlowCooldowns, mediaKey)

	// A committed selection may perform the normal lazy cleanup.
	require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())
	require.NotContains(t, group.cooldowns, dialKey)
	require.NotContains(t, group.mediaSlowCooldowns, mediaKey)
}

func TestVaneExplorationConcurrentQuotaIsExact(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	gamma := newVaneTestProxy("gamma", true, true)
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta, gamma)
	enableVaneExplorationForTest(group, 8)
	metadata := vaneExplorationMetadata("example.com", C.TCP)
	require.Equal(t, "alpha", group.pick(metadata, vaneTransportTCP, false, true).Name())

	const calls = 800
	var wg sync.WaitGroup
	var mu sync.Mutex
	selected := make(map[string]int)
	wg.Add(calls)
	for i := 0; i < calls; i++ {
		go func() {
			defer wg.Done()
			name := group.pick(metadata, vaneTransportTCP, false, true).Name()
			mu.Lock()
			selected[name]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	require.Equal(t, 100, selected["beta"]+selected["gamma"])
	require.Equal(t, 700, selected["alpha"])
	require.LessOrEqual(t, selected["beta"]-selected["gamma"], 1)
	require.LessOrEqual(t, selected["gamma"]-selected["beta"], 1)
}
