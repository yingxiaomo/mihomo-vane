package outboundgroup

import (
	"context"
	"net/url"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// CHAIN-08: a plan admitted on fresh throughput must not be committed after
// that evidence expired (or after the node control state disappeared).
func TestVaneCommitRejectsExpiredEvidenceForKnownGoodPlan(t *testing.T) {
	group, _, _, beta, metadata := newTargetGroupForTest(t)
	plan := prepareTargetHandoffForTest(t, group, metadata, beta)
	plan.knownGood = true

	now := group.clock.Now()
	group.mu.Lock()
	group.nodeControls["beta"] = &vaneNodeControlState{
		recentTCPThroughput: vaneRecentThroughput{
			bitsPerSecond: 6_000_000,
			observedAt:    now.Add(-vaneMediaEvidenceMaxAge - time.Second),
		},
	}
	group.mu.Unlock()

	require.Equal(t, "challenger-no-evidence", group.commitMediaReconnectDetailed(plan))
	group.mu.Lock()
	require.Empty(t, group.mediaBudgets, "a rejected commit must not consume budget")
	require.Empty(t, group.mediaHints)
	group.mu.Unlock()

	group.mu.Lock()
	delete(group.nodeControls, "beta")
	group.mu.Unlock()
	require.Equal(t, "challenger-no-evidence", group.commitMediaReconnectDetailed(plan),
		"missing control state is also missing evidence")
}

// CHAIN-04: commit must re-check the demand line that admitted the plan.
func TestVaneCommitRejectsDemandRegressionForKnownGoodPlan(t *testing.T) {
	group, _, _, beta, metadata := newTargetGroupForTest(t)
	group.media.demandBPS = 8_000_000
	plan := prepareTargetHandoffForTest(t, group, metadata, beta)
	plan.knownGood = true

	now := group.clock.Now()
	group.mu.Lock()
	group.nodeControls["beta"] = &vaneNodeControlState{
		recentTCPThroughput: vaneRecentThroughput{
			bitsPerSecond: 6_000_000,
			observedAt:    now,
		},
	}
	group.mu.Unlock()

	require.Equal(t, "challenger-evidence-degraded", group.commitMediaReconnectDetailed(plan))
	group.mu.Lock()
	require.Empty(t, group.mediaBudgets)
	require.Empty(t, group.mediaHints)
	group.mu.Unlock()
}

// RACE-01: commitTargetHandoff must reject a challenger whose target-scoped
// evidence has gone below the original required throughput.
func TestVaneTargetCommitRejectsFreshTargetEvidenceBelowRequired(t *testing.T) {
	group, _, _, beta, metadata := newTargetGroupForTest(t)
	plan := prepareTargetHandoffForTest(t, group, metadata, beta)

	now := group.clock.Now()
	group.mu.Lock()
	group.learning.mu.Lock()
	betaState := group.ensureProxyNodeLocked(beta, now)
	require.NotNil(t, betaState)
	plan.challengerEpoch = betaState.epoch
	group.targetEvidence[vaneTargetEvidenceKey{
		target: plan.targetStateKey,
		member: vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: betaState.epoch},
	}] = vaneTargetEvidence{bitsPerSecond: 1_000_000, observedAt: now}
	group.learning.mu.Unlock()
	group.mu.Unlock()

	require.Equal(t, "challenger-evidence-degraded", group.commitTargetHandoff(plan))
	group.mu.Lock()
	require.Empty(t, group.mediaBudgets, "a rejected target commit must not consume budget")
	require.Empty(t, group.targetHandoffs)
	group.mu.Unlock()
}

// RACE-07: a missing diagnostics token must not disable handoff commits. The
// lease is still required for the reconnect and for settlement.
func TestVaneTargetCommitSynthesizesTokenWhenDiagnosticsUnavailable(t *testing.T) {
	group, _, _, beta, metadata := newTargetGroupForTest(t)
	plan := prepareTargetHandoffForTest(t, group, metadata, beta)
	group.diagnostics = nil

	require.Empty(t, group.commitTargetHandoff(plan))

	targetKey, ok := group.targetKeyForMedia(metadata.Host, metadata.DstPort)
	require.True(t, ok)
	group.mu.Lock()
	lease, ok := group.targetHandoffs[targetKey]
	require.True(t, ok)
	require.NotNil(t, lease.token)
	require.Equal(t, plan.raceID, lease.token.id)
	require.Equal(t, plan.target, lease.token.target)
	require.Equal(t, plan.targetKey.target, lease.token.bucket)
	require.Equal(t, plan.port, lease.token.port)
	require.Equal(t, plan.current, lease.token.from)
	require.Equal(t, plan.challenger, lease.token.to)
	require.Equal(t, plan.currentBPS, lease.token.previousBPS)
	require.Equal(t, 1, group.mediaBudgets[plan.targetKey].count)
	_, slow := group.mediaSlowCooldowns[vaneMediaCandidateKey{
		vaneMediaTargetKey: plan.targetKey,
		candidate:          plan.current,
		identity:           plan.identity,
	}]
	require.True(t, slow)
	group.mu.Unlock()
}

// RACE-06: a race result may only act on the low-window round that scheduled
// it. A recovered-then-slow-again flow must not be closed by the old result.
func TestVaneOldRaceResultCannotCloseNewRound(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	configureVaneRacingForTest(t, group, vaneRacingOn)

	probeEntered := make(chan struct{})
	releaseProbe := make(chan struct{})
	var probeOnce sync.Once
	group.racing.probe = func(ctx context.Context, _ C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
		probeOnce.Do(func() { close(probeEntered) })
		select {
		case <-releaseProbe:
		case <-ctx.Done():
			return vaneProbeResult{reason: "canceled"}
		}
		return vaneProbeResult{
			valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap,
			duration: time.Second, lowerBoundBPS: 100_000_000, capHit: true,
		}
	}

	metadata := &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	decision := group.pickDecision(metadata, vaneTransportTCP, false, true)
	flow := newVaneMediaFlow(group, decision.proxy.Name(), metadata)
	require.NotNil(t, flow)
	flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
	actions := make(chan vanePolicyAction, 1)
	flow.setPolicySubmitter(func(action vanePolicyAction, _ bool) { actions <- action })

	low := vaneThroughputObservation{
		BitsPerSecond: 1_000_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second, Delivered: true,
	}
	for i := 0; i < 3; i++ {
		require.Nil(t, flow.observe(low))
	}
	select {
	case <-probeEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("race did not reach the probe")
	}

	// Recover, then slow again while the first round is still blocked in the
	// probe. The second round cannot start (group-level in-flight slot), and
	// the first round's callback must be recognized as stale.
	require.Nil(t, flow.observe(vaneThroughputObservation{
		BitsPerSecond: 10_000_000, TotalBytes: 8 * 1024 * 1024, Age: 21 * time.Second, Delivered: true,
	}))
	for i := 0; i < 3; i++ {
		require.Nil(t, flow.observe(low))
	}
	starts := 0
	for _, event := range group.VaneDiagnostics().RecentEvents {
		if event.Kind == "race-started" {
			starts++
		}
	}
	require.Equal(t, 1, starts, "the second round must be rejected by the in-flight slot")

	close(releaseProbe)
	require.Eventually(t, func() bool {
		for _, event := range group.VaneDiagnostics().RecentEvents {
			if event.Kind == "race-stale" {
				return true
			}
		}
		return false
	}, 2*time.Second, time.Millisecond)
	select {
	case <-actions:
		t.Fatal("a stale race must not submit a policy action")
	default:
	}
	group.mu.Lock()
	require.Empty(t, group.targetHandoffs)
	require.Empty(t, group.mediaHints)
	group.mu.Unlock()
}

// CHAIN-07: natural-close ownership invalidates an in-flight race before its
// callback can record a would-commit. The baseline action is intentionally not
// executed, so the flow stays open until Close wins.
func TestVaneNaturalCloseInvalidatesInFlightRace(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	configureVaneRacingForTest(t, group, vaneRacingShadow)

	probeEntered := make(chan struct{})
	releaseProbe := make(chan struct{})
	var probeOnce sync.Once
	group.racing.probe = func(ctx context.Context, _ C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
		probeOnce.Do(func() { close(probeEntered) })
		select {
		case <-releaseProbe:
		case <-ctx.Done():
			return vaneProbeResult{reason: "canceled"}
		}
		return vaneProbeResult{
			valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap,
			duration: time.Second, lowerBoundBPS: 100_000_000, capHit: true,
		}
	}

	metadata := &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	decision := group.pickDecision(metadata, vaneTransportTCP, false, true)
	flow := newVaneMediaFlow(group, decision.proxy.Name(), metadata)
	require.NotNil(t, flow)
	flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
	conn := newVaneControlledConnWithNative(&vaneConnTestConn{}, clock,
		nil, nil, nil, nil, nil, nil,
		func() { flow.markClosed() })

	low := vaneThroughputObservation{
		BitsPerSecond: 1_000_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second, Delivered: true,
	}
	for i := 0; i < 3; i++ {
		_ = flow.observe(low) // shadow's baseline action is deliberately left unexecuted
	}
	select {
	case <-probeEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("race did not reach the probe")
	}
	require.NoError(t, conn.Close())
	close(releaseProbe)
	require.Eventually(t, func() bool {
		group.racingRuntime.mu.Lock()
		defer group.racingRuntime.mu.Unlock()
		return !group.racingRuntime.inFlight
	}, 2*time.Second, time.Millisecond)

	for _, event := range group.VaneDiagnostics().RecentEvents {
		require.NotEqual(t, "handoff-would-commit", event.Kind,
			"a naturally closed flow must not record a would-commit")
	}
	group.mu.Lock()
	require.Empty(t, group.targetHandoffs)
	require.Empty(t, group.mediaHints)
	require.Empty(t, group.mediaBudgets)
	require.Empty(t, group.targetPreferences)
	group.mu.Unlock()
}

// The final commit gate also refuses a plan whose flow has already closed.
func TestVaneClosedFlowCannotCommitPlannedHandoff(t *testing.T) {
	group, _, _, beta, metadata := newTargetGroupForTest(t)
	plan := prepareTargetHandoffForTest(t, group, metadata, beta)
	flow := newVaneMediaFlow(group, plan.current, metadata)
	require.NotNil(t, flow)
	flow.markClosed()

	action := flow.policyActionForPlan(plan, vaneThroughputObservation{
		BitsPerSecond: 1_000_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second,
	}, 3, true)
	require.False(t, action())
	group.mu.Lock()
	require.Empty(t, group.targetHandoffs)
	require.Empty(t, group.mediaBudgets)
	group.mu.Unlock()
}

// A race that never calls back must still release the flow's round token;
// otherwise that flow could never race again.
func TestVaneRaceTokenReleasedWhenEngineHasNoWinner(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	configureVaneRacingForTest(t, group, vaneRacingOn)

	probeEntered := make(chan struct{})
	releaseProbe := make(chan struct{})
	var probeOnce sync.Once
	group.racing.probe = func(ctx context.Context, _ C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
		probeOnce.Do(func() { close(probeEntered) })
		select {
		case <-releaseProbe:
		case <-ctx.Done():
			return vaneProbeResult{reason: "canceled"}
		}
		return vaneProbeResult{reason: "zero-bytes"}
	}

	metadata := &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	decision := group.pickDecision(metadata, vaneTransportTCP, false, true)
	flow := newVaneMediaFlow(group, decision.proxy.Name(), metadata)
	require.NotNil(t, flow)
	flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
	flow.scheduleRace(vaneThroughputObservation{
		BitsPerSecond: 1_000_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second,
	}, 3)
	select {
	case <-probeEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("race did not reach the probe")
	}
	flow.mu.Lock()
	require.NotZero(t, flow.raceToken, "the round token must be held while the race runs")
	flow.mu.Unlock()

	close(releaseProbe)
	require.Eventually(t, func() bool {
		flow.mu.Lock()
		defer flow.mu.Unlock()
		return flow.raceToken == 0
	}, 2*time.Second, time.Millisecond, "the done callback must release a race that never called back")
}
