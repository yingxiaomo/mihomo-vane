package outboundgroup

import (
	"context"
	"net/url"
	"sync"
	"sync/atomic"
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
	// COLD-PICK: the probes below belong to the race under test.
	suppressColdPickProbeForTest(t, group, metadata)
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
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
	require.Eventually(t, func() bool {
		flow.mu.Lock()
		defer flow.mu.Unlock()
		return flow.raceToken == 0
	}, 2*time.Second, time.Millisecond, "a stale round must release its token")
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

// RACE-06 control: after the first round finishes cleanly (no winner, no
// callback), its token is released and a later round can schedule and commit.
func TestVaneRaceRoundRecoversAfterCleanFinish(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	configureVaneRacingForTest(t, group, vaneRacingOn)

	var probeCalls atomic.Int32
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		if probeCalls.Add(1) == 1 {
			return vaneProbeResult{reason: "zero-bytes"}
		}
		return vaneProbeResult{
			valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap,
			duration: time.Second, lowerBoundBPS: 100_000_000, capHit: true,
		}
	}

	metadata := &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	// COLD-PICK: the probes below belong to the race under test.
	suppressColdPickProbeForTest(t, group, metadata)
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
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
	require.Eventually(t, func() bool {
		flow.mu.Lock()
		defer flow.mu.Unlock()
		return flow.raceToken == 0
	}, 2*time.Second, time.Millisecond, "the clean first round must release its token")
	group.racingRuntime.mu.Lock()
	inFlight := group.racingRuntime.inFlight
	group.racingRuntime.mu.Unlock()
	require.False(t, inFlight)

	// The no-winner suppression is per target; expire it before the next round.
	clock.Advance(31 * time.Second)
	require.Nil(t, flow.observe(low))
	var action vanePolicyAction
	select {
	case action = <-actions:
	case <-time.After(2 * time.Second):
		t.Fatal("the second round did not submit a handoff action")
	}
	require.NotNil(t, action)
	require.True(t, action())
	group.mu.Lock()
	require.NotEmpty(t, group.targetHandoffs)
	group.mu.Unlock()
	require.Eventually(t, func() bool {
		flow.mu.Lock()
		defer flow.mu.Unlock()
		return flow.raceToken == 0
	}, 2*time.Second, time.Millisecond, "the committed round must release its token")
}

// RACE-01: the target evidence re-check must fire on the real race callback
// path and on the on+knownGood path, not only when commitTargetHandoff is
// called directly.
func TestVaneRace01RejectsTargetEvidenceOnBothPaths(t *testing.T) {
	t.Run("race callback", func(t *testing.T) {
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
		// COLD-PICK: the probes below belong to the race under test.
		suppressColdPickProbeForTest(t, group, metadata)
		decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
		flow := newVaneMediaFlow(group, decision.proxy.Name(), metadata)
		require.NotNil(t, flow)
		flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch

		now := clock.Now()
		group.mu.Lock()
		group.learning.mu.Lock()
		betaState := group.ensureProxyNodeLocked(beta, now)
		require.NotNil(t, betaState)
		group.learning.mu.Unlock()
		group.mu.Unlock()

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

		group.mu.Lock()
		group.targetEvidence[vaneTargetEvidenceKey{
			target: flow.targetStateKey,
			member: vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: betaState.epoch},
		}] = vaneTargetEvidence{bitsPerSecond: 1_000_000, observedAt: clock.Now()}
		group.mu.Unlock()
		close(releaseProbe)

		var action vanePolicyAction
		select {
		case action = <-actions:
		case <-time.After(2 * time.Second):
			t.Fatal("race callback did not submit an action")
		}
		require.False(t, action())
		group.mu.Lock()
		require.Empty(t, group.targetHandoffs)
		require.Empty(t, group.mediaBudgets)
		group.mu.Unlock()
	})

	t.Run("on knownGood", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		beta.delay = 10
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		configureVaneRacingForTest(t, group, vaneRacingOn)
		group.media.lowThroughputBPS = 5_000_000
		group.media.demandBPS = 2_000_000
		group.media.maxLowWindows = 3

		metadata := &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP}
		// COLD-PICK: the probes below belong to the race under test.
		suppressColdPickProbeForTest(t, group, metadata)
		decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
		flow := newVaneMediaFlow(group, decision.proxy.Name(), metadata)
		require.NotNil(t, flow)
		flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch

		now := clock.Now()
		group.mu.Lock()
		group.learning.mu.Lock()
		betaState := group.ensureProxyNodeLocked(beta, now)
		require.NotNil(t, betaState)
		group.nodeControls[beta.Name()].recentTCPThroughput = vaneRecentThroughput{
			bitsPerSecond: 6_000_000, observedAt: now,
		}
		group.learning.mu.Unlock()
		group.mu.Unlock()

		low := vaneThroughputObservation{
			BitsPerSecond: 1_000_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second, Delivered: true,
		}
		var action vanePolicyAction
		for i := 0; i < 3; i++ {
			action = flow.observe(low)
		}
		require.NotNil(t, action, "on+knownGood must return the target-commit action")

		group.mu.Lock()
		group.targetEvidence[vaneTargetEvidenceKey{
			target: flow.targetStateKey,
			member: vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: betaState.epoch},
		}] = vaneTargetEvidence{bitsPerSecond: 1_000_000, observedAt: clock.Now()}
		group.mu.Unlock()
		require.False(t, action())
		group.mu.Lock()
		require.Empty(t, group.targetHandoffs)
		require.Empty(t, group.mediaBudgets)
		group.mu.Unlock()
	})
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
	// COLD-PICK: the probes below belong to the race under test.
	suppressColdPickProbeForTest(t, group, metadata)
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
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
	flow.mu.Lock()
	require.True(t, flow.closed, "natural close must invalidate the flow")
	flow.mu.Unlock()
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

// CHAIN-07 (c): the connection lifecycle owns the close decision. Natural
// close wins over a queued policy action; a successful policy close wins over
// a later Close; a failed policy action returns the lifecycle to Open.
func TestVaneConnectionLifecycleArbitration(t *testing.T) {
	newConn := func(t *testing.T) (*vaneObservedConn, *[]vaneConnectionCloseObservation) {
		t.Helper()
		observations := make([]vaneConnectionCloseObservation, 0, 2)
		conn := newVaneControlledConnWithNative(&vaneConnTestConn{}, newVaneConnTestClock(),
			nil, nil, nil, nil,
			func(observation vaneConnectionCloseObservation) {
				observations = append(observations, observation)
			}, nil, nil)
		return conn.(*vaneObservedConn), &observations
	}

	t.Run("natural close wins", func(t *testing.T) {
		conn, observations := newConn(t)
		require.NoError(t, conn.Close())
		require.Len(t, *observations, 1)
		require.False(t, (*observations)[0].PolicyClosed)

		called := false
		conn.requestAbort(func() bool { called = true; return true })
		require.False(t, called)
		require.Len(t, *observations, 1, "the losing policy action must not emit a second observation")
	})

	t.Run("policy close wins", func(t *testing.T) {
		conn, observations := newConn(t)
		called := false
		conn.requestAbort(func() bool { called = true; return true })
		require.True(t, called)
		require.Len(t, *observations, 1)
		require.True(t, (*observations)[0].PolicyClosed)

		require.NoError(t, conn.Close())
		require.Len(t, *observations, 1, "natural close after a policy close must not emit a second observation")
	})

	t.Run("failed policy close reopens the lifecycle", func(t *testing.T) {
		conn, observations := newConn(t)
		conn.requestAbort(func() bool { return false })
		conn.lifecycleMu.Lock()
		require.Equal(t, vaneConnectionOpen, conn.lifecycle)
		conn.lifecycleMu.Unlock()
		require.Empty(t, *observations)

		require.NoError(t, conn.Close())
		require.Len(t, *observations, 1)
		require.False(t, (*observations)[0].PolicyClosed)
	})

	t.Run("closed flow rejects planned handoff", func(t *testing.T) {
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
	})
}

// CHAIN-07 (b): an on-mode race callback blocked at the submitter must lose to
// a natural close that already claimed lifecycleMu. The queued requestAbort
// must return before executing the commit action.
func TestVaneNaturalCloseWinsOverBlockedPolicySubmitter(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	configureVaneRacingForTest(t, group, vaneRacingOn)
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		return vaneProbeResult{
			valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap,
			duration: time.Second, lowerBoundBPS: 100_000_000, capHit: true,
		}
	}

	metadata := &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	// COLD-PICK: the probes below belong to the race under test.
	suppressColdPickProbeForTest(t, group, metadata)
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	flow := newVaneMediaFlow(group, decision.proxy.Name(), metadata)
	require.NotNil(t, flow)
	flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch

	var observations []vaneConnectionCloseObservation
	conn := newVaneControlledConnWithNative(&vaneConnTestConn{}, clock,
		nil, nil, nil, nil,
		func(observation vaneConnectionCloseObservation) {
			observations = append(observations, observation)
		}, nil,
		func() { flow.markClosed() })
	observed := conn.(*vaneObservedConn)

	submitEntered := make(chan struct{})
	releaseSubmit := make(chan struct{})
	var submitOnce sync.Once
	flow.setPolicySubmitter(func(action vanePolicyAction, delivered bool) {
		submitOnce.Do(func() { close(submitEntered) })
		<-releaseSubmit
		observed.submitPolicyAction(action, delivered)
	})

	low := vaneThroughputObservation{
		BitsPerSecond: 1_000_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second, Delivered: true,
	}
	for i := 0; i < 3; i++ {
		require.Nil(t, flow.observe(low))
	}
	select {
	case <-submitEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("race callback did not reach the policy submitter")
	}

	require.NoError(t, conn.Close())
	close(releaseSubmit)
	require.Eventually(t, func() bool {
		group.racingRuntime.mu.Lock()
		defer group.racingRuntime.mu.Unlock()
		return !group.racingRuntime.inFlight
	}, 2*time.Second, time.Millisecond)

	group.mu.Lock()
	require.Empty(t, group.targetHandoffs)
	require.Empty(t, group.mediaBudgets)
	require.Empty(t, group.targetPreferences)
	group.mu.Unlock()
	require.Len(t, observations, 1)
	require.False(t, observations[0].PolicyClosed, "natural close must own the only observation")
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
	// COLD-PICK: the probes below belong to the race under test.
	suppressColdPickProbeForTest(t, group, metadata)
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
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

// CHAIN-03: the synchronous chain must walk prepare -> commit -> close ->
// reconnect -> settlement -> preference, not just assert its pieces.
func TestVaneSyncChainPrepareCommitCloseSettleImproved(t *testing.T) {
	clock := newVaneConnTestClock()
	fill := func(payload []byte) (int, error) {
		for i := range payload {
			payload[i] = 1
		}
		return len(payload), nil
	}
	alphaConn := &vaneConnTestConn{readFunc: fill}
	betaConn := &vaneConnTestConn{readFunc: fill}
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.delay = 20
	alpha.dialConn = alphaConn
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	beta.dialConn = betaConn
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	group.media.lowThroughputBPS = 5_000_000
	group.media.demandBPS = 2_000_000
	group.media.minAge = 15 * time.Second
	group.media.minBytes = 2 * 1024 * 1024
	group.media.bufferGuard = 5 * time.Second
	group.media.maxLowWindows = 4

	now := clock.Now()
	group.mu.Lock()
	group.learning.mu.Lock()
	require.NotNil(t, group.ensureProxyNodeLocked(beta, now))
	group.nodeControls["beta"].recentTCPThroughput = vaneRecentThroughput{
		bitsPerSecond: 6_000_000, observedAt: now,
	}
	group.learning.mu.Unlock()
	group.mu.Unlock()

	metadata := &C.Metadata{Host: "rr1.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	conn, err := group.DialContext(t.Context(), metadata)
	require.NoError(t, err)
	observed := conn.(*vaneObservedConn)
	reader, counters := observed.UnwrapReader()
	payload := make([]byte, 64*1024)
	closed := false
	for i := 0; i < 128; i++ {
		n, readErr := reader.Read(payload)
		if readErr != nil {
			break
		}
		require.Equal(t, len(payload), n)
		for _, counter := range counters {
			counter(int64(n))
		}
		alphaConn.mu.Lock()
		closeCalls := alphaConn.closeCalls
		alphaConn.mu.Unlock()
		if closeCalls > 0 {
			closed = true
			break
		}
		clock.Advance(time.Second)
	}
	require.True(t, closed, "the slow flow must be closed by the synchronous plan")
	require.Equal(t, 1, alphaConn.closeCalls)

	key := vaneMediaTargetKey{target: "googlevideo.com", port: 443}
	group.mu.Lock()
	hint, hinted := group.mediaHints[key]
	group.mu.Unlock()
	require.True(t, hinted)
	require.Equal(t, "beta", hint.candidate)

	newConn, err := group.DialContext(t.Context(), metadata)
	require.NoError(t, err)
	newObserved := newConn.(*vaneObservedConn)
	newReader, newCounters := newObserved.UnwrapReader()
	big := make([]byte, 1<<20)
	for i := 0; i < 6; i++ {
		n, readErr := newReader.Read(big)
		require.NoError(t, readErr)
		require.Equal(t, len(big), n)
		for _, counter := range newCounters {
			counter(int64(n))
		}
		clock.Advance(time.Second)
	}
	require.Equal(t, uint64(1), group.VaneDiagnostics().Counters.HandoffImproved)
	require.Zero(t, group.VaneDiagnostics().Counters.HandoffNoGain)
	targetKey, ok := group.targetKeyForMedia(metadata.Host, metadata.DstPort)
	require.True(t, ok)
	group.mu.Lock()
	_, preferred := group.targetPreferences[targetKey]
	group.mu.Unlock()
	require.True(t, preferred, "a real improvement must create the target preference")
	require.NoError(t, newConn.Close())
}

// CHAIN-05: the challenger ordering keeps its four deterministic keys:
// knownGood, score, delay, then name.
func TestVanePrepareCandidateOrderingTieBreaks(t *testing.T) {
	metadata := &C.Metadata{Host: "rr1.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	seedMetrics := func(group *Vane, proxy *vaneTestProxy, now time.Time, connect, response time.Duration) {
		state := group.ensureProxyNodeLocked(proxy, now)
		require.NotNil(t, state)
		state.tcp.observeFailure(now, false)
		state.tcp.observeConnect(now, connect)
		state.tcp.observeResponse(now, response)
		state.tcp.observeThroughput(now, 6_000_000)
	}
	seedRecent := func(group *Vane, proxy *vaneTestProxy, now time.Time, bps float64) {
		require.NotNil(t, group.ensureProxyNodeLocked(proxy, now))
		group.nodeControls[proxy.Name()].recentTCPThroughput = vaneRecentThroughput{bitsPerSecond: bps, observedAt: now}
	}

	cases := []struct {
		name  string
		setup func(t *testing.T, group *Vane, beta, gamma *vaneTestProxy, now time.Time)
		want  string
	}{
		{
			name: "knownGood beats a shorter delay",
			setup: func(t *testing.T, group *Vane, beta, gamma *vaneTestProxy, now time.Time) {
				beta.delay, gamma.delay = 20, 5
				seedRecent(group, beta, now, 6_000_000)
			},
			want: "beta",
		},
		{
			name: "score breaks a knownGood tie",
			setup: func(t *testing.T, group *Vane, beta, gamma *vaneTestProxy, now time.Time) {
				beta.delay, gamma.delay = 10, 10
				seedMetrics(group, beta, now, 10*time.Millisecond, 20*time.Millisecond)
				seedMetrics(group, gamma, now, 500*time.Millisecond, time.Second)
				seedRecent(group, beta, now, 6_000_000)
				seedRecent(group, gamma, now, 6_000_000)
			},
			want: "beta",
		},
		{
			name: "throughput breaks a score tie",
			setup: func(t *testing.T, group *Vane, beta, gamma *vaneTestProxy, now time.Time) {
				beta.delay, gamma.delay = 10, 10
				seedMetrics(group, beta, now, 10*time.Millisecond, 20*time.Millisecond)
				seedMetrics(group, gamma, now, 10*time.Millisecond, 20*time.Millisecond)
				seedRecent(group, beta, now, 6_000_000)
				seedRecent(group, gamma, now, 10_000_000)
			},
			want: "gamma",
		},
		{
			name: "delay breaks a score tie",
			setup: func(t *testing.T, group *Vane, beta, gamma *vaneTestProxy, now time.Time) {
				beta.delay, gamma.delay = 10, 20
				// CHAIN-01: both challengers need evidence above the close bar.
				seedRecent(group, beta, now, 6_000_000)
				seedRecent(group, gamma, now, 6_000_000)
			},
			want: "beta",
		},
		{
			name: "name breaks a delay tie",
			setup: func(t *testing.T, group *Vane, beta, gamma *vaneTestProxy, now time.Time) {
				beta.delay, gamma.delay = 10, 10
				seedRecent(group, beta, now, 6_000_000)
				seedRecent(group, gamma, now, 6_000_000)
			},
			want: "beta",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			clock := newVaneConnTestClock()
			alpha := newVaneTestProxy("alpha", true, true)
			beta := newVaneTestProxy("beta", true, true)
			gamma := newVaneTestProxy("gamma", true, true)
			group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta, gamma)
			configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
			group.media.lowThroughputBPS = 5_000_000
			group.media.demandBPS = 2_000_000
			now := clock.Now()
			group.mu.Lock()
			group.learning.mu.Lock()
			alphaState := group.ensureProxyNodeLocked(alpha, now)
			require.NotNil(t, alphaState)
			testCase.setup(t, group, beta, gamma, now)
			group.learning.mu.Unlock()
			group.mu.Unlock()

			key := group.mediaTargetKey(metadata.Host, metadata.DstPort)
			plan, reason := group.prepareMediaReconnectForNodeDetailed(
				key, metadata.Host, metadata.DstPort, "alpha", alphaState.identity, alphaState.epoch, 1_600_000,
			)
			require.Empty(t, reason)
			require.Equal(t, testCase.want, plan.challenger)
		})
	}
}

// CHAIN-09: demand dominates the low-throughput line. A 6 Mbps candidate is
// not admissible when demand is 8 Mbps, and the race bar is 8 Mbps.
func TestVaneDemandDominatesCandidateAdmission(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	group.media.lowThroughputBPS = 5_000_000
	group.media.demandBPS = 8_000_000
	now := clock.Now()
	group.mu.Lock()
	group.learning.mu.Lock()
	alphaState := group.ensureProxyNodeLocked(alpha, now)
	require.NotNil(t, alphaState)
	require.NotNil(t, group.ensureProxyNodeLocked(beta, now))
	group.nodeControls["beta"].recentTCPThroughput = vaneRecentThroughput{
		bitsPerSecond: 6_000_000, observedAt: now,
	}
	group.learning.mu.Unlock()
	group.mu.Unlock()

	metadata := &C.Metadata{Host: "rr1.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	key := group.mediaTargetKey(metadata.Host, metadata.DstPort)
	plan, reason := group.prepareMediaReconnectForNodeDetailed(
		key, metadata.Host, metadata.DstPort, "alpha", alphaState.identity, alphaState.epoch, 1_600_000,
	)
	require.Equal(t, "no-evidence-candidate", reason)
	require.Empty(t, plan.challenger)

	flow := newVaneMediaFlow(group, "alpha", metadata)
	require.NotNil(t, flow)
	request := flow.raceRequest(vaneThroughputObservation{
		BitsPerSecond: 1_600_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second,
	}, 3)
	require.Equal(t, float64(8_000_000), request.requiredBPS)
	group.mu.Lock()
	require.Empty(t, group.targetPreferences)
	group.mu.Unlock()
}
