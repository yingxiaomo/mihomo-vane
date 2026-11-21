package outboundgroup

import (
	"context"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// chain01ProductionValues restores the values configureVaneMediaForTest
// quietly changed. CHAIN-01 assertions depend on them; a test that passes on
// the helper's weakened values is hollow.
func chain01ProductionValues(t *testing.T, group *Vane, demandBPS float64) {
	t.Helper()
	group.media.lowThroughputBPS = 5_000_000
	group.media.demandBPS = demandBPS
	group.media.maxLowWindows = 4
	group.media.minAge = 15 * time.Second
	group.media.minBytes = 2 * 1024 * 1024
	group.media.bufferGuard = 5 * time.Second
}

func seedChain01Traffic(t *testing.T, group *Vane, name string, now time.Time, bps float64) {
	t.Helper()
	group.mu.Lock()
	group.learning.mu.Lock()
	group.ensureNodeLocked(name, now)
	group.ensureNodeControlLocked(name, now).recentTCPThroughput = vaneRecentThroughput{
		bitsPerSecond: bps, observedAt: now,
	}
	group.learning.mu.Unlock()
	group.mu.Unlock()
}

func seedChain01Capability(t *testing.T, group *Vane, member vaneMemberLease, bps float64, observedAt time.Time) {
	t.Helper()
	group.racingRuntime.mu.Lock()
	group.racingRuntime.capabilities[member] = vaneCapabilityRecord{
		member: member, lowerBoundBPS: bps, bytes: vaneRacingProbeByteCap, observedAt: observedAt,
	}
	group.racingRuntime.mu.Unlock()
}

func chain01Prepare(t *testing.T, group *Vane, metadata *C.Metadata, current *vaneTestProxy, currentBPS float64) (vaneMediaPlan, string) {
	t.Helper()
	group.mu.Lock()
	group.learning.mu.Lock()
	state := group.ensureProxyNodeLocked(current, group.clock.Now())
	require.NotNil(t, state)
	identity, epoch := state.identity, state.epoch
	group.learning.mu.Unlock()
	group.mu.Unlock()
	key := group.mediaTargetKey(metadata.Host, metadata.DstPort)
	return group.prepareMediaReconnectForNodeDetailed(key, metadata.Host, metadata.DstPort, current.Name(), identity, epoch, currentBPS)
}

// CHAIN-01-01: cold start with delay-only challengers must not close the flow.
func TestVaneChain01ColdStartDoesNotCloseWithoutEvidence(t *testing.T) {
	for _, mode := range []vaneRacingMode{vaneRacingOff, vaneRacingShadow} {
		t.Run(mode.String(), func(t *testing.T) {
			clock := newVaneConnTestClock()
			alpha := newVaneTestProxy("alpha", true, true)
			beta := newVaneTestProxy("beta", true, true)
			beta.delay = 10
			group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
			configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
			chain01ProductionValues(t, group, 2_000_000)
			configureVaneRacingForTest(t, group, mode)
			var probeCalls atomic.Int64
			group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
				probeCalls.Add(1)
				return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 12_060_000, capHit: true}
			}

			metadata := &C.Metadata{Host: "rr1.googlevideo.com", DstPort: 443, NetWork: C.TCP}
			// COLD-PICK: suppress the cold-pick probe so the pick itself does
			// not write capability evidence; this test is about the gate on
			// the slow-flow path, not about the pick probe.
			group.mu.Lock()
			group.lastPickProbeAt[group.mediaTargetKey(metadata.Host, metadata.DstPort).target] = clock.Now()
			group.mu.Unlock()
			decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
			flow := newVaneMediaFlow(group, decision.proxy.Name(), metadata)
			require.NotNil(t, flow)
			flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
			low := vaneThroughputObservation{BitsPerSecond: 1_480_000, TotalBytes: 8 * 1024 * 1024, Age: 30 * time.Second, Delivered: true}
			for i := 0; i < 4; i++ {
				require.Nil(t, flow.observe(low))
			}

			snapshot := group.VaneDiagnostics()
			require.GreaterOrEqual(t, snapshot.Counters.ReconnectSuppressed, uint64(1))
			require.GreaterOrEqual(t, snapshot.Suppressions["no-evidence-candidate"], uint64(1))
			require.Zero(t, snapshot.Counters.ReconnectCommitted)
			key := group.mediaTargetKey(metadata.Host, metadata.DstPort)
			group.mu.Lock()
			require.Zero(t, group.mediaBudgets[key].count)
			_, hinted := group.mediaHints[key]
			_, cooled := group.mediaSlowCooldowns[vaneMediaCandidateKey{
				vaneMediaTargetKey: key, candidate: alpha.Name(), identity: alpha.identity,
			}]
			group.mu.Unlock()
			require.False(t, hinted)
			require.False(t, cooled)
			if mode == vaneRacingShadow {
				require.Eventually(t, func() bool { return probeCalls.Load() > 0 }, 2*time.Second, time.Millisecond,
					"shadow must schedule the recovery race")
			} else {
				require.Zero(t, probeCalls.Load())
			}
		})
	}
}

// CHAIN-01-02: fresh capability evidence above the bar admits the challenger
// over a lower-delay evidence-less distractor; expired capability does not.
func TestVaneChain01CapabilityEvidenceAdmitsChallenger(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 5 // distractor: lower delay, no evidence at all
	gamma := newVaneTestProxy("gamma", true, true)
	gamma.delay = 20
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta, gamma)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	chain01ProductionValues(t, group, 10_000_000)

	metadata := &C.Metadata{Host: "rr1.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	seedChain01Capability(t, group, vaneMemberLease{name: gamma.Name(), identity: gamma.identity, epoch: 1}, 12_060_000, clock.Now())
	// The race probed gamma before it was ever selected; give it node state so
	// its lease carries the epoch the record was written under.
	group.mu.Lock()
	group.learning.mu.Lock()
	group.ensureProxyNodeLocked(gamma, clock.Now())
	group.learning.mu.Unlock()
	group.mu.Unlock()

	plan, reason := chain01Prepare(t, group, metadata, alpha, 1_480_000)
	require.Empty(t, reason)
	require.Equal(t, gamma.Name(), plan.challenger,
		"capability evidence must admit gamma over the lower-delay distractor")
	require.False(t, plan.knownGood, "capability evidence does not produce knownGood")

	// Expired capability: same record, 11 minutes old -> no candidate.
	group.racingRuntime.mu.Lock()
	record := group.racingRuntime.capabilities[vaneMemberLease{name: gamma.Name(), identity: gamma.identity, epoch: 1}]
	record.observedAt = clock.Now().Add(-11 * time.Minute)
	group.racingRuntime.capabilities[vaneMemberLease{name: gamma.Name(), identity: gamma.identity, epoch: 1}] = record
	group.racingRuntime.mu.Unlock()
	plan, reason = chain01Prepare(t, group, metadata, alpha, 1_480_000)
	require.Equal(t, "no-evidence-candidate", reason)
	require.Empty(t, plan.challenger)
}

// CHAIN-01-03: fresh real-traffic evidence below the close bar must not close.
func TestVaneChain01FreshEvidenceBelowBarDoesNotClose(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	chain01ProductionValues(t, group, 2_000_000)
	seedChain01Traffic(t, group, beta.Name(), clock.Now(), 3_000_000)

	metadata := &C.Metadata{Host: "rr1.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	plan, reason := chain01Prepare(t, group, metadata, alpha, 1_600_000)
	require.Equal(t, "no-evidence-candidate", reason, "3 Mbps evidence is below the 5 Mbps bar")
	require.Empty(t, plan.challenger)
}

// CHAIN-01-04: 12 Mbps with demand 10M is the regression-protected knownGood
// path (old code passes too); 6 Mbps below the demand-inclusive bar is the new
// no-close behavior.
func TestVaneChain01DemandInclusiveBar(t *testing.T) {
	t.Run("12 Mbps knownGood still closes", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		beta.delay = 10
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		chain01ProductionValues(t, group, 10_000_000)
		seedChain01Traffic(t, group, beta.Name(), clock.Now(), 12_000_000)

		metadata := &C.Metadata{Host: "rr1.googlevideo.com", DstPort: 443, NetWork: C.TCP}
		plan, reason := chain01Prepare(t, group, metadata, alpha, 1_600_000)
		require.Empty(t, reason)
		require.Equal(t, beta.Name(), plan.challenger)
		require.True(t, plan.knownGood)

		// The close is only half of the story: the committed handoff must also
		// settle and build the target preference (CHAIN-03's full chain, pinned
		// at the unit level for the knownGood path).
		require.Empty(t, group.commitMediaReconnectDetailed(plan))
		decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
		require.NotNil(t, decision.handoff)
		// The settle member is what the reconnected flow would carry: the
		// baseline token has no toLease of its own (the hint carried it).
		member := vaneMemberLease{name: plan.challenger, identity: plan.challengerIdentity, epoch: plan.challengerEpoch}
		group.settleTargetHandoff(decision.handoff, member, vaneThroughputObservation{
			BitsPerSecond: 40_000_000, TotalBytes: 24 * 1024 * 1024, Age: 3 * time.Second,
		})
		group.mu.Lock()
		_, hasPreference := group.targetPreferences[plan.targetStateKey]
		group.mu.Unlock()
		require.True(t, hasPreference, "an improved settlement must build the target preference")
		require.Positive(t, group.VaneDiagnostics().Counters.HandoffImproved)
	})

	t.Run("6 Mbps below the 10M bar does not close", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		beta.delay = 10
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		chain01ProductionValues(t, group, 10_000_000)
		seedChain01Traffic(t, group, beta.Name(), clock.Now(), 6_000_000)

		metadata := &C.Metadata{Host: "rr1.googlevideo.com", DstPort: 443, NetWork: C.TCP}
		plan, reason := chain01Prepare(t, group, metadata, alpha, 1_600_000)
		require.Equal(t, "no-evidence-candidate", reason)
		require.Empty(t, plan.challenger)
	})
}

// CHAIN-01-06: the commit side re-checks evidence across the prepare->commit
// window for capability-admitted plans.
func TestVaneChain01CommitEvidenceRecheck(t *testing.T) {
	t.Run("capability expires before commit", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		beta.delay = 10
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		chain01ProductionValues(t, group, 10_000_000)
		metadata := &C.Metadata{Host: "rr1.googlevideo.com", DstPort: 443, NetWork: C.TCP}
		seedChain01Capability(t, group, vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: 1}, 12_060_000, clock.Now())
		group.mu.Lock()
		group.learning.mu.Lock()
		group.ensureProxyNodeLocked(beta, clock.Now())
		group.learning.mu.Unlock()
		group.mu.Unlock()
		plan, _ := chain01Prepare(t, group, metadata, alpha, 1_480_000)
		require.NotEmpty(t, plan.challenger)
		seedChain01Capability(t, group, vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: 1}, 12_060_000, clock.Now().Add(-11*time.Minute))
		require.Equal(t, "challenger-no-evidence", group.commitMediaReconnectDetailed(plan))
		group.mu.Lock()
		key := group.mediaTargetKey(metadata.Host, metadata.DstPort)
		require.Zero(t, group.mediaBudgets[key].count)
		group.mu.Unlock()
	})

	t.Run("real traffic degrades below the bar before commit", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		beta.delay = 10
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		chain01ProductionValues(t, group, 10_000_000)
		metadata := &C.Metadata{Host: "rr1.googlevideo.com", DstPort: 443, NetWork: C.TCP}
		seedChain01Capability(t, group, vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: 1}, 12_060_000, clock.Now())
		group.mu.Lock()
		group.learning.mu.Lock()
		group.ensureProxyNodeLocked(beta, clock.Now())
		group.learning.mu.Unlock()
		group.mu.Unlock()
		plan, _ := chain01Prepare(t, group, metadata, alpha, 1_480_000)
		require.NotEmpty(t, plan.challenger)
		// The capability cache is gone; fresh but slow real traffic replaces it.
		group.racingRuntime.mu.Lock()
		delete(group.racingRuntime.capabilities, vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: 1})
		group.racingRuntime.mu.Unlock()
		seedChain01Traffic(t, group, beta.Name(), clock.Now(), 3_000_000)
		require.Equal(t, "challenger-evidence-degraded", group.commitMediaReconnectDetailed(plan))
	})
}

// CHAIN-01-07: a target-evidence race winner commits through the target tier.
func TestVaneChain01TargetEvidenceWinnerCommits(t *testing.T) {
	t.Run("direct commit", func(t *testing.T) {
		group, _, _, beta, metadata := newTargetGroupForTest(t)
		chain01ProductionValues(t, group, 2_000_000)
		plan := prepareTargetHandoffForTest(t, group, metadata, beta)
		plan.challengerEpoch = 0
		now := group.clock.Now()
		group.mu.Lock()
		group.learning.mu.Lock()
		betaState := group.nodes[beta.Name()]
		require.NotNil(t, betaState)
		plan.challengerEpoch = betaState.epoch
		group.targetEvidence[vaneTargetEvidenceKey{
			target: plan.targetStateKey,
			member: vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: betaState.epoch},
		}] = vaneTargetEvidence{bitsPerSecond: 12_060_000, observedAt: now}
		group.learning.mu.Unlock()
		group.mu.Unlock()

		require.Empty(t, group.commitTargetHandoff(plan))
	})

	t.Run("race callback", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		beta.delay = 10
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		chain01ProductionValues(t, group, 2_000_000)
		configureVaneRacingForTest(t, group, vaneRacingOn)
		group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
			return vaneProbeResult{reason: "zero-bytes"}
		}

		metadata := &C.Metadata{Host: "rr1.googlevideo.com", DstPort: 443, NetWork: C.TCP}
		decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
		flow := newVaneMediaFlow(group, decision.proxy.Name(), metadata)
		require.NotNil(t, flow)
		flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
		now := clock.Now()
		group.mu.Lock()
		group.learning.mu.Lock()
		betaState := group.ensureProxyNodeLocked(beta, now)
		require.NotNil(t, betaState)
		group.targetEvidence[vaneTargetEvidenceKey{
			target: flow.targetStateKey,
			member: vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: betaState.epoch},
		}] = vaneTargetEvidence{bitsPerSecond: 12_060_000, observedAt: now}
		group.learning.mu.Unlock()
		group.mu.Unlock()

		actions := make(chan vanePolicyAction, 1)
		flow.setPolicySubmitter(func(action vanePolicyAction, _ bool) { actions <- action })
		low := vaneThroughputObservation{BitsPerSecond: 1_000_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second, Delivered: true}
		for i := 0; i < 4; i++ {
			require.Nil(t, flow.observe(low))
		}
		var action vanePolicyAction
		select {
		case action = <-actions:
		case <-time.After(2 * time.Second):
			t.Fatal("target-evidence race did not submit a policy action")
		}
		require.True(t, action())
		group.mu.Lock()
		require.Len(t, group.targetHandoffs, 1)
		group.mu.Unlock()
	})

	// CHAIN-01-07 (explicit 3M case): target evidence below the close bar
	// rejects the commit even though it is the winning tier. CHAIN-01-08
	// covers the same semantics from the priority angle; this one pins the
	// winner path itself.
	t.Run("below-bar target evidence rejects the commit", func(t *testing.T) {
		group, _, _, beta, metadata := newTargetGroupForTest(t)
		chain01ProductionValues(t, group, 2_000_000)
		plan := prepareTargetHandoffForTest(t, group, metadata, beta)
		now := group.clock.Now()
		group.mu.Lock()
		group.targetEvidence[vaneTargetEvidenceKey{
			target: plan.targetStateKey,
			member: vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: plan.challengerEpoch},
		}] = vaneTargetEvidence{bitsPerSecond: 3_000_000, observedAt: now}
		group.mu.Unlock()
		require.Equal(t, "challenger-evidence-degraded", group.commitTargetHandoff(plan))
	})
}

// CHAIN-01-08: target-level evidence outranks node-level evidence by tier.
func TestVaneChain01TargetEvidencePriority(t *testing.T) {
	newCase := func(t *testing.T) (*Vane, *vaneTestProxy, vaneMediaPlan, *C.Metadata) {
		group, _, _, beta, metadata := newTargetGroupForTest(t)
		chain01ProductionValues(t, group, 2_000_000)
		plan := prepareTargetHandoffForTest(t, group, metadata, beta)
		return group, beta, plan, metadata
	}

	t.Run("slow target evidence vetoes a knownGood plan", func(t *testing.T) {
		group, beta, plan, metadata := newCase(t)
		now := group.clock.Now()
		seedChain01Traffic(t, group, beta.Name(), now, 12_000_000)
		group.mu.Lock()
		group.targetEvidence[vaneTargetEvidenceKey{
			target: plan.targetStateKey,
			member: vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: plan.challengerEpoch},
		}] = vaneTargetEvidence{bitsPerSecond: 3_000_000, observedAt: now}
		group.mu.Unlock()
		require.Equal(t, "challenger-evidence-degraded", group.commitTargetHandoff(plan))
		_ = metadata
	})

	t.Run("target evidence outranks fresher node evidence", func(t *testing.T) {
		group, beta, plan, _ := newCase(t)
		now := group.clock.Now()
		seedChain01Traffic(t, group, beta.Name(), now, 3_000_000)
		group.mu.Lock()
		group.targetEvidence[vaneTargetEvidenceKey{
			target: plan.targetStateKey,
			member: vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: plan.challengerEpoch},
		}] = vaneTargetEvidence{bitsPerSecond: 12_060_000, observedAt: now.Add(-9 * time.Minute)}
		group.mu.Unlock()
		require.Empty(t, group.commitTargetHandoff(plan),
			"target-level strictness is intentional: the target tier wins even when node evidence is fresher")
	})
}
