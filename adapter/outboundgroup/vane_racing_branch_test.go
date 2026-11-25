package outboundgroup

import (
	"context"
	"fmt"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// Vane racing/target acceptance coverage map (round3 guide item 6). Every
// racing-related test cites the acceptance IDs it pins; this table is the
// index. IDs come from the Phase B active-racing plan:
//
//	RACE-CONFIG-001    old configs gain no new behavior
//	RACE-PROBE-001     probe byte/time boundaries repeat, real bytes are charged
//	RACE-MODE-001     shadow never changes baseline selection or policy state
//	RACE-ENGINE-001    first qualified challenger wins, peers cancel
//	RACE-IDENTITY-001  same-name replacement inherits nothing from probe results
//	RACE-BUDGET-001    concurrent and byte budgets never exceed bounds
//	RACE-LIFECYCLE-001 no stale commit and no goroutine leak after close/reload
//	RACE-HANDOFF-001   the slow flow closes only after the winner is ready
//	RACE-ATOMIC-001    without close ownership nothing leaks lease/cooldown/budget
//	RACE-DELIVERY-001  the positive bytes that triggered the close are never lost
//	RACE-SHADOW-001    shadow matches the frozen baseline in selection, close and state
//	RACE-DIAG-001      one handoff ID traces the whole lifecycle
//	RACE-DIAG-002      reading the diagnostics snapshot never mutates policy
//	RACE-DIAG-003      counters persist across restarts, the event ring stays bounded
//	TARGET-LEASE-001   after policy-close an immediate reconnect deterministically hits the challenger
//	TARGET-SCOPE-001   scene/target/port isolation, no cross-target pollution
//	TARGET-FEEDBACK-001 long-term preference only after real target improvement
//	TARGET-BOUND-001   state is bounded; expired/superseded/inactive entries are invalidated
//	TARGET-COOLDOWN-001 30s/1m/2m/4m/8m/15m progression is exact
//	TARGET-COOLDOWN-002 expiry keeps the streak, real success resets it
//	TARGET-COOLDOWN-003 slow and hard-failure states never contaminate each other

// RACE-ATOMIC-001: rejected commits leave no lease/cooldown/budget residue.
func TestVaneTargetCommitRejectionsLeaveNoState(t *testing.T) {
	cases := []struct {
		name      string
		committed bool
		mutate    func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneReconnectPlan, alpha, beta *vaneTestProxy)
		prepare   func(t *testing.T, group *Vane, plan vaneReconnectPlan)
		want      string
	}{
		{
			name: "challenger unhealthy",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneReconnectPlan, alpha, beta *vaneTestProxy) {
				beta.alive = false
			},
			want: "challenger-unhealthy",
		},
		{
			name: "stale current identity",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneReconnectPlan, alpha, beta *vaneTestProxy) {
				plan.identity = "test:alpha-old"
			},
			want: "stale-node-identity",
		},
		{
			name: "stale generation",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneReconnectPlan, alpha, beta *vaneTestProxy) {
				plan.generation = group.learningGeneration - 1
			},
			want: "stale-generation",
		},
		{
			name: "stale current epoch",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneReconnectPlan, alpha, beta *vaneTestProxy) {
				plan.nodeEpoch = plan.nodeEpoch + 7
			},
			want: "stale-node-identity",
		},
		{
			name: "stale challenger epoch",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneReconnectPlan, alpha, beta *vaneTestProxy) {
				plan.challengerEpoch = 9
			},
			want: "stale-node-identity",
		},
		{
			name: "invalid target",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneReconnectPlan, alpha, beta *vaneTestProxy) {
				plan.targetStateKey = vaneTargetKey{}
			},
			want: "invalid-target",
		},
		{
			name: "expired plan",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneReconnectPlan, alpha, beta *vaneTestProxy) {
				clock.Advance(group.flow.hintTTL + time.Second)
			},
			want: "plan-expired",
		},
		{
			name:      "reconnect cooldown",
			committed: true,
			prepare: func(t *testing.T, group *Vane, plan vaneReconnectPlan) {
				require.Empty(t, group.commitTargetHandoff(plan))
			},
			want: "reconnect-cooldown",
		},
		{
			name: "target candidate cooldown",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneReconnectPlan, alpha, beta *vaneTestProxy) {
				group.mu.Lock()
				node := group.ensureProxyNodeLocked(beta, clock.Now())
				lease := vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: node.epoch}
				group.recordTargetFailureLocked(plan.targetStateKey, lease, clock.Now())
				group.mu.Unlock()
			},
			want: "candidate-cooldown",
		},
		{
			name: "dial cooldown",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneReconnectPlan, alpha, beta *vaneTestProxy) {
				group.mu.Lock()
				group.cooldowns[vaneCooldownKey{
					transport: vaneTransportTCP, target: plan.target, port: plan.port,
					candidate: plan.challenger, identity: plan.challengerIdentity,
				}] = clock.Now().Add(time.Minute)
				group.mu.Unlock()
			},
			want: "candidate-cooldown",
		},
		{
			name: "challenger slow cooldown",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneReconnectPlan, alpha, beta *vaneTestProxy) {
				group.mu.Lock()
				group.slowCooldowns[vaneCandidateKey{
					vaneFlowKey: plan.targetKey, candidate: plan.challenger, identity: plan.challengerIdentity,
				}] = clock.Now().Add(time.Minute)
				group.mu.Unlock()
			},
			want: "challenger-slow-cooldown",
		},
		{
			name: "budget exhausted",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneReconnectPlan, alpha, beta *vaneTestProxy) {
				group.flow.budgetMax = 0
			},
			want: "budget-exhausted",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			group, clock, alpha, beta, metadata := newTargetGroupForTest(t)
			plan := prepareTargetHandoffForTest(t, group, metadata, beta)
			if testCase.prepare != nil {
				testCase.prepare(t, group, plan)
			}
			if testCase.mutate != nil {
				testCase.mutate(t, group, clock, &plan, alpha, beta)
			}
			require.Equal(t, testCase.want, group.commitTargetHandoff(plan))
			group.mu.Lock()
			if testCase.committed {
				require.Len(t, group.targetHandoffs, 1, "the earlier commit stays in place")
			} else {
				require.Empty(t, group.targetHandoffs, "a rejected plan must not publish a lease")
			}
			group.mu.Unlock()
		})
	}
}

// RACE-IDENTITY-001 + TARGET-COOLDOWN-001: selection skips stale identities and cooldown-bound members.
func TestVaneTargetSelectionSkipsStaleBlockedAndCooldownMembers(t *testing.T) {
	cases := []struct {
		name     string
		identity string
		mutate   func(t *testing.T, group *Vane, clock *vaneConnTestClock, key vaneTargetKey, lease vaneMemberLease)
	}{
		{
			name:     "stale preference identity",
			identity: "test:beta-old",
		},
		{
			name: "target cooldown blocks preference",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, key vaneTargetKey, lease vaneMemberLease) {
				group.recordTargetFailureLocked(key, lease, clock.Now())
			},
		},
		{
			name: "slow cooldown blocks preference",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, key vaneTargetKey, lease vaneMemberLease) {
				group.slowCooldowns[vaneCandidateKey{
					vaneFlowKey: vaneFlowKey{target: key.targetScope, port: key.port},
					candidate:   lease.name,
					identity:    lease.identity,
				}] = clock.Now().Add(time.Minute)
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			group, clock, _, beta, metadata := newTargetGroupForTest(t)
			key, ok := group.targetScopeForKey(metadata.Host, metadata.DstPort)
			require.True(t, ok)
			group.mu.Lock()
			node := group.ensureProxyNodeLocked(beta, clock.Now())
			lease := vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: node.epoch}
			if testCase.mutate != nil {
				testCase.mutate(t, group, clock, key, lease)
			}
			if testCase.identity != "" {
				lease.identity = testCase.identity
			}
			group.targetPreferences[key] = vaneTargetPreference{to: lease, expiresAt: clock.Now().Add(time.Hour), updatedAt: clock.Now()}
			group.mu.Unlock()

			suppressColdPickProbeForTest(t, group, metadata)
			decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
			require.NotEmpty(t, decision.proxy.Name(), "an unusable preference must fall back to normal scoring")
			require.Nil(t, decision.handoff, "a rejected preference never hands out a token")
			group.mu.Lock()
			_, preferred := group.targetPreferences[key]
			group.mu.Unlock()
			require.False(t, preferred, "an unusable preference must be dropped")
		})
	}

	t.Run("missing member proxy", func(t *testing.T) {
		group, clock, _, beta, metadata := newTargetGroupForTest(t)
		key, _ := group.targetScopeForKey(metadata.Host, metadata.DstPort)
		group.mu.Lock()
		lease := group.memberLeaseLocked(beta.Name(), beta.identity)
		group.targetPreferences[key] = vaneTargetPreference{to: lease, expiresAt: clock.Now().Add(time.Hour), updatedAt: clock.Now()}
		group.mu.Unlock()
		group.nodeIdentities[beta.Name()] = beta.identity
		group.mu.Lock()
		selected, _, source := group.takeTargetSelectionLocked(key, []C.Proxy{}, clock.Now(), true)
		group.mu.Unlock()
		require.Nil(t, selected)
		require.Empty(t, source)
	})
}

// TARGET-FEEDBACK-001 + TARGET-COOLDOWN-001: evidence and failure guards on the target path.
func TestVaneTargetEvidenceAndFailureGuards(t *testing.T) {
	group, clock, _, beta, metadata := newTargetGroupForTest(t)
	key, _ := group.targetScopeForKey(metadata.Host, metadata.DstPort)
	group.mu.Lock()
	lease := group.memberLeaseLocked(beta.Name(), beta.identity)
	group.mu.Unlock()

	group.recordTargetEvidence(key, lease, 0, false)
	group.mu.Lock()
	require.Empty(t, group.targetEvidence, "non-positive evidence must be dropped")
	group.mu.Unlock()

	configureVaneRacingForTest(t, group, vaneRacingShadow)
	group.recordTargetEvidence(key, lease, 5_000_000, false)
	group.mu.Lock()
	require.Len(t, group.targetEvidence, 1, "dry-run still collects trusted evidence")
	delete(group.targetEvidence, vaneTargetEvidenceKey{target: key, member: lease})
	group.mu.Unlock()
	configureVaneRacingForTest(t, group, vaneRacingOn)

	group.recordTargetEvidence(key, vaneMemberLease{name: "beta", identity: "test:beta-old"}, 5_000_000, false)
	group.mu.Lock()
	require.Empty(t, group.targetEvidence, "evidence for a replaced identity must be dropped")
	group.mu.Unlock()

	group.recordTargetEvidence(key, lease, 5_000_000, false)
	clock.Advance(vaneTargetEvidenceTTL + time.Second)
	group.mu.Lock()
	_, fresh, _ := group.targetEvidenceLocked(key, lease, clock.Now())
	group.targetPreferences[key] = vaneTargetPreference{to: lease, expiresAt: clock.Now(), updatedAt: clock.Now()}
	group.targetHandoffs[key] = vaneHandoffLease{id: 1, to: lease, from: lease, expiresAt: clock.Now(), updatedAt: clock.Now()}
	group.targetFailures[vaneTargetFailureKey{target: key, member: vaneMemberLease{name: "beta", identity: "test:beta-old"}}] = vaneTargetFailureState{streak: 1, lastFailureAt: clock.Now()}
	group.pruneTargetStateLocked(clock.Now())
	require.False(t, fresh)
	require.Empty(t, group.targetEvidence)
	require.Empty(t, group.targetPreferences)
	require.Empty(t, group.targetHandoffs)
	require.Empty(t, group.targetFailures)
	group.mu.Unlock()
}

// TARGET-BOUND-001: target state is bounded by trimming the oldest entries.
func TestVaneTargetStateLimitsTrimOldestEntries(t *testing.T) {
	group, clock, _, beta, metadata := newTargetGroupForTest(t)
	group.mu.Lock()
	lease := group.memberLeaseLocked(beta.Name(), beta.identity)
	for index := 0; index < vaneTargetStateLimit+25; index++ {
		key := vaneTargetKey{transport: vaneTransportTCP, targetScope: fmt.Sprintf("ev-%04d", index), port: 443}
		group.targetEvidence[vaneTargetEvidenceKey{target: key, member: lease}] = vaneTargetEvidence{
			bitsPerSecond: 1, observedAt: clock.Now().Add(-time.Duration(index) * time.Second),
		}
		failureKey := vaneTargetKey{transport: vaneTransportTCP, targetScope: fmt.Sprintf("fl-%04d", index), port: 443}
		group.targetFailures[vaneTargetFailureKey{target: failureKey, member: lease}] = vaneTargetFailureState{
			streak: 1, blockUntil: clock.Now().Add(-time.Minute), lastFailureAt: clock.Now().Add(-time.Duration(index) * time.Second),
		}
		handoffKey := vaneTargetKey{transport: vaneTransportTCP, targetScope: fmt.Sprintf("ho-%04d", index), port: 443}
		group.targetHandoffs[handoffKey] = vaneHandoffLease{
			id: uint64(index), from: lease, to: lease, expiresAt: clock.Now().Add(time.Hour), updatedAt: clock.Now().Add(-time.Duration(index) * time.Second),
		}
		preferenceKey := vaneTargetKey{transport: vaneTransportTCP, targetScope: fmt.Sprintf("pr-%04d", index), port: 443}
		group.targetPreferences[preferenceKey] = vaneTargetPreference{
			to: lease, expiresAt: clock.Now().Add(time.Hour), updatedAt: clock.Now().Add(-time.Duration(index) * time.Second),
		}
	}
	group.pruneTargetStateLocked(clock.Now())
	require.LessOrEqual(t, len(group.targetEvidence), vaneTargetStateLimit)
	require.LessOrEqual(t, len(group.targetFailures), vaneTargetStateLimit)
	require.LessOrEqual(t, len(group.targetHandoffs), vaneTargetStateLimit)
	require.LessOrEqual(t, len(group.targetPreferences), vaneTargetStateLimit)
	_, newestKept := group.targetEvidence[vaneTargetEvidenceKey{
		target: vaneTargetKey{transport: vaneTransportTCP, targetScope: "ev-0000", port: 443}, member: lease,
	}]
	require.True(t, newestKept, "the newest evidence must survive trimming")
	group.mu.Unlock()
	_ = metadata
}

// TARGET-LEASE-001 + RACE-ATOMIC-001: settle only accepts the owning, unexpired token.
func TestVaneTargetSettleRejectsForeignAndExpiredTokens(t *testing.T) {
	group, _, _, beta, metadata := newTargetGroupForTest(t)
	plan := prepareTargetHandoffForTest(t, group, metadata, beta)
	require.Empty(t, group.commitTargetHandoff(plan))
	suppressColdPickProbeForTest(t, group, metadata)
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.NotNil(t, decision.handoff)

	group.settleTargetHandoff(nil, vaneMemberLease{}, vaneThroughputObservation{BitsPerSecond: 1})
	foreign := *decision.handoff
	foreign.id++
	group.settleTargetHandoff(&foreign, decision.handoff.toLease, vaneThroughputObservation{BitsPerSecond: 9_000_000})
	group.mu.Lock()
	_, leaseKept := group.targetHandoffs[decision.handoff.targetKey]
	group.mu.Unlock()
	require.True(t, leaseKept, "a foreign token must not settle the live lease")

	group.settleTargetHandoff(decision.handoff, decision.handoff.toLease, vaneThroughputObservation{BitsPerSecond: 0})
	group.failTargetHandoff(nil, "noop", true)
	group.discardTargetHandoff(nil)
}

// RACE-CONFIG-001: fragment configurations are rejected. The overflow case
// was removed with the racing-budget-mb-hour hardcode.
func TestVaneRacingConfigRejectsFragment(t *testing.T) {
	fallback := newVaneTestProxy("fallback", true, false)
	_, err := NewVane(GroupCommonOption{Name: "vane"}, VaneOption{RacingURL: "https://example.com/file#frag"}, fallback, nil)
	require.Error(t, err)
}

// RACE-LIFECYCLE-001: close is idempotent.
func TestVaneRacingCloseIsIdempotent(t *testing.T) {
	group, _ := newVaneGroupForTest(newVaneConnTestClock(), 10, time.Hour, newVaneTestProxy("alpha", true, true))
	require.NoError(t, group.Close())
	require.NoError(t, group.Close())
	require.True(t, group.racingRuntime.closed)
}

// RACE-IDENTITY-001: a superseded generation never reaches probing.
func TestVaneRaceRejectsStaleGenerationBeforeProbing(t *testing.T) {
	group, _, _, _, _ := newVaneRacingEvidenceGroup(t)
	var probes atomic.Int32
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		probes.Add(1)
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 100_000_000, capHit: true}
	}
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	request.generation = group.learningGeneration - 1
	called := false
	scheduled, reason := group.scheduleReconnectRace(request, func(vaneRaceResult) { called = true })
	require.True(t, scheduled, reason)
	waitVaneRaceIdle(t, group)
	require.False(t, called)
	require.Zero(t, probes.Load())
	require.Positive(t, group.VaneDiagnostics().Counters.RaceStaleGeneration)

	// A stale race must not suppress the next race for this target: the very
	// next schedule with a current generation goes through.
	fresh := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	scheduled, reason = group.scheduleReconnectRace(fresh, func(vaneRaceResult) {})
	require.True(t, scheduled, reason)
	waitVaneRaceIdle(t, group)
}

// RACE-ENGINE-001: a genuine no-winner installs the suppression window.
func TestVaneRaceNoWinnerStillSuppresses(t *testing.T) {
	group, _, _, _, _ := newVaneRacingEvidenceGroup(t)
	var probes atomic.Int32
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		probes.Add(1)
		return vaneProbeResult{reason: "tls-error"}
	}
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	scheduled, reason := group.scheduleReconnectRace(request, func(vaneRaceResult) {
		t.Fatal("a race without a qualified challenger must not produce a winner")
	})
	require.True(t, scheduled, reason)
	waitVaneRaceIdle(t, group)
	require.Positive(t, probes.Load())
	require.Positive(t, group.VaneDiagnostics().Counters.RaceNoWinner)

	// A genuine no-winner result still installs the suppression window.
	scheduled, reason = group.scheduleReconnectRace(request, func(vaneRaceResult) {})
	require.False(t, scheduled)
	require.Equal(t, "no-winner-cooldown", reason)
}

// A flow that recovers while its race is in flight must not be closed by the
// race result (round3 item 4): the callback observes the current window state,
// not the trigger-time snapshot.
// RACE-HANDOFF-001: a flow that recovered mid-race must not be closed by its result.
func TestVaneRaceRecoveredFlowIsNotClosed(t *testing.T) {
	group, clock, alpha, beta, gamma := newVaneRacingEvidenceGroup(t)
	release := make(chan struct{})
	var probes atomic.Int32
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		probes.Add(1)
		<-release
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 100_000_000, capHit: true}
	}

	// Race scheduling validates member leases against the group's node
	// registry, so every challenger must be registered first.
	group.mu.Lock()
	for _, proxy := range []C.Proxy{alpha, beta, gamma} {
		group.ensureProxyNodeLocked(proxy, clock.Now())
	}
	alphaLease := group.memberLeaseLocked(alpha.Name(), alpha.identity)
	group.mu.Unlock()
	flow := newVaneFlow(group, alpha.Name(), &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	require.NotNil(t, flow)
	// Production stamps the dialing member's identity and epoch onto the flow
	// right after newVaneFlow; without them the race sees a stale lease.
	flow.identity = alphaLease.identity
	flow.nodeEpoch = alphaLease.epoch
	sample := vaneThroughputObservation{BitsPerSecond: 500_000, TotalBytes: 4 * 1024 * 1024, Age: 30 * time.Second}
	flow.mu.Lock()
	flow.lowWindows = 3
	flow.mu.Unlock()
	flow.scheduleRace(sample, 3)
	require.Eventually(t, func() bool { return probes.Load() == 2 }, 2*time.Second, time.Millisecond,
		"both challenger probes must be in flight while the flow is still low")

	// The flow recovers (a healthy window resets the streak) while the probes
	// are still blocked.
	flow.mu.Lock()
	flow.lowWindows = 0
	flow.mu.Unlock()
	close(release)
	waitVaneRaceIdle(t, group)

	group.mu.Lock()
	handoffs := len(group.targetHandoffs)
	group.mu.Unlock()
	require.Zero(t, handoffs, "a recovered flow must not get a handoff lease")
	require.False(t, flow.policyAborted(), "a recovered flow must not be closed")

	rejected := false
	for _, event := range vaneRecordedEvents(group) {
		if event.Kind == "reconnect-rejected" && event.Reason == "flow-recovered" {
			rejected = true
		}
	}
	require.True(t, rejected, "the recovery guard must be visible in diagnostics")
}

// RACE-DIAG-001 (race stage): one race task ID stitches the whole lifecycle —
// race-scheduled → race-started → race-candidate-qualified → handoff-committed
// → handoff-improved — and the committed lease carries the readable lease ID.
func TestVaneRaceLifecycleSharesOneIDAcrossHandoff(t *testing.T) {
	group, clock, alpha, beta, gamma := newVaneRacingEvidenceGroup(t)
	release := make(chan struct{})
	var probes atomic.Int32
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		probes.Add(1)
		<-release
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 100_000_000, capHit: true}
	}

	group.mu.Lock()
	for _, proxy := range []C.Proxy{alpha, beta, gamma} {
		group.ensureProxyNodeLocked(proxy, clock.Now())
	}
	alphaLease := group.memberLeaseLocked(alpha.Name(), alpha.identity)
	generation := group.learningGeneration
	group.mu.Unlock()
	flow := newVaneFlow(group, alpha.Name(), &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	require.NotNil(t, flow)
	flow.identity = alphaLease.identity
	flow.nodeEpoch = alphaLease.epoch
	flow.setPolicySubmitter(func(action vanePolicyAction, _ bool) { action() })

	sample := vaneThroughputObservation{BitsPerSecond: 500_000, TotalBytes: 4 * 1024 * 1024, Age: 30 * time.Second}
	flow.mu.Lock()
	flow.lowWindows = 3
	flow.mu.Unlock()
	flow.scheduleRace(sample, 3)
	require.Eventually(t, func() bool { return probes.Load() == 2 }, 2*time.Second, time.Millisecond,
		"both challenger probes must launch")
	close(release)
	waitVaneRaceIdle(t, group)

	group.mu.Lock()
	leases := make([]vaneHandoffLease, 0, len(group.targetHandoffs))
	for _, lease := range group.targetHandoffs {
		leases = append(leases, lease)
	}
	group.mu.Unlock()
	require.Len(t, leases, 1, "the race winner must be leased")
	lease := leases[0]
	raceID := lease.id
	require.NotZero(t, raceID)
	leaseID := fmt.Sprintf("vane-race-%d-%d", generation, raceID)

	kinds := make(map[string]int)
	for _, event := range vaneRecordedEvents(group) {
		if event.HandoffID != raceID {
			continue
		}
		kinds[event.Kind]++
		if event.Kind == "handoff-committed" {
			require.Equal(t, leaseID, event.LeaseID, "the committed lease must carry the readable race lease ID")
		}
	}
	require.Equal(t, 1, kinds["race-scheduled"], "race-stage events must share the handoff ID")
	require.Equal(t, 1, kinds["race-started"])
	require.Equal(t, 1, kinds["race-candidate-qualified"])
	require.Equal(t, 1, kinds["handoff-committed"])

	group.settleTargetHandoff(lease.token, lease.token.toLease, vaneThroughputObservation{
		BitsPerSecond: 40_000_000, TotalBytes: 24 * 1024 * 1024, Age: 3 * time.Second,
	})
	improved := false
	for _, event := range vaneRecordedEvents(group) {
		if event.Kind != "handoff-improved" {
			continue
		}
		improved = true
		require.Equal(t, raceID, event.HandoffID, "lifecycle events must carry the race ID")
		require.Equal(t, leaseID, event.LeaseID)
	}
	require.True(t, improved, "a qualifying settle must record handoff-improved")
}

// RACE-ENGINE-001: a snapshot without challengers returns no-candidate.
func TestVaneRaceSnapshotWithoutChallengers(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	configureVaneRacingForTest(t, group, vaneRacingOn)
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	candidates, reason := group.snapshotRaceCandidates(request)
	require.Empty(t, candidates)
	require.Equal(t, "no-challenger", reason)
}

// RACE-ENGINE-001 + TARGET-COOLDOWN-001: blocked candidates race only when nothing else is available.
func TestVaneRaceSnapshotBlockedCandidates(t *testing.T) {
	t.Run("slow cooldown extends the block deadline", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
		configureVaneRacingForTest(t, group, vaneRacingOn)
		request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		group.mu.Lock()
		lease := group.memberLeaseLocked(beta.Name(), beta.identity)
		failure := group.recordTargetFailureLocked(request.targetKey, lease, clock.Now())
		cooldown := clock.Now().Add(2 * time.Hour)
		group.slowCooldowns[vaneCandidateKey{
			vaneFlowKey: request.scopeKey, candidate: beta.Name(), identity: beta.identity,
		}] = cooldown
		group.mu.Unlock()

		candidates, reason := group.snapshotRaceCandidates(request)
		require.Empty(t, reason)
		require.Len(t, candidates, 1)
		require.Equal(t, beta.Name(), candidates[0].member.name)
		require.Equal(t, cooldown, candidates[0].blockUntil)
		require.True(t, candidates[0].blockUntil.After(failure.blockUntil), "the slow cooldown must win over the short failure backoff")
	})

	t.Run("the earliest blocked challenger is offered", func(t *testing.T) {
		group, clock, _, beta, gamma := newVaneRacingEvidenceGroup(t)
		request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		group.mu.Lock()
		betaLease := group.memberLeaseLocked(beta.Name(), beta.identity)
		gammaLease := group.memberLeaseLocked(gamma.Name(), gamma.identity)
		group.targetFailures[vaneTargetFailureKey{target: request.targetKey, member: betaLease}] = vaneTargetFailureState{
			streak: 1, blockUntil: clock.Now().Add(2 * time.Hour), lastFailureAt: clock.Now(),
		}
		group.targetFailures[vaneTargetFailureKey{target: request.targetKey, member: gammaLease}] = vaneTargetFailureState{
			streak: 1, blockUntil: clock.Now().Add(time.Minute), lastFailureAt: clock.Now(),
		}
		group.mu.Unlock()

		candidates, reason := group.snapshotRaceCandidates(request)
		require.Empty(t, reason)
		require.Len(t, candidates, 1, "when every challenger is cooling down the earliest one is still offered")
		require.Equal(t, gamma.Name(), candidates[0].member.name)
	})
}

// RACE-ENGINE-001 (round3 item 8a): the candidate snapshot drops candidates
// that would waste probe budget — fresh real-target evidence below the race
// bar, no evidence plus no health-check delay, and dial-cooldown members.
func TestVaneRaceSnapshotExcludesLowValueCandidates(t *testing.T) {
	metadata := &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP}

	t.Run("fresh real evidence below required skips probing", func(t *testing.T) {
		group, _, _, beta, _ := newVaneRacingEvidenceGroup(t)
		request := newVaneRaceRequestForTest(t, group, metadata)
		group.mu.Lock()
		betaLease := group.memberLeaseLocked(beta.Name(), beta.identity)
		group.mu.Unlock()
		group.recordTargetEvidence(request.targetKey, betaLease, 1_000, false)

		candidates, reason := group.snapshotRaceCandidates(request)
		require.Empty(t, reason)
		require.Len(t, candidates, 1, "fresh evidence below the bar must exclude beta")
		require.Equal(t, "gamma", candidates[0].member.name)
	})

	t.Run("no evidence and zero delay is not a fast node", func(t *testing.T) {
		group, _, _, beta, _ := newVaneRacingEvidenceGroup(t)
		request := newVaneRaceRequestForTest(t, group, metadata)
		beta.delay = 0

		candidates, reason := group.snapshotRaceCandidates(request)
		require.Empty(t, reason)
		require.Len(t, candidates, 1, "an unknown node with no health-check delay must not be probed")
		require.Equal(t, "gamma", candidates[0].member.name)
	})

	t.Run("dial cooldown skips the candidate", func(t *testing.T) {
		group, clock, _, beta, _ := newVaneRacingEvidenceGroup(t)
		request := newVaneRaceRequestForTest(t, group, metadata)
		group.mu.Lock()
		group.cooldowns[vaneCooldownKey{transport: vaneTransportTCP, target: request.target, port: request.port, candidate: beta.Name(), identity: beta.identity}] = clock.Now().Add(time.Hour)
		group.mu.Unlock()

		candidates, reason := group.snapshotRaceCandidates(request)
		require.Empty(t, reason)
		require.Len(t, candidates, 1, "a dial-cooldown candidate must not consume probe budget")
		require.Equal(t, "gamma", candidates[0].member.name)
	})

	t.Run("all candidates excluded returns no-challenger without probing", func(t *testing.T) {
		group, _, _, beta, gamma := newVaneRacingEvidenceGroup(t)
		var probes atomic.Int32
		group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
			probes.Add(1)
			return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 100_000_000, capHit: true}
		}
		request := newVaneRaceRequestForTest(t, group, metadata)
		leases := make([]vaneMemberLease, 0, 2)
		group.mu.Lock()
		for _, proxy := range []*vaneTestProxy{beta, gamma} {
			leases = append(leases, group.memberLeaseLocked(proxy.Name(), proxy.identity))
		}
		group.mu.Unlock()
		for _, lease := range leases {
			group.recordTargetEvidence(request.targetKey, lease, 1_000, false)
		}

		candidates, reason := group.snapshotRaceCandidates(request)
		require.Empty(t, candidates)
		require.Equal(t, "no-challenger", reason)

		scheduled, _ := group.scheduleReconnectRace(request, func(vaneRaceResult) { t.Fatal("no race may run without candidates") })
		require.True(t, scheduled, "scheduling succeeds and the race ends without a winner")
		waitVaneRaceIdle(t, group)
		require.Zero(t, probes.Load(), "an empty candidate pool must not start probes")
		require.Positive(t, group.VaneDiagnostics().Counters.RaceNoWinner)
	})

	t.Run("the remaining candidate still races normally", func(t *testing.T) {
		group, _, _, beta, _ := newVaneRacingEvidenceGroup(t)
		var probes atomic.Int32
		release := make(chan struct{})
		group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
			probes.Add(1)
			<-release
			return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 100_000_000, capHit: true}
		}
		request := newVaneRaceRequestForTest(t, group, metadata)
		group.mu.Lock()
		betaLease := group.memberLeaseLocked(beta.Name(), beta.identity)
		group.mu.Unlock()
		group.recordTargetEvidence(request.targetKey, betaLease, 1_000, false)

		resultCh := make(chan vaneRaceResult, 1)
		scheduled, reason := group.scheduleReconnectRace(request, func(result vaneRaceResult) { resultCh <- result })
		require.True(t, scheduled, reason)
		require.Eventually(t, func() bool { return probes.Load() == 1 }, 2*time.Second, time.Millisecond,
			"only the surviving candidate may be probed")
		close(release)
		result := <-resultCh
		require.Equal(t, "gamma", result.winner.name, "the surviving candidate must win the race")
		require.Equal(t, "probe", result.source)
		waitVaneRaceIdle(t, group)
	})
}

// RACE-ENGINE-001: candidate ordering tie-breaks are deterministic.
func TestVaneRaceCandidateOrderingTieBreaks(t *testing.T) {
	group, clock, _, beta, gamma := newVaneRacingEvidenceGroup(t)
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	group.mu.Lock()
	betaLease := group.memberLeaseLocked(beta.Name(), beta.identity)
	gammaLease := group.memberLeaseLocked(gamma.Name(), gamma.identity)
	group.mu.Unlock()
	// Two fresh target proofs with different rates: the faster one must lead.
	group.recordTargetEvidence(request.targetKey, betaLease, 3_000_000, false)
	group.recordTargetEvidence(request.targetKey, gammaLease, 6_000_000, false)
	candidates, reason := group.snapshotRaceCandidates(request)
	require.Empty(t, reason)
	require.Len(t, candidates, 2)
	require.Equal(t, "gamma", candidates[0].member.name)
	require.True(t, candidates[0].targetFresh)

	// Two fresh capability proofs with different rates.
	group.racingRuntime.mu.Lock()
	group.racingRuntime.capabilities[betaLease] = vaneCapabilityRecord{member: betaLease, lowerBoundBPS: 2_000_000, observedAt: clock.Now()}
	group.racingRuntime.capabilities[gammaLease] = vaneCapabilityRecord{member: gammaLease, lowerBoundBPS: 8_000_000, observedAt: clock.Now()}
	group.racingRuntime.mu.Unlock()
	otherKey := request
	otherKey.targetKey = vaneTargetKey{transport: vaneTransportTCP, targetScope: "googlevideo.com", port: 8443}
	otherKey.scopeKey = vaneFlowKey{target: "googlevideo.com", port: 8443}
	candidates, reason = group.snapshotRaceCandidates(otherKey)
	require.Empty(t, reason)
	require.Equal(t, "gamma", candidates[0].member.name)
	require.True(t, candidates[0].capFresh)
	require.False(t, candidates[0].targetFresh)
}

// RACE-BUDGET-001: reservations are atomic and bounded.
func TestVaneRaceBudgetReservationGuards(t *testing.T) {
	group, _, _, _, _ := newVaneRacingEvidenceGroup(t)
	require.Empty(t, group.reserveRaceBudget(0, group.clock.Now()))
	group.racing.budgetBytesHour = vaneRacingMinimumReservation - 1
	require.Empty(t, group.reserveRaceBudget(1, group.clock.Now()))
	group.racing.budgetBytesHour = 2 * vaneRacingMinimumReservation
	limits := group.reserveRaceBudget(4, group.clock.Now())
	require.NotEmpty(t, limits)
	for _, limit := range limits {
		require.GreaterOrEqual(t, limit, vaneRacingMinimumReservation)
	}
	total := int64(0)
	for _, limit := range limits {
		total += limit
	}
	require.LessOrEqual(t, total, 2*vaneRacingMinimumReservation)
}

// RACE-BUDGET-001: budget denial starts no probes.
func TestVaneRaceBudgetDeniedStopsProbing(t *testing.T) {
	group, _, _, _, _ := newVaneRacingEvidenceGroup(t)
	group.racing.budgetBytesHour = vaneRacingMinimumReservation - 1
	var probes int32
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		probes++
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 100_000_000, capHit: true}
	}
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	scheduled, reason := group.scheduleReconnectRace(request, func(vaneRaceResult) { t.Fatal("a denied budget must not produce a winner") })
	require.True(t, scheduled, reason)
	waitVaneRaceIdle(t, group)
	require.Zero(t, probes)
	require.Positive(t, group.VaneDiagnostics().Counters.RaceBudgetDenied)
}

// RACE-IDENTITY-001: winner validation rejects superseded generations.
func TestVaneValidateRaceWinnerRejectsStaleGeneration(t *testing.T) {
	group, _, _, beta, _ := newVaneRacingEvidenceGroup(t)
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	group.mu.Lock()
	lease := group.memberLeaseLocked(beta.Name(), beta.identity)
	group.mu.Unlock()
	require.True(t, group.validateRaceWinner(request, lease))
	staleRequest := request
	staleRequest.generation = request.generation - 1
	require.False(t, group.validateRaceWinner(staleRequest, lease))
}

// RACE-PROBE-001: invalid probe requests fail fast.
func TestVaneProbeRejectsInvalidRequests(t *testing.T) {
	proxy := newVaneTestProxy("probe", true, true)
	goodURL, err := url.Parse("https://example.com/file")
	require.NoError(t, err)
	httpURL, err := url.Parse("http://example.com/file")
	require.NoError(t, err)

	require.Equal(t, "invalid-request", probeVaneCapability(context.Background(), nil, goodURL, 1024).reason)
	require.Equal(t, "invalid-request", probeVaneCapability(context.Background(), proxy, nil, 1024).reason)
	require.Equal(t, "invalid-request", probeVaneCapability(context.Background(), proxy, httpURL, 1024).reason)
	require.Equal(t, "invalid-request", probeVaneCapability(context.Background(), proxy, goodURL, 0).reason)
}

// RACE-PROBE-001: canceled dials are classified, not failures.
func TestVaneProbeClassifiesCanceledDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	goodURL, err := url.Parse("https://example.com/file")
	require.NoError(t, err)
	result := probeVaneCapability(ctx, &vaneBlockingDialProxy{vaneTestProxy: newVaneTestProxy("probe", true, true)}, goodURL, 1024)
	require.Equal(t, "canceled", result.reason)
}

// RACE-DIAG-001: one handoff ID must stitch the whole lifecycle together.
func TestVaneHandoffLifecycleSharesOneDiagnosticID(t *testing.T) {
	group, _, _, beta, metadata := newTargetGroupForTest(t)
	plan := prepareTargetHandoffForTest(t, group, metadata, beta)
	require.Empty(t, group.commitTargetHandoff(plan))
	suppressColdPickProbeForTest(t, group, metadata)
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.NotNil(t, decision.handoff)
	id := decision.handoff.id
	group.settleTargetHandoff(decision.handoff, decision.handoff.toLease, vaneThroughputObservation{
		BitsPerSecond: 40_000_000, TotalBytes: 24 * 1024 * 1024, Age: 3 * time.Second,
	})

	kinds := make(map[string]int)
	for _, event := range vaneRecordedEvents(group) {
		if event.HandoffID == id {
			kinds[event.Kind]++
		}
	}
	require.Equal(t, 1, kinds["handoff-committed"])
	require.Equal(t, 1, kinds["handoff-improved"])

	group.failTargetHandoff(decision.handoff, "test-failure", false)
	for _, event := range vaneRecordedEvents(group) {
		if event.Kind == "handoff-failed" {
			require.Equal(t, id, event.HandoffID, "every lifecycle event must carry the same handoff ID")
		}
	}
}

// RACE-DIAG-002: reading diagnostics must never mutate selection policy.
func TestVaneDiagnosticsSnapshotIsReadOnly(t *testing.T) {
	group, _, _, beta, metadata := newTargetGroupForTest(t)
	plan := prepareTargetHandoffForTest(t, group, metadata, beta)
	require.Empty(t, group.commitTargetHandoff(plan))

	first := group.VaneDiagnostics()
	group.mu.Lock()
	handoffs, preferences, evidence := len(group.targetHandoffs), len(group.targetPreferences), len(group.targetEvidence)
	group.mu.Unlock()
	for attempt := 0; attempt < 5; attempt++ {
		repeated := group.VaneDiagnostics()
		require.Equal(t, first.Counters, repeated.Counters)
	}
	group.mu.Lock()
	require.Equal(t, handoffs, len(group.targetHandoffs))
	require.Equal(t, preferences, len(group.targetPreferences))
	require.Equal(t, evidence, len(group.targetEvidence))
	group.mu.Unlock()
	require.Equal(t, "beta", group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, false).proxy.Name(),
		"reads must not consume the handoff token or change the preferred member")
}

// RACE-DIAG-003: racing counters accumulate.
func TestVaneRacingCountersAccumulate(t *testing.T) {
	clock := newVaneConnTestClock()
	diagnostics := newVaneDiagnostics("vane-race", clock)
	diagnostics.record(vaneDiagnosticRecord{kind: "race-budget-denied", target: "rr.googlevideo.com", bucket: "googlevideo.com", port: 443})
	for index := 0; index < 104; index++ {
		diagnostics.record(vaneDiagnosticRecord{kind: "race-no-winner", reason: fmt.Sprintf("reason-%02d", index), target: "rr.googlevideo.com", bucket: "googlevideo.com", port: 443})
	}
	diagnostics.record(vaneDiagnosticRecord{kind: "race-no-winner", reason: "stale-generation", target: "rr.googlevideo.com", bucket: "googlevideo.com", port: 443})

	snapshot := diagnostics.snapshot()
	require.Equal(t, uint64(1), snapshot.Counters.RaceBudgetDenied)
	require.Equal(t, uint64(105), snapshot.Counters.RaceNoWinner)
}

type vaneBlockingDialProxy struct {
	*vaneTestProxy
}

func (p *vaneBlockingDialProxy) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
