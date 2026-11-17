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

func TestVaneTargetCommitRejectionsLeaveNoState(t *testing.T) {
	cases := []struct {
		name      string
		committed bool
		mutate    func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneMediaPlan, alpha, beta *vaneTestProxy)
		prepare   func(t *testing.T, group *Vane, plan vaneMediaPlan)
		want      string
	}{
		{
			name: "challenger unhealthy",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneMediaPlan, alpha, beta *vaneTestProxy) {
				beta.alive = false
			},
			want: "challenger-unhealthy",
		},
		{
			name: "stale current identity",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneMediaPlan, alpha, beta *vaneTestProxy) {
				plan.identity = "test:alpha-old"
			},
			want: "stale-node-identity",
		},
		{
			name: "stale generation",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneMediaPlan, alpha, beta *vaneTestProxy) {
				plan.generation = group.learningGeneration - 1
			},
			want: "stale-generation",
		},
		{
			name: "stale current epoch",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneMediaPlan, alpha, beta *vaneTestProxy) {
				plan.nodeEpoch = plan.nodeEpoch + 7
			},
			want: "stale-node-identity",
		},
		{
			name: "stale challenger epoch",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneMediaPlan, alpha, beta *vaneTestProxy) {
				plan.challengerEpoch = 9
			},
			want: "stale-node-identity",
		},
		{
			name: "invalid target",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneMediaPlan, alpha, beta *vaneTestProxy) {
				plan.targetStateKey = vaneTargetKey{}
			},
			want: "invalid-target",
		},
		{
			name: "expired plan",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneMediaPlan, alpha, beta *vaneTestProxy) {
				clock.Advance(group.media.hintTTL + time.Second)
			},
			want: "plan-expired",
		},
		{
			name:      "reconnect cooldown",
			committed: true,
			prepare: func(t *testing.T, group *Vane, plan vaneMediaPlan) {
				require.Empty(t, group.commitTargetHandoff(plan))
			},
			want: "reconnect-cooldown",
		},
		{
			name: "target candidate cooldown",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneMediaPlan, alpha, beta *vaneTestProxy) {
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
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneMediaPlan, alpha, beta *vaneTestProxy) {
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
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneMediaPlan, alpha, beta *vaneTestProxy) {
				group.mu.Lock()
				group.mediaSlowCooldowns[vaneMediaCandidateKey{
					vaneMediaTargetKey: plan.targetKey, candidate: plan.challenger, identity: plan.challengerIdentity,
				}] = clock.Now().Add(time.Minute)
				group.mu.Unlock()
			},
			want: "challenger-slow-cooldown",
		},
		{
			name: "budget exhausted",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, plan *vaneMediaPlan, alpha, beta *vaneTestProxy) {
				group.media.budgetMax = 0
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

func TestVaneTargetSelectionSkipsStaleBlockedAndCooldownMembers(t *testing.T) {
	cases := []struct {
		name       string
		identity   string
		mutate     func(t *testing.T, group *Vane, clock *vaneConnTestClock, key vaneTargetKey, lease vaneMemberLease)
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
			name: "media slow cooldown blocks preference",
			mutate: func(t *testing.T, group *Vane, clock *vaneConnTestClock, key vaneTargetKey, lease vaneMemberLease) {
				group.mediaSlowCooldowns[vaneMediaCandidateKey{
					vaneMediaTargetKey: vaneMediaTargetKey{target: key.targetScope, port: key.port},
					candidate:          lease.name,
					identity:           lease.identity,
				}] = clock.Now().Add(time.Minute)
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			group, clock, _, beta, metadata := newTargetGroupForTest(t)
			key, ok := group.targetKeyForMedia(metadata.Host, metadata.DstPort)
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

			decision := group.pickDecision(metadata, vaneTransportTCP, false, true)
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
		key, _ := group.targetKeyForMedia(metadata.Host, metadata.DstPort)
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

func TestVaneTargetEvidenceAndFailureGuards(t *testing.T) {
	group, clock, _, beta, metadata := newTargetGroupForTest(t)
	key, _ := group.targetKeyForMedia(metadata.Host, metadata.DstPort)
	group.mu.Lock()
	lease := group.memberLeaseLocked(beta.Name(), beta.identity)
	group.mu.Unlock()

	group.recordTargetEvidence(key, lease, 0)
	group.mu.Lock()
	require.Empty(t, group.targetEvidence, "non-positive evidence must be dropped")
	group.mu.Unlock()

	group.racing.mode = vaneRacingOff
	group.recordTargetEvidence(key, lease, 5_000_000)
	group.mu.Lock()
	require.Empty(t, group.targetEvidence, "evidence is only collected while racing is active")
	group.racing.mode = vaneRacingOn
	group.mu.Unlock()

	group.recordTargetEvidence(key, vaneMemberLease{name: "beta", identity: "test:beta-old"}, 5_000_000)
	group.mu.Lock()
	require.Empty(t, group.targetEvidence, "evidence for a replaced identity must be dropped")
	group.mu.Unlock()

	group.recordTargetEvidence(key, lease, 5_000_000)
	clock.Advance(vaneTargetEvidenceTTL + time.Second)
	group.mu.Lock()
	_, fresh := group.targetEvidenceLocked(key, lease, clock.Now())
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

func TestVaneTargetStateLimitsTrimOldestEntries(t *testing.T) {
	group, clock, _, beta, metadata := newTargetGroupForTest(t)
	group.mu.Lock()
	lease := group.memberLeaseLocked(beta.Name(), beta.identity)
	for index := 0; index < vaneTargetStateLimit+25; index++ {
		key := vaneTargetKey{transport: vaneTransportTCP, scene: vaneSceneMedia, targetScope: fmt.Sprintf("ev-%04d", index), port: 443}
		group.targetEvidence[vaneTargetEvidenceKey{target: key, member: lease}] = vaneTargetEvidence{
			bitsPerSecond: 1, observedAt: clock.Now().Add(-time.Duration(index) * time.Second),
		}
		failureKey := vaneTargetKey{transport: vaneTransportTCP, scene: vaneSceneMedia, targetScope: fmt.Sprintf("fl-%04d", index), port: 443}
		group.targetFailures[vaneTargetFailureKey{target: failureKey, member: lease}] = vaneTargetFailureState{
			streak: 1, blockUntil: clock.Now().Add(-time.Minute), lastFailureAt: clock.Now().Add(-time.Duration(index) * time.Second),
		}
		handoffKey := vaneTargetKey{transport: vaneTransportTCP, scene: vaneSceneMedia, targetScope: fmt.Sprintf("ho-%04d", index), port: 443}
		group.targetHandoffs[handoffKey] = vaneHandoffLease{
			id: uint64(index), from: lease, to: lease, expiresAt: clock.Now().Add(time.Hour), updatedAt: clock.Now().Add(-time.Duration(index) * time.Second),
		}
		preferenceKey := vaneTargetKey{transport: vaneTransportTCP, scene: vaneSceneMedia, targetScope: fmt.Sprintf("pr-%04d", index), port: 443}
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
		target: vaneTargetKey{transport: vaneTransportTCP, scene: vaneSceneMedia, targetScope: "ev-0000", port: 443}, member: lease,
	}]
	require.True(t, newestKept, "the newest evidence must survive trimming")
	group.mu.Unlock()
	_ = metadata
}

func TestVaneTargetSettleRejectsForeignAndExpiredTokens(t *testing.T) {
	group, _, _, beta, metadata := newTargetGroupForTest(t)
	plan := prepareTargetHandoffForTest(t, group, metadata, beta)
	require.Empty(t, group.commitTargetHandoff(plan))
	decision := group.pickDecision(metadata, vaneTransportTCP, false, true)
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

func TestVaneRacingConfigRejectsFragmentAndOverflow(t *testing.T) {
	fallback := newVaneTestProxy("fallback", true, false)
	_, err := NewVane(GroupCommonOption{Name: "vane"}, VaneOption{Racing: "on", RacingURL: "https://example.com/file#frag"}, fallback, nil)
	require.Error(t, err)
	_, err = NewVane(GroupCommonOption{Name: "vane"}, VaneOption{Racing: "on", RacingBudgetMBHour: int64(^uint64(0)>>1)/(1024*1024) + 1}, fallback, nil)
	require.Error(t, err)
}

func TestVaneRacingCloseIsIdempotent(t *testing.T) {
	group, _ := newVaneGroupForTest(newVaneConnTestClock(), 10, time.Hour, newVaneTestProxy("alpha", true, true))
	require.NoError(t, group.Close())
	require.NoError(t, group.Close())
	require.True(t, group.racingRuntime.closed)
}

func TestVaneRaceRejectsStaleGenerationBeforeProbing(t *testing.T) {
	group, _, _, _, _ := newVaneRacingEvidenceGroup(t)
	var probes int
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		probes++
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 100_000_000, capHit: true}
	}
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	request.generation = group.learningGeneration - 1
	called := false
	scheduled, reason := group.scheduleMediaRace(request, func(vaneRaceResult) { called = true })
	require.True(t, scheduled, reason)
	waitVaneRaceIdle(t, group)
	require.False(t, called)
	require.Zero(t, probes)
	require.Positive(t, group.VaneDiagnostics().Counters.RaceStaleGeneration)

	// A stale race must not suppress the next race for this target: the very
	// next schedule with a current generation goes through.
	fresh := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	scheduled, reason = group.scheduleMediaRace(fresh, func(vaneRaceResult) {})
	require.True(t, scheduled, reason)
	waitVaneRaceIdle(t, group)
}

func TestVaneRaceNoWinnerStillSuppresses(t *testing.T) {
	group, _, _, _, _ := newVaneRacingEvidenceGroup(t)
	var probes int
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		probes++
		return vaneProbeResult{reason: "tls-error"}
	}
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	scheduled, reason := group.scheduleMediaRace(request, func(vaneRaceResult) {
		t.Fatal("a race without a qualified challenger must not produce a winner")
	})
	require.True(t, scheduled, reason)
	waitVaneRaceIdle(t, group)
	require.Positive(t, probes)
	require.Positive(t, group.VaneDiagnostics().Counters.RaceNoWinner)

	// A genuine no-winner result still installs the suppression window.
	scheduled, reason = group.scheduleMediaRace(request, func(vaneRaceResult) {})
	require.False(t, scheduled)
	require.Equal(t, "no-winner-cooldown", reason)
}

func TestVaneRaceSnapshotWithoutChallengers(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	configureVaneRacingForTest(t, group, vaneRacingOn)
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	candidates, reason := group.snapshotRaceCandidates(request)
	require.Empty(t, candidates)
	require.Equal(t, "no-challenger", reason)
}

func TestVaneRaceSnapshotBlockedCandidates(t *testing.T) {
	t.Run("media slow cooldown extends the block deadline", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		configureVaneRacingForTest(t, group, vaneRacingOn)
		request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		group.mu.Lock()
		lease := group.memberLeaseLocked(beta.Name(), beta.identity)
		failure := group.recordTargetFailureLocked(request.targetKey, lease, clock.Now())
		cooldown := clock.Now().Add(2 * time.Hour)
		group.mediaSlowCooldowns[vaneMediaCandidateKey{
			vaneMediaTargetKey: request.mediaKey, candidate: beta.Name(), identity: beta.identity,
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

func TestVaneRaceCandidateOrderingTieBreaks(t *testing.T) {
	group, clock, _, beta, gamma := newVaneRacingEvidenceGroup(t)
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	group.mu.Lock()
	betaLease := group.memberLeaseLocked(beta.Name(), beta.identity)
	gammaLease := group.memberLeaseLocked(gamma.Name(), gamma.identity)
	group.mu.Unlock()
	// Two fresh target proofs with different rates: the faster one must lead.
	group.recordTargetEvidence(request.targetKey, betaLease, 3_000_000)
	group.recordTargetEvidence(request.targetKey, gammaLease, 6_000_000)
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
	otherKey.targetKey = vaneTargetKey{transport: vaneTransportTCP, scene: vaneSceneMedia, targetScope: "googlevideo.com", port: 8443}
	otherKey.mediaKey = vaneMediaTargetKey{target: "googlevideo.com", port: 8443}
	candidates, reason = group.snapshotRaceCandidates(otherKey)
	require.Empty(t, reason)
	require.Equal(t, "gamma", candidates[0].member.name)
	require.True(t, candidates[0].capFresh)
	require.False(t, candidates[0].targetFresh)
}

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

func TestVaneRaceBudgetDeniedStopsProbing(t *testing.T) {
	group, _, _, _, _ := newVaneRacingEvidenceGroup(t)
	group.racing.budgetBytesHour = vaneRacingMinimumReservation - 1
	var probes int32
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		probes++
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 100_000_000, capHit: true}
	}
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	scheduled, reason := group.scheduleMediaRace(request, func(vaneRaceResult) { t.Fatal("a denied budget must not produce a winner") })
	require.True(t, scheduled, reason)
	waitVaneRaceIdle(t, group)
	require.Zero(t, probes)
	require.Positive(t, group.VaneDiagnostics().Counters.RaceBudgetDenied)
}

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
	decision := group.pickDecision(metadata, vaneTransportTCP, false, true)
	require.NotNil(t, decision.handoff)
	id := decision.handoff.id
	group.settleTargetHandoff(decision.handoff, decision.handoff.toLease, vaneThroughputObservation{
		BitsPerSecond: 40_000_000, TotalBytes: 24 * 1024 * 1024, Age: 3 * time.Second,
	})

	kinds := make(map[string]int)
	for _, event := range group.VaneDiagnostics().RecentEvents {
		if event.HandoffID == id {
			kinds[event.Kind]++
		}
	}
	require.Equal(t, 1, kinds["handoff-committed"])
	require.Equal(t, 1, kinds["handoff-improved"])

	group.failTargetHandoff(decision.handoff, "test-failure", false)
	for _, event := range group.VaneDiagnostics().RecentEvents {
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
		require.Equal(t, len(first.RecentEvents), len(repeated.RecentEvents))
	}
	group.mu.Lock()
	require.Equal(t, handoffs, len(group.targetHandoffs))
	require.Equal(t, preferences, len(group.targetPreferences))
	require.Equal(t, evidence, len(group.targetEvidence))
	group.mu.Unlock()
	require.Equal(t, "beta", group.pickDecision(metadata, vaneTransportTCP, false, false).proxy.Name(),
		"reads must not consume the handoff token or change the preferred member")
}

// RACE-DIAG-003: racing counters survive a reload and the event ring stays bounded.
func TestVaneRacingCountersPersistAndRingStaysBounded(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneDiagnosticsTestStore()
	diagnostics := newVaneDiagnostics("vane-race", clock, store)
	diagnostics.persistInterval = 10 * time.Millisecond
	diagnostics.record(vaneDiagnosticRecord{kind: "race-budget-denied", target: "rr.googlevideo.com", bucket: "googlevideo.com", port: 443})
	for index := 0; index < vaneDiagnosticsRecentEventLimit+40; index++ {
		diagnostics.record(vaneDiagnosticRecord{kind: "race-no-winner", reason: fmt.Sprintf("reason-%02d", index), target: "rr.googlevideo.com", bucket: "googlevideo.com", port: 443})
	}
	diagnostics.record(vaneDiagnosticRecord{kind: "race-no-winner", reason: "stale-generation", target: "rr.googlevideo.com", bucket: "googlevideo.com", port: 443})
	require.Eventually(t, func() bool { return store.writeCount() > 0 }, time.Second, time.Millisecond)
	diagnostics.waitPersistence()

	restored := newVaneDiagnostics("vane-race", clock, store).snapshot()
	require.Equal(t, uint64(1), restored.Counters.RaceBudgetDenied)
	require.Equal(t, uint64(vaneDiagnosticsRecentEventLimit+41), restored.Counters.RaceNoWinner)
	require.Equal(t, uint64(1), restored.Counters.RaceStaleGeneration)
	require.LessOrEqual(t, len(restored.RecentEvents), vaneDiagnosticsRecentEventLimit)
	require.Equal(t, "stale-generation", restored.RecentEvents[len(restored.RecentEvents)-1].Reason,
		"the newest event must survive ring rotation")
}

type vaneBlockingDialProxy struct {
	*vaneTestProxy
}

func (p *vaneBlockingDialProxy) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
