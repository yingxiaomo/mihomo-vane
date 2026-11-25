package outboundgroup

import (
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// seedVaneB2CandidateEvidence makes a challenger survive the round3 8a pool
// filter (fresh real-target evidence at or above the race bar) so these tests
// exercise the Step 3 filter rather than the evidence prefilter.
func seedVaneB2CandidateEvidence(t *testing.T, group *Vane, proxy *vaneTestProxy, bps float64) vaneMemberLease {
	t.Helper()
	group.mu.Lock()
	group.ensureProxyNodeLocked(proxy, group.clock.Now())
	member := group.memberLeaseLocked(proxy.Name(), proxy.identity)
	group.mu.Unlock()
	require.NotZero(t, member.epoch)
	key, ok := group.targetScopeForKey("rr.googlevideo.com", 443)
	require.True(t, ok)
	group.recordTargetEvidence(key, member, bps, false)
	return member
}

func newVaneB2Step3RaceRequest(t *testing.T, group *Vane) vaneRaceRequest {
	t.Helper()
	return newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
}

func seedVaneB2FailureState(t *testing.T, group *Vane, request vaneRaceRequest, member vaneMemberLease, mutate func(*vaneTargetFailureState)) {
	t.Helper()
	key := vaneTargetFailureKey{target: request.targetKey, member: member}
	group.mu.Lock()
	state := group.targetFailures[key]
	mutate(&state)
	group.targetFailures[key] = state
	group.mu.Unlock()
}

func raceCandidateNames(candidates []vaneRaceCandidate) []string {
	names := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		names = append(names, candidate.member.name)
	}
	return names
}

// B2-STEP3-001: a challenger whose smoothed loss is over the line is dropped
// from the race snapshot, the boundary and sample gates hold, a good sample
// lifts the exclusion, and the failure record itself is never written.
func TestVaneB2Step3LossExclusion(t *testing.T) {
	newGroup := func(t *testing.T) (*Vane, *vaneRaceRequest, vaneMemberLease, vaneMemberLease) {
		t.Helper()
		group, _, _, beta, gamma := newVaneRacingEvidenceGroup(t)
		request := newVaneB2Step3RaceRequest(t, group)
		betaMember := seedVaneB2CandidateEvidence(t, group, beta, 8_000_000)
		gammaMember := seedVaneB2CandidateEvidence(t, group, gamma, 8_000_000)
		return group, &request, betaMember, gammaMember
	}

	t.Run("degraded challenger is excluded", func(t *testing.T) {
		group, request, betaMember, _ := newGroup(t)
		seedVaneB2FailureState(t, group, *request, betaMember, func(state *vaneTargetFailureState) {
			state.lossEMA, state.lossSamples = 0.30, 5
		})
		candidates, reason := group.snapshotRaceCandidates(*request)
		require.Empty(t, reason)
		require.Equal(t, []string{"gamma"}, raceCandidateNames(candidates))
	})

	t.Run("exactly on the line is not degraded", func(t *testing.T) {
		group, request, betaMember, _ := newGroup(t)
		seedVaneB2FailureState(t, group, *request, betaMember, func(state *vaneTargetFailureState) {
			state.lossEMA, state.lossSamples = vaneLossDegradedThreshold, 5
		})
		candidates, reason := group.snapshotRaceCandidates(*request)
		require.Empty(t, reason)
		require.ElementsMatch(t, []string{"beta", "gamma"}, raceCandidateNames(candidates))
	})

	t.Run("no samples is never degraded", func(t *testing.T) {
		group, request, betaMember, _ := newGroup(t)
		seedVaneB2FailureState(t, group, *request, betaMember, func(state *vaneTargetFailureState) {
			state.lossEMA, state.lossSamples = 0.90, 0
		})
		candidates, reason := group.snapshotRaceCandidates(*request)
		require.Empty(t, reason)
		require.ElementsMatch(t, []string{"beta", "gamma"}, raceCandidateNames(candidates))
	})

	t.Run("a clean sample lifts the exclusion", func(t *testing.T) {
		group, request, betaMember, _ := newGroup(t)
		seedVaneB2FailureState(t, group, *request, betaMember, func(state *vaneTargetFailureState) {
			// Just over the line: one good settlement (alpha 0.4/(1+0.05*5))
			// pulls the estimate back under it.
			state.lossEMA, state.lossSamples = 0.06, 5
		})
		before, reason := group.snapshotRaceCandidates(*request)
		require.Empty(t, reason)
		require.Equal(t, []string{"gamma"}, raceCandidateNames(before), "just-over-the-line is excluded first")

		flow := newVaneFlow(group, betaMember.name, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		require.NotNil(t, flow)
		flow.identity, flow.nodeEpoch = betaMember.identity, betaMember.epoch
		group.recordB2Loss(flow, vaneConnectionCloseObservation{
			TotalReadBytes: 8 << 20, LossSupported: true, LossRate: 0,
		}, group.clock.Now())

		after, reason := group.snapshotRaceCandidates(*request)
		require.Empty(t, reason)
		require.ElementsMatch(t, []string{"beta", "gamma"}, raceCandidateNames(after), "a clean settlement must lift the exclusion")
	})

	t.Run("exclusion never writes the failure record", func(t *testing.T) {
		group, request, betaMember, _ := newGroup(t)
		old := group.clock.Now().Add(-time.Minute)
		seedVaneB2FailureState(t, group, *request, betaMember, func(state *vaneTargetFailureState) {
			state.lossEMA, state.lossSamples = 0.30, 5
			state.streak, state.lastFailureAt, state.blockUntil = 3, old, old
		})
		candidates, reason := group.snapshotRaceCandidates(*request)
		require.Empty(t, reason)
		require.Equal(t, []string{"gamma"}, raceCandidateNames(candidates))

		group.mu.Lock()
		state := group.targetFailures[vaneTargetFailureKey{target: request.targetKey, member: betaMember}]
		group.mu.Unlock()
		require.Equal(t, uint8(3), state.streak)
		require.Equal(t, old, state.lastFailureAt)
		require.Equal(t, old, state.blockUntil)
		require.Equal(t, 5, int(state.lossSamples))
	})
}

// B2-STEP3-002: a frequent staller is parked on its own 30s cooldown — an idle
// challenger wins the slot, but the earliest-expiry fallback still recovers it
// when everyone is cooling, and the failure record is never written.
func TestVaneB2Step3StallCooldown(t *testing.T) {
	newGroup := func(t *testing.T) (*Vane, *vaneRaceRequest, vaneMemberLease, vaneMemberLease) {
		t.Helper()
		group, _, _, beta, gamma := newVaneRacingEvidenceGroup(t)
		request := newVaneB2Step3RaceRequest(t, group)
		betaMember := seedVaneB2CandidateEvidence(t, group, beta, 8_000_000)
		gammaMember := seedVaneB2CandidateEvidence(t, group, gamma, 8_000_000)
		return group, &request, betaMember, gammaMember
	}
	seedStall := func(t *testing.T, group *Vane, request vaneRaceRequest, member vaneMemberLease, stalls, attempts int64) {
		t.Helper()
		seedVaneB2FailureState(t, group, request, member, func(state *vaneTargetFailureState) {
			state.suspectedStallCount, state.attemptCount = stalls, attempts
		})
	}

	t.Run("frequent staller yields to an idle challenger", func(t *testing.T) {
		group, request, betaMember, _ := newGroup(t)
		seedStall(t, group, *request, betaMember, 3, 10)
		candidates, reason := group.snapshotRaceCandidates(*request)
		require.Empty(t, reason)
		require.Equal(t, []string{"gamma"}, raceCandidateNames(candidates), "the cooled staller must not take the slot")
	})

	t.Run("a lone cooled staller is recovered by the fallback", func(t *testing.T) {
		group, _, _, beta, gamma := newVaneRacingEvidenceGroup(t)
		request := newVaneB2Step3RaceRequest(t, group)
		betaMember := seedVaneB2CandidateEvidence(t, group, beta, 8_000_000)
		gammaMember := seedVaneB2CandidateEvidence(t, group, gamma, 8_000_000)
		seedStall(t, group, request, betaMember, 3, 10)
		seedStall(t, group, request, gammaMember, 4, 10)
		now := group.clock.Now()
		candidates, reason := group.snapshotRaceCandidates(request)
		require.Empty(t, reason)
		require.Len(t, candidates, 1)
		require.True(t, candidates[0].blockUntil.Equal(now.Add(vaneStallCooldown)),
			"the earliest expiry must be the stall cooldown horizon")
	})

	t.Run("exactly on the line is not frequent", func(t *testing.T) {
		group, request, betaMember, _ := newGroup(t)
		seedStall(t, group, *request, betaMember, 2, 10)
		candidates, reason := group.snapshotRaceCandidates(*request)
		require.Empty(t, reason)
		require.ElementsMatch(t, []string{"beta", "gamma"}, raceCandidateNames(candidates))
	})

	t.Run("too few attempts is never frequent", func(t *testing.T) {
		group, request, betaMember, _ := newGroup(t)
		seedStall(t, group, *request, betaMember, 1, 2)
		candidates, reason := group.snapshotRaceCandidates(*request)
		require.Empty(t, reason)
		require.ElementsMatch(t, []string{"beta", "gamma"}, raceCandidateNames(candidates))
	})

	// B2-STEP3-005: exactly 5 attempts is where the minimum-sample gate and the
	// ratio line meet — the most easily misjudged point of the stall rule.
	t.Run("exactly five attempts above the line is frequent", func(t *testing.T) {
		group, request, betaMember, _ := newGroup(t)
		seedStall(t, group, *request, betaMember, 2, 5)
		candidates, reason := group.snapshotRaceCandidates(*request)
		require.Empty(t, reason)
		require.Equal(t, []string{"gamma"}, raceCandidateNames(candidates), "2/5=0.40 clears the line once the sample minimum is met")
	})

	t.Run("exactly five attempts on the line is not frequent", func(t *testing.T) {
		group, request, betaMember, _ := newGroup(t)
		seedStall(t, group, *request, betaMember, 1, 5)
		candidates, reason := group.snapshotRaceCandidates(*request)
		require.Empty(t, reason)
		require.ElementsMatch(t, []string{"beta", "gamma"}, raceCandidateNames(candidates), "1/5=0.20 touches the line without clearing it")
	})

	t.Run("clean settlements dilute the rate", func(t *testing.T) {
		group, request, betaMember, _ := newGroup(t)
		seedStall(t, group, *request, betaMember, 3, 10)
		require.Equal(t, []string{"gamma"}, raceCandidateNames(mustVaneRaceCandidates(t, group, *request)))

		flow := newVaneFlow(group, betaMember.name, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		require.NotNil(t, flow)
		flow.identity, flow.nodeEpoch = betaMember.identity, betaMember.epoch
		for i := 0; i < 6; i++ {
			group.recordB2Stall(flow, vaneConnectionCloseObservation{WrotePayload: true, TotalReadBytes: 4 << 20}, group.clock.Now())
		}
		candidates, reason := group.snapshotRaceCandidates(*request)
		require.Empty(t, reason)
		require.ElementsMatch(t, []string{"beta", "gamma"}, raceCandidateNames(candidates), "3/16 is under the line again")
	})

	t.Run("stall cooldown never writes the failure record", func(t *testing.T) {
		group, request, betaMember, _ := newGroup(t)
		old := group.clock.Now().Add(-time.Minute)
		seedVaneB2FailureState(t, group, *request, betaMember, func(state *vaneTargetFailureState) {
			state.suspectedStallCount, state.attemptCount = 3, 10
			state.streak, state.lastFailureAt, state.blockUntil = 2, old, old
		})
		_, reason := group.snapshotRaceCandidates(*request)
		require.Empty(t, reason)

		group.mu.Lock()
		state := group.targetFailures[vaneTargetFailureKey{target: request.targetKey, member: betaMember}]
		group.mu.Unlock()
		require.Equal(t, uint8(2), state.streak)
		require.Equal(t, old, state.lastFailureAt)
		require.Equal(t, old, state.blockUntil)
		require.Equal(t, int64(10), state.attemptCount)
	})
}

func mustVaneRaceCandidates(t *testing.T, group *Vane, request vaneRaceRequest) []vaneRaceCandidate {
	t.Helper()
	candidates, reason := group.snapshotRaceCandidates(request)
	require.Empty(t, reason)
	return candidates
}

// B2-STEP3-003: the diagnostics runtime reports how many pairs actually cross
// each guard rail, so an all-over-the-line result is visible.
func TestVaneB2Step3DiagnosticTallies(t *testing.T) {
	group, _, beta, gamma, _ := newVaneRacingEvidenceGroup(t)
	require.Zero(t, group.VaneDiagnostics().Runtime.B2LossDegradedTargets)
	require.Zero(t, group.VaneDiagnostics().Runtime.B2StallFrequentTargets)

	group.mu.Lock()
	group.ensureProxyNodeLocked(beta, group.clock.Now())
	betaMember := group.memberLeaseLocked(beta.Name(), beta.identity)
	group.ensureProxyNodeLocked(gamma, group.clock.Now())
	gammaMember := group.memberLeaseLocked(gamma.Name(), gamma.identity)
	group.mu.Unlock()

	key, ok := group.targetScopeForKey("rr.googlevideo.com", 443)
	require.True(t, ok)
	group.mu.Lock()
	group.targetFailures[vaneTargetFailureKey{target: key, member: betaMember}] = vaneTargetFailureState{lossEMA: 0.4, lossSamples: 6, attemptCount: 10, suspectedStallCount: 5}
	group.targetFailures[vaneTargetFailureKey{target: key, member: gammaMember}] = vaneTargetFailureState{lossEMA: 0.01, lossSamples: 6, attemptCount: 10, suspectedStallCount: 0}
	group.mu.Unlock()

	runtime := group.VaneDiagnostics().Runtime
	require.Equal(t, 2, runtime.B2LossTargets)
	require.Equal(t, 2, runtime.B2StallTargets)
	require.Equal(t, 1, runtime.B2LossDegradedTargets)
	require.Equal(t, 1, runtime.B2StallFrequentTargets)
}
