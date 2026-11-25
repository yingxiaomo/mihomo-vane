package outboundgroup

import (
	"fmt"
	"net/url"
	"sort"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func prepareTargetHandoffForTest(t *testing.T, group *Vane, metadata *C.Metadata, challenger C.Proxy) vaneReconnectPlan {
	t.Helper()
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, "alpha", decision.proxy.Name())
	scopeKey := group.targetScopeKey(metadata.Host, metadata.DstPort)
	targetKey, ok := group.targetScopeForKey(metadata.Host, metadata.DstPort)
	require.True(t, ok)
	// CHAIN-01: commit now requires fresh challenger evidence. Seed the
	// challenger's node evidence so tests that exercise other commit paths
	// (leases, feedback, pruning) are not vetoed by the evidence check.
	now := group.clock.Now()
	group.mu.Lock()
	group.learning.mu.Lock()
	require.NotNil(t, group.ensureProxyNodeLocked(challenger, now))
	group.nodeControls[challenger.Name()].recentTCPThroughput = vaneRecentThroughput{
		bitsPerSecond: 12_000_000, observedAt: now,
	}
	group.learning.mu.Unlock()
	group.mu.Unlock()
	return vaneReconnectPlan{
		targetKey:          scopeKey,
		targetStateKey:     targetKey,
		target:             metadata.Host,
		port:               metadata.DstPort,
		current:            decision.proxy.Name(),
		identity:           decision.identity,
		nodeEpoch:          decision.nodeEpoch,
		challenger:         challenger.Name(),
		challengerIdentity: vaneProxyPersistentIdentity(challenger),
		generation:         group.learningGeneration,
		currentBPS:         1_000_000,
		preparedAt:         group.clock.Now(),
		totalBytes:         4 * 1024 * 1024,
		age:                20 * time.Second,
		lowWindows:         3,
	}
}

func newTargetGroupForTest(t *testing.T) (*Vane, *vaneConnTestClock, *vaneTestProxy, *vaneTestProxy, *C.Metadata) {
	t.Helper()
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com", "DOMAIN-SUFFIX,interactive.example")
	configureVaneRacingForTest(t, group, vaneRacingOn)
	metadata := &C.Metadata{Host: "rr1.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	return group, clock, alpha, beta, metadata
}

// TOKEN-ID-001: baseline-derived handoff IDs must live far above the race task
// ID space. Before the dedicated baseline counter, a commit without a race
// task ID derived its ID from the diagnostics Sequence — small numbers on a
// fresh group, exactly where race task IDs (nextTaskID counts up from 1) live
// — so a stale race settlement carrying the same task ID and member could be
// accepted against a lease it never created, feeding the preference judgment
// the race's previousBPS.
func TestVaneBaselineTokenIDNeverCollidesWithRaceTaskID(t *testing.T) {
	t.Run("baseline lease ids stay outside the race task space", func(t *testing.T) {
		group, _, _, beta, metadata := newTargetGroupForTest(t)
		plan := prepareTargetHandoffForTest(t, group, metadata, beta)
		require.Zero(t, plan.raceID, "a plan without a race task ID takes the baseline derivation")
		require.Empty(t, group.commitTargetHandoff(plan))
		decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
		require.NotNil(t, decision.handoff)
		require.Greater(t, decision.handoff.id, vaneBaselineTokenIDBase,
			"a Sequence-derived ID would sit inside the race task ID space (1, 2, 3, ...)")

		// A second commit on another port: strictly increasing IDs from the
		// same counter, still far from every race task ID.
		otherPort := *metadata
		otherPort.DstPort = 8443
		second := prepareTargetHandoffForTest(t, group, &otherPort, beta)
		require.Empty(t, group.commitTargetHandoff(second))
		secondDecision := group.pickDecision(t.Context(), &otherPort, vaneTransportTCP, false, true)
		require.NotNil(t, secondDecision.handoff)
		require.Greater(t, secondDecision.handoff.id, decision.handoff.id, "baseline IDs must be strictly increasing")
	})

	t.Run("stale race settlement cannot claim a baseline lease", func(t *testing.T) {
		group, _, _, beta, metadata := newTargetGroupForTest(t)
		plan := prepareTargetHandoffForTest(t, group, metadata, beta)
		require.Empty(t, group.commitTargetHandoff(plan))
		decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
		require.NotNil(t, decision.handoff)

		// Task ID 1 is what the very first race on a fresh group carries; the
		// member matches the lease on purpose, so only the ID must reject it.
		stale := *decision.handoff
		stale.id = 1
		stale.previousBPS = 50_000_000
		group.settleTargetHandoff(&stale, decision.handoff.toLease, vaneThroughputObservation{
			BitsPerSecond: 40_000_000, TotalBytes: 24 * 1024 * 1024, Age: 3 * time.Second,
		})
		targetKey, ok := group.targetScopeForKey(metadata.Host, metadata.DstPort)
		require.True(t, ok)
		group.mu.Lock()
		lease, alive := group.targetHandoffs[targetKey]
		require.True(t, alive, "a mismatched settlement must not consume the lease")
		require.Equal(t, decision.handoff.id, lease.id)
		require.Empty(t, group.targetPreferences, "no preference may form from the wrong previousBPS")
		group.mu.Unlock()
		require.Zero(t, group.VaneDiagnostics().Counters.HandoffImproved)

		// The lease's own token still settles and judges improvement by the
		// previousBPS it was created with.
		group.settleTargetHandoff(decision.handoff, decision.handoff.toLease, vaneThroughputObservation{
			BitsPerSecond: 40_000_000, TotalBytes: 24 * 1024 * 1024, Age: 3 * time.Second,
		})
		group.mu.Lock()
		require.Empty(t, group.targetHandoffs[targetKey], "the matched settlement consumes the lease")
		require.NotEmpty(t, group.targetPreferences)
		group.mu.Unlock()
		require.Positive(t, group.VaneDiagnostics().Counters.HandoffImproved)
	})

	t.Run("race-supplied task id still owns its lease", func(t *testing.T) {
		group, _, _, beta, metadata := newTargetGroupForTest(t)
		plan := prepareTargetHandoffForTest(t, group, metadata, beta)
		plan.raceID = 3
		require.Empty(t, group.commitTargetHandoff(plan))
		decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
		require.NotNil(t, decision.handoff)
		require.Equal(t, uint64(3), decision.handoff.id, "a caller-supplied race task ID must win unchanged")
		group.settleTargetHandoff(decision.handoff, decision.handoff.toLease, vaneThroughputObservation{
			BitsPerSecond: 40_000_000, TotalBytes: 24 * 1024 * 1024, Age: 3 * time.Second,
		})
		require.Positive(t, group.VaneDiagnostics().Counters.HandoffImproved)
	})
}

// TARGET-LEASE-001 + TARGET-SCOPE-001: lease scope isolation and single-outcome tokens.
func TestVaneTargetHandoffLeaseScopeAndSingleOutcomeToken(t *testing.T) {
	group, _, _, beta, metadata := newTargetGroupForTest(t)
	plan := prepareTargetHandoffForTest(t, group, metadata, beta)
	require.Empty(t, group.commitTargetHandoff(plan))

	first := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, "beta", first.proxy.Name())
	require.NotNil(t, first.handoff)
	second := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.Equal(t, "beta", second.proxy.Name(), "TTL-related concurrent connections must still prefer the handoff member")
	require.Nil(t, second.handoff, "only the first matching reconnect owns the outcome token")

	otherPort := *metadata
	otherPort.DstPort = 8443
	require.Equal(t, "alpha", group.pickDecision(t.Context(), &otherPort, vaneTransportTCP, false, true).proxy.Name())
	otherFamily := *metadata
	otherFamily.Host = "cdn.other.example"
	require.Equal(t, "alpha", group.pickDecision(t.Context(), &otherFamily, vaneTransportTCP, false, true).proxy.Name())
	interactive := &C.Metadata{Host: "interactive.example", DstPort: 443, NetWork: C.TCP}
	require.Equal(t, "alpha", group.pickDecision(t.Context(), interactive, vaneTransportTCP, false, true).proxy.Name())
}

// TARGET-FEEDBACK-001: preference forms only after real improvement.
func TestVaneTargetFeedbackCreatesPreferenceOnlyAfterImprovement(t *testing.T) {
	group, _, _, beta, metadata := newTargetGroupForTest(t)
	plan := prepareTargetHandoffForTest(t, group, metadata, beta)
	require.Empty(t, group.commitTargetHandoff(plan))
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.NotNil(t, decision.handoff)
	flow := newVaneFlow(group, decision.proxy.Name(), metadata, decision.handoff)
	flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
	sample := vaneThroughputObservation{BitsPerSecond: 5_000_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second}
	require.Nil(t, flow.observe(sample))

	key, _ := group.targetScopeForKey(metadata.Host, metadata.DstPort)
	group.mu.Lock()
	preference, preferred := group.targetPreferences[key]
	_, leaseStillPresent := group.targetHandoffs[key]
	group.mu.Unlock()
	require.True(t, preferred)
	require.Equal(t, "beta", preference.to.name)
	require.False(t, leaseStillPresent)
	require.Equal(t, "beta", group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true).proxy.Name())
	require.Equal(t, uint64(1), group.VaneDiagnostics().Counters.HandoffImproved)
}

// TARGET-COOLDOWN-003 + TARGET-FEEDBACK-001: no-gain uses slow cooldown, never hard failure.
func TestVaneTargetNoGainUsesSlowCooldownWithoutHardFailure(t *testing.T) {
	group, _, _, beta, metadata := newTargetGroupForTest(t)
	plan := prepareTargetHandoffForTest(t, group, metadata, beta)
	require.Empty(t, group.commitTargetHandoff(plan))
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	flow := newVaneFlow(group, decision.proxy.Name(), metadata, decision.handoff)
	flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
	flow.observe(vaneThroughputObservation{BitsPerSecond: 500_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second})

	key, _ := group.targetScopeForKey(metadata.Host, metadata.DstPort)
	member := vaneMemberLease{name: decision.proxy.Name(), identity: decision.identity, epoch: decision.nodeEpoch}
	group.mu.Lock()
	_, preferred := group.targetPreferences[key]
	// §A may leave an observation-only record here (the capability sample);
	// a hard failure means a failure streak or an active block, never the
	// observation fields.
	state, hasRecord := group.targetFailures[vaneTargetFailureKey{target: key, member: member}]
	hardFailed := hasRecord && (state.streak > 0 || state.blockUntil.After(group.clock.Now()))
	slowUntil := group.slowCooldowns[vaneCandidateKey{
		vaneFlowKey: group.targetScopeKey(metadata.Host, metadata.DstPort), candidate: member.name, identity: member.identity,
	}]
	group.mu.Unlock()
	require.False(t, preferred)
	require.False(t, hardFailed)
	require.True(t, slowUntil.After(group.clock.Now()))
	require.Equal(t, uint64(1), group.VaneDiagnostics().Counters.HandoffNoGain)
}

// TARGET-FEEDBACK-001: ordinary success only refreshes an existing preference.
func TestVaneTargetOrdinarySuccessOnlyRefreshesExistingPreference(t *testing.T) {
	group, clock, _, beta, metadata := newTargetGroupForTest(t)
	key, _ := group.targetScopeForKey(metadata.Host, metadata.DstPort)
	group.mu.Lock()
	betaLease := group.memberLeaseLocked(beta.Name(), beta.identity)
	group.mu.Unlock()
	group.refreshTargetPreference(key, betaLease, 5_000_000)
	group.mu.Lock()
	require.Empty(t, group.targetPreferences, "ordinary success cannot create a preference")
	group.targetPreferences[key] = vaneTargetPreference{to: betaLease, expiresAt: clock.Now().Add(time.Minute), updatedAt: clock.Now()}
	before := group.targetPreferences[key].expiresAt
	group.mu.Unlock()

	clock.Advance(10 * time.Second)
	group.refreshTargetPreference(key, betaLease, 5_000_000)
	group.mu.Lock()
	after := group.targetPreferences[key].expiresAt
	group.mu.Unlock()
	require.True(t, after.After(before))
}

// TARGET-COOLDOWN-001 + TARGET-COOLDOWN-002: progression plus expiry-vs-success reset.
func TestVaneTargetCooldownProgressionExpiryAndSuccessReset(t *testing.T) {
	group, clock, _, beta, metadata := newTargetGroupForTest(t)
	key, _ := group.targetScopeForKey(metadata.Host, metadata.DstPort)
	group.mu.Lock()
	member := group.memberLeaseLocked(beta.Name(), beta.identity)
	group.mu.Unlock()

	for index, expected := range vaneTargetFailureBackoff {
		group.mu.Lock()
		state := group.recordTargetFailureLocked(key, member, clock.Now())
		group.mu.Unlock()
		require.Equal(t, uint8(index+1), state.streak)
		require.Equal(t, expected, state.blockUntil.Sub(clock.Now()))
		clock.Advance(expected + time.Second)
		group.mu.Lock()
		_, blocked := group.targetMemberBlockedLocked(key, member, clock.Now())
		persisted := group.targetFailures[vaneTargetFailureKey{target: key, member: member}]
		group.mu.Unlock()
		require.False(t, blocked)
		require.Equal(t, uint8(index+1), persisted.streak, "block expiry must not erase the failure streak")
	}
	group.mu.Lock()
	state := group.recordTargetFailureLocked(key, member, clock.Now())
	require.Equal(t, uint8(len(vaneTargetFailureBackoff)), state.streak, "backoff must cap at 15 minutes")
	group.clearTargetFailureLocked(key, member)
	_, exists := group.targetFailures[vaneTargetFailureKey{target: key, member: member}]
	group.mu.Unlock()
	require.False(t, exists, "a proven target success clears the streak")
}

// TARGET-BOUND-001: failure state rejects replacements and stays bounded.
func TestVaneTargetFailureRejectsReplacementAndBoundsState(t *testing.T) {
	group, clock, alpha, beta, metadata := newTargetGroupForTest(t)
	_, provider := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	_ = provider
	key, _ := group.targetScopeForKey(metadata.Host, metadata.DstPort)
	group.mu.Lock()
	oldLease := group.memberLeaseLocked(beta.Name(), beta.identity)
	group.targetPreferences[key] = vaneTargetPreference{to: oldLease, expiresAt: clock.Now().Add(time.Hour), updatedAt: clock.Now()}
	group.mu.Unlock()

	newBeta := newVaneTestProxy("beta", true, true)
	newBeta.identity = "beta-new"
	group.refreshNodeIdentities([]C.Proxy{alpha, newBeta})
	group.mu.Lock()
	group.pruneTargetStateLocked(clock.Now())
	_, preferred := group.targetPreferences[key]
	group.mu.Unlock()
	require.False(t, preferred)

	group.mu.Lock()
	newLease := group.memberLeaseLocked(newBeta.Name(), newBeta.identity)
	for index := 0; index < vaneTargetStateLimit+10; index++ {
		target := vaneTargetKey{transport: vaneTransportTCP, targetScope: fmt.Sprintf("bucket-%04d", index), port: 443}
		group.targetPreferences[target] = vaneTargetPreference{to: newLease, expiresAt: clock.Now().Add(time.Hour), updatedAt: clock.Now().Add(time.Duration(index) * time.Millisecond)}
	}
	group.pruneTargetStateLocked(clock.Now())
	count := len(group.targetPreferences)
	group.mu.Unlock()
	require.LessOrEqual(t, count, vaneTargetStateLimit)
}

// TARGET-LEASE-001 + RACE-ATOMIC-001: failure and discard contracts clean up leases.
func TestVaneTargetHandoffFailureAndDiscardContracts(t *testing.T) {
	t.Run("nil token and empty scope are no-ops", func(t *testing.T) {
		group, _, _, _, _ := newTargetGroupForTest(t)
		group.failTargetHandoff(nil, "nil-token", true)
		group.failTargetHandoff(&vaneHandoffToken{}, "empty-scope", true)
		group.discardTargetHandoff(nil)
		group.discardTargetHandoff(&vaneHandoffToken{})
		group.mu.Lock()
		require.Empty(t, group.targetHandoffs, "no-op calls must not create state")
		group.mu.Unlock()
	})

	t.Run("stale id rejected by cas", func(t *testing.T) {
		group, _, _, beta, metadata := newTargetGroupForTest(t)
		plan := prepareTargetHandoffForTest(t, group, metadata, beta)
		require.Empty(t, group.commitTargetHandoff(plan))
		decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
		require.NotNil(t, decision.handoff)
		key := decision.handoff.targetKey
		stale := *decision.handoff
		stale.id = decision.handoff.id + 999
		group.failTargetHandoff(&stale, "stale-id", true)
		group.mu.Lock()
		_, leasePresent := group.targetHandoffs[key]
		group.mu.Unlock()
		require.True(t, leasePresent, "stale id must not remove the active lease")
	})

	t.Run("hard failure removes lease and preference and records failure", func(t *testing.T) {
		group, _, _, beta, metadata := newTargetGroupForTest(t)
		plan := prepareTargetHandoffForTest(t, group, metadata, beta)
		require.Empty(t, group.commitTargetHandoff(plan))
		decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
		require.NotNil(t, decision.handoff)
		key := decision.handoff.targetKey
		group.mu.Lock()
		group.targetPreferences[key] = vaneTargetPreference{to: vaneMemberLease{name: "beta", identity: vaneProxyPersistentIdentity(beta), epoch: decision.nodeEpoch}, updatedAt: group.clock.Now()}
		group.mu.Unlock()
		failedBefore := group.VaneDiagnostics().Counters.HandoffFailed
		group.failTargetHandoff(decision.handoff, "challenger-dial-failed", true)
		group.mu.Lock()
		_, leasePresent := group.targetHandoffs[key]
		_, preferencePresent := group.targetPreferences[key]
		group.mu.Unlock()
		require.False(t, leasePresent, "hard failure must remove the lease")
		require.False(t, preferencePresent, "hard failure must remove the preference")
		require.Equal(t, failedBefore+1, group.VaneDiagnostics().Counters.HandoffFailed)
		blockedUntil, blocked := group.targetMemberBlockedLocked(key, vaneMemberLease{name: "beta", identity: vaneProxyPersistentIdentity(beta), epoch: decision.nodeEpoch}, group.clock.Now())
		require.True(t, blocked && blockedUntil.After(group.clock.Now()),
			"hard handoff failure must block the failed member for the target")
	})

	t.Run("soft failure keeps preference", func(t *testing.T) {
		group, _, _, beta, metadata := newTargetGroupForTest(t)
		plan := prepareTargetHandoffForTest(t, group, metadata, beta)
		require.Empty(t, group.commitTargetHandoff(plan))
		decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
		require.NotNil(t, decision.handoff)
		key := decision.handoff.targetKey
		group.mu.Lock()
		group.targetPreferences[key] = vaneTargetPreference{to: vaneMemberLease{name: "beta", identity: vaneProxyPersistentIdentity(beta), epoch: decision.nodeEpoch}, updatedAt: group.clock.Now()}
		group.mu.Unlock()
		failedBefore := group.VaneDiagnostics().Counters.HandoffFailed
		group.failTargetHandoff(decision.handoff, "no-gain", false)
		group.mu.Lock()
		_, leasePresent := group.targetHandoffs[key]
		_, preferencePresent := group.targetPreferences[key]
		group.mu.Unlock()
		require.False(t, leasePresent, "failure must remove the lease")
		require.False(t, preferencePresent, "no-gain must not keep a preference (plan §2.8)")
		require.Equal(t, failedBefore+1, group.VaneDiagnostics().Counters.HandoffFailed)
		_, blocked := group.targetMemberBlockedLocked(key, vaneMemberLease{name: "beta", identity: vaneProxyPersistentIdentity(beta), epoch: decision.nodeEpoch}, group.clock.Now())
		require.False(t, blocked, "soft (no-gain) failure must not record a hard-failure streak — slow cooldown governs instead")
	})

	t.Run("discard removes lease only", func(t *testing.T) {
		group, _, _, beta, metadata := newTargetGroupForTest(t)
		plan := prepareTargetHandoffForTest(t, group, metadata, beta)
		require.Empty(t, group.commitTargetHandoff(plan))
		decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
		require.NotNil(t, decision.handoff)
		key := decision.handoff.targetKey
		group.discardTargetHandoff(decision.handoff)
		group.mu.Lock()
		group.targetPreferences[key] = vaneTargetPreference{to: vaneMemberLease{name: "beta", identity: vaneProxyPersistentIdentity(beta), epoch: decision.nodeEpoch}, updatedAt: group.clock.Now()}
		group.mu.Unlock()
		group.mu.Lock()
		_, leasePresent := group.targetHandoffs[key]
		_, preferencePresent := group.targetPreferences[key]
		group.mu.Unlock()
		require.False(t, leasePresent, "discard must remove the lease")
		require.True(t, preferencePresent, "discard must remove the lease only and leave the preference untouched")
	})
}

// TARGET-BOUND-001: target state prune keeps the maps bounded.
func TestVaneTargetStatePruneAndCapabilityWrapper(t *testing.T) {
	group, _, _, beta, metadata := newTargetGroupForTest(t)
	plan := prepareTargetHandoffForTest(t, group, metadata, beta)
	require.Empty(t, group.commitTargetHandoff(plan))
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.NotNil(t, decision.handoff)
	key := decision.handoff.targetKey

	lease := vaneMemberLease{name: "beta", identity: vaneProxyPersistentIdentity(beta), epoch: decision.nodeEpoch}
	staleLease := vaneMemberLease{name: "beta", identity: vaneProxyPersistentIdentity(beta), epoch: decision.nodeEpoch + 99}
	now := group.clock.Now()

	group.mu.Lock()
	// 手工布置四类状态：新鲜 / 过期 / 身份代不匹配
	group.targetHandoffs[key] = vaneHandoffLease{id: decision.handoff.id + 50, key: key, from: lease, to: lease, expiresAt: now.Add(time.Minute), updatedAt: now}
	group.targetPreferences[key] = vaneTargetPreference{to: lease, expiresAt: now.Add(time.Minute), updatedAt: now}
	group.mu.Unlock()

	t.Run("prune keeps fresh and valid state", func(t *testing.T) {
		group.pruneTargetStateLocked(now)
		group.mu.Lock()
		_, handoffKept := group.targetHandoffs[key]
		_, preferenceKept := group.targetPreferences[key]
		group.mu.Unlock()
		require.True(t, handoffKept, "fresh valid lease must survive pruning")
		require.True(t, preferenceKept, "fresh valid preference must survive pruning")
	})

	t.Run("prune removes expired state", func(t *testing.T) {
		group.mu.Lock()
		group.targetHandoffs[key] = vaneHandoffLease{id: 999, key: key, from: lease, to: lease, expiresAt: now.Add(-time.Minute), updatedAt: now}
		group.targetPreferences[key] = vaneTargetPreference{to: lease, expiresAt: now.Add(-time.Minute), updatedAt: now}
		group.pruneTargetStateLocked(now)
		_, handoffKept := group.targetHandoffs[key]
		_, preferenceKept := group.targetPreferences[key]
		group.mu.Unlock()
		require.False(t, handoffKept, "expired lease must be pruned")
		require.False(t, preferenceKept, "expired preference must be pruned")
	})

	t.Run("prune removes stale identity epoch", func(t *testing.T) {
		group.mu.Lock()
		group.targetHandoffs[key] = vaneHandoffLease{id: 998, key: key, from: lease, to: staleLease, expiresAt: now.Add(time.Minute), updatedAt: now}
		group.targetPreferences[key] = vaneTargetPreference{to: staleLease, expiresAt: now.Add(time.Minute), updatedAt: now}
		group.pruneTargetStateLocked(now)
		_, handoffKept := group.targetHandoffs[key]
		_, preferenceKept := group.targetPreferences[key]
		group.mu.Unlock()
		require.False(t, handoffKept, "stale identity epoch lease must be pruned")
		require.False(t, preferenceKept, "stale identity epoch preference must be pruned")
	})

	t.Run("capability wrapper delegates with default tls", func(t *testing.T) {
		proxy := beta
		endpoint := &url.URL{Scheme: "https", Host: "speed.cloudflare.com", Path: "/__down", RawQuery: "bytes=65536"}
		result := probeVaneCapability(t.Context(), proxy, endpoint, 64*1024)
		// 真实外网可达性不作为单测断言——只验证 wrapper 委托并返回结构化结果
		require.NotEmpty(t, result.reason, "wrapper must return a structured result")
	})
}

// TARGET-BOUND-001: prune LRU and evidence branches stay bounded.
func TestVaneTargetPruneLRUAndEvidenceBranches(t *testing.T) {
	group, _, _, beta, metadata := newTargetGroupForTest(t)
	plan := prepareTargetHandoffForTest(t, group, metadata, beta)
	require.Empty(t, group.commitTargetHandoff(plan))
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	now := group.clock.Now()

	group.mu.Lock()
	// 灌满 evidence / failures 超 1024 上限（全部新鲜，只触发 LRU 不触发过期）
	for i := 0; i < vaneTargetStateLimit+5; i++ {
		member := vaneMemberLease{name: fmt.Sprintf("e%d", i), identity: fmt.Sprintf("ei%d", i), epoch: uint64(i)}
		eKey := vaneTargetEvidenceKey{target: vaneTargetKey{transport: vaneTransportTCP, targetScope: fmt.Sprintf("s%d.example", i), port: 443}, member: member}
		group.targetEvidence[eKey] = vaneTargetEvidence{observedAt: now.Add(-time.Duration(i) * time.Millisecond)}
		fKey := vaneTargetFailureKey{target: vaneTargetKey{transport: vaneTransportTCP, targetScope: fmt.Sprintf("f%d.example", i), port: 443}, member: member}
		group.targetFailures[fKey] = vaneTargetFailureState{lastFailureAt: now.Add(-time.Duration(i) * time.Millisecond), streak: 1}
	}
	group.pruneTargetStateLocked(now)
	evidenceOver := len(group.targetEvidence) > vaneTargetStateLimit
	failuresOver := len(group.targetFailures) > vaneTargetStateLimit
	_, handoffKept := group.targetHandoffs[decision.handoff.targetKey]
	group.mu.Unlock()
	require.False(t, evidenceOver, "evidence map must be trimmed to the limit")
	require.False(t, failuresOver, "failures map must be trimmed to the limit")
	require.True(t, handoffKept, "active handoff must survive prune")

	// 身份失配清理分支：旧 epoch 的 evidence/failures 被清
	group.mu.Lock()
	oldMember := vaneMemberLease{name: "beta", identity: vaneProxyPersistentIdentity(beta), epoch: decision.nodeEpoch + 77}
	oldEKey := vaneTargetEvidenceKey{target: vaneTargetKey{transport: vaneTransportTCP, targetScope: "old.example", port: 443}, member: oldMember}
	group.targetEvidence[oldEKey] = vaneTargetEvidence{observedAt: now}
	oldFKey := vaneTargetFailureKey{target: vaneTargetKey{transport: vaneTransportTCP, targetScope: "oldf.example", port: 443}, member: oldMember}
	group.targetFailures[oldFKey] = vaneTargetFailureState{lastFailureAt: now, streak: 2}
	group.pruneTargetStateLocked(now)
	_, oldEvidence := group.targetEvidence[oldEKey]
	_, oldFailure := group.targetFailures[oldFKey]
	group.mu.Unlock()
	require.False(t, oldEvidence, "stale-epoch evidence must be pruned")
	require.False(t, oldFailure, "stale-epoch failure record must be pruned")
}

// TARGET-BOUND-001 (round3 item 8c): equal-timestamp pruning must evict the
// same entries on every run — the key text decides, never map iteration order.
func TestVaneTargetPruneEqualTimestampsIsDeterministic(t *testing.T) {
	t.Run("pruneTargetStateLocked evidence and failures", func(t *testing.T) {
		group, clock, alpha, _, _ := newVaneRacingEvidenceGroup(t)
		now := clock.Now()
		group.mu.Lock()
		defer group.mu.Unlock()
		group.ensureNodeIdentityLocked(alpha.Name(), alpha.identity, now)
		member := group.memberLeaseLocked(alpha.Name(), alpha.identity)
		scopes := func(limit int) []string {
			keys := make([]string, 0, limit)
			for index := 0; index < limit; index++ {
				keys = append(keys, fmt.Sprintf("rr%04d.googlevideo.com", index))
			}
			return keys
		}
		seed := func() {
			group.targetEvidence = make(map[vaneTargetEvidenceKey]vaneTargetEvidence)
			group.targetFailures = make(map[vaneTargetFailureKey]vaneTargetFailureState)
			for index := 0; index < vaneTargetStateLimit+8; index++ {
				key := vaneTargetKey{transport: vaneTransportTCP, targetScope: fmt.Sprintf("rr%04d.googlevideo.com", index), port: 443}
				group.targetEvidence[vaneTargetEvidenceKey{target: key, member: member}] = vaneTargetEvidence{bitsPerSecond: float64(index), observedAt: now}
				group.targetFailures[vaneTargetFailureKey{target: key, member: member}] = vaneTargetFailureState{streak: 1, lastFailureAt: now}
			}
		}
		var referenceEvidence, referenceFailures []string
		for run := 0; run < 20; run++ {
			seed()
			group.pruneTargetStateLocked(now)
			evidence := make([]string, 0, vaneTargetStateLimit)
			for key := range group.targetEvidence {
				evidence = append(evidence, key.target.targetScope)
			}
			failures := make([]string, 0, vaneTargetStateLimit)
			for key := range group.targetFailures {
				failures = append(failures, key.target.targetScope)
			}
			sort.Strings(evidence)
			sort.Strings(failures)
			require.Len(t, evidence, vaneTargetStateLimit)
			require.Len(t, failures, vaneTargetStateLimit)
			if run == 0 {
				referenceEvidence, referenceFailures = evidence, failures
				continue
			}
			require.Equal(t, referenceEvidence, evidence, "evidence eviction must be identical on every run")
			require.Equal(t, referenceFailures, failures, "failure eviction must be identical on every run")
		}
		// The tie-break evicts exactly the lexicographically smallest keys.
		evicted := scopes(8)
		for _, scope := range evicted {
			require.NotContains(t, referenceEvidence, scope, "the smallest key must be evicted first")
			require.NotContains(t, referenceFailures, scope)
		}
	})

	t.Run("trimTargetMap tie-break", func(t *testing.T) {
		now := time.Now()
		var reference []string
		for run := 0; run < 50; run++ {
			values := make(map[vaneTargetKey]int, vaneTargetStateLimit+8)
			for index := 0; index < vaneTargetStateLimit+8; index++ {
				key := vaneTargetKey{transport: vaneTransportTCP, targetScope: fmt.Sprintf("rr%04d.googlevideo.com", index), port: 443}
				values[key] = index
			}
			trimTargetMap(values, vaneTargetStateLimit, func(int) time.Time { return now })
			require.Len(t, values, vaneTargetStateLimit)
			survivors := make([]string, 0, vaneTargetStateLimit)
			for key := range values {
				survivors = append(survivors, key.targetScope)
			}
			sort.Strings(survivors)
			if run == 0 {
				reference = survivors
				continue
			}
			require.Equal(t, reference, survivors, "trim eviction must be identical on every run")
		}
	})

	t.Run("pruneCapabilitiesLocked tie-break", func(t *testing.T) {
		group, clock, _, _, _ := newVaneRacingEvidenceGroup(t)
		now := clock.Now()
		var reference []string
		for run := 0; run < 20; run++ {
			group.racingRuntime.mu.Lock()
			group.racingRuntime.capabilities = make(map[vaneMemberLease]vaneCapabilityRecord, vaneTargetStateLimit+8)
			for index := 0; index < vaneTargetStateLimit+8; index++ {
				member := vaneMemberLease{name: fmt.Sprintf("node%04d", index), identity: fmt.Sprintf("identity-node%04d", index), epoch: 1}
				group.racingRuntime.capabilities[member] = vaneCapabilityRecord{member: member, lowerBoundBPS: float64(index), observedAt: now}
			}
			group.pruneCapabilitiesLocked(now)
			survivors := make([]string, 0, vaneTargetStateLimit)
			for member := range group.racingRuntime.capabilities {
				survivors = append(survivors, member.name)
			}
			group.racingRuntime.mu.Unlock()
			sort.Strings(survivors)
			require.Len(t, survivors, vaneTargetStateLimit)
			if run == 0 {
				reference = survivors
				continue
			}
			require.Equal(t, reference, survivors, "capability eviction must be identical on every run")
		}
	})
}
