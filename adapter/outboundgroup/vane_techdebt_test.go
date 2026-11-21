package outboundgroup

// Batch-1 acceptance tests for the tech-debt guide (dev-vane @ 41828489):
// §A per-target capability records (CAP), §B the target tier in prepare
// (PREP-TARGET), §C evidence-ranked candidates (SORT-EVIDENCE), §D no-gain
// reconnect-cooldown release (NOGAIN), §L the demand-following trigger line
// plus the CHAIN-04 target-priority exemption (TRIGGER / TARGET-PRIORITY),
// §M the settlement absolute line (CHAIN02) and §F the halved sample gate
// (SAMPLE).

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// techdebtSeedTargetEvidence writes a fresh (or aged) target-scoped evidence
// record for member under the group locks.
func techdebtSeedTargetEvidence(t *testing.T, group *Vane, key vaneTargetKey, member vaneMemberLease, bps float64, observedAt time.Time) {
	t.Helper()
	group.mu.Lock()
	group.targetEvidence[vaneTargetEvidenceKey{target: key, member: member}] = vaneTargetEvidence{
		bitsPerSecond: bps, observedAt: observedAt,
	}
	group.mu.Unlock()
}

// techdebtSettleTargetHandoff commits a target handoff for beta, claims its
// token and settles it with sample — the full race-path settle used by the
// CAP / NOGAIN / CHAIN02 tests.
func techdebtSettleTargetHandoff(t *testing.T, group *Vane, metadata *C.Metadata, beta *vaneTestProxy, sample vaneThroughputObservation) vaneTargetKey {
	t.Helper()
	plan := prepareTargetHandoffForTest(t, group, metadata, beta)
	require.Empty(t, group.commitTargetHandoff(plan))
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.NotNil(t, decision.handoff)
	group.settleTargetHandoff(decision.handoff, decision.handoff.toLease, sample)
	key, ok := group.targetKeyForMedia(metadata.Host, metadata.DstPort)
	require.True(t, ok)
	return key
}

// §A: a large settlement folds its real-traffic sample into the (target,
// candidate) record — record-only, visible in the diagnostics tallies.
func TestVaneTargetCapabilitySamplesRecorded(t *testing.T) {
	group, _, _, beta, metadata := newTargetGroupForTest(t)
	chain01ProductionValues(t, group, 2_000_000)
	clock := group.clock

	key := techdebtSettleTargetHandoff(t, group, metadata, beta, vaneThroughputObservation{
		BitsPerSecond: 40_000_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second,
	})
	group.mu.Lock()
	lease := group.memberLeaseLocked(beta.Name(), beta.identity)
	state := group.targetFailures[vaneTargetFailureKey{target: key, member: lease}]
	group.mu.Unlock()

	// CAP-01
	require.Equal(t, 40_000_000.0, state.capBPS)
	require.Equal(t, int64(1), state.capSamples)
	require.Equal(t, clock.Now(), state.capAt)
	snapshot := group.VaneDiagnostics()
	require.Equal(t, 1, snapshot.Runtime.TargetCapabilities)
	require.Equal(t, int64(1), snapshot.Runtime.TargetCapabilitySamples)

	// CAP-04: the read side expires with capAt, never downgrading to the
	// node-level capability cache.
	group.mu.Lock()
	_, fresh := group.targetCapabilityLocked(key, lease, clock.Now())
	group.mu.Unlock()
	require.True(t, fresh)
	group.mu.Lock()
	_, expired := group.targetCapabilityLocked(key, lease, clock.Now().Add(11*time.Minute))
	group.mu.Unlock()
	require.False(t, expired, "an expired capability sample is no evidence")
}

// CAP-02: small settlements stay out of the capability record entirely.
func TestVaneTargetCapabilitySkipsSmallSettlements(t *testing.T) {
	group, _, _, beta, metadata := newTargetGroupForTest(t)
	chain01ProductionValues(t, group, 2_000_000)

	key := techdebtSettleTargetHandoff(t, group, metadata, beta, vaneThroughputObservation{
		BitsPerSecond: 40_000_000, TotalBytes: 1 * 1024 * 1024, Age: 20 * time.Second,
	})
	group.mu.Lock()
	lease := group.memberLeaseLocked(beta.Name(), beta.identity)
	state := group.targetFailures[vaneTargetFailureKey{target: key, member: lease}]
	group.mu.Unlock()
	require.Zero(t, state.capSamples)
	require.True(t, state.capAt.IsZero())
	snapshot := group.VaneDiagnostics()
	require.Zero(t, snapshot.Runtime.TargetCapabilities)
	require.Zero(t, snapshot.Runtime.TargetCapabilitySamples)
}

// CAP-03: a second large settlement updates the record to the latest sample —
// newest value wins, no averaging.
func TestVaneTargetCapabilityRecordsLatestSample(t *testing.T) {
	group, clock, _, beta, metadata := newTargetGroupForTest(t)
	chain01ProductionValues(t, group, 2_000_000)

	techdebtSettleTargetHandoff(t, group, metadata, beta, vaneThroughputObservation{
		BitsPerSecond: 40_000_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second,
	})
	// The improved settlement pinned a 10-minute preference; let it and the
	// reconnect cooldown expire so the same pair can be handed off again.
	clock.Advance(10*time.Minute + time.Minute)
	techdebtSettleTargetHandoff(t, group, metadata, beta, vaneThroughputObservation{
		BitsPerSecond: 50_000_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second,
	})

	key, _ := group.targetKeyForMedia(metadata.Host, metadata.DstPort)
	group.mu.Lock()
	lease := group.memberLeaseLocked(beta.Name(), beta.identity)
	state := group.targetFailures[vaneTargetFailureKey{target: key, member: lease}]
	group.mu.Unlock()
	require.Equal(t, int64(2), state.capSamples)
	require.Equal(t, 50_000_000.0, state.capBPS, "the latest sample wins")
	require.Equal(t, clock.Now(), state.capAt)
	snapshot := group.VaneDiagnostics()
	require.Equal(t, 1, snapshot.Runtime.TargetCapabilities)
	require.Equal(t, int64(2), snapshot.Runtime.TargetCapabilitySamples)
}

// §B: a challenger whose node-level sample expired but whose target-scoped
// evidence is fresh is admitted by the baseline prepare — the tier the racing
// path already had at commit.
func TestVanePrepareAdmitsTargetTierEvidence(t *testing.T) {
	group, clock, alpha, beta, metadata := newTargetGroupForTest(t)
	chain01ProductionValues(t, group, 2_000_000)
	suppressColdPickProbeForTest(t, group, metadata)
	group.mu.Lock()
	group.learning.mu.Lock()
	group.ensureProxyNodeLocked(alpha, clock.Now())
	group.ensureProxyNodeLocked(beta, clock.Now())
	group.learning.mu.Unlock()
	group.mu.Unlock()
	// Node sample expired, capability empty: only the target tier can admit.
	seedChain01Traffic(t, group, beta.Name(), clock.Now().Add(-11*time.Minute), 8_000_000)

	group.mu.Lock()
	key, _ := group.targetKeyForMedia(metadata.Host, metadata.DstPort)
	member := group.memberLeaseLocked(beta.Name(), beta.identity)
	group.mu.Unlock()

	// PREP-TARGET-01: fresh target evidence above the bar admits.
	techdebtSeedTargetEvidence(t, group, key, member, 12_000_000, clock.Now())
	plan, reason := chain01Prepare(t, group, metadata, alpha, 1_600_000)
	require.Empty(t, reason)
	require.Equal(t, beta.Name(), plan.challenger)
	require.False(t, plan.knownGood, "target-tier admission is not knownGood")

	// PREP-TARGET-02: fresh target evidence below the bar is no pass.
	techdebtSeedTargetEvidence(t, group, key, member, 3_000_000, clock.Now())
	plan, reason = chain01Prepare(t, group, metadata, alpha, 1_600_000)
	require.Equal(t, "no-evidence-candidate", reason)
	require.Empty(t, plan.challenger)

	// PREP-TARGET-03: expired target evidence does not count either.
	techdebtSeedTargetEvidence(t, group, key, member, 12_000_000, clock.Now().Add(-11*time.Minute))
	plan, reason = chain01Prepare(t, group, metadata, alpha, 1_600_000)
	require.Equal(t, "no-evidence-candidate", reason)
	require.Empty(t, plan.challenger)
}

// §C: admitted candidates of the same knownGood class rank by their evidence
// value before delay.
func TestVanePrepareRanksByEvidenceBeforeDelay(t *testing.T) {
	group, clock, alpha, beta, gamma, metadata := newTargetGroupForTest3(t)
	chain01ProductionValues(t, group, 2_000_000)
	suppressColdPickProbeForTest(t, group, metadata)
	group.mu.Lock()
	group.learning.mu.Lock()
	group.ensureProxyNodeLocked(alpha, clock.Now())
	group.ensureProxyNodeLocked(beta, clock.Now())
	group.ensureProxyNodeLocked(gamma, clock.Now())
	group.learning.mu.Unlock()
	group.mu.Unlock()

	// SORT-EVIDENCE-01: two capability candidates — the higher evidence wins
	// even with worse delay.
	seedChain01Capability(t, group, vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: 1}, 10_500_000, clock.Now())
	seedChain01Capability(t, group, vaneMemberLease{name: gamma.Name(), identity: gamma.identity, epoch: 1}, 12_000_000, clock.Now())
	plan, reason := chain01Prepare(t, group, metadata, alpha, 1_600_000)
	require.Empty(t, reason)
	require.Equal(t, gamma.Name(), plan.challenger, "12M must outrank 10.5M despite the worse delay")
	require.False(t, plan.knownGood)

	// SORT-EVIDENCE-02: two knownGood candidates with identical score and
	// throughput still fall through to delay (the evidence tier is a no-op).
	seedChain01Traffic(t, group, beta.Name(), clock.Now(), 12_000_000)
	seedChain01Traffic(t, group, gamma.Name(), clock.Now(), 12_000_000)
	group.racingRuntime.mu.Lock()
	delete(group.racingRuntime.capabilities, vaneMemberLease{name: beta.Name(), identity: beta.identity, epoch: 1})
	delete(group.racingRuntime.capabilities, vaneMemberLease{name: gamma.Name(), identity: gamma.identity, epoch: 1})
	group.racingRuntime.mu.Unlock()
	plan, reason = chain01Prepare(t, group, metadata, alpha, 1_600_000)
	require.Empty(t, reason)
	require.Equal(t, beta.Name(), plan.challenger, "equal knownGood evidence still ties to delay")
	require.True(t, plan.knownGood)

	// SORT-EVIDENCE-03: knownGood beats a higher-evidence non-knownGood.
	seedChain01Traffic(t, group, beta.Name(), clock.Now(), 12_000_000)
	seedChain01Traffic(t, group, gamma.Name(), clock.Now().Add(-11*time.Minute), 12_000_000)
	seedChain01Capability(t, group, vaneMemberLease{name: gamma.Name(), identity: gamma.identity, epoch: 1}, 20_000_000, clock.Now())
	plan, reason = chain01Prepare(t, group, metadata, alpha, 1_600_000)
	require.Empty(t, reason)
	require.Equal(t, beta.Name(), plan.challenger, "knownGood outranks a higher capability value")
	require.True(t, plan.knownGood)
}

// §D: a no-gain settlement releases the reconnect cooldown written at commit
// (baseline and race paths share the settle), while the slow cooldown stays.
func TestVaneNoGainReleasesReconnectCooldown(t *testing.T) {
	group, clock, alpha, beta, metadata := newTargetGroupForTest(t)
	chain01ProductionValues(t, group, 2_000_000)
	suppressColdPickProbeForTest(t, group, metadata)
	seedChain01Traffic(t, group, beta.Name(), clock.Now(), 12_000_000)

	metadataKey := group.mediaTargetKey(metadata.Host, metadata.DstPort)
	plan, reason := chain01Prepare(t, group, metadata, alpha, 1_600_000)
	require.Empty(t, reason)
	require.Equal(t, beta.Name(), plan.challenger)
	require.Empty(t, group.commitMediaReconnectDetailed(plan))

	group.mu.Lock()
	require.True(t, group.mediaReconnects[metadataKey].After(clock.Now()), "commit writes the reconnect cooldown")
	group.mu.Unlock()

	// NOGAIN-01: the settle lands on the switched-to flow (member = beta);
	// 1.5 Mbps is below required (2M) → no-gain. The reconnect cooldown is
	// released; the 30-minute slow cooldown on the candidate stays.
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.NotNil(t, decision.handoff)
	member := vaneMemberLease{name: plan.challenger, identity: plan.challengerIdentity, epoch: plan.challengerEpoch}
	group.settleTargetHandoff(decision.handoff, member, vaneThroughputObservation{
		BitsPerSecond: 1_500_000, TotalBytes: 8 * 1024 * 1024, Age: 30 * time.Second,
	})
	group.mu.Lock()
	_, reconnected := group.mediaReconnects[metadataKey]
	require.False(t, reconnected, "no-gain must release the reconnect cooldown")
	slowUntil := group.mediaSlowCooldowns[vaneMediaCandidateKey{
		vaneMediaTargetKey: metadataKey, candidate: beta.Name(), identity: beta.identity,
	}]
	group.mu.Unlock()
	require.True(t, slowUntil.After(clock.Now()), "the slow cooldown on the no-gain candidate stays")

	// NOGAIN-03 (regression): the next slow window can re-prepare without
	// hitting reconnect-cooldown. Beta itself is slow-cooled now, so the
	// snapshot comes back as no-challenger — anything but reconnect-cooldown
	// proves the release.
	plan, reason = chain01Prepare(t, group, metadata, alpha, 1_600_000)
	require.Equal(t, "no-challenger", reason, "the reconnect cooldown must be gone")
}

// NOGAIN-02: an improved settlement keeps the reconnect cooldown as the
// guard rail.
func TestVaneImprovedKeepsReconnectCooldown(t *testing.T) {
	group, clock, _, beta, metadata := newTargetGroupForTest(t)
	chain01ProductionValues(t, group, 2_000_000)
	metadataKey := group.mediaTargetKey(metadata.Host, metadata.DstPort)

	plan := prepareTargetHandoffForTest(t, group, metadata, beta)
	require.Empty(t, group.commitTargetHandoff(plan))
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.NotNil(t, decision.handoff)
	group.settleTargetHandoff(decision.handoff, decision.handoff.toLease, vaneThroughputObservation{
		BitsPerSecond: 40_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second,
	})

	group.mu.Lock()
	require.True(t, group.mediaReconnects[metadataKey].After(clock.Now()), "improved keeps the reconnect cooldown")
	group.mu.Unlock()
	require.Positive(t, group.VaneDiagnostics().Counters.HandoffImproved)
}

// §M: the improved verdict needs the sample above the 5M absolute line too —
// a relatively better but still slow node goes to no-gain instead of being
// pinned by a preference.
func TestVaneImprovedSettlementNeedsAbsoluteLine(t *testing.T) {
	// CHAIN02-01: 1.6 → 2.1 Mbps crosses required (2.0) but not 5M → no-gain.
	group, _, _, beta, metadata := newTargetGroupForTest(t)
	chain01ProductionValues(t, group, 1_000_000)
	key := techdebtSettleTargetHandoff(t, group, metadata, beta, vaneThroughputObservation{
		BitsPerSecond: 2_100_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second,
	})
	group.mu.Lock()
	_, preferred := group.targetPreferences[key]
	group.mu.Unlock()
	require.False(t, preferred, "a sub-5M node must not be pinned by a preference")
	snapshot := group.VaneDiagnostics()
	require.Equal(t, uint64(1), snapshot.Counters.HandoffNoGain)
	require.Zero(t, snapshot.Counters.HandoffImproved)

	// CHAIN02-02: 6 Mbps clears both lines → improved (regression path).
	group, _, _, beta, metadata = newTargetGroupForTest(t)
	chain01ProductionValues(t, group, 1_000_000)
	key = techdebtSettleTargetHandoff(t, group, metadata, beta, vaneThroughputObservation{
		BitsPerSecond: 6_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second,
	})
	group.mu.Lock()
	preference, preferred := group.targetPreferences[key]
	group.mu.Unlock()
	require.True(t, preferred)
	require.Equal(t, beta.Name(), preference.to.name)
	require.Equal(t, uint64(1), group.VaneDiagnostics().Counters.HandoffImproved)

	// CHAIN02-03: a 10M-demand group is a no-op for this check (required is
	// already ≥ 10M).
	group, _, _, beta, metadata = newTargetGroupForTest(t)
	chain01ProductionValues(t, group, 10_000_000)
	group.media.lowThroughputBPS = 10_000_000 // §L: the line follows demand
	key = techdebtSettleTargetHandoff(t, group, metadata, beta, vaneThroughputObservation{
		BitsPerSecond: 13_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second,
	})
	group.mu.Lock()
	_, preferred = group.targetPreferences[key]
	group.mu.Unlock()
	require.True(t, preferred, "the absolute line is a no-op above demand")
	require.Equal(t, uint64(1), group.VaneDiagnostics().Counters.HandoffImproved)

	// CHAIN02-04 (boundary): exactly 5M is inclusive.
	group, _, _, beta, metadata = newTargetGroupForTest(t)
	chain01ProductionValues(t, group, 1_000_000)
	key = techdebtSettleTargetHandoff(t, group, metadata, beta, vaneThroughputObservation{
		BitsPerSecond: 5_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second,
	})
	group.mu.Lock()
	_, preferred = group.targetPreferences[key]
	group.mu.Unlock()
	require.True(t, preferred, "5M is on the improved side of the line")
	_ = key
}

// §L: the low-window trigger line follows demand (floored at 5M). The config
// is built through newVaneMediaConfig — the production path that applies the
// raise — so mutating the raise breaks these tests.
func TestVaneTriggerLineFollowsDemand(t *testing.T) {
	newFlow := func(t *testing.T, demandBPS int64) (*Vane, *vaneMediaFlow) {
		t.Helper()
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		parsed, err := parseVaneSceneRules([]string{"DOMAIN-SUFFIX,googlevideo.com,media"})
		require.NoError(t, err)
		group.rules = parsed
		config, err := newVaneMediaConfig(VaneOption{
			MediaReconnect:        true,
			MediaReconnectDomains: []string{"googlevideo.com"},
			MediaDemandBPS:        vaneBandwidth(demandBPS),
		})
		require.NoError(t, err)
		config.enabled = true
		group.media = config
		require.Equal(t, demandBPS, int64(group.media.demandBPS))

		metadata := &C.Metadata{Host: "rr-trigger.googlevideo.com", DstPort: 443, NetWork: C.TCP}
		decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
		require.Equal(t, "alpha", decision.proxy.Name())
		flow := newVaneMediaFlow(group, decision.proxy.Name(), metadata)
		require.NotNil(t, flow)
		flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
		return group, flow
	}

	// TRIGGER-01: a 10M-demand group counts an 8M window as low (5M line would not).
	_, flow := newFlow(t, 10_000_000)
	require.Nil(t, flow.observe(vaneThroughputObservation{BitsPerSecond: 8_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second}))
	flow.mu.Lock()
	lowWindows := flow.lowWindows
	flow.mu.Unlock()
	require.Equal(t, 1, lowWindows, "8M is below the 10M line")

	// TRIGGER-02: a 2M-demand group keeps the 5M floor — 7M is not low.
	_, flow = newFlow(t, 2_000_000)
	require.Nil(t, flow.observe(vaneThroughputObservation{BitsPerSecond: 7_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second}))
	flow.mu.Lock()
	lowWindows = flow.lowWindows
	flow.mu.Unlock()
	require.Zero(t, lowWindows, "7M is above the 5M floor")

	// TRIGGER-03: the floor still catches a 3M window on the low-demand group.
	_, flow = newFlow(t, 2_000_000)
	require.Nil(t, flow.observe(vaneThroughputObservation{BitsPerSecond: 3_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second}))
	flow.mu.Lock()
	lowWindows = flow.lowWindows
	flow.mu.Unlock()
	require.Equal(t, 1, lowWindows, "3M is below the 5M floor")
}

// §L exemption: a plan admitted on fresh target evidence survives the CHAIN-04
// node-level re-check — the target tier outranks the node tier at commit too.
func TestVaneCommitTargetTierSurvivesNodeFloor(t *testing.T) {
	group, clock, alpha, beta, metadata := newTargetGroupForTest(t)
	chain01ProductionValues(t, group, 10_000_000)
	group.media.lowThroughputBPS = 10_000_000 // §L: the line follows demand
	suppressColdPickProbeForTest(t, group, metadata)
	group.mu.Lock()
	group.learning.mu.Lock()
	group.ensureProxyNodeLocked(alpha, clock.Now())
	group.ensureProxyNodeLocked(beta, clock.Now())
	group.learning.mu.Unlock()
	group.mu.Unlock()
	// Fresh node traffic inside the 5–10M band the raised floor now vetoes.
	seedChain01Traffic(t, group, beta.Name(), clock.Now(), 8_000_000)
	group.mu.Lock()
	key, _ := group.targetKeyForMedia(metadata.Host, metadata.DstPort)
	member := group.memberLeaseLocked(beta.Name(), beta.identity)
	group.mu.Unlock()
	techdebtSeedTargetEvidence(t, group, key, member, 12_000_000, clock.Now())

	plan, reason := chain01Prepare(t, group, metadata, alpha, 1_600_000)
	require.Empty(t, reason, "the 12M target evidence admits over the 8M node sample")
	require.Equal(t, beta.Name(), plan.challenger)
	require.False(t, plan.knownGood)
	require.Empty(t, group.commitMediaReconnectDetailed(plan),
		"the target tier must survive the CHAIN-04 node floor at commit")
	group.mu.Lock()
	hint := group.mediaHints[plan.targetKey]
	group.mu.Unlock()
	require.Equal(t, beta.Name(), hint.candidate)
}

// §F: the halved sample gate (64KB/2s → 32KB/1s), inclusive boundaries.
func TestVaneSampleGateHalved(t *testing.T) {
	// SAMPLE-01: 40KB over 1.5s is now a sample (it was not before).
	bps, ok := vaneThroughputSample(clockZero(), clockZero().Add(1500*time.Millisecond), 40*1024)
	require.True(t, ok)
	require.InDelta(t, 8*40*1024/1.5, bps, 1)
	// SAMPLE-02: below the payload gate — still not a sample.
	_, ok = vaneThroughputSample(clockZero(), clockZero().Add(1500*time.Millisecond), 20*1024)
	require.False(t, ok)
	// SAMPLE-03: below the window gate — still not a sample.
	_, ok = vaneThroughputSample(clockZero(), clockZero().Add(500*time.Millisecond), 40*1024)
	require.False(t, ok)
	// SAMPLE-04: the old gate sizes remain samples, formula unchanged.
	bps, ok = vaneThroughputSample(clockZero(), clockZero().Add(2*time.Second), 64*1024)
	require.True(t, ok)
	require.InDelta(t, 8*64*1024/2.0, bps, 1)
}

// newTargetGroupForTest3 extends newTargetGroupForTest with a third member.
func newTargetGroupForTest3(t *testing.T) (*Vane, *vaneConnTestClock, *vaneTestProxy, *vaneTestProxy, *vaneTestProxy, *C.Metadata) {
	t.Helper()
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	gamma := newVaneTestProxy("gamma", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta, gamma)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media", "DOMAIN-SUFFIX,interactive.example,interactive")
	configureVaneRacingForTest(t, group, vaneRacingOn)
	metadata := &C.Metadata{Host: "rr1.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	return group, clock, alpha, beta, gamma, metadata
}

// clockZero keeps the SAMPLE table readable.
func clockZero() time.Time { return time.Unix(0, 0) }

var _ = url.Parse

// §G: the shutdown flush forces a persist and waits for the store to catch up.
func TestVaneFlushDiagnosticsContextPersists(t *testing.T) {
	store := newVaneDiagnosticsTestStore()
	clock := newVaneConnTestClock()
	diagnostics := newVaneDiagnostics("flush-test", clock, store)
	key := vaneDiagnosticsStorageKey("flush-test")
	vaneDiagnosticsRegistry.Lock()
	previous := vaneDiagnosticsRegistry.entries[key]
	vaneDiagnosticsRegistry.entries[key] = diagnostics
	vaneDiagnosticsRegistry.Unlock()
	t.Cleanup(func() {
		vaneDiagnosticsRegistry.Lock()
		if previous != nil {
			vaneDiagnosticsRegistry.entries[key] = previous
		} else {
			delete(vaneDiagnosticsRegistry.entries, key)
		}
		vaneDiagnosticsRegistry.Unlock()
	})

	// FLUSH-01: a recorded counter survives the flush into the store.
	diagnostics.record(vaneDiagnosticRecord{kind: "throughput-sample", bps: 8_000_000})
	require.NoError(t, FlushVaneDiagnosticsContext(context.Background()))
	require.Positive(t, store.writeCount(), "the flush must persist the recorded counters")

	// FLUSH-02: an empty registry is a no-op, not an error.
	vaneDiagnosticsRegistry.Lock()
	restored := vaneDiagnosticsRegistry.entries
	vaneDiagnosticsRegistry.entries = make(map[string]*vaneDiagnostics)
	vaneDiagnosticsRegistry.Unlock()
	t.Cleanup(func() {
		vaneDiagnosticsRegistry.Lock()
		vaneDiagnosticsRegistry.entries = restored
		vaneDiagnosticsRegistry.Unlock()
	})
	require.NoError(t, FlushVaneDiagnosticsContext(context.Background()))
}

// §H: a full learning registry evicts its least-recently-accessed entry,
// flush-first, instead of silently dropping the new group's persistence.
func TestVaneLearningRegistryEvictsOldestWhenFull(t *testing.T) {
	store := newVaneLearningTestStore()
	previousFactory := vaneLearningRegistry.storeFactory
	vaneLearningRegistry.storeFactory = func() vaneLearningStore { return store }
	t.Cleanup(func() {
		vaneLearningRegistry.Lock()
		vaneLearningRegistry.storeFactory = previousFactory
		vaneLearningRegistry.Unlock()
	})
	vaneLearningRegistry.Lock()
	previousEntries := vaneLearningRegistry.entries
	vaneLearningRegistry.entries = make(map[string]*vaneLearningState)
	vaneLearningRegistry.Unlock()
	t.Cleanup(func() {
		vaneLearningRegistry.Lock()
		vaneLearningRegistry.entries = previousEntries
		vaneLearningRegistry.Unlock()
	})

	clock := newVaneConnTestClock()
	for i := 0; i < vaneLearningRegistryLimit; i++ {
		state := acquireVaneLearningState(fmt.Sprintf("group-%d", i), clock, time.Hour, 64)
		require.NotNil(t, state.store)
	}
	// group-0 carries the oldest access stamp; refresh group-42 so the victim
	// choice cannot depend on map iteration order.
	require.NotNil(t, acquireVaneLearningState("group-42", clock, time.Hour, 64))
	vaneLearningRegistry.Lock()
	oldest := vaneLearningRegistry.entries[vaneLearningStorageKey("group-0")]
	vaneLearningRegistry.Unlock()
	require.NotNil(t, oldest)
	oldest.mu.Lock()
	oldest.markDirtyLocked(clock.Now())
	oldest.mu.Unlock()

	// REGISTRY-01: the next acquire evicts the flushed oldest and gets a real
	// store instead of the old silent degradation.
	fresh := acquireVaneLearningState("fresh", clock, time.Hour, 64)
	require.NotNil(t, fresh.store, "the new group must get a store")
	vaneLearningRegistry.Lock()
	_, oldestGone := vaneLearningRegistry.entries[vaneLearningStorageKey("group-0")]
	_, group42Kept := vaneLearningRegistry.entries[vaneLearningStorageKey("group-42")]
	vaneLearningRegistry.Unlock()
	require.False(t, oldestGone, "the oldest entry must be evicted")
	require.True(t, group42Kept)
	require.Positive(t, store.writes, "the victim must have been flushed before deletion")

	// REGISTRY-03 (regression): the same name re-acquires the same state.
	again := acquireVaneLearningState("fresh", clock, time.Hour, 64)
	require.Same(t, fresh, again)
	vaneLearningRegistry.Lock()
	count := len(vaneLearningRegistry.entries)
	vaneLearningRegistry.Unlock()
	require.Equal(t, vaneLearningRegistryLimit, count, "re-acquisition must not occupy a new slot")
}

// §H: a victim whose flush fails stays in the registry; the new group
// degrades to the store-less candidate exactly like the old behavior.
func TestVaneLearningRegistryKeepsVictimOnFlushFailure(t *testing.T) {
	store := newVaneLearningTestStore()
	previousFactory := vaneLearningRegistry.storeFactory
	vaneLearningRegistry.storeFactory = func() vaneLearningStore { return store }
	t.Cleanup(func() {
		vaneLearningRegistry.Lock()
		vaneLearningRegistry.storeFactory = previousFactory
		vaneLearningRegistry.Unlock()
	})
	vaneLearningRegistry.Lock()
	previousEntries := vaneLearningRegistry.entries
	vaneLearningRegistry.entries = make(map[string]*vaneLearningState)
	vaneLearningRegistry.Unlock()
	t.Cleanup(func() {
		vaneLearningRegistry.Lock()
		vaneLearningRegistry.entries = previousEntries
		vaneLearningRegistry.Unlock()
	})

	clock := newVaneConnTestClock()
	for i := 0; i < vaneLearningRegistryLimit; i++ {
		state := acquireVaneLearningState(fmt.Sprintf("group-%d", i), clock, time.Hour, 64)
		require.NotNil(t, state.store)
	}
	// The victim holds unflushed changes, so the eviction's flush hits the
	// failing store.
	vaneLearningRegistry.Lock()
	victim := vaneLearningRegistry.entries[vaneLearningStorageKey("group-0")]
	vaneLearningRegistry.Unlock()
	require.NotNil(t, victim)
	victim.mu.Lock()
	victim.markDirtyLocked(clock.Now())
	victim.mu.Unlock()
	store.mu.Lock()
	store.fail = errors.New("save failed")
	store.mu.Unlock()
	t.Cleanup(func() {
		store.mu.Lock()
		store.fail = nil
		store.mu.Unlock()
	})

	// REGISTRY-02: the victim's flush fails during eviction — the victim
	// stays and the new group degrades.
	candidate := acquireVaneLearningState("newcomer", clock, time.Hour, 64)
	require.Nil(t, candidate.store, "the failed eviction degrades the new group")
	require.Equal(t, "node-state registry capacity unavailable", candidate.lastError)
	vaneLearningRegistry.Lock()
	_, victimKept := vaneLearningRegistry.entries[vaneLearningStorageKey("group-0")]
	vaneLearningRegistry.Unlock()
	require.True(t, victimKept, "a failed victim flush must not delete the victim")
}
