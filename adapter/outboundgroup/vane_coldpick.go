package outboundgroup

import (
	"context"
	"sort"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// Cold-pick probe (COLD-PICK): when a media flow's first pick falls through to
// the ranking path on a cold target, the top two candidates are probed through
// the racing endpoint so the initial node is measured, not just well-ranked by
// delay. Results write the node-level capability cache and nothing else —
// never targetEvidence, never a TargetPreference, never a race winner.
//
// Throttle is triple (any hit skips the probe): fresh capability records for
// either candidate, a per-scope probe timestamp inside the capability TTL, or
// a per-scope in-flight marker. Concurrency fails open: a second cold pick on
// the same scope while one probe runs takes the ranking choice immediately.

const (
	// pickProbeRelativeMargin treats two probe results within 5% of each
	// other as a tie; the baseline (ranking) choice wins the tie. Same
	// numeric value as switchMargin but a different meaning (throughput
	// relative difference, not score micros).
	pickProbeRelativeMargin = 0.05
)

type pickProbeCandidate struct {
	proxy  C.Proxy
	member vaneMemberLease
}

type pickProbeOutcome struct {
	proxy  C.Proxy
	member vaneMemberLease
	result vaneProbeResult
}

type coldPickProbe struct {
	scope      string
	candidates []pickProbeCandidate
	baseline   C.Proxy
	generation uint64
}

// coldPickGateLocked reports whether the ranking fallback path should run the
// cold-pick probe. Caller holds a.mu (+ learning.mu). freshCaps must be
// snapshotted before any lock (see snapshotFreshCapabilities).
func (a *Vane) coldPickGateLocked(freshCaps map[vaneMemberLease]float64, scope string, top2 []vaneRankedProxy, now time.Time) bool {
	if len(top2) < 2 {
		return false
	}
	for _, candidate := range top2 {
		identity := vaneProxyPersistentIdentity(candidate.proxy)
		if _, ok := freshCaps[vaneMemberLease{name: candidate.proxy.Name(), identity: identity, epoch: 1}]; ok {
			return false
		}
		if _, ok := freshCaps[vaneMemberLease{name: candidate.proxy.Name(), identity: identity}]; ok {
			return false
		}
	}
	if a.lastPickProbeAt[scope].Add(vaneRacingCapabilityTTL).After(now) {
		return false
	}
	return !a.pickProbeInflight[scope]
}

// runColdPickProbe is the unlocked stage (b): reserve budget, probe both
// candidates in parallel, wait for both results, settle the budget. It never
// touches a.mu or learning.mu; all shared state writes happen in stage (c).
func (a *Vane) runColdPickProbe(ctx context.Context, probe coldPickProbe) []pickProbeOutcome {
	limits := a.reserveRaceBudget(len(probe.candidates), a.clock.Now())
	if len(limits) == 0 {
		return nil
	}
	type entry struct {
		outcome pickProbeOutcome
	}
	results := make(chan entry, len(probe.candidates))
	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	probeFunc := a.racing.probe
	if probeFunc == nil {
		probeFunc = probeVaneCapability
	}
	for index, candidate := range probe.candidates {
		limit := limits[index]
		go func(candidate pickProbeCandidate, limit int64) {
			result := probeFunc(probeCtx, candidate.proxy, a.racing.url, limit)
			a.settleRaceBudget(limit, result.bytes)
			results <- entry{outcome: pickProbeOutcome{proxy: candidate.proxy, member: candidate.member, result: result}}
		}(candidate, limit)
	}
	outcomes := make([]pickProbeOutcome, 0, len(probe.candidates))
	for len(outcomes) < len(probe.candidates) {
		select {
		case <-ctx.Done():
			return outcomes
		case entry := <-results:
			outcomes = append(outcomes, entry.outcome)
		}
	}
	// Deterministic order: valid first (fastest bound, then member name), so
	// the tie-break in stage (c) is stable.
	sort.SliceStable(outcomes, func(i, j int) bool {
		leftValid, rightValid := outcomes[i].result.valid, outcomes[j].result.valid
		if leftValid != rightValid {
			return leftValid
		}
		if leftValid && outcomes[i].result.lowerBoundBPS != outcomes[j].result.lowerBoundBPS {
			return outcomes[i].result.lowerBoundBPS > outcomes[j].result.lowerBoundBPS
		}
		return outcomes[i].member.name < outcomes[j].member.name
	})
	return outcomes
}

// settleColdPickProbe is stage (c) under a.mu (+ learning.mu): record
// diagnostics, write capability cache for valid results, and pick the
// selected candidate per §2.3. Returns the winner (empty on fail-open) and
// the pick-probe-selected reason. A stale generation (reload mid-probe)
// poisons the measurement's ownership (RACE-06 lesson): diagnostics are still
// recorded, but the capability cache is never written and the pick falls
// back to ranking.
func (a *Vane) settleColdPickProbeLocked(scope string, probe coldPickProbe, outcomes []pickProbeOutcome, now time.Time) (pickProbeCandidate, string) {
	rankingFirst := probe.baseline.Name()
	stale := a.learningGeneration != probe.generation || a.learning.generation != probe.generation
	for _, outcome := range outcomes {
		member := vaneMemberLease{name: outcome.member.name, identity: outcome.member.identity, epoch: outcome.member.epoch}
		kind := "pick-probe-invalid"
		if outcome.result.valid {
			kind = "pick-probe-success"
		}
		a.diagnostics.record(vaneDiagnosticRecord{
			kind: kind, reason: outcome.result.reason,
			target: scope, bucket: scope, to: member.name,
			bps: outcome.result.lowerBoundBPS, totalBytes: outcome.result.bytes,
			age: outcome.result.duration, force: true,
		})
		if stale || !outcome.result.valid {
			continue
		}
		a.racingRuntime.mu.Lock()
		a.racingRuntime.capabilities[member] = vaneCapabilityRecord{
			member: member, lowerBoundBPS: outcome.result.lowerBoundBPS,
			bytes: outcome.result.bytes, observedAt: now,
		}
		a.pruneCapabilitiesLocked(now)
		a.racingRuntime.mu.Unlock()
	}
	var best *pickProbeOutcome
	for index := range outcomes {
		outcome := &outcomes[index]
		if !outcome.result.valid || !a.memberLeaseCurrentLocked(outcome.member) ||
			!outcome.proxy.AliveForTestUrl(a.testURL) {
			continue
		}
		if best == nil {
			best = outcome
			continue
		}
		if best.result.lowerBoundBPS*(1+pickProbeRelativeMargin) < outcome.result.lowerBoundBPS {
			best = outcome
		}
	}
	if best == nil || best.proxy.Name() == rankingFirst {
		return pickProbeCandidate{}, "ranked-fallback"
	}
	return pickProbeCandidate{proxy: best.proxy, member: best.member}, "probe"
}
