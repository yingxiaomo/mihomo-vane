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
// snapshotted before any lock (see snapshotFreshCapabilities). Capability
// records are matched by (name, identity) regardless of epoch: a deleted and
// re-added node keeps its identity but gains a new epoch, and its old probe
// evidence is still about the same endpoint.
func (a *Vane) coldPickGateLocked(freshCaps map[vaneMemberLease]float64, scope string, top2 []vaneRankedProxy, now time.Time) bool {
	if len(top2) < 2 {
		return false
	}
	for _, candidate := range top2 {
		identity := vaneProxyPersistentIdentity(candidate.proxy)
		name := candidate.proxy.Name()
		for member := range freshCaps {
			if member.name == name && member.identity == identity {
				return false
			}
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
func (a *Vane) runColdPickProbe(ctx context.Context, probe coldPickProbe) (outcomes []pickProbeOutcome, budgetDenied, canceled bool) {
	limits := a.reserveRaceBudget(len(probe.candidates), a.clock.Now())
	if len(limits) == 0 {
		a.diagnostics.record(vaneDiagnosticRecord{
			kind:   "pick-probe-budget-denied",
			target: probe.scope, bucket: probe.scope,
			force: true,
		})
		return nil, true, false
	}
	// P0 (audit 2026-11-22): reserveRaceBudget legitimately returns fewer
	// limits than requested when the hourly budget's remainder drops below
	// the minimum reservation — index limits[i] for i >= len(limits) panics
	// on the dial goroutine (no recover up the tunnel stack). Probe only the
	// candidates we actually reserved for, mirroring runMediaRace.
	probe.candidates = probe.candidates[:len(limits)]
	type entry struct {
		outcome  pickProbeOutcome
		panicked any
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
			// §J: a panicking probe must not crash the process past the flag
			// clearing — recover here and surface the panic to the collector,
			// which re-panics after the results are gathered.
			defer func() {
				if r := recover(); r != nil {
					// P1 (audit 2026-11-22): the reservation was taken in
					// reserveRaceBudget; a panicked probe that never reaches
					// the settle below must still release it, or the leaked
					// reserved bytes block the hourly reset (gated on
					// reserved == 0) and deny every later probe for this
					// group until reload.
					a.settleRaceBudget(limit, 0)
					results <- entry{panicked: r}
				}
			}()
			result := probeFunc(probeCtx, candidate.proxy, a.racing.url, limit)
			a.settleRaceBudget(limit, result.bytes)
			results <- entry{outcome: pickProbeOutcome{proxy: candidate.proxy, member: candidate.member, result: result}}
		}(candidate, limit)
	}
	outcomes = make([]pickProbeOutcome, 0, len(probe.candidates))
	for len(outcomes) < len(probe.candidates) {
		select {
		case <-ctx.Done():
			// P2 (audit 2026-11-22): a canceled gather must not be mistaken
			// for a completed probe — stage (c) would otherwise stamp the
			// per-scope timestamp and cache one-sided results. The race path
			// records race-canceled and writes nothing; mirror that.
			a.diagnostics.record(vaneDiagnosticRecord{
				kind:   "pick-probe-canceled",
				target: probe.scope, bucket: probe.scope,
				force: true,
			})
			return outcomes, false, true
		case entry := <-results:
			if entry.panicked != nil {
				panic(entry.panicked)
			}
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
	return outcomes, false, false
}

// settleColdPickProbe records probe diagnostics and returns the pick verdict.
// It is called under a.mu (+ learning.mu) but performs NO blocking work: it
// reads only a.mu-guarded state and returns. The capability cache write is
// the caller's job, after releasing a.mu — a.mu and racingRuntime.mu must
// never nest (CHAIN-01 lock-order rule; snapshotFreshCapabilities is the
// matching pre-lock snapshot).
//
// A stale generation (reload mid-probe) poisons the measurement's ownership
// (RACE-06 lesson): diagnostics are still recorded, but the verdict is always
// ranked-fallback and the capability cache is never written.
func (a *Vane) settleColdPickProbeLocked(scope string, probe coldPickProbe, outcomes []pickProbeOutcome, now time.Time) (pickProbeCandidate, []pickProbeOutcome, string) {
	rankingFirst := probe.baseline.Name()
	stale := a.learningGeneration != probe.generation || a.learning.generation != probe.generation
	validOutcomes := make([]pickProbeOutcome, 0, len(outcomes))
	for _, outcome := range outcomes {
		member := vaneMemberLease{name: outcome.member.name, identity: outcome.member.identity, epoch: outcome.member.epoch}
		kind := "pick-probe-invalid"
		if outcome.result.valid {
			kind = "pick-probe-success"
			if !stale {
				// Only genuinely measured, current-generation results are
				// eligible for the capability cache; the caller writes them
				// after releasing a.mu.
				validOutcomes = append(validOutcomes, outcome)
			}
		}
		a.diagnostics.record(vaneDiagnosticRecord{
			kind: kind, reason: outcome.result.reason,
			target: scope, bucket: scope, to: member.name,
			bps: outcome.result.lowerBoundBPS, totalBytes: outcome.result.bytes,
			age: outcome.result.duration, force: true,
		})
	}
	if stale {
		return pickProbeCandidate{}, nil, "ranked-fallback"
	}
	// §2.3: find the fastest valid+usable outcome. The baseline (ranking
	// choice) wins any tie — a result within the 5% relative margin of the
	// fastest does not displace it, because the margin compares against the
	// FASTEST result, not against the running best (a descending-ordered scan
	// would never let the baseline win a close second).
	var best *pickProbeOutcome
	fastest := 0.0
	for index := range outcomes {
		outcome := &outcomes[index]
		if !outcome.result.valid || !a.memberLeaseCurrentLocked(outcome.member) ||
			!outcome.proxy.AliveForTestUrl(a.testURL) {
			continue
		}
		if outcome.result.lowerBoundBPS > fastest {
			fastest = outcome.result.lowerBoundBPS
		}
		if best == nil || outcome.result.lowerBoundBPS > best.result.lowerBoundBPS {
			best = outcome
		}
	}
	if best == nil || fastest == 0 {
		return pickProbeCandidate{}, validOutcomes, "ranked-fallback"
	}
	// The ranking choice wins ties: if it is valid and within the margin of
	// the fastest result, keep the ranking choice.
	if best.proxy.Name() != rankingFirst {
		for index := range outcomes {
			outcome := &outcomes[index]
			if !outcome.result.valid || outcome.proxy.Name() != rankingFirst ||
				!a.memberLeaseCurrentLocked(outcome.member) || !outcome.proxy.AliveForTestUrl(a.testURL) {
				continue
			}
			if outcome.result.lowerBoundBPS >= fastest*(1-pickProbeRelativeMargin) {
				return pickProbeCandidate{}, validOutcomes, "ranked-fallback"
			}
			break
		}
	}
	return pickProbeCandidate{proxy: best.proxy, member: best.member}, validOutcomes, "probe"
}

// writeColdPickCapabilityLocked writes the probe results into the capability
// cache under racingRuntime.mu. It must be called AFTER releasing a.mu —
// never while holding it (CHAIN-01 lock-order rule).
func (a *Vane) writeColdPickCapabilityLocked(outcomes []pickProbeOutcome, now time.Time) {
	a.racingRuntime.mu.Lock()
	defer a.racingRuntime.mu.Unlock()
	for _, outcome := range outcomes {
		member := vaneMemberLease{name: outcome.member.name, identity: outcome.member.identity, epoch: outcome.member.epoch}
		a.racingRuntime.capabilities[member] = vaneCapabilityRecord{
			member: member, lowerBoundBPS: outcome.result.lowerBoundBPS,
			bytes: outcome.result.bytes, observedAt: now,
		}
	}
	a.pruneCapabilitiesLocked(now)
}
