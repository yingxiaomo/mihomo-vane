package outboundgroup

import (
	"fmt"
	"math"
	"sort"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

const (
	vaneTargetPreferenceTTL = 10 * time.Minute
	// vaneMinVerdictWindow keeps a verdict off a sub-second burst: a 200 ms
	// sample can report tens of Mbps from a few hundred kilobytes, and that
	// must not pin a preference.
	vaneMinVerdictWindow  = 3 * time.Second
	vaneTargetEvidenceTTL = 10 * time.Minute
	vaneTargetStateLimit  = 1024
)

var vaneTargetFailureBackoff = [...]time.Duration{
	30 * time.Second,
	1 * time.Minute,
	2 * time.Minute,
	4 * time.Minute,
	8 * time.Minute,
	15 * time.Minute,
}

type vaneTargetKey struct {
	transport   vaneTransport
	targetScope string
	port        uint16
}

type vaneMemberLease struct {
	name     string
	identity string
	epoch    uint64
}

type vaneHandoffLease struct {
	id        uint64
	key       vaneTargetKey
	from      vaneMemberLease
	to        vaneMemberLease
	expiresAt time.Time
	updatedAt time.Time
	claimed   bool
	token     *vaneHandoffToken
}

type vaneTargetPreference struct {
	to        vaneMemberLease
	expiresAt time.Time
	updatedAt time.Time
}

type vaneTargetEvidenceKey struct {
	target vaneTargetKey
	member vaneMemberLease
}

type vaneTargetEvidence struct {
	bitsPerSecond float64
	observedAt    time.Time
	// degraded marks a window whose throughput was healthy but whose loss or
	// latency crossed its line: the node is bad for this target even though it
	// is fast. Readers must not treat it as admitting evidence.
	degraded bool
}

type vaneTargetFailureKey struct {
	target vaneTargetKey
	member vaneMemberLease
}

type vaneTargetFailureState struct {
	streak        uint8
	blockUntil    time.Time
	lastFailureAt time.Time
	// observation fields (round5 item 2): passive loss telemetry that never
	// participates in selection. A record holding only these fields keeps its
	// zero streak/blockUntil/lastFailureAt, so it can never act as a failure.
	lossEMA             float64
	lossSamples         int64
	attemptCount        int64
	suspectedStallCount int64
	lastObservedAt      time.Time
	// §A (§12.3 step 1): the real-traffic throughput this (target, candidate)
	// pair last delivered, recorded at settlement. Record-only for now — no
	// selection path reads it; the read side is targetCapabilityLocked.
	capBPS     float64
	capAt      time.Time
	capSamples int64
}

// loss EMA weights early evidence more heavily and stabilizes the estimate
// as samples accumulate. The stall signature window and minimum attempt count
// are internal starting values. The Step 3 thresholds are deliberately fixed
// instead of tuned from shadow samples: the network is not stationary, so a
// number fitted to last week's samples is pseudo-precision. The real switching
// decision comes from live measurement (racing probes, target traffic
// evidence, the decaying loss EMA); these thresholds are only guard rails.
const (
	vaneLossAlphaBase    = 0.4
	vaneLossAlphaDecay   = 0.05
	vaneStallMinAge      = 10 * time.Second
	vaneStallMinAttempts = 5
	// Step 3 selection guard rails (STEP3-001 / STEP3-002): a healthy
	// path retransmits well under 1%, so 5% is already visibly bad for a stream,
	// and stalling one time in five is frequent enough to step aside.
	vaneLossDegradedThreshold  = 0.05
	vaneStallFrequentThreshold = 0.20
	// vaneStallCooldown is an independent cooldown source. It holds the same
	// value as vaneRacingNoWinnerCooldown but means something different, so it
	// is deliberately not reused from there.
	vaneStallCooldown = 30 * time.Second
)

// String renders the key for learning-state maps (round6 item 3). The format
// is internal to this package: persisted records carry the structured fields.
func (k vaneTargetKey) String() string {
	return fmt.Sprintf("%s|%s|%d", k.transport.String(), k.targetScope, k.port)
}

func (a *Vane) targetScopeForKey(target string, port uint16) (vaneTargetKey, bool) {
	key := a.targetScopeKey(target, port)
	if key.target == "" {
		return vaneTargetKey{}, false
	}
	return vaneTargetKey{
		transport:   vaneTransportTCP,
		targetScope: key.target,
		port:        port,
	}, true
}

// vaneStickyTTL is how long a host stays on one exit after a pick.
const vaneStickyTTL = 60 * time.Second

// vaneStickySwitchWindow is the sliding window that bounds switchCount.
const vaneStickySwitchWindow = 30 * time.Minute

// vaneStickyKeyFor builds the per-host stickiness key. Unlike targetScopeForKey
// it does not require a family rule: every TCP host gets its own 60s slot, which
// is the whole point of replacing the per-scene anchor.
func vaneStickyKeyFor(target string, port uint16) vaneTargetKey {
	return vaneTargetKey{transport: vaneTransportTCP, targetScope: target, port: port}
}

// stickyChoiceLocked reports the live sticky node for this host, if any.
// The caller must hold a.mu.
// stickyKeyFor scopes the sticky choice by the family rule set that claims the
// host, not by the host itself. A page and its CDN are different hostnames but
// the same service, and the user's rule set already says so: "GEOSITE,youtube"
// covers www.youtube.com and every rr*.googlevideo.com. Keying the sticky on
// the raw host gave each of them its own choice, so a switch could leave the
// page on one exit and the video on another — two IPs for one account.
func (a *Vane) stickyKeyFor(target string, port uint16) vaneTargetKey {
	if scopeKey := a.targetScopeKey(target, port); scopeKey.target != "" {
		return vaneTargetKey{transport: vaneTransportTCP, targetScope: scopeKey.target, port: port}
	}
	return vaneStickyKeyFor(target, port)
}

func (a *Vane) stickyChoiceLocked(target string, port uint16, now time.Time) (string, string, bool) {
	choice, ok := a.stickiness[a.stickyKeyFor(target, port)]
	if !ok || choice.name == "" || !choice.expiresAt.After(now) {
		return "", "", false
	}
	// STICKY-IDENTITY: return the identity the choice was made for. A provider
	// reload can reuse a name for a different endpoint, so the caller must not
	// pin by name alone.
	return choice.name, choice.identity, true
}

// rememberStickyLocked pins this host to name for vaneStickyTTL and bumps the
// 30 minute switch counter when the choice actually changes. The caller must
// hold a.mu.
func (a *Vane) rememberStickyLocked(target string, port uint16, name string, now time.Time) {
	if name == "" {
		return
	}
	identity := ""
	if st := a.nodes[name]; st != nil {
		identity = st.identity
	}
	key := a.stickyKeyFor(target, port)
	choice := a.stickiness[key]
	if choice.name != name || choice.identity != identity {
		if now.Sub(choice.switchWindowFrom) > vaneStickySwitchWindow {
			choice.switchCount = 0
			choice.switchWindowFrom = now
		}
		choice.switchCount++
		choice.lastSwitch = now
		// STICKY-RENEW: only a real change of exit renews the window. Renewing
		// on every hit pinned the host forever — each new connection pushed
		// expiresAt out another 60s, so a slow node was never re-evaluated.
		choice.expiresAt = now.Add(vaneStickyTTL)
	}
	choice.name = name
	choice.identity = identity
	a.stickiness[key] = choice
}

func (a *Vane) memberLeaseLocked(name, identity string) vaneMemberLease {
	lease := vaneMemberLease{name: name, identity: identity}
	if state := a.nodes[name]; state != nil && state.identity == identity {
		lease.epoch = state.epoch
	}
	return lease
}

func (a *Vane) memberLeaseCurrentLocked(lease vaneMemberLease) bool {
	if lease.name == "" || lease.identity == "" || a.nodeIdentities[lease.name] != lease.identity {
		return false
	}
	if lease.epoch == 0 {
		return true
	}
	state := a.nodes[lease.name]
	return state != nil && state.identity == lease.identity && state.epoch == lease.epoch
}

func (a *Vane) targetMemberBlockedLocked(key vaneTargetKey, member vaneMemberLease, now time.Time) (time.Time, bool) {
	state, ok := a.targetFailures[vaneTargetFailureKey{target: key, member: member}]
	if !ok || !state.blockUntil.After(now) {
		return time.Time{}, false
	}
	return state.blockUntil, true
}

func (a *Vane) recordTargetFailureLocked(key vaneTargetKey, member vaneMemberLease, now time.Time) vaneTargetFailureState {
	failureKey := vaneTargetFailureKey{target: key, member: member}
	state := a.targetFailures[failureKey]
	if state.streak < uint8(len(vaneTargetFailureBackoff)) {
		state.streak++
	}
	index := int(state.streak) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(vaneTargetFailureBackoff) {
		index = len(vaneTargetFailureBackoff) - 1
	}
	state.lastFailureAt = now
	state.blockUntil = now.Add(vaneTargetFailureBackoff[index])
	a.targetFailures[failureKey] = state
	return state
}

func (a *Vane) clearTargetFailureLocked(key vaneTargetKey, member vaneMemberLease) {
	delete(a.targetFailures, vaneTargetFailureKey{target: key, member: member})
}

// feedLoss folds one cumulative loss sample into the EMA. The first sample
// becomes the estimate directly; later samples decay with the sample count so
// early evidence weighs more and the estimate stabilizes over time. Values
// clamp to [0, 1]; NaN and Inf are rejected as no-sample.
func (s *vaneTargetFailureState) feedLoss(sample float64, now time.Time) {
	if math.IsNaN(sample) || math.IsInf(sample, 0) {
		return
	}
	if sample < 0 {
		sample = 0
	} else if sample > 1 {
		sample = 1
	}
	if s.lossSamples == 0 {
		s.lossEMA = sample
	} else {
		alpha := vaneLossAlphaBase / (1 + vaneLossAlphaDecay*float64(s.lossSamples))
		s.lossEMA += alpha * (sample - s.lossEMA)
	}
	s.lossSamples++
	s.lastObservedAt = now
}

// recordLoss folds one flow's cumulative loss observation into
// the flow's target record (round5 item 2). Observation only: the failure
// fields (streak, blockUntil, lastFailureAt) are never touched, so an
// observation record can never block or suppress a member. Small transfers
// stay out (a few kilobytes of loss ratio is noise), unsupported reads count
// as unsupported instead of fabricating a sample, and the recording runs
// regardless of the racing mode — the shadow data must not stop with it.
func (a *Vane) recordLoss(flow *vaneFlow, observation vaneConnectionCloseObservation, now time.Time) {
	if flow == nil || observation.TotalReadBytes < a.flow.minBytes {
		return
	}
	if !observation.LossSupported {
		a.diagnostics.record(vaneDiagnosticRecord{
			kind: "loss-unsupported", target: flow.target, bucket: flow.targetKey.target,
			port: flow.port, from: flow.candidate,
		})
		return
	}
	failureKey := vaneTargetFailureKey{
		target: flow.targetStateKey,
		member: vaneMemberLease{name: flow.candidate, identity: flow.identity, epoch: flow.nodeEpoch},
	}
	a.mu.Lock()
	state := a.targetFailures[failureKey]
	state = a.seedStateFromLearning(flow, state)
	state.feedLoss(observation.LossRate, now)
	a.targetFailures[failureKey] = state
	a.pruneTargetStateLocked(now)
	a.learning.pushTarget(a.targetSnapshot(flow, state), now)
	a.mu.Unlock()
	a.diagnostics.record(vaneDiagnosticRecord{
		kind: "loss-sample", target: flow.target, bucket: flow.targetKey.target,
		port: flow.port, from: flow.candidate,
	})
}

// vaneStallSignature reports the header-then-stall signature: the flow wrote
// payload, saw its first response, and then stayed silent until settlement —
// no byte read after the response snapshot and a quiet tail of at least
// vaneStallMinAge. A client that keeps reading (or gives up before the
// window) does not match. This is distinct from churn, which only recognizes
// short connections.
func vaneStallSignature(observation vaneConnectionCloseObservation, closedAt time.Time) bool {
	return observation.WrotePayload && observation.ResponseRecorded &&
		observation.TotalReadBytes == observation.ResponseBytes &&
		closedAt.Sub(observation.ResponseAt) >= vaneStallMinAge
}

// stallRate returns the suspected-stall ratio once at least
// vaneStallMinAttempts settled attempts exist; below that the ratio is
// meaningless and reads as zero. The clamp guards a future caller against
// suspected exceeding attempts (stalls are observed while the connection is
// alive, attempts only count at settlement).
func (s *vaneTargetFailureState) stallRate() float64 {
	if s.attemptCount < vaneStallMinAttempts {
		return 0
	}
	rate := float64(s.suspectedStallCount) / float64(s.attemptCount)
	if rate < 0 {
		return 0
	}
	if rate > 1 {
		return 1
	}
	return rate
}

// lossDegraded reports whether the smoothed retransmission ratio is bad enough
// to step away from this challenger. No extra sample floor: the EMA is already
// smoothed, and excluding the challenger is fail-safe — the flow simply stays
// where it is instead of moving to something worse.
func (s *vaneTargetFailureState) lossDegraded() bool {
	return s.lossSamples > 0 && s.lossEMA > vaneLossDegradedThreshold
}

// stallFrequent reports whether this challenger stalls often enough to be
// cooled down for a while. stallRate already applies the minimum-attempt
// floor, so no second gate is needed here.
func (s *vaneTargetFailureState) stallFrequent() bool {
	return s.stallRate() > vaneStallFrequentThreshold
}

// recordStall counts one flow settlement (round5 item 3):
// AttemptCount always, SuspectedStallCount when the header-stall signature
// matched. Observation only, same record as the loss EMA, same racing-mode
// independence.
func (a *Vane) recordStall(flow *vaneFlow, observation vaneConnectionCloseObservation, now time.Time) {
	if flow == nil {
		return
	}
	stalled := vaneStallSignature(observation, now)
	failureKey := vaneTargetFailureKey{
		target: flow.targetStateKey,
		member: vaneMemberLease{name: flow.candidate, identity: flow.identity, epoch: flow.nodeEpoch},
	}
	a.mu.Lock()
	state := a.targetFailures[failureKey]
	state = a.seedStateFromLearning(flow, state)
	state.attemptCount++
	if stalled {
		state.suspectedStallCount++
	}
	state.lastObservedAt = now
	a.targetFailures[failureKey] = state
	a.pruneTargetStateLocked(now)
	a.learning.pushTarget(a.targetSnapshot(flow, state), now)
	a.mu.Unlock()
	a.diagnostics.record(vaneDiagnosticRecord{
		kind: "stall-attempt", target: flow.target, bucket: flow.targetKey.target,
		port: flow.port, from: flow.candidate,
	})
	if stalled {
		a.diagnostics.record(vaneDiagnosticRecord{
			kind: "stall-suspected", reason: "header-stall", target: flow.target,
			bucket: flow.targetKey.target, port: flow.port, from: flow.candidate,
		})
	}
}

// targetSnapshot renders the live record's telemetry for the learning
// mirror (round6 item 3). Only observation fields — never streak, blockUntil
// or lastFailureAt.
func (a *Vane) targetSnapshot(flow *vaneFlow, state vaneTargetFailureState) vanePersistedTarget {
	return vanePersistedTarget{
		Transport:           flow.targetStateKey.transport.String(),
		TargetScope:         flow.targetStateKey.targetScope,
		Port:                flow.targetStateKey.port,
		Candidate:           flow.candidate,
		Identity:            flow.identity,
		LossEMA:             state.lossEMA,
		LossSamples:         state.lossSamples,
		AttemptCount:        state.attemptCount,
		SuspectedStallCount: state.suspectedStallCount,
		LastObservedAt:      state.lastObservedAt,
	}
}

// seedStateFromLearning starts a empty live record from the restored
// learning copy (round6 item 3). A record holding any data — even a single
// attempt — is never overwritten. Called with a.mu held.
func (a *Vane) seedStateFromLearning(flow *vaneFlow, state vaneTargetFailureState) vaneTargetFailureState {
	if state.lossSamples != 0 || state.attemptCount != 0 {
		return state
	}
	seed, ok := a.learning.seedTarget(
		flow.targetStateKey.transport,
		flow.targetStateKey.targetScope, flow.targetStateKey.port,
		flow.candidate, flow.identity,
	)
	if !ok {
		return state
	}
	state.lossEMA = seed.LossEMA
	state.lossSamples = seed.LossSamples
	state.attemptCount = seed.AttemptCount
	state.suspectedStallCount = seed.SuspectedStallCount
	state.lastObservedAt = seed.LastObservedAt
	return state
}

func (a *Vane) recordTargetEvidenceLocked(key vaneTargetKey, member vaneMemberLease, bitsPerSecond float64, degraded bool, now time.Time) {
	if bitsPerSecond <= 0 || !a.memberLeaseCurrentLocked(member) {
		return
	}
	a.targetEvidence[vaneTargetEvidenceKey{target: key, member: member}] = vaneTargetEvidence{
		bitsPerSecond: bitsPerSecond,
		observedAt:    now,
		degraded:      degraded,
	}
}

func (a *Vane) recordTargetEvidence(key vaneTargetKey, member vaneMemberLease, bitsPerSecond float64, degraded bool) {
	if bitsPerSecond <= 0 {
		return
	}
	now := a.clock.Now()
	a.mu.Lock()
	a.recordTargetEvidenceLocked(key, member, bitsPerSecond, degraded, now)
	a.pruneTargetStateLocked(now)
	a.mu.Unlock()
}

func (a *Vane) targetEvidenceLocked(key vaneTargetKey, member vaneMemberLease, now time.Time) (float64, bool, bool) {
	record, ok := a.targetEvidence[vaneTargetEvidenceKey{target: key, member: member}]
	if !ok || record.observedAt.IsZero() || now.Sub(record.observedAt) > vaneTargetEvidenceTTL || !a.memberLeaseCurrentLocked(member) {
		return 0, false, false
	}
	return record.bitsPerSecond, true, record.degraded
}

// targetCapabilityLocked is the read side of the §12.3 per-target capability
// observation (§A): the real-traffic throughput this (target, candidate) pair
// last delivered at settlement. Expired means no evidence — never a downgrade
// to the node-level capability cache. Record-only in this batch; the second
// step (ranking per-target capability above the node-level cache) wires this
// into selection once shadow data justifies it.
func (a *Vane) targetCapabilityLocked(key vaneTargetKey, member vaneMemberLease, now time.Time) (float64, bool) {
	record, ok := a.targetFailures[vaneTargetFailureKey{target: key, member: member}]
	if !ok || record.capSamples == 0 || record.capAt.IsZero() || now.Sub(record.capAt) > vaneTargetEvidenceTTL || !a.memberLeaseCurrentLocked(member) {
		return 0, false
	}
	return record.capBPS, true
}

func (a *Vane) takeTargetSelectionLocked(key vaneTargetKey, proxies []C.Proxy, now time.Time, claimHandoff bool) (C.Proxy, *vaneHandoffToken, string) {
	if a.racing.mode != vaneRacingOn {
		return nil, nil, ""
	}
	find := func(member vaneMemberLease) C.Proxy {
		if !a.memberLeaseCurrentLocked(member) {
			return nil
		}
		if _, blocked := a.targetMemberBlockedLocked(key, member, now); blocked {
			return nil
		}
		for _, proxy := range proxies {
			if proxy.Name() != member.name || vaneProxyPersistentIdentity(proxy) != member.identity {
				continue
			}
			if a.nodeCoolingLocked(member.name, now) {
				return nil
			}
			return proxy
		}
		return nil
	}

	if lease, ok := a.targetHandoffs[key]; ok {
		if lease.expiresAt.After(now) {
			if proxy := find(lease.to); proxy != nil {
				var token *vaneHandoffToken
				if claimHandoff && !lease.claimed {
					lease.claimed = true
					a.targetHandoffs[key] = lease
					token = lease.token
				}
				return proxy, token, "handoff"
			}
		}
		delete(a.targetHandoffs, key)
	}
	if preference, ok := a.targetPreferences[key]; ok {
		if preference.expiresAt.After(now) {
			if proxy := find(preference.to); proxy != nil {
				return proxy, nil, "preference"
			}
		}
		delete(a.targetPreferences, key)
	}
	return nil, nil, ""
}

func (a *Vane) commitTargetHandoff(plan vaneReconnectPlan) string {
	memberHealthy := false
	var challengerProxy C.Proxy
	for _, proxy := range a.GetProxies(false) {
		if proxy.Name() == plan.challenger && vaneProxyPersistentIdentity(proxy) == plan.challengerIdentity && proxy.AliveForTestUrl(a.testURL) {
			memberHealthy = true
			challengerProxy = proxy
			break
		}
	}
	if !memberHealthy {
		return "challenger-unhealthy"
	}
	release, current := a.lockVaneIdentities(map[string]string{
		plan.current:    plan.identity,
		plan.challenger: plan.challengerIdentity,
	})
	if !current {
		return "stale-node-identity"
	}
	defer release()

	now := a.clock.Now()
	// CHAIN-01: capability evidence is read before a.mu; no path may hold
	// racingRuntime.mu together with a.mu (see snapshotFreshCapabilities).
	capSnapshot := a.snapshotFreshCapabilities(now)
	a.mu.Lock()
	a.learning.mu.Lock()
	defer func() {
		a.learning.mu.Unlock()
		a.mu.Unlock()
	}()
	if a.learningGeneration != a.learning.generation || plan.generation != a.learningGeneration {
		return "stale-generation"
	}
	currentState := a.nodes[plan.current]
	if currentState == nil || currentState.identity != plan.identity || currentState.epoch != plan.nodeEpoch {
		return "stale-node-identity"
	}
	challengerState := a.ensureProxyNodeLocked(challengerProxy, now)
	if challengerState == nil || challengerState.identity != plan.challengerIdentity {
		return "stale-node-identity"
	}
	if plan.challengerEpoch != 0 && challengerState.epoch != plan.challengerEpoch {
		return "stale-node-identity"
	}
	key := plan.targetStateKey
	if key.targetScope == "" {
		return "invalid-target"
	}
	a.pruneFlowStateLocked(now)
	a.pruneTargetStateLocked(now)
	if now.Sub(plan.preparedAt) > a.flow.hintTTL {
		return "plan-expired"
	}
	// §E: valve plans skip the cooldown they are re-evaluating (no valve plan
	// reaches the target commit today, but the flag rides the shared plan).
	if !plan.skipReconnectCooldown {
		if reason := a.ledgerThrottleReasonLocked(plan.targetKey, now); reason != "" {
			return reason
		}
	}
	to := vaneMemberLease{name: plan.challenger, identity: plan.challengerIdentity, epoch: challengerState.epoch}
	// RACE-01: the race (or the on+knownGood path) may have admitted this
	// challenger minutes ago. If the target itself has since produced fresh
	// evidence below the original bar, refuse before touching budget/cooldown.
	// RESCUE: same rule as the reconnect commit — demand gates the current flow,
	// not the challenger that rescues it.
	requiredBPS := plan.currentBPS * a.flow.challengerRatio
	if targetBPS, fresh, degraded := a.targetEvidenceLocked(key, to, now); fresh && (degraded || targetBPS < requiredBPS) {
		return "challenger-evidence-degraded"
	}
	// A capability-cache win carries no target-scoped evidence and is therefore
	// not vetoed here; that evidence priority is intentional, not a bug.
	if _, blocked := a.targetMemberBlockedLocked(key, to, now); blocked {
		return "candidate-cooldown"
	}
	dialKey := vaneCooldownKey{transport: vaneTransportTCP, target: plan.target, port: plan.port, candidate: plan.challenger, identity: plan.challengerIdentity}
	if a.cooldownUntilLocked(dialKey, now, false).After(now) {
		return "candidate-cooldown"
	}
	if a.nodeCoolingLocked(plan.challenger, now) {
		return "challenger-slow-cooldown"
	}
	// CHAIN-01: the challenger must still have fresh evidence above the close
	// bar across all tiers. A race winner below the 5 Mbps slow line is vetoed
	// on purpose (do not cut a flow to a node that is still slow); a
	// target-evidence winner passes through the target tier here.
	if reason := a.checkChallengerEvidenceLocked(plan, capSnapshot, now); reason != "" {
		return reason
	}
	from := vaneMemberLease{name: plan.current, identity: plan.identity, epoch: plan.nodeEpoch}
	// SWITCH-AWAY: the node we leave is not a candidate for five minutes on
	// every target, which is what makes A->B->A impossible.
	a.coolNodeLocked(plan.current, now.Add(vaneSwitchAwayCooldown))
	token := a.diagnostics.recordReconnectCommit(vaneDiagnosticRecord{
		kind:       "handoff-committed",
		handoffID:  plan.raceID,
		leaseID:    vaneRaceLeaseID(plan.generation, plan.raceID),
		target:     plan.target,
		bucket:     plan.targetKey.target,
		port:       plan.port,
		from:       plan.current,
		to:         plan.challenger,
		bps:        plan.currentBPS,
		totalBytes: plan.totalBytes,
		age:        plan.age,
		lowWindows: plan.lowWindows,
	})
	if token == nil {
		// RACE-07: the handoff lease is also the reconnect target and the
		// settlement entry point, so a missing diagnostics token must not turn
		// into a failed commit. Synthesize the token locally instead; the same
		// environment condition is tolerated on the baseline path.
		token = &vaneHandoffToken{
			id:          plan.raceID,
			leaseID:     vaneRaceLeaseID(plan.generation, plan.raceID),
			target:      plan.target,
			bucket:      plan.targetKey.target,
			port:        plan.port,
			from:        plan.current,
			to:          plan.challenger,
			previousBPS: plan.currentBPS,
		}
	}
	token.targetKey = key
	token.fromLease = from
	token.toLease = to
	a.targetHandoffs[key] = vaneHandoffLease{
		id:        token.id,
		key:       key,
		from:      from,
		to:        to,
		expiresAt: now.Add(a.flow.hintTTL),
		updatedAt: now,
		token:     token,
	}
	a.noteSwitchLocked(plan.targetKey, plan.challenger, now)
	return ""
}

func (a *Vane) settleTargetHandoff(token *vaneHandoffToken, member vaneMemberLease, sample vaneThroughputObservation) {
	if token == nil || token.targetKey.targetScope == "" || sample.BitsPerSecond <= 0 {
		return
	}
	now := a.clock.Now()
	// RESCUE: a handoff counts as a gain when it beats the flow it replaced,
	// not when it already reaches demand.
	required := token.previousBPS * a.flow.challengerRatio
	// RESCUE-FLOOR: the settlement asks "did the landing beat the flow it
	// replaced", so its floor is the absolute rescue line (5M), not the
	// configured low line. Using the configured line here made a 6-9 Mbps
	// landing count as no-gain while the flow it replaced ran at 1 bps, and
	// no-gain cools that node for thirty minutes.
	if required < float64(vaneDefaultLowThroughputBPS) {
		required = float64(vaneDefaultLowThroughputBPS)
	}
	kind := "handoff-no-gain"
	a.mu.Lock()
	// §A: read the existing capability sample count before the branch — an
	// improved verdict clears the failure record, and the count must survive.
	capKey := vaneTargetFailureKey{target: token.targetKey, member: member}
	prevCapSamples := a.targetFailures[capKey].capSamples
	current := a.memberLeaseCurrentLocked(member)
	if lease, ok := a.targetHandoffs[token.targetKey]; ok && lease.id == token.id {
		if lease.to != member || !current {
			a.mu.Unlock()
			return
		}
		delete(a.targetHandoffs, token.targetKey)
	} else if !token.baseline || !current {
		// A target handoff must still own its lease. A baseline token has no
		// target lease; the hint that carried it is its validation.
		a.mu.Unlock()
		return
	}
	a.recordTargetEvidenceLocked(token.targetKey, member, sample.BitsPerSecond, false, now)
	// B.7: the verdict uses the same signal set as the low-window line. An
	// improved verdict pins a preference and keeps the reconnect cooldown, so a
	// node that is merely fast must not win one. The health signals are trusted
	// only once the first window has enough delivered bytes: a fresh socket's
	// cumulative retransmission ratio is noise, and no-gain writes a 30-minute
	// slow cooldown for the very node we just switched to.
	signalOK := sample.TotalBytes >= a.flow.minBytes && sample.Delivered
	// STABLE-WINDOW (audit 2026-11-26): a verdict must not rest on a short
	// burst. A 200 ms window can report 50 Mbps from a few hundred kilobytes;
	// that is not evidence of sustained bandwidth. A window that is too short
	// is not a verdict in EITHER direction — it must not pin a preference and
	// must not cool the node — so it returns before the improved/no-gain split
	// instead of falling into no-gain, which cools the node for 30 minutes.
	if sample.Age < vaneMinVerdictWindow {
		a.mu.Unlock()
		return
	}
	improved := sample.BitsPerSecond >= required &&
		(!signalOK || !sample.LossSupported || sample.LossRate <= vaneDefaultHighLossRate) &&
		(!signalOK || !sample.LatencySupported || sample.Latency <= vaneDefaultHighLatency)
	if improved {
		a.targetPreferences[token.targetKey] = vaneTargetPreference{
			to: member, expiresAt: now.Add(vaneTargetPreferenceTTL), updatedAt: now,
		}
		a.clearTargetFailureLocked(token.targetKey, member)
		// LANDING-CLEAR: the switch landed well, so the verify marker that
		// penalizeSlowLanding arms must be dropped. Without this the marker
		// survived until the 60 s observe window expired, and any low window
		// in between cooled the node we had just proven fast for ten minutes.
		a.clearLandingLocked(vaneFlowKey{target: token.targetKey.targetScope, port: token.targetKey.port}, member.name)
		kind = "handoff-improved"
	} else {
		// PREFERENCE-SCOPE: only drop the preference this member owns. The old
		// unconditional delete let one no-gain landing erase a preference another
		// member had already proven — the same asymmetry the improved and no-gain
		// clears fixed elsewhere in this file.
		if preference, ok := a.targetPreferences[token.targetKey]; ok && preference.to == member {
			delete(a.targetPreferences, token.targetKey)
		}
		legacyKey := vaneCandidateKey{
			vaneFlowKey: vaneFlowKey{target: token.targetKey.targetScope, port: token.targetKey.port},
			candidate:   member.name,
			identity:    member.identity,
		}
		a.coolNodeLocked(member.name, now.Add(a.flow.slowCooldown))
		// §D: the handoff did not help — clearing the ledger lets this target be
		// re-evaluated at once instead of waiting out the throttle. The node
		// cooldown above still keeps this same candidate out of the pool.
		delete(a.ledger, legacyKey.vaneFlowKey)
	}
	// §A: fold the settlement's real-traffic sample into the (target, member)
	// record — the per-target capability observation, record-only for now.
	// Written after the improved/no-gain branch because an improved verdict
	// clears the failure record first (the sample count was read above and is
	// carried over; the failure fields are not); small transfers stay out
	// (same minBytes gate as the sample path). The record is created
	// observation-only if it does not exist, which can never block (zero
	// streak/blockUntil), and lastObservedAt keeps the LRU eviction from
	// treating a cap-only record as the oldest.
	if sample.TotalBytes >= a.flow.minBytes {
		state := a.targetFailures[capKey]
		state.capBPS = sample.BitsPerSecond
		state.capAt = now
		state.capSamples = prevCapSamples + 1
		state.lastObservedAt = now
		a.targetFailures[capKey] = state
	}
	a.pruneTargetStateLocked(now)
	a.mu.Unlock()
	a.diagnostics.record(vaneDiagnosticRecord{
		kind:        kind,
		handoffID:   token.id,
		leaseID:     token.leaseID,
		target:      token.target,
		bucket:      token.bucket,
		port:        token.port,
		from:        token.from,
		to:          token.to,
		bps:         sample.BitsPerSecond,
		previousBPS: token.previousBPS,
		totalBytes:  sample.TotalBytes,
		age:         sample.Age,
	})
}

func (a *Vane) failTargetHandoff(token *vaneHandoffToken, reason string, hard bool) {
	if token == nil || token.targetKey.targetScope == "" {
		return
	}
	now := a.clock.Now()
	a.mu.Lock()
	if lease, ok := a.targetHandoffs[token.targetKey]; ok && lease.id == token.id {
		delete(a.targetHandoffs, token.targetKey)
	}
	// P2 (audit 2026-11-22): only the failed handoff's own member loses the
	// preference — a different member's proven preference must survive this
	// failure (same ownership rule as invalidateTargetPreference). Baseline
	// tokens carry no toLease, so baseline dial failures touch nothing here,
	// matching the hard-failure recording right below.
	if preference, ok := a.targetPreferences[token.targetKey]; ok && preference.to == token.toLease {
		delete(a.targetPreferences, token.targetKey)
	}
	if hard && a.memberLeaseCurrentLocked(token.toLease) {
		a.recordTargetFailureLocked(token.targetKey, token.toLease, now)
	}
	a.pruneTargetStateLocked(now)
	a.mu.Unlock()
	a.diagnostics.record(vaneDiagnosticRecord{
		kind:        "handoff-failed",
		reason:      reason,
		handoffID:   token.id,
		leaseID:     token.leaseID,
		target:      token.target,
		bucket:      token.bucket,
		port:        token.port,
		from:        token.from,
		to:          token.to,
		previousBPS: token.previousBPS,
	})
}

func (a *Vane) discardTargetHandoff(token *vaneHandoffToken) {
	if token == nil || token.targetKey.targetScope == "" {
		return
	}
	a.mu.Lock()
	if lease, ok := a.targetHandoffs[token.targetKey]; ok && lease.id == token.id {
		delete(a.targetHandoffs, token.targetKey)
	}
	a.mu.Unlock()
}

func (a *Vane) refreshTargetPreference(key vaneTargetKey, member vaneMemberLease, bitsPerSecond float64) {
	if a.racing.mode != vaneRacingOn || bitsPerSecond <= 0 {
		return
	}
	now := a.clock.Now()
	a.mu.Lock()
	a.recordTargetEvidenceLocked(key, member, bitsPerSecond, false, now)
	// PREFERENCE-TTL (audit 2026-11-26): the verdict's ten minutes start at the
	// settlement and do not slide. Renewing on every fast window kept a
	// preference alive for as long as any flow in the family ran well, so one
	// optimistic verdict could pin a slow node for an unbounded stretch. The
	// window below only retires a preference whose node lost its lease; the
	// deadline itself is left alone so a bad landing genuinely ages out.
	if preference, ok := a.targetPreferences[key]; ok && preference.to == member && !a.memberLeaseCurrentLocked(member) {
		delete(a.targetPreferences, key)
	}
	a.pruneTargetStateLocked(now)
	a.mu.Unlock()
}

func (a *Vane) invalidateTargetPreference(key vaneTargetKey, member vaneMemberLease) {
	if a.racing.mode != vaneRacingOn {
		return
	}
	a.mu.Lock()
	if preference, ok := a.targetPreferences[key]; ok && preference.to == member {
		delete(a.targetPreferences, key)
	}
	a.mu.Unlock()
}

func (a *Vane) pruneTargetStateLocked(now time.Time) {
	for key, lease := range a.targetHandoffs {
		if !lease.expiresAt.After(now) || !a.memberLeaseCurrentLocked(lease.to) || !a.memberLeaseCurrentLocked(lease.from) {
			delete(a.targetHandoffs, key)
		}
	}
	for key, preference := range a.targetPreferences {
		if !preference.expiresAt.After(now) || !a.memberLeaseCurrentLocked(preference.to) {
			delete(a.targetPreferences, key)
		}
	}
	for key, evidence := range a.targetEvidence {
		if evidence.observedAt.IsZero() || now.Sub(evidence.observedAt) > vaneTargetEvidenceTTL || !a.memberLeaseCurrentLocked(key.member) {
			delete(a.targetEvidence, key)
		}
	}
	for key := range a.targetFailures {
		if !a.memberLeaseCurrentLocked(key.member) {
			delete(a.targetFailures, key)
		}
	}
	trimTargetMap(a.targetHandoffs, vaneTargetStateLimit, func(value vaneHandoffLease) time.Time { return value.updatedAt })
	trimTargetMap(a.targetPreferences, vaneTargetStateLimit, func(value vaneTargetPreference) time.Time { return value.updatedAt })
	if len(a.targetEvidence) > vaneTargetStateLimit {
		type entry struct {
			key     vaneTargetEvidenceKey
			time    time.Time
			keyText string
		}
		entries := make([]entry, 0, len(a.targetEvidence))
		for key, value := range a.targetEvidence {
			entries = append(entries, entry{key: key, time: value.observedAt, keyText: fmt.Sprint(key)})
		}
		sort.Slice(entries, func(i, j int) bool {
			if !entries[i].time.Equal(entries[j].time) {
				return entries[i].time.Before(entries[j].time)
			}
			return entries[i].keyText < entries[j].keyText
		})
		for i := 0; i < len(entries)-vaneTargetStateLimit; i++ {
			delete(a.targetEvidence, entries[i].key)
		}
	}
	if len(a.targetFailures) > vaneTargetStateLimit {
		type entry struct {
			key     vaneTargetFailureKey
			time    time.Time
			keyText string
		}
		entries := make([]entry, 0, len(a.targetFailures))
		for key, value := range a.targetFailures {
			// item 2 (round5), eviction-timestamp choice (b): observation
			// records evict by observation freshness, not first-out by their
			// zero lastFailureAt.
			trimTime := value.lastFailureAt
			if value.lastObservedAt.After(trimTime) {
				trimTime = value.lastObservedAt
			}
			entries = append(entries, entry{key: key, time: trimTime, keyText: fmt.Sprint(key)})
		}
		sort.Slice(entries, func(i, j int) bool {
			if !entries[i].time.Equal(entries[j].time) {
				return entries[i].time.Before(entries[j].time)
			}
			return entries[i].keyText < entries[j].keyText
		})
		for i := 0; i < len(entries)-vaneTargetStateLimit; i++ {
			delete(a.targetFailures, entries[i].key)
		}
	}
}

func trimTargetMap[K comparable, V any](values map[K]V, limit int, timestamp func(V) time.Time) {
	if len(values) <= limit {
		return
	}
	type entry struct {
		key     K
		time    time.Time
		keyText string
	}
	entries := make([]entry, 0, len(values))
	for key, value := range values {
		entries = append(entries, entry{key: key, time: timestamp(value), keyText: fmt.Sprint(key)})
	}
	// Equal timestamps must not leave the outcome to map iteration order:
	// the key text decides deterministically.
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].time.Equal(entries[j].time) {
			return entries[i].time.Before(entries[j].time)
		}
		return entries[i].keyText < entries[j].keyText
	})
	for i := 0; i < len(entries)-limit; i++ {
		delete(values, entries[i].key)
	}
}
