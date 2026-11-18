package outboundgroup

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/geodata"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

const (
	vaneDefaultMediaLowThroughputBPS = int64(3_000_000)
	vaneDefaultMediaLowWindows       = 3
	vaneDefaultMediaMaxLowWindows    = 6
	vaneDefaultMediaMinAge           = 15 * time.Second
	vaneDefaultMediaMinBytes         = int64(2 * 1024 * 1024)
	vaneDefaultMediaDemandBPS        = int64(1_000_000)
	vaneDefaultMediaBufferGuard      = 3 * time.Second
	vaneDefaultMediaReconnectDelay   = 10 * time.Minute
	vaneDefaultMediaSlowCooldown     = 30 * time.Minute
	vaneDefaultMediaHintTTL          = 15 * time.Second
	vaneDefaultMediaChallengerRatio  = 1.25
	vaneDefaultMediaBudgetMax        = 3
	vaneDefaultMediaBudgetWindow     = 30 * time.Minute
	vaneMediaEvidenceMaxAge          = 10 * time.Minute
	vaneMaximumMediaThroughputBPS    = int64(1_000_000_000)
)

type vaneMediaConfig struct {
	enabled           bool
	domains           []string
	ruleSets          []string
	geoSites          []string
	lowThroughputBPS  float64
	lowWindows        int
	maxLowWindows     int
	minAge            time.Duration
	minBytes          int64
	demandBPS         float64
	bufferGuard       time.Duration
	reconnectCooldown time.Duration
	slowCooldown      time.Duration
	hintTTL           time.Duration
	challengerRatio   float64
	budgetMax         int
	budgetWindow      time.Duration
}

func defaultVaneMediaConfig() vaneMediaConfig {
	return vaneMediaConfig{
		lowThroughputBPS:  float64(vaneDefaultMediaLowThroughputBPS),
		lowWindows:        vaneDefaultMediaLowWindows,
		maxLowWindows:     vaneDefaultMediaMaxLowWindows,
		minAge:            vaneDefaultMediaMinAge,
		minBytes:          vaneDefaultMediaMinBytes,
		demandBPS:         float64(vaneDefaultMediaDemandBPS),
		bufferGuard:       vaneDefaultMediaBufferGuard,
		reconnectCooldown: vaneDefaultMediaReconnectDelay,
		slowCooldown:      vaneDefaultMediaSlowCooldown,
		hintTTL:           vaneDefaultMediaHintTTL,
		challengerRatio:   vaneDefaultMediaChallengerRatio,
		budgetMax:         vaneDefaultMediaBudgetMax,
		budgetWindow:      vaneDefaultMediaBudgetWindow,
	}
}

// parseVaneMediaRuleSetEntry is three-state: a valid `RULE-SET,<name>` entry
// returns (name, true, nil); a plain domain returns ("", false, nil); a
// malformed RULE-SET entry (empty name, or a name containing a comma) returns
// an error so it fails fast at construction instead of silently never
// matching. The prefix is case-insensitive like every other rule type; the
// provider name is kept verbatim.
func parseVaneMediaRuleSetEntry(entry string) (string, bool, error) {
	trimmed := strings.TrimSpace(entry)
	if !strings.HasPrefix(strings.ToUpper(trimmed), "RULE-SET,") {
		return "", false, nil
	}
	name := strings.TrimSpace(trimmed[len("RULE-SET,"):])
	if name == "" || strings.Contains(name, ",") {
		return "", false, fmt.Errorf("invalid media-reconnect-domain rule-set entry %q", entry)
	}
	return name, true, nil
}

// parseVaneMediaGeoSiteEntry is the GEOSITE counterpart of
// parseVaneMediaRuleSetEntry: a valid `GEOSITE,<category>` entry returns
// (category, true, nil); anything else returns ("", false, nil) so the caller
// can fall through to the plain-domain path. A malformed GEOSITE entry
// (empty category, or a category containing a comma) errors at construction.
// `!` negation and `@attr` suffixes are the loader's own syntax and pass
// through verbatim.
func parseVaneMediaGeoSiteEntry(entry string) (string, bool, error) {
	trimmed := strings.TrimSpace(entry)
	if !strings.HasPrefix(strings.ToUpper(trimmed), "GEOSITE,") {
		return "", false, nil
	}
	category := strings.TrimSpace(trimmed[len("GEOSITE,"):])
	if category == "" || strings.Contains(category, ",") {
		return "", false, fmt.Errorf("invalid media-reconnect-domain geosite entry %q", entry)
	}
	return category, true, nil
}

func newVaneMediaConfig(option VaneOption) (vaneMediaConfig, error) {
	config := defaultVaneMediaConfig()
	config.enabled = option.MediaReconnect
	for _, rawDomain := range option.MediaReconnectDomains {
		name, isRuleSet, err := parseVaneMediaRuleSetEntry(rawDomain)
		if err != nil {
			return vaneMediaConfig{}, err
		}
		if isRuleSet {
			config.ruleSets = append(config.ruleSets, name)
			continue
		}
		category, isGeoSite, err := parseVaneMediaGeoSiteEntry(rawDomain)
		if err != nil {
			return vaneMediaConfig{}, err
		}
		if isGeoSite {
			config.geoSites = append(config.geoSites, category)
			continue
		}
		domain, valid := normalizeVaneDomain(rawDomain)
		if !valid {
			return vaneMediaConfig{}, fmt.Errorf("invalid media-reconnect-domain %q", rawDomain)
		}
		config.domains = append(config.domains, domain)
	}

	if option.MediaLowThroughput < 0 || option.MediaLowThroughput > vaneMaximumMediaThroughputBPS {
		return vaneMediaConfig{}, fmt.Errorf("media-low-throughput must be between 0 and %d", vaneMaximumMediaThroughputBPS)
	}
	if option.MediaLowThroughput > 0 {
		config.lowThroughputBPS = float64(option.MediaLowThroughput)
	}
	if option.MediaLowWindows < 0 {
		return vaneMediaConfig{}, fmt.Errorf("media-low-windows must not be negative")
	}
	if option.MediaLowWindows > 0 {
		config.lowWindows = option.MediaLowWindows
	}
	if option.MediaMaxLowWindows < 0 {
		return vaneMediaConfig{}, fmt.Errorf("media-max-low-windows must not be negative")
	}
	if option.MediaMaxLowWindows > 0 {
		config.maxLowWindows = option.MediaMaxLowWindows
	}
	if config.maxLowWindows < config.lowWindows {
		return vaneMediaConfig{}, fmt.Errorf("media-max-low-windows must be at least media-low-windows")
	}
	if option.MediaMinBytes < 0 {
		return vaneMediaConfig{}, fmt.Errorf("media-min-bytes must not be negative")
	}
	if option.MediaMinBytes > 0 {
		config.minBytes = option.MediaMinBytes
	}
	if option.MediaDemandBPS < 0 || option.MediaDemandBPS > vaneMaximumMediaThroughputBPS {
		return vaneMediaConfig{}, fmt.Errorf("media-demand-bps must be between 0 and %d", vaneMaximumMediaThroughputBPS)
	}
	if option.MediaDemandBPS > 0 {
		config.demandBPS = float64(option.MediaDemandBPS)
	}
	if option.MediaChallengerRatio < 0 || (option.MediaChallengerRatio > 0 && option.MediaChallengerRatio < 1) {
		return vaneMediaConfig{}, fmt.Errorf("media-challenger-ratio must be zero or at least 1")
	}
	if option.MediaChallengerRatio > 0 {
		config.challengerRatio = option.MediaChallengerRatio
	}
	if option.MediaReconnectBudget < 0 {
		return vaneMediaConfig{}, fmt.Errorf("media-reconnect-budget must not be negative")
	}
	if option.MediaReconnectBudget > 0 {
		config.budgetMax = option.MediaReconnectBudget
	}

	var err error
	if config.minAge, err = vaneDurationOption("media-min-age", option.MediaMinAge, vaneDefaultMediaMinAge); err != nil {
		return vaneMediaConfig{}, err
	}
	if config.bufferGuard, err = vaneDurationOption("media-buffer-guard", option.MediaBufferGuard, vaneDefaultMediaBufferGuard); err != nil {
		return vaneMediaConfig{}, err
	}
	if config.reconnectCooldown, err = vaneDurationOption("media-reconnect-cooldown", option.MediaReconnectCooldown, vaneDefaultMediaReconnectDelay); err != nil {
		return vaneMediaConfig{}, err
	}
	if config.slowCooldown, err = vaneDurationOption("media-slow-cooldown", option.MediaSlowCooldown, vaneDefaultMediaSlowCooldown); err != nil {
		return vaneMediaConfig{}, err
	}
	if config.hintTTL, err = vaneDurationOption("media-hint-ttl", option.MediaHintTTL, vaneDefaultMediaHintTTL); err != nil {
		return vaneMediaConfig{}, err
	}
	if config.budgetWindow, err = vaneDurationOption("media-budget-window", option.MediaBudgetWindow, vaneDefaultMediaBudgetWindow); err != nil {
		return vaneMediaConfig{}, err
	}
	return config, nil
}

type vaneMediaTargetKey struct {
	target string
	port   uint16
}

type vaneMediaCandidateKey struct {
	vaneMediaTargetKey
	candidate string
	identity  string
}

type vaneMediaHint struct {
	candidate string
	identity  string
	expiresAt time.Time
	handoff   *vaneHandoffToken
}

type vaneMediaBudget struct {
	startedAt time.Time
	count     int
}

type vaneMediaFlow struct {
	group          *Vane
	candidate      string
	identity       string
	nodeEpoch      uint64
	target         string
	port           uint16
	targetKey      vaneMediaTargetKey
	targetStateKey vaneTargetKey

	mu              sync.Mutex
	lowWindows      int
	aborted         bool
	handoff         *vaneHandoffToken
	policySubmitter func(vanePolicyAction, bool)
	flowCountOnce   sync.Once
}

// mediaFlowStarted and mediaFlowEnded maintain the per-node live media-flow
// count (B2 item 4). The counter lives on its own lock: it churns per
// connection and must never contend with a.mu selection work.
func (a *Vane) mediaFlowStarted(name string) {
	a.mediaFlowsMu.Lock()
	a.mediaActiveFlows[name]++
	a.mediaFlowsMu.Unlock()
}

func (a *Vane) mediaFlowEnded(name string) {
	a.mediaFlowsMu.Lock()
	if a.mediaActiveFlows[name] <= 1 {
		delete(a.mediaActiveFlows, name)
	} else {
		a.mediaActiveFlows[name]--
	}
	a.mediaFlowsMu.Unlock()
}

// releaseActiveFlowCount drops the flow's per-node count exactly once, even if
// a second settlement path ever appears.
func (f *vaneMediaFlow) releaseActiveFlowCount() {
	if f == nil {
		return
	}
	f.flowCountOnce.Do(func() {
		f.group.mediaFlowEnded(f.candidate)
	})
}

func newVaneMediaFlow(group *Vane, candidate string, metadata *C.Metadata, handoff ...*vaneHandoffToken) *vaneMediaFlow {
	if group == nil || !group.media.enabled || classifyVaneScene(metadata, group.rules) != vaneSceneMedia {
		return nil
	}
	target, port := vaneTarget(metadata)
	if target == "" {
		return nil
	}
	targetKey := group.mediaTargetKey(target, port)
	if targetKey.target == "" {
		return nil
	}
	targetStateKey, ok := group.targetKeyForMedia(target, port)
	if !ok {
		return nil
	}
	flow := &vaneMediaFlow{group: group, candidate: candidate, target: target, port: port, targetKey: targetKey, targetStateKey: targetStateKey}
	if len(handoff) > 0 {
		flow.handoff = handoff[0]
	}
	group.diagnostics.record(vaneDiagnosticRecord{
		kind:   "media-flow-started",
		target: target,
		bucket: targetKey.target,
		port:   port,
		from:   candidate,
	})
	// B2 item 4: only successful flows hold a per-node count. The release
	// rides on the connection settlement (releaseActiveFlowCount); a
	// never-closing connection keeps holding its count, which is acceptable —
	// connections eventually close.
	group.mediaFlowStarted(candidate)
	return flow
}

func (f *vaneMediaFlow) failHandoff(reason string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	handoff := f.handoff
	f.handoff = nil
	f.mu.Unlock()
	if handoff == nil {
		return
	}
	f.group.failTargetHandoff(handoff, reason, true)
	f.group.diagnostics.record(vaneDiagnosticRecord{
		kind:        "handoff-dial-failed",
		reason:      reason,
		handoffID:   handoff.id,
		leaseID:     handoff.leaseID,
		target:      handoff.target,
		bucket:      handoff.bucket,
		port:        handoff.port,
		from:        handoff.from,
		to:          handoff.to,
		previousBPS: handoff.previousBPS,
		force:       true,
	})
}

func (f *vaneMediaFlow) discardHandoff() {
	if f == nil {
		return
	}
	f.mu.Lock()
	handoff := f.handoff
	f.handoff = nil
	f.mu.Unlock()
	f.group.discardTargetHandoff(handoff)
}

func (f *vaneMediaFlow) setPolicySubmitter(submitter func(vanePolicyAction, bool)) {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.policySubmitter = submitter
	f.mu.Unlock()
}

func (f *vaneMediaFlow) submitPolicyAction(action vanePolicyAction, delivered bool) {
	if f == nil || action == nil {
		return
	}
	f.mu.Lock()
	submitter := f.policySubmitter
	aborted := f.aborted
	f.mu.Unlock()
	if !aborted && submitter != nil {
		submitter(action, delivered)
	}
}

func (f *vaneMediaFlow) observe(sample vaneThroughputObservation) vanePolicyAction {
	if f == nil || sample.BitsPerSecond <= 0 {
		return nil
	}
	if !f.group.vaneMediaIdentityCurrent(f.candidate, f.identity, f.nodeEpoch) {
		f.discardHandoff()
		return nil
	}
	config := f.group.media
	member := vaneMemberLease{name: f.candidate, identity: f.identity, epoch: f.nodeEpoch}

	f.mu.Lock()
	if f.aborted {
		f.mu.Unlock()
		return nil
	}
	low := sample.BitsPerSecond < config.lowThroughputBPS
	if low {
		f.lowWindows++
	} else {
		f.lowWindows = 0
	}
	lowWindows := f.lowWindows
	handoff := f.handoff
	f.handoff = nil
	f.mu.Unlock()

	f.group.diagnostics.record(vaneDiagnosticRecord{
		kind:       "throughput-sample",
		target:     f.target,
		bucket:     f.targetKey.target,
		port:       f.port,
		from:       f.candidate,
		bps:        sample.BitsPerSecond,
		totalBytes: sample.TotalBytes,
		age:        sample.Age,
		lowWindows: lowWindows,
		low:        low,
	})
	f.group.recordTargetEvidence(f.targetStateKey, member, sample.BitsPerSecond)
	if low {
		f.group.invalidateTargetPreference(f.targetStateKey, member)
	} else {
		f.group.refreshTargetPreference(f.targetStateKey, member, sample.BitsPerSecond)
	}
	if handoff != nil {
		f.group.diagnostics.record(vaneDiagnosticRecord{
			kind:       "handoff-reconnect-positive",
			handoffID:  handoff.id,
			leaseID:    handoff.leaseID,
			target:     handoff.target,
			bucket:     handoff.bucket,
			port:       handoff.port,
			from:       handoff.from,
			to:         handoff.to,
			bps:        sample.BitsPerSecond,
			totalBytes: sample.TotalBytes,
			age:        sample.Age,
			force:      true,
		})
		f.group.diagnostics.record(vaneDiagnosticRecord{
			kind:        "handoff-measured",
			handoffID:   handoff.id,
			leaseID:     handoff.leaseID,
			target:      handoff.target,
			bucket:      handoff.bucket,
			port:        handoff.port,
			from:        handoff.from,
			to:          handoff.to,
			bps:         sample.BitsPerSecond,
			previousBPS: handoff.previousBPS,
			totalBytes:  sample.TotalBytes,
			age:         sample.Age,
			lowWindows:  lowWindows,
			force:       true,
		})
		f.group.settleTargetHandoff(handoff, member, sample)
	}
	if lowWindows < config.lowWindows || sample.Age < config.minAge || sample.TotalBytes < config.minBytes {
		return nil
	}
	creditBits := float64(sample.TotalBytes)*8 - config.demandBPS*sample.Age.Seconds()
	guardBits := config.demandBPS * config.bufferGuard.Seconds()
	if creditBits < guardBits && lowWindows < config.maxLowWindows {
		f.group.diagnostics.record(vaneDiagnosticRecord{
			kind:       "buffer-credit-deferred",
			reason:     "buffer-credit",
			target:     f.target,
			bucket:     f.targetKey.target,
			port:       f.port,
			from:       f.candidate,
			bps:        sample.BitsPerSecond,
			totalBytes: sample.TotalBytes,
			age:        sample.Age,
			lowWindows: lowWindows,
			force:      true,
		})
		log.Debugln("Vane: defer media reconnect target=%s:%d node=%s reason=buffer-credit bps=%.0f credit=%.0f guard=%.0f low-windows=%d/%d", f.target, f.port, f.candidate, sample.BitsPerSecond, creditBits, guardBits, lowWindows, config.maxLowWindows)
		return nil
	}

	plan, reason := f.group.prepareMediaReconnectForNodeDetailed(f.targetKey, f.target, f.port, f.candidate, f.identity, f.nodeEpoch, sample.BitsPerSecond)
	mode := f.group.racing.mode
	if reason != "" && !(mode != vaneRacingOff && reason == "no-challenger") {
		f.recordReconnectSuppressed(reason, sample, lowWindows)
		return nil
	}

	if mode == vaneRacingOff {
		if reason != "" {
			f.recordReconnectSuppressed(reason, sample, lowWindows)
			return nil
		}
		f.completeMediaPlan(&plan, sample, lowWindows)
		return f.policyActionForPlan(plan, sample, lowWindows, false)
	}

	if mode == vaneRacingShadow {
		if reason == "" && !plan.knownGood {
			f.scheduleRace(sample, lowWindows)
		} else if reason == "no-challenger" {
			f.scheduleRace(sample, lowWindows)
		}
		// Shadow preserves the frozen baseline action and every baseline media
		// state mutation. Racing contributes only capability and diagnostics.
		if reason != "" {
			f.recordReconnectSuppressed(reason, sample, lowWindows)
			return nil
		}
		f.completeMediaPlan(&plan, sample, lowWindows)
		return f.policyActionForPlan(plan, sample, lowWindows, false)
	}

	if reason == "" && plan.knownGood {
		f.completeMediaPlan(&plan, sample, lowWindows)
		return f.policyActionForPlan(plan, sample, lowWindows, true)
	}
	f.scheduleRace(sample, lowWindows)
	return nil
}

func (f *vaneMediaFlow) recordReconnectSuppressed(reason string, sample vaneThroughputObservation, lowWindows int) {
	f.group.diagnostics.record(vaneDiagnosticRecord{
		kind: "reconnect-suppressed", reason: reason, target: f.target, bucket: f.targetKey.target,
		port: f.port, from: f.candidate, bps: sample.BitsPerSecond, totalBytes: sample.TotalBytes,
		age: sample.Age, lowWindows: lowWindows, force: true,
	})
}

func (f *vaneMediaFlow) completeMediaPlan(plan *vaneMediaPlan, sample vaneThroughputObservation, lowWindows int) {
	plan.totalBytes = sample.TotalBytes
	plan.age = sample.Age
	plan.lowWindows = lowWindows
	f.group.diagnostics.record(vaneDiagnosticRecord{
		kind: "reconnect-prepared", target: f.target, bucket: f.targetKey.target, port: f.port,
		from: f.candidate, to: plan.challenger, bps: sample.BitsPerSecond, totalBytes: sample.TotalBytes,
		age: sample.Age, lowWindows: lowWindows, force: true,
	})
}

func (f *vaneMediaFlow) raceRequest(sample vaneThroughputObservation, lowWindows int) vaneRaceRequest {
	required := sample.BitsPerSecond * f.group.media.challengerRatio
	if required < f.group.media.demandBPS {
		required = f.group.media.demandBPS
	}
	f.group.mu.Lock()
	f.group.learning.mu.Lock()
	generation := f.group.learningGeneration
	f.group.learning.mu.Unlock()
	f.group.mu.Unlock()
	return vaneRaceRequest{
		targetKey: f.targetStateKey, mediaKey: f.targetKey, target: f.target, port: f.port,
		current:    vaneMemberLease{name: f.candidate, identity: f.identity, epoch: f.nodeEpoch},
		currentBPS: sample.BitsPerSecond, requiredBPS: required, totalBytes: sample.TotalBytes,
		age: sample.Age, lowWindows: lowWindows, generation: generation, requestedAt: f.group.clock.Now(),
	}
}

func (f *vaneMediaFlow) scheduleRace(sample vaneThroughputObservation, lowWindows int) {
	request := f.raceRequest(sample, lowWindows)
	scheduled, reason := f.group.scheduleMediaRace(request, func(result vaneRaceResult) {
		// The race is asynchronous: the flow may have recovered between the
		// trigger and this callback. A recovered flow must never be closed,
		// and its would-commit must not pollute shadow statistics.
		if f.flowRecovered() {
			f.group.diagnostics.record(vaneDiagnosticRecord{
				kind: "reconnect-rejected", reason: "flow-recovered", handoffID: result.taskID, target: f.target,
				bucket: f.targetKey.target, port: f.port, from: f.candidate, to: result.winner.name,
				bps: result.lowerBoundBPS, force: true,
			})
			return
		}
		if f.group.racing.mode == vaneRacingShadow {
			f.group.diagnostics.record(vaneDiagnosticRecord{
				kind: "handoff-would-commit", reason: result.source, handoffID: result.taskID,
				leaseID: vaneRaceLeaseID(result.request.generation, result.taskID), target: f.target,
				bucket: f.targetKey.target, port: f.port, from: f.candidate, to: result.winner.name,
				bps: result.lowerBoundBPS, previousBPS: sample.BitsPerSecond, totalBytes: sample.TotalBytes,
				age: sample.Age, lowWindows: lowWindows, force: true,
			})
			return
		}
		if f.group.racing.mode != vaneRacingOn {
			return
		}
		plan := vaneMediaPlan{
			targetKey: f.targetKey, targetStateKey: f.targetStateKey, target: f.target, port: f.port,
			current: f.candidate, identity: f.identity, nodeEpoch: f.nodeEpoch,
			challenger: result.winner.name, challengerIdentity: result.winner.identity, challengerEpoch: result.winner.epoch,
			generation: result.request.generation, raceID: result.taskID, currentBPS: sample.BitsPerSecond,
			preparedAt: f.group.clock.Now(), totalBytes: sample.TotalBytes, age: sample.Age, lowWindows: lowWindows,
		}
		f.group.diagnostics.record(vaneDiagnosticRecord{
			kind: "handoff-would-commit", reason: result.source, handoffID: result.taskID,
			leaseID: vaneRaceLeaseID(result.request.generation, result.taskID), target: f.target,
			bucket: f.targetKey.target, port: f.port, from: f.candidate, to: result.winner.name,
			bps: result.lowerBoundBPS, previousBPS: sample.BitsPerSecond, totalBytes: sample.TotalBytes,
			age: sample.Age, lowWindows: lowWindows,
		})
		f.submitPolicyAction(f.policyActionForPlan(plan, sample, lowWindows, true), sample.Delivered)
	})
	if !scheduled && reason != "race-in-flight" && reason != "no-winner-cooldown" {
		f.recordReconnectSuppressed(reason, sample, lowWindows)
	}
}

func (f *vaneMediaFlow) policyActionForPlan(plan vaneMediaPlan, sample vaneThroughputObservation, lowWindows int, targetCommit bool) vanePolicyAction {
	return func() bool {
		f.mu.Lock()
		if f.aborted {
			f.mu.Unlock()
			f.group.diagnostics.record(vaneDiagnosticRecord{
				kind: "reconnect-rejected", reason: "already-committed", handoffID: plan.raceID,
				leaseID: vaneRaceLeaseID(plan.generation, plan.raceID), target: f.target,
				bucket: f.targetKey.target, port: f.port, from: f.candidate, to: plan.challenger,
				bps: sample.BitsPerSecond, force: true,
			})
			return false
		}
		f.mu.Unlock()
		commitReason := ""
		if targetCommit {
			commitReason = f.group.commitTargetHandoff(plan)
		} else {
			commitReason = f.group.commitMediaReconnectDetailed(plan)
		}
		if commitReason != "" {
			f.group.diagnostics.record(vaneDiagnosticRecord{
				kind: "reconnect-rejected", reason: commitReason, handoffID: plan.raceID,
				leaseID: vaneRaceLeaseID(plan.generation, plan.raceID), target: f.target,
				bucket: f.targetKey.target, port: f.port, from: f.candidate, to: plan.challenger,
				bps: sample.BitsPerSecond, force: true,
			})
			return false
		}
		f.mu.Lock()
		f.aborted = true
		f.mu.Unlock()
		log.Infoln("Vane: media reconnect target=%s:%d bucket=%s from=%s to=%s bps=%.0f low-windows=%d", f.target, f.port, f.targetKey.target, f.candidate, plan.challenger, sample.BitsPerSecond, lowWindows)
		return true
	}
}

func (f *vaneMediaFlow) policyAborted() bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.aborted
}

// flowRecovered reports whether the flow's low-window streak has fallen back
// below the trigger threshold since the race was scheduled. The race is
// asynchronous, so a recovered flow must never be closed by its result.
func (f *vaneMediaFlow) flowRecovered() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lowWindows < f.group.media.lowWindows
}

type vaneMediaHealth struct {
	proxy C.Proxy
	alive bool
	delay uint16
}

type vaneMediaChallenger struct {
	proxy         C.Proxy
	knownGood     bool
	throughputBPS float64
	scoreMicros   int64
	delay         uint16
}

type vaneMediaPlan struct {
	targetKey          vaneMediaTargetKey
	target             string
	port               uint16
	current            string
	identity           string
	nodeEpoch          uint64
	challenger         string
	challengerIdentity string
	challengerEpoch    uint64
	targetStateKey     vaneTargetKey
	generation         uint64
	raceID             uint64
	knownGood          bool
	currentBPS         float64
	preparedAt         time.Time
	totalBytes         int64
	age                time.Duration
	lowWindows         int
}

type vaneLockedProxyProvider interface {
	ProxiesWithLock() ([]C.Proxy, func())
}

func (a *Vane) lockVaneMediaIdentities(expected map[string]string) (func(), bool) {
	providers := append([]P.ProxyProvider(nil), a.providers...)
	sort.SliceStable(providers, func(i, j int) bool { return providers[i].Name() < providers[j].Name() })
	releases := make([]func(), 0, len(providers))
	found := make(map[string]bool, len(expected))
	releaseAll := func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}
	lastProvider := ""
	for _, provider := range providers {
		if provider.Name() == lastProvider {
			continue
		}
		lastProvider = provider.Name()
		lockable, ok := provider.(vaneLockedProxyProvider)
		if !ok {
			releaseAll()
			return func() {}, false
		}
		proxies, release := lockable.ProxiesWithLock()
		releases = append(releases, release)
		for _, proxy := range proxies {
			if identity, wanted := expected[proxy.Name()]; wanted && vaneProxyPersistentIdentity(proxy) == identity {
				found[proxy.Name()] = true
			}
		}
	}
	for name := range expected {
		if !found[name] {
			releaseAll()
			return func() {}, false
		}
	}
	return releaseAll, true
}

func (a *Vane) prepareMediaReconnect(targetKey vaneMediaTargetKey, target string, port uint16, current string, currentBPS float64) (vaneMediaPlan, bool) {
	plan, reason := a.prepareMediaReconnectDetailed(targetKey, target, port, current, currentBPS)
	return plan, reason == ""
}

func (a *Vane) vaneMediaIdentityCurrent(name, identity string, nodeEpoch uint64) bool {
	if identity == "" {
		return true
	}
	release, current := a.lockVaneMediaIdentities(map[string]string{name: identity})
	if !current {
		return false
	}
	defer release()
	a.mu.Lock()
	a.learning.mu.Lock()
	state := a.nodes[name]
	stateCurrent := state != nil && state.identity == identity && state.epoch == nodeEpoch
	a.learning.mu.Unlock()
	a.mu.Unlock()
	return stateCurrent
}

func (a *Vane) prepareMediaReconnectDetailed(targetKey vaneMediaTargetKey, target string, port uint16, current string, currentBPS float64) (vaneMediaPlan, string) {
	return a.prepareMediaReconnectForNodeDetailed(targetKey, target, port, current, "", 0, currentBPS)
}

func (a *Vane) prepareMediaReconnectForNodeDetailed(targetKey vaneMediaTargetKey, target string, port uint16, current, identity string, nodeEpoch uint64, currentBPS float64) (vaneMediaPlan, string) {
	proxies := a.GetProxies(false)
	health := make([]vaneMediaHealth, 0, len(proxies))
	for _, proxy := range proxies {
		health = append(health, vaneMediaHealth{
			proxy: proxy,
			alive: proxy.AliveForTestUrl(a.testURL),
			delay: proxy.LastDelayForTestUrl(a.testURL),
		})
	}
	if identity != "" {
		release, current := a.lockVaneMediaIdentities(map[string]string{current: identity})
		if !current {
			return vaneMediaPlan{}, "stale-node-identity"
		}
		defer release()
	}
	now := a.clock.Now()

	a.mu.Lock()
	a.learning.mu.Lock()
	defer func() {
		a.learning.mu.Unlock()
		a.mu.Unlock()
	}()
	if identity != "" {
		state := a.nodes[current]
		if state == nil || state.identity != identity || state.epoch != nodeEpoch {
			return vaneMediaPlan{}, "stale-node-identity"
		}
	}
	a.pruneMediaLocked(now)
	if until := a.mediaReconnects[targetKey]; until.After(now) {
		return vaneMediaPlan{}, "reconnect-cooldown"
	}
	budget := a.mediaBudgets[targetKey]
	if budget.startedAt.IsZero() || !budget.startedAt.Add(a.media.budgetWindow).After(now) {
		budget = vaneMediaBudget{startedAt: now}
	}
	if budget.count >= a.media.budgetMax {
		return vaneMediaPlan{}, "budget-exhausted"
	}

	candidates := make([]vaneMediaChallenger, 0, len(health))
	for _, item := range health {
		proxy := item.proxy
		if proxy.Name() == current || !item.alive {
			continue
		}
		candidateKey := vaneMediaCandidateKey{vaneMediaTargetKey: targetKey, candidate: proxy.Name(), identity: vaneProxyPersistentIdentity(proxy)}
		if a.mediaSlowCooldowns[candidateKey].After(now) {
			continue
		}
		dialKey := vaneCooldownKey{transport: vaneTransportTCP, target: target, port: port, candidate: proxy.Name(), identity: vaneProxyPersistentIdentity(proxy)}
		if a.cooldownUntilLocked(dialKey, now, false).After(now) {
			continue
		}

		snapshot := vaneMetricsSnapshot{}
		var recent vaneRecentThroughput
		if state := a.nodes[proxy.Name()]; state != nil {
			snapshot = state.snapshot(vaneTransportTCP, now)
		}
		if state := a.nodeControls[proxy.Name()]; state != nil {
			recent = state.recentTCPThroughput
		}
		throughputBPS := 0.0
		knownGood := false
		freshThroughput := recent.bitsPerSecond > 0 && !recent.observedAt.IsZero() && now.Sub(recent.observedAt) <= vaneMediaEvidenceMaxAge
		if freshThroughput {
			throughputBPS = recent.bitsPerSecond
			knownGood = throughputBPS >= a.media.lowThroughputBPS && throughputBPS >= a.media.demandBPS && throughputBPS >= currentBPS*a.media.challengerRatio
			if !knownGood {
				continue
			}
		}
		if !knownGood && item.delay == 0 {
			continue
		}
		candidates = append(candidates, vaneMediaChallenger{
			proxy:         proxy,
			knownGood:     knownGood,
			throughputBPS: throughputBPS,
			scoreMicros:   scoreVaneMetrics(vaneSceneMedia, snapshot),
			delay:         item.delay,
		})
	}
	if len(candidates) == 0 {
		log.Debugln("Vane: suppress media reconnect target=%s:%d node=%s reason=no-challenger", target, port, current)
		return vaneMediaPlan{}, "no-challenger"
	}

	sort.Slice(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if left.knownGood != right.knownGood {
			return left.knownGood
		}
		if left.knownGood {
			if left.scoreMicros != right.scoreMicros {
				return left.scoreMicros < right.scoreMicros
			}
			if left.throughputBPS != right.throughputBPS {
				return left.throughputBPS > right.throughputBPS
			}
		}
		if left.delay != right.delay {
			return left.delay < right.delay
		}
		return left.proxy.Name() < right.proxy.Name()
	})

	return vaneMediaPlan{
		targetKey:          targetKey,
		target:             target,
		port:               port,
		current:            current,
		identity:           identity,
		nodeEpoch:          nodeEpoch,
		challenger:         candidates[0].proxy.Name(),
		challengerIdentity: vaneProxyPersistentIdentity(candidates[0].proxy),
		challengerEpoch: func() uint64 {
			if state := a.nodes[candidates[0].proxy.Name()]; state != nil && state.identity == vaneProxyPersistentIdentity(candidates[0].proxy) {
				return state.epoch
			}
			return a.learning.nodeEpochs[vaneLearningNodeKey(candidates[0].proxy.Name(), vaneProxyPersistentIdentity(candidates[0].proxy))]
		}(),
		targetStateKey: func() vaneTargetKey {
			key, _ := a.targetKeyForMedia(target, port)
			return key
		}(),
		generation: a.learningGeneration,
		knownGood:  candidates[0].knownGood,
		currentBPS: currentBPS,
		preparedAt: now,
	}, ""
}

func (a *Vane) commitMediaReconnect(plan vaneMediaPlan) bool {
	return a.commitMediaReconnectDetailed(plan) == ""
}

func (a *Vane) commitMediaReconnectDetailed(plan vaneMediaPlan) string {
	memberHealthy := false
	for _, proxy := range a.GetProxies(false) {
		if proxy.Name() == plan.challenger && proxy.AliveForTestUrl(a.testURL) {
			memberHealthy = true
		}
	}
	if !memberHealthy {
		return "challenger-unhealthy"
	}
	if plan.identity != "" {
		release, current := a.lockVaneMediaIdentities(map[string]string{
			plan.current:    plan.identity,
			plan.challenger: plan.challengerIdentity,
		})
		if !current {
			return "stale-node-identity"
		}
		defer release()
	}
	now := a.clock.Now()
	a.mu.Lock()
	a.learning.mu.Lock()
	defer func() {
		a.learning.mu.Unlock()
		a.mu.Unlock()
	}()
	if plan.identity != "" {
		state := a.nodes[plan.current]
		if state == nil || state.identity != plan.identity || state.epoch != plan.nodeEpoch {
			return "stale-node-identity"
		}
	}
	a.pruneMediaLocked(now)
	if now.Sub(plan.preparedAt) > a.media.hintTTL {
		return "plan-expired"
	}
	if a.mediaReconnects[plan.targetKey].After(now) {
		return "reconnect-cooldown"
	}
	dialKey := vaneCooldownKey{transport: vaneTransportTCP, target: plan.target, port: plan.port, candidate: plan.challenger, identity: plan.challengerIdentity}
	if a.cooldownUntilLocked(dialKey, now, false).After(now) {
		return "candidate-cooldown"
	}
	challengerKey := vaneMediaCandidateKey{vaneMediaTargetKey: plan.targetKey, candidate: plan.challenger, identity: plan.challengerIdentity}
	if a.mediaSlowCooldowns[challengerKey].After(now) {
		return "challenger-slow-cooldown"
	}
	if state := a.nodeControls[plan.challenger]; state != nil {
		recent := state.recentTCPThroughput
		if recent.bitsPerSecond > 0 && !recent.observedAt.IsZero() && now.Sub(recent.observedAt) <= vaneMediaEvidenceMaxAge &&
			(recent.bitsPerSecond < a.media.lowThroughputBPS || recent.bitsPerSecond < plan.currentBPS*a.media.challengerRatio) {
			return "challenger-evidence-degraded"
		}
	}
	budget := a.mediaBudgets[plan.targetKey]
	if budget.startedAt.IsZero() || !budget.startedAt.Add(a.media.budgetWindow).After(now) {
		budget = vaneMediaBudget{startedAt: now}
	}
	if budget.count >= a.media.budgetMax {
		return "budget-exhausted"
	}
	budget.count++
	a.mediaBudgets[plan.targetKey] = budget
	currentKey := vaneMediaCandidateKey{vaneMediaTargetKey: plan.targetKey, candidate: plan.current, identity: plan.identity}
	a.mediaSlowCooldowns[currentKey] = now.Add(a.media.slowCooldown)
	handoff := a.diagnostics.recordReconnectCommit(vaneDiagnosticRecord{
		target:     plan.target,
		bucket:     plan.targetKey.target,
		port:       plan.port,
		from:       plan.current,
		to:         plan.challenger,
		bps:        plan.currentBPS,
		totalBytes: plan.totalBytes,
		age:        plan.age,
		lowWindows: plan.lowWindows,
		force:      true,
	})
	a.mediaHints[plan.targetKey] = vaneMediaHint{
		candidate: plan.challenger,
		identity:  plan.challengerIdentity,
		expiresAt: now.Add(a.media.hintTTL),
		handoff:   handoff,
	}
	a.mediaReconnects[plan.targetKey] = now.Add(a.media.reconnectCooldown)
	return ""
}

func (a *Vane) mediaTargetKey(target string, port uint16) vaneMediaTargetKey {
	host := normalizeVaneMediaTarget(target)
	for _, domain := range a.media.domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return vaneMediaTargetKey{target: domain, port: port}
		}
	}
	// Round8 item 3: RULE-SET entries are checked after plain domains, and a
	// hit scopes by the provider name — "scope is what the config names", so
	// one provider per service or one provider for all streaming is the
	// user's choice.
	for _, name := range a.media.ruleSets {
		provider, ok := tunnel.RuleProviders()[name]
		if !ok {
			continue
		}
		if provider.Match(&C.Metadata{Host: host}, C.RuleMatchHelper{}) {
			return vaneMediaTargetKey{target: name, port: port}
		}
	}
	// Round8.5: GEOSITE entries resolve against the shared GeoSite database —
	// no extra download — and scope by the category name. Fail-closed like
	// every geodata path: a missing database is "no match", never an error.
	for _, category := range a.media.geoSites {
		matcher, err := geodata.LoadGeoSiteMatcher(category)
		if err != nil {
			continue
		}
		if matcher.ApplyDomain(host) {
			return vaneMediaTargetKey{target: category, port: port}
		}
	}
	return vaneMediaTargetKey{port: port}
}

func normalizeVaneMediaTarget(target string) string {
	normalized, valid := normalizeVaneDomain(target)
	if !valid {
		return ""
	}
	return normalized
}

func (a *Vane) takeMediaHintLocked(target string, port uint16, proxies []C.Proxy, now time.Time, claimHandoff bool) (C.Proxy, *vaneHandoffToken) {
	key := a.mediaTargetKey(target, port)
	if key.target == "" {
		return nil, nil
	}
	hint, ok := a.mediaHints[key]
	if !ok {
		return nil, nil
	}
	if !hint.expiresAt.After(now) {
		delete(a.mediaHints, key)
		return nil, nil
	}
	for _, proxy := range proxies {
		if proxy.Name() != hint.candidate ||
			(hint.identity != "" && vaneProxyPersistentIdentity(proxy) != hint.identity) ||
			!proxy.AliveForTestUrl(a.testURL) {
			continue
		}
		dialKey := vaneCooldownKey{transport: vaneTransportTCP, target: target, port: port, candidate: proxy.Name(), identity: vaneProxyPersistentIdentity(proxy)}
		if a.cooldownUntilLocked(dialKey, now, false).After(now) {
			return nil, nil
		}
		mediaKey := vaneMediaCandidateKey{vaneMediaTargetKey: key, candidate: proxy.Name(), identity: vaneProxyPersistentIdentity(proxy)}
		if a.mediaSlowCooldowns[mediaKey].After(now) {
			return nil, nil
		}
		var handoff *vaneHandoffToken
		if claimHandoff && hint.handoff != nil &&
			hint.handoff.target == normalizeVaneMediaTarget(target) &&
			hint.handoff.port == port && hint.handoff.to == proxy.Name() {
			handoff = hint.handoff
			hint.handoff = nil
			a.mediaHints[key] = hint
		}
		return proxy, handoff
	}
	return nil, nil
}

func (a *Vane) mediaCooldownUntilLocked(target string, port uint16, candidate string, now time.Time) time.Time {
	return a.mediaCooldownUntilLockedWithCleanup(target, port, candidate, "", now, true)
}

func (a *Vane) mediaCooldownUntilLockedWithCleanup(target string, port uint16, candidate, identity string, now time.Time, cleanup bool) time.Time {
	targetKey := a.mediaTargetKey(target, port)
	if targetKey.target == "" {
		return time.Time{}
	}
	key := vaneMediaCandidateKey{
		vaneMediaTargetKey: targetKey,
		candidate:          candidate,
		identity:           identity,
	}
	until := a.mediaSlowCooldowns[key]
	if !until.After(now) && !until.IsZero() {
		if cleanup {
			delete(a.mediaSlowCooldowns, key)
		}
		return time.Time{}
	}
	return until
}

func (a *Vane) mediaCandidateCoolingLocked(candidate string, now time.Time) bool {
	return a.mediaCandidateCoolingLockedWithCleanup(candidate, "", now, true)
}

func (a *Vane) mediaCandidateCoolingLockedWithCleanup(candidate, identity string, now time.Time, cleanup bool) bool {
	cooling := false
	for key, until := range a.mediaSlowCooldowns {
		if !until.After(now) {
			if cleanup {
				delete(a.mediaSlowCooldowns, key)
			}
			continue
		}
		if key.candidate == candidate && (identity == "" || key.identity == "" || key.identity == identity) {
			cooling = true
		}
	}
	return cooling
}

func (a *Vane) pruneMediaLocked(now time.Time) {
	for key, hint := range a.mediaHints {
		if !hint.expiresAt.After(now) {
			delete(a.mediaHints, key)
		}
	}
	for key, until := range a.mediaReconnects {
		if !until.After(now) {
			delete(a.mediaReconnects, key)
		}
	}
	for key, until := range a.mediaSlowCooldowns {
		if !until.After(now) {
			delete(a.mediaSlowCooldowns, key)
		}
	}
	for key, budget := range a.mediaBudgets {
		if !budget.startedAt.Add(a.media.budgetWindow).After(now) {
			delete(a.mediaBudgets, key)
		}
	}
}
