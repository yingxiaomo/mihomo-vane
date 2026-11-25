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
	// These media thresholds are behavior constants, not user policy knobs.
	// Changing them requires a kernel rebuild; demand, scope and switches remain configurable.
	vaneDefaultMediaLowThroughputBPS = int64(5_000_000)
	vaneDefaultMediaLowWindows       = 3
	vaneDefaultMediaMaxLowWindows    = 4
	vaneDefaultMediaMinAge           = 15 * time.Second
	vaneDefaultMediaMinBytes         = int64(2 * 1024 * 1024)
	vaneDefaultMediaDemandBPS        = int64(1_000_000)
	vaneDefaultMediaBufferGuard      = 5 * time.Second
	vaneDefaultMediaReconnectDelay   = 10 * time.Minute
	// BREAK-WINDOW: a switch that lands on a worse node must not freeze the
	// target for the whole reconnect cooldown. Once the new flow is starving
	// again and this window has passed, one retry is allowed; the budget still
	// caps the total number of switches per window.
	vaneMediaBreakWindow            = 5 * time.Minute
	vaneDefaultMediaSlowCooldown    = 30 * time.Minute
	vaneDefaultMediaHintTTL         = 15 * time.Second
	vaneDefaultMediaChallengerRatio = 1.25
	vaneDefaultMediaBudgetMax       = 3
	vaneDefaultMediaBudgetWindow    = 30 * time.Minute
	vaneMediaEvidenceMaxAge         = 10 * time.Minute
	vaneMaximumMediaThroughputBPS   = int64(1_000_000_000)
	// B-part degradation lines. Loss reuses the 5% the B2 loss EMA already
	// treats as degraded (healthy paths retransmit < 1%); latency is where a
	// video path is visibly unusable (production saw 800 ms), far above the
	// 50-200 ms a healthy CDN path keeps.
	vaneDefaultMediaHighLossRate = 0.05
	vaneDefaultMediaHighLatency  = 500 * time.Millisecond
	// §E: the re-evaluation valve. A flow that was just switched to and keeps
	// producing no qualified samples gets one prepare re-run per target per
	// throttle window, so a bad challenger cannot lock the target for the full
	// reconnect cooldown while it never produces enough bytes to settle.
	vaneMediaValveEmptyWindows = 2
	vaneMediaValveThrottle     = 10 * time.Minute
	// P1 (background mis-close): the observed rate is the delivery rate
	// (min(node, client)), so a client that throttles briefly (background
	// tab) looks like a slow node. A low window within this window of the
	// last non-low sample is graced — not counted toward the trigger. It
	// only delays a genuine collapse (by up to the grace plus the remaining
	// windows), never cancels it.
	vaneMediaFastGrace = 30 * time.Second
	// §2.4 stall watchdog: a flow that delivered samples and then went fully
	// silent (open connection, zero reads) produces no windows at all, so the
	// trigger can never fire. After this much silence the watchdog feeds a
	// synthetic near-zero window through the normal observe path so the
	// grace, trigger, race and prepare chain all apply. The tick
	// granularity bounds how late the first synthetic window can arrive.
	vaneMediaStallSilence = 10 * time.Second
	vaneMediaWatchdogTick = 5 * time.Second
	// BACKLOG-STREAK: how long one backlog sighting excuses low windows.
	// A backgrounded player (browser tab, phone screen off) throttles or
	// stops reading, so its delivery rate collapses while the node is fine.
	// The backlog probe only reports while bytes are unwritten, which is
	// intermittent for a throttled-but-alive reader, so the excuse has to
	// outlive the probe's own tick by a wide margin. Without this the
	// "recently-fast" branch counted those windows and closed healthy
	// flows after a few minutes in the background.
	vaneMediaBacklogGrace = 90 * time.Second
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

	// PHASE1: demand-bps is the new key. media-demand-bps still parses so an
	// existing config keeps working; the new key wins when both are set.
	demand := option.DemandBPS
	if option.MediaDemandBPS != 0 {
		log.Warnln("Vane: media-demand-bps is deprecated, use demand-bps")
		if demand == 0 {
			demand = option.MediaDemandBPS
		}
	}
	if int64(demand) < 0 || int64(demand) > vaneMaximumMediaThroughputBPS {
		return vaneMediaConfig{}, fmt.Errorf("demand-bps must be between 0 and %d", vaneMaximumMediaThroughputBPS)
	}
	if demand > 0 {
		config.demandBPS = float64(demand)
	}
	// §L: the low-window trigger line follows the group's demand (floored at
	// the 5M default). demand already dominates the close bar, knownGood and
	// the settlement line; a 4K-demand group must also accumulate low windows
	// below its own bar, or a 40→10 drop never triggers at all.
	if config.demandBPS > config.lowThroughputBPS {
		config.lowThroughputBPS = config.demandBPS
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

// vaneMediaNodeKey scopes a cooldown or budget to (target, node) instead of the
// whole target. NODE-SCOPE: one slow node must be punished alone — a target is
// usually shared by many concurrent player connections, and a domain-wide
// quota let one bad node burn the whole budget for every other connection on
// the same target (the field symptom: five rejections with reason
// budget-exhausted while three connections sat dead on one node).
type vaneMediaNodeKey struct {
	vaneMediaTargetKey
	candidate string
}

func vaneMediaNodeKeyFor(targetKey vaneMediaTargetKey, candidate string) vaneMediaNodeKey {
	return vaneMediaNodeKey{vaneMediaTargetKey: targetKey, candidate: candidate}
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

	mu         sync.Mutex
	lowWindows int
	// P1 grace: when the last non-low sample arrived (zero = never fast).
	lastNonLowAt time.Time
	// §2.4: the last real sample and when it arrived. A flow that has a
	// sample but then goes silent is a stall candidate; a flow that never
	// sampled is just starting and is left alone.
	lastSampleAt    time.Time
	lastSample      vaneThroughputObservation
	hasSample       bool
	aborted         bool
	closed          bool
	handoff         *vaneHandoffToken
	raceSeq         uint64
	raceToken       uint64
	policySubmitter func(vanePolicyAction, bool)
	flowCountOnce   sync.Once
	// PHASE1: only a configured media target holds a B2 media-flow count.
	// Every TCP flow is watched, but the count keeps its media meaning.
	counted bool
	// PHASE2: a flow that matches a configured media target keeps media
	// semantics (its own diagnostics and target-evidence writes). Other TCP
	// flows are watched and may now be switched, but stay out of the
	// media-only bookkeeping.
	flowMedia bool
	// §E: only the flow that claimed the handoff token (the connection the
	// switch was made for) arms the re-evaluation valve. valveCurrentBPS
	// keeps the pre-switch speed from the token for the re-run prepare.
	switchedTo        bool
	valveCurrentBPS   float64
	valveEmptyWindows int
	// §6 backlog: the last time the watchdog saw unwritten bytes queued on the
	// connection. A low window is not counted for two ticks after that, since
	// the client, not the node, was the bottleneck.
	backloggedAt time.Time
	backlogFunc  func() int64
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
		if f.counted {
			f.group.mediaFlowEnded(f.candidate)
		}
		f.group.forgetMediaFlow(f)
	})
}

func newVaneMediaFlow(group *Vane, candidate string, metadata *C.Metadata, handoff ...*vaneHandoffToken) *vaneMediaFlow {
	if group == nil || !group.media.enabled {
		return nil
	}
	target, port := vaneTarget(metadata)
	if target == "" {
		return nil
	}
	// PHASE2: every TCP flow gets a target scope so a stalled download can be
	// rescued the same way a video flow is. A media target keeps its
	// rule-derived scope and its target state; any other host gets a per-host
	// scope and skips the target-evidence writes (it has no rule identity).
	mediaKey := group.mediaTargetKey(target, port)
	flowMedia := mediaKey.target != ""
	targetKey := mediaKey
	if !flowMedia {
		targetKey = vaneMediaTargetKey{target: target, port: port}
	}
	targetStateKey, _ := group.targetKeyForMedia(target, port)
	flow := &vaneMediaFlow{group: group, candidate: candidate, target: target, port: port, targetKey: targetKey, targetStateKey: targetStateKey, flowMedia: flowMedia}
	if len(handoff) > 0 && handoff[0] != nil {
		flow.handoff = handoff[0]
		// §E: this flow is the one the switch was made for — arm the
		// re-evaluation valve with the pre-switch speed.
		flow.switchedTo = true
		flow.valveCurrentBPS = handoff[0].previousBPS
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
	if flowMedia {
		flow.counted = true
		group.mediaFlowStarted(candidate)
	}
	// §2.4: the watchdog only watches flows that have actually delivered
	// samples, so registration is cheap and silence is measured against the
	// flow's own sample clock.
	group.trackMediaFlow(flow)
	return flow
}

// trackMediaFlow registers an active media flow with the stall watchdog and
// starts the group's single ticker goroutine on first use.
func (a *Vane) trackMediaFlow(flow *vaneMediaFlow) {
	if a == nil || flow == nil {
		return
	}
	a.mediaFlowsMu.Lock()
	if a.mediaFlowSet == nil {
		a.mediaFlowSet = make(map[*vaneMediaFlow]struct{})
	}
	a.mediaFlowSet[flow] = struct{}{}
	a.mediaFlowsMu.Unlock()
	a.mediaWatchdogOnce.Do(func() {
		go a.mediaWatchdogLoop()
	})
}

// forgetMediaFlow drops a settled media flow from the watchdog set.
func (a *Vane) forgetMediaFlow(flow *vaneMediaFlow) {
	if a == nil || flow == nil {
		return
	}
	a.mediaFlowsMu.Lock()
	delete(a.mediaFlowSet, flow)
	a.mediaFlowsMu.Unlock()
}

// mediaWatchdogLoop is the group's single stall ticker. It stops when the
// group closes (racingRuntime.ctx is canceled in stopRacing).
func (a *Vane) mediaWatchdogLoop() {
	ticker := time.NewTicker(vaneMediaWatchdogTick)
	defer ticker.Stop()
	for {
		select {
		case <-a.racingRuntime.ctx.Done():
			return
		case <-ticker.C:
			a.runMediaWatchdogTick(a.clock.Now())
		}
	}
}

// runMediaWatchdogTick feeds synthetic near-zero windows to flows that were
// delivering samples and then went silent while still open. The synthetic
// window goes through the normal observe() path, so the grace, low-window
// trigger, race and prepare chain all apply unchanged — the
// watchdog only makes "fully stalled" visible to a trigger that is otherwise
// sample-driven.
func (a *Vane) runMediaWatchdogTick(now time.Time) {
	a.mediaFlowsMu.Lock()
	flows := make([]*vaneMediaFlow, 0, len(a.mediaFlowSet))
	for flow := range a.mediaFlowSet {
		flows = append(flows, flow)
	}
	a.mediaFlowsMu.Unlock()
	for _, flow := range flows {
		// Backlog first: the synthetic window below must already see it.
		flow.noteBacklog(now)
		flow.observeSyntheticStall(now)
	}
}

// observeSyntheticStall synthesizes one silent window for a stalled flow.
// Flows that never sampled are just starting — left alone. A flow that was
// fast within the grace window is graced by observe() itself, so a paused
// player is not switched until the grace expires.
func (f *vaneMediaFlow) observeSyntheticStall(now time.Time) {
	if f == nil {
		return
	}
	f.mu.Lock()
	if f.closed || f.aborted || !f.hasSample || f.lastSampleAt.IsZero() ||
		now.Sub(f.lastSampleAt) < vaneMediaStallSilence {
		f.mu.Unlock()
		return
	}
	last := f.lastSample
	silence := now.Sub(f.lastSampleAt)
	f.mu.Unlock()
	// BPS must stay positive: observe() treats <= 0 as "no sample". The byte
	// total is the last real cumulative total (nothing arrived since), and
	// the age advances by the silence so the age/min-bytes gates see truth.
	synthetic := vaneThroughputObservation{
		BitsPerSecond: 1,
		untrusted:     true,
		synthetic:     true,
		TotalBytes:    last.TotalBytes,
		Age:           last.Age + silence,
	}
	// The watchdog used to drop the action observe() returned, so a stalled
	// flow's immediate plan (knownGood baseline) never ran at all.
	if action := f.observe(synthetic); action != nil {
		f.submitPolicyAction(action, vaneActionIsImmediate(synthetic))
	}
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

func (f *vaneMediaFlow) setBacklogFunc(probe func() int64) {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.backlogFunc = probe
	f.mu.Unlock()
}

// noteBacklog stamps the flow when the connection is holding unwritten bytes.
// The probe runs outside f.mu: it takes vaneObservedConn.mu, and observeRead
// calls its callbacks only after dropping that lock.
func (f *vaneMediaFlow) noteBacklog(now time.Time) {
	if f == nil {
		return
	}
	f.mu.Lock()
	if f.closed || f.aborted {
		f.mu.Unlock()
		return
	}
	probe := f.backlogFunc
	f.mu.Unlock()
	if probe == nil || probe() <= 0 {
		return
	}
	f.mu.Lock()
	if !f.closed && !f.aborted {
		f.backloggedAt = now
	}
	f.mu.Unlock()
}

func (f *vaneMediaFlow) setPolicySubmitter(submitter func(vanePolicyAction, bool)) {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.policySubmitter = submitter
	f.mu.Unlock()
}

// vaneActionIsImmediate: a synthetic (watchdog) window means the flow stopped
// reading, so parking its action would wait for a read that never comes — the
// "found a better node and never switched" stall.
func vaneActionIsImmediate(sample vaneThroughputObservation) bool {
	return sample.Delivered || sample.synthetic
}

func (f *vaneMediaFlow) submitPolicyAction(action vanePolicyAction, delivered bool) {
	if f == nil || action == nil {
		return
	}
	if f.group.racing.mode == vaneRacingShadow {
		f.group.diagnostics.record(vaneDiagnosticRecord{
			kind: "handoff-would-commit", reason: "dry-run", target: f.target,
			bucket: f.targetKey.target, port: f.port, from: f.candidate,
		})
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
	if f.aborted || f.closed {
		f.mu.Unlock()
		return nil
	}
	lowLoss := sample.LossSupported && sample.LossRate > vaneDefaultMediaHighLossRate
	// B-part: throughput is no longer the only degradation signal. Loss and
	// latency only count when the kernel actually reported them; latency also
	// needs delivered data this window, because srtt keeps its last value on a
	// silent socket (a paused flow must not be judged by a stale RTT).
	lowLatency := sample.LatencySupported && sample.Delivered && sample.Latency > vaneDefaultMediaHighLatency
	low := sample.BitsPerSecond < config.lowThroughputBPS || lowLoss || lowLatency
	lowSignal := ""
	if sample.BitsPerSecond < config.lowThroughputBPS {
		lowSignal = "throughput"
	} else if lowLoss {
		lowSignal = "loss"
	} else if lowLatency {
		lowSignal = "latency"
	}
	now := f.group.clock.Now()
	// D: the node's RTT EMA is fed by real kernel readings only. It is
	// independent of the low-window decision, so it feeds before the grace
	// bookkeeping below.
	if sample.LatencySupported && sample.Latency > 0 {
		f.group.recordLatencyIdentity(f.candidate, f.identity, f.nodeEpoch, sample.Latency)
	}
	graceReason := ""
	if low {
		// P1 grace: the measured rate is the delivery rate, so a brief client
		// throttle (background tab) can dip below the line while the node is
		// fine. A low sample within vaneMediaFastGrace of the last non-low
		// sample only delays the streak — it never cancels a genuine collapse,
		// which keeps accumulating once the grace is over.
		//
		// §6 backlog: unwritten bytes on the connection are direct proof the
		// client is behind, which is stronger than "it was fast recently", so
		// it wins when both apply.
		//
		// STALL-STREAK: only client backlog excuses a low window from the
		// streak. "recently-fast" still marks the window untrusted (no
		// evidence is written) but no longer skips the count. A bursty node
		// that delivers one fast window every 30s used to refresh the grace
		// forever, so a flow that stalled between bursts never reached the
		// switch threshold and the player stayed stuck on a half-dead node.
		switch {
		case !f.backloggedAt.IsZero() && now.Sub(f.backloggedAt) < vaneMediaBacklogGrace:
			graceReason = "client-backlog"
			// BACKLOG-STREAK: a client that is not reading (background tab,
			// paused player, phone screen off) produces low delivery windows
			// that say nothing about the node, so the streak is cleared and a
			// return to the foreground starts from zero.
			f.lowWindows = 0
		case !f.lastNonLowAt.IsZero() && now.Sub(f.lastNonLowAt) < vaneMediaFastGrace:
			graceReason = "recently-fast"
			f.lowWindows++
		default:
			f.lowWindows++
		}
	} else {
		// STALL-STREAK: decay instead of reset. A throughput pulse between
		// two silent windows is not a recovery; zeroing the streak let a
		// bursty node hold the flow indefinitely. A healthy flow never
		// accumulates a low window, so decay only changes degraded paths.
		if f.lowWindows > 0 {
			f.lowWindows--
		}
		f.lastNonLowAt = now
		// A recovered flow invalidates any in-flight race: its result belongs
		// to the previous low-window streak, not the next one (RACE-06).
		f.raceToken = 0
	}
	// §E: a qualified sample resets the valve's empty-window streak.
	f.valveEmptyWindows = 0
	// §2.4: the flow is alive; the stall watchdog counts silence from here.
	f.lastSampleAt = now
	f.lastSample = sample
	f.hasSample = true
	lowWindows := f.lowWindows
	handoff := f.handoff
	f.handoff = nil
	f.mu.Unlock()

	// PHASE1: every TCP flow is observed, but only a configured media target
	// owns target state, may arm a switch, and emits per-sample diagnostics.
	// A flow with an empty targetKey still counts low windows so the phase-2
	// rollout has data, without flooding the log with one record per window.
	mediaTarget := f.flowMedia
	if mediaTarget {
		f.group.diagnostics.record(vaneDiagnosticRecord{
			kind:          "throughput-sample",
			target:        f.target,
			bucket:        f.targetKey.target,
			port:          f.port,
			from:          f.candidate,
			bps:           sample.BitsPerSecond,
			totalBytes:    sample.TotalBytes,
			age:           sample.Age,
			lowWindows:    lowWindows,
			low:           low,
			lowSignal:     lowSignal,
			latencyMillis: sample.Latency.Milliseconds(),
			lossRate:      sample.LossRate,
		})
		if graceReason != "" {
			f.group.diagnostics.record(vaneDiagnosticRecord{
				kind:       "low-window-graced",
				reason:     graceReason,
				target:     f.target,
				bucket:     f.targetKey.target,
				port:       f.port,
				from:       f.candidate,
				bps:        sample.BitsPerSecond,
				totalBytes: sample.TotalBytes,
				age:        sample.Age,
				lowWindows: lowWindows,
			})
		}
	}
	untrusted := sample.untrusted || graceReason != ""
	// Client throttling and synthetic windows trigger policy, never node-health writes.
	if !untrusted && mediaTarget {
		f.group.recordTargetEvidence(f.targetStateKey, member, sample.BitsPerSecond, lowLoss || lowLatency)
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
			})
			f.group.settleTargetHandoff(handoff, member, sample)
		}
	}
	if lowWindows < config.lowWindows || sample.Age < config.minAge || sample.TotalBytes < config.minBytes {
		return nil
	}
	creditBits := float64(sample.TotalBytes)*8 - config.demandBPS*sample.Age.Seconds()
	guardBits := config.demandBPS * config.bufferGuard.Seconds()
	// CREDIT-STALL: the credit is a lifetime average (bytes read so far minus
	// what the demand line would have used), so it only answers "was this flow
	// fast on average". A synthetic window is ten seconds of zero bytes: the
	// node stopped delivering, and the credit earned during the fast part of
	// its life must not buy it more patience. Letting it do so is how a
	// connection that downloaded 754 MB and then died kept its slot until the
	// streak reached maxLowWindows.
	if !sample.synthetic && creditBits < guardBits && lowWindows < config.maxLowWindows {
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
		})
		log.Debugln("Vane: defer media reconnect target=%s:%d node=%s reason=buffer-credit bps=%.0f credit=%.0f guard=%.0f low-windows=%d/%d", f.target, f.port, f.candidate, sample.BitsPerSecond, creditBits, guardBits, lowWindows, config.maxLowWindows)
		return nil
	}

	// COOLDOWN-STARVE-01: a cooldown armed by an earlier commit must not freeze
	// a flow that is already starving past the credit guard; the reconnect
	// budget (3/30min) still bounds thrash. Same exemption rides the plan, so
	// the commit gates honor it too; it also skips the queued-action recovery
	// recheck, which only guards against a burst that arrives before the close.
	starving := lowWindows >= config.maxLowWindows && creditBits < guardBits
	plan, reason := f.group.prepareMediaReconnectForNodeDetailedSkipCooldown(f.targetKey, f.target, f.port, f.candidate, f.identity, f.nodeEpoch, sample.BitsPerSecond, starving)
	mode := f.group.racing.mode
	if reason != "" && reason != "no-challenger" && reason != "no-evidence-candidate" {
		f.recordReconnectSuppressed(reason, sample, lowWindows)
		return nil
	}

	if mode == vaneRacingShadow {
		if reason == "" {
			f.group.diagnostics.record(vaneDiagnosticRecord{
				kind: "handoff-would-commit", reason: "baseline", target: f.target,
				bucket: f.targetKey.target, port: f.port, from: f.candidate, to: plan.challenger,
				bps: sample.BitsPerSecond, totalBytes: sample.TotalBytes, age: sample.Age,
				lowWindows: lowWindows,
			})
		} else {
			f.recordReconnectSuppressed(reason, sample, lowWindows)
		}
		if reason != "" || !plan.knownGood {
			f.scheduleRace(sample, lowWindows)
		}
		return nil
	}

	if reason == "" && plan.knownGood {
		f.completeMediaPlan(&plan, sample, lowWindows)
		return f.policyActionForPlan(plan, sample, lowWindows, true)
	}
	if reason == "no-evidence-candidate" {
		f.recordReconnectSuppressed(reason, sample, lowWindows)
	}
	f.scheduleRace(sample, lowWindows)
	return nil
}

func (f *vaneMediaFlow) recordReconnectSuppressed(reason string, sample vaneThroughputObservation, lowWindows int) {
	f.group.diagnostics.record(vaneDiagnosticRecord{
		kind: "reconnect-suppressed", reason: reason, target: f.target, bucket: f.targetKey.target,
		port: f.port, from: f.candidate, bps: sample.BitsPerSecond, totalBytes: sample.TotalBytes,
		age: sample.Age, lowWindows: lowWindows,
	})
}

func (f *vaneMediaFlow) completeMediaPlan(plan *vaneMediaPlan, sample vaneThroughputObservation, lowWindows int) {
	plan.totalBytes = sample.TotalBytes
	plan.age = sample.Age
	plan.lowWindows = lowWindows
	f.group.diagnostics.record(vaneDiagnosticRecord{
		kind: "reconnect-prepared", target: f.target, bucket: f.targetKey.target, port: f.port,
		from: f.candidate, to: plan.challenger, bps: sample.BitsPerSecond, totalBytes: sample.TotalBytes,
		age: sample.Age, lowWindows: lowWindows,
	})
}

func (f *vaneMediaFlow) raceRequest(sample vaneThroughputObservation, lowWindows int) vaneRaceRequest {
	// RESCUE: the race asks for a node that beats the current flow, not one that
	// already reaches demand — a 1 bps flow would otherwise race for nothing.
	required := sample.BitsPerSecond * f.group.media.challengerRatio
	// RESCUE-FLOOR: the absolute floor is the 5M slow line, never the
	// demand-inflated lowThroughputBPS (which §L raises to demand).
	if floor := float64(vaneDefaultMediaLowThroughputBPS); required < floor {
		required = floor
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
	token, ok := f.beginRaceToken()
	if !ok {
		return
	}
	request := f.raceRequest(sample, lowWindows)
	scheduled, reason := f.group.scheduleMediaRace(request, func(result vaneRaceResult) {
		// The race is asynchronous: the flow may have recovered, closed, or
		// started a new low-window round between the trigger and this callback.
		// Only the round that scheduled this race may act on its result.
		closed, recovered, stale := f.raceVerdict(token)
		if closed {
			return
		}
		if recovered {
			f.group.diagnostics.record(vaneDiagnosticRecord{
				kind: "reconnect-rejected", reason: "flow-recovered", handoffID: result.taskID, target: f.target,
				bucket: f.targetKey.target, port: f.port, from: f.candidate, to: result.winner.name,
				bps: result.lowerBoundBPS,
			})
			return
		}
		if stale {
			f.group.diagnostics.record(vaneDiagnosticRecord{
				kind: "race-stale", reason: "stale-generation", handoffID: result.taskID, target: f.target,
				bucket: f.targetKey.target, port: f.port, from: f.candidate, to: result.winner.name,
				bps: result.lowerBoundBPS,
			})
			return
		}
		if f.group.racing.mode == vaneRacingShadow {
			f.group.diagnostics.record(vaneDiagnosticRecord{
				kind: "handoff-would-commit", reason: result.source, handoffID: result.taskID,
				leaseID: vaneRaceLeaseID(result.request.generation, result.taskID), target: f.target,
				bucket: f.targetKey.target, port: f.port, from: f.candidate, to: result.winner.name,
				bps: result.lowerBoundBPS, previousBPS: sample.BitsPerSecond, totalBytes: sample.TotalBytes,
				age: sample.Age, lowWindows: lowWindows,
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
		f.submitPolicyAction(f.policyActionForPlan(plan, sample, lowWindows, true), vaneActionIsImmediate(sample))
	}, func() {
		f.clearRaceToken(token)
	})
	if !scheduled {
		f.clearRaceToken(token)
		if reason != "race-in-flight" && reason != "no-winner-cooldown" {
			f.recordReconnectSuppressed(reason, sample, lowWindows)
		}
	}
}

func (f *vaneMediaFlow) policyActionForPlan(plan vaneMediaPlan, sample vaneThroughputObservation, lowWindows int, targetCommit bool) vanePolicyAction {
	return func() bool {
		f.mu.Lock()
		aborted, closed := f.aborted, f.closed
		// SYNC-RECHECK: the queued action can sit in pendingAction while the
		// flow keeps reading. If a fast window ran observe() in between, the
		// low-window streak was reset — the recovery already happened and the
		// close must not fire. Known limit: a flow that only reads via direct
		// reads keeps its old lowWindows here, so this re-check catches
		// recoveries that observe() actually saw, nothing more.
		// §E: valve plans skip this recheck — their flow has not produced any
		// samples, so lowWindows == 0 means "no data", not "recovered".
		lowWindowsNow := f.lowWindows
		f.mu.Unlock()
		if closed {
			// The connection already won the close race. Do not turn a
			// natural close into a handoff commit.
			return false
		}
		if aborted {
			f.group.diagnostics.record(vaneDiagnosticRecord{
				kind: "reconnect-rejected", reason: "already-committed", handoffID: plan.raceID,
				leaseID: vaneRaceLeaseID(plan.generation, plan.raceID), target: f.target,
				bucket: f.targetKey.target, port: f.port, from: f.candidate, to: plan.challenger,
				bps: sample.BitsPerSecond,
			})
			return false
		}
		if !plan.skipReconnectCooldown && lowWindowsNow < f.group.media.lowWindows {
			f.group.diagnostics.record(vaneDiagnosticRecord{
				kind: "reconnect-rejected", reason: "recovered", handoffID: plan.raceID,
				leaseID: vaneRaceLeaseID(plan.generation, plan.raceID), target: f.target,
				bucket: f.targetKey.target, port: f.port, from: f.candidate, to: plan.challenger,
				bps: sample.BitsPerSecond,
			})
			return false
		}
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
				bps: sample.BitsPerSecond,
			})
			return false
		}
		f.mu.Lock()
		f.aborted = true
		f.mu.Unlock()
		log.Infoln("Vane: media reconnect target=%s:%d bucket=%s from=%s to=%s bps=%.0f low-windows=%d", f.target, f.port, f.targetKey.target, f.candidate, plan.challenger, sample.BitsPerSecond, lowWindows)
		// FANOUT: the switch must cancel every sibling flow on the same target
		// that is still pinned to the node we just left. A player streams a
		// video over several concurrent connections; closing only the flow
		// that happened to trip the watchdog leaves the others stalled on the
		// same slow node, which is exactly what "switched but still stuck"
		// looked like in the field. Siblings are closed, never committed: the
		// budget, cooldown and hint are already written by this commit.
		for _, sibling := range f.group.mediaSiblingFlows(plan.targetKey, f.candidate, f) {
			sibling.submitPolicyAction(sibling.siblingCloseAction(plan, sample), true)
		}
		return true
	}
}

// mediaSiblingFlows snapshots the other active flows for the same target that
// are still on candidate, so a committed switch can close them too.
func (a *Vane) mediaSiblingFlows(targetKey vaneMediaTargetKey, candidate string, exclude *vaneMediaFlow) []*vaneMediaFlow {
	if a == nil {
		return nil
	}
	a.mediaFlowsMu.Lock()
	defer a.mediaFlowsMu.Unlock()
	var siblings []*vaneMediaFlow
	for flow := range a.mediaFlowSet {
		if flow == exclude || flow == nil {
			continue
		}
		if flow.targetKey != targetKey || flow.candidate != candidate {
			continue
		}
		siblings = append(siblings, flow)
	}
	return siblings
}

// siblingCloseAction closes a flow without running the commit again. The
// per-flow view is re-checked under the lock so a flow that already recovered,
// closed or committed is left alone.
func (f *vaneMediaFlow) siblingCloseAction(plan vaneMediaPlan, sample vaneThroughputObservation) vanePolicyAction {
	return func() bool {
		f.mu.Lock()
		if f.aborted || f.closed {
			f.mu.Unlock()
			return false
		}
		f.aborted = true
		target, port, from, low := f.target, f.port, f.candidate, f.lowWindows
		f.mu.Unlock()
		log.Infoln("Vane: media reconnect sibling target=%s:%d bucket=%s from=%s to=%s bps=%.0f low-windows=%d", target, port, plan.targetKey.target, from, plan.challenger, sample.BitsPerSecond, low)
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

// noteEmptyWindow is §E's counter hook: the connection settled a 5-second
// window that produced no qualified sample. Only the flow the switch was
// made for counts. A qualified sample resets the streak in
// observe(); two consecutive empty windows fire the valve once.
func (f *vaneMediaFlow) noteEmptyWindow() {
	if f == nil || !f.switchedTo {
		return
	}
	f.mu.Lock()
	aborted, closed := f.aborted, f.closed
	if aborted || closed {
		f.mu.Unlock()
		return
	}
	f.valveEmptyWindows++
	trigger := f.valveEmptyWindows >= vaneMediaValveEmptyWindows
	if trigger {
		f.valveEmptyWindows = 0
	}
	f.mu.Unlock()
	if trigger {
		f.runReconnectValve()
	}
}

// runReconnectValve re-runs prepare for the switch that just went bad. The
// re-run starts from the challenger we switched TO (the flow's own node) with
// the pre-switch speed from the handoff token, skips the reconnect cooldown
// the original commit wrote, and closes this flow early when a better-evidenced
// candidate exists. Finding nothing does nothing — the next low window (or the
// next valve fire after the throttle) re-evaluates again. The per-target
// throttle keeps this to one run per window.
func (f *vaneMediaFlow) runReconnectValve() {
	f.mu.Lock()
	currentBPS := f.valveCurrentBPS
	f.mu.Unlock()
	if currentBPS <= 0 {
		return
	}
	now := f.group.clock.Now()
	f.group.mu.Lock()
	if until, ok := f.group.mediaValveLastRun[f.targetStateKey]; ok && now.Sub(until) < vaneMediaValveThrottle {
		f.group.mu.Unlock()
		return
	}
	f.group.mediaValveLastRun[f.targetStateKey] = now
	f.group.mu.Unlock()

	plan, reason := f.group.prepareMediaReconnectForNodeDetailedSkipCooldown(
		f.targetKey, f.target, f.port, f.candidate, f.identity, f.nodeEpoch, currentBPS, true)
	f.group.diagnostics.record(vaneDiagnosticRecord{
		kind: "reconnect-valve", reason: reason,
		target: f.target, bucket: f.targetKey.target, port: f.port,
		from: f.candidate, to: plan.challenger,
		bps: currentBPS,
	})
	if reason != "" {
		return
	}
	// The early close rides the normal commit path with the §E skip flag; the
	// sample below only feeds the diagnostics on the rejection paths.
	sample := vaneThroughputObservation{BitsPerSecond: currentBPS, Age: f.group.clock.Now().Sub(now)}
	f.submitPolicyAction(f.policyActionForPlan(plan, sample, 0, false), true)
}

// beginRaceToken reserves this flow's race round before the engine is called.
// The callback can then tell whether its result still belongs to the current
// low-window streak; a token must never be derived from raceToken itself
// because recovery/close resets that field.
func (f *vaneMediaFlow) beginRaceToken() (uint64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.aborted || f.raceToken != 0 {
		return 0, false
	}
	f.raceSeq++
	if f.raceSeq == 0 {
		f.raceSeq = 1
	}
	f.raceToken = f.raceSeq
	return f.raceToken, true
}

func (f *vaneMediaFlow) clearRaceToken(token uint64) {
	if token == 0 {
		return
	}
	f.mu.Lock()
	if f.raceToken == token {
		f.raceToken = 0
	}
	f.mu.Unlock()
}

// raceVerdict answers closed/recovered/stale in one lock acquisition; separate
// reads would leave gaps between the three checks.
func (f *vaneMediaFlow) raceVerdict(token uint64) (closed, recovered, stale bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Only a natural close invalidates observation; commits recheck aborted.
	return f.closed, f.lowWindows < f.group.media.lowWindows, f.raceToken != token
}

// markClosed is called at natural-close ownership. It invalidates any race
// result that has not been submitted yet.
func (f *vaneMediaFlow) markClosed() {
	f.mu.Lock()
	f.closed = true
	f.raceToken = 0
	f.mu.Unlock()
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
	// §C: the evidence value that admitted this candidate (target tier >
	// node throughput > capability). Admission only used to gate candidates;
	// this ranks admitted candidates whose evidence differs.
	evidenceBPS float64
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
	// §E: set on valve-triggered plans. Both the prepare reconnect-cooldown
	// gate and the commit one honor it, and the execution-time recovery
	// recheck (SYNC-RECHECK) skips it — a valve flow has no samples yet, so
	// lowWindows == 0 there means "no data", not "recovered".
	skipReconnectCooldown bool
}

// TARGET-BUDGET: switching is scoped per node, so a target can ping-pong
// A->B->C forever - each new node carries no cooldown record. The budget and
// the observe window therefore live on the target, not the node.
const (
	vaneTargetSwitchBudgetWindow = 30 * time.Minute
	vaneTargetSwitchBudgetMax    = 3
	vaneSwitchObserveWindow      = 60 * time.Second
)

type vaneTargetSwitchBudget struct {
	windowFrom time.Time
	count      int
	lastSwitch time.Time
}

func (a *Vane) mediaTargetBudgetBlocksLocked(targetKey vaneMediaTargetKey, now time.Time) string {
	budget := a.mediaTargetSwitches[targetKey]
	if budget.lastSwitch.IsZero() {
		return ""
	}
	if now.Sub(budget.lastSwitch) < vaneSwitchObserveWindow {
		return "switch-observing"
	}
	if now.Sub(budget.windowFrom) < vaneTargetSwitchBudgetWindow && budget.count >= vaneTargetSwitchBudgetMax {
		return "target-switch-budget"
	}
	return ""
}

func (a *Vane) noteMediaTargetSwitchLocked(targetKey vaneMediaTargetKey, now time.Time) {
	if a.mediaTargetSwitches == nil {
		a.mediaTargetSwitches = make(map[vaneMediaTargetKey]vaneTargetSwitchBudget)
	}
	budget := a.mediaTargetSwitches[targetKey]
	if budget.windowFrom.IsZero() || now.Sub(budget.windowFrom) >= vaneTargetSwitchBudgetWindow {
		budget.windowFrom = now
		budget.count = 0
	}
	budget.count++
	budget.lastSwitch = now
	a.mediaTargetSwitches[targetKey] = budget
}

// mediaCooldownBlocksLocked reports whether the reconnect cooldown still
// forbids another switch for this target. BREAK-WINDOW: the cooldown exists to
// stop flapping, not to trap a target on a node that is already starving. When
// the current flow is back below the low line and the break window has elapsed
// since the switch that armed the cooldown, one retry is allowed. The caller
// still has to pass the challenger evidence bar and the budget.
func (a *Vane) mediaCooldownBlocksLocked(key vaneMediaNodeKey, currentBPS float64, now time.Time) bool {
	until := a.mediaReconnects[key]
	if !until.After(now) {
		return false
	}
	if currentBPS >= a.media.lowThroughputBPS {
		return true
	}
	lastSwitch := until.Add(-a.media.reconnectCooldown)
	return now.Sub(lastSwitch) < vaneMediaBreakWindow
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
	return a.prepareMediaReconnectForNodeDetailedSkipCooldown(targetKey, target, port, current, identity, nodeEpoch, currentBPS, false)
}

// prepareMediaReconnectForNodeDetailedSkipCooldown is the §E valve entry: the
// re-run must bypass the reconnect cooldown the original commit wrote (the
// flag rides the plan so both commit checks honor it too).
func (a *Vane) prepareMediaReconnectForNodeDetailedSkipCooldown(targetKey vaneMediaTargetKey, target string, port uint16, current, identity string, nodeEpoch uint64, currentBPS float64, skipReconnectCooldown bool) (vaneMediaPlan, string) {
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
	// CHAIN-01: capability evidence is read before a.mu; no path may hold
	// racingRuntime.mu together with a.mu (see snapshotFreshCapabilities).
	capSnapshot := a.snapshotFreshCapabilities(now)
	// RESCUE: demand is the bar the *current* flow has to clear, never the bar
	// a rescue challenger has to clear. A 1 bps flow must be allowed to move to
	// any node that beats the slow line by the challenger ratio.
	requiredBPS := currentBPS * a.media.challengerRatio
	improvementBar := float64(vaneDefaultMediaLowThroughputBPS)
	if requiredBPS > improvementBar {
		improvementBar = requiredBPS
	}

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
	// §E: the valve's re-run carries its own skip flag — the cooldown it would
	// hit was written by the very commit being re-evaluated.
	currentNodeKey := vaneMediaNodeKeyFor(targetKey, current)
	if !skipReconnectCooldown && a.mediaCooldownBlocksLocked(currentNodeKey, currentBPS, now) {
		return vaneMediaPlan{}, "reconnect-cooldown"
	}
	if !skipReconnectCooldown {
		if reason := a.mediaTargetBudgetBlocksLocked(targetKey, now); reason != "" {
			return vaneMediaPlan{}, reason
		}
	}
	budget := a.mediaBudgets[currentNodeKey]
	if budget.startedAt.IsZero() || !budget.startedAt.Add(a.media.budgetWindow).After(now) {
		budget = vaneMediaBudget{startedAt: now}
	}
	if budget.count >= a.media.budgetMax {
		return vaneMediaPlan{}, "budget-exhausted"
	}

	// BASELINE-COOLDOWN-001: the progressive target backoff gates the baseline
	// path too — a challenger parked by a failed handoff for this target must
	// not come back through the baseline snapshot.
	stateKey, _ := a.targetKeyForMedia(target, port)

	candidates := make([]vaneMediaChallenger, 0, len(health))
	sawEvidenceFiltered := false
	for _, item := range health {
		proxy := item.proxy
		if proxy.Name() == current || !item.alive {
			continue
		}
		challengerIdentity := vaneProxyPersistentIdentity(proxy)
		candidateKey := vaneMediaCandidateKey{vaneMediaTargetKey: targetKey, candidate: proxy.Name(), identity: challengerIdentity}
		if a.mediaSlowCooldowns[candidateKey].After(now) {
			continue
		}
		// Same lease shape (name + identity + epoch) the failure records are
		// keyed by, built the way the racing snapshot builds its lookup lease.
		member := a.memberLeaseLocked(proxy.Name(), challengerIdentity)
		if member.epoch == 0 {
			if epoch := a.learning.nodeEpochs[vaneLearningNodeKey(member.name, member.identity)]; epoch != 0 {
				member.epoch = epoch
			}
		}
		if _, blocked := a.targetMemberBlockedLocked(stateKey, member, now); blocked {
			continue
		}
		dialKey := vaneCooldownKey{transport: vaneTransportTCP, target: target, port: port, candidate: proxy.Name(), identity: challengerIdentity}
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
			if rate, ok := a.nodes[proxy.Name()].cumulLossRate(now); ok && rate > vaneDefaultMediaHighLossRate {
				// B.3: a node that keeps retransmitting on a long horizon is
				// not a knownGood candidate however fast one probe looked.
				// Its capability probe still counts, just below this tier.
				knownGood = false
			}
		}
		// CHAIN-01: real traffic first, capability cache only when there is no
		// fresh real-traffic sample. A candidate below the close bar is not a
		// valid reason to break the current flow. A never-selected candidate
		// has no node state, so its lease epoch is 0; try both the computed
		// lease and its zero-epoch form, because a probe that never selected
		// the challenger wrote its record under epoch 0.
		// §B: target-scoped real traffic outranks both node tiers, as at commit.
		bestEvidence := 0.0
		if targetBPS, fresh, degraded := a.targetEvidenceLocked(stateKey, member, now); fresh && !degraded {
			bestEvidence = targetBPS
		} else if freshThroughput {
			bestEvidence = recent.bitsPerSecond
		} else if capBPS, ok := capSnapshot[member]; ok {
			bestEvidence = capBPS
		} else {
			zeroEpoch := member
			zeroEpoch.epoch = 0
			if capBPS, ok := capSnapshot[zeroEpoch]; ok {
				bestEvidence = capBPS
			}
		}
		if bestEvidence < improvementBar {
			sawEvidenceFiltered = true
			continue
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
			evidenceBPS:   bestEvidence,
		})
	}
	if len(candidates) == 0 {
		if sawEvidenceFiltered {
			log.Debugln("Vane: suppress media reconnect target=%s:%d node=%s reason=no-evidence-candidate", target, port, current)
			return vaneMediaPlan{}, "no-evidence-candidate"
		}
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
		// §C: among candidates of the same knownGood class, higher admitted
		// evidence wins before delay. For knownGood pairs this is a no-op
		// (evidenceBPS == throughputBPS, already compared above); it ranks
		// capability/target-admitted candidates by what admitted them.
		if left.evidenceBPS != right.evidenceBPS {
			return left.evidenceBPS > right.evidenceBPS
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
		targetStateKey: stateKey,
		generation:     a.learningGeneration,
		knownGood:      candidates[0].knownGood,
		currentBPS:     currentBPS,
		preparedAt:     now,
		// §E: valve-triggered plans carry the skip so both commit checks and
		// the execution-time recovery recheck honor it.
		skipReconnectCooldown: skipReconnectCooldown,
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
	// CHAIN-01: capability evidence is read before a.mu; no path may hold
	// racingRuntime.mu together with a.mu (see snapshotFreshCapabilities).
	capSnapshot := a.snapshotFreshCapabilities(now)
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
	if !plan.skipReconnectCooldown && a.mediaCooldownBlocksLocked(vaneMediaNodeKeyFor(plan.targetKey, plan.current), plan.currentBPS, now) {
		return "reconnect-cooldown"
	}
	dialKey := vaneCooldownKey{transport: vaneTransportTCP, target: plan.target, port: plan.port, candidate: plan.challenger, identity: plan.challengerIdentity}
	if a.cooldownUntilLocked(dialKey, now, false).After(now) {
		return "candidate-cooldown"
	}
	// BASELINE-COOLDOWN-001: re-check the progressive target block at commit
	// time — the challenger may have entered its backoff window between
	// prepare and commit. Same lease shape (name + identity + epoch) the
	// failure records are keyed by, with the freshest epoch for this identity.
	challengerEpoch := plan.challengerEpoch
	if state := a.nodes[plan.challenger]; state != nil && state.identity == plan.challengerIdentity {
		challengerEpoch = state.epoch
	}
	if _, blocked := a.targetMemberBlockedLocked(plan.targetStateKey, vaneMemberLease{
		name: plan.challenger, identity: plan.challengerIdentity, epoch: challengerEpoch,
	}, now); blocked {
		return "candidate-blocked"
	}
	challengerKey := vaneMediaCandidateKey{vaneMediaTargetKey: plan.targetKey, candidate: plan.challenger, identity: plan.challengerIdentity}
	if a.mediaSlowCooldowns[challengerKey].After(now) {
		return "challenger-slow-cooldown"
	}
	// CHAIN-08: a plan admitted on fresh throughput must still have fresh
	// evidence at commit. The old check silently skipped when nodeControls was
	// missing (for example after a reload replaced the same-named node).
	state := a.nodeControls[plan.challenger]
	var recent vaneRecentThroughput
	if state != nil {
		recent = state.recentTCPThroughput
	}
	if plan.knownGood && (state == nil || recent.bitsPerSecond <= 0 || recent.observedAt.IsZero() ||
		now.Sub(recent.observedAt) > vaneMediaEvidenceMaxAge) {
		return "challenger-no-evidence"
	}
	// CHAIN-04: re-check the same admission lines at commit, including demand
	// for plans that were admitted on throughput.
	if state != nil && recent.bitsPerSecond > 0 && !recent.observedAt.IsZero() &&
		now.Sub(recent.observedAt) <= vaneMediaEvidenceMaxAge &&
		(recent.bitsPerSecond < a.media.lowThroughputBPS ||
			recent.bitsPerSecond < plan.currentBPS*a.media.challengerRatio) {
		// §L exemption: a fresh target-tier measurement at or above the bar is
		// the authority (target > node), and checkChallengerEvidenceLocked
		// below would accept the plan through that tier. Vetoing here would
		// let the node-level signal override the more specific one — once the
		// low line follows demand, that inversion would kill exactly the
		// plans §B admits on target evidence alone.
		to := vaneMemberLease{name: plan.challenger, identity: plan.challengerIdentity, epoch: plan.challengerEpoch}
		// RESCUE: the bar is "clearly better than the current flow", not
		// "reaches demand". demand decides whether the current flow is good
		// enough; once it is not, a challenger that clears the slow line and
		// the ratio rescues the user even if it cannot reach demand.
		bar := float64(vaneDefaultMediaLowThroughputBPS)
		if required := plan.currentBPS * a.media.challengerRatio; required > bar {
			bar = required
		}
		if targetBPS, targetFresh, degraded := a.targetEvidenceLocked(plan.targetStateKey, to, now); !(targetFresh && !degraded && targetBPS >= bar) {
			return "challenger-evidence-degraded"
		}
	}
	// CHAIN-01: the challenger must still have fresh evidence above the close
	// bar when the close happens, across all evidence tiers. This also covers
	// the prepare->commit expiry window for non-knownGood (capability) plans.
	if reason := a.checkChallengerEvidenceLocked(plan, capSnapshot, now); reason != "" {
		return reason
	}
	budgetKey := vaneMediaNodeKeyFor(plan.targetKey, plan.current)
	budget := a.mediaBudgets[budgetKey]
	if budget.startedAt.IsZero() || !budget.startedAt.Add(a.media.budgetWindow).After(now) {
		budget = vaneMediaBudget{startedAt: now}
	}
	if budget.count >= a.media.budgetMax {
		return "budget-exhausted"
	}
	budget.count++
	a.mediaBudgets[budgetKey] = budget
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
	})
	if handoff != nil {
		handoff.targetKey = plan.targetStateKey
		handoff.baseline = true
	}
	a.mediaHints[plan.targetKey] = vaneMediaHint{
		candidate: plan.challenger,
		identity:  plan.challengerIdentity,
		expiresAt: now.Add(a.media.hintTTL),
		handoff:   handoff,
	}
	a.mediaReconnects[vaneMediaNodeKeyFor(plan.targetKey, plan.current)] = now.Add(a.media.reconnectCooldown)
	a.noteMediaTargetSwitchLocked(plan.targetKey, now)
	return ""
}

// checkChallengerEvidenceLocked reports "" when the challenger still has fresh
// evidence above the CHAIN-01 close bar, or the rejection reason. Caller holds
// a.mu (+ learning.mu); caps was snapshotted before any lock (see
// snapshotFreshCapabilities). Tiers, priority-ordered: fresh target-level real
// traffic first (most specific direct measurement), then fresh node-level real
// traffic, capability cache only when there is no fresh real traffic at all.
// The target tier is REQUIRED: a target-evidence race winner never writes the
// capability cache (runMediaRace returns early), so without this tier commit
// would veto a legitimate winner. The bar mirrors RACE-01's required
// (max(currentBPS x challengerRatio, the 5 Mbps slow line)): demand is
// deliberately absent — it gates the current flow, not its rescue. KnownGood
// plans are NOT exempt:
// the target tier can still veto them (deliberate target-level strictness).
func (a *Vane) checkChallengerEvidenceLocked(plan vaneMediaPlan, caps map[vaneMemberLease]float64, now time.Time) string {
	lease := vaneMemberLease{name: plan.challenger, identity: plan.challengerIdentity, epoch: plan.challengerEpoch}
	best := 0.0
	if plan.targetStateKey.targetScope != "" {
		if bps, fresh, degraded := a.targetEvidenceLocked(plan.targetStateKey, lease, now); fresh && degraded {
			// A target-scoped "bad for this target" record outranks every
			// generic tier below it; do not fall through to node evidence.
			return "challenger-evidence-degraded"
		} else if fresh {
			best = bps
		}
	}
	if best <= 0 {
		if state := a.nodeControls[plan.challenger]; state != nil {
			recent := state.recentTCPThroughput
			if recent.bitsPerSecond > 0 && !recent.observedAt.IsZero() && now.Sub(recent.observedAt) <= vaneMediaEvidenceMaxAge {
				best = recent.bitsPerSecond
			}
		}
	}
	if best <= 0 {
		if bps, ok := caps[lease]; ok {
			best = bps
		} else {
			// A never-selected challenger has no node state, so its plan may
			// carry a zero epoch while the probe wrote its record under epoch 0.
			zeroEpoch := lease
			zeroEpoch.epoch = 0
			if bps, ok := caps[zeroEpoch]; ok {
				best = bps
			}
		}
	}
	if best <= 0 {
		return "challenger-no-evidence"
	}
	// RESCUE: demand is not a floor for the challenger. A starving flow is
	// rescued by any challenger that clears the slow line and the ratio; the
	// old demand floor kept a dead flow alive because no candidate could
	// reach a bar that only the dead flow's own demand defined.
	bar := float64(vaneDefaultMediaLowThroughputBPS)
	requiredBPS := plan.currentBPS * a.media.challengerRatio
	if requiredBPS > bar {
		bar = requiredBPS
	}
	if best < bar {
		return "challenger-evidence-degraded"
	}
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
	// Scene-as-gate (SCENE-GATE-001): a flow classified as media by a scene
	// rule that carries a target identity is gate-eligible with that identity
	// as the scope, so the rule set only needs to be named once (in
	// scene-rules) and media-reconnect-domains can stay empty. The match is
	// re-run against the host alone so the scope is a pure function of
	// (target, port) and agrees at every call site; the gate lists above keep
	// precedence, so existing configs behave exactly as before. Rules without
	// a target identity (NETWORK, DST-PORT, ...) yield no scope and fall
	// through to the empty key below.
	if rule, ok := matchVaneSceneRule(&C.Metadata{Host: host}, a.rules); ok && rule.scene == vaneSceneMedia {
		if scope := rule.scope(); scope != "" {
			return vaneMediaTargetKey{target: scope, port: port}
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
	// §E: expired valve throttle entries fall out with the rest.
	for key, until := range a.mediaValveLastRun {
		if now.Sub(until) >= vaneMediaValveThrottle {
			delete(a.mediaValveLastRun, key)
		}
	}
}
