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
	// These flow thresholds are behavior constants, not user policy knobs.
	// Changing them requires a kernel rebuild; demand, scope and switches remain configurable.
	vaneDefaultLowThroughputBPS = int64(5_000_000)
	vaneDefaultLowWindows       = 3
	vaneDefaultMaxLowWindows    = 4
	vaneDefaultMinAge           = 15 * time.Second
	vaneDefaultMinBytes         = int64(2 * 1024 * 1024)
	vaneDefaultDemandBPS        = int64(1_000_000)
	vaneDefaultBufferGuard      = 5 * time.Second
	vaneDefaultReconnectDelay   = 10 * time.Minute
	vaneDefaultSlowCooldown     = 30 * time.Minute
	vaneDefaultHintTTL          = 15 * time.Second
	vaneDefaultChallengerRatio  = 1.25
	vaneDefaultBudgetMax        = 8
	vaneDefaultBudgetWindow     = 30 * time.Minute
	vaneEvidenceMaxAge          = 10 * time.Minute
	vaneMaximumThroughputBPS    = int64(1_000_000_000)
	// B-part degradation lines. Loss reuses the 5% the loss EMA already
	// treats as degraded (healthy paths retransmit < 1%); latency is where a
	// video path is visibly unusable (production saw 800 ms), far above the
	// 50-200 ms a healthy CDN path keeps.
	vaneDefaultHighLossRate = 0.05
	vaneDefaultHighLatency  = 500 * time.Millisecond
	// §E: the re-evaluation valve. A flow that was just switched to and keeps
	// producing no qualified samples gets one prepare re-run per target per
	// throttle window, so a bad challenger cannot lock the target for the full
	// reconnect cooldown while it never produces enough bytes to settle.
	vaneValveEmptyWindows = 2
	vaneValveThrottle     = 10 * time.Minute
	// P1 (background mis-close): the observed rate is the delivery rate
	// (min(node, client)), so a client that throttles briefly (background
	// tab) looks like a slow node. A low window within this window of the
	// last non-low sample is graced — not counted toward the trigger. It
	// only delays a genuine collapse (by up to the grace plus the remaining
	// windows), never cancels it.
	vaneFastGrace = 30 * time.Second
	// §2.4 stall watchdog: a flow that delivered samples and then went fully
	// silent (open connection, zero reads) produces no windows at all, so the
	// trigger can never fire. After this much silence the watchdog feeds a
	// synthetic near-zero window through the normal observe path so the
	// grace, trigger, race and prepare chain all apply. The tick
	// granularity bounds how late the first synthetic window can arrive.
	vaneStallSilence = 10 * time.Second
	// STALL-TOLERANCE: how long a silent flow may stay silent before the
	// watchdog calls it a stall. A DASH player drains its buffer between
	// segments: the socket goes quiet, the client has nothing left to read
	// and reports no backlog, so a fixed silence threshold cannot tell that
	// gap from a dead node. The buffered playback time can: bytes already
	// read, divided by the demand rate, is how long the client keeps playing
	// without us. A flow that banked 534 MB at 15 Mbps is covered for
	// minutes; a flow that stopped after 2 MB is covered for a second.
	vaneStallToleranceMin = 30 * time.Second
	vaneStallToleranceMax = 180 * time.Second
	// SWITCH-EVIDENCE: a flow without a target scope has to move this many bytes before a
	// low rate says anything about the node. A 30 KB API reply is not slow,
	// it is small, and switching it burns the race budget the video needs.
	vaneSwitchMinBytes = int64(8 * 1024 * 1024)
	// LOW-VOLUME: a phone video can stall below the 2 MiB gate and never reach
	// it. The YouTube app pulls a small SABR segment first; if that segment is
	// slow the connection sits at a few hundred kilobytes forever, so the
	// min-bytes gate keeps the watchdog from ever judging it while the screen
	// is stuck on a spinner. A synthetic window means the socket went fully
	// silent for at least the stall tolerance, so the flow is not merely young:
	// after this long, with this much read, a byte gate measured on lifetime
	// total must not veto the verdict. The synthetic requirement keeps a live
	// but small connection (SSE heartbeat, keepalive) out of this branch.
	vaneLowVolumeAge = 45 * time.Second
	// ZERO-SAMPLE: a connection that opened and then delivered fewer bytes than
	// one sample (32 KiB) stays invisible to a sample-driven watchdog forever.
	// Age it from the flow's start instead, but demand a much longer silence:
	// a slow first byte and a dead connection are indistinguishable before TLS
	// and the request have completed, so this branch trades patience for reach.
	vaneZeroSampleSilence = 90 * time.Second
	// vanePartialSilence is the same idea for a flow that did deliver some
	// bytes and then stopped. A googlevideo connection that answers with a few
	// hundred bytes and goes quiet is not a slow start, so it does not need the
	// full zero-sample patience.
	vanePartialSilence = 12 * time.Second
	vaneWatchdogTick   = 5 * time.Second
	// BACKLOG-STREAK: how long one backlog sighting excuses low windows.
	// A backgrounded player (browser tab, phone screen off) throttles or
	// stops reading, so its delivery rate collapses while the node is fine.
	// The backlog probe only reports while bytes are unwritten, which is
	// intermittent for a throttled-but-alive reader, so the excuse has to
	// outlive the probe's own tick by a wide margin. Without this the
	// "recently-fast" branch counted those windows and closed healthy
	// flows after a few minutes in the background.
	vaneBacklogGrace = 90 * time.Second
)

type vaneFlowConfig struct {
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

func defaultVaneFlowConfig() vaneFlowConfig {
	return vaneFlowConfig{
		lowThroughputBPS:  float64(vaneDefaultLowThroughputBPS),
		lowWindows:        vaneDefaultLowWindows,
		maxLowWindows:     vaneDefaultMaxLowWindows,
		minAge:            vaneDefaultMinAge,
		minBytes:          vaneDefaultMinBytes,
		demandBPS:         float64(vaneDefaultDemandBPS),
		bufferGuard:       vaneDefaultBufferGuard,
		reconnectCooldown: vaneDefaultReconnectDelay,
		slowCooldown:      vaneDefaultSlowCooldown,
		hintTTL:           vaneDefaultHintTTL,
		challengerRatio:   vaneDefaultChallengerRatio,
		budgetMax:         vaneDefaultBudgetMax,
		budgetWindow:      vaneDefaultBudgetWindow,
	}
}

// parseVaneRuleSetEntry is three-state: a valid `RULE-SET,<name>` entry
// returns (name, true, nil); a plain domain returns ("", false, nil); a
// malformed RULE-SET entry (empty name, or a name containing a comma) returns
// an error so it fails fast at construction instead of silently never
// matching. The prefix is case-insensitive like every other rule type; the
// provider name is kept verbatim.
func parseVaneRuleSetEntry(entry string) (string, bool, error) {
	trimmed := strings.TrimSpace(entry)
	if !strings.HasPrefix(strings.ToUpper(trimmed), "RULE-SET,") {
		return "", false, nil
	}
	name := strings.TrimSpace(trimmed[len("RULE-SET,"):])
	if name == "" || strings.Contains(name, ",") {
		return "", false, fmt.Errorf("invalid family rule-set entry %q", entry)
	}
	return name, true, nil
}

// parseVaneGeoSiteEntry is the GEOSITE counterpart of
// parseVaneRuleSetEntry: a valid `GEOSITE,<category>` entry returns
// (category, true, nil); anything else returns ("", false, nil) so the caller
// can fall through to the plain-domain path. A malformed GEOSITE entry
// (empty category, or a category containing a comma) errors at construction.
// `!` negation and `@attr` suffixes are the loader's own syntax and pass
// through verbatim.
func parseVaneGeoSiteEntry(entry string) (string, bool, error) {
	trimmed := strings.TrimSpace(entry)
	if !strings.HasPrefix(strings.ToUpper(trimmed), "GEOSITE,") {
		return "", false, nil
	}
	category := strings.TrimSpace(trimmed[len("GEOSITE,"):])
	if category == "" || strings.Contains(category, ",") {
		return "", false, fmt.Errorf("invalid family geosite entry %q", entry)
	}
	return category, true, nil
}

func newVaneFlowConfig(option VaneOption) (vaneFlowConfig, error) {
	config := defaultVaneFlowConfig()
	config.enabled = option.Reconnect
	for _, rawDomain := range option.ReconnectDomains {
		name, isRuleSet, err := parseVaneRuleSetEntry(rawDomain)
		if err != nil {
			return vaneFlowConfig{}, err
		}
		if isRuleSet {
			config.ruleSets = append(config.ruleSets, name)
			continue
		}
		category, isGeoSite, err := parseVaneGeoSiteEntry(rawDomain)
		if err != nil {
			return vaneFlowConfig{}, err
		}
		if isGeoSite {
			config.geoSites = append(config.geoSites, category)
			continue
		}
		domain, valid := normalizeVaneDomain(rawDomain)
		if !valid {
			return vaneFlowConfig{}, fmt.Errorf("invalid family domain %q", rawDomain)
		}
		config.domains = append(config.domains, domain)
	}

	demand := option.DemandBPS
	if int64(demand) < 0 || int64(demand) > vaneMaximumThroughputBPS {
		return vaneFlowConfig{}, fmt.Errorf("demand-bps must be between 0 and %d", vaneMaximumThroughputBPS)
	}
	if demand > 0 {
		config.demandBPS = float64(demand)
	}
	// LOW-LINE: the low-window trigger line stays at the flat 5M default or the
	// explicit low-throughput-bps value. It must NOT follow demand - on a pool
	// that peaks at 25M a 15M demand marked 71% of real samples "low" and kept
	// the watchdog switching forever.
	if option.LowThroughputBPS > 0 {
		if int64(option.LowThroughputBPS) > vaneMaximumThroughputBPS {
			return vaneFlowConfig{}, fmt.Errorf("low-throughput-bps must be between 0 and %d", vaneMaximumThroughputBPS)
		}
		config.lowThroughputBPS = float64(option.LowThroughputBPS)
	}
	return config, nil
}

type vaneFlowKey struct {
	target string
	port   uint16
}

type vaneCandidateKey struct {
	vaneFlowKey
	candidate string
	identity  string
}

// reconnectFloorLocked is the absolute floor a rescue candidate must clear.
// It follows the configured low line, so a pool tuned with
// low-throughput-bps: 10M does not hand a stalled flow to a 5M node and let it
// stall again. The demand rate stays out of this bar on purpose: demand gates
// the current flow, never its replacement.
func (a *Vane) reconnectFloorLocked() float64 {
	floor := float64(vaneDefaultLowThroughputBPS)
	if a.flow.lowThroughputBPS > floor {
		return a.flow.lowThroughputBPS
	}
	return floor
}

type vaneHint struct {
	candidate string
	identity  string
	expiresAt time.Time
	handoff   *vaneHandoffToken
}

type vaneBudget struct {
	startedAt time.Time
	count     int
}

type vaneFlow struct {
	group          *Vane
	candidate      string
	identity       string
	nodeEpoch      uint64
	target         string
	port           uint16
	targetKey      vaneFlowKey
	targetStateKey vaneTargetKey
	// CREATED-AT: the zero-sample watchdog branch ages silence from here,
	// because a flow that never produced a sample has no lastSampleAt.
	createdAt time.Time

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
	// PHASE1: only a configured target scope holds a flow count.
	// Every TCP flow is watched, but the count keeps its target-scoped meaning.
	counted bool
	// PHASE2: a flow that matches a configured target scope keeps
	// semantics (its own diagnostics and target-evidence writes). Other TCP
	// flows are watched and may now be switched, but stay out of the
	// target-scoped bookkeeping.
	targetScoped bool
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
	// LAST-READ: the connection's last non-zero read, so a silent window ages
	// on data arrival instead of on qualified samples.
	lastReadFunc func() time.Time
}

// flowStarted and flowEnded maintain the per-node live flow
// count (item 4). The counter lives on its own lock: it churns per
// connection and must never contend with a.mu selection work.
func (a *Vane) flowStarted(name string) {
	a.flowsMu.Lock()
	a.activeFlows[name]++
	a.flowsMu.Unlock()
}

func (a *Vane) flowEnded(name string) {
	a.flowsMu.Lock()
	if a.activeFlows[name] <= 1 {
		delete(a.activeFlows, name)
	} else {
		a.activeFlows[name]--
	}
	a.flowsMu.Unlock()
}

// releaseActiveFlowCount drops the flow's per-node count exactly once, even if
// a second settlement path ever appears.
func (f *vaneFlow) releaseActiveFlowCount() {
	if f == nil {
		return
	}
	f.flowCountOnce.Do(func() {
		if f.counted {
			f.group.flowEnded(f.candidate)
		}
		f.group.forgetFlow(f)
	})
}

func newVaneFlow(group *Vane, candidate string, metadata *C.Metadata, handoff ...*vaneHandoffToken) *vaneFlow {
	if group == nil || !group.flow.enabled {
		return nil
	}
	target, port := vaneTarget(metadata)
	if target == "" {
		return nil
	}
	// Every TCP flow has a rescue scope; configured families keep sharing theirs,
	// while other hosts keep the separate small-flow protection below.
	scopeKey := group.targetScopeKey(target, port)
	targetScoped := scopeKey.target != ""
	targetKey := scopeKey
	if !targetScoped {
		targetKey = vaneFlowKey{target: target, port: port}
	}
	targetStateKey := group.flowStateKeyForTarget(target, port)
	flow := &vaneFlow{group: group, candidate: candidate, target: target, port: port, targetKey: targetKey, targetStateKey: targetStateKey, targetScoped: targetScoped, createdAt: group.clock.Now()}
	if len(handoff) > 0 && handoff[0] != nil {
		flow.handoff = handoff[0]
		// §E: this flow is the one the switch was made for — arm the
		// re-evaluation valve with the pre-switch speed.
		flow.switchedTo = true
		flow.valveCurrentBPS = handoff[0].previousBPS
	}
	group.diagnostics.record(vaneDiagnosticRecord{
		kind:   "flow-started",
		target: target,
		bucket: targetKey.target,
		port:   port,
		from:   candidate,
	})
	// item 4: only successful flows hold a per-node count. The release
	// rides on the connection settlement (releaseActiveFlowCount); a
	// never-closing connection keeps holding its count, which is acceptable —
	// connections eventually close.
	if targetScoped {
		flow.counted = true
		group.flowStarted(candidate)
	}
	// §2.4: the watchdog only watches flows that have actually delivered
	// samples, so registration is cheap and silence is measured against the
	// flow's own sample clock.
	group.trackFlow(flow)
	return flow
}

// trackFlow registers an active flow with the stall watchdog and
// starts the group's single ticker goroutine on first use.
func (a *Vane) trackFlow(flow *vaneFlow) {
	if a == nil || flow == nil {
		return
	}
	a.flowsMu.Lock()
	if a.flowSet == nil {
		a.flowSet = make(map[*vaneFlow]struct{})
	}
	a.flowSet[flow] = struct{}{}
	a.flowsMu.Unlock()
	a.watchdogOnce.Do(func() {
		go a.flowWatchdogLoop()
	})
}

// forgetFlow drops a settled flow from the watchdog set.
func (a *Vane) forgetFlow(flow *vaneFlow) {
	if a == nil || flow == nil {
		return
	}
	a.flowsMu.Lock()
	delete(a.flowSet, flow)
	a.flowsMu.Unlock()
}

// flowWatchdogLoop is the group's single stall ticker. It stops when the
// group closes (racingRuntime.ctx is canceled in stopRacing).
func (a *Vane) flowWatchdogLoop() {
	ticker := time.NewTicker(vaneWatchdogTick)
	defer ticker.Stop()
	for {
		select {
		case <-a.racingRuntime.ctx.Done():
			return
		case <-ticker.C:
			a.runFlowWatchdogTick(a.clock.Now())
		}
	}
}

// runFlowWatchdogTick feeds synthetic near-zero windows to flows that were
// delivering samples and then went silent while still open. The synthetic
// window goes through the normal observe() path, so the grace, low-window
// trigger, race and prepare chain all apply unchanged — the
// watchdog only makes "fully stalled" visible to a trigger that is otherwise
// sample-driven.
func (a *Vane) runFlowWatchdogTick(now time.Time) {
	a.flowsMu.Lock()
	flows := make([]*vaneFlow, 0, len(a.flowSet))
	for flow := range a.flowSet {
		flows = append(flows, flow)
	}
	a.flowsMu.Unlock()
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
func (f *vaneFlow) observeSyntheticStall(now time.Time) {
	if f == nil {
		return
	}
	f.mu.Lock()
	if f.closed || f.aborted {
		f.mu.Unlock()
		return
	}
	if !f.hasSample {
		// ZERO-SAMPLE: a flow that never produced a qualified sample has no
		// lastSampleAt to age from, so it used to be invisible to this watchdog
		// forever — a connection that opened and then delivered nothing stayed
		// open until the player gave up on its own. Age it from startedAt and
		// demand a much longer silence, because a slow first byte and a dead
		// connection look identical from socket level.
		started := f.createdAt
		probe := f.lastReadFunc
		f.mu.Unlock()
		if started.IsZero() {
			return
		}
		// PARTIAL-SILENCE: a flow that returned a few hundred bytes and then
		// went quiet is not a slow first byte; a player stares at it for as long
		// as the watchdog lets it. Age from the last byte once anything arrived.
		threshold := vaneZeroSampleSilence
		since := started
		if probe != nil {
			if at := probe(); !at.IsZero() && at.After(since) {
				since = at
				threshold = vanePartialSilence
			}
		}
		if now.Sub(since) < threshold {
			return
		}
		synthetic := vaneThroughputObservation{
			BitsPerSecond: 1,
			untrusted:     true,
			synthetic:     true,
			silence:       now.Sub(since),
			TotalBytes:    0,
			Age:           now.Sub(started),
		}
		if action := f.observe(synthetic); action != nil {
			f.submitPolicyAction(action, vaneActionIsImmediate(synthetic))
		}
		return
	}
	// LAST-READ: silence has to be measured from the last byte that arrived,
	// not from the last qualified sample. A low-bitrate stream (voice, a
	// throttled download) never clears the 32 KiB / 1 s sample floor, so aging
	// on lastSampleAt judged a healthy trickling flow as stalled every window.
	last := f.lastSample
	lastRead := f.lastSampleAt
	probe := f.lastReadFunc
	tolerance := f.stallToleranceLocked()
	f.mu.Unlock()
	if probe != nil {
		if at := probe(); at.After(lastRead) {
			lastRead = at
		}
	}
	silence := now.Sub(lastRead)
	if silence < tolerance {
		return
	}
	// BPS must stay positive: observe() treats <= 0 as "no sample". The byte
	// total is the last real cumulative total (nothing arrived since), and
	// the age advances by the silence so the age/min-bytes gates see truth.
	synthetic := vaneThroughputObservation{
		BitsPerSecond: 1,
		untrusted:     true,
		synthetic:     true,
		silence:       silence,
		TotalBytes:    last.TotalBytes,
		Age:           last.Age + silence,
	}
	// The watchdog used to drop the action observe() returned, so a stalled
	// flow's immediate plan (knownGood baseline) never ran at all.
	if action := f.observe(synthetic); action != nil {
		f.submitPolicyAction(action, vaneActionIsImmediate(synthetic))
	}
}

// stallToleranceLocked is how long this flow may stay silent before the
// watchdog treats the silence as a stall: the playback time its already-read
// bytes cover, clamped so a tiny flow is not switched on a whim and a huge
// flow is not left stalled for minutes.
func (f *vaneFlow) stallToleranceLocked() time.Duration {
	demand := f.group.flow.demandBPS
	if demand <= 0 {
		return vaneStallSilence
	}
	buffered := time.Duration(float64(f.lastSample.TotalBytes) * 8 / demand * float64(time.Second))
	if buffered < vaneStallToleranceMin {
		return vaneStallToleranceMin
	}
	if buffered > vaneStallToleranceMax {
		return vaneStallToleranceMax
	}
	return buffered
}

func (f *vaneFlow) failHandoff(reason string) {
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

func (f *vaneFlow) discardHandoff() {
	if f == nil {
		return
	}
	f.mu.Lock()
	handoff := f.handoff
	f.handoff = nil
	f.mu.Unlock()
	f.group.discardTargetHandoff(handoff)
}

func (f *vaneFlow) setBacklogFunc(probe func() int64) {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.backlogFunc = probe
	f.mu.Unlock()
}

// LAST-READ: registered post-construction for the same reason as the backlog
// probe — the flow is already inside the watchdog set by then.
func (f *vaneFlow) setLastReadFunc(probe func() time.Time) {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.lastReadFunc = probe
	f.mu.Unlock()
}

// noteBacklog stamps the flow when the connection is holding unwritten bytes.
// The probe runs outside f.mu: it takes vaneObservedConn.mu, and observeRead
// calls its callbacks only after dropping that lock.
func (f *vaneFlow) noteBacklog(now time.Time) {
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

func (f *vaneFlow) setPolicySubmitter(submitter func(vanePolicyAction, bool)) {
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

func (f *vaneFlow) submitPolicyAction(action vanePolicyAction, delivered bool) {
	if f == nil || action == nil {
		return
	}
	if f.group.switchMode == vaneSwitchObserve {
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

func (f *vaneFlow) observe(sample vaneThroughputObservation) vanePolicyAction {
	if f == nil || sample.BitsPerSecond <= 0 {
		return nil
	}
	if !f.group.vaneIdentityCurrent(f.candidate, f.identity, f.nodeEpoch) {
		f.discardHandoff()
		return nil
	}
	config := f.group.flow
	member := vaneMemberLease{name: f.candidate, identity: f.identity, epoch: f.nodeEpoch}

	f.mu.Lock()
	if f.aborted || f.closed {
		f.mu.Unlock()
		return nil
	}
	lowLoss := sample.LossSupported && sample.LossRate > vaneDefaultHighLossRate
	// B-part: throughput is no longer the only degradation signal. Loss and
	// latency only count when the kernel actually reported them; latency also
	// needs delivered data this window, because srtt keeps its last value on a
	// silent socket (a paused flow must not be judged by a stale RTT).
	lowLatency := sample.LatencySupported && sample.Delivered && sample.Latency > vaneDefaultHighLatency
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
		// fine. A low sample within vaneFastGrace of the last non-low
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
		// BACKLOG-FIRST: a client that is not reading (background tab, paused
		// player, phone screen off) also goes socket-silent, which is exactly
		// what makes the watchdog synthesize a window. Testing the synthetic
		// case first made this exemption unreachable, so a backgrounded player
		// was judged on its own silence and switched off a healthy node.
		case !f.backloggedAt.IsZero() && now.Sub(f.backloggedAt) < vaneBacklogGrace:
			graceReason = "client-backlog"
			// BACKLOG-STREAK: a client that is not reading produces low delivery
			// windows that say nothing about the node, so the streak is cleared
			// and a return to the foreground starts from zero.
			f.lowWindows = 0
		case sample.synthetic:
			// STALL-TOLERANCE: a silent window says nothing about the node's
			// rate; the watchdog only synthesizes one after the flow outlived
			// its buffered playback time. It must not touch the streak.
			graceReason = ""
		case !f.lastNonLowAt.IsZero() && now.Sub(f.lastNonLowAt) < vaneFastGrace:
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
	// Only real samples advance the watchdog clock; a synthetic tick must not
	// restart the actual silence while the small-flow gate is still waiting.
	if !sample.synthetic {
		f.lastSampleAt = now
		f.lastSample = sample
		f.hasSample = true
	}
	lowWindows := f.lowWindows
	// BACKLOG-FIRST: a synthetic window that the backlog branch excused
	// (graceReason == "client-backlog") must not drag the streak to the
	// trigger line either, or a backgrounded player still switches itself.
	if sample.synthetic && graceReason == "" {
		// A tolerated stall is already proof the node stopped delivering, so
		// the streak is not consulted: the flow goes straight to the trigger.
		lowWindows = f.group.flow.lowWindows
		// STREAK-WRITEBACK: the plan is committed later, and that last check
		// compares the trigger line against the flow's live streak. Promoting
		// only a local copy made every synthetic trigger look "recovered" at
		// commit time, so a flow that never produced a sample could be judged
		// and then never switched. Still inside the flow lock here.
		f.lowWindows = lowWindows
	}
	untrusted := sample.untrusted || graceReason != ""
	var handoff *vaneHandoffToken
	if !untrusted && !sample.synthetic && vaneVerdictWindow(sample) >= vaneMinVerdictWindow {
		handoff = f.handoff
		f.handoff = nil
	}
	f.mu.Unlock()

	// Family rules still control per-sample diagnostics. Host-scoped rescue
	// leases and preferences use the same evidence and settlement path.
	targetScopedFlow := f.targetScoped
	stateScopedFlow := f.targetStateKey.targetScope != ""
	if targetScopedFlow {
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
	// VERIFY-STALL: a flow that goes silent right after a switch is evidence about
	// the node it landed on, even though the synthetic window itself cannot be used
	// as throughput evidence. Without this a landing that returns zero bytes was
	// never cooled, so the next connection was steered onto it again. Synthetic
	// only: a recently-fast graced window says nothing about the node — the
	// client was reading fast 30 seconds ago.
	landingPenaltyEligible := (sample.TotalBytes >= config.minBytes && (sample.synthetic || vaneVerdictWindow(sample) >= vaneMinVerdictWindow)) ||
		(sample.synthetic && sample.silence >= vaneLowVolumeAge)
	if sample.synthetic && landingPenaltyEligible && stateScopedFlow && lowWindows >= vaneVerifyPenaltyLowWindows && f.group.switchMode == vaneSwitchLive {
		f.group.penalizeSlowLanding(f.targetKey, f.candidate, now, "stall-landing", sample.BitsPerSecond, lowWindows)
	}
	// Client throttling and synthetic windows trigger policy, never node-health writes.
	if !untrusted && stateScopedFlow {
		// VERIFY: real bytes only. A node we just landed on that keeps tripping
		// the counter is cooled down; synthetic/graced windows never count.
		if low && landingPenaltyEligible &&
			lowWindows >= vaneVerifyPenaltyLowWindows {
			f.group.penalizeSlowLanding(f.targetKey, f.candidate, now, "slow-landing", sample.BitsPerSecond, lowWindows)
		}
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
	if lowWindows < config.lowWindows || sample.Age < config.minAge {
		return nil
	}
	// SMALL-FLOW: a flow under min-bytes carries little evidence either way,
	// so it only counts as stalled after the long partial-silence window. The
	// ordinary synthetic window is ten seconds of zero bytes, which is a
	// keep-alive going idle, not a stall - judging a telegram API socket or a
	// thumbnail request on it switched those flows every dozen seconds.
	stalledSmallFlow := sample.synthetic && sample.silence >= vaneLowVolumeAge
	if sample.TotalBytes < config.minBytes && !stalledSmallFlow {
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
	// SWITCH-EVIDENCE: below this many bytes a low rate is the request being
	// small, not the node being slow. Target scopes keep the older, lower
	// floor because a video flow proves itself by growing quickly.
	// TARGET-SCOPED: a flow the config never named as a switch candidate has no
	// business being reconnected on a few hundred kilobytes. Its silence is a
	// keep-alive going idle (HTTP/2 to an API host), not a stalled segment, and
	// cutting it also tears down every sibling on the same connection. Only a
	// configured target may use the low-volume exception.
	// TARGET-SCOPE: a flow with no configured domain scope carries too little
	// evidence to justify tearing its connection down, and an API host that
	// keeps a socket alive for minutes would otherwise read as stalled forever.
	// Only a flow that has moved vaneSwitchMinBytes is worth acting on; the
	// small-flow window above does not bypass this.
	if !f.targetScoped && sample.TotalBytes < vaneSwitchMinBytes {
		return nil
	}
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
		log.Debugln("Vane: defer reconnect target=%s:%d node=%s reason=buffer-credit bps=%.0f credit=%.0f guard=%.0f low-windows=%d/%d", f.target, f.port, f.candidate, sample.BitsPerSecond, creditBits, guardBits, lowWindows, config.maxLowWindows)
		return nil
	}

	// COOLDOWN-STARVE-01: a cooldown armed by an earlier commit must not freeze
	// a flow that is already starving past the credit guard; the reconnect
	// budget (3/30min) still bounds thrash. Same exemption rides the plan, so
	// the commit gates honor it too; it also skips the queued-action recovery
	// recheck, which only guards against a burst that arrives before the close.
	starving := lowWindows >= config.maxLowWindows && creditBits < guardBits
	plan, reason := f.group.prepareReconnectForNodeDetailedSkipCooldown(f.targetKey, f.target, f.port, f.candidate, f.identity, f.nodeEpoch, sample.BitsPerSecond, starving)
	mode := f.group.switchMode
	if reason != "" && reason != "no-challenger" && reason != "no-evidence-candidate" {
		f.recordReconnectSuppressed(reason, sample, lowWindows)
		return nil
	}

	if mode == vaneSwitchObserve {
		// SMALL-FLOW: observe mode must still report what live mode would
		// decide, but a window is recorded once. A small flow skips the probe,
		// so its skip record replaces the generic suppression and carries the
		// reason the live path would have acted on.
		if smallFlow(sample, f.group.flow) && (reason != "" || !plan.knownGood) {
			f.group.diagnostics.record(vaneDiagnosticRecord{
				kind: "small-flow-probe-skipped", reason: reason, target: f.target,
				bucket: f.targetKey.target, port: f.port, from: f.candidate, to: plan.challenger,
				bps: sample.BitsPerSecond, totalBytes: sample.TotalBytes, age: sample.Age,
				lowWindows: lowWindows,
			})
			return nil
		}
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
		f.completeReconnectPlan(&plan, sample, lowWindows)
		return f.policyActionForPlan(plan, sample, lowWindows, true)
	}
	if reason == "no-evidence-candidate" {
		f.recordReconnectSuppressed(reason, sample, lowWindows)
	}
	// SMALL-FLOW: a flow carrying a few hundred bytes cannot fund a probe.
	// The scores already carry real traffic, so rescue it with the ranked
	// challenger instead of spending up to 8 MB to prove what they say. Without
	// a ranked challenger, leave the small flow alone.
	if smallFlow(sample, f.group.flow) {
		if reason == "" {
			f.completeReconnectPlan(&plan, sample, lowWindows)
			return f.policyActionForPlan(plan, sample, lowWindows, true)
		}
		f.recordReconnectSuppressed("small-flow-no-known-good", sample, lowWindows)
		return nil
	}
	f.scheduleRace(sample, lowWindows)
	return nil
}

// smallFlow reports whether a flow has moved too few bytes for a probe to be
// worth its bytes. One probe costs up to 8 MB across the candidates; a keep-alive
// connection carrying a few hundred bytes cannot pay for that, and its score
// already comes from the same real traffic.
func smallFlow(sample vaneThroughputObservation, config vaneFlowConfig) bool {
	return sample.TotalBytes < config.minBytes
}

func (f *vaneFlow) recordReconnectSuppressed(reason string, sample vaneThroughputObservation, lowWindows int) {
	f.group.diagnostics.record(vaneDiagnosticRecord{
		kind: "reconnect-suppressed", reason: reason, target: f.target, bucket: f.targetKey.target,
		port: f.port, from: f.candidate, bps: sample.BitsPerSecond, totalBytes: sample.TotalBytes,
		age: sample.Age, lowWindows: lowWindows,
	})
}

func (f *vaneFlow) completeReconnectPlan(plan *vaneReconnectPlan, sample vaneThroughputObservation, lowWindows int) {
	plan.totalBytes = sample.TotalBytes
	plan.age = sample.Age
	plan.lowWindows = lowWindows
	f.group.diagnostics.record(vaneDiagnosticRecord{
		kind: "reconnect-prepared", target: f.target, bucket: f.targetKey.target, port: f.port,
		from: f.candidate, to: plan.challenger, bps: sample.BitsPerSecond, totalBytes: sample.TotalBytes,
		age: sample.Age, lowWindows: lowWindows,
	})
}

func (f *vaneFlow) raceRequest(sample vaneThroughputObservation, lowWindows int) vaneRaceRequest {
	// RESCUE: the race asks for a node that beats the current flow, not one that
	// already reaches demand — a 1 bps flow would otherwise race for nothing.
	required := sample.BitsPerSecond * f.group.flow.challengerRatio
	// RESCUE-FLOOR: the absolute floor is the slow line, never demand.
	if floor := f.group.reconnectFloorLocked(); required < floor {
		required = floor
	}
	f.group.mu.Lock()
	f.group.learning.mu.Lock()
	generation := f.group.learningGeneration
	f.group.learning.mu.Unlock()
	f.group.mu.Unlock()
	return vaneRaceRequest{
		targetKey: f.targetStateKey, target: f.target, port: f.port,
		current:    vaneMemberLease{name: f.candidate, identity: f.identity, epoch: f.nodeEpoch},
		currentBPS: sample.BitsPerSecond, requiredBPS: required, totalBytes: sample.TotalBytes,
		age: sample.Age, lowWindows: lowWindows, generation: generation, requestedAt: f.group.clock.Now(),
	}
}

func (f *vaneFlow) scheduleRace(sample vaneThroughputObservation, lowWindows int) {
	token, ok := f.beginRaceToken()
	if !ok {
		return
	}
	request := f.raceRequest(sample, lowWindows)
	scheduled, reason := f.group.scheduleReconnectRace(request, func(result vaneRaceResult) {
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
		if f.group.switchMode == vaneSwitchObserve {
			f.group.diagnostics.record(vaneDiagnosticRecord{
				kind: "handoff-would-commit", reason: result.source, handoffID: result.taskID,
				leaseID: vaneRaceLeaseID(result.request.generation, result.taskID), target: f.target,
				bucket: f.targetKey.target, port: f.port, from: f.candidate, to: result.winner.name,
				bps: result.lowerBoundBPS, previousBPS: sample.BitsPerSecond, totalBytes: sample.TotalBytes,
				age: sample.Age, lowWindows: lowWindows,
			})
			return
		}
		if f.group.switchMode != vaneSwitchLive {
			return
		}
		plan := vaneReconnectPlan{
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

func (f *vaneFlow) policyActionForPlan(plan vaneReconnectPlan, sample vaneThroughputObservation, lowWindows int, targetCommit bool) vanePolicyAction {
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
		if !plan.skipReconnectCooldown && lowWindowsNow < f.group.flow.lowWindows {
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
			commitReason = f.group.commitReconnectDetailed(plan)
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
		log.Infoln("Vane: reconnect target=%s:%d bucket=%s from=%s to=%s bps=%.0f low-windows=%d", f.target, f.port, f.targetKey.target, f.candidate, plan.challenger, sample.BitsPerSecond, lowWindows)
		// FANOUT: the switch must cancel every sibling flow on the same target
		// that is still pinned to the node we just left. A player streams a
		// video over several concurrent connections; closing only the flow
		// that happened to trip the watchdog leaves the others stalled on the
		// same slow node, which is exactly what "switched but still stuck"
		// looked like in the field. Siblings are closed, never committed: the
		// budget, cooldown and hint are already written by this commit.
		for _, sibling := range f.group.siblingFlows(plan.targetKey, f.candidate, f) {
			sibling.submitPolicyAction(sibling.siblingCloseAction(plan, sample), true)
		}
		return true
	}
}

// siblingFlows snapshots the other active flows for the same target that
// are still on candidate, so a committed switch can close them too.
func (a *Vane) siblingFlows(targetKey vaneFlowKey, candidate string, exclude *vaneFlow) []*vaneFlow {
	if a == nil {
		return nil
	}
	a.flowsMu.Lock()
	defer a.flowsMu.Unlock()
	var siblings []*vaneFlow
	for flow := range a.flowSet {
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
func (f *vaneFlow) siblingCloseAction(plan vaneReconnectPlan, sample vaneThroughputObservation) vanePolicyAction {
	return func() bool {
		f.mu.Lock()
		if f.aborted || f.closed {
			f.mu.Unlock()
			return false
		}
		f.aborted = true
		target, port, from, low := f.target, f.port, f.candidate, f.lowWindows
		f.mu.Unlock()
		log.Infoln("Vane: reconnect sibling target=%s:%d bucket=%s from=%s to=%s bps=%.0f low-windows=%d", target, port, plan.targetKey.target, from, plan.challenger, sample.BitsPerSecond, low)
		return true
	}
}

func (f *vaneFlow) policyAborted() bool {
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
func (f *vaneFlow) noteEmptyWindow() {
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
	trigger := f.valveEmptyWindows >= vaneValveEmptyWindows
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
func (f *vaneFlow) runReconnectValve() {
	f.mu.Lock()
	currentBPS := f.valveCurrentBPS
	f.mu.Unlock()
	if currentBPS <= 0 {
		return
	}
	now := f.group.clock.Now()
	f.group.mu.Lock()
	if until, ok := f.group.valveLastRun[f.targetStateKey]; ok && now.Sub(until) < vaneValveThrottle {
		f.group.mu.Unlock()
		return
	}
	f.group.valveLastRun[f.targetStateKey] = now
	f.group.mu.Unlock()

	plan, reason := f.group.prepareReconnectForNodeDetailedSkipCooldown(
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
func (f *vaneFlow) beginRaceToken() (uint64, bool) {
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

func (f *vaneFlow) clearRaceToken(token uint64) {
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
func (f *vaneFlow) raceVerdict(token uint64) (closed, recovered, stale bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Only a natural close invalidates observation; commits recheck aborted.
	return f.closed, f.lowWindows < f.group.flow.lowWindows, f.raceToken != token
}

// markClosed is called at natural-close ownership. It invalidates any race
// result that has not been submitted yet.
func (f *vaneFlow) markClosed() {
	f.mu.Lock()
	f.closed = true
	f.raceToken = 0
	f.mu.Unlock()
}

type vaneFlowHealth struct {
	proxy C.Proxy
	alive bool
	delay uint16
}

type vaneChallenger struct {
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

type vaneReconnectPlan struct {
	targetKey          vaneFlowKey
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

// SWITCH-LEDGER: one record per target answers every "may we switch again?"
// question. The previous model kept four overlapping tables: per-node
// reconnects, per-node budgets, per-target budgets and per-candidate slow
// cooldowns. Any one of them could reject, so the reason a stuck flow reported
// depended on which table happened to be populated, and switching away from a
// bad node armed a ten-minute freeze on the target instead of on the node.
// Two rules live here (throttle and budget). The third, no-backtrack, falls out
// of the five-minute node cooldown every switch writes: a node we just left is
// not a candidate, so A->B->A cannot happen.
const (
	// SWITCH-THROTTLE: one switch per target per minute.
	// vaneStarvingBPS marks a flow as dead rather than merely slow. Only a dead
	// flow is exempt from the observation window; a slow one still waits it out,
	// otherwise every low window would re-open the switch and the group would
	// thrash again.
	vaneStarvingBPS    = float64(1_000_000)
	vaneSwitchThrottle = 15 * time.Second
	// SWITCH-BUDGET: four switches per target per half hour.
	vaneSwitchBudgetWindow = 30 * time.Minute
	vaneSwitchBudgetMax    = 8
	// SWITCH-AWAY-COOLDOWN: the node we leave sits out this long on every
	// target. This is what makes no-backtrack structural rather than a rule.
	vaneSwitchAwayCooldown = 5 * time.Minute
	// VERIFY: a landing is judged on real bytes, not the probe.
	vaneVerifyPenaltyLowWindows = 2
	vaneVerifyPenaltyCooldown   = 10 * time.Minute
	// vaneVerifyPenaltyWindow is how long a landing stays under verification.
	// A zero-sample flow only trips its own branch after 90 s of silence, so a
	// 60 s window would miss the exact case this penalty exists for.
	vaneVerifyPenaltyWindow = 5 * time.Minute
)

type vaneSwitchLedger struct {
	windowFrom time.Time
	count      int
	lastSwitch time.Time
	// VERIFY: the node we just landed on and when.
	verifyNode string
	verifyAt   time.Time
}

// ledgerBudgetLocked reads the configured switch budget, falling back to the
// built-in defaults so a zero value keeps the production behaviour.
func (a *Vane) ledgerBudgetLocked() (int, time.Duration) {
	window := a.flow.budgetWindow
	if window <= 0 {
		window = vaneSwitchBudgetWindow
	}
	return a.flow.budgetMax, window
}

// ledgerThrottleReasonLocked is the target-wide half of "may we switch".
// ledgerThrottleReasonLocked reports the target-wide brake that applies right
// now. A starving flow is exempt from the observation window: that window exists
// so a fresh switch is not second-guessed, but a flow the switch did not rescue
// is evidence the switch failed, and waiting out the window leaves the player
// stalled. The per-window budget still applies.
func (a *Vane) ledgerThrottleReasonLocked(targetKey vaneFlowKey, starving bool, now time.Time) string {
	limit, window := a.ledgerBudgetLocked()
	if limit <= 0 {
		// SWITCH-BUDGET: a zero budget forbids switching at all.
		return "target-budget"
	}
	ledger := a.ledger[targetKey]
	if ledger.lastSwitch.IsZero() {
		return ""
	}
	if now.Sub(ledger.lastSwitch) < vaneSwitchThrottle {
		if !starving {
			return "switch-observing"
		}
	}
	if now.Sub(ledger.windowFrom) < window && ledger.count >= limit {
		return "target-budget"
	}
	return ""
}

// noteSwitchLocked records a committed switch: it consumes budget, arms the
// throttle and marks the landing for verification.
func (a *Vane) noteSwitchLocked(targetKey vaneFlowKey, node string, now time.Time) {
	if a.ledger == nil {
		a.ledger = make(map[vaneFlowKey]vaneSwitchLedger)
	}
	_, window := a.ledgerBudgetLocked()
	ledger := a.ledger[targetKey]
	if ledger.windowFrom.IsZero() || now.Sub(ledger.windowFrom) >= window {
		ledger.windowFrom = now
		ledger.count = 0
	}
	ledger.count++
	ledger.lastSwitch = now
	ledger.verifyNode = node
	ledger.verifyAt = now
	a.ledger[targetKey] = ledger
}

// clearLandingLocked drops the verification marker once the landing proves
// itself.
func (a *Vane) clearLandingLocked(targetKey vaneFlowKey, node string) {
	ledger, ok := a.ledger[targetKey]
	if !ok || ledger.verifyNode != node {
		return
	}
	ledger.verifyNode = ""
	ledger.verifyAt = time.Time{}
	a.ledger[targetKey] = ledger
}

// nodeCoolingLocked reports whether a node sits on its own cooldown, which
// applies to every target because the node is the failing unit.
func (a *Vane) nodeCoolingLocked(name string, now time.Time) bool {
	state := a.nodes[name]
	return state != nil && state.cooldown.After(now)
}

// coolNodeLocked puts a node on cooldown across every target.
func (a *Vane) coolNodeLocked(name string, until time.Time, switched bool) {
	if name == "" {
		return
	}
	state := a.nodes[name]
	if state == nil {
		// NODE-COOL: a node that has not served traffic yet has no state row, but
		// the switch that just left it still needs its cooling recorded.
		state = &vaneNodeState{name: name, identity: a.nodeIdentities[name]}
		a.nodes[name] = state
	}
	// SWITCH-SCORE: only a real switch away extends the next rest, so a
	// chronic offender spends longer out of the pool than a node that failed
	// once. A penalty (slow landing, slow settle) cools the node without
	// adding debt, or the same failure would be counted three times.
	if switched {
		state.switchAway++
	}
	base := until.Sub(a.clock.Now())
	if base > 0 && switched {
		extra := state.switchAway / 2
		if extra > 3 {
			extra = 3
		}
		if extended := a.clock.Now().Add(base + time.Duration(extra)*base); extended.After(until) {
			until = extended
		}
	}
	if until.After(state.cooldown) {
		state.cooldown = until
	}
}

// penalizeSlowLanding cools down a node we just switched onto but which is
// already tripping the low-window counter. VERIFY: the probe can be wildly
// optimistic (a free node measured 18Mbps to dl.google.com yet delivered only
// 4Mbps of googlevideo), so a bad landing is judged on real bytes. The penalty
// lands on the node, not on the target, because the node is what failed.
func (a *Vane) penalizeSlowLanding(targetKey vaneFlowKey, candidate string, now time.Time, reason string, bps float64, lowWindows int) {
	a.mu.Lock()
	ledger, ok := a.ledger[targetKey]
	if !ok || ledger.verifyNode != candidate || now.Sub(ledger.verifyAt) > vaneVerifyPenaltyWindow {
		a.mu.Unlock()
		return
	}
	if a.nodeCoolingLocked(candidate, now) {
		a.mu.Unlock()
		return
	}
	a.coolNodeLocked(candidate, now.Add(vaneVerifyPenaltyCooldown), false)
	a.mu.Unlock()
	a.diagnostics.record(vaneDiagnosticRecord{
		kind:       "verify-penalty",
		target:     targetKey.target,
		port:       targetKey.port,
		to:         candidate,
		reason:     reason,
		bps:        bps,
		lowWindows: lowWindows,
	})
}

type vaneLockedProxyProvider interface {
	ProxiesWithLock() ([]C.Proxy, func())
}

func (a *Vane) lockVaneIdentities(expected map[string]string) (func(), bool) {
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

func (a *Vane) vaneIdentityCurrent(name, identity string, nodeEpoch uint64) bool {
	if identity == "" {
		return true
	}
	release, current := a.lockVaneIdentities(map[string]string{name: identity})
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

func (a *Vane) prepareReconnectDetailed(targetKey vaneFlowKey, target string, port uint16, current string, currentBPS float64) (vaneReconnectPlan, string) {
	return a.prepareReconnectForNodeDetailed(targetKey, target, port, current, "", 0, currentBPS)
}

func (a *Vane) prepareReconnectForNodeDetailed(targetKey vaneFlowKey, target string, port uint16, current, identity string, nodeEpoch uint64, currentBPS float64) (vaneReconnectPlan, string) {
	return a.prepareReconnectForNodeDetailedSkipCooldown(targetKey, target, port, current, identity, nodeEpoch, currentBPS, false)
}

// prepareReconnectForNodeDetailedSkipCooldown is the §E valve entry: the
// re-run must bypass the reconnect cooldown the original commit wrote (the
// flag rides the plan so both commit checks honor it too).
func (a *Vane) prepareReconnectForNodeDetailedSkipCooldown(targetKey vaneFlowKey, target string, port uint16, current, identity string, nodeEpoch uint64, currentBPS float64, skipReconnectCooldown bool) (vaneReconnectPlan, string) {
	proxies := a.GetProxies(false)
	health := make([]vaneFlowHealth, 0, len(proxies))
	for _, proxy := range proxies {
		health = append(health, vaneFlowHealth{
			proxy: proxy,
			alive: proxy.AliveForTestUrl(a.testURL),
			delay: proxy.LastDelayForTestUrl(a.testURL),
		})
	}
	if identity != "" {
		release, current := a.lockVaneIdentities(map[string]string{current: identity})
		if !current {
			return vaneReconnectPlan{}, "stale-node-identity"
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
	requiredBPS := currentBPS * a.flow.challengerRatio
	improvementBar := a.reconnectFloorLocked()
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
			return vaneReconnectPlan{}, "stale-node-identity"
		}
	}
	a.pruneFlowStateLocked(now)
	// §E: the valve's re-run carries its own skip flag — the cooldown it would
	// hit was written by the very commit being re-evaluated.
	// SWITCH-LEDGER: throttle and budget are the only target-wide gates left.
	if !skipReconnectCooldown {
		if reason := a.ledgerThrottleReasonLocked(targetKey, currentBPS < vaneStarvingBPS, now); reason != "" {
			return vaneReconnectPlan{}, reason
		}
	}

	// BASELINE-COOLDOWN-001: the progressive target backoff gates the baseline
	// path too — a challenger parked by a failed handoff for this target must
	// not come back through the baseline snapshot.
	stateKey := a.flowStateKeyForTarget(target, port)

	candidates := make([]vaneChallenger, 0, len(health))
	sawEvidenceFiltered := false
	for _, item := range health {
		proxy := item.proxy
		if proxy.Name() == current || !item.alive {
			continue
		}
		challengerIdentity := vaneProxyPersistentIdentity(proxy)
		if a.nodeCoolingLocked(proxy.Name(), now) {
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
		freshThroughput := recent.bitsPerSecond > 0 && !recent.observedAt.IsZero() && now.Sub(recent.observedAt) <= vaneEvidenceMaxAge
		if freshThroughput {
			throughputBPS = recent.bitsPerSecond
			knownGood = throughputBPS >= a.flow.lowThroughputBPS && throughputBPS >= a.flow.demandBPS && throughputBPS >= currentBPS*a.flow.challengerRatio
			if rate, ok := a.nodes[proxy.Name()].cumulLossRate(now); ok && rate > vaneDefaultHighLossRate {
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
		} else if capRec, ok := capSnapshot[member]; ok {
			bestEvidence = capRec.bps
		} else {
			zeroEpoch := member
			zeroEpoch.epoch = 0
			if capRec, ok := capSnapshot[zeroEpoch]; ok {
				bestEvidence = capRec.bps
			}
		}
		if bestEvidence < improvementBar {
			sawEvidenceFiltered = true
			continue
		}
		if !knownGood && item.delay == 0 {
			continue
		}
		candidates = append(candidates, vaneChallenger{
			proxy:         proxy,
			knownGood:     knownGood,
			throughputBPS: throughputBPS,
			scoreMicros:   scoreVaneMetricsFlat(snapshot),
			delay:         item.delay,
			evidenceBPS:   bestEvidence,
		})
	}
	if len(candidates) == 0 {
		if sawEvidenceFiltered {
			log.Debugln("Vane: suppress reconnect target=%s:%d node=%s reason=no-evidence-candidate", target, port, current)
			return vaneReconnectPlan{}, "no-evidence-candidate"
		}
		log.Debugln("Vane: suppress reconnect target=%s:%d node=%s reason=no-challenger", target, port, current)
		return vaneReconnectPlan{}, "no-challenger"
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

	return vaneReconnectPlan{
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

func (a *Vane) commitReconnect(plan vaneReconnectPlan) bool {
	return a.commitReconnectDetailed(plan) == ""
}

func (a *Vane) commitReconnectDetailed(plan vaneReconnectPlan) string {
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
		release, current := a.lockVaneIdentities(map[string]string{
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
	a.pruneFlowStateLocked(now)
	if now.Sub(plan.preparedAt) > a.flow.hintTTL {
		return "plan-expired"
	}
	if !plan.skipReconnectCooldown {
		if reason := a.ledgerThrottleReasonLocked(plan.targetKey, plan.currentBPS < vaneStarvingBPS, now); reason != "" {
			return reason
		}
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
	if a.nodeCoolingLocked(plan.challenger, now) {
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
		now.Sub(recent.observedAt) > vaneEvidenceMaxAge) {
		return "challenger-no-evidence"
	}
	// CHAIN-04: re-check the same admission lines at commit, including demand
	// for plans that were admitted on throughput.
	if state != nil && recent.bitsPerSecond > 0 && !recent.observedAt.IsZero() &&
		now.Sub(recent.observedAt) <= vaneEvidenceMaxAge &&
		(recent.bitsPerSecond < a.flow.lowThroughputBPS ||
			recent.bitsPerSecond < plan.currentBPS*a.flow.challengerRatio) {
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
		bar := a.reconnectFloorLocked()
		if required := plan.currentBPS * a.flow.challengerRatio; required > bar {
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
	// SWITCH-AWAY: the node we leave is not a candidate for five minutes on
	// every target, which is what makes A->B->A impossible.
	a.coolNodeLocked(plan.current, now.Add(vaneSwitchAwayCooldown), true)
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
	a.hints[plan.targetKey] = vaneHint{
		candidate: plan.challenger,
		identity:  plan.challengerIdentity,
		expiresAt: now.Add(a.flow.hintTTL),
		handoff:   handoff,
	}
	a.noteSwitchLocked(plan.targetKey, plan.challenger, now)
	return ""
}

// checkChallengerEvidenceLocked reports "" when the challenger still has fresh
// evidence above the CHAIN-01 close bar, or the rejection reason. Caller holds
// a.mu (+ learning.mu); caps was snapshotted before any lock (see
// snapshotFreshCapabilities). Tiers, priority-ordered: fresh target-level real
// traffic first (most specific direct measurement), then fresh node-level real
// traffic, capability cache only when there is no fresh real traffic at all.
// The target tier is REQUIRED: a target-evidence race winner never writes the
// capability cache (runReconnectRace returns early), so without this tier commit
// would veto a legitimate winner. The bar mirrors RACE-01's required
// (max(currentBPS x challengerRatio, the 5 Mbps slow line)): demand is
// deliberately absent — it gates the current flow, not its rescue. KnownGood
// plans are NOT exempt:
// the target tier can still veto them (deliberate target-level strictness).
func (a *Vane) checkChallengerEvidenceLocked(plan vaneReconnectPlan, caps map[vaneMemberLease]vaneFreshCapability, now time.Time) string {
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
			if recent.bitsPerSecond > 0 && !recent.observedAt.IsZero() && now.Sub(recent.observedAt) <= vaneEvidenceMaxAge {
				best = recent.bitsPerSecond
			}
		}
	}
	if best <= 0 {
		if capRec, ok := caps[lease]; ok {
			best = capRec.bps
		} else {
			// A never-selected challenger has no node state, so its plan may
			// carry a zero epoch while the probe wrote its record under epoch 0.
			zeroEpoch := lease
			zeroEpoch.epoch = 0
			if capRec, ok := caps[zeroEpoch]; ok {
				best = capRec.bps
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
	bar := a.reconnectFloorLocked()
	requiredBPS := plan.currentBPS * a.flow.challengerRatio
	if requiredBPS > bar {
		bar = requiredBPS
	}
	if best < bar {
		return "challenger-evidence-degraded"
	}
	return ""
}

func (a *Vane) targetScopeKey(target string, port uint16) vaneFlowKey {
	host := normalizeVaneTarget(target)
	for _, domain := range a.flow.domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return vaneFlowKey{target: domain, port: port}
		}
	}
	// Round8 item 3: RULE-SET entries are checked after plain domains, and a
	// hit scopes by the provider name — "scope is what the config names", so
	// one provider per service or one provider for all streaming is the
	// user's choice.
	for _, name := range a.flow.ruleSets {
		provider, ok := tunnel.RuleProviders()[name]
		if !ok {
			continue
		}
		if provider.Match(&C.Metadata{Host: host}, C.RuleMatchHelper{}) {
			return vaneFlowKey{target: name, port: port}
		}
	}
	// Round8.5: GEOSITE entries resolve against the shared GeoSite database —
	// no extra download — and scope by the category name. Fail-closed like
	// every geodata path: a missing database is "no match", never an error.
	for _, category := range a.flow.geoSites {
		matcher, err := geodata.LoadGeoSiteMatcher(category)
		if err != nil {
			continue
		}
		if matcher.ApplyDomain(host) {
			return vaneFlowKey{target: category, port: port}
		}
	}
	// A flow that matches a family rule resolves to that family as its scope;
	// rule that carries a target identity is gate-eligible with that identity
	// as the scope, so the rule set only needs to be named once (in
	// families) and reconnect-domains can stay empty. The match is
	// re-run against the host alone so the scope is a pure function of
	// (target, port) and agrees at every call site; the gate lists above keep
	// precedence, so existing configs behave exactly as before. Rules without
	// a target identity (NETWORK, DST-PORT, ...) yield no scope and fall
	// through to the empty key below.
	if rule, ok := matchVaneFamilyRule(&C.Metadata{Host: host}, a.rules); ok && rule.scope() != "" {
		if scope := rule.scope(); scope != "" {
			return vaneFlowKey{target: scope, port: port}
		}
	}
	return vaneFlowKey{port: port}
}

func normalizeVaneTarget(target string) string {
	normalized, valid := normalizeVaneDomain(target)
	if !valid {
		return ""
	}
	return normalized
}

func (a *Vane) takeHintLocked(target string, port uint16, proxies []C.Proxy, now time.Time, claimHandoff bool) (C.Proxy, *vaneHandoffToken) {
	key := a.targetScopeKey(target, port)
	if key.target == "" {
		return nil, nil
	}
	hint, ok := a.hints[key]
	if !ok {
		return nil, nil
	}
	if !hint.expiresAt.After(now) {
		delete(a.hints, key)
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
		if a.nodeCoolingLocked(proxy.Name(), now) {
			return nil, nil
		}
		var handoff *vaneHandoffToken
		if claimHandoff && hint.handoff != nil &&
			hint.handoff.target == normalizeVaneTarget(target) &&
			hint.handoff.port == port && hint.handoff.to == proxy.Name() {
			handoff = hint.handoff
			hint.handoff = nil
			a.hints[key] = hint
		}
		return proxy, handoff
	}
	return nil, nil
}

func (a *Vane) flowCooldownUntilLocked(target string, port uint16, candidate string, now time.Time) time.Time {
	return a.cooldownUntilLockedWithCleanup(target, port, candidate, "", now, true)
}

// cooldownUntilLockedWithCleanup reports the node's own cooldown. NODE-COOLDOWN:
// the failing unit is the node, so its cooldown applies to every target.
func (a *Vane) cooldownUntilLockedWithCleanup(target string, port uint16, candidate, identity string, now time.Time, cleanup bool) time.Time {
	_ = target
	_ = port
	_ = cleanup
	state := a.nodes[candidate]
	if state == nil || !state.cooldown.After(now) {
		return time.Time{}
	}
	if identity != "" && state.identity != "" && state.identity != identity {
		return time.Time{}
	}
	return state.cooldown
}

func (a *Vane) flowCandidateCoolingLocked(candidate string, now time.Time) bool {
	return a.candidateCoolingLockedWithCleanup(candidate, "", now, true)
}

func (a *Vane) candidateCoolingLockedWithCleanup(candidate, identity string, now time.Time, cleanup bool) bool {
	_ = cleanup
	state := a.nodes[candidate]
	if state == nil || !state.cooldown.After(now) {
		return false
	}
	return identity == "" || state.identity == "" || state.identity == identity
}

func (a *Vane) pruneFlowStateLocked(now time.Time) {
	for key, hint := range a.hints {
		if !hint.expiresAt.After(now) {
			delete(a.hints, key)
		}
	}
	// SWITCH-LEDGER: a record only matters while its budget window or its
	// throttle is live.
	for key, ledger := range a.ledger {
		if ledger.lastSwitch.IsZero() {
			delete(a.ledger, key)
			continue
		}
		if ledger.windowFrom.Add(vaneSwitchBudgetWindow).Before(now) && now.Sub(ledger.lastSwitch) >= vaneSwitchThrottle {
			delete(a.ledger, key)
		}
	}
	// §E: expired valve throttle entries fall out with the rest.
	for key, until := range a.valveLastRun {
		if now.Sub(until) >= vaneValveThrottle {
			delete(a.valveLastRun, key)
		}
	}
	for key, choice := range a.stickiness {
		if !choice.expiresAt.After(now) {
			delete(a.stickiness, key)
		}
	}
}
