package outboundgroup

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

const (
	VaneDiagnosticsSchemaVersion    = 2
	vaneDiagnosticsOldestSchema     = 1
	vaneDiagnosticsRecentEventLimit = 64

	// vaneBaselineTokenIDBase offsets baseline reconnect token IDs far away
	// from the race task ID space (nextTaskID counts up from 1), so a stale
	// race settlement can never present an ID that matches a live baseline
	// lease. The offset only shapes the ID namespace; Sequence-derived IDs
	// remain purely a diagnostics display concern.
	vaneBaselineTokenIDBase = uint64(1) << 40
)

// VaneDiagnosticCounters contains cumulative Vane observations.
// Counters survive config reloads and process restarts when the profile cache is
// available. They are observations only and never participate in selection.
type VaneDiagnosticCounters struct {
	MediaFlows            uint64 `json:"mediaFlows"`
	ThroughputSamples     uint64 `json:"throughputSamples"`
	LowThroughputSamples  uint64 `json:"lowThroughputSamples"`
	LowWindowsByLoss      uint64 `json:"lowWindowsByLoss"`
	LowWindowsByLatency   uint64 `json:"lowWindowsByLatency"`
	BufferCreditDeferrals uint64 `json:"bufferCreditDeferrals"`
	ReconnectSuppressed   uint64 `json:"reconnectSuppressed"`
	ReconnectPrepared     uint64 `json:"reconnectPrepared"`
	ReconnectCommitted    uint64 `json:"reconnectCommitted"`
	ReconnectRejected     uint64 `json:"reconnectRejected"`
	HandoffSelections     uint64 `json:"handoffSelections"`
	HandoffMeasured       uint64 `json:"handoffMeasured"`
	HandoffDialFailed     uint64 `json:"handoffDialFailed"`
	ChurnCandidates       uint64 `json:"churnCandidates"`
	ChurnSuspected        uint64 `json:"churnSuspected"`
	ChurnResets           uint64 `json:"churnResets"`
	ExplorationSelections uint64 `json:"explorationSelections"`
	ExplorationSucceeded  uint64 `json:"explorationSucceeded"`
	ExplorationFailed     uint64 `json:"explorationFailed"`
	ExplorationNeutral    uint64 `json:"explorationNeutral"`
	ProbeCount            uint64 `json:"probeCount"`
	ProbeSuccess          uint64 `json:"probeSuccess"`
	ProbeInvalid          uint64 `json:"probeInvalid"`
	ProbeCanceled         uint64 `json:"probeCanceled"`
	ProbeBytes            uint64 `json:"probeBytes"`
	WouldHandoff          uint64 `json:"wouldHandoff"`
	HandoffCommitted      uint64 `json:"handoffCommitted"`
	ReconnectSelected     uint64 `json:"reconnectSelected"`
	ReconnectPositive     uint64 `json:"reconnectPositive"`
	HandoffImproved       uint64 `json:"handoffImproved"`
	HandoffNoGain         uint64 `json:"handoffNoGain"`
	HandoffFailed         uint64 `json:"handoffFailed"`
	RaceBudgetDenied      uint64 `json:"raceBudgetDenied"`
	RaceNoWinner          uint64 `json:"raceNoWinner"`
	RaceStaleGeneration   uint64 `json:"raceStaleGeneration"`
	B2LossSamples         uint64 `json:"b2LossSamples"`
	B2LossUnsupported     uint64 `json:"b2LossUnsupported"`
	B2StallSuspected      uint64 `json:"b2StallSuspected"`
	B2StallAttempts       uint64 `json:"b2StallAttempts"`
	// ProbeInvalidReasons splits ProbeInvalid by probe failure reason, so a
	// rotated event ring can no longer erase why probes failed.
	ProbeInvalidReasons map[string]uint64 `json:"probeInvalidReasons,omitempty"`
	// COLD-PICK: cold-first-pick probe counters. PickProbeBytes follows the
	// same semantics as ProbeBytes (actual bytes, canceled included).
	PickProbeCount   uint64 `json:"pickProbeCount"`
	PickProbeSuccess uint64 `json:"pickProbeSuccess"`
	PickProbeInvalid uint64 `json:"pickProbeInvalid"`
	PickProbeBytes   uint64 `json:"pickProbeBytes"`
}

type VaneDiagnosticPersistence struct {
	Available     bool      `json:"available"`
	LastSuccessAt time.Time `json:"lastSuccessAt,omitempty"`
	LastError     string    `json:"lastError,omitempty"`
}

// VaneDiagnosticEvent is a bounded, credential-free Vane decision event.
// Throughput values are bits per second, byte counts are bytes, and ages are
// milliseconds.
type VaneDiagnosticEvent struct {
	Sequence               uint64    `json:"sequence"`
	HandoffID              uint64    `json:"handoffId,omitempty"`
	LeaseID                string    `json:"leaseId,omitempty"`
	ExplorationID          uint64    `json:"explorationId,omitempty"`
	Time                   time.Time `json:"time"`
	Kind                   string    `json:"kind"`
	Reason                 string    `json:"reason,omitempty"`
	Transport              string    `json:"transport,omitempty"`
	Scene                  string    `json:"scene,omitempty"`
	Target                 string    `json:"target,omitempty"`
	Port                   uint16    `json:"port,omitempty"`
	From                   string    `json:"from,omitempty"`
	To                     string    `json:"to,omitempty"`
	BPS                    float64   `json:"bps,omitempty"`
	PreviousBPS            float64   `json:"previousBps,omitempty"`
	TotalBytes             int64     `json:"totalBytes,omitempty"`
	AgeMS                  int64     `json:"ageMs,omitempty"`
	LowWindows             int       `json:"lowWindows,omitempty"`
	Occurrences            int       `json:"occurrences,omitempty"`
	EvidenceCoverageMicros int64     `json:"evidenceCoverageMicros,omitempty"`
	ScopeEligibleOrdinal   uint64    `json:"scopeEligibleOrdinal,omitempty"`
}

type VaneDiagnosticConfig struct {
	MediaEnabled                  bool     `json:"mediaEnabled"`
	MediaDomains                  []string `json:"mediaDomains"`
	LowThroughputBPS              float64  `json:"lowThroughputBps"`
	LowWindows                    int      `json:"lowWindows"`
	MaxLowWindows                 int      `json:"maxLowWindows"`
	MinAgeMS                      int64    `json:"minAgeMs"`
	MinBytes                      int64    `json:"minBytes"`
	DemandBPS                     float64  `json:"demandBps"`
	BufferGuardMS                 int64    `json:"bufferGuardMs"`
	ReconnectCooldownMS           int64    `json:"reconnectCooldownMs"`
	SlowCooldownMS                int64    `json:"slowCooldownMs"`
	HintTTLMS                     int64    `json:"hintTtlMs"`
	ReconnectBudget               int      `json:"reconnectBudget"`
	BudgetWindowMS                int64    `json:"budgetWindowMs"`
	ChurnShadowEnabled            bool     `json:"churnShadowEnabled"`
	ChurnWindowMS                 int64    `json:"churnWindowMs"`
	ChurnLimit                    int      `json:"churnLimit"`
	ChurnMaxBytes                 int64    `json:"churnMaxBytes"`
	ChurnMaxAgeMS                 int64    `json:"churnMaxAgeMs"`
	ExplorationEnabled            bool     `json:"explorationEnabled"`
	ExplorationInterval           int      `json:"explorationInterval"`
	GrayFailureObservationEnabled bool     `json:"grayFailureObservationEnabled"`
	RacingMode                    string   `json:"racingMode"`
	RacingURL                     string   `json:"racingUrl,omitempty"`
	RacingBudgetBytesHour         int64    `json:"racingBudgetBytesHour"`
}

type VaneDiagnosticExplorationScope struct {
	Transport             string `json:"transport"`
	Scene                 string `json:"scene"`
	EligibleSelections    uint64 `json:"eligibleSelections"`
	ExplorationSelections uint64 `json:"explorationSelections"`
	SinceLastExploration  uint64 `json:"sinceLastExploration"`
	NextIn                uint64 `json:"nextIn"`
}

type VaneDiagnosticRuntime struct {
	ActiveHints              int                              `json:"activeHints"`
	ActiveReconnectCooldowns int                              `json:"activeReconnectCooldowns"`
	ActiveSlowCooldowns      int                              `json:"activeSlowCooldowns"`
	ActiveBudgets            int                              `json:"activeBudgets"`
	ActiveChurnStates        int                              `json:"activeChurnStates"`
	ExplorationSince         time.Time                        `json:"explorationSince,omitempty"`
	ExplorationScopes        []VaneDiagnosticExplorationScope `json:"explorationScopes,omitempty"`
	CapabilityCache          int                              `json:"capabilityCache"`
	ActiveHandoffLeases      int                              `json:"activeHandoffLeases"`
	ActiveTargetPreferences  int                              `json:"activeTargetPreferences"`
	ActiveTargetCooldowns    int                              `json:"activeTargetCooldowns"`
	B2LossTargets            int                              `json:"b2LossTargets"`
	B2StallTargets           int                              `json:"b2StallTargets"`
	// Step 3 guard-rail tallies: how many target/member pairs actually cross
	// the loss and stall lines. All pairs over the line means the line is
	// drawn wrong, which the two raw tallies above cannot answer.
	B2LossDegradedTargets  int `json:"b2LossDegradedTargets"`
	B2StallFrequentTargets int `json:"b2StallFrequentTargets"`
	// §A (§12.3 step 1): the per-target capability observation tally. Pairs is
	// how many (target, candidate) records hold at least one settlement sample;
	// Samples is the total count. Record-only — no selection path reads them.
	TargetCapabilities      int                             `json:"targetCapabilities"`
	TargetCapabilitySamples int64                           `json:"targetCapabilitySamples"`
	B2ActiveMediaFlows      map[string]int                  `json:"b2ActiveMediaFlows,omitempty"`
	P5Nodes                 map[string]VaneDiagnosticP5Node `json:"p5Nodes,omitempty"`
}

// VaneDiagnosticP5Node is the passive per-node throughput profile (round6
// item 1). Only nodes that have seen throughput samples appear in the map.
type VaneDiagnosticP5Node struct {
	TCP VaneDiagnosticP5Transport `json:"tcp"`
	UDP VaneDiagnosticP5Transport `json:"udp"`
}

type VaneDiagnosticP5Transport struct {
	P10BPS  float64   `json:"p10Bps,omitempty"`
	PeakBPS float64   `json:"peakBps,omitempty"`
	PeakAt  time.Time `json:"peakAt,omitempty"`
	Hours   []float64 `json:"hours,omitempty"`
}

// VaneDiagnosticsSnapshot is returned by GET /group/{name}/vane.
// PlayerTelemetryAvailable remains false until an application-side player
// supplies rebuffer data; transport recovery must not be described as no-stall.
type VaneDiagnosticsSnapshot struct {
	SchemaVersion            int                       `json:"schemaVersion"`
	Group                    string                    `json:"group"`
	Since                    time.Time                 `json:"since"`
	UpdatedAt                time.Time                 `json:"updatedAt"`
	PlayerTelemetryAvailable bool                      `json:"playerTelemetryAvailable"`
	LearningPersistence      VaneLearningPersistence   `json:"learningPersistence"`
	Counters                 VaneDiagnosticCounters    `json:"counters"`
	Suppressions             map[string]uint64         `json:"suppressions"`
	Rejections               map[string]uint64         `json:"rejections"`
	ChurnSuppressions        map[string]uint64         `json:"churnSuppressions"`
	RecentEvents             []VaneDiagnosticEvent     `json:"recentEvents"`
	GrayFailure              VaneDiagnosticGrayFailure `json:"grayFailure"`
	Config                   VaneDiagnosticConfig      `json:"config"`
	Runtime                  VaneDiagnosticRuntime     `json:"runtime"`
}

// VaneDiagnosticsProvider is the read-only Controller capability exposed by
// Vane groups.
type VaneDiagnosticsProvider interface {
	VaneDiagnostics() VaneDiagnosticsSnapshot
}

type vaneHandoffToken struct {
	id          uint64
	leaseID     string
	target      string
	bucket      string
	port        uint16
	from        string
	to          string
	previousBPS float64
	targetKey   vaneTargetKey
	fromLease   vaneMemberLease
	toLease     vaneMemberLease
	// baseline marks a token created by the synchronous hint path. It has no
	// targetHandoffs lease; settlement validates it through the media hint.
	baseline bool
}

type vaneDiagnostics struct {
	mu           sync.Mutex
	clock        vaneClock
	snapshotData VaneDiagnosticsSnapshot
	// nextBaselineTokenID allocates IDs for baseline reconnect tokens. It
	// lives far away from the race task ID space (nextTaskID counts up from
	// 1) so a stale race settlement can never present an ID that matches a
	// live baseline lease. Sequence-based IDs used to serve this purpose and
	// collided in the narrow window where the event ring was still short.
	nextBaselineTokenID uint64
	// nextExplorationID replaces the event-ring sequence as the exploration
	// token ID source now that the ring is gone.
	nextExplorationID uint64

	// sink captures the [vane] line in tests; nil means the mihomo log.
	sink      func(vaneDiagnosticRecord)
	logDedupe map[string]time.Time
}

// vaneLogDedupWindow collapses one (kind,target,reason) to a single Info line
// per window: reconnect-suppressed runs per flow per five seconds and would
// flood the log otherwise. Different reasons on one target stay visible.
const vaneLogDedupWindow = 30 * time.Second

// vaneLogLine is the fixed field order: kind, target, from, to, bps, reason,
// lowWindows, then the B.4 metrics. Fixed so `grep '[vane]' | cut` works.
func vaneLogLine(record vaneDiagnosticRecord) string {
	fields := []string{"[vane]", "kind=" + record.kind}
	if record.target != "" {
		fields = append(fields, "target="+record.target)
	}
	if record.port != 0 {
		fields = append(fields, "port="+strconv.Itoa(int(record.port)))
	}
	if record.from != "" {
		fields = append(fields, "from="+record.from)
	}
	if record.to != "" {
		fields = append(fields, "to="+record.to)
	}
	if record.bps > 0 {
		fields = append(fields, "bps="+strconv.FormatFloat(record.bps, 'f', 0, 64))
	}
	if record.reason != "" {
		fields = append(fields, "reason="+record.reason)
	}
	if record.lowSignal != "" {
		fields = append(fields, "signal="+record.lowSignal)
	}
	if record.latencyMillis > 0 {
		fields = append(fields, "latencyMs="+strconv.FormatInt(record.latencyMillis, 10))
	}
	if record.lossRate > 0 {
		fields = append(fields, "lossRate="+strconv.FormatFloat(record.lossRate, 'f', 4, 64))
	}
	if record.lowWindows > 0 {
		fields = append(fields, "lowWindows="+strconv.Itoa(record.lowWindows))
	}
	if record.scoreMicros > 0 {
		fields = append(fields, "score="+strconv.FormatFloat(float64(record.scoreMicros)/1_000_000, 'f', 4, 64))
	}
	if record.bestMicros > 0 {
		fields = append(fields, "best="+strconv.FormatFloat(float64(record.bestMicros)/1_000_000, 'f', 4, 64))
	}
	if record.scoreParts != "" {
		fields = append(fields, "parts="+record.scoreParts)
	}
	return strings.Join(fields, " ")
}

// emitLocked is the single carrier for every Vane event: a test sink, or one
// deduplicated Info line with the [vane] tag. Per-window noise stays in the
// counters only.
func (d *vaneDiagnostics) emitLocked(record vaneDiagnosticRecord, now time.Time) {
	switch record.kind {
	case "throughput-sample", "churn-candidate", "churn-reset":
		return
	}
	if d.sink != nil {
		d.sink(record)
		return
	}
	key := record.kind + "\x00" + record.target + "\x00" + record.reason
	if last, ok := d.logDedupe[key]; ok && now.Sub(last) < vaneLogDedupWindow {
		return
	}
	if len(d.logDedupe) > 512 {
		d.logDedupe = make(map[string]time.Time)
	}
	if d.logDedupe == nil {
		d.logDedupe = make(map[string]time.Time)
	}
	d.logDedupe[key] = now
	log.Infoln(vaneLogLine(record))
}

type vaneDiagnosticRecord struct {
	kind                   string
	reason                 string
	target                 string
	bucket                 string
	port                   uint16
	from                   string
	to                     string
	handoffID              uint64
	leaseID                string
	explorationID          uint64
	transport              string
	scene                  string
	bps                    float64
	previousBPS            float64
	totalBytes             int64
	age                    time.Duration
	lowWindows             int
	occurrences            int
	evidenceCoverageMicros int64
	scopeEligibleOrdinal   uint64
	low                    bool
	// B.4: which signal made the window low, plus the raw metric values, so a
	// suppression can be told apart from a throughput one after the fact.
	lowSignal     string
	latencyMillis int64
	lossRate      float64
	// pick-scored: winner score, the raw best score, and the dimension
	// contributions that added up to it.
	scoreMicros int64
	bestMicros  int64
	scoreParts  string
	force       bool
}

func newVaneDiagnostics(group string, clock vaneClock) *vaneDiagnostics {
	if clock == nil {
		clock = vaneSystemClock{}
	}
	now := clock.Now().UTC()
	return &vaneDiagnostics{
		clock: clock,
		snapshotData: VaneDiagnosticsSnapshot{
			SchemaVersion:     VaneDiagnosticsSchemaVersion,
			Group:             group,
			Since:             now,
			UpdatedAt:         now,
			Suppressions:      make(map[string]uint64),
			Rejections:        make(map[string]uint64),
			ChurnSuppressions: make(map[string]uint64),
			RecentEvents:      make([]VaneDiagnosticEvent, 0, vaneDiagnosticsRecentEventLimit),
			GrayFailure: VaneDiagnosticGrayFailure{
				Exclusions: newVaneGrayExclusions(),
			},
		},
	}
}

func (d *vaneDiagnostics) record(record vaneDiagnosticRecord) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.recordLocked(record)
	d.mu.Unlock()
}

func (d *vaneDiagnostics) recordReconnectCommit(record vaneDiagnosticRecord) *vaneHandoffToken {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	if record.kind == "" {
		record.kind = "reconnect-committed"
	}
	record.force = true
	// A caller-supplied handoffID (a race task ID) wins: it stitches the
	// race-stage events to every handoff lifecycle event. Otherwise the
	// commit event takes an ID from the dedicated baseline counter, which
	// lives far above the race task ID space so the two can never collide.
	if record.handoffID == 0 {
		d.nextBaselineTokenID++
		record.handoffID = vaneBaselineTokenIDBase + d.nextBaselineTokenID
	}
	d.recordLocked(record)
	d.mu.Unlock()
	return &vaneHandoffToken{
		id:          record.handoffID,
		leaseID:     record.leaseID,
		target:      normalizeVaneMediaTarget(record.target),
		bucket:      record.bucket,
		port:        record.port,
		from:        record.from,
		to:          record.to,
		previousBPS: record.bps,
	}
}

func (d *vaneDiagnostics) recordExplorationSelection(selection vaneExplorationSelection) *vaneExplorationToken {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	record := vaneDiagnosticRecord{
		kind:                   "exploration-selected",
		transport:              selection.transport.String(),
		scene:                  selection.scene.String(),
		target:                 selection.target,
		port:                   selection.port,
		from:                   selection.fromAnchor,
		to:                     selection.toCandidate,
		evidenceCoverageMicros: selection.evidenceCoverageMicros,
		scopeEligibleOrdinal:   selection.scopeEligibleOrdinal,
	}
	d.nextExplorationID++
	record.explorationID = d.nextExplorationID
	d.recordLocked(record)
	d.mu.Unlock()
	return &vaneExplorationToken{
		diagnostics:            d,
		id:                     record.explorationID,
		transport:              selection.transport,
		scene:                  selection.scene,
		target:                 selection.target,
		port:                   selection.port,
		fromAnchor:             selection.fromAnchor,
		toCandidate:            selection.toCandidate,
		evidenceCoverageMicros: selection.evidenceCoverageMicros,
		scopeEligibleOrdinal:   selection.scopeEligibleOrdinal,
	}
}

// countProbeInvalidReasonLocked splits invalid probes by failure reason. The
// map is created on first use because a snapshot restored from an older
// version carries no map at all.
func (d *vaneDiagnostics) countProbeInvalidReasonLocked(reason string) {
	if reason == "" {
		reason = "unknown"
	}
	if d.snapshotData.Counters.ProbeInvalidReasons == nil {
		d.snapshotData.Counters.ProbeInvalidReasons = make(map[string]uint64)
	}
	d.snapshotData.Counters.ProbeInvalidReasons[reason]++
}

func (d *vaneDiagnostics) recordLocked(record vaneDiagnosticRecord) VaneDiagnosticEvent {
	now := d.clock.Now().UTC()
	d.snapshotData.UpdatedAt = now

	switch record.kind {
	case "media-flow-started":
		d.snapshotData.Counters.MediaFlows++
	case "throughput-sample":
		d.snapshotData.Counters.ThroughputSamples++
		if record.low {
			d.snapshotData.Counters.LowThroughputSamples++
			switch record.lowSignal {
			case "loss":
				d.snapshotData.Counters.LowWindowsByLoss++
			case "latency":
				d.snapshotData.Counters.LowWindowsByLatency++
			}
		}
	case "buffer-credit-deferred":
		d.snapshotData.Counters.BufferCreditDeferrals++
	case "reconnect-suppressed":
		d.snapshotData.Counters.ReconnectSuppressed++
		d.snapshotData.Suppressions[record.reason]++
	case "reconnect-prepared":
		d.snapshotData.Counters.ReconnectPrepared++
	case "reconnect-committed":
		d.snapshotData.Counters.ReconnectCommitted++
	case "reconnect-rejected":
		d.snapshotData.Counters.ReconnectRejected++
		d.snapshotData.Rejections[record.reason]++
	case "handoff-selected":
		d.snapshotData.Counters.HandoffSelections++
	case "handoff-measured":
		d.snapshotData.Counters.HandoffMeasured++
	case "handoff-dial-failed":
		d.snapshotData.Counters.HandoffDialFailed++
	case "churn-candidate":
		d.snapshotData.Counters.ChurnCandidates++
	case "churn-suspected":
		d.snapshotData.Counters.ChurnSuspected++
	case "churn-reset":
		d.snapshotData.Counters.ChurnResets++
	case "churn-suppressed":
		d.snapshotData.ChurnSuppressions[record.reason]++
	case "exploration-selected":
		d.snapshotData.Counters.ExplorationSelections++
	case "exploration-succeeded":
		d.snapshotData.Counters.ExplorationSucceeded++
	case "exploration-failed":
		d.snapshotData.Counters.ExplorationFailed++
	case "exploration-neutral":
		d.snapshotData.Counters.ExplorationNeutral++
	case "race-probe-success":
		d.snapshotData.Counters.ProbeCount++
		d.snapshotData.Counters.ProbeSuccess++
		d.snapshotData.Counters.ProbeBytes += vaneDiagnosticBytes(record.totalBytes)
	case "race-probe-invalid":
		d.snapshotData.Counters.ProbeCount++
		d.snapshotData.Counters.ProbeInvalid++
		d.snapshotData.Counters.ProbeBytes += vaneDiagnosticBytes(record.totalBytes)
		d.countProbeInvalidReasonLocked(record.reason)
	case "race-probe-canceled":
		d.snapshotData.Counters.ProbeCount++
		d.snapshotData.Counters.ProbeCanceled++
		d.snapshotData.Counters.ProbeBytes += vaneDiagnosticBytes(record.totalBytes)
	case "pick-probe-success":
		d.snapshotData.Counters.PickProbeCount++
		d.snapshotData.Counters.PickProbeSuccess++
		d.snapshotData.Counters.PickProbeBytes += vaneDiagnosticBytes(record.totalBytes)
	case "pick-probe-invalid":
		d.snapshotData.Counters.PickProbeCount++
		d.snapshotData.Counters.PickProbeInvalid++
		d.snapshotData.Counters.PickProbeBytes += vaneDiagnosticBytes(record.totalBytes)
	case "handoff-would-commit":
		d.snapshotData.Counters.WouldHandoff++
	case "handoff-committed":
		d.snapshotData.Counters.HandoffCommitted++
	case "handoff-reconnect-selected":
		d.snapshotData.Counters.ReconnectSelected++
	case "handoff-reconnect-positive":
		d.snapshotData.Counters.ReconnectPositive++
	case "handoff-improved":
		d.snapshotData.Counters.HandoffImproved++
	case "handoff-no-gain":
		d.snapshotData.Counters.HandoffNoGain++
	case "handoff-failed":
		d.snapshotData.Counters.HandoffFailed++
	case "race-budget-denied":
		d.snapshotData.Counters.RaceBudgetDenied++
	case "race-no-winner":
		d.snapshotData.Counters.RaceNoWinner++
		if record.reason == "stale-generation" {
			d.snapshotData.Counters.RaceStaleGeneration++
		}
	case "race-canceled":
		if record.reason == "stale-generation" {
			d.snapshotData.Counters.RaceStaleGeneration++
		}
	case "b2-loss-sample":
		d.snapshotData.Counters.B2LossSamples++
	case "b2-loss-unsupported":
		d.snapshotData.Counters.B2LossUnsupported++
	case "b2-stall-attempt":
		d.snapshotData.Counters.B2StallAttempts++
	case "b2-stall-suspected":
		d.snapshotData.Counters.B2StallSuspected++
	case "gray-attempt-succeeded":
		d.snapshotData.GrayFailure.Counters.AttemptEligible++
		d.snapshotData.GrayFailure.Counters.AttemptSucceeded++
	case "gray-attempt-failed":
		d.snapshotData.GrayFailure.Counters.AttemptEligible++
		d.snapshotData.GrayFailure.Counters.AttemptFailed++
	case "gray-close-progress":
		d.snapshotData.GrayFailure.Counters.CloseEligible++
		d.snapshotData.GrayFailure.Counters.CloseProgress++
	case "gray-close-tiny":
		d.snapshotData.GrayFailure.Counters.CloseEligible++
		d.snapshotData.GrayFailure.Counters.CloseTiny++
	case "gray-attempt-excluded":
		if vaneGrayKnownExclusion("attempt", record.reason) {
			d.snapshotData.GrayFailure.Exclusions.Attempt[record.reason]++
		}
	case "gray-close-excluded":
		if vaneGrayKnownExclusion("close", record.reason) {
			d.snapshotData.GrayFailure.Exclusions.Close[record.reason]++
		}
	}

	var event VaneDiagnosticEvent
	if record.kind != "throughput-sample" && record.kind != "churn-candidate" && record.kind != "churn-reset" && record.kind != "churn-suppressed" &&
		!strings.HasPrefix(record.kind, "gray-") && !strings.HasPrefix(record.kind, "b2-") {
		event = d.appendEventLocked(record, now)
	}
	d.emitLocked(record, now)
	return event
}

func vaneDiagnosticBytes(value int64) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

func (d *vaneDiagnostics) appendEventLocked(record vaneDiagnosticRecord, now time.Time) VaneDiagnosticEvent {
	sequence := uint64(1)
	if events := d.snapshotData.RecentEvents; len(events) > 0 {
		sequence = events[len(events)-1].Sequence + 1
	}
	event := VaneDiagnosticEvent{
		Sequence:               sequence,
		HandoffID:              record.handoffID,
		LeaseID:                record.leaseID,
		ExplorationID:          record.explorationID,
		Time:                   now,
		Kind:                   record.kind,
		Reason:                 record.reason,
		Transport:              record.transport,
		Scene:                  record.scene,
		Target:                 record.target,
		Port:                   record.port,
		From:                   record.from,
		To:                     record.to,
		BPS:                    record.bps,
		PreviousBPS:            record.previousBPS,
		TotalBytes:             record.totalBytes,
		AgeMS:                  record.age.Milliseconds(),
		LowWindows:             record.lowWindows,
		Occurrences:            record.occurrences,
		EvidenceCoverageMicros: record.evidenceCoverageMicros,
		ScopeEligibleOrdinal:   record.scopeEligibleOrdinal,
	}
	d.snapshotData.RecentEvents = append(d.snapshotData.RecentEvents, event)
	if excess := len(d.snapshotData.RecentEvents) - vaneDiagnosticsRecentEventLimit; excess > 0 {
		copy(d.snapshotData.RecentEvents, d.snapshotData.RecentEvents[excess:])
		d.snapshotData.RecentEvents = d.snapshotData.RecentEvents[:vaneDiagnosticsRecentEventLimit]
	}
	return event
}

func (d *vaneDiagnostics) snapshot() VaneDiagnosticsSnapshot {
	if d == nil {
		return VaneDiagnosticsSnapshot{}
	}
	d.mu.Lock()
	snapshot := cloneVaneDiagnosticsSnapshot(d.snapshotData)
	d.mu.Unlock()
	return snapshot
}

func cloneVaneDiagnosticsSnapshot(source VaneDiagnosticsSnapshot) VaneDiagnosticsSnapshot {
	cloned := source
	cloned.Suppressions = make(map[string]uint64, len(source.Suppressions))
	for reason, count := range source.Suppressions {
		cloned.Suppressions[reason] = count
	}
	cloned.Rejections = make(map[string]uint64, len(source.Rejections))
	for reason, count := range source.Rejections {
		cloned.Rejections[reason] = count
	}
	cloned.ChurnSuppressions = make(map[string]uint64, len(source.ChurnSuppressions))
	for reason, count := range source.ChurnSuppressions {
		cloned.ChurnSuppressions[reason] = count
	}
	// ProbeInvalidReasons must not be shared with the live counters: the
	// snapshot is marshalled outside the diagnostics lock, and a concurrent
	// write to a shared map is a fatal runtime error. A nil source stays nil.
	if source.Counters.ProbeInvalidReasons != nil {
		cloned.Counters.ProbeInvalidReasons = make(map[string]uint64, len(source.Counters.ProbeInvalidReasons))
		for reason, count := range source.Counters.ProbeInvalidReasons {
			cloned.Counters.ProbeInvalidReasons[reason] = count
		}
	}
	cloned.RecentEvents = append([]VaneDiagnosticEvent(nil), source.RecentEvents...)
	cloned.GrayFailure.Exclusions.Attempt = make(map[string]uint64, len(source.GrayFailure.Exclusions.Attempt))
	for reason, count := range source.GrayFailure.Exclusions.Attempt {
		cloned.GrayFailure.Exclusions.Attempt[reason] = count
	}
	cloned.GrayFailure.Exclusions.Close = make(map[string]uint64, len(source.GrayFailure.Exclusions.Close))
	for reason, count := range source.GrayFailure.Exclusions.Close {
		cloned.GrayFailure.Exclusions.Close[reason] = count
	}
	cloned.GrayFailure.Series = append([]VaneDiagnosticGraySeries(nil), source.GrayFailure.Series...)
	for index := range cloned.GrayFailure.Series {
		cloned.GrayFailure.Series[index].Reasons = append([]string(nil), source.GrayFailure.Series[index].Reasons...)
	}
	cloned.Config.MediaDomains = append([]string(nil), source.Config.MediaDomains...)
	cloned.Runtime.ExplorationScopes = append([]VaneDiagnosticExplorationScope(nil), source.Runtime.ExplorationScopes...)
	return cloned
}
