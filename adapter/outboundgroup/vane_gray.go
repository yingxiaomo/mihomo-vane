package outboundgroup

import (
	"crypto/sha256"
	"encoding/base64"
	"sort"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

const (
	vaneGrayBucketWidth = 30 * time.Second
	vaneGrayShortWindow = 5 * time.Minute
	vaneGrayLongWindow  = 15 * time.Minute
	vaneGrayMaxSeries   = 512

	vaneGrayAttemptSufficientDenominator = uint64(20)
	vaneGrayCloseSufficientDenominator   = uint64(8)

	vaneGrayAttemptWatchDenominator = uint64(20)
	vaneGrayAttemptWatchFailures    = uint64(3)
	vaneGrayAttemptWatchRate        = 0.10
	vaneGrayCloseWatchDenominator   = uint64(8)
	vaneGrayCloseWatchTiny          = uint64(4)
	vaneGrayCloseWatchRate          = 0.50

	vaneGrayAttemptSuspectedShortDenominator = uint64(20)
	vaneGrayAttemptSuspectedShortFailures    = uint64(5)
	vaneGrayAttemptSuspectedShortRate        = 0.25
	vaneGrayAttemptSuspectedLongDenominator  = uint64(50)
	vaneGrayAttemptSuspectedLongFailures     = uint64(8)
	vaneGrayAttemptSuspectedLongRate         = 0.15
	vaneGrayCloseSuspectedShortDenominator   = uint64(12)
	vaneGrayCloseSuspectedShortTiny          = uint64(8)
	vaneGrayCloseSuspectedShortRate          = 2.0 / 3.0
	vaneGrayCloseSuspectedLongDenominator    = uint64(20)
	vaneGrayCloseSuspectedLongTiny           = uint64(10)
	vaneGrayCloseSuspectedLongRate           = 0.50
)

const (
	vaneGrayLevelInsufficient = "insufficient"
	vaneGrayLevelNormal       = "normal"
	vaneGrayLevelWatch        = "watch"
	vaneGrayLevelSuspected    = "suspected"
)

var (
	vaneGrayAttemptExclusionReasons = [...]string{
		"missing-member-identity",
		"probe-not-reported-alive",
		"internal-flow",
		"invalid-target",
		"dns-bootstrap",
		"neutral-outcome",
	}
	vaneGrayCloseExclusionReasons = [...]string{
		"non-tcp",
		"missing-member-identity",
		"probe-not-reported-alive",
		"internal-flow",
		"invalid-target",
		"dns-bootstrap",
		"policy-close",
		"no-positive-write",
		"lifetime-outside-window",
	}
)

type VaneDiagnosticGrayCounters struct {
	AttemptEligible  uint64 `json:"attemptEligible"`
	AttemptSucceeded uint64 `json:"attemptSucceeded"`
	AttemptFailed    uint64 `json:"attemptFailed"`
	CloseEligible    uint64 `json:"closeEligible"`
	CloseProgress    uint64 `json:"closeProgress"`
	CloseTiny        uint64 `json:"closeTiny"`
}

type VaneDiagnosticGrayExclusions struct {
	Attempt map[string]uint64 `json:"attempt"`
	Close   map[string]uint64 `json:"close"`
}

type VaneDiagnosticGrayThresholds struct {
	AttemptSufficientDenominator     uint64  `json:"attemptSufficientDenominator"`
	CloseSufficientDenominator       uint64  `json:"closeSufficientDenominator"`
	AttemptWatchDenominator          uint64  `json:"attemptWatchDenominator"`
	AttemptWatchFailures             uint64  `json:"attemptWatchFailures"`
	AttemptWatchRate                 float64 `json:"attemptWatchRate"`
	CloseWatchDenominator            uint64  `json:"closeWatchDenominator"`
	CloseWatchTiny                   uint64  `json:"closeWatchTiny"`
	CloseWatchRate                   float64 `json:"closeWatchRate"`
	AttemptSuspectedShortDenominator uint64  `json:"attemptSuspectedShortDenominator"`
	AttemptSuspectedShortFailures    uint64  `json:"attemptSuspectedShortFailures"`
	AttemptSuspectedShortRate        float64 `json:"attemptSuspectedShortRate"`
	AttemptSuspectedLongDenominator  uint64  `json:"attemptSuspectedLongDenominator"`
	AttemptSuspectedLongFailures     uint64  `json:"attemptSuspectedLongFailures"`
	AttemptSuspectedLongRate         float64 `json:"attemptSuspectedLongRate"`
	CloseSuspectedShortDenominator   uint64  `json:"closeSuspectedShortDenominator"`
	CloseSuspectedShortTiny          uint64  `json:"closeSuspectedShortTiny"`
	CloseSuspectedShortRate          float64 `json:"closeSuspectedShortRate"`
	CloseSuspectedLongDenominator    uint64  `json:"closeSuspectedLongDenominator"`
	CloseSuspectedLongTiny           uint64  `json:"closeSuspectedLongTiny"`
	CloseSuspectedLongRate           float64 `json:"closeSuspectedLongRate"`
}

type VaneDiagnosticGrayAttemptWindow struct {
	Denominator uint64  `json:"denominator"`
	Successes   uint64  `json:"successes"`
	Failures    uint64  `json:"failures"`
	FailureRate float64 `json:"failureRate"`
}

type VaneDiagnosticGrayCloseWindow struct {
	Denominator uint64  `json:"denominator"`
	Progress    uint64  `json:"progress"`
	Tiny        uint64  `json:"tiny"`
	TinyRate    float64 `json:"tinyRate"`
}

type VaneDiagnosticGrayWindow struct {
	Start        time.Time                       `json:"start"`
	EndExclusive time.Time                       `json:"endExclusive"`
	Attempt      VaneDiagnosticGrayAttemptWindow `json:"attempt"`
	Close        VaneDiagnosticGrayCloseWindow   `json:"close"`
}

type VaneDiagnosticGraySeries struct {
	Candidate   string                   `json:"candidate"`
	MemberID    string                   `json:"memberId"`
	Transport   string                   `json:"transport"`
	Level       string                   `json:"level"`
	Reasons     []string                 `json:"reasons"`
	ShortWindow VaneDiagnosticGrayWindow `json:"shortWindow"`
	LongWindow  VaneDiagnosticGrayWindow `json:"longWindow"`
}

type VaneDiagnosticGrayFailure struct {
	Enabled                 bool                         `json:"enabled"`
	Scope                   string                       `json:"scope"`
	CorrelationOnly         bool                         `json:"correlationOnly"`
	ProbeFreshnessAvailable bool                         `json:"probeFreshnessAvailable"`
	BucketMS                int64                        `json:"bucketMs"`
	ShortWindowMS           int64                        `json:"shortWindowMs"`
	LongWindowMS            int64                        `json:"longWindowMs"`
	MaxSeries               int                          `json:"maxSeries"`
	CurrentLevel            string                       `json:"currentLevel"`
	Thresholds              VaneDiagnosticGrayThresholds `json:"thresholds"`
	Counters                VaneDiagnosticGrayCounters   `json:"counters"`
	Exclusions              VaneDiagnosticGrayExclusions `json:"exclusions"`
	Series                  []VaneDiagnosticGraySeries   `json:"series"`
}

type vaneGraySelection struct {
	candidate             string
	identity              string
	transport             vaneTransport
	reportedAliveAtSelect bool
}

type vaneGrayAttempt struct {
	once      sync.Once
	observer  *vaneGrayObserver
	selection vaneGraySelection
}

type vaneGraySeriesKey struct {
	identity  string
	transport vaneTransport
}

type vaneGrayBucket struct {
	start          time.Time
	attemptSuccess uint64
	attemptFailure uint64
	closeProgress  uint64
	closeTiny      uint64
}

type vaneGraySeriesState struct {
	candidate   string
	identity    string
	transport   vaneTransport
	lastUpdated time.Time
	buckets     map[int64]*vaneGrayBucket
}

type vaneGrayObserver struct {
	mu          sync.Mutex
	enabled     bool
	clock       vaneClock
	diagnostics *vaneDiagnostics
	series      map[vaneGraySeriesKey]*vaneGraySeriesState
}

func newVaneGrayObserver(enabled bool, clock vaneClock, diagnostics *vaneDiagnostics) *vaneGrayObserver {
	if clock == nil {
		clock = vaneSystemClock{}
	}
	return &vaneGrayObserver{
		enabled:     enabled,
		clock:       clock,
		diagnostics: diagnostics,
		series:      make(map[vaneGraySeriesKey]*vaneGraySeriesState),
	}
}

func (o *vaneGrayObserver) setDiagnostics(diagnostics *vaneDiagnostics) {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.diagnostics = diagnostics
	o.mu.Unlock()
}

func (o *vaneGrayObserver) newAttempt(selection vaneGraySelection, metadata *C.Metadata) *vaneGrayAttempt {
	if o == nil || !o.isEnabled() {
		return nil
	}
	if reason := vaneGrayAttemptExclusion(selection, metadata); reason != "" {
		o.recordExclusion("attempt", reason)
		return nil
	}
	return &vaneGrayAttempt{observer: o, selection: selection}
}

func (a *vaneGrayAttempt) settle(outcome string) {
	if a == nil || a.observer == nil {
		return
	}
	a.once.Do(func() {
		switch outcome {
		case "success", "failure":
			a.observer.recordAttempt(a.selection, outcome)
		default:
			a.observer.recordExclusion("attempt", "neutral-outcome")
		}
	})
}

func (o *vaneGrayObserver) recordClose(selection vaneGraySelection, metadata *C.Metadata, observation vaneConnectionCloseObservation) {
	if o == nil || !o.isEnabled() {
		return
	}
	if reason := vaneGrayCloseExclusion(selection, metadata, observation); reason != "" {
		o.recordExclusion("close", reason)
		return
	}
	kind := "close-tiny"
	if observation.TotalReadBytes >= vaneChurnMaxDownloadBytes {
		kind = "close-progress"
	}
	o.recordBucket(selection, kind)
	o.recordDiagnostic(vaneDiagnosticRecord{kind: "gray-" + kind})
}

func vaneGrayAttemptExclusion(selection vaneGraySelection, metadata *C.Metadata) string {
	if selection.identity == "" {
		return "missing-member-identity"
	}
	if !selection.reportedAliveAtSelect {
		return "probe-not-reported-alive"
	}
	if metadata != nil && metadata.Type == C.INNER {
		return "internal-flow"
	}
	target, port, valid := vaneChurnTarget(metadata)
	if !valid {
		return "invalid-target"
	}
	if vaneChurnDNSBootstrap(target, port) {
		return "dns-bootstrap"
	}
	return ""
}

func vaneGrayCloseExclusion(selection vaneGraySelection, metadata *C.Metadata, observation vaneConnectionCloseObservation) string {
	if selection.transport != vaneTransportTCP {
		return "non-tcp"
	}
	if selection.identity == "" {
		return "missing-member-identity"
	}
	if !selection.reportedAliveAtSelect {
		return "probe-not-reported-alive"
	}
	if metadata == nil {
		return "invalid-target"
	}
	if metadata.NetWork != C.TCP {
		return "non-tcp"
	}
	if metadata.Type == C.INNER {
		return "internal-flow"
	}
	target, port, valid := vaneChurnTarget(metadata)
	if !valid {
		return "invalid-target"
	}
	if vaneChurnDNSBootstrap(target, port) {
		return "dns-bootstrap"
	}
	if observation.PolicyClosed {
		return "policy-close"
	}
	if !observation.WrotePayload {
		return "no-positive-write"
	}
	if observation.Age <= 0 || observation.Age >= vaneChurnMaxLifetime {
		return "lifetime-outside-window"
	}
	return ""
}

func (o *vaneGrayObserver) isEnabled() bool {
	o.mu.Lock()
	enabled := o.enabled
	o.mu.Unlock()
	return enabled
}

func (o *vaneGrayObserver) recordAttempt(selection vaneGraySelection, outcome string) {
	kind := "attempt-failed"
	if outcome == "success" {
		kind = "attempt-succeeded"
	}
	o.recordBucket(selection, kind)
	o.recordDiagnostic(vaneDiagnosticRecord{kind: "gray-" + kind})
}

func (o *vaneGrayObserver) recordExclusion(channel, reason string) {
	o.recordDiagnostic(vaneDiagnosticRecord{kind: "gray-" + channel + "-excluded", reason: reason})
}

func (o *vaneGrayObserver) recordDiagnostic(record vaneDiagnosticRecord) {
	o.mu.Lock()
	diagnostics := o.diagnostics
	o.mu.Unlock()
	diagnostics.record(record)
}

func (o *vaneGrayObserver) recordBucket(selection vaneGraySelection, kind string) {
	now := o.clock.Now().UTC()
	bucketStart := now.Truncate(vaneGrayBucketWidth)
	key := vaneGraySeriesKey{identity: selection.identity, transport: selection.transport}

	o.mu.Lock()
	state := o.series[key]
	if state == nil {
		if len(o.series) >= vaneGrayMaxSeries {
			o.evictOldestLocked()
		}
		state = &vaneGraySeriesState{
			candidate: selection.candidate,
			identity:  selection.identity,
			transport: selection.transport,
			buckets:   make(map[int64]*vaneGrayBucket),
		}
		o.series[key] = state
	}
	state.candidate = selection.candidate
	state.lastUpdated = now
	bucketKey := bucketStart.Unix()
	bucket := state.buckets[bucketKey]
	if bucket == nil {
		bucket = &vaneGrayBucket{start: bucketStart}
		state.buckets[bucketKey] = bucket
	}
	switch kind {
	case "attempt-succeeded":
		bucket.attemptSuccess++
	case "attempt-failed":
		bucket.attemptFailure++
	case "close-progress":
		bucket.closeProgress++
	case "close-tiny":
		bucket.closeTiny++
	}
	oldest := bucketStart.Add(-vaneGrayLongWindow + vaneGrayBucketWidth)
	for timestamp, candidate := range state.buckets {
		if candidate == nil || candidate.start.Before(oldest) {
			delete(state.buckets, timestamp)
		}
	}
	o.mu.Unlock()
}

func (o *vaneGrayObserver) evictOldestLocked() {
	var oldestKey vaneGraySeriesKey
	var oldest *vaneGraySeriesState
	found := false
	for key, state := range o.series {
		if !found || vaneGraySeriesOlder(key, state, oldestKey, oldest) {
			oldestKey, oldest, found = key, state, true
		}
	}
	if found {
		delete(o.series, oldestKey)
	}
}

func vaneGraySeriesOlder(leftKey vaneGraySeriesKey, left *vaneGraySeriesState, rightKey vaneGraySeriesKey, right *vaneGraySeriesState) bool {
	if left == nil || right == nil {
		return left == nil && right != nil
	}
	if !left.lastUpdated.Equal(right.lastUpdated) {
		return left.lastUpdated.Before(right.lastUpdated)
	}
	leftMember, rightMember := vaneGrayMemberID(leftKey.identity), vaneGrayMemberID(rightKey.identity)
	if leftMember != rightMember {
		return leftMember < rightMember
	}
	return leftKey.transport < rightKey.transport
}

func (o *vaneGrayObserver) snapshot(persisted VaneDiagnosticGrayFailure) VaneDiagnosticGrayFailure {
	result := persisted
	result.Exclusions = normalizeVaneGrayExclusions(result.Exclusions)
	result.Enabled = false
	if o != nil {
		result.Enabled = o.isEnabled()
	}
	result.Scope = "member-transport"
	result.CorrelationOnly = true
	result.ProbeFreshnessAvailable = false
	result.BucketMS = vaneGrayBucketWidth.Milliseconds()
	result.ShortWindowMS = vaneGrayShortWindow.Milliseconds()
	result.LongWindowMS = vaneGrayLongWindow.Milliseconds()
	result.MaxSeries = vaneGrayMaxSeries
	result.CurrentLevel = vaneGrayLevelInsufficient
	result.Thresholds = vaneGrayThresholds()
	result.Series = nil
	if o == nil || !result.Enabled {
		return result
	}

	now := o.clock.Now().UTC()
	bucketStart := now.Truncate(vaneGrayBucketWidth)
	shortStart := bucketStart.Add(-vaneGrayShortWindow + vaneGrayBucketWidth)
	longStart := bucketStart.Add(-vaneGrayLongWindow + vaneGrayBucketWidth)
	endExclusive := bucketStart.Add(vaneGrayBucketWidth)

	o.mu.Lock()
	states := make([]vaneGraySeriesState, 0, len(o.series))
	for _, state := range o.series {
		if state == nil {
			continue
		}
		copied := vaneGraySeriesState{
			candidate: state.candidate,
			identity:  state.identity,
			transport: state.transport,
			buckets:   make(map[int64]*vaneGrayBucket, len(state.buckets)),
		}
		for timestamp, bucket := range state.buckets {
			if bucket == nil {
				continue
			}
			bucketCopy := *bucket
			copied.buckets[timestamp] = &bucketCopy
		}
		states = append(states, copied)
	}
	o.mu.Unlock()

	for _, state := range states {
		shortWindow := VaneDiagnosticGrayWindow{Start: shortStart, EndExclusive: endExclusive}
		longWindow := VaneDiagnosticGrayWindow{Start: longStart, EndExclusive: endExclusive}
		for _, bucket := range state.buckets {
			if bucket.start.Before(longStart) || !bucket.start.Before(endExclusive) {
				continue
			}
			addVaneGrayBucket(&longWindow, bucket)
			if !bucket.start.Before(shortStart) {
				addVaneGrayBucket(&shortWindow, bucket)
			}
		}
		finishVaneGrayWindow(&shortWindow)
		finishVaneGrayWindow(&longWindow)
		if longWindow.Attempt.Denominator == 0 && longWindow.Close.Denominator == 0 {
			continue
		}
		level, reasons := vaneGrayAlertLevel(shortWindow, longWindow)
		series := VaneDiagnosticGraySeries{
			Candidate:   state.candidate,
			MemberID:    vaneGrayMemberID(state.identity),
			Transport:   state.transport.String(),
			Level:       level,
			Reasons:     reasons,
			ShortWindow: shortWindow,
			LongWindow:  longWindow,
		}
		result.Series = append(result.Series, series)
		if vaneGrayLevelRank(level) > vaneGrayLevelRank(result.CurrentLevel) {
			result.CurrentLevel = level
		}
	}
	sort.Slice(result.Series, func(i, j int) bool {
		if result.Series[i].Candidate != result.Series[j].Candidate {
			return result.Series[i].Candidate < result.Series[j].Candidate
		}
		if result.Series[i].MemberID != result.Series[j].MemberID {
			return result.Series[i].MemberID < result.Series[j].MemberID
		}
		return result.Series[i].Transport < result.Series[j].Transport
	})
	return result
}

func addVaneGrayBucket(window *VaneDiagnosticGrayWindow, bucket *vaneGrayBucket) {
	window.Attempt.Successes += bucket.attemptSuccess
	window.Attempt.Failures += bucket.attemptFailure
	window.Close.Progress += bucket.closeProgress
	window.Close.Tiny += bucket.closeTiny
}

func finishVaneGrayWindow(window *VaneDiagnosticGrayWindow) {
	window.Attempt.Denominator = window.Attempt.Successes + window.Attempt.Failures
	if window.Attempt.Denominator > 0 {
		window.Attempt.FailureRate = float64(window.Attempt.Failures) / float64(window.Attempt.Denominator)
	}
	window.Close.Denominator = window.Close.Progress + window.Close.Tiny
	if window.Close.Denominator > 0 {
		window.Close.TinyRate = float64(window.Close.Tiny) / float64(window.Close.Denominator)
	}
}

func vaneGrayAlertLevel(short, long VaneDiagnosticGrayWindow) (string, []string) {
	attemptSuspected := short.Attempt.Denominator >= vaneGrayAttemptSuspectedShortDenominator &&
		short.Attempt.Failures >= vaneGrayAttemptSuspectedShortFailures &&
		short.Attempt.FailureRate >= vaneGrayAttemptSuspectedShortRate &&
		long.Attempt.Denominator >= vaneGrayAttemptSuspectedLongDenominator &&
		long.Attempt.Failures >= vaneGrayAttemptSuspectedLongFailures &&
		long.Attempt.FailureRate >= vaneGrayAttemptSuspectedLongRate
	closeSuspected := short.Close.Denominator >= vaneGrayCloseSuspectedShortDenominator &&
		short.Close.Tiny >= vaneGrayCloseSuspectedShortTiny &&
		short.Close.TinyRate >= vaneGrayCloseSuspectedShortRate &&
		long.Close.Denominator >= vaneGrayCloseSuspectedLongDenominator &&
		long.Close.Tiny >= vaneGrayCloseSuspectedLongTiny &&
		long.Close.TinyRate >= vaneGrayCloseSuspectedLongRate
	if attemptSuspected || closeSuspected {
		reasons := make([]string, 0, 2)
		if attemptSuspected {
			reasons = append(reasons, "attempt-sustained-disagreement")
		}
		if closeSuspected {
			reasons = append(reasons, "close-sustained-disagreement")
		}
		return vaneGrayLevelSuspected, reasons
	}

	attemptWatch := short.Attempt.Denominator >= vaneGrayAttemptWatchDenominator &&
		short.Attempt.Failures >= vaneGrayAttemptWatchFailures &&
		short.Attempt.FailureRate >= vaneGrayAttemptWatchRate
	closeWatch := short.Close.Denominator >= vaneGrayCloseWatchDenominator &&
		short.Close.Tiny >= vaneGrayCloseWatchTiny &&
		short.Close.TinyRate >= vaneGrayCloseWatchRate
	if attemptWatch || closeWatch {
		reasons := make([]string, 0, 2)
		if attemptWatch {
			reasons = append(reasons, "attempt-short-disagreement")
		}
		if closeWatch {
			reasons = append(reasons, "close-short-disagreement")
		}
		return vaneGrayLevelWatch, reasons
	}
	if long.Attempt.Denominator >= vaneGrayAttemptSufficientDenominator || long.Close.Denominator >= vaneGrayCloseSufficientDenominator {
		return vaneGrayLevelNormal, []string{}
	}
	return vaneGrayLevelInsufficient, []string{}
}

func vaneGrayLevelRank(level string) int {
	switch level {
	case vaneGrayLevelSuspected:
		return 3
	case vaneGrayLevelWatch:
		return 2
	case vaneGrayLevelNormal:
		return 1
	default:
		return 0
	}
}

func vaneGrayThresholds() VaneDiagnosticGrayThresholds {
	return VaneDiagnosticGrayThresholds{
		AttemptSufficientDenominator:     vaneGrayAttemptSufficientDenominator,
		CloseSufficientDenominator:       vaneGrayCloseSufficientDenominator,
		AttemptWatchDenominator:          vaneGrayAttemptWatchDenominator,
		AttemptWatchFailures:             vaneGrayAttemptWatchFailures,
		AttemptWatchRate:                 vaneGrayAttemptWatchRate,
		CloseWatchDenominator:            vaneGrayCloseWatchDenominator,
		CloseWatchTiny:                   vaneGrayCloseWatchTiny,
		CloseWatchRate:                   vaneGrayCloseWatchRate,
		AttemptSuspectedShortDenominator: vaneGrayAttemptSuspectedShortDenominator,
		AttemptSuspectedShortFailures:    vaneGrayAttemptSuspectedShortFailures,
		AttemptSuspectedShortRate:        vaneGrayAttemptSuspectedShortRate,
		AttemptSuspectedLongDenominator:  vaneGrayAttemptSuspectedLongDenominator,
		AttemptSuspectedLongFailures:     vaneGrayAttemptSuspectedLongFailures,
		AttemptSuspectedLongRate:         vaneGrayAttemptSuspectedLongRate,
		CloseSuspectedShortDenominator:   vaneGrayCloseSuspectedShortDenominator,
		CloseSuspectedShortTiny:          vaneGrayCloseSuspectedShortTiny,
		CloseSuspectedShortRate:          vaneGrayCloseSuspectedShortRate,
		CloseSuspectedLongDenominator:    vaneGrayCloseSuspectedLongDenominator,
		CloseSuspectedLongTiny:           vaneGrayCloseSuspectedLongTiny,
		CloseSuspectedLongRate:           vaneGrayCloseSuspectedLongRate,
	}
}

func newVaneGrayExclusions() VaneDiagnosticGrayExclusions {
	return normalizeVaneGrayExclusions(VaneDiagnosticGrayExclusions{})
}

func normalizeVaneGrayExclusions(source VaneDiagnosticGrayExclusions) VaneDiagnosticGrayExclusions {
	result := VaneDiagnosticGrayExclusions{
		Attempt: make(map[string]uint64, len(vaneGrayAttemptExclusionReasons)),
		Close:   make(map[string]uint64, len(vaneGrayCloseExclusionReasons)),
	}
	for _, reason := range vaneGrayAttemptExclusionReasons {
		result.Attempt[reason] = source.Attempt[reason]
	}
	for _, reason := range vaneGrayCloseExclusionReasons {
		result.Close[reason] = source.Close[reason]
	}
	return result
}

func vaneGrayKnownExclusion(channel, reason string) bool {
	reasons := vaneGrayAttemptExclusionReasons[:]
	if channel == "close" {
		reasons = vaneGrayCloseExclusionReasons[:]
	} else if channel != "attempt" {
		return false
	}
	for _, candidate := range reasons {
		if candidate == reason {
			return true
		}
	}
	return false
}

func vaneGrayMemberID(identity string) string {
	if identity == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(identity))
	return "agm1:" + base64.RawURLEncoding.EncodeToString(digest[:12])
}
