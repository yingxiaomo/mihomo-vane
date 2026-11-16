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
	sageGrayBucketWidth = 30 * time.Second
	sageGrayShortWindow = 5 * time.Minute
	sageGrayLongWindow  = 15 * time.Minute
	sageGrayMaxSeries   = 512

	sageGrayAttemptSufficientDenominator = uint64(20)
	sageGrayCloseSufficientDenominator   = uint64(8)

	sageGrayAttemptWatchDenominator = uint64(20)
	sageGrayAttemptWatchFailures    = uint64(3)
	sageGrayAttemptWatchRate        = 0.10
	sageGrayCloseWatchDenominator   = uint64(8)
	sageGrayCloseWatchTiny          = uint64(4)
	sageGrayCloseWatchRate          = 0.50

	sageGrayAttemptSuspectedShortDenominator = uint64(20)
	sageGrayAttemptSuspectedShortFailures    = uint64(5)
	sageGrayAttemptSuspectedShortRate        = 0.25
	sageGrayAttemptSuspectedLongDenominator  = uint64(50)
	sageGrayAttemptSuspectedLongFailures     = uint64(8)
	sageGrayAttemptSuspectedLongRate         = 0.15
	sageGrayCloseSuspectedShortDenominator   = uint64(12)
	sageGrayCloseSuspectedShortTiny          = uint64(8)
	sageGrayCloseSuspectedShortRate          = 2.0 / 3.0
	sageGrayCloseSuspectedLongDenominator    = uint64(20)
	sageGrayCloseSuspectedLongTiny           = uint64(10)
	sageGrayCloseSuspectedLongRate           = 0.50
)

const (
	sageGrayLevelInsufficient = "insufficient"
	sageGrayLevelNormal       = "normal"
	sageGrayLevelWatch        = "watch"
	sageGrayLevelSuspected    = "suspected"
)

var (
	sageGrayAttemptExclusionReasons = [...]string{
		"missing-member-identity",
		"probe-not-reported-alive",
		"internal-flow",
		"invalid-target",
		"dns-bootstrap",
		"neutral-outcome",
	}
	sageGrayCloseExclusionReasons = [...]string{
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

type SageDiagnosticGrayCounters struct {
	AttemptEligible  uint64 `json:"attemptEligible"`
	AttemptSucceeded uint64 `json:"attemptSucceeded"`
	AttemptFailed    uint64 `json:"attemptFailed"`
	CloseEligible    uint64 `json:"closeEligible"`
	CloseProgress    uint64 `json:"closeProgress"`
	CloseTiny        uint64 `json:"closeTiny"`
}

type SageDiagnosticGrayExclusions struct {
	Attempt map[string]uint64 `json:"attempt"`
	Close   map[string]uint64 `json:"close"`
}

type SageDiagnosticGrayThresholds struct {
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

type SageDiagnosticGrayAttemptWindow struct {
	Denominator uint64  `json:"denominator"`
	Successes   uint64  `json:"successes"`
	Failures    uint64  `json:"failures"`
	FailureRate float64 `json:"failureRate"`
}

type SageDiagnosticGrayCloseWindow struct {
	Denominator uint64  `json:"denominator"`
	Progress    uint64  `json:"progress"`
	Tiny        uint64  `json:"tiny"`
	TinyRate    float64 `json:"tinyRate"`
}

type SageDiagnosticGrayWindow struct {
	Start        time.Time                       `json:"start"`
	EndExclusive time.Time                       `json:"endExclusive"`
	Attempt      SageDiagnosticGrayAttemptWindow `json:"attempt"`
	Close        SageDiagnosticGrayCloseWindow   `json:"close"`
}

type SageDiagnosticGraySeries struct {
	Candidate   string                   `json:"candidate"`
	MemberID    string                   `json:"memberId"`
	Transport   string                   `json:"transport"`
	Level       string                   `json:"level"`
	Reasons     []string                 `json:"reasons"`
	ShortWindow SageDiagnosticGrayWindow `json:"shortWindow"`
	LongWindow  SageDiagnosticGrayWindow `json:"longWindow"`
}

type SageDiagnosticGrayFailure struct {
	Enabled                 bool                         `json:"enabled"`
	Scope                   string                       `json:"scope"`
	CorrelationOnly         bool                         `json:"correlationOnly"`
	ProbeFreshnessAvailable bool                         `json:"probeFreshnessAvailable"`
	BucketMS                int64                        `json:"bucketMs"`
	ShortWindowMS           int64                        `json:"shortWindowMs"`
	LongWindowMS            int64                        `json:"longWindowMs"`
	MaxSeries               int                          `json:"maxSeries"`
	CurrentLevel            string                       `json:"currentLevel"`
	Thresholds              SageDiagnosticGrayThresholds `json:"thresholds"`
	Counters                SageDiagnosticGrayCounters   `json:"counters"`
	Exclusions              SageDiagnosticGrayExclusions `json:"exclusions"`
	Series                  []SageDiagnosticGraySeries   `json:"series"`
}

type sageGraySelection struct {
	candidate             string
	identity              string
	transport             sageTransport
	reportedAliveAtSelect bool
}

type sageGrayAttempt struct {
	once      sync.Once
	observer  *sageGrayObserver
	selection sageGraySelection
}

type sageGraySeriesKey struct {
	identity  string
	transport sageTransport
}

type sageGrayBucket struct {
	start          time.Time
	attemptSuccess uint64
	attemptFailure uint64
	closeProgress  uint64
	closeTiny      uint64
}

type sageGraySeriesState struct {
	candidate   string
	identity    string
	transport   sageTransport
	lastUpdated time.Time
	buckets     map[int64]*sageGrayBucket
}

type sageGrayObserver struct {
	mu          sync.Mutex
	enabled     bool
	clock       sageClock
	diagnostics *sageDiagnostics
	series      map[sageGraySeriesKey]*sageGraySeriesState
}

func newSageGrayObserver(enabled bool, clock sageClock, diagnostics *sageDiagnostics) *sageGrayObserver {
	if clock == nil {
		clock = sageSystemClock{}
	}
	return &sageGrayObserver{
		enabled:     enabled,
		clock:       clock,
		diagnostics: diagnostics,
		series:      make(map[sageGraySeriesKey]*sageGraySeriesState),
	}
}

func (o *sageGrayObserver) setDiagnostics(diagnostics *sageDiagnostics) {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.diagnostics = diagnostics
	o.mu.Unlock()
}

func (o *sageGrayObserver) newAttempt(selection sageGraySelection, metadata *C.Metadata) *sageGrayAttempt {
	if o == nil || !o.isEnabled() {
		return nil
	}
	if reason := sageGrayAttemptExclusion(selection, metadata); reason != "" {
		o.recordExclusion("attempt", reason)
		return nil
	}
	return &sageGrayAttempt{observer: o, selection: selection}
}

func (a *sageGrayAttempt) settle(outcome string) {
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

func (o *sageGrayObserver) recordClose(selection sageGraySelection, metadata *C.Metadata, observation sageConnectionCloseObservation) {
	if o == nil || !o.isEnabled() {
		return
	}
	if reason := sageGrayCloseExclusion(selection, metadata, observation); reason != "" {
		o.recordExclusion("close", reason)
		return
	}
	kind := "close-tiny"
	if observation.TotalReadBytes >= sageChurnMaxDownloadBytes {
		kind = "close-progress"
	}
	o.recordBucket(selection, kind)
	o.recordDiagnostic(sageDiagnosticRecord{kind: "gray-" + kind})
}

func sageGrayAttemptExclusion(selection sageGraySelection, metadata *C.Metadata) string {
	if selection.identity == "" {
		return "missing-member-identity"
	}
	if !selection.reportedAliveAtSelect {
		return "probe-not-reported-alive"
	}
	if metadata != nil && metadata.Type == C.INNER {
		return "internal-flow"
	}
	target, port, valid := sageChurnTarget(metadata)
	if !valid {
		return "invalid-target"
	}
	if sageChurnDNSBootstrap(target, port) {
		return "dns-bootstrap"
	}
	return ""
}

func sageGrayCloseExclusion(selection sageGraySelection, metadata *C.Metadata, observation sageConnectionCloseObservation) string {
	if selection.transport != sageTransportTCP {
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
	target, port, valid := sageChurnTarget(metadata)
	if !valid {
		return "invalid-target"
	}
	if sageChurnDNSBootstrap(target, port) {
		return "dns-bootstrap"
	}
	if observation.PolicyClosed {
		return "policy-close"
	}
	if !observation.WrotePayload {
		return "no-positive-write"
	}
	if observation.Age <= 0 || observation.Age >= sageChurnMaxLifetime {
		return "lifetime-outside-window"
	}
	return ""
}

func (o *sageGrayObserver) isEnabled() bool {
	o.mu.Lock()
	enabled := o.enabled
	o.mu.Unlock()
	return enabled
}

func (o *sageGrayObserver) recordAttempt(selection sageGraySelection, outcome string) {
	kind := "attempt-failed"
	if outcome == "success" {
		kind = "attempt-succeeded"
	}
	o.recordBucket(selection, kind)
	o.recordDiagnostic(sageDiagnosticRecord{kind: "gray-" + kind})
}

func (o *sageGrayObserver) recordExclusion(channel, reason string) {
	o.recordDiagnostic(sageDiagnosticRecord{kind: "gray-" + channel + "-excluded", reason: reason})
}

func (o *sageGrayObserver) recordDiagnostic(record sageDiagnosticRecord) {
	o.mu.Lock()
	diagnostics := o.diagnostics
	o.mu.Unlock()
	diagnostics.record(record)
}

func (o *sageGrayObserver) recordBucket(selection sageGraySelection, kind string) {
	now := o.clock.Now().UTC()
	bucketStart := now.Truncate(sageGrayBucketWidth)
	key := sageGraySeriesKey{identity: selection.identity, transport: selection.transport}

	o.mu.Lock()
	state := o.series[key]
	if state == nil {
		if len(o.series) >= sageGrayMaxSeries {
			o.evictOldestLocked()
		}
		state = &sageGraySeriesState{
			candidate: selection.candidate,
			identity:  selection.identity,
			transport: selection.transport,
			buckets:   make(map[int64]*sageGrayBucket),
		}
		o.series[key] = state
	}
	state.candidate = selection.candidate
	state.lastUpdated = now
	bucketKey := bucketStart.Unix()
	bucket := state.buckets[bucketKey]
	if bucket == nil {
		bucket = &sageGrayBucket{start: bucketStart}
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
	oldest := bucketStart.Add(-sageGrayLongWindow + sageGrayBucketWidth)
	for timestamp, candidate := range state.buckets {
		if candidate == nil || candidate.start.Before(oldest) {
			delete(state.buckets, timestamp)
		}
	}
	o.mu.Unlock()
}

func (o *sageGrayObserver) evictOldestLocked() {
	var oldestKey sageGraySeriesKey
	var oldest *sageGraySeriesState
	found := false
	for key, state := range o.series {
		if !found || sageGraySeriesOlder(key, state, oldestKey, oldest) {
			oldestKey, oldest, found = key, state, true
		}
	}
	if found {
		delete(o.series, oldestKey)
	}
}

func sageGraySeriesOlder(leftKey sageGraySeriesKey, left *sageGraySeriesState, rightKey sageGraySeriesKey, right *sageGraySeriesState) bool {
	if left == nil || right == nil {
		return left == nil && right != nil
	}
	if !left.lastUpdated.Equal(right.lastUpdated) {
		return left.lastUpdated.Before(right.lastUpdated)
	}
	leftMember, rightMember := sageGrayMemberID(leftKey.identity), sageGrayMemberID(rightKey.identity)
	if leftMember != rightMember {
		return leftMember < rightMember
	}
	return leftKey.transport < rightKey.transport
}

func (o *sageGrayObserver) snapshot(persisted SageDiagnosticGrayFailure) SageDiagnosticGrayFailure {
	result := persisted
	result.Exclusions = normalizeSageGrayExclusions(result.Exclusions)
	result.Enabled = false
	if o != nil {
		result.Enabled = o.isEnabled()
	}
	result.Scope = "member-transport"
	result.CorrelationOnly = true
	result.ProbeFreshnessAvailable = false
	result.BucketMS = sageGrayBucketWidth.Milliseconds()
	result.ShortWindowMS = sageGrayShortWindow.Milliseconds()
	result.LongWindowMS = sageGrayLongWindow.Milliseconds()
	result.MaxSeries = sageGrayMaxSeries
	result.CurrentLevel = sageGrayLevelInsufficient
	result.Thresholds = sageGrayThresholds()
	result.Series = nil
	if o == nil || !result.Enabled {
		return result
	}

	now := o.clock.Now().UTC()
	bucketStart := now.Truncate(sageGrayBucketWidth)
	shortStart := bucketStart.Add(-sageGrayShortWindow + sageGrayBucketWidth)
	longStart := bucketStart.Add(-sageGrayLongWindow + sageGrayBucketWidth)
	endExclusive := bucketStart.Add(sageGrayBucketWidth)

	o.mu.Lock()
	states := make([]sageGraySeriesState, 0, len(o.series))
	for _, state := range o.series {
		if state == nil {
			continue
		}
		copied := sageGraySeriesState{
			candidate: state.candidate,
			identity:  state.identity,
			transport: state.transport,
			buckets:   make(map[int64]*sageGrayBucket, len(state.buckets)),
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
		shortWindow := SageDiagnosticGrayWindow{Start: shortStart, EndExclusive: endExclusive}
		longWindow := SageDiagnosticGrayWindow{Start: longStart, EndExclusive: endExclusive}
		for _, bucket := range state.buckets {
			if bucket.start.Before(longStart) || !bucket.start.Before(endExclusive) {
				continue
			}
			addSageGrayBucket(&longWindow, bucket)
			if !bucket.start.Before(shortStart) {
				addSageGrayBucket(&shortWindow, bucket)
			}
		}
		finishSageGrayWindow(&shortWindow)
		finishSageGrayWindow(&longWindow)
		if longWindow.Attempt.Denominator == 0 && longWindow.Close.Denominator == 0 {
			continue
		}
		level, reasons := sageGrayAlertLevel(shortWindow, longWindow)
		series := SageDiagnosticGraySeries{
			Candidate:   state.candidate,
			MemberID:    sageGrayMemberID(state.identity),
			Transport:   state.transport.String(),
			Level:       level,
			Reasons:     reasons,
			ShortWindow: shortWindow,
			LongWindow:  longWindow,
		}
		result.Series = append(result.Series, series)
		if sageGrayLevelRank(level) > sageGrayLevelRank(result.CurrentLevel) {
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

func addSageGrayBucket(window *SageDiagnosticGrayWindow, bucket *sageGrayBucket) {
	window.Attempt.Successes += bucket.attemptSuccess
	window.Attempt.Failures += bucket.attemptFailure
	window.Close.Progress += bucket.closeProgress
	window.Close.Tiny += bucket.closeTiny
}

func finishSageGrayWindow(window *SageDiagnosticGrayWindow) {
	window.Attempt.Denominator = window.Attempt.Successes + window.Attempt.Failures
	if window.Attempt.Denominator > 0 {
		window.Attempt.FailureRate = float64(window.Attempt.Failures) / float64(window.Attempt.Denominator)
	}
	window.Close.Denominator = window.Close.Progress + window.Close.Tiny
	if window.Close.Denominator > 0 {
		window.Close.TinyRate = float64(window.Close.Tiny) / float64(window.Close.Denominator)
	}
}

func sageGrayAlertLevel(short, long SageDiagnosticGrayWindow) (string, []string) {
	attemptSuspected := short.Attempt.Denominator >= sageGrayAttemptSuspectedShortDenominator &&
		short.Attempt.Failures >= sageGrayAttemptSuspectedShortFailures &&
		short.Attempt.FailureRate >= sageGrayAttemptSuspectedShortRate &&
		long.Attempt.Denominator >= sageGrayAttemptSuspectedLongDenominator &&
		long.Attempt.Failures >= sageGrayAttemptSuspectedLongFailures &&
		long.Attempt.FailureRate >= sageGrayAttemptSuspectedLongRate
	closeSuspected := short.Close.Denominator >= sageGrayCloseSuspectedShortDenominator &&
		short.Close.Tiny >= sageGrayCloseSuspectedShortTiny &&
		short.Close.TinyRate >= sageGrayCloseSuspectedShortRate &&
		long.Close.Denominator >= sageGrayCloseSuspectedLongDenominator &&
		long.Close.Tiny >= sageGrayCloseSuspectedLongTiny &&
		long.Close.TinyRate >= sageGrayCloseSuspectedLongRate
	if attemptSuspected || closeSuspected {
		reasons := make([]string, 0, 2)
		if attemptSuspected {
			reasons = append(reasons, "attempt-sustained-disagreement")
		}
		if closeSuspected {
			reasons = append(reasons, "close-sustained-disagreement")
		}
		return sageGrayLevelSuspected, reasons
	}

	attemptWatch := short.Attempt.Denominator >= sageGrayAttemptWatchDenominator &&
		short.Attempt.Failures >= sageGrayAttemptWatchFailures &&
		short.Attempt.FailureRate >= sageGrayAttemptWatchRate
	closeWatch := short.Close.Denominator >= sageGrayCloseWatchDenominator &&
		short.Close.Tiny >= sageGrayCloseWatchTiny &&
		short.Close.TinyRate >= sageGrayCloseWatchRate
	if attemptWatch || closeWatch {
		reasons := make([]string, 0, 2)
		if attemptWatch {
			reasons = append(reasons, "attempt-short-disagreement")
		}
		if closeWatch {
			reasons = append(reasons, "close-short-disagreement")
		}
		return sageGrayLevelWatch, reasons
	}
	if long.Attempt.Denominator >= sageGrayAttemptSufficientDenominator || long.Close.Denominator >= sageGrayCloseSufficientDenominator {
		return sageGrayLevelNormal, []string{}
	}
	return sageGrayLevelInsufficient, []string{}
}

func sageGrayLevelRank(level string) int {
	switch level {
	case sageGrayLevelSuspected:
		return 3
	case sageGrayLevelWatch:
		return 2
	case sageGrayLevelNormal:
		return 1
	default:
		return 0
	}
}

func sageGrayThresholds() SageDiagnosticGrayThresholds {
	return SageDiagnosticGrayThresholds{
		AttemptSufficientDenominator:     sageGrayAttemptSufficientDenominator,
		CloseSufficientDenominator:       sageGrayCloseSufficientDenominator,
		AttemptWatchDenominator:          sageGrayAttemptWatchDenominator,
		AttemptWatchFailures:             sageGrayAttemptWatchFailures,
		AttemptWatchRate:                 sageGrayAttemptWatchRate,
		CloseWatchDenominator:            sageGrayCloseWatchDenominator,
		CloseWatchTiny:                   sageGrayCloseWatchTiny,
		CloseWatchRate:                   sageGrayCloseWatchRate,
		AttemptSuspectedShortDenominator: sageGrayAttemptSuspectedShortDenominator,
		AttemptSuspectedShortFailures:    sageGrayAttemptSuspectedShortFailures,
		AttemptSuspectedShortRate:        sageGrayAttemptSuspectedShortRate,
		AttemptSuspectedLongDenominator:  sageGrayAttemptSuspectedLongDenominator,
		AttemptSuspectedLongFailures:     sageGrayAttemptSuspectedLongFailures,
		AttemptSuspectedLongRate:         sageGrayAttemptSuspectedLongRate,
		CloseSuspectedShortDenominator:   sageGrayCloseSuspectedShortDenominator,
		CloseSuspectedShortTiny:          sageGrayCloseSuspectedShortTiny,
		CloseSuspectedShortRate:          sageGrayCloseSuspectedShortRate,
		CloseSuspectedLongDenominator:    sageGrayCloseSuspectedLongDenominator,
		CloseSuspectedLongTiny:           sageGrayCloseSuspectedLongTiny,
		CloseSuspectedLongRate:           sageGrayCloseSuspectedLongRate,
	}
}

func newSageGrayExclusions() SageDiagnosticGrayExclusions {
	return normalizeSageGrayExclusions(SageDiagnosticGrayExclusions{})
}

func normalizeSageGrayExclusions(source SageDiagnosticGrayExclusions) SageDiagnosticGrayExclusions {
	result := SageDiagnosticGrayExclusions{
		Attempt: make(map[string]uint64, len(sageGrayAttemptExclusionReasons)),
		Close:   make(map[string]uint64, len(sageGrayCloseExclusionReasons)),
	}
	for _, reason := range sageGrayAttemptExclusionReasons {
		result.Attempt[reason] = source.Attempt[reason]
	}
	for _, reason := range sageGrayCloseExclusionReasons {
		result.Close[reason] = source.Close[reason]
	}
	return result
}

func sageGrayKnownExclusion(channel, reason string) bool {
	reasons := sageGrayAttemptExclusionReasons[:]
	if channel == "close" {
		reasons = sageGrayCloseExclusionReasons[:]
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

func sageGrayMemberID(identity string) string {
	if identity == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(identity))
	return "agm1:" + base64.RawURLEncoding.EncodeToString(digest[:12])
}
