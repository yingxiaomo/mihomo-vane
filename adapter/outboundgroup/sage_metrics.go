package outboundgroup

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// sageScene is deliberately small and closed: unknown values use the
// conservative default scene rather than acquiring their own metric history.
type sageScene uint8

const (
	sageSceneDefault sageScene = iota
	sageSceneInteractive
	sageSceneMedia
	sageSceneBulk
)

func (s sageScene) String() string {
	switch s {
	case sageSceneInteractive:
		return "interactive"
	case sageSceneMedia:
		return "media"
	case sageSceneBulk:
		return "bulk"
	default:
		return "default"
	}
}

func parseSageScene(value string) (sageScene, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "default":
		return sageSceneDefault, true
	case "interactive":
		return sageSceneInteractive, true
	case "media":
		return sageSceneMedia, true
	case "bulk":
		return sageSceneBulk, true
	default:
		return sageSceneDefault, false
	}
}

func normalizeSageDomain(value string) (string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.TrimSuffix(normalized, ".")
	if normalized == "" || strings.HasPrefix(normalized, ".") || strings.HasSuffix(normalized, ".") || strings.Contains(normalized, "..") {
		return "", false
	}
	return normalized, true
}

type sageRuleKind uint8

const (
	sageRuleInvalid sageRuleKind = iota
	sageRuleDomain
	sageRuleDomainSuffix
	sageRuleNetwork
	sageRuleDstPort
	sageRuleInName
	sageRuleInUser
	sageRuleProcess
	sageRuleProcessPath
	sageRuleDSCP
)

type sageUintRange struct {
	first uint64
	last  uint64
}

func (r sageUintRange) contains(value uint64) bool {
	return value >= r.first && value <= r.last
}

// sageSceneRule is the parsed, I/O-free form used on the selection path.
// Config strings use TYPE,payload,scene and are evaluated in slice order.
type sageSceneRule struct {
	kind    sageRuleKind
	scene   sageScene
	value   string
	values  []string
	ranges  []sageUintRange
	network C.NetWork
}

func parseSageSceneRules(raw []string) ([]sageSceneRule, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	rules := make([]sageSceneRule, 0, len(raw))
	for i, text := range raw {
		rule, err := parseSageSceneRule(text)
		if err != nil {
			return nil, fmt.Errorf("sage scene rule %d: %w", i, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func parseSageSceneRule(text string) (sageSceneRule, error) {
	parts := strings.Split(text, ",")
	if len(parts) != 3 {
		return sageSceneRule{}, fmt.Errorf("expected TYPE,payload,scene")
	}

	ruleType := strings.ToUpper(strings.TrimSpace(parts[0]))
	payload := strings.TrimSpace(parts[1])
	scene, ok := parseSageScene(parts[2])
	if !ok {
		return sageSceneRule{}, fmt.Errorf("unsupported scene %q", strings.TrimSpace(parts[2]))
	}
	if payload == "" {
		return sageSceneRule{}, fmt.Errorf("empty payload for %s", ruleType)
	}

	rule := sageSceneRule{scene: scene}
	switch ruleType {
	case "DOMAIN":
		rule.kind = sageRuleDomain
		var valid bool
		rule.value, valid = normalizeSageDomain(payload)
		if !valid {
			return sageSceneRule{}, fmt.Errorf("invalid DOMAIN payload %q", payload)
		}
	case "DOMAIN-SUFFIX":
		rule.kind = sageRuleDomainSuffix
		var valid bool
		rule.value, valid = normalizeSageDomain(payload)
		if !valid {
			return sageSceneRule{}, fmt.Errorf("invalid DOMAIN-SUFFIX payload %q", payload)
		}
	case "NETWORK":
		rule.kind = sageRuleNetwork
		switch strings.ToLower(payload) {
		case "tcp":
			rule.network = C.TCP
		case "udp":
			rule.network = C.UDP
		default:
			return sageSceneRule{}, fmt.Errorf("unsupported network %q", payload)
		}
	case "DST-PORT":
		rule.kind = sageRuleDstPort
		ranges, err := parseSageUintRanges(payload, math.MaxUint16)
		if err != nil {
			return sageSceneRule{}, fmt.Errorf("invalid DST-PORT payload %q: %w", payload, err)
		}
		rule.ranges = ranges
	case "IN-NAME":
		rule.kind = sageRuleInName
		values, err := parseSageAlternatives(payload)
		if err != nil {
			return sageSceneRule{}, err
		}
		rule.values = values
	case "IN-USER":
		rule.kind = sageRuleInUser
		values, err := parseSageAlternatives(payload)
		if err != nil {
			return sageSceneRule{}, err
		}
		rule.values = values
	case "PROCESS":
		rule.kind = sageRuleProcess
		rule.value = payload
	case "PROCESS-PATH":
		rule.kind = sageRuleProcessPath
		rule.value = payload
	case "DSCP":
		rule.kind = sageRuleDSCP
		ranges, err := parseSageUintRanges(payload, 63)
		if err != nil {
			return sageSceneRule{}, fmt.Errorf("invalid DSCP payload %q: %w", payload, err)
		}
		rule.ranges = ranges
	default:
		return sageSceneRule{}, fmt.Errorf("unsupported rule type %q", ruleType)
	}
	return rule, nil
}

func parseSageAlternatives(payload string) ([]string, error) {
	parts := strings.Split(payload, "/")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			return nil, fmt.Errorf("empty alternative in payload %q", payload)
		}
		values = append(values, value)
	}
	return values, nil
}

func parseSageUintRanges(payload string, maximum uint64) ([]sageUintRange, error) {
	parts := strings.Split(payload, "/")
	ranges := make([]sageUintRange, 0, len(parts))
	for _, part := range parts {
		bounds := strings.Split(strings.TrimSpace(part), "-")
		if len(bounds) < 1 || len(bounds) > 2 || bounds[0] == "" {
			return nil, fmt.Errorf("invalid range %q", part)
		}
		first, err := strconv.ParseUint(strings.TrimSpace(bounds[0]), 10, 64)
		if err != nil || first > maximum {
			return nil, fmt.Errorf("invalid range start %q", bounds[0])
		}
		last := first
		if len(bounds) == 2 {
			if bounds[1] == "" {
				return nil, fmt.Errorf("invalid range end")
			}
			last, err = strconv.ParseUint(strings.TrimSpace(bounds[1]), 10, 64)
			if err != nil || last > maximum || last < first {
				return nil, fmt.Errorf("invalid range end %q", bounds[1])
			}
		}
		ranges = append(ranges, sageUintRange{first: first, last: last})
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("empty ranges")
	}
	return ranges, nil
}

func classifySageScene(metadata *C.Metadata, rules []sageSceneRule) sageScene {
	if metadata == nil {
		return sageSceneDefault
	}
	for _, rule := range rules {
		if rule.matches(metadata) {
			return rule.scene
		}
	}
	return sageSceneDefault
}

func (r sageSceneRule) matches(metadata *C.Metadata) bool {
	if metadata == nil {
		return false
	}

	switch r.kind {
	case sageRuleDomain:
		host, valid := normalizeSageDomain(metadata.RuleHost())
		return valid && host == r.value
	case sageRuleDomainSuffix:
		host, valid := normalizeSageDomain(metadata.RuleHost())
		return valid && (host == r.value || strings.HasSuffix(host, "."+r.value))
	case sageRuleNetwork:
		return metadata.NetWork == r.network
	case sageRuleDstPort:
		return metadata.DstPort != 0 && sageRangesContain(r.ranges, uint64(metadata.DstPort))
	case sageRuleInName:
		return sageStringsContain(r.values, metadata.InName)
	case sageRuleInUser:
		return sageStringsContain(r.values, metadata.InUser)
	case sageRuleProcess:
		return strings.EqualFold(metadata.Process, r.value)
	case sageRuleProcessPath:
		return strings.EqualFold(metadata.ProcessPath, r.value)
	case sageRuleDSCP:
		// Metadata does not carry a separate DSCP-presence bit. Treat the
		// zero value as unknown so an omitted field cannot satisfy a rule.
		return metadata.DSCP != 0 && sageRangesContain(r.ranges, uint64(metadata.DSCP))
	default:
		return false
	}
}

func sageStringsContain(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sageRangesContain(ranges []sageUintRange, target uint64) bool {
	for _, valueRange := range ranges {
		if valueRange.contains(target) {
			return true
		}
	}
	return false
}

type sageClock interface {
	Now() time.Time
}

type sageSystemClock struct{}

func (sageSystemClock) Now() time.Time { return time.Now() }

type sageMetricKind uint8

const (
	sageMetricFailure sageMetricKind = iota
	sageMetricConnect
	sageMetricResponse
	sageMetricThroughput
)

const sageMinimumEvidence = 1e-6

type sageMetricSpec struct {
	fastHalfLife time.Duration
	slowHalfLife time.Duration
	confidenceK  float64
	missingCost  float64
}

func sageSpec(kind sageMetricKind) sageMetricSpec {
	switch kind {
	case sageMetricFailure:
		return sageMetricSpec{2 * time.Minute, 30 * time.Minute, 8, 0.35}
	case sageMetricConnect:
		return sageMetricSpec{5 * time.Minute, 2 * time.Hour, 6, 0.55}
	case sageMetricResponse:
		return sageMetricSpec{5 * time.Minute, 2 * time.Hour, 6, 0.55}
	case sageMetricThroughput:
		return sageMetricSpec{10 * time.Minute, 6 * time.Hour, 4, 0.60}
	default:
		return sageMetricSpec{}
	}
}

type sageDecayLayer struct {
	weight    float64
	sum       float64
	updatedAt time.Time
	valid     bool
}

func (l *sageDecayLayer) observe(now time.Time, halfLife time.Duration, value, quality float64) {
	if quality <= 0 || math.IsNaN(quality) || math.IsInf(quality, 0) ||
		math.IsNaN(value) || math.IsInf(value, 0) {
		return
	}
	if !l.valid {
		l.weight = quality
		l.sum = quality * value
		l.updatedAt = now
		l.valid = true
		return
	}

	decay := sageDecay(now, l.updatedAt, halfLife)
	l.weight = decay*l.weight + quality
	l.sum = decay*l.sum + quality*value
	// A wall-clock rollback is a zero interval, not a move of the decay origin.
	if !now.Before(l.updatedAt) {
		l.updatedAt = now
	}
}

func (l sageDecayLayer) decayed(now time.Time, halfLife time.Duration) sageDecayLayer {
	if !l.valid {
		return l
	}
	decay := sageDecay(now, l.updatedAt, halfLife)
	l.weight *= decay
	l.sum *= decay
	return l
}

func sageDecay(now, updatedAt time.Time, halfLife time.Duration) float64 {
	if halfLife <= 0 || !now.After(updatedAt) {
		return 1
	}
	return math.Exp2(-float64(now.Sub(updatedAt)) / float64(halfLife))
}

type sageDualMetric struct {
	fast sageDecayLayer
	slow sageDecayLayer
}

func (m *sageDualMetric) observe(kind sageMetricKind, now time.Time, value, quality float64) {
	spec := sageSpec(kind)
	m.fast.observe(now, spec.fastHalfLife, value, quality)
	m.slow.observe(now, spec.slowHalfLife, value, quality)
}

type sageMetricEstimate struct {
	value      float64
	evidence   float64
	confidence float64
	valid      bool
}

func (m sageDualMetric) estimate(kind sageMetricKind, now time.Time) sageMetricEstimate {
	spec := sageSpec(kind)
	fast := m.fast.decayed(now, spec.fastHalfLife)
	slow := m.slow.decayed(now, spec.slowHalfLife)

	var weightedSum, evidence float64
	if fast.valid && fast.weight >= sageMinimumEvidence {
		weightedSum += 0.7 * fast.sum
		evidence += 0.7 * fast.weight
	}
	if slow.valid && slow.weight >= sageMinimumEvidence {
		weightedSum += 0.3 * slow.sum
		evidence += 0.3 * slow.weight
	}
	if evidence <= 0 {
		return sageMetricEstimate{}
	}
	return sageMetricEstimate{
		value:      weightedSum / evidence,
		evidence:   evidence,
		confidence: 1 - math.Exp(-evidence/spec.confidenceK),
		valid:      true,
	}
}

// sageMetrics keeps each observation family independent. TCP and UDP use
// separate instances; UDP simply never observes response or throughput.
type sageMetrics struct {
	failure    sageDualMetric
	connect    sageDualMetric
	response   sageDualMetric
	throughput sageDualMetric
}

func (m *sageMetrics) observeFailure(now time.Time, failed bool) {
	value := 0.0
	if failed {
		value = 1
	}
	m.failure.observe(sageMetricFailure, now, value, 1)
}

func (m *sageMetrics) observeConnect(now time.Time, elapsed time.Duration) {
	m.connect.observe(sageMetricConnect, now, sageLogClamp(durationMillis(elapsed), 1, 30_000), 1)
}

func (m *sageMetrics) observeResponse(now time.Time, elapsed time.Duration) {
	m.response.observe(sageMetricResponse, now, sageLogClamp(durationMillis(elapsed), 1, 60_000), 1)
}

func (m *sageMetrics) observeThroughput(now time.Time, bitsPerSecond float64) {
	m.throughput.observe(sageMetricThroughput, now, sageLogClamp(bitsPerSecond, 8_192, 1_000_000_000), 1)
}

func durationMillis(elapsed time.Duration) float64 {
	return float64(elapsed) / float64(time.Millisecond)
}

func sageLogClamp(value, minimum, maximum float64) float64 {
	return math.Log(sageClamp(value, minimum, maximum))
}

func sageClamp(value, minimum, maximum float64) float64 {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

type sageMetricsSnapshot struct {
	failure    sageMetricEstimate
	connect    sageMetricEstimate
	response   sageMetricEstimate
	throughput sageMetricEstimate
}

func (m sageMetrics) snapshot(now time.Time) sageMetricsSnapshot {
	return sageMetricsSnapshot{
		failure:    m.failure.estimate(sageMetricFailure, now),
		connect:    m.connect.estimate(sageMetricConnect, now),
		response:   m.response.estimate(sageMetricResponse, now),
		throughput: m.throughput.estimate(sageMetricThroughput, now),
	}
}

// sageMetricBank is a small clock-injected convenience for event writers.
// Selection can copy metrics and call snapshot with one shared timestamp.
type sageMetricBank struct {
	clock   sageClock
	metrics sageMetrics
}

func newSageMetricBank(clock sageClock) *sageMetricBank {
	if clock == nil {
		clock = sageSystemClock{}
	}
	return &sageMetricBank{clock: clock}
}

func (b *sageMetricBank) observeFailure(failed bool) {
	b.metrics.observeFailure(b.clock.Now(), failed)
}

func (b *sageMetricBank) observeConnect(elapsed time.Duration) {
	b.metrics.observeConnect(b.clock.Now(), elapsed)
}

func (b *sageMetricBank) observeResponse(elapsed time.Duration) {
	b.metrics.observeResponse(b.clock.Now(), elapsed)
}

func (b *sageMetricBank) observeThroughput(bitsPerSecond float64) {
	b.metrics.observeThroughput(b.clock.Now(), bitsPerSecond)
}

func (b *sageMetricBank) snapshot() sageMetricsSnapshot {
	return b.metrics.snapshot(b.clock.Now())
}

type sageSceneScoring struct {
	failureWeight      float64
	connectWeight      float64
	responseWeight     float64
	throughputWeight   float64
	connectGoodMillis  float64
	connectBadMillis   float64
	responseGoodMillis float64
	responseBadMillis  float64
	throughputLowBPS   float64
	throughputHighBPS  float64
}

func sageScoring(scene sageScene) sageSceneScoring {
	const mbps = 1_000_000
	switch scene {
	case sageSceneInteractive:
		return sageSceneScoring{0.35, 0.25, 0.35, 0.05, 50, 1500, 100, 1500, 0.25 * mbps, 5 * mbps}
	case sageSceneMedia:
		return sageSceneScoring{0.30, 0.10, 0.20, 0.40, 50, 1500, 200, 3000, 3 * mbps, 12 * mbps}
	case sageSceneBulk:
		return sageSceneScoring{0.25, 0.05, 0.05, 0.65, 50, 1500, 300, 5000, 2 * mbps, 80 * mbps}
	default:
		return sageSceneScoring{0.35, 0.20, 0.20, 0.25, 50, 1500, 150, 3000, 1 * mbps, 20 * mbps}
	}
}

func scoreSageMetrics(scene sageScene, snapshot sageMetricsSnapshot) int64 {
	return scoreSageMetricsWithPrior(scene, snapshot, sagePriorSnapshot{})
}

func scoreSageMetricsWithPrior(scene sageScene, snapshot sageMetricsSnapshot, prior sagePriorSnapshot) int64 {
	config := sageScoring(scene)
	failure := sageMetricCostWithPrior(snapshot.failure, sageMetricFailure, prior.failure, func(value float64) float64 {
		return sageClamp(value, 0, 1)
	})
	connect := sageMetricCostWithPrior(snapshot.connect, sageMetricConnect, prior.connect, func(value float64) float64 {
		return sageLatencyCost(value, config.connectGoodMillis, config.connectBadMillis)
	})
	response := sageMetricCostWithPrior(snapshot.response, sageMetricResponse, prior.response, func(value float64) float64 {
		return sageLatencyCost(value, config.responseGoodMillis, config.responseBadMillis)
	})
	throughput := sageMetricCostWithPrior(snapshot.throughput, sageMetricThroughput, prior.throughput, func(value float64) float64 {
		return sageThroughputCost(value, config.throughputLowBPS, config.throughputHighBPS)
	})

	score := config.failureWeight*failure +
		config.connectWeight*connect +
		config.responseWeight*response +
		config.throughputWeight*throughput
	return int64(math.Round(sageClamp(score, 0, 1) * 1_000_000))
}

func sageMetricCostWithPrior(estimate sageMetricEstimate, kind sageMetricKind, prior sagePriorEstimate, observed func(float64) float64) float64 {
	missing := sageSpec(kind).missingCost
	fallback := missing
	if prior.valid && sagePriorFinite(prior.value) && sagePriorFinite(prior.confidence) {
		confidence := sageClamp(prior.confidence, 0, sagePriorMaxConfidence)
		fallback = confidence*sageClamp(observed(prior.value), 0, 1) + (1-confidence)*missing
	}
	if !estimate.valid {
		return fallback
	}
	confidence := sageClamp(estimate.confidence, 0, 1)
	return confidence*sageClamp(observed(estimate.value), 0, 1) + (1-confidence)*fallback
}

func sageMetricCost(estimate sageMetricEstimate, kind sageMetricKind, observed func(float64) float64) float64 {
	missing := sageSpec(kind).missingCost
	if !estimate.valid {
		return missing
	}
	confidence := sageClamp(estimate.confidence, 0, 1)
	return confidence*sageClamp(observed(estimate.value), 0, 1) + (1-confidence)*missing
}

// Latency estimates are already in log(milliseconds).
func sageLatencyCost(logMillis, goodMillis, badMillis float64) float64 {
	return sageClamp((logMillis-math.Log(goodMillis))/math.Log(badMillis/goodMillis), 0, 1)
}

// Throughput estimates are already in log(bits/second).
func sageThroughputCost(logBPS, lowBPS, highBPS float64) float64 {
	return sageClamp((math.Log(highBPS)-logBPS)/math.Log(highBPS/lowBPS), 0, 1)
}

type sageCandidateScore struct {
	name        string
	scoreMicros int64
}

func rankSageCandidates(scene sageScene, snapshots map[string]sageMetricsSnapshot) []sageCandidateScore {
	ranked := make([]sageCandidateScore, 0, len(snapshots))
	for name, snapshot := range snapshots {
		ranked = append(ranked, sageCandidateScore{name: name, scoreMicros: scoreSageMetrics(scene, snapshot)})
	}
	sort.Slice(ranked, func(i, j int) bool {
		return compareSageCandidateScores(ranked[i], ranked[j]) < 0
	})
	return ranked
}

func compareSageCandidateScores(left, right sageCandidateScore) int {
	if left.scoreMicros < right.scoreMicros {
		return -1
	}
	if left.scoreMicros > right.scoreMicros {
		return 1
	}
	return strings.Compare(left.name, right.name)
}
