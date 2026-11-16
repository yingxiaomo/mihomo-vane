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

// vaneScene is deliberately small and closed: unknown values use the
// conservative default scene rather than acquiring their own metric history.
type vaneScene uint8

const (
	vaneSceneDefault vaneScene = iota
	vaneSceneInteractive
	vaneSceneMedia
	vaneSceneBulk
)

func (s vaneScene) String() string {
	switch s {
	case vaneSceneInteractive:
		return "interactive"
	case vaneSceneMedia:
		return "media"
	case vaneSceneBulk:
		return "bulk"
	default:
		return "default"
	}
}

func parseVaneScene(value string) (vaneScene, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "default":
		return vaneSceneDefault, true
	case "interactive":
		return vaneSceneInteractive, true
	case "media":
		return vaneSceneMedia, true
	case "bulk":
		return vaneSceneBulk, true
	default:
		return vaneSceneDefault, false
	}
}

func normalizeVaneDomain(value string) (string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.TrimSuffix(normalized, ".")
	if normalized == "" || strings.HasPrefix(normalized, ".") || strings.HasSuffix(normalized, ".") || strings.Contains(normalized, "..") {
		return "", false
	}
	return normalized, true
}

type vaneRuleKind uint8

const (
	vaneRuleInvalid vaneRuleKind = iota
	vaneRuleDomain
	vaneRuleDomainSuffix
	vaneRuleNetwork
	vaneRuleDstPort
	vaneRuleInName
	vaneRuleInUser
	vaneRuleProcess
	vaneRuleProcessPath
	vaneRuleDSCP
)

type vaneUintRange struct {
	first uint64
	last  uint64
}

func (r vaneUintRange) contains(value uint64) bool {
	return value >= r.first && value <= r.last
}

// vaneSceneRule is the parsed, I/O-free form used on the selection path.
// Config strings use TYPE,payload,scene and are evaluated in slice order.
type vaneSceneRule struct {
	kind    vaneRuleKind
	scene   vaneScene
	value   string
	values  []string
	ranges  []vaneUintRange
	network C.NetWork
}

func parseVaneSceneRules(raw []string) ([]vaneSceneRule, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	rules := make([]vaneSceneRule, 0, len(raw))
	for i, text := range raw {
		rule, err := parseVaneSceneRule(text)
		if err != nil {
			return nil, fmt.Errorf("vane scene rule %d: %w", i, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func parseVaneSceneRule(text string) (vaneSceneRule, error) {
	parts := strings.Split(text, ",")
	if len(parts) != 3 {
		return vaneSceneRule{}, fmt.Errorf("expected TYPE,payload,scene")
	}

	ruleType := strings.ToUpper(strings.TrimSpace(parts[0]))
	payload := strings.TrimSpace(parts[1])
	scene, ok := parseVaneScene(parts[2])
	if !ok {
		return vaneSceneRule{}, fmt.Errorf("unsupported scene %q", strings.TrimSpace(parts[2]))
	}
	if payload == "" {
		return vaneSceneRule{}, fmt.Errorf("empty payload for %s", ruleType)
	}

	rule := vaneSceneRule{scene: scene}
	switch ruleType {
	case "DOMAIN":
		rule.kind = vaneRuleDomain
		var valid bool
		rule.value, valid = normalizeVaneDomain(payload)
		if !valid {
			return vaneSceneRule{}, fmt.Errorf("invalid DOMAIN payload %q", payload)
		}
	case "DOMAIN-SUFFIX":
		rule.kind = vaneRuleDomainSuffix
		var valid bool
		rule.value, valid = normalizeVaneDomain(payload)
		if !valid {
			return vaneSceneRule{}, fmt.Errorf("invalid DOMAIN-SUFFIX payload %q", payload)
		}
	case "NETWORK":
		rule.kind = vaneRuleNetwork
		switch strings.ToLower(payload) {
		case "tcp":
			rule.network = C.TCP
		case "udp":
			rule.network = C.UDP
		default:
			return vaneSceneRule{}, fmt.Errorf("unsupported network %q", payload)
		}
	case "DST-PORT":
		rule.kind = vaneRuleDstPort
		ranges, err := parseVaneUintRanges(payload, math.MaxUint16)
		if err != nil {
			return vaneSceneRule{}, fmt.Errorf("invalid DST-PORT payload %q: %w", payload, err)
		}
		rule.ranges = ranges
	case "IN-NAME":
		rule.kind = vaneRuleInName
		values, err := parseVaneAlternatives(payload)
		if err != nil {
			return vaneSceneRule{}, err
		}
		rule.values = values
	case "IN-USER":
		rule.kind = vaneRuleInUser
		values, err := parseVaneAlternatives(payload)
		if err != nil {
			return vaneSceneRule{}, err
		}
		rule.values = values
	case "PROCESS":
		rule.kind = vaneRuleProcess
		rule.value = payload
	case "PROCESS-PATH":
		rule.kind = vaneRuleProcessPath
		rule.value = payload
	case "DSCP":
		rule.kind = vaneRuleDSCP
		ranges, err := parseVaneUintRanges(payload, 63)
		if err != nil {
			return vaneSceneRule{}, fmt.Errorf("invalid DSCP payload %q: %w", payload, err)
		}
		rule.ranges = ranges
	default:
		return vaneSceneRule{}, fmt.Errorf("unsupported rule type %q", ruleType)
	}
	return rule, nil
}

func parseVaneAlternatives(payload string) ([]string, error) {
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

func parseVaneUintRanges(payload string, maximum uint64) ([]vaneUintRange, error) {
	parts := strings.Split(payload, "/")
	ranges := make([]vaneUintRange, 0, len(parts))
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
		ranges = append(ranges, vaneUintRange{first: first, last: last})
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("empty ranges")
	}
	return ranges, nil
}

func classifyVaneScene(metadata *C.Metadata, rules []vaneSceneRule) vaneScene {
	if metadata == nil {
		return vaneSceneDefault
	}
	for _, rule := range rules {
		if rule.matches(metadata) {
			return rule.scene
		}
	}
	return vaneSceneDefault
}

func (r vaneSceneRule) matches(metadata *C.Metadata) bool {
	if metadata == nil {
		return false
	}

	switch r.kind {
	case vaneRuleDomain:
		host, valid := normalizeVaneDomain(metadata.RuleHost())
		return valid && host == r.value
	case vaneRuleDomainSuffix:
		host, valid := normalizeVaneDomain(metadata.RuleHost())
		return valid && (host == r.value || strings.HasSuffix(host, "."+r.value))
	case vaneRuleNetwork:
		return metadata.NetWork == r.network
	case vaneRuleDstPort:
		return metadata.DstPort != 0 && vaneRangesContain(r.ranges, uint64(metadata.DstPort))
	case vaneRuleInName:
		return vaneStringsContain(r.values, metadata.InName)
	case vaneRuleInUser:
		return vaneStringsContain(r.values, metadata.InUser)
	case vaneRuleProcess:
		return strings.EqualFold(metadata.Process, r.value)
	case vaneRuleProcessPath:
		return strings.EqualFold(metadata.ProcessPath, r.value)
	case vaneRuleDSCP:
		// Metadata does not carry a separate DSCP-presence bit. Treat the
		// zero value as unknown so an omitted field cannot satisfy a rule.
		return metadata.DSCP != 0 && vaneRangesContain(r.ranges, uint64(metadata.DSCP))
	default:
		return false
	}
}

func vaneStringsContain(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func vaneRangesContain(ranges []vaneUintRange, target uint64) bool {
	for _, valueRange := range ranges {
		if valueRange.contains(target) {
			return true
		}
	}
	return false
}

type vaneClock interface {
	Now() time.Time
}

type vaneSystemClock struct{}

func (vaneSystemClock) Now() time.Time { return time.Now() }

type vaneMetricKind uint8

const (
	vaneMetricFailure vaneMetricKind = iota
	vaneMetricConnect
	vaneMetricResponse
	vaneMetricThroughput
)

const vaneMinimumEvidence = 1e-6

type vaneMetricSpec struct {
	fastHalfLife time.Duration
	slowHalfLife time.Duration
	confidenceK  float64
	missingCost  float64
}

func vaneSpec(kind vaneMetricKind) vaneMetricSpec {
	switch kind {
	case vaneMetricFailure:
		return vaneMetricSpec{2 * time.Minute, 30 * time.Minute, 8, 0.35}
	case vaneMetricConnect:
		return vaneMetricSpec{5 * time.Minute, 2 * time.Hour, 6, 0.55}
	case vaneMetricResponse:
		return vaneMetricSpec{5 * time.Minute, 2 * time.Hour, 6, 0.55}
	case vaneMetricThroughput:
		return vaneMetricSpec{10 * time.Minute, 6 * time.Hour, 4, 0.60}
	default:
		return vaneMetricSpec{}
	}
}

type vaneDecayLayer struct {
	weight    float64
	sum       float64
	updatedAt time.Time
	valid     bool
}

func (l *vaneDecayLayer) observe(now time.Time, halfLife time.Duration, value, quality float64) {
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

	decay := vaneDecay(now, l.updatedAt, halfLife)
	l.weight = decay*l.weight + quality
	l.sum = decay*l.sum + quality*value
	// A wall-clock rollback is a zero interval, not a move of the decay origin.
	if !now.Before(l.updatedAt) {
		l.updatedAt = now
	}
}

func (l vaneDecayLayer) decayed(now time.Time, halfLife time.Duration) vaneDecayLayer {
	if !l.valid {
		return l
	}
	decay := vaneDecay(now, l.updatedAt, halfLife)
	l.weight *= decay
	l.sum *= decay
	return l
}

func vaneDecay(now, updatedAt time.Time, halfLife time.Duration) float64 {
	if halfLife <= 0 || !now.After(updatedAt) {
		return 1
	}
	return math.Exp2(-float64(now.Sub(updatedAt)) / float64(halfLife))
}

type vaneDualMetric struct {
	fast vaneDecayLayer
	slow vaneDecayLayer
}

func (m *vaneDualMetric) observe(kind vaneMetricKind, now time.Time, value, quality float64) {
	spec := vaneSpec(kind)
	m.fast.observe(now, spec.fastHalfLife, value, quality)
	m.slow.observe(now, spec.slowHalfLife, value, quality)
}

type vaneMetricEstimate struct {
	value      float64
	evidence   float64
	confidence float64
	valid      bool
}

func (m vaneDualMetric) estimate(kind vaneMetricKind, now time.Time) vaneMetricEstimate {
	spec := vaneSpec(kind)
	fast := m.fast.decayed(now, spec.fastHalfLife)
	slow := m.slow.decayed(now, spec.slowHalfLife)

	var weightedSum, evidence float64
	if fast.valid && fast.weight >= vaneMinimumEvidence {
		weightedSum += 0.7 * fast.sum
		evidence += 0.7 * fast.weight
	}
	if slow.valid && slow.weight >= vaneMinimumEvidence {
		weightedSum += 0.3 * slow.sum
		evidence += 0.3 * slow.weight
	}
	if evidence <= 0 {
		return vaneMetricEstimate{}
	}
	return vaneMetricEstimate{
		value:      weightedSum / evidence,
		evidence:   evidence,
		confidence: 1 - math.Exp(-evidence/spec.confidenceK),
		valid:      true,
	}
}

// vaneMetrics keeps each observation family independent. TCP and UDP use
// separate instances; UDP simply never observes response or throughput.
type vaneMetrics struct {
	failure    vaneDualMetric
	connect    vaneDualMetric
	response   vaneDualMetric
	throughput vaneDualMetric
}

func (m *vaneMetrics) observeFailure(now time.Time, failed bool) {
	value := 0.0
	if failed {
		value = 1
	}
	m.failure.observe(vaneMetricFailure, now, value, 1)
}

func (m *vaneMetrics) observeConnect(now time.Time, elapsed time.Duration) {
	m.connect.observe(vaneMetricConnect, now, vaneLogClamp(durationMillis(elapsed), 1, 30_000), 1)
}

func (m *vaneMetrics) observeResponse(now time.Time, elapsed time.Duration) {
	m.response.observe(vaneMetricResponse, now, vaneLogClamp(durationMillis(elapsed), 1, 60_000), 1)
}

func (m *vaneMetrics) observeThroughput(now time.Time, bitsPerSecond float64) {
	m.throughput.observe(vaneMetricThroughput, now, vaneLogClamp(bitsPerSecond, 8_192, 1_000_000_000), 1)
}

func durationMillis(elapsed time.Duration) float64 {
	return float64(elapsed) / float64(time.Millisecond)
}

func vaneLogClamp(value, minimum, maximum float64) float64 {
	return math.Log(vaneClamp(value, minimum, maximum))
}

func vaneClamp(value, minimum, maximum float64) float64 {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

type vaneMetricsSnapshot struct {
	failure    vaneMetricEstimate
	connect    vaneMetricEstimate
	response   vaneMetricEstimate
	throughput vaneMetricEstimate
}

func (m vaneMetrics) snapshot(now time.Time) vaneMetricsSnapshot {
	return vaneMetricsSnapshot{
		failure:    m.failure.estimate(vaneMetricFailure, now),
		connect:    m.connect.estimate(vaneMetricConnect, now),
		response:   m.response.estimate(vaneMetricResponse, now),
		throughput: m.throughput.estimate(vaneMetricThroughput, now),
	}
}

// vaneMetricBank is a small clock-injected convenience for event writers.
// Selection can copy metrics and call snapshot with one shared timestamp.
type vaneMetricBank struct {
	clock   vaneClock
	metrics vaneMetrics
}

func newVaneMetricBank(clock vaneClock) *vaneMetricBank {
	if clock == nil {
		clock = vaneSystemClock{}
	}
	return &vaneMetricBank{clock: clock}
}

func (b *vaneMetricBank) observeFailure(failed bool) {
	b.metrics.observeFailure(b.clock.Now(), failed)
}

func (b *vaneMetricBank) observeConnect(elapsed time.Duration) {
	b.metrics.observeConnect(b.clock.Now(), elapsed)
}

func (b *vaneMetricBank) observeResponse(elapsed time.Duration) {
	b.metrics.observeResponse(b.clock.Now(), elapsed)
}

func (b *vaneMetricBank) observeThroughput(bitsPerSecond float64) {
	b.metrics.observeThroughput(b.clock.Now(), bitsPerSecond)
}

func (b *vaneMetricBank) snapshot() vaneMetricsSnapshot {
	return b.metrics.snapshot(b.clock.Now())
}

type vaneSceneScoring struct {
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

func vaneScoring(scene vaneScene) vaneSceneScoring {
	const mbps = 1_000_000
	switch scene {
	case vaneSceneInteractive:
		return vaneSceneScoring{0.35, 0.25, 0.35, 0.05, 50, 1500, 100, 1500, 0.25 * mbps, 5 * mbps}
	case vaneSceneMedia:
		return vaneSceneScoring{0.30, 0.10, 0.20, 0.40, 50, 1500, 200, 3000, 3 * mbps, 12 * mbps}
	case vaneSceneBulk:
		return vaneSceneScoring{0.25, 0.05, 0.05, 0.65, 50, 1500, 300, 5000, 2 * mbps, 80 * mbps}
	default:
		return vaneSceneScoring{0.35, 0.20, 0.20, 0.25, 50, 1500, 150, 3000, 1 * mbps, 20 * mbps}
	}
}

func scoreVaneMetrics(scene vaneScene, snapshot vaneMetricsSnapshot) int64 {
	config := vaneScoring(scene)
	failure := vaneMetricCost(snapshot.failure, vaneMetricFailure, func(value float64) float64 {
		return vaneClamp(value, 0, 1)
	})
	connect := vaneMetricCost(snapshot.connect, vaneMetricConnect, func(value float64) float64 {
		return vaneLatencyCost(value, config.connectGoodMillis, config.connectBadMillis)
	})
	response := vaneMetricCost(snapshot.response, vaneMetricResponse, func(value float64) float64 {
		return vaneLatencyCost(value, config.responseGoodMillis, config.responseBadMillis)
	})
	throughput := vaneMetricCost(snapshot.throughput, vaneMetricThroughput, func(value float64) float64 {
		return vaneThroughputCost(value, config.throughputLowBPS, config.throughputHighBPS)
	})

	score := config.failureWeight*failure +
		config.connectWeight*connect +
		config.responseWeight*response +
		config.throughputWeight*throughput
	return int64(math.Round(vaneClamp(score, 0, 1) * 1_000_000))
}
func vaneMetricCost(estimate vaneMetricEstimate, kind vaneMetricKind, observed func(float64) float64) float64 {
	missing := vaneSpec(kind).missingCost
	if !estimate.valid {
		return missing
	}
	confidence := vaneClamp(estimate.confidence, 0, 1)
	return confidence*vaneClamp(observed(estimate.value), 0, 1) + (1-confidence)*missing
}

// Latency estimates are already in log(milliseconds).
func vaneLatencyCost(logMillis, goodMillis, badMillis float64) float64 {
	return vaneClamp((logMillis-math.Log(goodMillis))/math.Log(badMillis/goodMillis), 0, 1)
}

// Throughput estimates are already in log(bits/second).
func vaneThroughputCost(logBPS, lowBPS, highBPS float64) float64 {
	return vaneClamp((math.Log(highBPS)-logBPS)/math.Log(highBPS/lowBPS), 0, 1)
}

type vaneCandidateScore struct {
	name        string
	scoreMicros int64
}

func rankVaneCandidates(scene vaneScene, snapshots map[string]vaneMetricsSnapshot) []vaneCandidateScore {
	ranked := make([]vaneCandidateScore, 0, len(snapshots))
	for name, snapshot := range snapshots {
		ranked = append(ranked, vaneCandidateScore{name: name, scoreMicros: scoreVaneMetrics(scene, snapshot)})
	}
	sort.Slice(ranked, func(i, j int) bool {
		return compareVaneCandidateScores(ranked[i], ranked[j]) < 0
	})
	return ranked
}

func compareVaneCandidateScores(left, right vaneCandidateScore) int {
	if left.scoreMicros < right.scoreMicros {
		return -1
	}
	if left.scoreMicros > right.scoreMicros {
		return 1
	}
	return strings.Compare(left.name, right.name)
}
