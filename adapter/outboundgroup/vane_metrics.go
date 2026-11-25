package outboundgroup

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/geodata"
	_ "github.com/metacubex/mihomo/component/geodata/memconservative"
	_ "github.com/metacubex/mihomo/component/geodata/standard"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

// parseVaneTransport is the persistence-side counterpart of
// vaneTransport.String (round6 item 3).
func parseVaneTransport(value string) (vaneTransport, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "tcp":
		return vaneTransportTCP, true
	case "udp":
		return vaneTransportUDP, true
	}
	return vaneTransportTCP, false
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
	vaneRuleRuleSet
	vaneRuleGeoSite
)

type vaneUintRange struct {
	first uint64
	last  uint64
}

func (r vaneUintRange) contains(value uint64) bool {
	return value >= r.first && value <= r.last
}

// vaneFamilyRule is the parsed, I/O-free form used on the selection path.
// Config strings use TYPE,payload,scene and are evaluated in slice order.
type vaneFamilyRule struct {
	kind    vaneRuleKind
	value   string
	values  []string
	ranges  []vaneUintRange
	network C.NetWork
}

func parseVaneFamilyRules(raw []string) ([]vaneFamilyRule, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	rules := make([]vaneFamilyRule, 0, len(raw))
	for i, text := range raw {
		rule, err := parseVaneSceneRule(text)
		if err != nil {
			return nil, fmt.Errorf("vane scene rule %d: %w", i, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func parseVaneSceneRule(text string) (vaneFamilyRule, error) {
	parts := strings.Split(text, ",")
	if len(parts) < 2 {
		return vaneFamilyRule{}, fmt.Errorf("expected TYPE,payload")
	}
	// FAMILY: a third field used to name the scene. It is accepted and ignored
	// so existing "GEOSITE,youtube,media" lines keep working.

	rule, err := parseVaneRulePayload(parts[0], parts[1])
	if err != nil {
		return vaneFamilyRule{}, err
	}
	return rule, nil
}

// parseVaneHashRules parses the two-part hash-rules list. The hash key is the
// rule's set name, so the type must be one that carries a scope at all.
func parseVaneHashRules(raw []string) ([]vaneFamilyRule, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	rules := make([]vaneFamilyRule, 0, len(raw))
	for i, text := range raw {
		parts := strings.Split(text, ",")
		if len(parts) != 2 {
			return nil, fmt.Errorf("vane hash rule %d: expected TYPE,payload", i)
		}
		rule, err := parseVaneRulePayload(parts[0], parts[1])
		if err != nil {
			return nil, fmt.Errorf("vane hash rule %d: %w", i, err)
		}
		if rule.scope() == "" {
			return nil, fmt.Errorf("vane hash rule %d: %s carries no rule-set name", i, strings.ToUpper(strings.TrimSpace(parts[0])))
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func parseVaneRulePayload(typeText, payloadText string) (vaneFamilyRule, error) {
	ruleType := strings.ToUpper(strings.TrimSpace(typeText))
	payload := strings.TrimSpace(payloadText)
	if payload == "" {
		return vaneFamilyRule{}, fmt.Errorf("empty payload for %s", ruleType)
	}

	rule := vaneFamilyRule{}
	switch ruleType {
	case "DOMAIN":
		rule.kind = vaneRuleDomain
		var valid bool
		rule.value, valid = normalizeVaneDomain(payload)
		if !valid {
			return vaneFamilyRule{}, fmt.Errorf("invalid DOMAIN payload %q", payload)
		}
	case "DOMAIN-SUFFIX":
		rule.kind = vaneRuleDomainSuffix
		var valid bool
		rule.value, valid = normalizeVaneDomain(payload)
		if !valid {
			return vaneFamilyRule{}, fmt.Errorf("invalid DOMAIN-SUFFIX payload %q", payload)
		}
	case "NETWORK":
		rule.kind = vaneRuleNetwork
		switch strings.ToLower(payload) {
		case "tcp":
			rule.network = C.TCP
		case "udp":
			rule.network = C.UDP
		default:
			return vaneFamilyRule{}, fmt.Errorf("unsupported network %q", payload)
		}
	case "RULE-SET":
		// The provider name is stored verbatim and resolved lazily at match
		// time: rule providers register asynchronously, so an unregistered
		// name is "no match", never a construction error.
		rule.kind = vaneRuleRuleSet
		rule.value = payload
	case "GEOSITE":
		// The category is stored verbatim; `!` negation and `@attr` suffixes
		// are the geodata loader's own syntax, parsed there — not here.
		rule.kind = vaneRuleGeoSite
		rule.value = payload
	case "DST-PORT":
		rule.kind = vaneRuleDstPort
		ranges, err := parseVaneUintRanges(payload, math.MaxUint16)
		if err != nil {
			return vaneFamilyRule{}, fmt.Errorf("invalid DST-PORT payload %q: %w", payload, err)
		}
		rule.ranges = ranges
	case "IN-NAME":
		rule.kind = vaneRuleInName
		values, err := parseVaneAlternatives(payload)
		if err != nil {
			return vaneFamilyRule{}, err
		}
		rule.values = values
	case "IN-USER":
		rule.kind = vaneRuleInUser
		values, err := parseVaneAlternatives(payload)
		if err != nil {
			return vaneFamilyRule{}, err
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
			return vaneFamilyRule{}, fmt.Errorf("invalid DSCP payload %q: %w", payload, err)
		}
		rule.ranges = ranges
	default:
		return vaneFamilyRule{}, fmt.Errorf("unsupported rule type %q", ruleType)
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

func matchVaneFamilyRule(metadata *C.Metadata, rules []vaneFamilyRule) (vaneFamilyRule, bool) {
	if metadata == nil {
		return vaneFamilyRule{}, false
	}
	for _, rule := range rules {
		if rule.matches(metadata) {
			return rule, true
		}
	}
	return vaneFamilyRule{}, false
}

// scope returns the gate scope this rule carries when it classifies a flow as
// media: the domain for DOMAIN / DOMAIN-SUFFIX, the provider name for
// RULE-SET, the category name for GEOSITE. Rules that match on something other
// than a target identity (NETWORK, DST-PORT, IN-NAME, IN-USER, PROCESS,
// PROCESS-PATH, DSCP) carry no scope and return "".
func (r vaneFamilyRule) scope() string {
	switch r.kind {
	case vaneRuleDomain, vaneRuleDomainSuffix, vaneRuleRuleSet, vaneRuleGeoSite:
		return r.value
	default:
		return ""
	}
}

func (r vaneFamilyRule) matches(metadata *C.Metadata) bool {
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
	case vaneRuleRuleSet:
		// Looked up from the tunnel registry on every match, mirroring the
		// main engine's RuleSet.getProvider: registration, updates and
		// removals are all reflected without rebuilding the group.
		provider, ok := tunnel.RuleProviders()[r.value]
		if !ok {
			return false
		}
		return provider.Match(metadata, C.RuleMatchHelper{})
	case vaneRuleGeoSite:
		// Fail-closed: without a GeoSite database the load errors and the
		// rule never matches — construction is not affected and no error
		// reaches the selection path.
		host, valid := normalizeVaneDomain(metadata.RuleHost())
		if !valid {
			return false
		}
		matcher, err := geodata.LoadGeoSiteMatcher(r.value)
		if err != nil {
			return false
		}
		return matcher.ApplyDomain(host)
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
	vaneMetricJitter
	// C batch: node profile dimensions. loss is the lifetime retransmission
	// ratio (B.3); the rest are raw counters that say "this node has been
	// proven" rather than "this node is fast right now".
	vaneMetricLoss
	vaneMetricLatency
	vaneMetricSuccess
	vaneMetricMaxRate
	vaneMetricDuration
	vaneMetricDownloadTotal
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
	case vaneMetricJitter:
		return vaneMetricSpec{5 * time.Minute, 2 * time.Hour, 6, 0.55}
	case vaneMetricLoss:
		// halfLife/confidenceK unused: this dimension uses the 7-day profile
		// window and computes confidence inline (cumulSent/1000).
		return vaneMetricSpec{10 * time.Minute, 6 * time.Hour, 1000, 0.50}
	case vaneMetricLatency:
		// halfLife/confidenceK unused: this dimension uses the 7-day profile
		// window and computes confidence inline (latencySamples/10).
		return vaneMetricSpec{10 * time.Minute, 6 * time.Hour, 10, 0.50}
	case vaneMetricSuccess:
		return vaneMetricSpec{2 * time.Minute, 30 * time.Minute, 10, 0.50}
	case vaneMetricMaxRate:
		return vaneMetricSpec{10 * time.Minute, 6 * time.Hour, 1, 0.50}
	case vaneMetricDuration:
		return vaneMetricSpec{5 * time.Minute, 2 * time.Hour, 10, 0.50}
	case vaneMetricDownloadTotal:
		return vaneMetricSpec{10 * time.Minute, 6 * time.Hour, 1, 0.50}
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

type vaneJitterTracker struct {
	mean      vaneDualMetric
	deviation vaneDualMetric
	samples   int
}

func (t *vaneJitterTracker) observeLatency(now time.Time, elapsedMillis float64) {
	if math.IsNaN(elapsedMillis) || math.IsInf(elapsedMillis, 0) || elapsedMillis < 0 {
		return
	}
	meanMillis := elapsedMillis
	if estimate := t.mean.estimate(vaneMetricJitter, now); estimate.valid && estimate.value > 0 {
		meanMillis = estimate.value
	}
	delta := elapsedMillis - meanMillis
	t.mean.observe(vaneMetricJitter, now, elapsedMillis, 1)
	t.deviation.observe(vaneMetricJitter, now, delta*delta, 1)
	t.samples++
}

func (t vaneJitterTracker) estimate(now time.Time) vaneMetricEstimate {
	if t.samples < 2 {
		return vaneMetricEstimate{}
	}
	mean := t.mean.estimate(vaneMetricJitter, now)
	deviation := t.deviation.estimate(vaneMetricJitter, now)
	if !mean.valid || !deviation.valid || mean.value <= 0 {
		return vaneMetricEstimate{}
	}
	evidence := math.Min(mean.evidence, deviation.evidence)
	if evidence <= 0 {
		return vaneMetricEstimate{}
	}
	return vaneMetricEstimate{value: math.Sqrt(math.Max(deviation.value, 0)), evidence: evidence,
		confidence: 1 - math.Exp(-evidence/vaneSpec(vaneMetricJitter).confidenceK), valid: true}
}

func (t vaneJitterTracker) ratio(now time.Time) float64 {
	estimate := t.estimate(now)
	mean := t.mean.estimate(vaneMetricJitter, now)
	if !estimate.valid || !mean.valid || mean.value <= 0 {
		return 0
	}
	return estimate.value / mean.value
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
	jitter     vaneJitterTracker
	// p5 carries the passive percentile/peak/hourly profile (round6 item 1).
	// It feeds on the raw sample below; scoring never reads it.
	p5 vaneP5
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
	// Connect and response have different baselines; pooling them creates artificial jitter.
	m.jitter.observeLatency(now, durationMillis(elapsed))
}

func (m *vaneMetrics) observeResponse(now time.Time, elapsed time.Duration) {
	m.response.observe(vaneMetricResponse, now, vaneLogClamp(durationMillis(elapsed), 1, 60_000), 1)
}

func (m *vaneMetrics) observeThroughput(now time.Time, bitsPerSecond float64) {
	m.throughput.observe(vaneMetricThroughput, now, vaneLogClamp(bitsPerSecond, 8_192, 1_000_000_000), 1)
	// P5 (round6 item 1) takes the raw sample — the log clamp stays a scoring
	// concern only.
	m.p5.observe(now, bitsPerSecond)
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
	// jitter is the RMSE of one-step prediction residuals against the previous
	// mean (not a strict σ — the first sample's delta is always 0), in raw
	// milliseconds.
	jitter vaneMetricEstimate
	// Node profile dimensions (C batch). They live on the node, not on the
	// per-transport EMA, so vaneMetrics.snapshot leaves them invalid and
	// vaneNodeState.snapshot fills them.
	loss          vaneMetricEstimate
	latency       vaneMetricEstimate
	success       vaneMetricEstimate
	maxRate       vaneMetricEstimate
	duration      vaneMetricEstimate
	downloadTotal vaneMetricEstimate
}

func (m vaneMetrics) snapshot(now time.Time) vaneMetricsSnapshot {
	return vaneMetricsSnapshot{
		failure:    m.failure.estimate(vaneMetricFailure, now),
		connect:    m.connect.estimate(vaneMetricConnect, now),
		response:   m.response.estimate(vaneMetricResponse, now),
		throughput: m.throughput.estimate(vaneMetricThroughput, now),
		jitter:     m.jitter.estimate(now),
	}
}

type vaneScoringConfig struct {
	failureWeight       float64
	connectWeight       float64
	responseWeight      float64
	throughputWeight    float64
	jitterWeight        float64
	lossWeight          float64
	latencyWeight       float64
	successWeight       float64
	maxRateWeight       float64
	durationWeight      float64
	downloadTotalWeight float64
	connectGoodMillis   float64
	connectBadMillis    float64
	responseGoodMillis  float64
	responseBadMillis   float64
	jitterGoodMillis    float64
	jitterBadMillis     float64
	throughputLowBPS    float64
	throughputHighBPS   float64
	latencyGoodMillis   float64
	latencyBadMillis    float64
	durationGoodSeconds float64
	durationBadSeconds  float64
}

// normalized keeps the ten weights summing to 1.0 while preserving their
// relative sizes, so adding dimensions never inflates a score.
func (c vaneScoringConfig) normalized() vaneScoringConfig {
	total := c.failureWeight + c.connectWeight + c.responseWeight + c.throughputWeight + c.jitterWeight +
		c.lossWeight + c.latencyWeight + c.successWeight + c.maxRateWeight + c.durationWeight + c.downloadTotalWeight
	if total <= 0 {
		return c
	}
	c.failureWeight /= total
	c.connectWeight /= total
	c.responseWeight /= total
	c.throughputWeight /= total
	c.jitterWeight /= total
	c.lossWeight /= total
	c.latencyWeight /= total
	c.successWeight /= total
	c.maxRateWeight /= total
	c.durationWeight /= total
	c.downloadTotalWeight /= total
	return c
}

// vaneScoringConfigSum is the assertion surface for SCORE-WEIGHT-01.
func vaneScoringConfigSum(scoring vaneScoringConfig) float64 {
	return scoring.failureWeight + scoring.connectWeight + scoring.responseWeight + scoring.throughputWeight +
		scoring.jitterWeight + scoring.lossWeight + scoring.latencyWeight + scoring.successWeight +
		scoring.maxRateWeight + scoring.durationWeight + scoring.downloadTotalWeight
}

// vaneWeightSet is the raw weight table: throughput > latency > loss >
// everything else in every scene (owner's order). normalized() divides by the
// sum, so these need not add up to 1.0.
type vaneWeightSet struct {
	throughput, latency, loss, failure, response, jitter, connect float64
	success, maxRate, duration, downloadTotal                     float64
}

// BANDWIDTH-FIRST: throughput > latency > loss > the rest, per the user goal.
var vaneWeights = vaneWeightSet{0.55, 0.18, 0.12, 0.06, 0.03, 0.02, 0.02, 0.01, 0.005, 0.0025, 0.0025}

func vaneScoringFlat() vaneScoringConfig {
	const mbps = 1_000_000
	weights := vaneWeights
	scoring := vaneScoringConfig{}
	scoring.throughputWeight = weights.throughput
	scoring.latencyWeight = weights.latency
	scoring.lossWeight = weights.loss
	scoring.failureWeight = weights.failure
	scoring.responseWeight = weights.response
	scoring.jitterWeight = weights.jitter
	scoring.connectWeight = weights.connect
	scoring.successWeight = weights.success
	scoring.maxRateWeight = weights.maxRate
	scoring.durationWeight = weights.duration
	scoring.downloadTotalWeight = weights.downloadTotal
	scoring.connectGoodMillis, scoring.connectBadMillis = 50, 1500
	scoring.responseGoodMillis, scoring.responseBadMillis = 200, 3000
	scoring.throughputLowBPS, scoring.throughputHighBPS = 1*mbps, 20*mbps
	scoring.jitterGoodMillis, scoring.jitterBadMillis = 3, 100
	// 50ms is a healthy CDN path; 500ms is the media chain's high-latency line.
	scoring.latencyGoodMillis, scoring.latencyBadMillis = 50, 500
	scoring.durationGoodSeconds = 10
	scoring.durationBadSeconds = 300
	return scoring.normalized()
}

// scoreVaneMetricsFlat is scoreVaneMetrics without the scene argument.
func scoreVaneMetricsFlat(snapshot vaneMetricsSnapshot) int64 {
	return scoreVaneMetricsPartsWith(vaneScoringFlat(), snapshot).total
}

// vaneScoreParts keeps each dimension's weighted contribution so a pick can be
// explained in the log; total is the only thing ranking compares.
type vaneScoreParts struct {
	total                                                         int64
	throughput, latency, loss, failure, response, jitter, connect float64
	success, maxRate, duration, downloadTotal                     float64
}

// explain renders the contributions in the scoring order, values in [0,1].
func (p vaneScoreParts) explain() string {
	return fmt.Sprintf(
		"tp=%.2f rtt=%.2f loss=%.2f fail=%.2f resp=%.2f jit=%.2f conn=%.2f succ=%.2f peak=%.2f dur=%.2f vol=%.2f",
		p.throughput, p.latency, p.loss, p.failure, p.response, p.jitter,
		p.connect, p.success, p.maxRate, p.duration, p.downloadTotal,
	)
}

func scoreVaneMetricsPartsWith(config vaneScoringConfig, snapshot vaneMetricsSnapshot) vaneScoreParts {
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
	jitter := vaneMetricCost(snapshot.jitter, vaneMetricJitter, func(value float64) float64 {
		return vaneJitterCost(value, config.jitterGoodMillis, config.jitterBadMillis)
	})

	loss := vaneMetricCost(snapshot.loss, vaneMetricLoss, vaneLossCost)
	latency := vaneMetricCost(snapshot.latency, vaneMetricLatency, func(value float64) float64 {
		return vaneLatencyCost(value, config.latencyGoodMillis, config.latencyBadMillis)
	})
	success := vaneMetricCost(snapshot.success, vaneMetricSuccess, func(value float64) float64 {
		return 1 - vaneClamp(value, 0, 1)
	})
	maxRate := vaneMetricCost(snapshot.maxRate, vaneMetricMaxRate, func(value float64) float64 {
		return vaneThroughputCost(value, config.throughputLowBPS, config.throughputHighBPS)
	})
	duration := vaneMetricCost(snapshot.duration, vaneMetricDuration, func(value float64) float64 {
		return vaneDurationCost(value, config.durationGoodSeconds, config.durationBadSeconds)
	})
	downloadTotal := vaneMetricCost(snapshot.downloadTotal, vaneMetricDownloadTotal, vaneDownloadTotalCost)

	parts := vaneScoreParts{
		throughput:    config.throughputWeight * throughput,
		latency:       config.latencyWeight * latency,
		loss:          config.lossWeight * loss,
		failure:       config.failureWeight * failure,
		response:      config.responseWeight * response,
		jitter:        config.jitterWeight * jitter,
		connect:       config.connectWeight * connect,
		success:       config.successWeight * success,
		maxRate:       config.maxRateWeight * maxRate,
		duration:      config.durationWeight * duration,
		downloadTotal: config.downloadTotalWeight * downloadTotal,
	}
	score := parts.failure + parts.connect + parts.response + parts.throughput +
		parts.jitter + parts.loss + parts.latency + parts.success + parts.maxRate +
		parts.duration + parts.downloadTotal
	parts.total = int64(math.Round(vaneClamp(score, 0, 1) * 1_000_000))
	return parts
}
func vaneMetricCost(estimate vaneMetricEstimate, kind vaneMetricKind, observed func(float64) float64) float64 {
	missing := vaneSpec(kind).missingCost
	if !estimate.valid {
		return missing
	}
	confidence := vaneClamp(estimate.confidence, 0, 1)
	return confidence*vaneClamp(observed(estimate.value), 0, 1) + (1-confidence)*missing
}

// vaneLossCost: under 1% retransmission is healthy, over 5% is degraded — the
// same line the media chain uses, so scoring and switching agree.
func vaneLossCost(rate float64) float64 {
	return vaneClamp((rate-0.01)/0.04, 0, 1)
}

// vaneDurationCost: a socket that lived seconds says little; minutes of
// survival is the stability signal.
func vaneDurationCost(seconds, good, bad float64) float64 {
	return 1 - vaneClamp((seconds-good)/(bad-good), 0, 1)
}

// vaneDownloadTotalCost takes log10(bytes): 1 MiB is neutral, 100 MiB is fully
// proven. Linear bytes would let the oldest node win forever.
func vaneDownloadTotalCost(logBytes float64) float64 {
	return 1 - vaneClamp((logBytes-6)/2, 0, 1)
}

// vaneLatencyHardCapMs is a hard pick-time filter: a node whose media-window
// RTT EMA exceeds it is not ranked at all. 350ms is roughly a round trip most
// of the way around the planet. Nodes without live samples are never capped.
const vaneLatencyHardCapMs = 350.0

// Latency estimates are already in log(milliseconds).
func vaneLatencyCost(logMillis, goodMillis, badMillis float64) float64 {
	return vaneClamp((logMillis-math.Log(goodMillis))/math.Log(badMillis/goodMillis), 0, 1)
}

// Jitter is σ in raw milliseconds; its anchors share the latency log scale.
func vaneJitterCost(sigmaMillis, goodMillis, badMillis float64) float64 {
	if sigmaMillis <= 0 {
		return 0
	}
	return vaneLatencyCost(math.Log(sigmaMillis), goodMillis, badMillis)
}

// Throughput estimates are already in log(bits/second).
func vaneThroughputCost(logBPS, lowBPS, highBPS float64) float64 {
	return vaneClamp((math.Log(highBPS)-logBPS)/math.Log(highBPS/lowBPS), 0, 1)
}

type vaneCandidateScore struct {
	name        string
	scoreMicros int64
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
