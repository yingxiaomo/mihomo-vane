package outboundgroup

import (
	"errors"
	"math"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

const (
	vaneDefaultExplorationInterval = 32
	vaneMaximumExplorationInterval = 1_000_000
	vaneExplorationScopeCount      = 8
)

type vaneExplorationConfig struct {
	enabled  bool
	interval uint64
}

func newVaneExplorationConfig(enabled bool, interval int) (vaneExplorationConfig, error) {
	if !enabled {
		if interval != 0 {
			return vaneExplorationConfig{}, errors.New("exploration-interval requires exploration to be enabled")
		}
		return vaneExplorationConfig{}, nil
	}
	if interval == 0 {
		interval = vaneDefaultExplorationInterval
	}
	if interval < 2 || interval > vaneMaximumExplorationInterval {
		return vaneExplorationConfig{}, errors.New("exploration-interval must be between 2 and 1000000")
	}
	return vaneExplorationConfig{enabled: true, interval: uint64(interval)}, nil
}

type vaneExplorationScopeState struct {
	eligibleSelections    uint64
	explorationSelections uint64
	sinceLastExploration  uint64
}

type vaneExplorationSelection struct {
	proxy                  C.Proxy
	transport              vaneTransport
	target                 string
	port                   uint16
	fromAnchor             string
	toCandidate            string
	evidenceCoverageMicros int64
	scopeEligibleOrdinal   uint64
}

type vaneExplorationToken struct {
	once                   sync.Once
	diagnostics            *vaneDiagnostics
	id                     uint64
	transport              vaneTransport
	target                 string
	port                   uint16
	fromAnchor             string
	toCandidate            string
	evidenceCoverageMicros int64
	scopeEligibleOrdinal   uint64
}

func (t *vaneExplorationToken) settle(kind, reason string) {
	if t == nil {
		return
	}
	t.once.Do(func() {
		t.diagnostics.record(vaneDiagnosticRecord{
			kind:                   kind,
			reason:                 reason,
			explorationID:          t.id,
			transport:              t.transport.String(),
			target:                 t.target,
			port:                   t.port,
			from:                   t.fromAnchor,
			to:                     t.toCandidate,
			evidenceCoverageMicros: t.evidenceCoverageMicros,
			scopeEligibleOrdinal:   t.scopeEligibleOrdinal,
		})
	})
}

func (t vaneTransport) String() string {
	if t == vaneTransportUDP {
		return "udp"
	}
	return "tcp"
}

func vaneExplorationScopeIndex(transport vaneTransport) int {
	return int(transport)
}

func vaneExplorationScopeValues(index int) vaneTransport {
	return vaneTransport(index)
}

func vaneEvidenceCoverageMicros(snapshot vaneMetricsSnapshot, transport vaneTransport) int64 {
	weights := vaneScoringFlat()
	weighted := weights.failureWeight*vaneEstimateConfidence(snapshot.failure) +
		weights.connectWeight*vaneEstimateConfidence(snapshot.connect) +
		weights.jitterWeight*vaneEstimateConfidence(snapshot.jitter)
	denominator := weights.failureWeight + weights.connectWeight + weights.jitterWeight
	if transport == vaneTransportTCP {
		weighted += weights.responseWeight*vaneEstimateConfidence(snapshot.response) +
			weights.throughputWeight*vaneEstimateConfidence(snapshot.throughput)
		denominator += weights.responseWeight + weights.throughputWeight
	}
	if denominator <= 0 {
		return 0
	}
	coverage := vaneClamp(weighted/denominator, 0, 1)
	return int64(math.Round(coverage * 1_000_000))
}

func vaneEstimateConfidence(estimate vaneMetricEstimate) float64 {
	if !estimate.valid {
		return 0
	}
	return vaneClamp(estimate.confidence, 0, 1)
}

// maybeSelectExplorationLocked allocates a bounded exploration slot after the
// ordinary selector has produced a stable anchor choice. It never changes the
// score, anchor, cooldown, media hint or reconnect budget.
func (a *Vane) maybeSelectExplorationLocked(
	metadata *C.Metadata,
	transport vaneTransport,
	now time.Time,
	target string,
	port uint16,
	ranked []vaneRankedProxy,
	baseline vaneRankedProxy,
	anchor vaneAnchor,
	anchorCoolingAnywhere bool,
	hasAlive bool,
) *vaneExplorationSelection {
	if a.learningGeneration != a.learning.generation {
		return nil
	}
	if !a.exploration.enabled || metadata == nil || metadata.Type == C.INNER || target == "" || port == 0 ||
		!hasAlive || anchor.name == "" || anchorCoolingAnywhere || baseline.name != anchor.name ||
		baseline.cooldownUntil.After(now) {
		return nil
	}

	scopeIndex := vaneExplorationScopeIndex(transport)
	var selected *vaneRankedProxy
	var selectedLastOrdinal uint64
	for i := range ranked {
		candidate := &ranked[i]
		if candidate.name == anchor.name || candidate.cooldownUntil.After(now) {
			continue
		}
		lastOrdinal := uint64(0)
		if state := a.nodeControls[candidate.name]; state != nil {
			lastOrdinal = state.lastExplored[scopeIndex]
		}
		if selected == nil || candidate.evidenceCoverageMicros < selected.evidenceCoverageMicros ||
			(candidate.evidenceCoverageMicros == selected.evidenceCoverageMicros &&
				(lastOrdinal < selectedLastOrdinal || (lastOrdinal == selectedLastOrdinal && candidate.name < selected.name))) {
			selected = candidate
			selectedLastOrdinal = lastOrdinal
		}
	}
	if selected == nil {
		return nil
	}

	scope := &a.explorationScopes[scopeIndex]
	scope.eligibleSelections++
	scope.sinceLastExploration++
	if scope.sinceLastExploration < a.exploration.interval {
		return nil
	}

	scope.sinceLastExploration = 0
	scope.explorationSelections++
	a.explorationOrdinal++
	if a.explorationOrdinal == 0 {
		// This requires 2^64 exploration selections. Preserve zero as the
		// never-explored sentinel rather than allowing it to win ties.
		a.explorationOrdinal = 1
	}
	a.ensureNodeLocked(selected.name, now)
	state := a.ensureNodeControlLocked(selected.name, now)
	state.lastExplored[scopeIndex] = a.explorationOrdinal

	return &vaneExplorationSelection{
		proxy:                  selected.proxy,
		transport:              transport,
		target:                 target,
		port:                   port,
		fromAnchor:             anchor.name,
		toCandidate:            selected.name,
		evidenceCoverageMicros: selected.evidenceCoverageMicros,
		scopeEligibleOrdinal:   scope.eligibleSelections,
	}
}
