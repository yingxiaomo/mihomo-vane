package outboundgroup

import (
	"errors"
	"math"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

const (
	sageDefaultExplorationInterval = 32
	sageMaximumExplorationInterval = 1_000_000
	sageExplorationScopeCount      = 8
)

type sageExplorationConfig struct {
	enabled  bool
	interval uint64
}

func newSageExplorationConfig(enabled bool, interval int) (sageExplorationConfig, error) {
	if !enabled {
		if interval != 0 {
			return sageExplorationConfig{}, errors.New("exploration-interval requires exploration to be enabled")
		}
		return sageExplorationConfig{}, nil
	}
	if interval == 0 {
		interval = sageDefaultExplorationInterval
	}
	if interval < 2 || interval > sageMaximumExplorationInterval {
		return sageExplorationConfig{}, errors.New("exploration-interval must be between 2 and 1000000")
	}
	return sageExplorationConfig{enabled: true, interval: uint64(interval)}, nil
}

type sageExplorationScopeState struct {
	eligibleSelections    uint64
	explorationSelections uint64
	sinceLastExploration  uint64
}

type sageExplorationSelection struct {
	proxy                  C.Proxy
	transport              sageTransport
	scene                  sageScene
	target                 string
	port                   uint16
	fromAnchor             string
	toCandidate            string
	evidenceCoverageMicros int64
	scopeEligibleOrdinal   uint64
}

type sageExplorationToken struct {
	once                   sync.Once
	diagnostics            *sageDiagnostics
	id                     uint64
	transport              sageTransport
	scene                  sageScene
	target                 string
	port                   uint16
	fromAnchor             string
	toCandidate            string
	evidenceCoverageMicros int64
	scopeEligibleOrdinal   uint64
}

func (t *sageExplorationToken) settle(kind, reason string) {
	if t == nil {
		return
	}
	t.once.Do(func() {
		t.diagnostics.record(sageDiagnosticRecord{
			kind:                   kind,
			reason:                 reason,
			explorationID:          t.id,
			transport:              t.transport.String(),
			scene:                  t.scene.String(),
			target:                 t.target,
			port:                   t.port,
			from:                   t.fromAnchor,
			to:                     t.toCandidate,
			evidenceCoverageMicros: t.evidenceCoverageMicros,
			scopeEligibleOrdinal:   t.scopeEligibleOrdinal,
		})
	})
}

func (t sageTransport) String() string {
	if t == sageTransportUDP {
		return "udp"
	}
	return "tcp"
}

func sageExplorationScopeIndex(transport sageTransport, scene sageScene) int {
	return int(transport)*4 + int(scene)
}

func sageExplorationScopeValues(index int) (sageTransport, sageScene) {
	return sageTransport(index / 4), sageScene(index % 4)
}

func sageEvidenceCoverageMicros(snapshot sageMetricsSnapshot, transport sageTransport, scene sageScene) int64 {
	weights := sageScoring(scene)
	weighted := weights.failureWeight*sageEstimateConfidence(snapshot.failure) +
		weights.connectWeight*sageEstimateConfidence(snapshot.connect)
	denominator := weights.failureWeight + weights.connectWeight
	if transport == sageTransportTCP {
		weighted += weights.responseWeight*sageEstimateConfidence(snapshot.response) +
			weights.throughputWeight*sageEstimateConfidence(snapshot.throughput)
		denominator += weights.responseWeight + weights.throughputWeight
	}
	if denominator <= 0 {
		return 0
	}
	coverage := sageClamp(weighted/denominator, 0, 1)
	return int64(math.Round(coverage * 1_000_000))
}

func sageEstimateConfidence(estimate sageMetricEstimate) float64 {
	if !estimate.valid {
		return 0
	}
	return sageClamp(estimate.confidence, 0, 1)
}

// maybeSelectExplorationLocked allocates a bounded exploration slot after the
// ordinary selector has produced a stable anchor choice. It never changes the
// score, anchor, cooldown, media hint or reconnect budget.
func (a *Sage) maybeSelectExplorationLocked(
	metadata *C.Metadata,
	transport sageTransport,
	scene sageScene,
	now time.Time,
	target string,
	port uint16,
	ranked []sageRankedProxy,
	baseline sageRankedProxy,
	anchor sageAnchor,
	anchorCoolingAnywhere bool,
	hasAlive bool,
) *sageExplorationSelection {
	if a.learningGeneration != a.learning.generation {
		return nil
	}
	if !a.exploration.enabled || metadata == nil || metadata.Type == C.INNER || target == "" || port == 0 ||
		!hasAlive || anchor.name == "" || anchorCoolingAnywhere || baseline.name != anchor.name ||
		baseline.cooldownUntil.After(now) {
		return nil
	}

	scopeIndex := sageExplorationScopeIndex(transport, scene)
	var selected *sageRankedProxy
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

	return &sageExplorationSelection{
		proxy:                  selected.proxy,
		transport:              transport,
		scene:                  scene,
		target:                 target,
		port:                   port,
		fromAnchor:             anchor.name,
		toCandidate:            selected.name,
		evidenceCoverageMicros: selected.evidenceCoverageMicros,
		scopeEligibleOrdinal:   scope.eligibleSelections,
	}
}
