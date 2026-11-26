package outboundgroup

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/log"
)

const (
	VaneLearningSchemaVersion      = 2
	vaneLearningRegistryLimit      = 256
	vaneLearningPersistInterval    = 30 * time.Second
	vaneLearningFutureSkew         = 5 * time.Minute
	vaneLearningMaximumWeight      = 1e12
	vaneLearningMaximumAverage     = 40.0
	vaneLearningMaximumJitterValue = 1e12 // raw milliseconds and squared milliseconds, not logs
	vaneLearningPayloadLimit       = 2 * 1024 * 1024
)

type vaneLearningStore interface {
	Load(key string) (payload, token []byte, err error)
	Save(key string, expectedToken, payload []byte) (token []byte, err error)
}

type vaneCacheLearningStore struct{}

func (vaneCacheLearningStore) Load(key string) ([]byte, []byte, error) {
	return cachefile.Cache().GetVaneStateWithToken(key)
}

func (vaneCacheLearningStore) Save(key string, expectedToken, payload []byte) ([]byte, error) {
	return cachefile.Cache().CompareAndSwapVaneState(key, expectedToken, payload)
}

// VaneLearningPersistence describes the durable node-metric owner. It is
// diagnostic only; reading it never loads, saves, prunes, or refreshes state.
type VaneLearningPersistence struct {
	Available         bool      `json:"available"`
	RestoredNodes     int       `json:"restoredNodes"`
	ActiveNodes       int       `json:"activeNodes"`
	Revision          uint64    `json:"revision"`
	PersistedRevision uint64    `json:"persistedRevision"`
	LastSuccessAt     time.Time `json:"lastSuccessAt,omitempty"`
	LastError         string    `json:"lastError,omitempty"`
}

type vanePersistedDecayLayer struct {
	Weight    float64   `json:"weight"`
	Sum       float64   `json:"sum"`
	UpdatedAt time.Time `json:"updatedAt"`
	Valid     bool      `json:"valid"`
}

type vanePersistedDualMetric struct {
	Fast vanePersistedDecayLayer `json:"fast"`
	Slow vanePersistedDecayLayer `json:"slow"`
}

type vanePersistedJitter struct {
	Mean      vanePersistedDualMetric `json:"mean"`
	Deviation vanePersistedDualMetric `json:"deviation"`
	Samples   int                     `json:"samples"`
}

type vanePersistedMetrics struct {
	Failure    vanePersistedDualMetric `json:"failure"`
	Connect    vanePersistedDualMetric `json:"connect"`
	Response   vanePersistedDualMetric `json:"response"`
	Throughput vanePersistedDualMetric `json:"throughput"`
	Jitter     *vanePersistedJitter    `json:"jitter,omitempty"`
	// P5 (round6 item 2) is passive per-node telemetry; its presence never
	// affects node validity on restore.
	P5 *vanePersistedP5 `json:"p5,omitempty"`
}

type vanePersistedNode struct {
	Name     string               `json:"name"`
	Identity string               `json:"identity"`
	LastSeen time.Time            `json:"lastSeen"`
	TCP      vanePersistedMetrics `json:"tcp"`
	UDP      vanePersistedMetrics `json:"udp"`
	// B.9: the B.3 cumulative loss counters are durable. They are telemetry,
	// not selection state, so they may cross a reload.
	CumulSent    uint64 `json:"cumulSent,omitempty"`
	CumulRetrans uint64 `json:"cumulRetrans,omitempty"`
	// C batch: node profile counters. Durable because a restart must not throw
	// away weeks of evidence, but each group carries its own ObservedAt so the
	// restore can drop stale counters (see vaneProfileAgeReset).
	SuccessCount    uint64    `json:"successCount,omitempty"`
	FailureCount    uint64    `json:"failureCount,omitempty"`
	CountersAt      time.Time `json:"countersAt,omitempty"`
	MaxDownloadRate float64   `json:"maxDownloadRate,omitempty"`
	MaxRateAt       time.Time `json:"maxRateAt,omitempty"`
	TotalDuration   int64     `json:"totalDurationMs,omitempty"`
	DurationCount   uint64    `json:"durationCount,omitempty"`
	DownloadTotal   uint64    `json:"downloadTotal,omitempty"`
	TotalsAt        time.Time `json:"totalsAt,omitempty"`
	// D batch: node-level RTT EMA.
	LatencyMs      float64   `json:"latencyMs,omitempty"`
	LatencySamples uint64    `json:"latencySamples,omitempty"`
	LatencyAt      time.Time `json:"latencyAt,omitempty"`
	// E batch: without this the cumulative loss pair never ages out.
	CumulObservedAt time.Time `json:"cumulObservedAt,omitempty"`
}

// vanePersistedTarget carries one target+member pair's telemetry across
// restarts (round6 item 3). Coordination state — streak, blockUntil,
// lastFailureAt — is deliberately absent: it is selection state, not
// telemetry, and must never resurrect.
type vanePersistedTarget struct {
	Transport           string    `json:"transport"`
	TargetScope         string    `json:"targetScope"`
	Port                uint16    `json:"port"`
	Candidate           string    `json:"candidate"`
	Identity            string    `json:"identity"`
	LossEMA             float64   `json:"lossEma,omitempty"`
	LossSamples         int64     `json:"lossSamples,omitempty"`
	AttemptCount        int64     `json:"attemptCount,omitempty"`
	SuspectedStallCount int64     `json:"suspectedStallCount,omitempty"`
	LastObservedAt      time.Time `json:"lastObservedAt"`
}

// vaneLearningTargetLimit mirrors the target-state cap.
const vaneLearningTargetLimit = 1024

func vaneLearningTargetKey(transport vaneTransport, targetScope string, port uint16, candidate, identity string) string {
	key := vaneTargetKey{transport: transport, targetScope: targetScope, port: port}
	return key.String() + "\x00" + candidate + "\x00" + identity
}

type vaneLearningSnapshot struct {
	SchemaVersion int                   `json:"schemaVersion"`
	Group         string                `json:"group"`
	Revision      uint64                `json:"revision"`
	UpdatedAt     time.Time             `json:"updatedAt"`
	Nodes         []vanePersistedNode   `json:"nodes"`
	Targets       []vanePersistedTarget `json:"targets,omitempty"`
}

type vaneLearningPending struct {
	revision uint64
	snapshot vaneLearningSnapshot
}

type vaneLearningState struct {
	mu      sync.Mutex
	flushMu sync.Mutex

	clock      vaneClock
	store      vaneLearningStore
	group      string
	storageKey string
	nodes      map[string]*vaneNodeState
	nodeEpochs map[string]uint64
	// targets mirrors the live telemetry per (target, candidate, identity)
	// pair (round6 item 3). The group pushes updates while holding a.mu and
	// taking this lock; the flush serializes from here without ever reaching
	// back for a.mu.
	targets    map[string]vanePersistedTarget
	stateTTL   time.Duration
	maxStates  int
	generation uint64

	revision          uint64
	processedRevision uint64
	pending           vaneLearningPending
	persistInterval   time.Duration
	lastScheduled     time.Time
	persistTimer      *time.Timer
	persistRunning    bool
	// §H: the registry's access stamp at the last touch (read under the
	// registry lock during eviction).
	lastAccess uint64
	// §H: set while an eviction is flushing this state — the acquire hit path
	// must not hand an evicting victim out (a reload re-acquiring the same
	// group mid-flush would otherwise adopt it and lose it to the delete).
	evicting       bool
	persistRetryAt time.Time
	persistWG      sync.WaitGroup
	retiring       bool

	available     bool
	restoredNodes int
	lastSuccessAt time.Time
	lastError     string
	storeToken    []byte
	writeBlocked  bool
}

type vaneLearningRegistryState struct {
	sync.Mutex
	entries      map[string]*vaneLearningState
	storeFactory func() vaneLearningStore
	// §H: a monotonically increasing access stamp for the LRU eviction —
	// touched on key hits and at entry creation, read when the registry is
	// full and the least-recently-accessed victim must go.
	access uint64
}

var vaneLearningRegistry = vaneLearningRegistryState{
	entries: make(map[string]*vaneLearningState),
	storeFactory: func() vaneLearningStore {
		return vaneCacheLearningStore{}
	},
}

func vaneLearningStorageKey(group string) string {
	sum := sha256.Sum256([]byte(group))
	return "vane-state-v1:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func vaneLearningNodeKey(name, identity string) string {
	if identity == "" {
		return name
	}
	return name + "\x00" + identity
}

func newVaneLearningState(group string, clock vaneClock, store vaneLearningStore, stateTTL time.Duration, maxStates int) *vaneLearningState {
	if clock == nil {
		clock = vaneSystemClock{}
	}
	now := clock.Now().UTC()
	state := &vaneLearningState{
		clock:           clock,
		store:           store,
		group:           group,
		storageKey:      vaneLearningStorageKey(group),
		nodes:           make(map[string]*vaneNodeState),
		nodeEpochs:      make(map[string]uint64),
		targets:         make(map[string]vanePersistedTarget),
		stateTTL:        stateTTL,
		maxStates:       maxStates,
		generation:      1,
		persistInterval: vaneLearningPersistInterval,
		lastScheduled:   now,
	}
	if store == nil {
		state.lastError = "persistence disabled"
		return state
	}

	payload, token, err := store.Load(state.storageKey)
	state.storeToken = append([]byte(nil), token...)
	if err != nil {
		state.lastError = err.Error()
		if errors.Is(err, cachefile.ErrVaneStateIncompatibleSchema) && len(token) != 0 {
			state.available = true
			state.writeBlocked = true
			log.Warnln("Vane: node state for group %s uses an incompatible schema and is read-only: %s", group, err.Error())
			return state
		}
		if errors.Is(err, cachefile.ErrVaneStatePayloadTooLarge) && len(token) != 0 {
			// Keep the writer fence so the first bounded valid snapshot can
			// atomically replace a legacy oversized row.
			state.available = true
			log.Warnln("Vane: oversized node state for group %s will be replaced after new evidence: %s", group, err.Error())
			return state
		}
		log.Warnln("Vane: node-state persistence unavailable for group %s: %s", group, err.Error())
		state.store = nil
		return state
	}
	state.available = true
	if len(payload) == 0 {
		return state
	}
	if err := state.restore(payload); err != nil {
		state.lastError = err.Error()
		log.Warnln("Vane: ignore invalid node state for group %s: %s", group, err.Error())
	}
	return state
}

// vaneLearningNoStoreCandidate builds the degraded candidate a full registry
// hands out when it cannot make room (§H keeps this as the failure path).
func vaneLearningNoStoreCandidate(group string, clock vaneClock, stateTTL time.Duration, maxStates int, lastError string) *vaneLearningState {
	candidate := newVaneLearningState(group, clock, nil, stateTTL, maxStates)
	candidate.mu.Lock()
	candidate.lastError = lastError
	candidate.mu.Unlock()
	return candidate
}

func acquireVaneLearningState(group string, clock vaneClock, stateTTL time.Duration, maxStates int) *vaneLearningState {
	key := vaneLearningStorageKey(group)
	vaneLearningRegistry.Lock()
	if current := vaneLearningRegistry.entries[key]; current != nil && !current.evicting {
		vaneLearningRegistry.access++
		current.lastAccess = vaneLearningRegistry.access
		vaneLearningRegistry.Unlock()
		return current
	}
	if len(vaneLearningRegistry.entries) >= vaneLearningRegistryLimit {
		// §H: the registry used to degrade straight to a store-less state,
		// silently losing persistence for the new group. Evict the
		// least-recently-accessed entry instead — flush-first so the victim's
		// latest revision survives, then delete. A failed victim flush keeps
		// the victim and degrades the new group exactly like before.
		victimKey, victim := vaneLearningEvictOldestLocked()
		vaneLearningRegistry.Unlock()
		var flushErr error
		if victim != nil {
			flushErr = victim.flush()
		}
		vaneLearningRegistry.Lock()
		if victim != nil {
			if current := vaneLearningRegistry.entries[victimKey]; current == victim {
				if flushErr == nil {
					delete(vaneLearningRegistry.entries, victimKey)
				} else {
					// P2 (audit 2026-11-22): the eviction gave up — clear the
					// flag so the surviving victim is handed out again.
					victim.evicting = false
				}
			}
			// else: replaced concurrently while flushing; nothing to delete.
		}
		if victim == nil || flushErr != nil || len(vaneLearningRegistry.entries) >= vaneLearningRegistryLimit {
			// Concurrent acquires refilled the registry while the victim was
			// flushing; degrade rather than evict a second victim here.
			vaneLearningRegistry.Unlock()
			return vaneLearningNoStoreCandidate(group, clock, stateTTL, maxStates, "node-state registry capacity unavailable")
		}
	}
	storeFactory := vaneLearningRegistry.storeFactory
	if storeFactory == nil {
		storeFactory = func() vaneLearningStore { return vaneCacheLearningStore{} }
	}
	// Opening the durable writer rotates its fencing token. Keep registry
	// publication serialized so a losing first-registration candidate cannot
	// fence the canonical owner that wins this key.
	candidate := newVaneLearningState(group, clock, storeFactory(), stateTTL, maxStates)
	vaneLearningRegistry.access++
	candidate.lastAccess = vaneLearningRegistry.access
	vaneLearningRegistry.entries[key] = candidate
	vaneLearningRegistry.Unlock()
	return candidate
}

// vaneLearningEvictOldestLocked picks the least-recently-accessed entry.
// Caller holds the registry lock; the victim is flushed with the lock
// released, then re-verified before deletion.
func vaneLearningEvictOldestLocked() (string, *vaneLearningState) {
	var victimKey string
	var victim *vaneLearningState
	var oldest uint64
	for candidateKey, candidate := range vaneLearningRegistry.entries {
		// P2 (audit 2026-11-22): another evictor is already flushing this
		// entry — never hand it out or evict it twice.
		if candidate.evicting {
			continue
		}
		if victim == nil || candidate.lastAccess < oldest {
			victimKey, victim, oldest = candidateKey, candidate, candidate.lastAccess
		}
	}
	if victim != nil {
		victim.evicting = true
	}
	return victimKey, victim
}

func activateVaneLearningState(state *vaneLearningState, stateTTL time.Duration, maxStates int) uint64 {
	state.mu.Lock()
	generation := state.generation + 1
	if generation == 0 {
		generation = 1
	}
	state.generation = generation
	state.stateTTL = stateTTL
	state.maxStates = maxStates
	state.mu.Unlock()
	return generation
}

func sharedVaneLearningState(group string, clock vaneClock, stateTTL time.Duration, maxStates int) (*vaneLearningState, uint64) {
	state := acquireVaneLearningState(group, clock, stateTTL, maxStates)
	return state, activateVaneLearningState(state, stateTTL, maxStates)
}

// FlushVaneLearningStates drains the latest durable revision for every
// registered Vane group. It is called during process shutdown; reloads use
// the shared owner and therefore do not require a load/save handoff.
func FlushVaneLearningStates() error {
	return FlushVaneLearningStatesContext(context.Background())
}

func FlushVaneLearningStatesContext(ctx context.Context) error {
	vaneLearningRegistry.Lock()
	states := make([]*vaneLearningState, 0, len(vaneLearningRegistry.entries))
	for _, state := range vaneLearningRegistry.entries {
		states = append(states, state)
	}
	vaneLearningRegistry.Unlock()

	results := make(chan error, len(states))
	for _, state := range states {
		go func(state *vaneLearningState) { results <- state.flush() }(state)
	}
	var result error
	for range states {
		select {
		case err := <-results:
			result = errors.Join(result, err)
		case <-ctx.Done():
			return errors.Join(result, ctx.Err())
		}
	}
	return result
}

func (s *vaneLearningState) restore(payload []byte) error {
	var snapshot vaneLearningSnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return fmt.Errorf("decode node state: %w", err)
	}
	if snapshot.SchemaVersion != VaneLearningSchemaVersion {
		if snapshot.SchemaVersion > VaneLearningSchemaVersion {
			s.writeBlocked = true
		}
		return fmt.Errorf("unsupported node-state schema %d", snapshot.SchemaVersion)
	}
	if snapshot.Group != s.group {
		return fmt.Errorf("node-state group mismatch")
	}
	if snapshot.UpdatedAt.IsZero() {
		return fmt.Errorf("node-state timestamp missing")
	}
	now := s.clock.Now().UTC()
	if snapshot.UpdatedAt.After(now.Add(vaneLearningFutureSkew)) {
		return fmt.Errorf("node-state timestamp is in the future")
	}

	byKey := make(map[string]vanePersistedNode, len(snapshot.Nodes))
	invalidNodes := 0
	for _, node := range snapshot.Nodes {
		if node.Name == "" || len(node.Name) > 4096 || node.Identity == "" || len(node.Identity) > 4096 || node.LastSeen.IsZero() || node.LastSeen.After(now.Add(vaneLearningFutureSkew)) {
			invalidNodes++
			continue
		}
		restored, ok, invalid := restoreVaneNode(node, now)
		if invalid {
			invalidNodes++
		}
		if !ok {
			continue
		}
		key := vaneLearningNodeKey(node.Name, node.Identity)
		if previous, exists := byKey[key]; exists {
			invalidNodes++
			if !node.LastSeen.After(previous.LastSeen) {
				continue
			}
		}
		byKey[key] = node
		restored.epoch = 1
		s.nodes[key] = restored
		s.nodeEpochs[key] = restored.epoch
	}

	s.restoredNodes = len(s.nodes)
	// Round6 item 3: restore the telemetry targets. Bad entries count and
	// skip — one corrupted record must not fail the whole snapshot. Only
	// telemetry fields exist on the persisted struct, so nothing selection-
	// related can resurrect here.
	invalidTargets := 0
	for _, target := range snapshot.Targets {
		if target.TargetScope == "" || len(target.TargetScope) > 4096 ||
			target.Candidate == "" || len(target.Candidate) > 4096 ||
			target.Identity == "" || len(target.Identity) > 4096 ||
			target.LossSamples < 0 || target.AttemptCount < 0 || target.SuspectedStallCount < 0 ||
			target.LossSamples == 0 && target.AttemptCount == 0 ||
			math.IsNaN(target.LossEMA) || math.IsInf(target.LossEMA, 0) || target.LossEMA < 0 || target.LossEMA > 1 ||
			target.LastObservedAt.IsZero() || target.LastObservedAt.After(now.Add(vaneLearningFutureSkew)) {
			invalidTargets++
			continue
		}
		transport, transportOK := parseVaneTransport(target.Transport)
		if !transportOK {
			invalidTargets++
			continue
		}
		key := vaneLearningTargetKey(transport, target.TargetScope, target.Port, target.Candidate, target.Identity)
		if previous, exists := s.targets[key]; exists && !target.LastObservedAt.After(previous.LastObservedAt) {
			continue
		}
		s.targets[key] = target
	}
	// The durable revision is diagnostic metadata, not a cross-process CAS
	// sequence. A fresh writer lease starts its own bounded local sequence.
	s.revision = 0
	s.processedRevision = 0
	if invalidNodes > 0 {
		return fmt.Errorf("node state contained %d invalid entries", invalidNodes)
	}
	if invalidTargets > 0 {
		return fmt.Errorf("node state contained %d invalid target entries", invalidTargets)
	}
	return nil
}

func restoreVaneNode(node vanePersistedNode, now time.Time) (*vaneNodeState, bool, bool) {
	tcp, tcpValid, tcpInvalid := restoreVaneMetrics(node.TCP, now)
	udp, udpValid, udpInvalid := restoreVaneMetrics(node.UDP, now)
	state := &vaneNodeState{
		name: node.Name, identity: node.Identity, tcp: tcp, udp: udp, lastObservedAt: node.LastSeen,
	}
	// E: the cumulative loss pair is only restored while fresh; stale counters
	// are dropped entirely so a past lossy phase cannot label the node forever.
	if !node.CumulObservedAt.IsZero() && !node.CumulObservedAt.After(now) &&
		now.Sub(node.CumulObservedAt) < vaneProfileAgeReset {
		// Apply the same decay the booking path applies, so a restart does not
		// skip the interval between the last booking and now.
		decay := math.Exp(-now.Sub(node.CumulObservedAt).Seconds() / vaneCumulDecayTauSeconds)
		state.cumulSent = uint64(math.Round(float64(node.CumulSent) * decay))
		state.cumulRetrans = uint64(math.Round(float64(node.CumulRetrans) * decay))
		state.cumulAt = node.CumulObservedAt
	}
	profileValid, profileInvalid := restoreVaneProfile(state, node, now)
	if !tcpValid && !udpValid && !profileValid {
		return nil, false, tcpInvalid || udpInvalid || profileInvalid
	}
	return state, true, tcpInvalid || udpInvalid || profileInvalid
}

// restoreVaneProfile restores the C batch counters. Out-of-domain values are
// invalid and zeroed (the store never clamps in place), and a group untouched
// for vaneProfileAgeReset is dropped so an old peak cannot pin a node forever.
func restoreVaneProfile(state *vaneNodeState, node vanePersistedNode, now time.Time) (bool, bool) {
	invalid := false
	fresh := func(at time.Time) bool {
		return !at.IsZero() && !at.After(now) && now.Sub(at) < vaneProfileAgeReset
	}
	if fresh(node.CountersAt) {
		state.successCount, state.failureCount, state.countersAt = node.SuccessCount, node.FailureCount, node.CountersAt
	}
	if fresh(node.MaxRateAt) {
		switch {
		case math.IsNaN(node.MaxDownloadRate) || math.IsInf(node.MaxDownloadRate, 0) || node.MaxDownloadRate < 0:
			invalid = true
		case node.MaxDownloadRate > 0:
			state.maxDownloadRate, state.maxRateAt = node.MaxDownloadRate, node.MaxRateAt
		}
	}
	if fresh(node.LatencyAt) && node.LatencySamples > 0 && node.LatencyMs > 0 &&
		!math.IsNaN(node.LatencyMs) && !math.IsInf(node.LatencyMs, 0) {
		state.latencyMs, state.latencySamples, state.latencyAt = node.LatencyMs, node.LatencySamples, node.LatencyAt
	} else if node.LatencyMs < 0 || math.IsNaN(node.LatencyMs) || math.IsInf(node.LatencyMs, 0) ||
		(node.LatencyMs == 0 && node.LatencySamples > 0) {
		invalid = true
	}
	if fresh(node.TotalsAt) {
		switch {
		case node.TotalDuration < 0:
			invalid = true
		default:
			if node.TotalDuration > 0 && node.DurationCount > 0 {
				state.totalDuration = time.Duration(node.TotalDuration) * time.Millisecond
				state.durationCount = node.DurationCount
			}
			if node.DownloadTotal > 0 {
				state.downloadTotal = node.DownloadTotal
			}
			if state.downloadTotal > 0 || state.durationCount > 0 {
				state.totalsAt = node.TotalsAt
			}
		}
	}
	valid := state.successCount+state.failureCount > 0 || state.maxDownloadRate > 0 ||
		state.durationCount > 0 || state.downloadTotal > 0 || state.latencySamples > 0
	return valid, invalid
}

func restoreVaneMetrics(metrics vanePersistedMetrics, now time.Time) (vaneMetrics, bool, bool) {
	failure, failureValid, failureInvalid := restoreVaneDualMetric(metrics.Failure, now)
	connect, connectValid, connectInvalid := restoreVaneDualMetric(metrics.Connect, now)
	response, responseValid, responseInvalid := restoreVaneDualMetric(metrics.Response, now)
	throughput, throughputValid, throughputInvalid := restoreVaneDualMetric(metrics.Throughput, now)
	jitter, jitterValid, jitterInvalid := restoreVaneJitter(metrics.Jitter, now)
	// P5 restores but never decides validity: a node kept alive only by its
	// P5 profile would resurrect selection state from telemetry.
	return vaneMetrics{failure: failure, connect: connect, response: response, throughput: throughput, jitter: jitter, p5: restoreVaneP5(metrics.P5, now)},
		failureValid || connectValid || responseValid || throughputValid || jitterValid,
		failureInvalid || connectInvalid || responseInvalid || throughputInvalid || jitterInvalid
}

func restoreVaneDualMetric(metric vanePersistedDualMetric, now time.Time) (vaneDualMetric, bool, bool) {
	fast, fastValid, fastInvalid := restoreVaneDecayLayer(metric.Fast, now)
	slow, slowValid, slowInvalid := restoreVaneDecayLayer(metric.Slow, now)
	return vaneDualMetric{fast: fast, slow: slow}, fastValid || slowValid, fastInvalid || slowInvalid
}

func restoreVaneDualMetricWithCap(metric vanePersistedDualMetric, now time.Time, maxAverage float64) (vaneDualMetric, bool, bool) {
	fast, fastValid, fastInvalid := restoreVaneDecayLayerWithCap(metric.Fast, now, maxAverage)
	slow, slowValid, slowInvalid := restoreVaneDecayLayerWithCap(metric.Slow, now, maxAverage)
	return vaneDualMetric{fast: fast, slow: slow}, fastValid || slowValid, fastInvalid || slowInvalid
}

func restoreVaneJitter(persisted *vanePersistedJitter, now time.Time) (vaneJitterTracker, bool, bool) {
	if persisted == nil {
		return vaneJitterTracker{}, false, false
	}
	mean, meanValid, meanInvalid := restoreVaneDualMetricWithCap(persisted.Mean, now, vaneLearningMaximumJitterValue)
	deviation, deviationValid, deviationInvalid := restoreVaneDualMetricWithCap(persisted.Deviation, now, vaneLearningMaximumJitterValue)
	tracker := vaneJitterTracker{mean: mean, deviation: deviation, samples: persisted.Samples}
	if persisted.Samples < 0 {
		return vaneJitterTracker{}, false, true
	}
	if persisted.Samples == 0 {
		if meanValid || deviationValid {
			return vaneJitterTracker{}, false, true
		}
		return tracker, false, meanInvalid || deviationInvalid
	}
	valid := meanValid || deviationValid
	invalid := meanInvalid || deviationInvalid
	if !valid {
		invalid = true
	}
	return tracker, valid, invalid
}

func restoreVaneDecayLayer(layer vanePersistedDecayLayer, now time.Time) (vaneDecayLayer, bool, bool) {
	return restoreVaneDecayLayerWithCap(layer, now, vaneLearningMaximumAverage)
}

func restoreVaneDecayLayerWithCap(layer vanePersistedDecayLayer, now time.Time, maxAverage float64) (vaneDecayLayer, bool, bool) {
	if !layer.Valid {
		invalid := layer.Weight != 0 || layer.Sum != 0 || !layer.UpdatedAt.IsZero()
		return vaneDecayLayer{}, false, invalid
	}
	if layer.Weight <= 0 || layer.Weight > vaneLearningMaximumWeight || math.IsNaN(layer.Weight) || math.IsInf(layer.Weight, 0) ||
		layer.Sum < 0 || math.IsNaN(layer.Sum) || math.IsInf(layer.Sum, 0) || layer.UpdatedAt.IsZero() ||
		layer.UpdatedAt.After(now.Add(vaneLearningFutureSkew)) || layer.Sum/layer.Weight > maxAverage {
		return vaneDecayLayer{}, false, true
	}
	return vaneDecayLayer{weight: layer.Weight, sum: layer.Sum, updatedAt: layer.UpdatedAt, valid: true}, true, false
}

func persistVaneDecayLayer(layer vaneDecayLayer) vanePersistedDecayLayer {
	return vanePersistedDecayLayer{Weight: layer.weight, Sum: layer.sum, UpdatedAt: layer.updatedAt, Valid: layer.valid}
}

func persistVaneDualMetric(metric vaneDualMetric) vanePersistedDualMetric {
	return vanePersistedDualMetric{Fast: persistVaneDecayLayer(metric.fast), Slow: persistVaneDecayLayer(metric.slow)}
}

func persistVaneJitter(tracker vaneJitterTracker) *vanePersistedJitter {
	if tracker.samples == 0 {
		return nil
	}
	return &vanePersistedJitter{Mean: persistVaneDualMetric(tracker.mean),
		Deviation: persistVaneDualMetric(tracker.deviation), Samples: tracker.samples}
}

func persistVaneMetrics(metrics vaneMetrics, now time.Time) vanePersistedMetrics {
	return vanePersistedMetrics{
		Failure:    persistVaneDualMetric(metrics.failure),
		Connect:    persistVaneDualMetric(metrics.connect),
		Response:   persistVaneDualMetric(metrics.response),
		Throughput: persistVaneDualMetric(metrics.throughput),
		Jitter:     persistVaneJitter(metrics.jitter),
		P5:         persistVaneP5(&metrics.p5, now),
	}
}

// pushTarget mirrors one live target record's telemetry into the
// learning state (round6 item 3). The group calls it while holding a.mu —
// the same a.mu → learning order the observe path uses — and only the
// learning lock is taken here. The flush serializes from the map without
// ever reaching back for a.mu. Over the cap the oldest entries evict first
// (lastObservedAt ascending, key text breaking ties), matching the snapshot
// ordering.
func (s *vaneLearningState) pushTarget(target vanePersistedTarget, now time.Time) {
	if s == nil || target.TargetScope == "" || target.Candidate == "" || target.Identity == "" {
		return
	}
	transport, transportOK := parseVaneTransport(target.Transport)
	if !transportOK {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targets[vaneLearningTargetKey(transport, target.TargetScope, target.Port, target.Candidate, target.Identity)] = target
	for len(s.targets) > vaneLearningTargetLimit {
		oldestKey, oldestAt := "", time.Time{}
		for key, candidate := range s.targets {
			if oldestKey == "" || candidate.LastObservedAt.Before(oldestAt) ||
				(candidate.LastObservedAt.Equal(oldestAt) && key < oldestKey) {
				oldestKey, oldestAt = key, candidate.LastObservedAt
			}
		}
		delete(s.targets, oldestKey)
	}
	s.markDirtyLocked(now.UTC())
}

// seedTarget returns the persisted telemetry for one pair so a live record
// without data can start from the restored values instead of zero
// (round6 item 3). Called with a.mu held; takes only learning.mu.
func (s *vaneLearningState) seedTarget(transport vaneTransport, targetScope string, port uint16, candidate, identity string) (vanePersistedTarget, bool) {
	if s == nil || targetScope == "" || candidate == "" || identity == "" {
		return vanePersistedTarget{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	target, ok := s.targets[vaneLearningTargetKey(transport, targetScope, port, candidate, identity)]
	return target, ok
}

// markDirtyLocked must be called with s.mu held after a persisted field changes.
func (s *vaneLearningState) markDirtyLocked(now time.Time) {
	if s.revision == math.MaxUint64 {
		s.writeBlocked = true
		s.lastError = "node-state revision exhausted"
		return
	}
	s.revision++
	if s.store == nil || s.retiring || s.writeBlocked {
		return
	}
	s.queuePersistenceLocked(now.UTC(), false)
}

func (s *vaneLearningState) queuePersistenceLocked(now time.Time, force bool) {
	interval := s.persistInterval
	if interval <= 0 {
		interval = vaneLearningPersistInterval
	}
	if s.persistRetryAt.After(now) {
		if s.persistTimer == nil && !s.persistRunning {
			s.persistTimer = time.AfterFunc(s.persistRetryAt.Sub(now), s.flushDelayed)
		}
		return
	}
	elapsed := now.Sub(s.lastScheduled)
	if elapsed < 0 {
		elapsed = 0
	}
	if force || elapsed >= interval {
		s.schedulePersistLocked(now)
		return
	}
	if s.persistTimer == nil {
		s.persistTimer = time.AfterFunc(interval-elapsed, s.flushDelayed)
	}
}

func (s *vaneLearningState) snapshotLocked(now time.Time) vaneLearningSnapshot {
	type persistedCandidate struct {
		key   string
		state *vaneNodeState
	}
	candidates := make([]persistedCandidate, 0, len(s.nodes))
	for key, state := range s.nodes {
		if state != nil && vaneIdentityIsPersistent(state.identity) {
			candidates = append(candidates, persistedCandidate{key: key, state: state})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].state.lastObservedAt.Equal(candidates[j].state.lastObservedAt) {
			return candidates[i].state.lastObservedAt.After(candidates[j].state.lastObservedAt)
		}
		return candidates[i].key < candidates[j].key
	})
	nodeLimit := s.maxStates
	if nodeLimit <= 0 || nodeLimit > vaneDefaultMaxStates {
		nodeLimit = vaneDefaultMaxStates
	}
	if len(candidates) > nodeLimit {
		candidates = candidates[:nodeLimit]
	}
	nodes := make([]vanePersistedNode, 0, len(candidates))
	for _, candidate := range candidates {
		state := candidate.state
		nodes = append(nodes, vanePersistedNode{
			Name:            state.name,
			Identity:        state.identity,
			LastSeen:        state.lastObservedAt,
			TCP:             persistVaneMetrics(state.tcp, now),
			UDP:             persistVaneMetrics(state.udp, now),
			CumulSent:       state.cumulSent,
			CumulRetrans:    state.cumulRetrans,
			SuccessCount:    state.successCount,
			FailureCount:    state.failureCount,
			CountersAt:      state.countersAt,
			MaxDownloadRate: state.maxDownloadRate,
			MaxRateAt:       state.maxRateAt,
			TotalDuration:   int64(state.totalDuration / time.Millisecond),
			DurationCount:   state.durationCount,
			DownloadTotal:   state.downloadTotal,
			TotalsAt:        state.totalsAt,
			LatencyMs:       state.latencyMs,
			LatencySamples:  state.latencySamples,
			LatencyAt:       state.latencyAt,
			CumulObservedAt: state.cumulAt,
		})
	}
	targetPairs := make([]struct {
		key    string
		target vanePersistedTarget
	}, 0, len(s.targets))
	for key, target := range s.targets {
		targetPairs = append(targetPairs, struct {
			key    string
			target vanePersistedTarget
		}{key: key, target: target})
	}
	sort.Slice(targetPairs, func(i, j int) bool {
		if !targetPairs[i].target.LastObservedAt.Equal(targetPairs[j].target.LastObservedAt) {
			return targetPairs[i].target.LastObservedAt.After(targetPairs[j].target.LastObservedAt)
		}
		return targetPairs[i].key < targetPairs[j].key
	})
	if len(targetPairs) > vaneLearningTargetLimit {
		targetPairs = targetPairs[:vaneLearningTargetLimit]
	}
	targets := make([]vanePersistedTarget, 0, len(targetPairs))
	for _, pair := range targetPairs {
		targets = append(targets, pair.target)
	}
	return vaneLearningSnapshot{
		SchemaVersion: VaneLearningSchemaVersion,
		Group:         s.group,
		Revision:      s.revision,
		UpdatedAt:     now.UTC(),
		Nodes:         nodes,
		Targets:       targets,
	}
}

func vaneIdentityIsPersistent(identity string) bool {
	return identity != "" && !strings.HasPrefix(identity, "instance:")
}

func marshalVaneLearningSnapshot(snapshot vaneLearningSnapshot) ([]byte, error) {
	payload, err := json.Marshal(snapshot)
	if err != nil || len(payload) <= vaneLearningPayloadLimit {
		return payload, err
	}
	if len(snapshot.Targets) > 0 {
		// Round6 item 3: under the payload cap the telemetry details are the
		// first thing to sacrifice — the 4-dim metrics decide selection.
		snapshot.Targets = nil
		payload, err = json.Marshal(snapshot)
		if err != nil || len(payload) <= vaneLearningPayloadLimit {
			return payload, err
		}
	}
	low, high := 0, len(snapshot.Nodes)
	for low < high {
		mid := (low + high + 1) / 2
		candidate := snapshot
		candidate.Nodes = snapshot.Nodes[:mid]
		encoded, encodeErr := json.Marshal(candidate)
		if encodeErr != nil {
			return nil, encodeErr
		}
		if len(encoded) <= vaneLearningPayloadLimit {
			low = mid
		} else {
			high = mid - 1
		}
	}
	snapshot.Nodes = snapshot.Nodes[:low]
	return json.Marshal(snapshot)
}

func (s *vaneLearningState) schedulePersistLocked(now time.Time) {
	if s.store == nil || s.revision == 0 {
		return
	}
	if s.persistTimer != nil {
		s.persistTimer.Stop()
		s.persistTimer = nil
	}
	s.persistRetryAt = time.Time{}
	if s.revision > s.pending.revision {
		s.pending = vaneLearningPending{revision: s.revision, snapshot: s.snapshotLocked(now)}
	}
	s.lastScheduled = now
	if !s.persistRunning {
		s.persistRunning = true
		s.persistWG.Add(1)
		go s.persistLoop()
	}
}

func (s *vaneLearningState) flushDelayed() {
	s.mu.Lock()
	s.persistTimer = nil
	if s.store != nil && !s.retiring && !s.writeBlocked {
		s.schedulePersistLocked(s.clock.Now().UTC())
	}
	s.mu.Unlock()
}

func (s *vaneLearningState) persistLoop() {
	defer s.persistWG.Done()
	for {
		s.mu.Lock()
		pending := s.pending
		if pending.revision == 0 {
			s.persistRunning = false
			s.mu.Unlock()
			return
		}
		s.pending = vaneLearningPending{}
		store := s.store
		key := s.storageKey
		expectedToken := append([]byte(nil), s.storeToken...)
		s.mu.Unlock()

		payload, err := marshalVaneLearningSnapshot(pending.snapshot)
		var nextToken []byte
		if err == nil {
			if store == nil {
				err = cachefile.ErrCacheUnavailable
			} else {
				nextToken, err = store.Save(key, expectedToken, payload)
			}
		}

		now := s.clock.Now().UTC()
		s.mu.Lock()
		if err != nil {
			conflict := errors.Is(err, cachefile.ErrVaneStateConflict)
			if !conflict && pending.revision > s.pending.revision {
				s.pending = pending
			}
			s.persistRunning = false
			s.available = false
			s.lastError = err.Error()
			if conflict {
				s.writeBlocked = true
				s.pending = vaneLearningPending{}
				s.persistRetryAt = time.Time{}
			} else {
				interval := s.persistInterval
				if interval <= 0 {
					interval = vaneLearningPersistInterval
				}
				s.persistRetryAt = now.Add(interval)
				if s.persistTimer == nil && !s.retiring {
					s.persistTimer = time.AfterFunc(interval, s.flushDelayed)
				}
			}
			s.mu.Unlock()
			log.Warnln("Vane: persist node state for group %s failed: %s", s.group, err.Error())
			return
		}
		if pending.revision > s.processedRevision {
			s.processedRevision = pending.revision
		}
		s.storeToken = append(s.storeToken[:0], nextToken...)
		s.available = true
		s.lastSuccessAt = now
		s.lastError = ""
		s.persistRetryAt = time.Time{}
		s.mu.Unlock()
	}
}

func (s *vaneLearningState) flush() error {
	if s == nil {
		return nil
	}
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	for {
		s.mu.Lock()
		if s.writeBlocked {
			err := errors.New(s.lastError)
			s.mu.Unlock()
			return err
		}
		if s.store == nil {
			err := s.lastError
			s.mu.Unlock()
			if err == "" || err == "persistence disabled" || err == "node-state registry capacity unavailable" {
				return nil
			}
			return errors.New(err)
		}
		s.retiring = true
		if s.persistTimer != nil {
			s.persistTimer.Stop()
			s.persistTimer = nil
		}
		if s.processedRevision >= s.revision && s.pending.revision == 0 && !s.persistRunning {
			s.retiring = false
			s.mu.Unlock()
			return nil
		}
		s.schedulePersistLocked(s.clock.Now().UTC())
		s.mu.Unlock()
		s.persistWG.Wait()

		s.mu.Lock()
		if s.lastError != "" {
			err := errors.New(s.lastError)
			s.retiring = false
			if !s.writeBlocked && s.persistTimer == nil {
				interval := s.persistInterval
				if interval <= 0 {
					interval = vaneLearningPersistInterval
				}
				s.persistTimer = time.AfterFunc(interval, s.flushDelayed)
			}
			s.mu.Unlock()
			return err
		}
		caughtUp := s.processedRevision >= s.revision
		if caughtUp {
			s.retiring = false
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()
	}
}

func (s *vaneLearningState) status() VaneLearningPersistence {
	if s == nil {
		return VaneLearningPersistence{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return VaneLearningPersistence{
		Available:         s.available,
		RestoredNodes:     s.restoredNodes,
		ActiveNodes:       len(s.nodes),
		Revision:          s.revision,
		PersistedRevision: s.processedRevision,
		LastSuccessAt:     s.lastSuccessAt,
		LastError:         s.lastError,
	}
}
