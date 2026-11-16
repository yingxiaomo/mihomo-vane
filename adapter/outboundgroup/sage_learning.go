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
	SageLearningSchemaVersion   = 1
	sageLearningRegistryLimit   = 256
	sageLearningPersistInterval = 30 * time.Second
	sageLearningFutureSkew      = 5 * time.Minute
	sageLearningMaximumWeight   = 1e12
	sageLearningMaximumAverage  = 40.0
	sageLearningPayloadLimit    = 2 * 1024 * 1024
)

type sageLearningStore interface {
	Load(key string) (payload, token []byte, err error)
	Save(key string, expectedToken, payload []byte) (token []byte, err error)
}

type sageCacheLearningStore struct{}

func (sageCacheLearningStore) Load(key string) ([]byte, []byte, error) {
	return cachefile.Cache().GetSageStateWithToken(key)
}

func (sageCacheLearningStore) Save(key string, expectedToken, payload []byte) ([]byte, error) {
	return cachefile.Cache().CompareAndSwapSageState(key, expectedToken, payload)
}

// SageLearningPersistence describes the durable node-metric owner. It is
// diagnostic only; reading it never loads, saves, prunes, or refreshes state.
type SageLearningPersistence struct {
	Available         bool      `json:"available"`
	RestoredNodes     int       `json:"restoredNodes"`
	ActiveNodes       int       `json:"activeNodes"`
	Revision          uint64    `json:"revision"`
	PersistedRevision uint64    `json:"persistedRevision"`
	LastSuccessAt     time.Time `json:"lastSuccessAt,omitempty"`
	LastError         string    `json:"lastError,omitempty"`
}

type sagePersistedDecayLayer struct {
	Weight    float64   `json:"weight"`
	Sum       float64   `json:"sum"`
	UpdatedAt time.Time `json:"updatedAt"`
	Valid     bool      `json:"valid"`
}

type sagePersistedDualMetric struct {
	Fast sagePersistedDecayLayer `json:"fast"`
	Slow sagePersistedDecayLayer `json:"slow"`
}

type sagePersistedMetrics struct {
	Failure    sagePersistedDualMetric `json:"failure"`
	Connect    sagePersistedDualMetric `json:"connect"`
	Response   sagePersistedDualMetric `json:"response"`
	Throughput sagePersistedDualMetric `json:"throughput"`
}

type sagePersistedNode struct {
	Name     string               `json:"name"`
	Identity string               `json:"identity"`
	LastSeen time.Time            `json:"lastSeen"`
	TCP      sagePersistedMetrics `json:"tcp"`
	UDP      sagePersistedMetrics `json:"udp"`
}

type sageLearningSnapshot struct {
	SchemaVersion int                 `json:"schemaVersion"`
	Group         string              `json:"group"`
	Revision      uint64              `json:"revision"`
	UpdatedAt     time.Time           `json:"updatedAt"`
	Nodes         []sagePersistedNode `json:"nodes"`
}

type sageLearningPending struct {
	revision uint64
	snapshot sageLearningSnapshot
}

type sageLearningState struct {
	mu      sync.Mutex
	flushMu sync.Mutex

	clock      sageClock
	store      sageLearningStore
	group      string
	storageKey string
	nodes      map[string]*sageNodeState
	nodeEpochs map[string]uint64
	stateTTL   time.Duration
	maxStates  int
	generation uint64

	revision          uint64
	processedRevision uint64
	pending           sageLearningPending
	persistInterval   time.Duration
	lastScheduled     time.Time
	persistTimer      *time.Timer
	persistRunning    bool
	persistRetryAt    time.Time
	persistWG         sync.WaitGroup
	retiring          bool

	available     bool
	restoredNodes int
	lastSuccessAt time.Time
	lastError     string
	storeToken    []byte
	writeBlocked  bool
}

type sageLearningRegistryState struct {
	sync.Mutex
	entries      map[string]*sageLearningState
	storeFactory func() sageLearningStore
}

var sageLearningRegistry = sageLearningRegistryState{
	entries: make(map[string]*sageLearningState),
	storeFactory: func() sageLearningStore {
		return sageCacheLearningStore{}
	},
}

func sageLearningStorageKey(group string) string {
	sum := sha256.Sum256([]byte(group))
	return "sage-state-v1:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func sageLearningNodeKey(name, identity string) string {
	if identity == "" {
		return name
	}
	return name + "\x00" + identity
}

func newSageLearningState(group string, clock sageClock, store sageLearningStore, stateTTL time.Duration, maxStates int) *sageLearningState {
	if clock == nil {
		clock = sageSystemClock{}
	}
	now := clock.Now().UTC()
	state := &sageLearningState{
		clock:           clock,
		store:           store,
		group:           group,
		storageKey:      sageLearningStorageKey(group),
		nodes:           make(map[string]*sageNodeState),
		nodeEpochs:      make(map[string]uint64),
		stateTTL:        stateTTL,
		maxStates:       maxStates,
		generation:      1,
		persistInterval: sageLearningPersistInterval,
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
		if errors.Is(err, cachefile.ErrSageStateIncompatibleSchema) && len(token) != 0 {
			state.available = true
			state.writeBlocked = true
			log.Warnln("Sage: node state for group %s uses an incompatible schema and is read-only: %s", group, err.Error())
			return state
		}
		if errors.Is(err, cachefile.ErrSageStatePayloadTooLarge) && len(token) != 0 {
			// Keep the writer fence so the first bounded valid snapshot can
			// atomically replace a legacy oversized row.
			state.available = true
			log.Warnln("Sage: oversized node state for group %s will be replaced after new evidence: %s", group, err.Error())
			return state
		}
		log.Warnln("Sage: node-state persistence unavailable for group %s: %s", group, err.Error())
		state.store = nil
		return state
	}
	state.available = true
	if len(payload) == 0 {
		return state
	}
	if err := state.restore(payload); err != nil {
		state.lastError = err.Error()
		log.Warnln("Sage: ignore invalid node state for group %s: %s", group, err.Error())
	}
	return state
}

func acquireSageLearningState(group string, clock sageClock, stateTTL time.Duration, maxStates int) *sageLearningState {
	key := sageLearningStorageKey(group)
	sageLearningRegistry.Lock()
	if current := sageLearningRegistry.entries[key]; current != nil {
		sageLearningRegistry.Unlock()
		return current
	}
	if len(sageLearningRegistry.entries) >= sageLearningRegistryLimit {
		sageLearningRegistry.Unlock()
		candidate := newSageLearningState(group, clock, nil, stateTTL, maxStates)
		candidate.mu.Lock()
		candidate.lastError = "node-state registry capacity unavailable"
		candidate.mu.Unlock()
		return candidate
	}
	storeFactory := sageLearningRegistry.storeFactory
	if storeFactory == nil {
		storeFactory = func() sageLearningStore { return sageCacheLearningStore{} }
	}
	// Opening the durable writer rotates its fencing token. Keep registry
	// publication serialized so a losing first-registration candidate cannot
	// fence the canonical owner that wins this key.
	candidate := newSageLearningState(group, clock, storeFactory(), stateTTL, maxStates)
	sageLearningRegistry.entries[key] = candidate
	sageLearningRegistry.Unlock()
	return candidate
}

func activateSageLearningState(state *sageLearningState, stateTTL time.Duration, maxStates int) uint64 {
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

func sharedSageLearningState(group string, clock sageClock, stateTTL time.Duration, maxStates int) (*sageLearningState, uint64) {
	state := acquireSageLearningState(group, clock, stateTTL, maxStates)
	return state, activateSageLearningState(state, stateTTL, maxStates)
}

// FlushSageLearningStates drains the latest durable revision for every
// registered Sage group. It is called during process shutdown; reloads use
// the shared owner and therefore do not require a load/save handoff.
func FlushSageLearningStates() error {
	return FlushSageLearningStatesContext(context.Background())
}

func FlushSageLearningStatesContext(ctx context.Context) error {
	sageLearningRegistry.Lock()
	states := make([]*sageLearningState, 0, len(sageLearningRegistry.entries))
	for _, state := range sageLearningRegistry.entries {
		states = append(states, state)
	}
	sageLearningRegistry.Unlock()

	results := make(chan error, len(states))
	for _, state := range states {
		go func(state *sageLearningState) { results <- state.flush() }(state)
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

func (s *sageLearningState) restore(payload []byte) error {
	var snapshot sageLearningSnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return fmt.Errorf("decode node state: %w", err)
	}
	if snapshot.SchemaVersion != SageLearningSchemaVersion {
		if snapshot.SchemaVersion > SageLearningSchemaVersion {
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
	if snapshot.UpdatedAt.After(now.Add(sageLearningFutureSkew)) {
		return fmt.Errorf("node-state timestamp is in the future")
	}

	byKey := make(map[string]sagePersistedNode, len(snapshot.Nodes))
	invalidNodes := 0
	for _, node := range snapshot.Nodes {
		if node.Name == "" || len(node.Name) > 4096 || node.Identity == "" || len(node.Identity) > 4096 || node.LastSeen.IsZero() || node.LastSeen.After(now.Add(sageLearningFutureSkew)) {
			invalidNodes++
			continue
		}
		restored, ok, invalid := restoreSageNode(node, now)
		if invalid {
			invalidNodes++
		}
		if !ok {
			continue
		}
		key := sageLearningNodeKey(node.Name, node.Identity)
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
	// The durable revision is diagnostic metadata, not a cross-process CAS
	// sequence. A fresh writer lease starts its own bounded local sequence.
	s.revision = 0
	s.processedRevision = 0
	if invalidNodes > 0 {
		return fmt.Errorf("node state contained %d invalid entries", invalidNodes)
	}
	return nil
}

func restoreSageNode(node sagePersistedNode, now time.Time) (*sageNodeState, bool, bool) {
	tcp, tcpValid, tcpInvalid := restoreSageMetrics(node.TCP, now)
	udp, udpValid, udpInvalid := restoreSageMetrics(node.UDP, now)
	if !tcpValid && !udpValid {
		return nil, false, tcpInvalid || udpInvalid
	}
	return &sageNodeState{name: node.Name, identity: node.Identity, tcp: tcp, udp: udp, lastObservedAt: node.LastSeen}, true, tcpInvalid || udpInvalid
}

func restoreSageMetrics(metrics sagePersistedMetrics, now time.Time) (sageMetrics, bool, bool) {
	failure, failureValid, failureInvalid := restoreSageDualMetric(metrics.Failure, now)
	connect, connectValid, connectInvalid := restoreSageDualMetric(metrics.Connect, now)
	response, responseValid, responseInvalid := restoreSageDualMetric(metrics.Response, now)
	throughput, throughputValid, throughputInvalid := restoreSageDualMetric(metrics.Throughput, now)
	return sageMetrics{failure: failure, connect: connect, response: response, throughput: throughput},
		failureValid || connectValid || responseValid || throughputValid,
		failureInvalid || connectInvalid || responseInvalid || throughputInvalid
}

func restoreSageDualMetric(metric sagePersistedDualMetric, now time.Time) (sageDualMetric, bool, bool) {
	fast, fastValid, fastInvalid := restoreSageDecayLayer(metric.Fast, now)
	slow, slowValid, slowInvalid := restoreSageDecayLayer(metric.Slow, now)
	return sageDualMetric{fast: fast, slow: slow}, fastValid || slowValid, fastInvalid || slowInvalid
}

func restoreSageDecayLayer(layer sagePersistedDecayLayer, now time.Time) (sageDecayLayer, bool, bool) {
	if !layer.Valid {
		invalid := layer.Weight != 0 || layer.Sum != 0 || !layer.UpdatedAt.IsZero()
		return sageDecayLayer{}, false, invalid
	}
	if layer.Weight <= 0 || layer.Weight > sageLearningMaximumWeight || math.IsNaN(layer.Weight) || math.IsInf(layer.Weight, 0) ||
		layer.Sum < 0 || math.IsNaN(layer.Sum) || math.IsInf(layer.Sum, 0) || layer.UpdatedAt.IsZero() ||
		layer.UpdatedAt.After(now.Add(sageLearningFutureSkew)) || layer.Sum/layer.Weight > sageLearningMaximumAverage {
		return sageDecayLayer{}, false, true
	}
	return sageDecayLayer{weight: layer.Weight, sum: layer.Sum, updatedAt: layer.UpdatedAt, valid: true}, true, false
}

func persistSageDecayLayer(layer sageDecayLayer) sagePersistedDecayLayer {
	return sagePersistedDecayLayer{Weight: layer.weight, Sum: layer.sum, UpdatedAt: layer.updatedAt, Valid: layer.valid}
}

func persistSageDualMetric(metric sageDualMetric) sagePersistedDualMetric {
	return sagePersistedDualMetric{Fast: persistSageDecayLayer(metric.fast), Slow: persistSageDecayLayer(metric.slow)}
}

func persistSageMetrics(metrics sageMetrics) sagePersistedMetrics {
	return sagePersistedMetrics{
		Failure:    persistSageDualMetric(metrics.failure),
		Connect:    persistSageDualMetric(metrics.connect),
		Response:   persistSageDualMetric(metrics.response),
		Throughput: persistSageDualMetric(metrics.throughput),
	}
}

// markDirtyLocked must be called with s.mu held after a persisted field changes.
func (s *sageLearningState) markDirtyLocked(now time.Time) {
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

func (s *sageLearningState) queuePersistenceLocked(now time.Time, force bool) {
	interval := s.persistInterval
	if interval <= 0 {
		interval = sageLearningPersistInterval
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

func (s *sageLearningState) snapshotLocked(now time.Time) sageLearningSnapshot {
	type persistedCandidate struct {
		key   string
		state *sageNodeState
	}
	candidates := make([]persistedCandidate, 0, len(s.nodes))
	for key, state := range s.nodes {
		if state != nil && sageIdentityIsPersistent(state.identity) {
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
	if nodeLimit <= 0 || nodeLimit > sageDefaultMaxStates {
		nodeLimit = sageDefaultMaxStates
	}
	if len(candidates) > nodeLimit {
		candidates = candidates[:nodeLimit]
	}
	nodes := make([]sagePersistedNode, 0, len(candidates))
	for _, candidate := range candidates {
		state := candidate.state
		nodes = append(nodes, sagePersistedNode{
			Name:     state.name,
			Identity: state.identity,
			LastSeen: state.lastObservedAt,
			TCP:      persistSageMetrics(state.tcp),
			UDP:      persistSageMetrics(state.udp),
		})
	}
	return sageLearningSnapshot{
		SchemaVersion: SageLearningSchemaVersion,
		Group:         s.group,
		Revision:      s.revision,
		UpdatedAt:     now.UTC(),
		Nodes:         nodes,
	}
}

func sageIdentityIsPersistent(identity string) bool {
	return identity != "" && !strings.HasPrefix(identity, "instance:")
}

func marshalSageLearningSnapshot(snapshot sageLearningSnapshot) ([]byte, error) {
	payload, err := json.Marshal(snapshot)
	if err != nil || len(payload) <= sageLearningPayloadLimit {
		return payload, err
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
		if len(encoded) <= sageLearningPayloadLimit {
			low = mid
		} else {
			high = mid - 1
		}
	}
	snapshot.Nodes = snapshot.Nodes[:low]
	return json.Marshal(snapshot)
}

func (s *sageLearningState) schedulePersistLocked(now time.Time) {
	if s.store == nil || s.revision == 0 {
		return
	}
	if s.persistTimer != nil {
		s.persistTimer.Stop()
		s.persistTimer = nil
	}
	s.persistRetryAt = time.Time{}
	if s.revision > s.pending.revision {
		s.pending = sageLearningPending{revision: s.revision, snapshot: s.snapshotLocked(now)}
	}
	s.lastScheduled = now
	if !s.persistRunning {
		s.persistRunning = true
		s.persistWG.Add(1)
		go s.persistLoop()
	}
}

func (s *sageLearningState) flushDelayed() {
	s.mu.Lock()
	s.persistTimer = nil
	if s.store != nil && !s.retiring && !s.writeBlocked {
		s.schedulePersistLocked(s.clock.Now().UTC())
	}
	s.mu.Unlock()
}

func (s *sageLearningState) persistLoop() {
	defer s.persistWG.Done()
	for {
		s.mu.Lock()
		pending := s.pending
		if pending.revision == 0 {
			s.persistRunning = false
			s.mu.Unlock()
			return
		}
		s.pending = sageLearningPending{}
		store := s.store
		key := s.storageKey
		expectedToken := append([]byte(nil), s.storeToken...)
		s.mu.Unlock()

		payload, err := marshalSageLearningSnapshot(pending.snapshot)
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
			conflict := errors.Is(err, cachefile.ErrSageStateConflict)
			if !conflict && pending.revision > s.pending.revision {
				s.pending = pending
			}
			s.persistRunning = false
			s.available = false
			s.lastError = err.Error()
			if conflict {
				s.writeBlocked = true
				s.pending = sageLearningPending{}
				s.persistRetryAt = time.Time{}
			} else {
				interval := s.persistInterval
				if interval <= 0 {
					interval = sageLearningPersistInterval
				}
				s.persistRetryAt = now.Add(interval)
				if s.persistTimer == nil && !s.retiring {
					s.persistTimer = time.AfterFunc(interval, s.flushDelayed)
				}
			}
			s.mu.Unlock()
			log.Warnln("Sage: persist node state for group %s failed: %s", s.group, err.Error())
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

func (s *sageLearningState) flush() error {
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
					interval = sageLearningPersistInterval
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

func (s *sageLearningState) status() SageLearningPersistence {
	if s == nil {
		return SageLearningPersistence{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return SageLearningPersistence{
		Available:         s.available,
		RestoredNodes:     s.restoredNodes,
		ActiveNodes:       len(s.nodes),
		Revision:          s.revision,
		PersistedRevision: s.processedRevision,
		LastSuccessAt:     s.lastSuccessAt,
		LastError:         s.lastError,
	}
}
