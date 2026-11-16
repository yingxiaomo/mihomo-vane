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
	VaneLearningSchemaVersion   = 1
	vaneLearningRegistryLimit   = 256
	vaneLearningPersistInterval = 30 * time.Second
	vaneLearningFutureSkew      = 5 * time.Minute
	vaneLearningMaximumWeight   = 1e12
	vaneLearningMaximumAverage  = 40.0
	vaneLearningPayloadLimit    = 2 * 1024 * 1024
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

type vanePersistedMetrics struct {
	Failure    vanePersistedDualMetric `json:"failure"`
	Connect    vanePersistedDualMetric `json:"connect"`
	Response   vanePersistedDualMetric `json:"response"`
	Throughput vanePersistedDualMetric `json:"throughput"`
}

type vanePersistedNode struct {
	Name     string               `json:"name"`
	Identity string               `json:"identity"`
	LastSeen time.Time            `json:"lastSeen"`
	TCP      vanePersistedMetrics `json:"tcp"`
	UDP      vanePersistedMetrics `json:"udp"`
}

type vaneLearningSnapshot struct {
	SchemaVersion int                 `json:"schemaVersion"`
	Group         string              `json:"group"`
	Revision      uint64              `json:"revision"`
	UpdatedAt     time.Time           `json:"updatedAt"`
	Nodes         []vanePersistedNode `json:"nodes"`
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

type vaneLearningRegistryState struct {
	sync.Mutex
	entries      map[string]*vaneLearningState
	storeFactory func() vaneLearningStore
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

func acquireVaneLearningState(group string, clock vaneClock, stateTTL time.Duration, maxStates int) *vaneLearningState {
	key := vaneLearningStorageKey(group)
	vaneLearningRegistry.Lock()
	if current := vaneLearningRegistry.entries[key]; current != nil {
		vaneLearningRegistry.Unlock()
		return current
	}
	if len(vaneLearningRegistry.entries) >= vaneLearningRegistryLimit {
		vaneLearningRegistry.Unlock()
		candidate := newVaneLearningState(group, clock, nil, stateTTL, maxStates)
		candidate.mu.Lock()
		candidate.lastError = "node-state registry capacity unavailable"
		candidate.mu.Unlock()
		return candidate
	}
	storeFactory := vaneLearningRegistry.storeFactory
	if storeFactory == nil {
		storeFactory = func() vaneLearningStore { return vaneCacheLearningStore{} }
	}
	// Opening the durable writer rotates its fencing token. Keep registry
	// publication serialized so a losing first-registration candidate cannot
	// fence the canonical owner that wins this key.
	candidate := newVaneLearningState(group, clock, storeFactory(), stateTTL, maxStates)
	vaneLearningRegistry.entries[key] = candidate
	vaneLearningRegistry.Unlock()
	return candidate
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
	// The durable revision is diagnostic metadata, not a cross-process CAS
	// sequence. A fresh writer lease starts its own bounded local sequence.
	s.revision = 0
	s.processedRevision = 0
	if invalidNodes > 0 {
		return fmt.Errorf("node state contained %d invalid entries", invalidNodes)
	}
	return nil
}

func restoreVaneNode(node vanePersistedNode, now time.Time) (*vaneNodeState, bool, bool) {
	tcp, tcpValid, tcpInvalid := restoreVaneMetrics(node.TCP, now)
	udp, udpValid, udpInvalid := restoreVaneMetrics(node.UDP, now)
	if !tcpValid && !udpValid {
		return nil, false, tcpInvalid || udpInvalid
	}
	return &vaneNodeState{name: node.Name, identity: node.Identity, tcp: tcp, udp: udp, lastObservedAt: node.LastSeen}, true, tcpInvalid || udpInvalid
}

func restoreVaneMetrics(metrics vanePersistedMetrics, now time.Time) (vaneMetrics, bool, bool) {
	failure, failureValid, failureInvalid := restoreVaneDualMetric(metrics.Failure, now)
	connect, connectValid, connectInvalid := restoreVaneDualMetric(metrics.Connect, now)
	response, responseValid, responseInvalid := restoreVaneDualMetric(metrics.Response, now)
	throughput, throughputValid, throughputInvalid := restoreVaneDualMetric(metrics.Throughput, now)
	return vaneMetrics{failure: failure, connect: connect, response: response, throughput: throughput},
		failureValid || connectValid || responseValid || throughputValid,
		failureInvalid || connectInvalid || responseInvalid || throughputInvalid
}

func restoreVaneDualMetric(metric vanePersistedDualMetric, now time.Time) (vaneDualMetric, bool, bool) {
	fast, fastValid, fastInvalid := restoreVaneDecayLayer(metric.Fast, now)
	slow, slowValid, slowInvalid := restoreVaneDecayLayer(metric.Slow, now)
	return vaneDualMetric{fast: fast, slow: slow}, fastValid || slowValid, fastInvalid || slowInvalid
}

func restoreVaneDecayLayer(layer vanePersistedDecayLayer, now time.Time) (vaneDecayLayer, bool, bool) {
	if !layer.Valid {
		invalid := layer.Weight != 0 || layer.Sum != 0 || !layer.UpdatedAt.IsZero()
		return vaneDecayLayer{}, false, invalid
	}
	if layer.Weight <= 0 || layer.Weight > vaneLearningMaximumWeight || math.IsNaN(layer.Weight) || math.IsInf(layer.Weight, 0) ||
		layer.Sum < 0 || math.IsNaN(layer.Sum) || math.IsInf(layer.Sum, 0) || layer.UpdatedAt.IsZero() ||
		layer.UpdatedAt.After(now.Add(vaneLearningFutureSkew)) || layer.Sum/layer.Weight > vaneLearningMaximumAverage {
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

func persistVaneMetrics(metrics vaneMetrics) vanePersistedMetrics {
	return vanePersistedMetrics{
		Failure:    persistVaneDualMetric(metrics.failure),
		Connect:    persistVaneDualMetric(metrics.connect),
		Response:   persistVaneDualMetric(metrics.response),
		Throughput: persistVaneDualMetric(metrics.throughput),
	}
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
			Name:     state.name,
			Identity: state.identity,
			LastSeen: state.lastObservedAt,
			TCP:      persistVaneMetrics(state.tcp),
			UDP:      persistVaneMetrics(state.udp),
		})
	}
	return vaneLearningSnapshot{
		SchemaVersion: VaneLearningSchemaVersion,
		Group:         s.group,
		Revision:      s.revision,
		UpdatedAt:     now.UTC(),
		Nodes:         nodes,
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
