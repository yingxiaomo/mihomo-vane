package outboundgroup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	A "github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/stretchr/testify/require"
)

type vaneLearningTestStore struct {
	mu     sync.Mutex
	data   map[string][]byte
	writes int
	fail   error
	saved  chan struct{}
}

func newVaneLearningTestStore() *vaneLearningTestStore {
	return &vaneLearningTestStore{data: make(map[string][]byte)}
}

func vaneLearningTestNodeKey(name string) string {
	return vaneLearningNodeKey(name, "test:"+name)
}

func (s *vaneLearningTestStore) Load(key string) ([]byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	payload := append([]byte(nil), s.data[key]...)
	if payload == nil {
		return nil, nil, nil
	}
	digest := sha256.Sum256(payload)
	return payload, append([]byte(nil), digest[:]...), nil
}

func (s *vaneLearningTestStore) Save(key string, expectedToken, payload []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return nil, s.fail
	}
	var currentToken []byte
	if current := s.data[key]; current != nil {
		digest := sha256.Sum256(current)
		currentToken = digest[:]
	}
	if !bytes.Equal(currentToken, expectedToken) {
		return nil, cachefile.ErrVaneStateConflict
	}
	s.data[key] = append([]byte(nil), payload...)
	s.writes++
	if s.saved != nil {
		select {
		case s.saved <- struct{}{}:
		default:
		}
	}
	digest := sha256.Sum256(payload)
	return append([]byte(nil), digest[:]...), nil
}

type vaneLearningLoadErrorStore struct{ err error }

func (s vaneLearningLoadErrorStore) Load(string) ([]byte, []byte, error) {
	return nil, nil, s.err
}
func (s vaneLearningLoadErrorStore) Save(string, []byte, []byte) ([]byte, error) {
	return nil, nil
}

type vaneLearningOversizedStore struct {
	token []byte
	saved []byte
}

func (s *vaneLearningOversizedStore) Load(string) ([]byte, []byte, error) {
	return nil, append([]byte(nil), s.token...), fmt.Errorf("%w: seeded legacy row", cachefile.ErrVaneStatePayloadTooLarge)
}

func (s *vaneLearningOversizedStore) Save(_ string, expectedToken, payload []byte) ([]byte, error) {
	if !bytes.Equal(expectedToken, s.token) {
		return nil, cachefile.ErrVaneStateConflict
	}
	s.saved = append([]byte(nil), payload...)
	s.token = []byte("next-token")
	return append([]byte(nil), s.token...), nil
}

type vaneLearningBlockingLoadStore struct {
	*vaneLearningTestStore
	entered chan struct{}
	release chan struct{}
}

func (s *vaneLearningBlockingLoadStore) Load(key string) ([]byte, []byte, error) {
	s.entered <- struct{}{}
	<-s.release
	return s.vaneLearningTestStore.Load(key)
}

func (s *vaneLearningTestStore) payload(key string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.data[key]...)
}

type vaneLearningBlockingStore struct {
	*vaneLearningTestStore
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func newVaneLearningBlockingStore() *vaneLearningBlockingStore {
	return &vaneLearningBlockingStore{
		vaneLearningTestStore: newVaneLearningTestStore(),
		entered:               make(chan struct{}),
		release:               make(chan struct{}),
	}
}

func (s *vaneLearningBlockingStore) Save(key string, expectedToken, payload []byte) ([]byte, error) {
	s.once.Do(func() {
		close(s.entered)
		<-s.release
	})
	return s.vaneLearningTestStore.Save(key, expectedToken, payload)
}

func attachVaneLearningForTest(group *Vane, state *vaneLearningState, generation uint64) {
	group.attachLearningState(state, generation)
}

func useVaneLearningRegistryStoreForTest(t *testing.T, group string, store vaneLearningStore) {
	t.Helper()
	key := vaneLearningStorageKey(group)
	vaneLearningRegistry.Lock()
	previousFactory := vaneLearningRegistry.storeFactory
	delete(vaneLearningRegistry.entries, key)
	vaneLearningRegistry.storeFactory = func() vaneLearningStore { return store }
	vaneLearningRegistry.Unlock()
	t.Cleanup(func() {
		vaneLearningRegistry.Lock()
		state := vaneLearningRegistry.entries[key]
		delete(vaneLearningRegistry.entries, key)
		vaneLearningRegistry.storeFactory = previousFactory
		vaneLearningRegistry.Unlock()
		if state != nil {
			_ = state.flush()
		}
	})
}

func TestVaneLearningProxyIdentityScopesSameNameEvidence(t *testing.T) {
	proxyMapping := func(port int) map[string]any {
		return map[string]any{"name": "alpha", "type": "socks5", "server": "127.0.0.1", "port": port, "username": "sensitive-user", "password": "sensitive-password"}
	}
	firstProxy, err := A.ParseProxy(proxyMapping(1080), A.WithProviderName("provider-a"))
	require.NoError(t, err)
	sameProxy, err := A.ParseProxy(proxyMapping(1080), A.WithProviderName("provider-a"))
	require.NoError(t, err)
	replacedProxy, err := A.ParseProxy(proxyMapping(1081), A.WithProviderName("provider-a"))
	require.NoError(t, err)
	otherProviderProxy, err := A.ParseProxy(proxyMapping(1080), A.WithProviderName("provider-b"))
	require.NoError(t, err)

	firstIdentity := vaneProxyPersistentIdentity(firstProxy)
	require.NotEmpty(t, firstIdentity)
	require.Equal(t, firstIdentity, vaneProxyPersistentIdentity(sameProxy))
	require.NotEqual(t, firstIdentity, vaneProxyPersistentIdentity(replacedProxy))
	require.NotEqual(t, firstIdentity, vaneProxyPersistentIdentity(otherProviderProxy))

	clock := newVaneConnTestClock()
	store := newVaneLearningTestStore()
	owner := newVaneLearningState("identity-scope", clock, store, time.Hour, 16)
	firstGroup, _ := newVaneGroupForTest(clock, 16, time.Hour, firstProxy)
	attachVaneLearningForTest(firstGroup, owner, owner.generation)
	firstGroup.observeConnect("alpha", vaneTransportTCP, clock.Now(), 25*time.Millisecond)
	require.NoError(t, owner.flush())
	persistedPayload := string(store.payload(owner.storageKey))
	require.NotContains(t, persistedPayload, "sensitive-user")
	require.NotContains(t, persistedPayload, "sensitive-password")

	restoredSame := newVaneLearningState("identity-scope", clock, store, time.Hour, 16)
	sameGroup, _ := newVaneGroupForTest(clock, 16, time.Hour, sameProxy)
	attachVaneLearningForTest(sameGroup, restoredSame, restoredSame.generation)
	require.Equal(t, "alpha", sameGroup.pick(nil, vaneTransportTCP, false, true).Name())
	sameGroup.mu.Lock()
	sameSnapshot := sameGroup.nodes["alpha"].snapshot(vaneTransportTCP, clock.Now())
	sameGroup.mu.Unlock()
	require.True(t, sameSnapshot.connect.valid, "unchanged normalized identity must restore evidence")

	restoredChanged := newVaneLearningState("identity-scope", clock, store, time.Hour, 16)
	changedGroup, _ := newVaneGroupForTest(clock, 16, time.Hour, replacedProxy)
	attachVaneLearningForTest(changedGroup, restoredChanged, restoredChanged.generation)
	require.Equal(t, "alpha", changedGroup.pick(nil, vaneTransportTCP, false, true).Name())
	changedGroup.mu.Lock()
	changedSnapshot := changedGroup.nodes["alpha"].snapshot(vaneTransportTCP, clock.Now())
	changedGroup.mu.Unlock()
	require.False(t, changedSnapshot.connect.valid, "same-named replacement must start cold")
}

func TestVaneLearningInstanceScopedCandidateIsNotPersisted(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneLearningTestStore()
	proxy := A.NewProxy(newVaneTestProxy("anonymous", true, true).Adapter())
	replacement := A.NewProxy(newVaneTestProxy("anonymous", true, true).Adapter())
	require.NotEqual(t, vaneProxyPersistentIdentity(proxy), vaneProxyPersistentIdentity(replacement))
	require.False(t, vaneIdentityIsPersistent(vaneProxyPersistentIdentity(proxy)))
	owner := newVaneLearningState("unidentifiable", clock, store, time.Hour, 16)
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, proxy)
	attachVaneLearningForTest(group, owner, owner.generation)
	group.observeConnect("anonymous", vaneTransportTCP, clock.Now(), 20*time.Millisecond)
	require.NoError(t, owner.flush())
	var snapshot vaneLearningSnapshot
	require.NoError(t, json.Unmarshal(store.payload(owner.storageKey), &snapshot))
	require.Empty(t, snapshot.Nodes)
}

func TestVaneLearningLateCallbackCannotContaminateSameNameReplacement(t *testing.T) {
	clock := newVaneConnTestClock()
	oldProxy := newVaneTestProxy("alpha", true, true)
	oldProxy.identity = "identity-old"
	newProxy := newVaneTestProxy("alpha", true, true)
	newProxy.identity = "identity-new"
	owner := newVaneLearningState("identity-callback", clock, newVaneLearningTestStore(), time.Hour, 16)
	group, provider := newVaneGroupForTest(clock, 16, time.Hour, oldProxy)
	attachVaneLearningForTest(group, owner, owner.generation)
	require.Equal(t, "alpha", group.pick(nil, vaneTransportTCP, false, true).Name())
	oldIdentity := vaneProxyPersistentIdentity(oldProxy)

	provider.setProxies(newProxy)
	require.Equal(t, "alpha", group.pick(nil, vaneTransportTCP, false, true).Name())
	group.observeThroughputIdentity("alpha", oldIdentity, vaneTransportTCP, clock.Now(), 9_000_000)

	group.mu.Lock()
	current := group.nodes["alpha"]
	currentControl := group.nodeControls["alpha"]
	group.mu.Unlock()
	require.Equal(t, "identity-new", current.identity)
	require.False(t, current.snapshot(vaneTransportTCP, clock.Now()).throughput.valid)
	require.Zero(t, currentControl.recentTCPThroughput, "late old-identity callback must not recreate control evidence")
	owner.mu.Lock()
	oldState := owner.nodes[vaneLearningNodeKey("alpha", "identity-old")]
	owner.mu.Unlock()
	require.True(t, oldState.snapshot(vaneTransportTCP, clock.Now()).throughput.valid, "late sample remains attributed to its original durable identity")
}

func TestVaneLearningRestoredMaxRevisionStartsFreshWriterSequence(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneLearningTestStore()
	groupName := "max-revision"
	key := vaneLearningStorageKey(groupName)
	payload, err := json.Marshal(vaneLearningSnapshot{
		SchemaVersion: VaneLearningSchemaVersion,
		Group:         groupName,
		Revision:      math.MaxUint64,
		UpdatedAt:     clock.Now().UTC(),
	})
	require.NoError(t, err)
	store.data[key] = payload
	state := newVaneLearningState(groupName, clock, store, time.Hour, 16)
	require.Zero(t, state.revision)
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, newVaneTestProxy("alpha", true, true))
	attachVaneLearningForTest(group, state, state.generation)
	group.observeConnect("alpha", vaneTransportTCP, clock.Now(), 10*time.Millisecond)
	require.NoError(t, state.flush())
	require.Equal(t, 1, store.writes)
	require.Equal(t, uint64(1), state.status().PersistedRevision)
}

func TestVaneLearningProductionConstructorReloadAndFreshProcessRestore(t *testing.T) {
	const groupName = "vane-learning-production-restart"
	store := newVaneLearningTestStore()
	useVaneLearningRegistryStoreForTest(t, groupName, store)
	fallback := newVaneTestProxy("fallback", true, false)
	alpha := newVaneTestProxy("alpha", true, true)
	provider := newVaneTestProvider(alpha)

	first, err := NewVane(GroupCommonOption{Name: groupName, URL: C.DefaultTestURL}, VaneOption{}, fallback, []P.ProxyProvider{provider})
	require.NoError(t, err)
	ActivateVaneLearningStates(map[string]C.Proxy{groupName: A.NewProxy(first)})
	first.observeConnect("alpha", vaneTransportTCP, first.clock.Now(), 25*time.Millisecond)
	first.observeResponse("alpha", vaneTransportTCP, first.clock.Now(), 50*time.Millisecond)
	first.mu.Lock()
	first.anchors[vaneAnchorKey{transport: vaneTransportTCP}] = vaneAnchor{name: "alpha"}
	first.cooldowns[vaneCooldownKey{transport: vaneTransportTCP, candidate: "alpha"}] = first.clock.Now().Add(time.Hour)
	first.mu.Unlock()
	first.mu.Lock()
	first.ensureNodeControlLocked("alpha", first.clock.Now()).lastExplored[0] = 42
	first.mu.Unlock()
	require.NoError(t, first.learning.flush())

	key := vaneLearningStorageKey(groupName)
	vaneLearningRegistry.Lock()
	delete(vaneLearningRegistry.entries, key)
	vaneLearningRegistry.Unlock()

	second, err := NewVane(GroupCommonOption{Name: groupName, URL: C.DefaultTestURL}, VaneOption{}, fallback, []P.ProxyProvider{provider})
	require.NoError(t, err)
	ActivateVaneLearningStates(map[string]C.Proxy{groupName: A.NewProxy(second)})
	require.Equal(t, 1, second.learning.status().RestoredNodes)
	second.mu.Lock()
	second.learning.mu.Lock()
	second.nodes["alpha"] = second.learning.nodes[vaneLearningTestNodeKey("alpha")]
	snapshot := second.nodes["alpha"].snapshot(vaneTransportTCP, second.clock.Now())
	require.Empty(t, second.nodeControls)
	second.learning.mu.Unlock()
	second.mu.Unlock()
	require.True(t, snapshot.connect.valid)
	require.True(t, snapshot.response.valid)
	require.Empty(t, second.anchors)
	require.Empty(t, second.cooldowns)
}

func TestVaneLearningProductionReloadSharesCanonicalOwner(t *testing.T) {
	const groupName = "vane-learning-production-reload"
	store := newVaneLearningTestStore()
	useVaneLearningRegistryStoreForTest(t, groupName, store)
	fallback := newVaneTestProxy("fallback", true, false)
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	provider := newVaneTestProvider(alpha, beta)

	oldGroup, err := NewVane(GroupCommonOption{Name: groupName, URL: C.DefaultTestURL}, VaneOption{}, fallback, []P.ProxyProvider{provider})
	require.NoError(t, err)
	ActivateVaneLearningStates(map[string]C.Proxy{groupName: A.NewProxy(oldGroup)})
	oldGroup.observeConnect("beta", vaneTransportTCP, oldGroup.clock.Now(), 100*time.Millisecond)
	oldGroup.mu.Lock()
	oldGroup.ensureNodeControlLocked("beta", oldGroup.clock.Now()).lastExplored[0] = 9
	oldGroup.mu.Unlock()

	newGroup, err := NewVane(GroupCommonOption{Name: groupName, URL: C.DefaultTestURL}, VaneOption{}, fallback, []P.ProxyProvider{provider})
	require.NoError(t, err)
	require.NotSame(t, oldGroup.learning, newGroup.learning, "parse must remain dormant")
	oldGroup.mu.Lock()
	oldGroup.learning.mu.Lock()
	require.Equal(t, oldGroup.learningGeneration, oldGroup.learning.generation, "construction alone must not retire the live generation")
	require.Equal(t, uint64(9), oldGroup.nodeControls["beta"].lastExplored[0], "failed parse must not reset live control state")
	oldGroup.learning.mu.Unlock()
	oldGroup.mu.Unlock()
	ActivateVaneLearningStates(map[string]C.Proxy{groupName: A.NewProxy(newGroup)})
	require.Same(t, oldGroup.learning, newGroup.learning)
	require.Less(t, oldGroup.learningGeneration, newGroup.learningGeneration)
	require.Empty(t, newGroup.nodeControls)

	oldGroup.observeResponse("beta", vaneTransportTCP, oldGroup.clock.Now(), 55*time.Millisecond)
	oldGroup.observeThroughput("beta", vaneTransportTCP, oldGroup.clock.Now(), 2_000_000)
	require.Empty(t, newGroup.nodeControls, "late old-generation callbacks must not repopulate new-generation control state")
	newGroup.mu.Lock()
	newGroup.learning.mu.Lock()
	newGroup.nodes["beta"] = newGroup.learning.nodes[vaneLearningTestNodeKey("beta")]
	snapshot := newGroup.nodes["beta"].snapshot(vaneTransportTCP, newGroup.clock.Now())
	newGroup.learning.mu.Unlock()
	newGroup.mu.Unlock()
	require.True(t, snapshot.connect.valid)
	require.True(t, snapshot.response.valid)
	require.True(t, snapshot.throughput.valid)

	oldGroup.learning.mu.Lock()
	oldGroup.nodes["beta"].lastObservedAt = oldGroup.clock.Now().Add(-2 * vaneDefaultStateTTL)
	oldGroup.pruneLocked(oldGroup.clock.Now(), []C.Proxy{alpha})
	_, survived := oldGroup.nodes["beta"]
	oldGroup.learning.mu.Unlock()
	require.True(t, survived, "stale reload generation must not prune canonical state")
}

func TestVaneCloseDoesNotDrainSharedLearningOwner(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneLearningTestStore()
	owner := newVaneLearningState("close-is-retire-only", clock, store, time.Hour, 16)
	owner.persistInterval = time.Hour
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, newVaneTestProxy("alpha", true, true))
	attachVaneLearningForTest(group, owner, owner.generation)
	group.observeConnect("alpha", vaneTransportTCP, clock.Now(), 20*time.Millisecond)
	require.NoError(t, group.Close())
	require.Nil(t, store.payload(owner.storageKey), "closing a reload generation must not drain the shared owner")
	require.NoError(t, owner.flush())
	require.NotNil(t, store.payload(owner.storageKey))
}

func TestVaneLearningOverlappingReloadsUsePublicationOrderGenerations(t *testing.T) {
	const groupName = "vane-learning-overlapping-reloads"
	store := newVaneLearningTestStore()
	useVaneLearningRegistryStoreForTest(t, groupName, store)
	fallback := newVaneTestProxy("fallback", true, false)
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	provider := newVaneTestProvider(alpha, beta)

	live, err := NewVane(GroupCommonOption{Name: groupName, URL: C.DefaultTestURL}, VaneOption{}, fallback, []P.ProxyProvider{provider})
	require.NoError(t, err)
	ActivateVaneLearningStates(map[string]C.Proxy{groupName: A.NewProxy(live)})
	live.observeConnect("beta", vaneTransportTCP, live.clock.Now(), 50*time.Millisecond)

	first, err := NewVane(GroupCommonOption{Name: groupName, URL: C.DefaultTestURL}, VaneOption{}, fallback, []P.ProxyProvider{provider})
	require.NoError(t, err)
	second, err := NewVane(GroupCommonOption{Name: groupName, URL: C.DefaultTestURL}, VaneOption{}, fallback, []P.ProxyProvider{provider})
	require.NoError(t, err)
	require.Equal(t, first.learningGeneration, second.learningGeneration, "parse must not reserve publication generations")
	require.Equal(t, live.learningGeneration, live.learning.generation, "parsing must not advance the active generation")

	ActivateVaneLearningStates(map[string]C.Proxy{groupName: A.NewProxy(second)})
	require.Equal(t, second.learningGeneration, second.learning.generation)
	ActivateVaneLearningStates(map[string]C.Proxy{groupName: A.NewProxy(first)})
	require.Equal(t, first.learningGeneration, first.learning.generation)
	require.Greater(t, first.learningGeneration, second.learningGeneration, "last publication must own the newest generation even when parse order is reversed")

	second.mu.Lock()
	second.learning.mu.Lock()
	second.learning.nodes[vaneLearningTestNodeKey("beta")].lastObservedAt = second.clock.Now().Add(-2 * vaneDefaultStateTTL)
	second.pruneLocked(second.clock.Now(), []C.Proxy{alpha})
	_, survived := second.learning.nodes[vaneLearningTestNodeKey("beta")]
	second.learning.mu.Unlock()
	second.mu.Unlock()
	require.True(t, survived, "the earlier published group must become stale after the later publication")
}

func TestVaneLearningRestartRestoresOnlyMetricEvidenceAndChangesRanking(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneLearningTestStore()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	first, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
	state := newVaneLearningState("restart-ranking", clock, store, time.Hour, 16)
	attachVaneLearningForTest(first, state, state.generation)

	for i := 0; i < 8; i++ {
		first.recordDialSuccess(nil, vaneTransportTCP, "alpha", first.nodeIdentity("alpha"), clock.Now())
		first.observeConnect("alpha", vaneTransportTCP, clock.Now(), 900*time.Millisecond)
		first.observeResponse("alpha", vaneTransportTCP, clock.Now(), 2*time.Second)
		first.observeThroughput("alpha", vaneTransportTCP, clock.Now(), 100_000)
		first.recordDialSuccess(nil, vaneTransportTCP, "beta", first.nodeIdentity("beta"), clock.Now())
		first.observeConnect("beta", vaneTransportTCP, clock.Now(), 20*time.Millisecond)
		first.observeResponse("beta", vaneTransportTCP, clock.Now(), 40*time.Millisecond)
		first.observeThroughput("beta", vaneTransportTCP, clock.Now(), 8_000_000)
		first.recordDialSuccess(nil, vaneTransportUDP, "beta", first.nodeIdentity("beta"), clock.Now())
		first.observeConnect("beta", vaneTransportUDP, clock.Now(), 10*time.Millisecond)
	}
	first.mu.Lock()
	first.anchors[vaneAnchorKey{transport: vaneTransportTCP}] = vaneAnchor{name: "alpha", scoreMicros: 1}
	first.cooldowns[vaneCooldownKey{transport: vaneTransportTCP, target: "example.com", port: 443, candidate: "beta"}] = clock.Now().Add(time.Hour)
	first.mu.Unlock()
	first.mu.Lock()
	first.ensureNodeControlLocked("beta", clock.Now()).lastExplored[0] = 99
	require.NotZero(t, first.nodeControls["beta"].recentTCPThroughput.bitsPerSecond)
	first.mu.Unlock()

	require.NoError(t, state.flush())
	clock.Advance(5 * time.Minute)
	state.mu.Lock()
	expectedTCP := state.nodes[vaneLearningTestNodeKey("beta")].snapshot(vaneTransportTCP, clock.Now())
	state.mu.Unlock()
	restored := newVaneLearningState("restart-ranking", clock, store, time.Hour, 16)
	status := restored.status()
	require.True(t, status.Available)
	require.Equal(t, 2, status.RestoredNodes)
	require.Empty(t, status.LastError)

	restored.mu.Lock()
	betaState := restored.nodes[vaneLearningTestNodeKey("beta")]
	require.NotNil(t, betaState)
	tcp := betaState.snapshot(vaneTransportTCP, clock.Now())
	udp := betaState.snapshot(vaneTransportUDP, clock.Now())
	require.True(t, tcp.failure.valid)
	require.True(t, tcp.connect.valid)
	require.True(t, tcp.response.valid)
	require.True(t, tcp.throughput.valid)
	require.True(t, udp.failure.valid)
	require.True(t, udp.connect.valid)
	require.Greater(t, tcp.throughput.evidence, 0.0)
	require.InDelta(t, expectedTCP.connect.value, tcp.connect.value, 1e-12)
	require.InDelta(t, expectedTCP.connect.evidence, tcp.connect.evidence, 1e-12)
	require.InDelta(t, expectedTCP.response.evidence, tcp.response.evidence, 1e-12)
	require.InDelta(t, expectedTCP.throughput.evidence, tcp.throughput.evidence, 1e-12)
	restored.mu.Unlock()

	second, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
	attachVaneLearningForTest(second, restored, restored.generation)
	require.Empty(t, second.anchors)
	require.Empty(t, second.cooldowns)
	require.Empty(t, second.nodeControls)
	require.Empty(t, second.hints)
	require.Empty(t, second.ledger)
	require.Empty(t, vaneCooledNodes(second))
	require.Empty(t, second.churn)
	require.Zero(t, second.explorationOrdinal)
	require.Zero(t, second.explorationScopes)
	require.Equal(t, "beta", second.pick(nil, vaneTransportTCP, false, true).Name())
}

func TestVaneLearningReadOnlyAPIsDoNotMutateOrSchedulePersistence(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneLearningTestStore()
	alpha := newVaneTestProxy("alpha", true, true)
	group, provider := newVaneGroupForTest(clock, 16, time.Hour, alpha)
	state := newVaneLearningState("read-only", clock, store, time.Hour, 16)
	attachVaneLearningForTest(group, state, state.generation)
	group.observeConnect("alpha", vaneTransportTCP, clock.Now(), 15*time.Millisecond)
	require.NoError(t, state.flush())

	state.mu.Lock()
	revision := state.revision
	processed := state.processedRevision
	pending := state.pending.revision
	lastSeen := state.nodes[vaneLearningTestNodeKey("alpha")].lastObservedAt
	state.mu.Unlock()
	replacement := newVaneTestProxy("alpha", true, true)
	replacement.identity = "read-only-replacement"
	provider.setProxies(replacement)
	require.Equal(t, "alpha", group.Now())
	require.Equal(t, "alpha", group.Unwrap(nil, false).Name())
	_, err := group.MarshalJSON()
	require.NoError(t, err)
	_ = state.status()
	state.mu.Lock()
	defer state.mu.Unlock()
	require.Equal(t, revision, state.revision)
	require.Equal(t, processed, state.processedRevision)
	require.Equal(t, pending, state.pending.revision)
	require.Nil(t, state.persistTimer)
	require.False(t, state.persistRunning)
	require.Equal(t, lastSeen, state.nodes[vaneLearningTestNodeKey("alpha")].lastObservedAt)
	require.Equal(t, vaneProxyPersistentIdentity(alpha), group.nodeIdentities["alpha"], "read-only selection must not bind a replacement identity")
}

func TestVaneLearningUnknownAndCorruptPayloadAreNonFatalAndObservable(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneLearningTestStore()
	key := vaneLearningStorageKey("corrupt")
	store.data[key] = []byte(`{"schemaVersion":999,"group":"corrupt","updatedAt":"2026-11-14T00:00:00Z"}`)

	unknownPayload := append([]byte(nil), store.data[key]...)
	state := newVaneLearningState("corrupt", clock, store, time.Hour, 16)
	require.Empty(t, state.nodes)
	require.Contains(t, state.status().LastError, "unsupported node-state schema")
	unknownGroup, _ := newVaneGroupForTest(clock, 16, time.Hour, newVaneTestProxy("alpha", true, true))
	attachVaneLearningForTest(unknownGroup, state, state.generation)
	unknownGroup.observeConnect("alpha", vaneTransportTCP, clock.Now(), 10*time.Millisecond)
	require.ErrorContains(t, state.flush(), "unsupported node-state schema")
	require.Equal(t, unknownPayload, store.payload(key), "an older writer must not downgrade an unknown newer schema")

	store.data[key] = []byte(`{"schemaVersion":1`)
	state = newVaneLearningState("corrupt", clock, store, time.Hour, 16)
	require.Empty(t, state.nodes)
	require.Contains(t, state.status().LastError, "decode node state")

	now := clock.Now()
	partial := vaneLearningSnapshot{
		SchemaVersion: VaneLearningSchemaVersion,
		Group:         "corrupt",
		UpdatedAt:     now,
		Nodes: []vanePersistedNode{
			{Name: "good", Identity: "test:good", LastSeen: now, TCP: vanePersistedMetrics{Connect: vanePersistedDualMetric{Fast: vanePersistedDecayLayer{Weight: 1, Sum: 1, UpdatedAt: now, Valid: true}}}},
			{Name: "bad", Identity: "test:bad", LastSeen: now, TCP: vanePersistedMetrics{Connect: vanePersistedDualMetric{Fast: vanePersistedDecayLayer{Weight: -1, Sum: 1, UpdatedAt: now, Valid: true}}}},
		},
	}
	partialPayload, err := json.Marshal(partial)
	require.NoError(t, err)
	store.data[key] = partialPayload
	state = newVaneLearningState("corrupt", clock, store, time.Hour, 16)
	require.Contains(t, state.nodes, vaneLearningTestNodeKey("good"))
	require.NotContains(t, state.nodes, vaneLearningTestNodeKey("bad"))
	require.Contains(t, state.status().LastError, "invalid entries")

	group, _ := newVaneGroupForTest(clock, 16, time.Hour, newVaneTestProxy("alpha", true, true))
	attachVaneLearningForTest(group, state, state.generation)
	group.observeConnect("alpha", vaneTransportTCP, clock.Now(), 25*time.Millisecond)
	require.NoError(t, state.flush())
	require.Empty(t, state.status().LastError)

	var snapshot vaneLearningSnapshot
	require.NoError(t, json.Unmarshal(store.payload(key), &snapshot))
	require.Equal(t, VaneLearningSchemaVersion, snapshot.SchemaVersion)
	require.Len(t, snapshot.Nodes, 2)
}

func TestVaneLearningRestoreDefersDeterministicBoundUntilMembershipIsKnown(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneLearningTestStore()
	now := clock.Now()
	valid := vanePersistedMetrics{Connect: vanePersistedDualMetric{Fast: vanePersistedDecayLayer{
		Weight: 1, Sum: 1, UpdatedAt: now, Valid: true,
	}}}
	snapshot := vaneLearningSnapshot{
		SchemaVersion: VaneLearningSchemaVersion,
		Group:         "bounded",
		UpdatedAt:     now,
		Nodes: []vanePersistedNode{
			{Name: "old-a", Identity: "test:old-a", LastSeen: now.Add(-3 * time.Hour), TCP: valid},
			{Name: "old-b", Identity: "test:old-b", LastSeen: now.Add(-3 * time.Hour), TCP: valid},
			{Name: "middle", Identity: "test:middle", LastSeen: now.Add(-2 * time.Hour), TCP: valid},
			{Name: "new-a", Identity: "test:new-a", LastSeen: now.Add(-time.Hour), TCP: valid},
			{Name: "new-b", Identity: "test:new-b", LastSeen: now.Add(-time.Hour), TCP: valid},
		},
	}
	payload, err := json.Marshal(snapshot)
	require.NoError(t, err)
	store.data[vaneLearningStorageKey("bounded")] = payload

	state := newVaneLearningState("bounded", clock, store, 24*time.Hour, 3)
	state.mu.Lock()
	require.Len(t, state.nodes, 5, "restore must not discard records before providers expose current membership")
	state.mu.Unlock()

	newA := newVaneTestProxy("new-a", true, true)
	newB := newVaneTestProxy("new-b", true, true)
	group, _ := newVaneGroupForTest(clock, 3, 24*time.Hour, newA, newB)
	attachVaneLearningForTest(group, state, state.generation)
	group.mu.Lock()
	state.mu.Lock()
	group.pruneLocked(clock.Now(), []C.Proxy{newA, newB})
	require.Len(t, state.nodes, 3)
	require.NotContains(t, state.nodes, vaneLearningTestNodeKey("old-a"))
	require.NotContains(t, state.nodes, vaneLearningTestNodeKey("old-b"))
	require.Contains(t, state.nodes, vaneLearningTestNodeKey("middle"))
	require.Contains(t, state.nodes, vaneLearningTestNodeKey("new-a"))
	require.Contains(t, state.nodes, vaneLearningTestNodeKey("new-b"))
	state.mu.Unlock()
	group.mu.Unlock()
}

func TestVaneLearningDefaultMaximumSnapshotFitsCachePayload(t *testing.T) {
	clock := newVaneConnTestClock()
	state := newVaneLearningState("payload-bound", clock, nil, time.Hour, vaneDefaultMaxStates)
	now := clock.Now()
	layer := vaneDecayLayer{weight: 10, sum: 100, updatedAt: now, valid: true}
	metric := vaneDualMetric{fast: layer, slow: layer}
	metrics := vaneMetrics{failure: metric, connect: metric, response: metric, throughput: metric}
	state.mu.Lock()
	for i := 0; i < vaneDefaultMaxStates; i++ {
		name := string(rune(i + 1))
		identity := "test:" + name
		state.nodes[vaneLearningNodeKey(name, identity)] = &vaneNodeState{name: name, identity: identity, tcp: metrics, udp: metrics, lastObservedAt: now}
	}
	payload, err := json.Marshal(state.snapshotLocked(now))
	state.mu.Unlock()
	require.NoError(t, err)
	require.LessOrEqual(t, len(payload), 2*1024*1024)
}

func TestVaneLearningMarshalDeterministicallyTrimsOversizedPayload(t *testing.T) {
	now := time.Now().UTC()
	snapshot := vaneLearningSnapshot{
		SchemaVersion: VaneLearningSchemaVersion,
		Group:         "payload-byte-bound",
		Revision:      7,
		UpdatedAt:     now,
		Nodes:         make([]vanePersistedNode, 512),
	}
	for i := range snapshot.Nodes {
		snapshot.Nodes[i] = vanePersistedNode{
			Name:     fmt.Sprintf("%04d-%s", i, strings.Repeat("n", 4096)),
			Identity: strings.Repeat("i", 4096),
			LastSeen: now.Add(-time.Duration(i) * time.Second),
		}
	}
	payload, err := marshalVaneLearningSnapshot(snapshot)
	require.NoError(t, err)
	require.LessOrEqual(t, len(payload), vaneLearningPayloadLimit)
	var trimmed vaneLearningSnapshot
	require.NoError(t, json.Unmarshal(payload, &trimmed))
	require.NotEmpty(t, trimmed.Nodes)
	require.Less(t, len(trimmed.Nodes), len(snapshot.Nodes))
	require.Equal(t, snapshot.Nodes[:len(trimmed.Nodes)], trimmed.Nodes, "byte trimming must retain the deterministic newest prefix")
}

func TestVaneLearningRemovedNodeHonorsTTLAndDoesNotResurrect(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneLearningTestStore()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	owner := newVaneLearningState("remove-readd", clock, store, time.Hour, 16)
	group, provider := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
	attachVaneLearningForTest(group, owner, owner.generation)
	group.observeConnect("alpha", vaneTransportTCP, clock.Now(), 25*time.Millisecond)

	clock.Advance(30 * time.Minute)
	provider.setProxies(beta)
	group.pick(nil, vaneTransportTCP, false, true)
	owner.mu.Lock()
	require.Contains(t, owner.nodes, vaneLearningTestNodeKey("alpha"), "removed node must survive before state TTL")
	owner.mu.Unlock()

	provider.setProxies(alpha, beta)
	group.pick(nil, vaneTransportTCP, false, true)
	owner.mu.Lock()
	require.True(t, owner.nodes[vaneLearningTestNodeKey("alpha")].snapshot(vaneTransportTCP, clock.Now()).connect.valid)
	owner.mu.Unlock()

	clock.Advance(2 * time.Hour)
	provider.setProxies(beta)
	group.pick(nil, vaneTransportTCP, false, true)
	owner.mu.Lock()
	require.NotContains(t, owner.nodes, vaneLearningTestNodeKey("alpha"))
	owner.mu.Unlock()
	require.NoError(t, owner.flush())

	restored := newVaneLearningState("remove-readd", clock, store, time.Hour, 16)
	restored.mu.Lock()
	require.NotContains(t, restored.nodes, vaneLearningTestNodeKey("alpha"), "expired deletion must be durable")
	restored.mu.Unlock()

	provider.setProxies(alpha, beta)
	readded, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
	attachVaneLearningForTest(readded, restored, restored.generation)
	require.Equal(t, "alpha", readded.pick(nil, vaneTransportTCP, false, true).Name())
	restored.mu.Lock()
	cold := restored.nodes[vaneLearningTestNodeKey("alpha")].snapshot(vaneTransportTCP, clock.Now())
	restored.mu.Unlock()
	require.False(t, cold.connect.valid, "re-adding after TTL and durable prune must create a cold node")
}

func TestVaneLearningReaddAfterSilentTTLStartsCold(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	owner := newVaneLearningState("silent-readd", clock, newVaneLearningTestStore(), time.Hour, 16)
	group, provider := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
	attachVaneLearningForTest(group, owner, owner.generation)
	group.observeConnect("alpha", vaneTransportTCP, clock.Now(), 25*time.Millisecond)

	provider.setProxies(beta)
	group.pick(nil, vaneTransportTCP, false, true)
	clock.Advance(2 * time.Hour) // no selector runs while alpha remains absent
	provider.setProxies(alpha)
	group.pick(nil, vaneTransportTCP, false, true)

	owner.mu.Lock()
	snapshot := owner.nodes[vaneLearningTestNodeKey("alpha")].snapshot(vaneTransportTCP, clock.Now())
	owner.mu.Unlock()
	require.False(t, snapshot.connect.valid, "readd must expire old evidence before refreshing membership freshness")
}

func TestVaneLearningExpiredFlowCallbackCannotResurrectNode(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	owner := newVaneLearningState("late-expired-flow", clock, newVaneLearningTestStore(), time.Hour, 16)
	group, provider := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
	attachVaneLearningForTest(group, owner, owner.generation)
	decision := group.pickDecision(context.Background(), nil, vaneTransportTCP, false, true)
	require.Equal(t, "alpha", decision.proxy.Name())
	group.observeConnectEpochIdentity("alpha", decision.identity, decision.nodeEpoch, vaneTransportTCP, clock.Now(), 25*time.Millisecond)

	provider.setProxies(beta)
	clock.Advance(2 * time.Hour)
	group.pick(nil, vaneTransportTCP, false, true)
	owner.mu.Lock()
	require.NotContains(t, owner.nodes, vaneLearningTestNodeKey("alpha"))
	owner.mu.Unlock()

	group.observeResponseEpochIdentity("alpha", decision.identity, decision.nodeEpoch, vaneTransportTCP, clock.Now(), 50*time.Millisecond)
	owner.mu.Lock()
	require.NotContains(t, owner.nodes, vaneLearningTestNodeKey("alpha"), "callback from the deleted incarnation must remain fenced")
	owner.mu.Unlock()
}

func TestVaneLearningBlockedSaveDoesNotBlockObservationsAndFlushKeepsNewestRevision(t *testing.T) {
	clock := newVaneConnTestClock()
	store := &vaneLearningBlockingStore{
		vaneLearningTestStore: newVaneLearningTestStore(),
		entered:               make(chan struct{}),
		release:               make(chan struct{}),
	}
	state := newVaneLearningState("blocked", clock, store, time.Hour, 16)
	state.persistInterval = time.Nanosecond
	state.lastScheduled = clock.Now().Add(-time.Second)
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, newVaneTestProxy("alpha", true, true))
	attachVaneLearningForTest(group, state, state.generation)

	group.observeConnect("alpha", vaneTransportTCP, clock.Now(), 30*time.Millisecond)
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("persistence writer did not enter blocked store")
	}

	observed := make(chan struct{})
	go func() {
		group.observeResponse("alpha", vaneTransportTCP, clock.Now(), 50*time.Millisecond)
		close(observed)
	}()
	select {
	case <-observed:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("hot-path observation blocked behind persistence I/O")
	}

	flushed := make(chan error, 2)
	go func() { flushed <- state.flush() }()
	go func() { flushed <- state.flush() }()
	select {
	case err := <-flushed:
		t.Fatalf("flush returned before blocked save was released: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(store.release)
	require.NoError(t, <-flushed)
	require.NoError(t, <-flushed)

	restored := newVaneLearningState("blocked", clock, store, time.Hour, 16)
	restored.mu.Lock()
	metrics := restored.nodes[vaneLearningTestNodeKey("alpha")].snapshot(vaneTransportTCP, clock.Now())
	restored.mu.Unlock()
	require.True(t, metrics.connect.valid)
	require.True(t, metrics.response.valid)
	require.GreaterOrEqual(t, store.writes, 2)
}

func TestVaneLearningGlobalDrainHonorsContextDeadline(t *testing.T) {
	const groupName = "bounded-global-drain"
	clock := newVaneConnTestClock()
	store := newVaneLearningBlockingStore()
	useVaneLearningRegistryStoreForTest(t, groupName, store)
	group, err := NewVane(GroupCommonOption{Name: groupName, URL: C.DefaultTestURL}, VaneOption{}, newVaneTestProxy("fallback", true, false), []P.ProxyProvider{newVaneTestProvider(newVaneTestProxy("alpha", true, true))})
	require.NoError(t, err)
	ActivateVaneLearningStates(map[string]C.Proxy{groupName: A.NewProxy(group)})
	group.learning.persistInterval = time.Nanosecond
	group.learning.lastScheduled = clock.Now().Add(-time.Second)
	group.observeConnect("alpha", vaneTransportTCP, group.clock.Now(), 20*time.Millisecond)
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("persistence writer did not block")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, FlushVaneLearningStatesContext(ctx), context.DeadlineExceeded)
	close(store.release)
	require.NoError(t, group.learning.flush())
}

func TestVaneLearningReloadSharesMetricsButRejectsStalePruning(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneLearningTestStore()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	owner := newVaneLearningState("reload", clock, store, time.Hour, 16)
	oldGroup, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
	attachVaneLearningForTest(oldGroup, owner, owner.generation)
	oldGroup.observeConnect("beta", vaneTransportTCP, clock.Now(), 100*time.Millisecond)

	owner.mu.Lock()
	owner.generation++
	newGeneration := owner.generation
	owner.nodes[vaneLearningTestNodeKey("beta")].lastObservedAt = clock.Now().Add(-2 * time.Hour)
	owner.mu.Unlock()
	newGroup, _ := newVaneGroupForTest(clock, 16, time.Hour, alpha, beta)
	attachVaneLearningForTest(newGroup, owner, newGeneration)

	oldGroup.learning.mu.Lock()
	oldGroup.pruneLocked(clock.Now(), []C.Proxy{alpha})
	oldGroup.learning.mu.Unlock()
	owner.mu.Lock()
	require.Contains(t, owner.nodes, vaneLearningTestNodeKey("beta"))
	owner.mu.Unlock()

	oldGroup.observeResponse("beta", vaneTransportTCP, clock.Now(), 55*time.Millisecond)
	owner.mu.Lock()
	snapshot := owner.nodes[vaneLearningTestNodeKey("beta")].snapshot(vaneTransportTCP, clock.Now())
	owner.mu.Unlock()
	require.True(t, snapshot.connect.valid)
	require.True(t, snapshot.response.valid)
	require.Empty(t, newGroup.nodeControls)
	require.Same(t, owner, newGroup.learning)
	require.NoError(t, owner.flush())
}

func TestVaneLearningFlushReportsStoreFailureWithoutLosingDirtyRevision(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneLearningTestStore()
	store.fail = errors.New("save failed")
	state := newVaneLearningState("failure", clock, store, time.Hour, 16)
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, newVaneTestProxy("alpha", true, true))
	attachVaneLearningForTest(group, state, state.generation)
	group.observeConnect("alpha", vaneTransportTCP, clock.Now(), 10*time.Millisecond)

	require.ErrorContains(t, state.flush(), "save failed")
	status := state.status()
	require.Contains(t, status.LastError, "save failed")
	require.Greater(t, status.Revision, status.PersistedRevision)
}

func TestVaneLearningOversizedLegacyRowIsReplacedByNextValidSnapshot(t *testing.T) {
	clock := newVaneConnTestClock()
	store := &vaneLearningOversizedStore{token: []byte("legacy-token")}
	state := newVaneLearningState("oversized-recovery", clock, store, time.Hour, 16)
	require.True(t, state.status().Available)
	require.ErrorContains(t, errors.New(state.status().LastError), "payload too large")
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, newVaneTestProxy("alpha", true, true))
	attachVaneLearningForTest(group, state, state.generation)
	group.observeConnect("alpha", vaneTransportTCP, clock.Now(), 25*time.Millisecond)
	require.NoError(t, state.flush())
	require.NotEmpty(t, store.saved)
	require.Equal(t, state.status().Revision, state.status().PersistedRevision)
}

func TestVaneLearningSaveFailureRetriesAndPersistsLatestRevision(t *testing.T) {
	clock := vaneSystemClock{}
	store := newVaneLearningTestStore()
	store.fail = errors.New("temporary save failure")
	store.saved = make(chan struct{}, 1)
	state := newVaneLearningState("save-retry", clock, store, time.Hour, 16)
	state.persistInterval = 5 * time.Millisecond
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, newVaneTestProxy("alpha", true, true))
	attachVaneLearningForTest(group, state, state.generation)
	group.observeConnect("alpha", vaneTransportTCP, clock.Now(), 10*time.Millisecond)
	require.Eventually(t, func() bool {
		return state.status().LastError == "temporary save failure"
	}, time.Second, time.Millisecond)
	group.observeResponse("alpha", vaneTransportTCP, clock.Now(), 20*time.Millisecond)
	store.mu.Lock()
	store.fail = nil
	store.mu.Unlock()
	select {
	case <-store.saved:
	case <-time.After(time.Second):
		t.Fatal("failed save did not retry after the backoff")
	}
	require.NoError(t, state.flush())
	status := state.status()
	require.Equal(t, status.Revision, status.PersistedRevision)
	require.Empty(t, status.LastError)
	restored := newVaneLearningState("save-retry", clock, store, time.Hour, 16)
	restored.mu.Lock()
	metrics := restored.nodes[vaneLearningTestNodeKey("alpha")].snapshot(vaneTransportTCP, clock.Now())
	restored.mu.Unlock()
	require.True(t, metrics.connect.valid)
	require.True(t, metrics.response.valid)
}

func TestVaneLearningCASConflictPermanentlyFencesOldWriter(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneLearningTestStore()
	store.fail = cachefile.ErrVaneStateConflict
	state := newVaneLearningState("cas-fenced", clock, store, time.Hour, 16)
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, newVaneTestProxy("alpha", true, true))
	attachVaneLearningForTest(group, state, state.generation)
	group.observeConnect("alpha", vaneTransportTCP, clock.Now(), 10*time.Millisecond)
	require.ErrorContains(t, state.flush(), cachefile.ErrVaneStateConflict.Error())

	state.mu.Lock()
	require.True(t, state.writeBlocked)
	require.Zero(t, state.pending.revision)
	require.Nil(t, state.persistTimer)
	state.mu.Unlock()
	store.fail = nil
	group.observeResponse("alpha", vaneTransportTCP, clock.Now(), 20*time.Millisecond)
	require.ErrorContains(t, state.flush(), cachefile.ErrVaneStateConflict.Error())
	require.Nil(t, store.payload(state.storageKey), "a fenced writer must never rebase and overwrite the current owner")
}

func TestVaneLearningDebouncedWriterAndFlushEdgeCases(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneLearningTestStore()
	store.saved = make(chan struct{}, 1)
	state := newVaneLearningState("debounced", clock, store, time.Hour, 16)
	state.persistInterval = 5 * time.Millisecond
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, newVaneTestProxy("alpha", true, true))
	attachVaneLearningForTest(group, state, state.generation)
	group.observeConnect("alpha", vaneTransportTCP, clock.Now(), 10*time.Millisecond)
	select {
	case <-store.saved:
	case <-time.After(time.Second):
		t.Fatal("debounced writer did not persist")
	}
	require.NoError(t, state.flush())
	require.Equal(t, state.status().Revision, state.status().PersistedRevision)

	var nilState *vaneLearningState
	require.NoError(t, nilState.flush())
	require.Zero(t, nilState.status())
	disabled := newVaneLearningState("disabled", nil, nil, time.Hour, 16)
	require.NoError(t, disabled.flush())
	loadFailure := newVaneLearningState("load-failure", clock, vaneLearningLoadErrorStore{err: errors.New("load failed")}, time.Hour, 16)
	require.Contains(t, loadFailure.status().LastError, "load failed")
}

func TestVaneLearningConcurrentFirstRegistrationPublishesOneCanonicalOwner(t *testing.T) {
	const groupName = "vane-learning-concurrent-registration"
	key := vaneLearningStorageKey(groupName)
	store := &vaneLearningBlockingLoadStore{
		vaneLearningTestStore: newVaneLearningTestStore(),
		entered:               make(chan struct{}, 2),
		release:               make(chan struct{}),
	}
	vaneLearningRegistry.Lock()
	previousFactory := vaneLearningRegistry.storeFactory
	delete(vaneLearningRegistry.entries, key)
	vaneLearningRegistry.storeFactory = func() vaneLearningStore { return store }
	vaneLearningRegistry.Unlock()
	t.Cleanup(func() {
		vaneLearningRegistry.Lock()
		delete(vaneLearningRegistry.entries, key)
		vaneLearningRegistry.storeFactory = previousFactory
		vaneLearningRegistry.Unlock()
	})

	type result struct {
		state      *vaneLearningState
		generation uint64
	}
	results := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			state, generation := sharedVaneLearningState(groupName, newVaneConnTestClock(), time.Hour, 16)
			results <- result{state: state, generation: generation}
		}()
	}
	<-store.entered
	close(store.release)
	first := <-results
	second := <-results
	require.Same(t, first.state, second.state)
	require.ElementsMatch(t, []uint64{2, 3}, []uint64{first.generation, second.generation})
	first.state.mu.Lock()
	require.Equal(t, uint64(3), first.state.generation, "each concurrent publication must receive a unique monotonic generation")
	first.state.mu.Unlock()
}

// §H changed the full-registry behavior: instead of degrading the new group,
// the least-recently-accessed entry is evicted (flush-first) and the new group
// gets a real store. The registry still stays bounded; the degraded path
// survives only as the victim-flush-failure fallback (see the §H tests).
func TestVaneLearningRegistryCapacityEvictsOldestAndStaysBounded(t *testing.T) {
	store := newVaneLearningTestStore()
	vaneLearningRegistry.Lock()
	previousFactory := vaneLearningRegistry.storeFactory
	vaneLearningRegistry.storeFactory = func() vaneLearningStore { return store }
	added := make([]string, 0, vaneLearningRegistryLimit)
	for i := len(vaneLearningRegistry.entries); i < vaneLearningRegistryLimit; i++ {
		key := vaneLearningStorageKey("capacity-" + string(rune(i+1)))
		if vaneLearningRegistry.entries[key] == nil {
			vaneLearningRegistry.entries[key] = newVaneLearningState("capacity", newVaneConnTestClock(), nil, time.Hour, 1)
			added = append(added, key)
		}
	}
	vaneLearningRegistry.Unlock()
	t.Cleanup(func() {
		vaneLearningRegistry.Lock()
		for _, key := range added {
			delete(vaneLearningRegistry.entries, key)
		}
		vaneLearningRegistry.storeFactory = previousFactory
		vaneLearningRegistry.Unlock()
	})

	state, _ := sharedVaneLearningState("capacity-overflow", newVaneConnTestClock(), time.Hour, 1)
	require.NotNil(t, state.store, "a full registry must evict, not degrade the new group")
	vaneLearningRegistry.Lock()
	require.LessOrEqual(t, len(vaneLearningRegistry.entries), vaneLearningRegistryLimit)
	vaneLearningRegistry.Unlock()
}

func TestFlushVaneLearningStatesDrainsAllAndAggregatesFailure(t *testing.T) {
	clock := newVaneConnTestClock()
	goodStore := newVaneLearningTestStore()
	badStore := newVaneLearningTestStore()
	badStore.fail = errors.New("global flush failed")
	good := newVaneLearningState("global-good", clock, goodStore, time.Hour, 16)
	bad := newVaneLearningState("global-bad", clock, badStore, time.Hour, 16)
	for _, state := range []*vaneLearningState{good, bad} {
		state.mu.Lock()
		node := &vaneNodeState{name: "alpha", identity: "test:alpha", lastObservedAt: clock.Now()}
		node.tcp.observeConnect(clock.Now(), 10*time.Millisecond)
		state.nodes[vaneLearningTestNodeKey("alpha")] = node
		state.markDirtyLocked(clock.Now())
		state.mu.Unlock()
	}

	vaneLearningRegistry.Lock()
	previousEntries := vaneLearningRegistry.entries
	vaneLearningRegistry.entries = map[string]*vaneLearningState{"good": good, "bad": bad}
	vaneLearningRegistry.Unlock()
	t.Cleanup(func() {
		vaneLearningRegistry.Lock()
		vaneLearningRegistry.entries = previousEntries
		vaneLearningRegistry.Unlock()
		bad.mu.Lock()
		if bad.persistTimer != nil {
			bad.persistTimer.Stop()
			bad.persistTimer = nil
		}
		bad.store = nil
		bad.mu.Unlock()
	})

	require.ErrorContains(t, FlushVaneLearningStates(), "global flush failed")
	require.NotEmpty(t, goodStore.payload(good.storageKey))
}
