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

type sageLearningTestStore struct {
	mu     sync.Mutex
	data   map[string][]byte
	writes int
	fail   error
	saved  chan struct{}
}

func newSageLearningTestStore() *sageLearningTestStore {
	return &sageLearningTestStore{data: make(map[string][]byte)}
}

func sageLearningTestNodeKey(name string) string {
	return sageLearningNodeKey(name, "test:"+name)
}

func (s *sageLearningTestStore) Load(key string) ([]byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	payload := append([]byte(nil), s.data[key]...)
	if payload == nil {
		return nil, nil, nil
	}
	digest := sha256.Sum256(payload)
	return payload, append([]byte(nil), digest[:]...), nil
}

func (s *sageLearningTestStore) Save(key string, expectedToken, payload []byte) ([]byte, error) {
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
		return nil, cachefile.ErrSageStateConflict
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

type sageLearningLoadErrorStore struct{ err error }

func (s sageLearningLoadErrorStore) Load(string) ([]byte, []byte, error) {
	return nil, nil, s.err
}
func (s sageLearningLoadErrorStore) Save(string, []byte, []byte) ([]byte, error) {
	return nil, nil
}

type sageLearningOversizedStore struct {
	token []byte
	saved []byte
}

func (s *sageLearningOversizedStore) Load(string) ([]byte, []byte, error) {
	return nil, append([]byte(nil), s.token...), fmt.Errorf("%w: seeded legacy row", cachefile.ErrSageStatePayloadTooLarge)
}

func (s *sageLearningOversizedStore) Save(_ string, expectedToken, payload []byte) ([]byte, error) {
	if !bytes.Equal(expectedToken, s.token) {
		return nil, cachefile.ErrSageStateConflict
	}
	s.saved = append([]byte(nil), payload...)
	s.token = []byte("next-token")
	return append([]byte(nil), s.token...), nil
}

type sageLearningBlockingLoadStore struct {
	*sageLearningTestStore
	entered chan struct{}
	release chan struct{}
}

func (s *sageLearningBlockingLoadStore) Load(key string) ([]byte, []byte, error) {
	s.entered <- struct{}{}
	<-s.release
	return s.sageLearningTestStore.Load(key)
}

func (s *sageLearningTestStore) payload(key string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.data[key]...)
}

type sageLearningBlockingStore struct {
	*sageLearningTestStore
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func newSageLearningBlockingStore() *sageLearningBlockingStore {
	return &sageLearningBlockingStore{
		sageLearningTestStore: newSageLearningTestStore(),
		entered:               make(chan struct{}),
		release:               make(chan struct{}),
	}
}

func (s *sageLearningBlockingStore) Save(key string, expectedToken, payload []byte) ([]byte, error) {
	s.once.Do(func() {
		close(s.entered)
		<-s.release
	})
	return s.sageLearningTestStore.Save(key, expectedToken, payload)
}

func attachSageLearningForTest(group *Sage, state *sageLearningState, generation uint64) {
	group.attachLearningState(state, generation)
}

func useSageLearningRegistryStoreForTest(t *testing.T, group string, store sageLearningStore) {
	t.Helper()
	key := sageLearningStorageKey(group)
	sageLearningRegistry.Lock()
	previousFactory := sageLearningRegistry.storeFactory
	delete(sageLearningRegistry.entries, key)
	sageLearningRegistry.storeFactory = func() sageLearningStore { return store }
	sageLearningRegistry.Unlock()
	t.Cleanup(func() {
		sageLearningRegistry.Lock()
		state := sageLearningRegistry.entries[key]
		delete(sageLearningRegistry.entries, key)
		sageLearningRegistry.storeFactory = previousFactory
		sageLearningRegistry.Unlock()
		if state != nil {
			_ = state.flush()
		}
	})
}

func TestSageLearningProxyIdentityScopesSameNameEvidence(t *testing.T) {
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

	firstIdentity := sageProxyPersistentIdentity(firstProxy)
	require.NotEmpty(t, firstIdentity)
	require.Equal(t, firstIdentity, sageProxyPersistentIdentity(sameProxy))
	require.NotEqual(t, firstIdentity, sageProxyPersistentIdentity(replacedProxy))
	require.NotEqual(t, firstIdentity, sageProxyPersistentIdentity(otherProviderProxy))

	clock := newSageConnTestClock()
	store := newSageLearningTestStore()
	owner := newSageLearningState("identity-scope", clock, store, time.Hour, 16)
	firstGroup, _ := newSageGroupForTest(clock, 16, time.Hour, firstProxy)
	attachSageLearningForTest(firstGroup, owner, owner.generation)
	firstGroup.observeConnect("alpha", sageTransportTCP, clock.Now(), 25*time.Millisecond)
	require.NoError(t, owner.flush())
	persistedPayload := string(store.payload(owner.storageKey))
	require.NotContains(t, persistedPayload, "sensitive-user")
	require.NotContains(t, persistedPayload, "sensitive-password")

	restoredSame := newSageLearningState("identity-scope", clock, store, time.Hour, 16)
	sameGroup, _ := newSageGroupForTest(clock, 16, time.Hour, sameProxy)
	attachSageLearningForTest(sameGroup, restoredSame, restoredSame.generation)
	require.Equal(t, "alpha", sameGroup.pick(nil, sageTransportTCP, false, true).Name())
	sameGroup.mu.Lock()
	sameSnapshot := sameGroup.nodes["alpha"].snapshot(sageTransportTCP, clock.Now())
	sameGroup.mu.Unlock()
	require.True(t, sameSnapshot.connect.valid, "unchanged normalized identity must restore evidence")

	restoredChanged := newSageLearningState("identity-scope", clock, store, time.Hour, 16)
	changedGroup, _ := newSageGroupForTest(clock, 16, time.Hour, replacedProxy)
	attachSageLearningForTest(changedGroup, restoredChanged, restoredChanged.generation)
	require.Equal(t, "alpha", changedGroup.pick(nil, sageTransportTCP, false, true).Name())
	changedGroup.mu.Lock()
	changedSnapshot := changedGroup.nodes["alpha"].snapshot(sageTransportTCP, clock.Now())
	changedGroup.mu.Unlock()
	require.False(t, changedSnapshot.connect.valid, "same-named replacement must start cold")
}

func TestSageLearningInstanceScopedCandidateIsNotPersisted(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageLearningTestStore()
	proxy := A.NewProxy(newSageTestProxy("anonymous", true, true).Adapter())
	replacement := A.NewProxy(newSageTestProxy("anonymous", true, true).Adapter())
	require.NotEqual(t, sageProxyPersistentIdentity(proxy), sageProxyPersistentIdentity(replacement))
	require.False(t, sageIdentityIsPersistent(sageProxyPersistentIdentity(proxy)))
	owner := newSageLearningState("unidentifiable", clock, store, time.Hour, 16)
	group, _ := newSageGroupForTest(clock, 16, time.Hour, proxy)
	attachSageLearningForTest(group, owner, owner.generation)
	group.observeConnect("anonymous", sageTransportTCP, clock.Now(), 20*time.Millisecond)
	require.NoError(t, owner.flush())
	var snapshot sageLearningSnapshot
	require.NoError(t, json.Unmarshal(store.payload(owner.storageKey), &snapshot))
	require.Empty(t, snapshot.Nodes)
}

func TestSageLearningLateCallbackCannotContaminateSameNameReplacement(t *testing.T) {
	clock := newSageConnTestClock()
	oldProxy := newSageTestProxy("alpha", true, true)
	oldProxy.identity = "identity-old"
	newProxy := newSageTestProxy("alpha", true, true)
	newProxy.identity = "identity-new"
	owner := newSageLearningState("identity-callback", clock, newSageLearningTestStore(), time.Hour, 16)
	group, provider := newSageGroupForTest(clock, 16, time.Hour, oldProxy)
	attachSageLearningForTest(group, owner, owner.generation)
	require.Equal(t, "alpha", group.pick(nil, sageTransportTCP, false, true).Name())
	oldIdentity := sageProxyPersistentIdentity(oldProxy)

	provider.setProxies(newProxy)
	require.Equal(t, "alpha", group.pick(nil, sageTransportTCP, false, true).Name())
	group.observeThroughputIdentity("alpha", oldIdentity, sageTransportTCP, clock.Now(), 9_000_000)

	group.mu.Lock()
	current := group.nodes["alpha"]
	currentControl := group.nodeControls["alpha"]
	group.mu.Unlock()
	require.Equal(t, "identity-new", current.identity)
	require.False(t, current.snapshot(sageTransportTCP, clock.Now()).throughput.valid)
	require.Zero(t, currentControl.recentTCPThroughput, "late old-identity callback must not recreate control evidence")
	owner.mu.Lock()
	oldState := owner.nodes[sageLearningNodeKey("alpha", "identity-old")]
	owner.mu.Unlock()
	require.True(t, oldState.snapshot(sageTransportTCP, clock.Now()).throughput.valid, "late sample remains attributed to its original durable identity")
}

func TestSageLearningRestoredMaxRevisionStartsFreshWriterSequence(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageLearningTestStore()
	groupName := "max-revision"
	key := sageLearningStorageKey(groupName)
	payload, err := json.Marshal(sageLearningSnapshot{
		SchemaVersion: SageLearningSchemaVersion,
		Group:         groupName,
		Revision:      math.MaxUint64,
		UpdatedAt:     clock.Now().UTC(),
	})
	require.NoError(t, err)
	store.data[key] = payload
	state := newSageLearningState(groupName, clock, store, time.Hour, 16)
	require.Zero(t, state.revision)
	group, _ := newSageGroupForTest(clock, 16, time.Hour, newSageTestProxy("alpha", true, true))
	attachSageLearningForTest(group, state, state.generation)
	group.observeConnect("alpha", sageTransportTCP, clock.Now(), 10*time.Millisecond)
	require.NoError(t, state.flush())
	require.Equal(t, 1, store.writes)
	require.Equal(t, uint64(1), state.status().PersistedRevision)
}

func TestSageLearningProductionConstructorReloadAndFreshProcessRestore(t *testing.T) {
	const groupName = "sage-learning-production-restart"
	store := newSageLearningTestStore()
	useSageLearningRegistryStoreForTest(t, groupName, store)
	fallback := newSageTestProxy("fallback", true, false)
	alpha := newSageTestProxy("alpha", true, true)
	provider := newSageTestProvider(alpha)

	first, err := NewSage(GroupCommonOption{Name: groupName, URL: C.DefaultTestURL}, SageOption{}, fallback, []P.ProxyProvider{provider})
	require.NoError(t, err)
	ActivateSageLearningStates(map[string]C.Proxy{groupName: A.NewProxy(first)})
	first.observeConnect("alpha", sageTransportTCP, first.clock.Now(), 25*time.Millisecond)
	first.observeResponse("alpha", sageTransportTCP, first.clock.Now(), 50*time.Millisecond)
	first.mu.Lock()
	first.anchors[sageAnchorKey{transport: sageTransportTCP, scene: sageSceneDefault}] = sageAnchor{name: "alpha"}
	first.cooldowns[sageCooldownKey{transport: sageTransportTCP, candidate: "alpha"}] = first.clock.Now().Add(time.Hour)
	first.mu.Unlock()
	first.mu.Lock()
	first.ensureNodeControlLocked("alpha", first.clock.Now()).lastExplored[0] = 42
	first.mu.Unlock()
	require.NoError(t, first.learning.flush())

	key := sageLearningStorageKey(groupName)
	sageLearningRegistry.Lock()
	delete(sageLearningRegistry.entries, key)
	sageLearningRegistry.Unlock()

	second, err := NewSage(GroupCommonOption{Name: groupName, URL: C.DefaultTestURL}, SageOption{}, fallback, []P.ProxyProvider{provider})
	require.NoError(t, err)
	ActivateSageLearningStates(map[string]C.Proxy{groupName: A.NewProxy(second)})
	require.Equal(t, 1, second.learning.status().RestoredNodes)
	second.mu.Lock()
	second.learning.mu.Lock()
	second.nodes["alpha"] = second.learning.nodes[sageLearningTestNodeKey("alpha")]
	snapshot := second.nodes["alpha"].snapshot(sageTransportTCP, second.clock.Now())
	require.Empty(t, second.nodeControls)
	second.learning.mu.Unlock()
	second.mu.Unlock()
	require.True(t, snapshot.connect.valid)
	require.True(t, snapshot.response.valid)
	require.Empty(t, second.anchors)
	require.Empty(t, second.cooldowns)
}

func TestSageLearningProductionReloadSharesCanonicalOwner(t *testing.T) {
	const groupName = "sage-learning-production-reload"
	store := newSageLearningTestStore()
	useSageLearningRegistryStoreForTest(t, groupName, store)
	fallback := newSageTestProxy("fallback", true, false)
	alpha := newSageTestProxy("alpha", true, true)
	beta := newSageTestProxy("beta", true, true)
	provider := newSageTestProvider(alpha, beta)

	oldGroup, err := NewSage(GroupCommonOption{Name: groupName, URL: C.DefaultTestURL}, SageOption{}, fallback, []P.ProxyProvider{provider})
	require.NoError(t, err)
	ActivateSageLearningStates(map[string]C.Proxy{groupName: A.NewProxy(oldGroup)})
	oldGroup.observeConnect("beta", sageTransportTCP, oldGroup.clock.Now(), 100*time.Millisecond)
	oldGroup.mu.Lock()
	oldGroup.ensureNodeControlLocked("beta", oldGroup.clock.Now()).lastExplored[0] = 9
	oldGroup.mu.Unlock()

	newGroup, err := NewSage(GroupCommonOption{Name: groupName, URL: C.DefaultTestURL}, SageOption{}, fallback, []P.ProxyProvider{provider})
	require.NoError(t, err)
	require.NotSame(t, oldGroup.learning, newGroup.learning, "parse must remain dormant")
	oldGroup.mu.Lock()
	oldGroup.learning.mu.Lock()
	require.Equal(t, oldGroup.learningGeneration, oldGroup.learning.generation, "construction alone must not retire the live generation")
	require.Equal(t, uint64(9), oldGroup.nodeControls["beta"].lastExplored[0], "failed parse must not reset live control state")
	oldGroup.learning.mu.Unlock()
	oldGroup.mu.Unlock()
	ActivateSageLearningStates(map[string]C.Proxy{groupName: A.NewProxy(newGroup)})
	require.Same(t, oldGroup.learning, newGroup.learning)
	require.Less(t, oldGroup.learningGeneration, newGroup.learningGeneration)
	require.Empty(t, newGroup.nodeControls)

	oldGroup.observeResponse("beta", sageTransportTCP, oldGroup.clock.Now(), 55*time.Millisecond)
	oldGroup.observeThroughput("beta", sageTransportTCP, oldGroup.clock.Now(), 2_000_000)
	require.Empty(t, newGroup.nodeControls, "late old-generation callbacks must not repopulate new-generation control state")
	newGroup.mu.Lock()
	newGroup.learning.mu.Lock()
	newGroup.nodes["beta"] = newGroup.learning.nodes[sageLearningTestNodeKey("beta")]
	snapshot := newGroup.nodes["beta"].snapshot(sageTransportTCP, newGroup.clock.Now())
	newGroup.learning.mu.Unlock()
	newGroup.mu.Unlock()
	require.True(t, snapshot.connect.valid)
	require.True(t, snapshot.response.valid)
	require.True(t, snapshot.throughput.valid)

	oldGroup.learning.mu.Lock()
	oldGroup.nodes["beta"].lastObservedAt = oldGroup.clock.Now().Add(-2 * sageDefaultStateTTL)
	oldGroup.pruneLocked(oldGroup.clock.Now(), []C.Proxy{alpha})
	_, survived := oldGroup.nodes["beta"]
	oldGroup.learning.mu.Unlock()
	require.True(t, survived, "stale reload generation must not prune canonical state")
}

func TestSageCloseDoesNotDrainSharedLearningOwner(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageLearningTestStore()
	owner := newSageLearningState("close-is-retire-only", clock, store, time.Hour, 16)
	owner.persistInterval = time.Hour
	group, _ := newSageGroupForTest(clock, 16, time.Hour, newSageTestProxy("alpha", true, true))
	attachSageLearningForTest(group, owner, owner.generation)
	group.observeConnect("alpha", sageTransportTCP, clock.Now(), 20*time.Millisecond)
	require.NoError(t, group.Close())
	require.Nil(t, store.payload(owner.storageKey), "closing a reload generation must not drain the shared owner")
	require.NoError(t, owner.flush())
	require.NotNil(t, store.payload(owner.storageKey))
}

func TestSageLearningOverlappingReloadsUsePublicationOrderGenerations(t *testing.T) {
	const groupName = "sage-learning-overlapping-reloads"
	store := newSageLearningTestStore()
	useSageLearningRegistryStoreForTest(t, groupName, store)
	fallback := newSageTestProxy("fallback", true, false)
	alpha := newSageTestProxy("alpha", true, true)
	beta := newSageTestProxy("beta", true, true)
	provider := newSageTestProvider(alpha, beta)

	live, err := NewSage(GroupCommonOption{Name: groupName, URL: C.DefaultTestURL}, SageOption{}, fallback, []P.ProxyProvider{provider})
	require.NoError(t, err)
	ActivateSageLearningStates(map[string]C.Proxy{groupName: A.NewProxy(live)})
	live.observeConnect("beta", sageTransportTCP, live.clock.Now(), 50*time.Millisecond)

	first, err := NewSage(GroupCommonOption{Name: groupName, URL: C.DefaultTestURL}, SageOption{}, fallback, []P.ProxyProvider{provider})
	require.NoError(t, err)
	second, err := NewSage(GroupCommonOption{Name: groupName, URL: C.DefaultTestURL}, SageOption{}, fallback, []P.ProxyProvider{provider})
	require.NoError(t, err)
	require.Equal(t, first.learningGeneration, second.learningGeneration, "parse must not reserve publication generations")
	require.Equal(t, live.learningGeneration, live.learning.generation, "parsing must not advance the active generation")

	ActivateSageLearningStates(map[string]C.Proxy{groupName: A.NewProxy(second)})
	require.Equal(t, second.learningGeneration, second.learning.generation)
	ActivateSageLearningStates(map[string]C.Proxy{groupName: A.NewProxy(first)})
	require.Equal(t, first.learningGeneration, first.learning.generation)
	require.Greater(t, first.learningGeneration, second.learningGeneration, "last publication must own the newest generation even when parse order is reversed")

	second.mu.Lock()
	second.learning.mu.Lock()
	second.learning.nodes[sageLearningTestNodeKey("beta")].lastObservedAt = second.clock.Now().Add(-2 * sageDefaultStateTTL)
	second.pruneLocked(second.clock.Now(), []C.Proxy{alpha})
	_, survived := second.learning.nodes[sageLearningTestNodeKey("beta")]
	second.learning.mu.Unlock()
	second.mu.Unlock()
	require.True(t, survived, "the earlier published group must become stale after the later publication")
}

func TestSageLearningRestartRestoresOnlyMetricEvidenceAndChangesRanking(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageLearningTestStore()
	alpha := newSageTestProxy("alpha", true, true)
	beta := newSageTestProxy("beta", true, true)
	first, _ := newSageGroupForTest(clock, 16, time.Hour, alpha, beta)
	state := newSageLearningState("restart-ranking", clock, store, time.Hour, 16)
	attachSageLearningForTest(first, state, state.generation)

	for i := 0; i < 8; i++ {
		first.recordDialSuccess(nil, sageTransportTCP, "alpha", first.nodeIdentity("alpha"), clock.Now())
		first.observeConnect("alpha", sageTransportTCP, clock.Now(), 900*time.Millisecond)
		first.observeResponse("alpha", sageTransportTCP, clock.Now(), 2*time.Second)
		first.observeThroughput("alpha", sageTransportTCP, clock.Now(), 100_000)
		first.recordDialSuccess(nil, sageTransportTCP, "beta", first.nodeIdentity("beta"), clock.Now())
		first.observeConnect("beta", sageTransportTCP, clock.Now(), 20*time.Millisecond)
		first.observeResponse("beta", sageTransportTCP, clock.Now(), 40*time.Millisecond)
		first.observeThroughput("beta", sageTransportTCP, clock.Now(), 8_000_000)
		first.recordDialSuccess(nil, sageTransportUDP, "beta", first.nodeIdentity("beta"), clock.Now())
		first.observeConnect("beta", sageTransportUDP, clock.Now(), 10*time.Millisecond)
	}
	first.mu.Lock()
	first.anchors[sageAnchorKey{transport: sageTransportTCP, scene: sageSceneDefault}] = sageAnchor{name: "alpha", scoreMicros: 1}
	first.cooldowns[sageCooldownKey{transport: sageTransportTCP, target: "example.com", port: 443, candidate: "beta"}] = clock.Now().Add(time.Hour)
	first.mu.Unlock()
	first.mu.Lock()
	first.ensureNodeControlLocked("beta", clock.Now()).lastExplored[0] = 99
	require.NotZero(t, first.nodeControls["beta"].recentTCPThroughput.bitsPerSecond)
	first.mu.Unlock()

	require.NoError(t, state.flush())
	clock.Advance(5 * time.Minute)
	state.mu.Lock()
	expectedTCP := state.nodes[sageLearningTestNodeKey("beta")].snapshot(sageTransportTCP, clock.Now())
	state.mu.Unlock()
	restored := newSageLearningState("restart-ranking", clock, store, time.Hour, 16)
	status := restored.status()
	require.True(t, status.Available)
	require.Equal(t, 2, status.RestoredNodes)
	require.Empty(t, status.LastError)

	restored.mu.Lock()
	betaState := restored.nodes[sageLearningTestNodeKey("beta")]
	require.NotNil(t, betaState)
	tcp := betaState.snapshot(sageTransportTCP, clock.Now())
	udp := betaState.snapshot(sageTransportUDP, clock.Now())
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

	second, _ := newSageGroupForTest(clock, 16, time.Hour, alpha, beta)
	attachSageLearningForTest(second, restored, restored.generation)
	require.Empty(t, second.anchors)
	require.Empty(t, second.cooldowns)
	require.Empty(t, second.nodeControls)
	require.Empty(t, second.mediaHints)
	require.Empty(t, second.mediaReconnects)
	require.Empty(t, second.mediaSlowCooldowns)
	require.Empty(t, second.mediaBudgets)
	require.Empty(t, second.churn)
	require.Zero(t, second.explorationOrdinal)
	require.Zero(t, second.explorationScopes)
	require.Equal(t, "beta", second.pick(nil, sageTransportTCP, false, true).Name())
}

func TestSageLearningReadOnlyAPIsDoNotMutateOrSchedulePersistence(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageLearningTestStore()
	alpha := newSageTestProxy("alpha", true, true)
	group, provider := newSageGroupForTest(clock, 16, time.Hour, alpha)
	state := newSageLearningState("read-only", clock, store, time.Hour, 16)
	attachSageLearningForTest(group, state, state.generation)
	group.observeConnect("alpha", sageTransportTCP, clock.Now(), 15*time.Millisecond)
	require.NoError(t, state.flush())

	state.mu.Lock()
	revision := state.revision
	processed := state.processedRevision
	pending := state.pending.revision
	lastSeen := state.nodes[sageLearningTestNodeKey("alpha")].lastObservedAt
	state.mu.Unlock()
	replacement := newSageTestProxy("alpha", true, true)
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
	require.Equal(t, lastSeen, state.nodes[sageLearningTestNodeKey("alpha")].lastObservedAt)
	require.Equal(t, sageProxyPersistentIdentity(alpha), group.nodeIdentities["alpha"], "read-only selection must not bind a replacement identity")
}

func TestSageLearningUnknownAndCorruptPayloadAreNonFatalAndObservable(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageLearningTestStore()
	key := sageLearningStorageKey("corrupt")
	store.data[key] = []byte(`{"schemaVersion":999,"group":"corrupt","updatedAt":"2026-11-14T00:00:00Z"}`)

	unknownPayload := append([]byte(nil), store.data[key]...)
	state := newSageLearningState("corrupt", clock, store, time.Hour, 16)
	require.Empty(t, state.nodes)
	require.Contains(t, state.status().LastError, "unsupported node-state schema")
	unknownGroup, _ := newSageGroupForTest(clock, 16, time.Hour, newSageTestProxy("alpha", true, true))
	attachSageLearningForTest(unknownGroup, state, state.generation)
	unknownGroup.observeConnect("alpha", sageTransportTCP, clock.Now(), 10*time.Millisecond)
	require.ErrorContains(t, state.flush(), "unsupported node-state schema")
	require.Equal(t, unknownPayload, store.payload(key), "an older writer must not downgrade an unknown newer schema")

	store.data[key] = []byte(`{"schemaVersion":1`)
	state = newSageLearningState("corrupt", clock, store, time.Hour, 16)
	require.Empty(t, state.nodes)
	require.Contains(t, state.status().LastError, "decode node state")

	now := clock.Now()
	partial := sageLearningSnapshot{
		SchemaVersion: SageLearningSchemaVersion,
		Group:         "corrupt",
		UpdatedAt:     now,
		Nodes: []sagePersistedNode{
			{Name: "good", Identity: "test:good", LastSeen: now, TCP: sagePersistedMetrics{Connect: sagePersistedDualMetric{Fast: sagePersistedDecayLayer{Weight: 1, Sum: 1, UpdatedAt: now, Valid: true}}}},
			{Name: "bad", Identity: "test:bad", LastSeen: now, TCP: sagePersistedMetrics{Connect: sagePersistedDualMetric{Fast: sagePersistedDecayLayer{Weight: -1, Sum: 1, UpdatedAt: now, Valid: true}}}},
		},
	}
	partialPayload, err := json.Marshal(partial)
	require.NoError(t, err)
	store.data[key] = partialPayload
	state = newSageLearningState("corrupt", clock, store, time.Hour, 16)
	require.Contains(t, state.nodes, sageLearningTestNodeKey("good"))
	require.NotContains(t, state.nodes, sageLearningTestNodeKey("bad"))
	require.Contains(t, state.status().LastError, "invalid entries")

	group, _ := newSageGroupForTest(clock, 16, time.Hour, newSageTestProxy("alpha", true, true))
	attachSageLearningForTest(group, state, state.generation)
	group.observeConnect("alpha", sageTransportTCP, clock.Now(), 25*time.Millisecond)
	require.NoError(t, state.flush())
	require.Empty(t, state.status().LastError)

	var snapshot sageLearningSnapshot
	require.NoError(t, json.Unmarshal(store.payload(key), &snapshot))
	require.Equal(t, SageLearningSchemaVersion, snapshot.SchemaVersion)
	require.Len(t, snapshot.Nodes, 2)
}

func TestSageLearningRestoreDefersDeterministicBoundUntilMembershipIsKnown(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageLearningTestStore()
	now := clock.Now()
	valid := sagePersistedMetrics{Connect: sagePersistedDualMetric{Fast: sagePersistedDecayLayer{
		Weight: 1, Sum: 1, UpdatedAt: now, Valid: true,
	}}}
	snapshot := sageLearningSnapshot{
		SchemaVersion: SageLearningSchemaVersion,
		Group:         "bounded",
		UpdatedAt:     now,
		Nodes: []sagePersistedNode{
			{Name: "old-a", Identity: "test:old-a", LastSeen: now.Add(-3 * time.Hour), TCP: valid},
			{Name: "old-b", Identity: "test:old-b", LastSeen: now.Add(-3 * time.Hour), TCP: valid},
			{Name: "middle", Identity: "test:middle", LastSeen: now.Add(-2 * time.Hour), TCP: valid},
			{Name: "new-a", Identity: "test:new-a", LastSeen: now.Add(-time.Hour), TCP: valid},
			{Name: "new-b", Identity: "test:new-b", LastSeen: now.Add(-time.Hour), TCP: valid},
		},
	}
	payload, err := json.Marshal(snapshot)
	require.NoError(t, err)
	store.data[sageLearningStorageKey("bounded")] = payload

	state := newSageLearningState("bounded", clock, store, 24*time.Hour, 3)
	state.mu.Lock()
	require.Len(t, state.nodes, 5, "restore must not discard records before providers expose current membership")
	state.mu.Unlock()

	newA := newSageTestProxy("new-a", true, true)
	newB := newSageTestProxy("new-b", true, true)
	group, _ := newSageGroupForTest(clock, 3, 24*time.Hour, newA, newB)
	attachSageLearningForTest(group, state, state.generation)
	group.mu.Lock()
	state.mu.Lock()
	group.pruneLocked(clock.Now(), []C.Proxy{newA, newB})
	require.Len(t, state.nodes, 3)
	require.NotContains(t, state.nodes, sageLearningTestNodeKey("old-a"))
	require.NotContains(t, state.nodes, sageLearningTestNodeKey("old-b"))
	require.Contains(t, state.nodes, sageLearningTestNodeKey("middle"))
	require.Contains(t, state.nodes, sageLearningTestNodeKey("new-a"))
	require.Contains(t, state.nodes, sageLearningTestNodeKey("new-b"))
	state.mu.Unlock()
	group.mu.Unlock()
}

func TestSageLearningDefaultMaximumSnapshotFitsCachePayload(t *testing.T) {
	clock := newSageConnTestClock()
	state := newSageLearningState("payload-bound", clock, nil, time.Hour, sageDefaultMaxStates)
	now := clock.Now()
	layer := sageDecayLayer{weight: 10, sum: 100, updatedAt: now, valid: true}
	metric := sageDualMetric{fast: layer, slow: layer}
	metrics := sageMetrics{failure: metric, connect: metric, response: metric, throughput: metric}
	state.mu.Lock()
	for i := 0; i < sageDefaultMaxStates; i++ {
		name := string(rune(i + 1))
		identity := "test:" + name
		state.nodes[sageLearningNodeKey(name, identity)] = &sageNodeState{name: name, identity: identity, tcp: metrics, udp: metrics, lastObservedAt: now}
	}
	payload, err := json.Marshal(state.snapshotLocked(now))
	state.mu.Unlock()
	require.NoError(t, err)
	require.LessOrEqual(t, len(payload), 2*1024*1024)
}

func TestSageLearningMarshalDeterministicallyTrimsOversizedPayload(t *testing.T) {
	now := time.Now().UTC()
	snapshot := sageLearningSnapshot{
		SchemaVersion: SageLearningSchemaVersion,
		Group:         "payload-byte-bound",
		Revision:      7,
		UpdatedAt:     now,
		Nodes:         make([]sagePersistedNode, 512),
	}
	for i := range snapshot.Nodes {
		snapshot.Nodes[i] = sagePersistedNode{
			Name:     fmt.Sprintf("%04d-%s", i, strings.Repeat("n", 4096)),
			Identity: strings.Repeat("i", 4096),
			LastSeen: now.Add(-time.Duration(i) * time.Second),
		}
	}
	payload, err := marshalSageLearningSnapshot(snapshot)
	require.NoError(t, err)
	require.LessOrEqual(t, len(payload), sageLearningPayloadLimit)
	var trimmed sageLearningSnapshot
	require.NoError(t, json.Unmarshal(payload, &trimmed))
	require.NotEmpty(t, trimmed.Nodes)
	require.Less(t, len(trimmed.Nodes), len(snapshot.Nodes))
	require.Equal(t, snapshot.Nodes[:len(trimmed.Nodes)], trimmed.Nodes, "byte trimming must retain the deterministic newest prefix")
}

func TestSageLearningRemovedNodeHonorsTTLAndDoesNotResurrect(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageLearningTestStore()
	alpha := newSageTestProxy("alpha", true, true)
	beta := newSageTestProxy("beta", true, true)
	owner := newSageLearningState("remove-readd", clock, store, time.Hour, 16)
	group, provider := newSageGroupForTest(clock, 16, time.Hour, alpha, beta)
	attachSageLearningForTest(group, owner, owner.generation)
	group.observeConnect("alpha", sageTransportTCP, clock.Now(), 25*time.Millisecond)

	clock.Advance(30 * time.Minute)
	provider.setProxies(beta)
	group.pick(nil, sageTransportTCP, false, true)
	owner.mu.Lock()
	require.Contains(t, owner.nodes, sageLearningTestNodeKey("alpha"), "removed node must survive before state TTL")
	owner.mu.Unlock()

	provider.setProxies(alpha, beta)
	group.pick(nil, sageTransportTCP, false, true)
	owner.mu.Lock()
	require.True(t, owner.nodes[sageLearningTestNodeKey("alpha")].snapshot(sageTransportTCP, clock.Now()).connect.valid)
	owner.mu.Unlock()

	clock.Advance(2 * time.Hour)
	provider.setProxies(beta)
	group.pick(nil, sageTransportTCP, false, true)
	owner.mu.Lock()
	require.NotContains(t, owner.nodes, sageLearningTestNodeKey("alpha"))
	owner.mu.Unlock()
	require.NoError(t, owner.flush())

	restored := newSageLearningState("remove-readd", clock, store, time.Hour, 16)
	restored.mu.Lock()
	require.NotContains(t, restored.nodes, sageLearningTestNodeKey("alpha"), "expired deletion must be durable")
	restored.mu.Unlock()

	provider.setProxies(alpha, beta)
	readded, _ := newSageGroupForTest(clock, 16, time.Hour, alpha, beta)
	attachSageLearningForTest(readded, restored, restored.generation)
	require.Equal(t, "alpha", readded.pick(nil, sageTransportTCP, false, true).Name())
	restored.mu.Lock()
	cold := restored.nodes[sageLearningTestNodeKey("alpha")].snapshot(sageTransportTCP, clock.Now())
	restored.mu.Unlock()
	require.False(t, cold.connect.valid, "re-adding after TTL and durable prune must create a cold node")
}

func TestSageLearningReaddAfterSilentTTLStartsCold(t *testing.T) {
	clock := newSageConnTestClock()
	alpha := newSageTestProxy("alpha", true, true)
	beta := newSageTestProxy("beta", true, true)
	owner := newSageLearningState("silent-readd", clock, newSageLearningTestStore(), time.Hour, 16)
	group, provider := newSageGroupForTest(clock, 16, time.Hour, alpha, beta)
	attachSageLearningForTest(group, owner, owner.generation)
	group.observeConnect("alpha", sageTransportTCP, clock.Now(), 25*time.Millisecond)

	provider.setProxies(beta)
	group.pick(nil, sageTransportTCP, false, true)
	clock.Advance(2 * time.Hour) // no selector runs while alpha remains absent
	provider.setProxies(alpha)
	group.pick(nil, sageTransportTCP, false, true)

	owner.mu.Lock()
	snapshot := owner.nodes[sageLearningTestNodeKey("alpha")].snapshot(sageTransportTCP, clock.Now())
	owner.mu.Unlock()
	require.False(t, snapshot.connect.valid, "readd must expire old evidence before refreshing membership freshness")
}

func TestSageLearningExpiredFlowCallbackCannotResurrectNode(t *testing.T) {
	clock := newSageConnTestClock()
	alpha := newSageTestProxy("alpha", true, true)
	beta := newSageTestProxy("beta", true, true)
	owner := newSageLearningState("late-expired-flow", clock, newSageLearningTestStore(), time.Hour, 16)
	group, provider := newSageGroupForTest(clock, 16, time.Hour, alpha, beta)
	attachSageLearningForTest(group, owner, owner.generation)
	decision := group.pickDecision(nil, sageTransportTCP, false, true)
	require.Equal(t, "alpha", decision.proxy.Name())
	group.observeConnectEpochIdentity("alpha", decision.identity, decision.nodeEpoch, sageTransportTCP, clock.Now(), 25*time.Millisecond)

	provider.setProxies(beta)
	clock.Advance(2 * time.Hour)
	group.pick(nil, sageTransportTCP, false, true)
	owner.mu.Lock()
	require.NotContains(t, owner.nodes, sageLearningTestNodeKey("alpha"))
	owner.mu.Unlock()

	group.observeResponseEpochIdentity("alpha", decision.identity, decision.nodeEpoch, sageTransportTCP, clock.Now(), 50*time.Millisecond)
	owner.mu.Lock()
	require.NotContains(t, owner.nodes, sageLearningTestNodeKey("alpha"), "callback from the deleted incarnation must remain fenced")
	owner.mu.Unlock()
}

func TestSageLearningBlockedSaveDoesNotBlockObservationsAndFlushKeepsNewestRevision(t *testing.T) {
	clock := newSageConnTestClock()
	store := &sageLearningBlockingStore{
		sageLearningTestStore: newSageLearningTestStore(),
		entered:               make(chan struct{}),
		release:               make(chan struct{}),
	}
	state := newSageLearningState("blocked", clock, store, time.Hour, 16)
	state.persistInterval = time.Nanosecond
	state.lastScheduled = clock.Now().Add(-time.Second)
	group, _ := newSageGroupForTest(clock, 16, time.Hour, newSageTestProxy("alpha", true, true))
	attachSageLearningForTest(group, state, state.generation)

	group.observeConnect("alpha", sageTransportTCP, clock.Now(), 30*time.Millisecond)
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("persistence writer did not enter blocked store")
	}

	observed := make(chan struct{})
	go func() {
		group.observeResponse("alpha", sageTransportTCP, clock.Now(), 50*time.Millisecond)
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

	restored := newSageLearningState("blocked", clock, store, time.Hour, 16)
	restored.mu.Lock()
	metrics := restored.nodes[sageLearningTestNodeKey("alpha")].snapshot(sageTransportTCP, clock.Now())
	restored.mu.Unlock()
	require.True(t, metrics.connect.valid)
	require.True(t, metrics.response.valid)
	require.GreaterOrEqual(t, store.writes, 2)
}

func TestSageLearningGlobalDrainHonorsContextDeadline(t *testing.T) {
	const groupName = "bounded-global-drain"
	clock := newSageConnTestClock()
	store := newSageLearningBlockingStore()
	useSageLearningRegistryStoreForTest(t, groupName, store)
	group, err := NewSage(GroupCommonOption{Name: groupName, URL: C.DefaultTestURL}, SageOption{}, newSageTestProxy("fallback", true, false), []P.ProxyProvider{newSageTestProvider(newSageTestProxy("alpha", true, true))})
	require.NoError(t, err)
	ActivateSageLearningStates(map[string]C.Proxy{groupName: A.NewProxy(group)})
	group.learning.persistInterval = time.Nanosecond
	group.learning.lastScheduled = clock.Now().Add(-time.Second)
	group.observeConnect("alpha", sageTransportTCP, group.clock.Now(), 20*time.Millisecond)
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("persistence writer did not block")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, FlushSageLearningStatesContext(ctx), context.DeadlineExceeded)
	close(store.release)
	require.NoError(t, group.learning.flush())
}

func TestSageLearningReloadSharesMetricsButRejectsStalePruning(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageLearningTestStore()
	alpha := newSageTestProxy("alpha", true, true)
	beta := newSageTestProxy("beta", true, true)
	owner := newSageLearningState("reload", clock, store, time.Hour, 16)
	oldGroup, _ := newSageGroupForTest(clock, 16, time.Hour, alpha, beta)
	attachSageLearningForTest(oldGroup, owner, owner.generation)
	oldGroup.observeConnect("beta", sageTransportTCP, clock.Now(), 100*time.Millisecond)

	owner.mu.Lock()
	owner.generation++
	newGeneration := owner.generation
	owner.nodes[sageLearningTestNodeKey("beta")].lastObservedAt = clock.Now().Add(-2 * time.Hour)
	owner.mu.Unlock()
	newGroup, _ := newSageGroupForTest(clock, 16, time.Hour, alpha, beta)
	attachSageLearningForTest(newGroup, owner, newGeneration)

	oldGroup.learning.mu.Lock()
	oldGroup.pruneLocked(clock.Now(), []C.Proxy{alpha})
	oldGroup.learning.mu.Unlock()
	owner.mu.Lock()
	require.Contains(t, owner.nodes, sageLearningTestNodeKey("beta"))
	owner.mu.Unlock()

	oldGroup.observeResponse("beta", sageTransportTCP, clock.Now(), 55*time.Millisecond)
	owner.mu.Lock()
	snapshot := owner.nodes[sageLearningTestNodeKey("beta")].snapshot(sageTransportTCP, clock.Now())
	owner.mu.Unlock()
	require.True(t, snapshot.connect.valid)
	require.True(t, snapshot.response.valid)
	require.Empty(t, newGroup.nodeControls)
	require.Same(t, owner, newGroup.learning)
	require.NoError(t, owner.flush())
}

func TestSageLearningFlushReportsStoreFailureWithoutLosingDirtyRevision(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageLearningTestStore()
	store.fail = errors.New("save failed")
	state := newSageLearningState("failure", clock, store, time.Hour, 16)
	group, _ := newSageGroupForTest(clock, 16, time.Hour, newSageTestProxy("alpha", true, true))
	attachSageLearningForTest(group, state, state.generation)
	group.observeConnect("alpha", sageTransportTCP, clock.Now(), 10*time.Millisecond)

	require.ErrorContains(t, state.flush(), "save failed")
	status := state.status()
	require.Contains(t, status.LastError, "save failed")
	require.Greater(t, status.Revision, status.PersistedRevision)
}

func TestSageLearningOversizedLegacyRowIsReplacedByNextValidSnapshot(t *testing.T) {
	clock := newSageConnTestClock()
	store := &sageLearningOversizedStore{token: []byte("legacy-token")}
	state := newSageLearningState("oversized-recovery", clock, store, time.Hour, 16)
	require.True(t, state.status().Available)
	require.ErrorContains(t, errors.New(state.status().LastError), "payload too large")
	group, _ := newSageGroupForTest(clock, 16, time.Hour, newSageTestProxy("alpha", true, true))
	attachSageLearningForTest(group, state, state.generation)
	group.observeConnect("alpha", sageTransportTCP, clock.Now(), 25*time.Millisecond)
	require.NoError(t, state.flush())
	require.NotEmpty(t, store.saved)
	require.Equal(t, state.status().Revision, state.status().PersistedRevision)
}

func TestSageLearningSaveFailureRetriesAndPersistsLatestRevision(t *testing.T) {
	clock := sageSystemClock{}
	store := newSageLearningTestStore()
	store.fail = errors.New("temporary save failure")
	store.saved = make(chan struct{}, 1)
	state := newSageLearningState("save-retry", clock, store, time.Hour, 16)
	state.persistInterval = 5 * time.Millisecond
	group, _ := newSageGroupForTest(clock, 16, time.Hour, newSageTestProxy("alpha", true, true))
	attachSageLearningForTest(group, state, state.generation)
	group.observeConnect("alpha", sageTransportTCP, clock.Now(), 10*time.Millisecond)
	require.Eventually(t, func() bool {
		return state.status().LastError == "temporary save failure"
	}, time.Second, time.Millisecond)
	group.observeResponse("alpha", sageTransportTCP, clock.Now(), 20*time.Millisecond)
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
	restored := newSageLearningState("save-retry", clock, store, time.Hour, 16)
	restored.mu.Lock()
	metrics := restored.nodes[sageLearningTestNodeKey("alpha")].snapshot(sageTransportTCP, clock.Now())
	restored.mu.Unlock()
	require.True(t, metrics.connect.valid)
	require.True(t, metrics.response.valid)
}

func TestSageLearningCASConflictPermanentlyFencesOldWriter(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageLearningTestStore()
	store.fail = cachefile.ErrSageStateConflict
	state := newSageLearningState("cas-fenced", clock, store, time.Hour, 16)
	group, _ := newSageGroupForTest(clock, 16, time.Hour, newSageTestProxy("alpha", true, true))
	attachSageLearningForTest(group, state, state.generation)
	group.observeConnect("alpha", sageTransportTCP, clock.Now(), 10*time.Millisecond)
	require.ErrorContains(t, state.flush(), cachefile.ErrSageStateConflict.Error())

	state.mu.Lock()
	require.True(t, state.writeBlocked)
	require.Zero(t, state.pending.revision)
	require.Nil(t, state.persistTimer)
	state.mu.Unlock()
	store.fail = nil
	group.observeResponse("alpha", sageTransportTCP, clock.Now(), 20*time.Millisecond)
	require.ErrorContains(t, state.flush(), cachefile.ErrSageStateConflict.Error())
	require.Nil(t, store.payload(state.storageKey), "a fenced writer must never rebase and overwrite the current owner")
}

func TestSageLearningDebouncedWriterAndFlushEdgeCases(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageLearningTestStore()
	store.saved = make(chan struct{}, 1)
	state := newSageLearningState("debounced", clock, store, time.Hour, 16)
	state.persistInterval = 5 * time.Millisecond
	group, _ := newSageGroupForTest(clock, 16, time.Hour, newSageTestProxy("alpha", true, true))
	attachSageLearningForTest(group, state, state.generation)
	group.observeConnect("alpha", sageTransportTCP, clock.Now(), 10*time.Millisecond)
	select {
	case <-store.saved:
	case <-time.After(time.Second):
		t.Fatal("debounced writer did not persist")
	}
	require.NoError(t, state.flush())
	require.Equal(t, state.status().Revision, state.status().PersistedRevision)

	var nilState *sageLearningState
	require.NoError(t, nilState.flush())
	require.Zero(t, nilState.status())
	disabled := newSageLearningState("disabled", nil, nil, time.Hour, 16)
	require.NoError(t, disabled.flush())
	loadFailure := newSageLearningState("load-failure", clock, sageLearningLoadErrorStore{err: errors.New("load failed")}, time.Hour, 16)
	require.Contains(t, loadFailure.status().LastError, "load failed")
}

func TestSageLearningConcurrentFirstRegistrationPublishesOneCanonicalOwner(t *testing.T) {
	const groupName = "sage-learning-concurrent-registration"
	key := sageLearningStorageKey(groupName)
	store := &sageLearningBlockingLoadStore{
		sageLearningTestStore: newSageLearningTestStore(),
		entered:               make(chan struct{}, 2),
		release:               make(chan struct{}),
	}
	sageLearningRegistry.Lock()
	previousFactory := sageLearningRegistry.storeFactory
	delete(sageLearningRegistry.entries, key)
	sageLearningRegistry.storeFactory = func() sageLearningStore { return store }
	sageLearningRegistry.Unlock()
	t.Cleanup(func() {
		sageLearningRegistry.Lock()
		delete(sageLearningRegistry.entries, key)
		sageLearningRegistry.storeFactory = previousFactory
		sageLearningRegistry.Unlock()
	})

	type result struct {
		state      *sageLearningState
		generation uint64
	}
	results := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			state, generation := sharedSageLearningState(groupName, newSageConnTestClock(), time.Hour, 16)
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

func TestSageLearningRegistryCapacityFailsClosedAndStaysBounded(t *testing.T) {
	store := newSageLearningTestStore()
	sageLearningRegistry.Lock()
	previousFactory := sageLearningRegistry.storeFactory
	sageLearningRegistry.storeFactory = func() sageLearningStore { return store }
	added := make([]string, 0, sageLearningRegistryLimit)
	for i := len(sageLearningRegistry.entries); i < sageLearningRegistryLimit; i++ {
		key := sageLearningStorageKey("capacity-" + string(rune(i+1)))
		if sageLearningRegistry.entries[key] == nil {
			sageLearningRegistry.entries[key] = newSageLearningState("capacity", newSageConnTestClock(), nil, time.Hour, 1)
			added = append(added, key)
		}
	}
	sageLearningRegistry.Unlock()
	t.Cleanup(func() {
		sageLearningRegistry.Lock()
		for _, key := range added {
			delete(sageLearningRegistry.entries, key)
		}
		sageLearningRegistry.storeFactory = previousFactory
		sageLearningRegistry.Unlock()
	})

	state, _ := sharedSageLearningState("capacity-overflow", newSageConnTestClock(), time.Hour, 1)
	require.Nil(t, state.store)
	require.Contains(t, state.status().LastError, "registry capacity")
	sageLearningRegistry.Lock()
	require.LessOrEqual(t, len(sageLearningRegistry.entries), sageLearningRegistryLimit)
	sageLearningRegistry.Unlock()
}

func TestFlushSageLearningStatesDrainsAllAndAggregatesFailure(t *testing.T) {
	clock := newSageConnTestClock()
	goodStore := newSageLearningTestStore()
	badStore := newSageLearningTestStore()
	badStore.fail = errors.New("global flush failed")
	good := newSageLearningState("global-good", clock, goodStore, time.Hour, 16)
	bad := newSageLearningState("global-bad", clock, badStore, time.Hour, 16)
	for _, state := range []*sageLearningState{good, bad} {
		state.mu.Lock()
		node := &sageNodeState{name: "alpha", identity: "test:alpha", lastObservedAt: clock.Now()}
		node.tcp.observeConnect(clock.Now(), 10*time.Millisecond)
		state.nodes[sageLearningTestNodeKey("alpha")] = node
		state.markDirtyLocked(clock.Now())
		state.mu.Unlock()
	}

	sageLearningRegistry.Lock()
	previousEntries := sageLearningRegistry.entries
	sageLearningRegistry.entries = map[string]*sageLearningState{"good": good, "bad": bad}
	sageLearningRegistry.Unlock()
	t.Cleanup(func() {
		sageLearningRegistry.Lock()
		sageLearningRegistry.entries = previousEntries
		sageLearningRegistry.Unlock()
		bad.mu.Lock()
		if bad.persistTimer != nil {
			bad.persistTimer.Stop()
			bad.persistTimer = nil
		}
		bad.store = nil
		bad.mu.Unlock()
	})

	require.ErrorContains(t, FlushSageLearningStates(), "global flush failed")
	require.NotEmpty(t, goodStore.payload(good.storageKey))
}
