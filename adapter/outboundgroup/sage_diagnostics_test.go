package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	A "github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/stretchr/testify/require"
)

type sageDiagnosticsTestStore struct {
	mu     sync.Mutex
	data   map[string][]byte
	writes int
}

type sageDiagnosticsFailStore struct {
	loadErr error
	saveErr error
}

func (s sageDiagnosticsFailStore) Load(string) ([]byte, error) { return nil, s.loadErr }
func (s sageDiagnosticsFailStore) Save(string, []byte) error   { return s.saveErr }

type sageDiagnosticsBlockingStore struct {
	*sageDiagnosticsTestStore
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

type sageDiagnosticsBlockingLoadStore struct {
	*sageDiagnosticsTestStore
	mu      sync.Mutex
	loads   int
	entered chan struct{}
	release chan struct{}
}

type sageDiagnosticsFlakyStore struct {
	*sageDiagnosticsTestStore
	mu       sync.Mutex
	failures int
	attempts int
}

func (s *sageDiagnosticsBlockingStore) Save(key string, payload []byte) error {
	s.once.Do(func() {
		close(s.entered)
		<-s.release
	})
	return s.sageDiagnosticsTestStore.Save(key, payload)
}

func (s *sageDiagnosticsBlockingLoadStore) Load(key string) ([]byte, error) {
	s.mu.Lock()
	s.loads++
	loads := s.loads
	s.mu.Unlock()
	if loads == 2 {
		close(s.entered)
		<-s.release
	}
	return s.sageDiagnosticsTestStore.Load(key)
}

func (s *sageDiagnosticsBlockingLoadStore) loadCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loads
}

func (s *sageDiagnosticsFlakyStore) Save(key string, payload []byte) error {
	s.mu.Lock()
	s.attempts++
	if s.failures > 0 {
		s.failures--
		s.mu.Unlock()
		return errors.New("temporary save failure")
	}
	s.mu.Unlock()
	return s.sageDiagnosticsTestStore.Save(key, payload)
}

func (s *sageDiagnosticsFlakyStore) attemptCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

func newSageDiagnosticsTestStore() *sageDiagnosticsTestStore {
	return &sageDiagnosticsTestStore{data: make(map[string][]byte)}
}

func (s *sageDiagnosticsTestStore) Load(key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.data[key]...), nil
}

func (s *sageDiagnosticsTestStore) Save(key string, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = append([]byte(nil), payload...)
	s.writes++
	return nil
}

func (s *sageDiagnosticsTestStore) writeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

func TestSageDiagnosticsPersistReconnectLifecycleAndOutcome(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageDiagnosticsTestStore()
	alpha := newSageTestProxy("alpha", true, true)
	alpha.delay = 20
	beta := newSageTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newSageGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureSageMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	group.diagnostics = newSageDiagnostics(group.Name(), clock, store)
	metadata := &C.Metadata{Host: "rr1.googlevideo.com", DstPort: 443, NetWork: C.TCP}

	flow := newSageMediaFlow(group, "alpha", metadata)
	require.NotNil(t, flow)
	low := sageThroughputObservation{
		BitsPerSecond: 1_000_000,
		TotalBytes:    4 * 1024 * 1024,
		Age:           20 * time.Second,
	}
	require.Nil(t, flow.observe(low))
	require.Nil(t, flow.observe(low))
	action := flow.observe(low)
	require.NotNil(t, action)
	require.True(t, action())
	selected, token := group.pickWithHandoff(metadata, sageTransportTCP, false, true)
	require.Equal(t, "beta", selected.Name())
	require.NotNil(t, token)
	require.Equal(t, "beta", group.pick(metadata, sageTransportTCP, false, true).Name(), "the sticky policy hint remains reusable")

	handoff := newSageMediaFlow(group, "beta", metadata, token)
	require.NotNil(t, handoff)
	competing := newSageMediaFlow(group, "beta", metadata)
	require.NotNil(t, competing)
	high := sageThroughputObservation{
		BitsPerSecond: 8_000_000,
		TotalBytes:    8 * 1024 * 1024,
		Age:           5 * time.Second,
	}
	require.Nil(t, competing.observe(high))
	require.Zero(t, group.SageDiagnostics().Counters.HandoffMeasured, "an unrelated same-target flow must not consume the handoff outcome")
	require.Nil(t, handoff.observe(high))

	snapshot := group.SageDiagnostics()
	require.Equal(t, SageDiagnosticsSchemaVersion, snapshot.SchemaVersion)
	require.Equal(t, group.Name(), snapshot.Group)
	require.False(t, snapshot.PlayerTelemetryAvailable)
	require.Equal(t, uint64(3), snapshot.Counters.MediaFlows)
	require.Equal(t, uint64(5), snapshot.Counters.ThroughputSamples)
	require.Equal(t, uint64(3), snapshot.Counters.LowThroughputSamples)
	require.Equal(t, uint64(1), snapshot.Counters.ReconnectPrepared)
	require.Equal(t, uint64(1), snapshot.Counters.ReconnectCommitted)
	require.Equal(t, uint64(2), snapshot.Counters.HandoffSelections)
	require.Equal(t, uint64(1), snapshot.Counters.HandoffMeasured)
	require.NotEmpty(t, snapshot.RecentEvents)

	last := snapshot.RecentEvents[len(snapshot.RecentEvents)-1]
	require.Equal(t, "handoff-measured", last.Kind)
	require.Equal(t, "alpha", last.From)
	require.Equal(t, "beta", last.To)
	require.NotZero(t, last.HandoffID)
	require.InDelta(t, 1_000_000, last.PreviousBPS, 0.1)
	require.InDelta(t, 8_000_000, last.BPS, 0.1)

	group.diagnostics.waitPersistence()
	restored := newSageDiagnostics(group.Name(), clock, store).snapshot()
	require.Equal(t, snapshot.Counters, restored.Counters)
	require.Equal(t, snapshot.Suppressions, restored.Suppressions)
	require.Equal(t, snapshot.Rejections, restored.Rejections)
	require.Equal(t, snapshot.RecentEvents, restored.RecentEvents)
}

func TestSageDiagnosticsProductionReasons(t *testing.T) {
	t.Run("buffer credit defer", func(t *testing.T) {
		clock := newSageConnTestClock()
		alpha := newSageTestProxy("alpha", true, true)
		beta := newSageTestProxy("beta", true, true)
		beta.delay = 10
		group, _ := newSageGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureSageMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		group.media.demandBPS = 10_000_000
		group.media.bufferGuard = 3 * time.Second
		flow := newSageMediaFlow(group, "alpha", &C.Metadata{Host: "rr2.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		low := sageThroughputObservation{BitsPerSecond: 1_000_000, TotalBytes: 512 * 1024, Age: 20 * time.Second}
		require.Nil(t, flow.observe(low))
		require.Nil(t, flow.observe(low))
		require.Nil(t, flow.observe(low))

		snapshot := group.SageDiagnostics()
		require.Equal(t, uint64(1), snapshot.Counters.BufferCreditDeferrals)
		require.Equal(t, "buffer-credit", snapshot.RecentEvents[len(snapshot.RecentEvents)-1].Reason)
	})

	t.Run("no challenger suppression", func(t *testing.T) {
		clock := newSageConnTestClock()
		alpha := newSageTestProxy("alpha", true, true)
		beta := newSageTestProxy("beta", true, true)
		beta.delay = 0
		group, _ := newSageGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureSageMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		flow := newSageMediaFlow(group, "alpha", &C.Metadata{Host: "rr3.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		low := sageThroughputObservation{BitsPerSecond: 1_000_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second}
		require.Nil(t, flow.observe(low))
		require.Nil(t, flow.observe(low))
		require.Nil(t, flow.observe(low))

		snapshot := group.SageDiagnostics()
		require.Equal(t, uint64(1), snapshot.Counters.ReconnectSuppressed)
		require.Equal(t, uint64(1), snapshot.Suppressions["no-challenger"])
	})

	t.Run("commit rejection", func(t *testing.T) {
		clock := newSageConnTestClock()
		alpha := newSageTestProxy("alpha", true, true)
		beta := newSageTestProxy("beta", true, true)
		beta.delay = 10
		group, _ := newSageGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureSageMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		flow := newSageMediaFlow(group, "alpha", &C.Metadata{Host: "rr4.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		low := sageThroughputObservation{BitsPerSecond: 1_000_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second}
		require.Nil(t, flow.observe(low))
		require.Nil(t, flow.observe(low))
		action := flow.observe(low)
		require.NotNil(t, action)
		beta.alive = false
		require.False(t, action())

		snapshot := group.SageDiagnostics()
		require.Equal(t, uint64(1), snapshot.Counters.ReconnectRejected)
		require.Equal(t, uint64(1), snapshot.Rejections["challenger-unhealthy"])
	})
}

func TestSageDiagnosticsSamplePersistenceIsRateLimited(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageDiagnosticsTestStore()
	diagnostics := newSageDiagnostics("sage", clock, store)

	for i := 0; i < 100; i++ {
		diagnostics.record(sageDiagnosticRecord{kind: "throughput-sample", bps: 8_000_000})
	}
	require.Zero(t, store.writeCount(), "hot-path samples must not write the cache on every window")
	clock.Advance(sageDiagnosticsPersistInterval)
	diagnostics.record(sageDiagnosticRecord{kind: "throughput-sample", bps: 8_000_000})
	diagnostics.waitPersistence()
	require.Equal(t, 1, store.writeCount())
}

func TestSageDiagnosticsIdleSamplesFlushAfterBoundedDelay(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageDiagnosticsTestStore()
	diagnostics := newSageDiagnostics("idle-flush", clock, store)
	diagnostics.persistInterval = 10 * time.Millisecond

	diagnostics.record(sageDiagnosticRecord{kind: "throughput-sample", bps: 8_000_000})
	require.Eventually(t, func() bool { return store.writeCount() == 1 }, time.Second, time.Millisecond)
	diagnostics.waitPersistence()
	restored := newSageDiagnostics("idle-flush", clock, store).snapshot()
	require.Equal(t, uint64(1), restored.Counters.ThroughputSamples)
}

func TestSageDiagnosticsHandoffDialFailureIsAttributed(t *testing.T) {
	clock := newSageConnTestClock()
	alpha := newSageTestProxy("alpha", true, true)
	beta := newSageTestProxy("beta", true, true)
	beta.dialErr = errors.New("dial failed")
	group, _ := newSageGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureSageMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	metadata := &C.Metadata{Host: "rr-fail.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	targetKey := group.mediaTargetKey(metadata.Host, metadata.DstPort)

	handoff := group.diagnostics.recordReconnectCommit(sageDiagnosticRecord{
		target: metadata.Host,
		bucket: targetKey.target,
		port:   metadata.DstPort,
		from:   "alpha",
		to:     "beta",
		bps:    1_000_000,
	})
	group.mediaHints[targetKey] = sageMediaHint{candidate: "beta", expiresAt: clock.Now().Add(time.Minute), handoff: handoff}

	_, err := group.DialContext(context.Background(), metadata)
	require.Error(t, err)
	snapshot := group.SageDiagnostics()
	require.Equal(t, uint64(1), snapshot.Counters.HandoffDialFailed)
	last := snapshot.RecentEvents[len(snapshot.RecentEvents)-1]
	require.Equal(t, "handoff-dial-failed", last.Kind)
	require.NotZero(t, last.HandoffID)
	require.Equal(t, "alpha", last.From)
	require.Equal(t, "beta", last.To)
}

func TestSageDiagnosticsHandoffFirstWriteFailureIsAttributed(t *testing.T) {
	clock := newSageConnTestClock()
	alpha := newSageTestProxy("alpha", true, true)
	beta := newSageTestProxy("beta", true, true)
	beta.dialConn = &sageEarlyTestConn{sageConnTestConn: &sageConnTestConn{
		writeFunc: func([]byte) (int, error) { return 0, errSageTestWrite },
	}}
	group, _ := newSageGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureSageMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	metadata := &C.Metadata{Host: "rr-write-fail.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	targetKey := group.mediaTargetKey(metadata.Host, metadata.DstPort)
	handoff := group.diagnostics.recordReconnectCommit(sageDiagnosticRecord{
		target: metadata.Host, bucket: targetKey.target,
		port: metadata.DstPort, from: "alpha", to: "beta", bps: 1_000_000,
	})
	group.mediaHints[targetKey] = sageMediaHint{candidate: "beta", expiresAt: clock.Now().Add(time.Minute), handoff: handoff}

	conn, err := group.DialContext(context.Background(), metadata)
	require.NoError(t, err)
	_, err = conn.Write([]byte("request"))
	require.ErrorIs(t, err, errSageTestWrite)
	snapshot := group.SageDiagnostics()
	require.Equal(t, uint64(1), snapshot.Counters.HandoffDialFailed)
	last := snapshot.RecentEvents[len(snapshot.RecentEvents)-1]
	require.Equal(t, "handoff-dial-failed", last.Kind)
	require.Equal(t, "first-write-failed", last.Reason)
	require.NotZero(t, last.HandoffID)
}

func TestSageDiagnosticsReadDoesNotPrunePolicyState(t *testing.T) {
	clock := newSageConnTestClock()
	alpha := newSageTestProxy("alpha", true, true)
	group, _ := newSageGroupForTest(clock, 10, time.Hour, alpha)
	configureSageMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	key := sageMediaTargetKey{target: "googlevideo.com", port: 443}
	expired := clock.Now().Add(-time.Second)
	group.mediaHints[key] = sageMediaHint{candidate: "alpha", expiresAt: expired}
	group.mediaReconnects[key] = expired
	group.mediaSlowCooldowns[sageMediaCandidateKey{sageMediaTargetKey: key, candidate: "alpha"}] = expired
	group.mediaBudgets[key] = sageMediaBudget{startedAt: clock.Now().Add(-group.media.budgetWindow)}

	first := group.SageDiagnostics()
	second := group.SageDiagnostics()
	require.Equal(t, first, second)
	require.Equal(t, SageDiagnosticRuntime{}, first.Runtime)
	require.Len(t, group.mediaHints, 1)
	require.Len(t, group.mediaReconnects, 1)
	require.Len(t, group.mediaSlowCooldowns, 1)
	require.Len(t, group.mediaBudgets, 1)
}

func TestSageDiagnosticsReasonsAreVisibleAndBounded(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageDiagnosticsTestStore()
	diagnostics := newSageDiagnostics("sage", clock, store)

	for i := 0; i < sageDiagnosticsRecentEventLimit+20; i++ {
		diagnostics.record(sageDiagnosticRecord{
			kind:   "reconnect-suppressed",
			reason: "no-challenger",
			target: "googlevideo.com",
			port:   443,
			from:   "alpha",
			force:  true,
		})
		clock.Advance(time.Millisecond)
	}

	snapshot := diagnostics.snapshot()
	require.Len(t, snapshot.RecentEvents, sageDiagnosticsRecentEventLimit)
	require.Equal(t, uint64(sageDiagnosticsRecentEventLimit+20), snapshot.Counters.ReconnectSuppressed)
	require.Equal(t, uint64(sageDiagnosticsRecentEventLimit+20), snapshot.Suppressions["no-challenger"])
	for i := 1; i < len(snapshot.RecentEvents); i++ {
		require.Greater(t, snapshot.RecentEvents[i].Sequence, snapshot.RecentEvents[i-1].Sequence)
	}
}

func TestSageDiagnosticsRestoreValidationAndNilSafety(t *testing.T) {
	clock := newSageConnTestClock()
	key := sageDiagnosticsStorageKey("sage")

	for name, payload := range map[string][]byte{
		"invalid json": []byte("{"),
		"wrong schema": []byte(`{"schemaVersion":99,"group":"sage"}`),
		"wrong group":  []byte(`{"schemaVersion":1,"group":"other"}`),
	} {
		t.Run(name, func(t *testing.T) {
			store := newSageDiagnosticsTestStore()
			store.data[key] = payload
			snapshot := newSageDiagnostics("sage", clock, store).snapshot()
			require.Equal(t, SageDiagnosticsSchemaVersion, snapshot.SchemaVersion)
			require.Equal(t, "sage", snapshot.Group)
			require.Empty(t, snapshot.RecentEvents)
		})
	}

	events := make([]SageDiagnosticEvent, sageDiagnosticsRecentEventLimit+3)
	for i := range events {
		events[i] = SageDiagnosticEvent{Sequence: uint64(i + 1)}
	}
	payload, err := json.Marshal(SageDiagnosticsSnapshot{
		SchemaVersion: SageDiagnosticsSchemaVersion,
		Group:         "sage",
		RecentEvents:  events,
	})
	require.NoError(t, err)
	store := newSageDiagnosticsTestStore()
	store.data[key] = payload
	restored := newSageDiagnostics("sage", clock, store).snapshot()
	require.Len(t, restored.RecentEvents, sageDiagnosticsRecentEventLimit)
	require.Equal(t, uint64(4), restored.RecentEvents[0].Sequence)
	require.NotNil(t, restored.Suppressions)
	require.NotNil(t, restored.Rejections)

	defaultClock := newSageDiagnostics("sage", nil, nil)
	require.NotNil(t, defaultClock)
	defaultClock.record(sageDiagnosticRecord{kind: "future-event", reason: "unknown"})
	require.Equal(t, "future-event", defaultClock.snapshot().RecentEvents[0].Kind)

	var nilDiagnostics *sageDiagnostics
	nilDiagnostics.record(sageDiagnosticRecord{kind: "ignored"})
	require.Equal(t, SageDiagnosticsSnapshot{}, nilDiagnostics.snapshot())
}

func TestSageDiagnosticsExposePersistenceFailure(t *testing.T) {
	clock := newSageConnTestClock()
	loadFailure := newSageDiagnostics("load-failure", clock, sageDiagnosticsFailStore{loadErr: errors.New("load unavailable")})
	loadSnapshot := loadFailure.snapshot()
	require.False(t, loadSnapshot.Persistence.Available)
	require.Contains(t, loadSnapshot.Persistence.LastError, "load unavailable")

	saveFailure := newSageDiagnostics("save-failure", clock, sageDiagnosticsFailStore{saveErr: errors.New("save unavailable")})
	require.True(t, saveFailure.snapshot().Persistence.Available)
	saveFailure.record(sageDiagnosticRecord{kind: "reconnect-suppressed", reason: "no-challenger", force: true})
	saveFailure.waitPersistence()
	saveSnapshot := saveFailure.snapshot()
	require.False(t, saveSnapshot.Persistence.Available)
	require.Contains(t, saveSnapshot.Persistence.LastError, "save unavailable")
	saveFailure.mu.Lock()
	if saveFailure.persistTimer != nil {
		saveFailure.persistTimer.Stop()
		saveFailure.persistTimer = nil
	}
	saveFailure.mu.Unlock()
}

func TestSageDiagnosticsRetriesTransientPersistenceFailure(t *testing.T) {
	clock := newSageConnTestClock()
	store := &sageDiagnosticsFlakyStore{
		sageDiagnosticsTestStore: newSageDiagnosticsTestStore(),
		failures:                 1,
	}
	diagnostics := newSageDiagnostics("save-retry", clock, store)
	diagnostics.persistInterval = 5 * time.Millisecond
	diagnostics.record(sageDiagnosticRecord{kind: "reconnect-suppressed", reason: "no-challenger", force: true})

	require.Eventually(t, func() bool { return store.writeCount() == 1 }, time.Second, time.Millisecond)
	diagnostics.waitPersistence()
	require.GreaterOrEqual(t, store.attemptCount(), 2)
	snapshot := diagnostics.snapshot()
	require.True(t, snapshot.Persistence.Available)
	require.Empty(t, snapshot.Persistence.LastError)
	restored := newSageDiagnostics("save-retry", clock, store).snapshot()
	require.Equal(t, uint64(1), restored.Counters.ReconnectSuppressed)
}

func TestSageDiagnosticsPersistenceFailureBacksOffForcedEvents(t *testing.T) {
	clock := newSageConnTestClock()
	store := &sageDiagnosticsFlakyStore{
		sageDiagnosticsTestStore: newSageDiagnosticsTestStore(),
		failures:                 1,
	}
	diagnostics := newSageDiagnostics("save-backoff", clock, store)
	diagnostics.persistInterval = 100 * time.Millisecond
	diagnostics.record(sageDiagnosticRecord{kind: "reconnect-suppressed", reason: "no-challenger", force: true})
	diagnostics.waitPersistence()
	require.Equal(t, 1, store.attemptCount())

	for i := 0; i < 16; i++ {
		diagnostics.record(sageDiagnosticRecord{kind: "reconnect-suppressed", reason: "no-challenger", force: true})
	}
	time.Sleep(20 * time.Millisecond)
	require.Equal(t, 1, store.attemptCount(), "forced events must coalesce behind the retry backoff")
	require.Eventually(t, func() bool { return store.writeCount() == 1 }, time.Second, time.Millisecond)
	diagnostics.waitPersistence()
	require.Equal(t, 2, store.attemptCount())
	require.Equal(t, uint64(17), newSageDiagnostics("save-backoff", clock, store).snapshot().Counters.ReconnectSuppressed)
}

func TestSageDiagnosticsExpiredHintDoesNotExposeHandoff(t *testing.T) {
	clock := newSageConnTestClock()
	alpha := newSageTestProxy("alpha", true, true)
	beta := newSageTestProxy("beta", true, true)
	group, _ := newSageGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureSageMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	metadata := &C.Metadata{Host: "rr-expired.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	key := group.mediaTargetKey(metadata.Host, metadata.DstPort)
	handoff := group.diagnostics.recordReconnectCommit(sageDiagnosticRecord{
		target: metadata.Host, bucket: key.target, port: metadata.DstPort,
		from: "alpha", to: "beta", bps: 1_000_000,
	})
	group.mediaHints[key] = sageMediaHint{candidate: "beta", expiresAt: clock.Now().Add(time.Second), handoff: handoff}
	clock.Advance(2 * time.Second)

	_, claimed := group.pickWithHandoff(metadata, sageTransportTCP, false, true)
	require.Nil(t, claimed)
	require.Zero(t, group.SageDiagnostics().Counters.HandoffSelections)
}

func TestSageDiagnosticsHandoffIdentityIsBoundToEachGenerationHint(t *testing.T) {
	clock := newSageConnTestClock()
	shared := newSageDiagnostics("reload-shared", clock, newSageDiagnosticsTestStore())
	newGroup := func() *Sage {
		alpha := newSageTestProxy("alpha", true, true)
		beta := newSageTestProxy("beta", true, true)
		group, _ := newSageGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureSageMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		group.diagnostics = shared
		return group
	}
	oldGeneration := newGroup()
	newGeneration := newGroup()
	metadata := &C.Metadata{Host: "rr-reload.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	key := oldGeneration.mediaTargetKey(metadata.Host, metadata.DstPort)
	plan := sageMediaPlan{
		targetKey: key, target: metadata.Host, port: metadata.DstPort,
		current: "alpha", challenger: "beta", currentBPS: 1_000_000, preparedAt: clock.Now(),
	}

	require.Empty(t, oldGeneration.commitMediaReconnectDetailed(plan))
	require.Empty(t, newGeneration.commitMediaReconnectDetailed(plan))
	oldProxy, oldHandoff := oldGeneration.pickWithHandoff(metadata, sageTransportTCP, false, true)
	newProxy, newHandoff := newGeneration.pickWithHandoff(metadata, sageTransportTCP, false, true)
	require.Equal(t, "beta", oldProxy.Name())
	require.Equal(t, "beta", newProxy.Name())
	require.NotNil(t, oldHandoff)
	require.NotNil(t, newHandoff)
	require.NotEqual(t, oldHandoff.id, newHandoff.id)
	require.Equal(t, "alpha", oldHandoff.from)
	require.Equal(t, "alpha", newHandoff.from)
	require.Equal(t, uint64(2), shared.snapshot().Counters.ReconnectCommitted)
}

func TestSageDiagnosticsHandoffIdentityRequiresExactTarget(t *testing.T) {
	clock := newSageConnTestClock()
	alpha := newSageTestProxy("alpha", true, true)
	beta := newSageTestProxy("beta", true, true)
	group, _ := newSageGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureSageMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	origin := &C.Metadata{Host: "rr-origin.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	unrelated := &C.Metadata{Host: "rr-unrelated.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	key := group.mediaTargetKey(origin.Host, origin.DstPort)
	handoff := group.diagnostics.recordReconnectCommit(sageDiagnosticRecord{
		target: origin.Host, bucket: key.target, port: origin.DstPort,
		from: "alpha", to: "beta", bps: 1_000_000,
	})
	group.mediaHints[key] = sageMediaHint{candidate: "beta", expiresAt: clock.Now().Add(time.Minute), handoff: handoff}

	proxy, claimed := group.pickWithHandoff(unrelated, sageTransportTCP, false, true)
	require.Equal(t, "beta", proxy.Name(), "bucket-level sticky candidate remains reusable")
	require.Nil(t, claimed, "another exact target must not steal the diagnostic identity")
	proxy, claimed = group.pickWithHandoff(origin, sageTransportTCP, false, true)
	require.Equal(t, "beta", proxy.Name())
	require.Same(t, handoff, claimed)
}

func TestSageDiagnosticsHandoffIdentityAcceptsRootDotEquivalentTarget(t *testing.T) {
	clock := newSageConnTestClock()
	alpha := newSageTestProxy("alpha", true, true)
	beta := newSageTestProxy("beta", true, true)
	alpha.dialConn = &sageConnTestConn{}
	beta.dialConn = &sageConnTestConn{}
	alphaDialed := false
	betaDialed := false
	alpha.dialHook = func() { alphaDialed = true }
	beta.dialHook = func() { betaDialed = true }
	group, _ := newSageGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureSageMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	origin := &C.Metadata{Host: "googlevideo.com", DstPort: 443, NetWork: C.TCP}
	rootDot := &C.Metadata{Host: "GOOGLEVIDEO.COM.", DstPort: 443, NetWork: C.TCP}
	key := group.mediaTargetKey(origin.Host, origin.DstPort)
	handoff := group.diagnostics.recordReconnectCommit(sageDiagnosticRecord{
		target: origin.Host, bucket: key.target, port: origin.DstPort,
		from: "alpha", to: "beta", bps: 1_000_000,
	})
	group.mediaHints[key] = sageMediaHint{candidate: "beta", expiresAt: clock.Now().Add(time.Minute), handoff: handoff}

	conn, err := group.DialContext(context.Background(), rootDot)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.False(t, alphaDialed)
	require.True(t, betaDialed)
	require.Equal(t, uint64(1), group.SageDiagnostics().Counters.HandoffSelections)
}

func TestSageDiagnosticsNeutralHandoffFailuresAreNotCounted(t *testing.T) {
	t.Run("dial canceled", func(t *testing.T) {
		clock := newSageConnTestClock()
		alpha := newSageTestProxy("alpha", true, true)
		beta := newSageTestProxy("beta", true, true)
		beta.dialErr = context.Canceled
		group, _ := newSageGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureSageMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		metadata := &C.Metadata{Host: "rr-canceled.googlevideo.com", DstPort: 443, NetWork: C.TCP}
		key := group.mediaTargetKey(metadata.Host, metadata.DstPort)
		handoff := group.diagnostics.recordReconnectCommit(sageDiagnosticRecord{
			target: metadata.Host, bucket: key.target, port: metadata.DstPort,
			from: "alpha", to: "beta", bps: 1_000_000,
		})
		group.mediaHints[key] = sageMediaHint{candidate: "beta", expiresAt: clock.Now().Add(time.Minute), handoff: handoff}

		_, err := group.DialContext(context.Background(), metadata)
		require.ErrorIs(t, err, context.Canceled)
		require.Zero(t, group.SageDiagnostics().Counters.HandoffDialFailed)
	})

	t.Run("first write closed pipe", func(t *testing.T) {
		clock := newSageConnTestClock()
		alpha := newSageTestProxy("alpha", true, true)
		beta := newSageTestProxy("beta", true, true)
		beta.dialConn = &sageEarlyTestConn{sageConnTestConn: &sageConnTestConn{
			writeFunc: func([]byte) (int, error) { return 0, io.ErrClosedPipe },
		}}
		group, _ := newSageGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureSageMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		metadata := &C.Metadata{Host: "rr-closed.googlevideo.com", DstPort: 443, NetWork: C.TCP}
		key := group.mediaTargetKey(metadata.Host, metadata.DstPort)
		handoff := group.diagnostics.recordReconnectCommit(sageDiagnosticRecord{
			target: metadata.Host, bucket: key.target, port: metadata.DstPort,
			from: "alpha", to: "beta", bps: 1_000_000,
		})
		group.mediaHints[key] = sageMediaHint{candidate: "beta", expiresAt: clock.Now().Add(time.Minute), handoff: handoff}

		conn, err := group.DialContext(context.Background(), metadata)
		require.NoError(t, err)
		_, err = conn.Write([]byte("request"))
		require.ErrorIs(t, err, io.ErrClosedPipe)
		require.Zero(t, group.SageDiagnostics().Counters.HandoffDialFailed)
	})
}

func TestSageDiagnosticsRegistryIsLRUBounded(t *testing.T) {
	registry := sageDiagnosticsRegistryState{entries: make(map[string]*sageDiagnostics)}
	var first *sageDiagnostics
	for i := 0; i < sageDiagnosticsRegistryLimit; i++ {
		diagnostics := newSageDiagnostics(fmt.Sprintf("bounded-%03d", i), nil, nil)
		if i == 0 {
			first = diagnostics
		}
		registry.Lock()
		registry.addLocked(diagnostics.storageKey, diagnostics)
		registry.Unlock()
	}
	registry.touch(first)
	extra := newSageDiagnostics("bounded-extra", nil, nil)
	registry.Lock()
	registry.addLocked(extra.storageKey, extra)
	count := len(registry.entries)
	_, keptFirst := registry.entries[first.storageKey]
	_, evictedSecond := registry.entries[sageDiagnosticsStorageKey("bounded-001")]
	registry.Unlock()

	require.Equal(t, sageDiagnosticsRegistryLimit, count)
	require.True(t, keptFirst)
	require.False(t, evictedSecond)
}

func TestSageDiagnosticsRegistryEvictionFlushesDirtySnapshot(t *testing.T) {
	registry := sageDiagnosticsRegistryState{entries: make(map[string]*sageDiagnostics)}
	store := newSageDiagnosticsTestStore()
	dirty := newSageDiagnostics("dirty-oldest", nil, store)
	registry.Lock()
	registry.addLocked(dirty.storageKey, dirty)
	registry.Unlock()
	dirty.mu.Lock()
	dirty.recordLocked(sageDiagnosticRecord{kind: "throughput-sample", bps: 8_000_000})
	dirty.mu.Unlock()
	require.Zero(t, store.writeCount())

	for i := 1; i <= sageDiagnosticsRegistryLimit; i++ {
		diagnostics := newSageDiagnostics(fmt.Sprintf("dirty-%03d", i), nil, nil)
		registry.Lock()
		registry.addLocked(diagnostics.storageKey, diagnostics)
		registry.Unlock()
	}

	require.Equal(t, 1, store.writeCount())
	restored := newSageDiagnostics("dirty-oldest", nil, store).snapshot()
	require.Equal(t, uint64(1), restored.Counters.ThroughputSamples)
}

func TestSageDiagnosticsRegistryEvictionPersistsRecordsArrivingDuringRetirement(t *testing.T) {
	registry := sageDiagnosticsRegistryState{entries: make(map[string]*sageDiagnostics)}
	store := &sageDiagnosticsBlockingStore{
		sageDiagnosticsTestStore: newSageDiagnosticsTestStore(),
		entered:                  make(chan struct{}),
		release:                  make(chan struct{}),
	}
	victim := newSageDiagnostics("retiring-writer", nil, store)
	victim.persistInterval = time.Hour
	registry.Lock()
	require.True(t, registry.addLocked(victim.storageKey, victim))
	registry.Unlock()
	victim.mu.Lock()
	victim.recordLocked(sageDiagnosticRecord{kind: "throughput-sample", bps: 8_000_000})
	victim.mu.Unlock()
	for i := 1; i < sageDiagnosticsRegistryLimit; i++ {
		diagnostics := newSageDiagnostics(fmt.Sprintf("retiring-%03d", i), nil, nil)
		registry.Lock()
		require.True(t, registry.addLocked(diagnostics.storageKey, diagnostics))
		registry.Unlock()
	}

	extra := newSageDiagnostics("retiring-extra", nil, nil)
	registered := make(chan bool, 1)
	go func() {
		registry.Lock()
		registered <- registry.addLocked(extra.storageKey, extra)
		registry.Unlock()
	}()
	<-store.entered
	victim.record(sageDiagnosticRecord{kind: "throughput-sample", bps: 4_000_000})
	close(store.release)
	require.True(t, <-registered)

	restored := newSageDiagnostics("retiring-writer", nil, store).snapshot()
	require.Equal(t, uint64(2), restored.Counters.ThroughputSamples)
	victim.mu.Lock()
	require.True(t, victim.retired)
	require.True(t, victim.detached)
	require.False(t, victim.snapshotData.Persistence.Available)
	victim.mu.Unlock()
}

func TestSageDiagnosticsRegistryKeepsVictimWhenEvictionFlushFails(t *testing.T) {
	registry := sageDiagnosticsRegistryState{entries: make(map[string]*sageDiagnostics)}
	store := &sageDiagnosticsFlakyStore{
		sageDiagnosticsTestStore: newSageDiagnosticsTestStore(),
		failures:                 1,
	}
	victim := newSageDiagnostics("failed-victim", nil, store)
	victim.persistInterval = time.Hour
	registry.Lock()
	require.True(t, registry.addLocked(victim.storageKey, victim))
	registry.Unlock()
	victim.mu.Lock()
	victim.recordLocked(sageDiagnosticRecord{kind: "throughput-sample", bps: 8_000_000})
	victim.mu.Unlock()

	for i := 1; i < sageDiagnosticsRegistryLimit; i++ {
		diagnostics := newSageDiagnostics(fmt.Sprintf("failed-%03d", i), nil, nil)
		registry.Lock()
		require.True(t, registry.addLocked(diagnostics.storageKey, diagnostics))
		registry.Unlock()
	}
	extra := newSageDiagnostics("failed-extra", nil, nil)
	registry.Lock()
	registered := registry.addLocked(extra.storageKey, extra)
	_, victimKept := registry.entries[victim.storageKey]
	_, extraAdded := registry.entries[extra.storageKey]
	count := len(registry.entries)
	registry.Unlock()

	require.False(t, registered)
	require.True(t, victimKept)
	require.False(t, extraAdded)
	require.Equal(t, sageDiagnosticsRegistryLimit, count)
	victim.mu.Lock()
	require.False(t, victim.retired)
	require.False(t, victim.retiring)
	require.NotNil(t, victim.persistTimer)
	victim.persistTimer.Stop()
	victim.persistTimer = nil
	victim.mu.Unlock()
	require.Equal(t, 1, store.attemptCount())
}

func TestSageDiagnosticsDetachedGenerationCannotOverwriteNewerPersistedState(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageDiagnosticsTestStore()
	group := "retired-latest-" + t.Name()
	key := sageDiagnosticsStorageKey(group)
	stale := newSageDiagnostics(group, clock, store)
	stale.record(sageDiagnosticRecord{kind: "reconnect-suppressed", reason: "first", force: true})
	stale.waitPersistence()
	newer := newSageDiagnostics(group, clock, store)
	newer.record(sageDiagnosticRecord{kind: "reconnect-suppressed", reason: "second", force: true})
	newer.waitPersistence()

	stale.mu.Lock()
	stale.retired = true
	stale.detached = true
	stale.store = nil
	stale.snapshotData.Persistence.Available = false
	stale.snapshotData.Persistence.LastError = "diagnostics registry entry evicted"
	stale.mu.Unlock()
	sageDiagnosticsRegistry.Lock()
	delete(sageDiagnosticsRegistry.entries, key)
	sageDiagnosticsRegistry.current.Delete(key)
	sageDiagnosticsRegistry.Unlock()
	t.Cleanup(func() {
		sageDiagnosticsRegistry.Lock()
		delete(sageDiagnosticsRegistry.entries, key)
		sageDiagnosticsRegistry.current.Delete(key)
		sageDiagnosticsRegistry.Unlock()
	})

	stale.record(sageDiagnosticRecord{kind: "reconnect-suppressed", reason: "detached"})
	restored := newSageDiagnostics(group, clock, store).snapshot()
	require.Equal(t, uint64(2), restored.Counters.ReconnectSuppressed)
	require.Zero(t, restored.Suppressions["detached"])

	current := newSageDiagnostics(group, clock, store)
	sageDiagnosticsRegistry.Lock()
	require.True(t, sageDiagnosticsRegistry.addLocked(key, current))
	sageDiagnosticsRegistry.Unlock()
	stale.record(sageDiagnosticRecord{kind: "reconnect-suppressed", reason: "redirected", force: true})
	current.waitPersistence()
	restored = newSageDiagnostics(group, clock, store).snapshot()
	require.Equal(t, uint64(3), restored.Counters.ReconnectSuppressed)
	require.Equal(t, uint64(1), restored.Suppressions["first"])
	require.Equal(t, uint64(1), restored.Suppressions["second"])
	require.Equal(t, uint64(1), restored.Suppressions["redirected"])
}

func TestSageDiagnosticsSnapshotDoesNotReactivateRetiredState(t *testing.T) {
	diagnostics := newSageDiagnostics("retired-read-only", nil, nil)
	diagnostics.record(sageDiagnosticRecord{kind: "throughput-sample", bps: 8_000_000})
	diagnostics.mu.Lock()
	diagnostics.retired = true
	diagnostics.mu.Unlock()
	sageDiagnosticsRegistry.Lock()
	delete(sageDiagnosticsRegistry.entries, diagnostics.storageKey)
	sageDiagnosticsRegistry.current.Delete(diagnostics.storageKey)
	sageDiagnosticsRegistry.Unlock()

	first := diagnostics.snapshot()
	second := diagnostics.snapshot()
	require.Equal(t, first, second)
	require.Equal(t, uint64(1), first.Counters.ThroughputSamples)
	diagnostics.mu.Lock()
	require.True(t, diagnostics.retired)
	require.Nil(t, diagnostics.redirect)
	diagnostics.mu.Unlock()
	sageDiagnosticsRegistry.Lock()
	_, registered := sageDiagnosticsRegistry.entries[diagnostics.storageKey]
	sageDiagnosticsRegistry.Unlock()
	require.False(t, registered)
}

func TestSageDiagnosticsDetachedRecordNeverLoadsStoreSynchronously(t *testing.T) {
	store := &sageDiagnosticsBlockingLoadStore{
		sageDiagnosticsTestStore: newSageDiagnosticsTestStore(),
		entered:                  make(chan struct{}),
		release:                  make(chan struct{}),
	}
	diagnostics := newSageDiagnostics("detached-no-load", nil, store)
	require.Equal(t, 1, store.loadCount())
	diagnostics.mu.Lock()
	diagnostics.retired = true
	diagnostics.detached = true
	diagnostics.mu.Unlock()
	sageDiagnosticsRegistry.Lock()
	delete(sageDiagnosticsRegistry.entries, diagnostics.storageKey)
	sageDiagnosticsRegistry.current.Delete(diagnostics.storageKey)
	sageDiagnosticsRegistry.Unlock()

	done := make(chan struct{})
	go func() {
		diagnostics.record(sageDiagnosticRecord{kind: "throughput-sample", bps: 8_000_000})
		close(done)
	}()
	select {
	case <-done:
	case <-store.entered:
		close(store.release)
		<-done
		t.Fatal("record synchronously loaded persistence for a detached handle")
	case <-time.After(time.Second):
		t.Fatal("detached record blocked")
	}
	require.Equal(t, 1, store.loadCount())
	require.Equal(t, uint64(1), diagnostics.snapshot().Counters.ThroughputSamples)
}

func TestSageDiagnosticsRetiredHandleRedirectsOnlyToExplicitCurrent(t *testing.T) {
	group := "retired-redirect-" + t.Name()
	storageKey := sageDiagnosticsStorageKey(group)
	retired := newSageDiagnostics(group, nil, nil)
	current := newSageDiagnostics(group, nil, nil)

	retired.mu.Lock()
	retired.retired = true
	retired.detached = true
	retired.mu.Unlock()
	sageDiagnosticsRegistry.Lock()
	sageDiagnosticsRegistry.entries[storageKey] = current
	sageDiagnosticsRegistry.current.Store(storageKey, current)
	sageDiagnosticsRegistry.touch(current)
	sageDiagnosticsRegistry.Unlock()
	t.Cleanup(func() {
		sageDiagnosticsRegistry.Lock()
		delete(sageDiagnosticsRegistry.entries, storageKey)
		sageDiagnosticsRegistry.current.Delete(storageKey)
		sageDiagnosticsRegistry.Unlock()
	})

	retired.record(sageDiagnosticRecord{kind: "throughput-sample", bps: 8_000_000})
	require.Equal(t, uint64(1), current.snapshot().Counters.ThroughputSamples)
	require.Equal(t, uint64(1), retired.snapshot().Counters.ThroughputSamples)

	sageDiagnosticsRegistry.Lock()
	delete(sageDiagnosticsRegistry.entries, storageKey)
	sageDiagnosticsRegistry.current.Delete(storageKey)
	sageDiagnosticsRegistry.Unlock()
	current.mu.Lock()
	current.retired = true
	current.detached = true
	current.redirect = nil
	current.mu.Unlock()

	current.record(sageDiagnosticRecord{kind: "throughput-sample", bps: 4_000_000})
	require.Equal(t, uint64(2), current.snapshot().Counters.ThroughputSamples)
	current.mu.Lock()
	require.Nil(t, current.redirect)
	current.mu.Unlock()

	replacement := newSageDiagnostics(group, nil, nil)
	sageDiagnosticsRegistry.Lock()
	sageDiagnosticsRegistry.entries[storageKey] = replacement
	sageDiagnosticsRegistry.current.Store(storageKey, replacement)
	sageDiagnosticsRegistry.touch(replacement)
	sageDiagnosticsRegistry.Unlock()
	current.record(sageDiagnosticRecord{kind: "throughput-sample", bps: 2_000_000})
	require.Equal(t, uint64(1), replacement.snapshot().Counters.ThroughputSamples)
	require.Equal(t, uint64(1), current.snapshot().Counters.ThroughputSamples)
}

func TestSageMediaReconnectDetailedReasons(t *testing.T) {
	newGroup := func(t *testing.T) (*Sage, *sageConnTestClock, *sageTestProxy, *sageTestProxy, sageMediaTargetKey) {
		t.Helper()
		clock := newSageConnTestClock()
		alpha := newSageTestProxy("alpha", true, true)
		alpha.delay = 20
		beta := newSageTestProxy("beta", true, true)
		beta.delay = 10
		group, _ := newSageGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureSageMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		return group, clock, alpha, beta, sageMediaTargetKey{target: "googlevideo.com", port: 443}
	}

	t.Run("prepare cooldown", func(t *testing.T) {
		group, clock, _, _, key := newGroup(t)
		group.mediaReconnects[key] = clock.Now().Add(time.Minute)
		_, reason := group.prepareMediaReconnectDetailed(key, "rr.googlevideo.com", 443, "alpha", 1_000_000)
		require.Equal(t, "reconnect-cooldown", reason)
	})

	t.Run("prepare budget", func(t *testing.T) {
		group, clock, _, _, key := newGroup(t)
		group.mediaBudgets[key] = sageMediaBudget{startedAt: clock.Now(), count: group.media.budgetMax}
		_, reason := group.prepareMediaReconnectDetailed(key, "rr.googlevideo.com", 443, "alpha", 1_000_000)
		require.Equal(t, "budget-exhausted", reason)
	})

	t.Run("prepare candidate cooldown leaves no challenger", func(t *testing.T) {
		group, clock, _, beta, key := newGroup(t)
		group.mediaSlowCooldowns[sageMediaCandidateKey{sageMediaTargetKey: key, candidate: beta.Name(), identity: beta.identity}] = clock.Now().Add(time.Minute)
		_, reason := group.prepareMediaReconnectDetailed(key, "rr.googlevideo.com", 443, "alpha", 1_000_000)
		require.Equal(t, "no-challenger", reason)
	})

	t.Run("prepare ranks known evidence before probe-only candidates", func(t *testing.T) {
		clock := newSageConnTestClock()
		alpha := newSageTestProxy("alpha", true, true)
		beta := newSageTestProxy("beta", true, true)
		beta.delay = 30
		gamma := newSageTestProxy("gamma", true, true)
		gamma.delay = 10
		delta := newSageTestProxy("delta", true, true)
		delta.delay = 5
		group, _ := newSageGroupForTest(clock, 10, time.Hour, alpha, beta, gamma, delta)
		configureSageMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		now := clock.Now()
		group.ensureNodeLocked("beta", now)
		group.ensureNodeControlLocked("beta", now).recentTCPThroughput = sageRecentThroughput{bitsPerSecond: 5_000_000, observedAt: now}
		group.ensureNodeLocked("gamma", now)
		group.ensureNodeControlLocked("gamma", now).recentTCPThroughput = sageRecentThroughput{bitsPerSecond: 8_000_000, observedAt: now}
		plan, reason := group.prepareMediaReconnectDetailed(
			sageMediaTargetKey{target: "googlevideo.com", port: 443},
			"rr.googlevideo.com",
			443,
			"alpha",
			1_000_000,
		)
		require.Empty(t, reason)
		require.Equal(t, "gamma", plan.challenger)
	})

	commitReason := func(t *testing.T, mutate func(*Sage, *sageConnTestClock, *sageTestProxy, sageMediaPlan)) string {
		t.Helper()
		group, clock, _, beta, key := newGroup(t)
		plan, reason := group.prepareMediaReconnectDetailed(key, "rr.googlevideo.com", 443, "alpha", 1_000_000)
		require.Empty(t, reason)
		mutate(group, clock, beta, plan)
		return group.commitMediaReconnectDetailed(plan)
	}

	t.Run("plan expired", func(t *testing.T) {
		reason := commitReason(t, func(group *Sage, clock *sageConnTestClock, beta *sageTestProxy, plan sageMediaPlan) {
			clock.Advance(group.media.hintTTL + time.Second)
		})
		require.Equal(t, "plan-expired", reason)
	})

	t.Run("commit reconnect cooldown", func(t *testing.T) {
		reason := commitReason(t, func(group *Sage, clock *sageConnTestClock, beta *sageTestProxy, plan sageMediaPlan) {
			group.mediaReconnects[plan.targetKey] = clock.Now().Add(time.Minute)
		})
		require.Equal(t, "reconnect-cooldown", reason)
	})

	t.Run("candidate cooldown", func(t *testing.T) {
		reason := commitReason(t, func(group *Sage, clock *sageConnTestClock, beta *sageTestProxy, plan sageMediaPlan) {
			group.cooldowns[sageCooldownKey{transport: sageTransportTCP, target: plan.target, port: plan.port, candidate: plan.challenger}] = clock.Now().Add(time.Minute)
		})
		require.Equal(t, "candidate-cooldown", reason)
	})

	t.Run("challenger slow cooldown", func(t *testing.T) {
		reason := commitReason(t, func(group *Sage, clock *sageConnTestClock, beta *sageTestProxy, plan sageMediaPlan) {
			group.mediaSlowCooldowns[sageMediaCandidateKey{sageMediaTargetKey: plan.targetKey, candidate: plan.challenger, identity: plan.challengerIdentity}] = clock.Now().Add(time.Minute)
		})
		require.Equal(t, "challenger-slow-cooldown", reason)
	})

	t.Run("challenger evidence degraded", func(t *testing.T) {
		reason := commitReason(t, func(group *Sage, clock *sageConnTestClock, beta *sageTestProxy, plan sageMediaPlan) {
			group.ensureNodeLocked(plan.challenger, clock.Now())
			state := group.ensureNodeControlLocked(plan.challenger, clock.Now())
			state.recentTCPThroughput = sageRecentThroughput{bitsPerSecond: 100_000, observedAt: clock.Now()}
		})
		require.Equal(t, "challenger-evidence-degraded", reason)
	})

	t.Run("commit budget", func(t *testing.T) {
		reason := commitReason(t, func(group *Sage, clock *sageConnTestClock, beta *sageTestProxy, plan sageMediaPlan) {
			group.mediaBudgets[plan.targetKey] = sageMediaBudget{startedAt: clock.Now(), count: group.media.budgetMax}
		})
		require.Equal(t, "budget-exhausted", reason)
	})
}

func TestSageDiagnosticsConcurrentAccountingAndReadOnlySnapshot(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageDiagnosticsTestStore()
	diagnostics := newSageDiagnostics("sage", clock, store)

	const workers = 32
	const recordsPerWorker = 25
	var wait sync.WaitGroup
	wait.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wait.Done()
			for j := 0; j < recordsPerWorker; j++ {
				diagnostics.record(sageDiagnosticRecord{
					kind:   "buffer-credit-deferred",
					reason: "buffer-credit",
					target: "googlevideo.com",
					port:   443,
					from:   "alpha",
					force:  true,
				})
			}
		}()
	}
	wait.Wait()
	diagnostics.waitPersistence()

	before := store.writeCount()
	first := diagnostics.snapshot()
	second := diagnostics.snapshot()
	require.Equal(t, first, second)
	require.Equal(t, before, store.writeCount(), "diagnostic reads must not write or refresh persisted state")
	require.Equal(t, uint64(workers*recordsPerWorker), first.Counters.BufferCreditDeferrals)

	payload, err := store.Load(sageDiagnosticsStorageKey("sage"))
	require.NoError(t, err)
	var persisted SageDiagnosticsSnapshot
	require.NoError(t, json.Unmarshal(payload, &persisted))
	require.Equal(t, first.Counters.BufferCreditDeferrals, persisted.Counters.BufferCreditDeferrals,
		"out-of-order async flushes must never overwrite the newest cumulative snapshot")
}

func TestSageDiagnosticsCoalescesWritesWhileStoreIsBlocked(t *testing.T) {
	clock := newSageConnTestClock()
	store := &sageDiagnosticsBlockingStore{
		sageDiagnosticsTestStore: newSageDiagnosticsTestStore(),
		entered:                  make(chan struct{}),
		release:                  make(chan struct{}),
	}
	diagnostics := newSageDiagnostics("sage-coalesced", clock, store)
	diagnostics.record(sageDiagnosticRecord{kind: "reconnect-suppressed", reason: "no-challenger", force: true})
	<-store.entered
	for i := 0; i < 1000; i++ {
		diagnostics.record(sageDiagnosticRecord{kind: "reconnect-suppressed", reason: "no-challenger", force: true})
	}
	close(store.release)
	diagnostics.waitPersistence()

	require.Equal(t, 2, store.writeCount(), "one in-flight write plus one latest coalesced snapshot is sufficient")
	payload, err := store.Load(sageDiagnosticsStorageKey("sage-coalesced"))
	require.NoError(t, err)
	var persisted SageDiagnosticsSnapshot
	require.NoError(t, json.Unmarshal(payload, &persisted))
	require.Equal(t, uint64(1001), persisted.Counters.ReconnectSuppressed)
}

func TestSageDiagnosticsRegistryIsDormantUntilActivation(t *testing.T) {
	const groupName = "diagnostics-dormant-until-activation"
	key := sageDiagnosticsStorageKey(groupName)
	sageDiagnosticsRegistry.Lock()
	delete(sageDiagnosticsRegistry.entries, key)
	sageDiagnosticsRegistry.current.Delete(key)
	sageDiagnosticsRegistry.Unlock()
	t.Cleanup(func() {
		sageDiagnosticsRegistry.Lock()
		delete(sageDiagnosticsRegistry.entries, key)
		sageDiagnosticsRegistry.current.Delete(key)
		sageDiagnosticsRegistry.Unlock()
	})

	fallback := newSageTestProxy("fallback", true, false)
	provider := newSageTestProvider(newSageTestProxy("alpha", true, true))
	group, err := NewSage(GroupCommonOption{Name: groupName, URL: C.DefaultTestURL}, SageOption{}, fallback, []P.ProxyProvider{provider})
	require.NoError(t, err)
	sageDiagnosticsRegistry.Lock()
	_, registeredBefore := sageDiagnosticsRegistry.entries[key]
	sageDiagnosticsRegistry.Unlock()
	require.False(t, registeredBefore, "parse-only construction must not mutate the diagnostics registry")

	ActivateSageLearningStates(map[string]C.Proxy{groupName: A.NewProxy(group)})
	sageDiagnosticsRegistry.Lock()
	_, registeredAfter := sageDiagnosticsRegistry.entries[key]
	sageDiagnosticsRegistry.Unlock()
	require.True(t, registeredAfter)
}
