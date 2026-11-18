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

type vaneDiagnosticsTestStore struct {
	mu     sync.Mutex
	data   map[string][]byte
	writes int
}

type vaneDiagnosticsFailStore struct {
	loadErr error
	saveErr error
}

func (s vaneDiagnosticsFailStore) Load(string) ([]byte, error) { return nil, s.loadErr }
func (s vaneDiagnosticsFailStore) Save(string, []byte) error   { return s.saveErr }

type vaneDiagnosticsBlockingStore struct {
	*vaneDiagnosticsTestStore
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

type vaneDiagnosticsBlockingLoadStore struct {
	*vaneDiagnosticsTestStore
	mu      sync.Mutex
	loads   int
	entered chan struct{}
	release chan struct{}
}

type vaneDiagnosticsFlakyStore struct {
	*vaneDiagnosticsTestStore
	mu       sync.Mutex
	failures int
	attempts int
}

func (s *vaneDiagnosticsBlockingStore) Save(key string, payload []byte) error {
	s.once.Do(func() {
		close(s.entered)
		<-s.release
	})
	return s.vaneDiagnosticsTestStore.Save(key, payload)
}

func (s *vaneDiagnosticsBlockingLoadStore) Load(key string) ([]byte, error) {
	s.mu.Lock()
	s.loads++
	loads := s.loads
	s.mu.Unlock()
	if loads == 2 {
		close(s.entered)
		<-s.release
	}
	return s.vaneDiagnosticsTestStore.Load(key)
}

func (s *vaneDiagnosticsBlockingLoadStore) loadCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loads
}

func (s *vaneDiagnosticsFlakyStore) Save(key string, payload []byte) error {
	s.mu.Lock()
	s.attempts++
	if s.failures > 0 {
		s.failures--
		s.mu.Unlock()
		return errors.New("temporary save failure")
	}
	s.mu.Unlock()
	return s.vaneDiagnosticsTestStore.Save(key, payload)
}

func (s *vaneDiagnosticsFlakyStore) attemptCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

func newVaneDiagnosticsTestStore() *vaneDiagnosticsTestStore {
	return &vaneDiagnosticsTestStore{data: make(map[string][]byte)}
}

func (s *vaneDiagnosticsTestStore) Load(key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.data[key]...), nil
}

func (s *vaneDiagnosticsTestStore) Save(key string, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = append([]byte(nil), payload...)
	s.writes++
	return nil
}

func (s *vaneDiagnosticsTestStore) writeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes
}

func TestVaneDiagnosticsPersistReconnectLifecycleAndOutcome(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneDiagnosticsTestStore()
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.delay = 20
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	group.diagnostics = newVaneDiagnostics(group.Name(), clock, store)
	metadata := &C.Metadata{Host: "rr1.googlevideo.com", DstPort: 443, NetWork: C.TCP}

	flow := newVaneMediaFlow(group, "alpha", metadata)
	require.NotNil(t, flow)
	low := vaneThroughputObservation{
		BitsPerSecond: 1_000_000,
		TotalBytes:    4 * 1024 * 1024,
		Age:           20 * time.Second,
	}
	require.Nil(t, flow.observe(low))
	require.Nil(t, flow.observe(low))
	action := flow.observe(low)
	require.NotNil(t, action)
	require.True(t, action())
	selected, token := group.pickWithHandoff(metadata, vaneTransportTCP, false, true)
	require.Equal(t, "beta", selected.Name())
	require.NotNil(t, token)
	require.Equal(t, "beta", group.pick(metadata, vaneTransportTCP, false, true).Name(), "the sticky policy hint remains reusable")

	handoff := newVaneMediaFlow(group, "beta", metadata, token)
	require.NotNil(t, handoff)
	competing := newVaneMediaFlow(group, "beta", metadata)
	require.NotNil(t, competing)
	high := vaneThroughputObservation{
		BitsPerSecond: 8_000_000,
		TotalBytes:    8 * 1024 * 1024,
		Age:           5 * time.Second,
	}
	require.Nil(t, competing.observe(high))
	require.Zero(t, group.VaneDiagnostics().Counters.HandoffMeasured, "an unrelated same-target flow must not consume the handoff outcome")
	require.Nil(t, handoff.observe(high))

	snapshot := group.VaneDiagnostics()
	require.Equal(t, VaneDiagnosticsSchemaVersion, snapshot.SchemaVersion)
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
	restored := newVaneDiagnostics(group.Name(), clock, store).snapshot()
	require.Equal(t, snapshot.Counters, restored.Counters)
	require.Equal(t, snapshot.Suppressions, restored.Suppressions)
	require.Equal(t, snapshot.Rejections, restored.Rejections)
	require.Equal(t, snapshot.RecentEvents, restored.RecentEvents)
}

func TestVaneDiagnosticsProductionReasons(t *testing.T) {
	t.Run("buffer credit defer", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		beta.delay = 10
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		group.media.demandBPS = 10_000_000
		group.media.bufferGuard = 3 * time.Second
		flow := newVaneMediaFlow(group, "alpha", &C.Metadata{Host: "rr2.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		low := vaneThroughputObservation{BitsPerSecond: 1_000_000, TotalBytes: 512 * 1024, Age: 20 * time.Second}
		require.Nil(t, flow.observe(low))
		require.Nil(t, flow.observe(low))
		require.Nil(t, flow.observe(low))

		snapshot := group.VaneDiagnostics()
		require.Equal(t, uint64(1), snapshot.Counters.BufferCreditDeferrals)
		require.Equal(t, "buffer-credit", snapshot.RecentEvents[len(snapshot.RecentEvents)-1].Reason)
	})

	t.Run("no challenger suppression", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		beta.delay = 0
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		flow := newVaneMediaFlow(group, "alpha", &C.Metadata{Host: "rr3.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		low := vaneThroughputObservation{BitsPerSecond: 1_000_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second}
		require.Nil(t, flow.observe(low))
		require.Nil(t, flow.observe(low))
		require.Nil(t, flow.observe(low))

		snapshot := group.VaneDiagnostics()
		require.Equal(t, uint64(1), snapshot.Counters.ReconnectSuppressed)
		require.Equal(t, uint64(1), snapshot.Suppressions["no-challenger"])
	})

	t.Run("commit rejection", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		beta.delay = 10
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		flow := newVaneMediaFlow(group, "alpha", &C.Metadata{Host: "rr4.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		low := vaneThroughputObservation{BitsPerSecond: 1_000_000, TotalBytes: 4 * 1024 * 1024, Age: 20 * time.Second}
		require.Nil(t, flow.observe(low))
		require.Nil(t, flow.observe(low))
		action := flow.observe(low)
		require.NotNil(t, action)
		beta.alive = false
		require.False(t, action())

		snapshot := group.VaneDiagnostics()
		require.Equal(t, uint64(1), snapshot.Counters.ReconnectRejected)
		require.Equal(t, uint64(1), snapshot.Rejections["challenger-unhealthy"])
	})
}

func TestVaneDiagnosticsSamplePersistenceIsRateLimited(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneDiagnosticsTestStore()
	diagnostics := newVaneDiagnostics("vane", clock, store)

	for i := 0; i < 100; i++ {
		diagnostics.record(vaneDiagnosticRecord{kind: "throughput-sample", bps: 8_000_000})
	}
	require.Zero(t, store.writeCount(), "hot-path samples must not write the cache on every window")
	clock.Advance(vaneDiagnosticsPersistInterval)
	diagnostics.record(vaneDiagnosticRecord{kind: "throughput-sample", bps: 8_000_000})
	diagnostics.waitPersistence()
	require.Equal(t, 1, store.writeCount())
}

func TestVaneDiagnosticsIdleSamplesFlushAfterBoundedDelay(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneDiagnosticsTestStore()
	diagnostics := newVaneDiagnostics("idle-flush", clock, store)
	diagnostics.persistInterval = 10 * time.Millisecond

	diagnostics.record(vaneDiagnosticRecord{kind: "throughput-sample", bps: 8_000_000})
	require.Eventually(t, func() bool { return store.writeCount() == 1 }, time.Second, time.Millisecond)
	diagnostics.waitPersistence()
	restored := newVaneDiagnostics("idle-flush", clock, store).snapshot()
	require.Equal(t, uint64(1), restored.Counters.ThroughputSamples)
}

func TestVaneDiagnosticsHandoffDialFailureIsAttributed(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	beta.dialErr = errors.New("dial failed")
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	metadata := &C.Metadata{Host: "rr-fail.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	targetKey := group.mediaTargetKey(metadata.Host, metadata.DstPort)

	handoff := group.diagnostics.recordReconnectCommit(vaneDiagnosticRecord{
		target: metadata.Host,
		bucket: targetKey.target,
		port:   metadata.DstPort,
		from:   "alpha",
		to:     "beta",
		bps:    1_000_000,
	})
	group.mediaHints[targetKey] = vaneMediaHint{candidate: "beta", expiresAt: clock.Now().Add(time.Minute), handoff: handoff}

	_, err := group.DialContext(context.Background(), metadata)
	require.Error(t, err)
	snapshot := group.VaneDiagnostics()
	require.Equal(t, uint64(1), snapshot.Counters.HandoffDialFailed)
	last := snapshot.RecentEvents[len(snapshot.RecentEvents)-1]
	require.Equal(t, "handoff-dial-failed", last.Kind)
	require.NotZero(t, last.HandoffID)
	require.Equal(t, "alpha", last.From)
	require.Equal(t, "beta", last.To)
}

func TestVaneDiagnosticsHandoffFirstWriteFailureIsAttributed(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	beta.dialConn = &vaneEarlyTestConn{vaneConnTestConn: &vaneConnTestConn{
		writeFunc: func([]byte) (int, error) { return 0, errVaneTestWrite },
	}}
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	metadata := &C.Metadata{Host: "rr-write-fail.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	targetKey := group.mediaTargetKey(metadata.Host, metadata.DstPort)
	handoff := group.diagnostics.recordReconnectCommit(vaneDiagnosticRecord{
		target: metadata.Host, bucket: targetKey.target,
		port: metadata.DstPort, from: "alpha", to: "beta", bps: 1_000_000,
	})
	group.mediaHints[targetKey] = vaneMediaHint{candidate: "beta", expiresAt: clock.Now().Add(time.Minute), handoff: handoff}

	conn, err := group.DialContext(context.Background(), metadata)
	require.NoError(t, err)
	_, err = conn.Write([]byte("request"))
	require.ErrorIs(t, err, errVaneTestWrite)
	snapshot := group.VaneDiagnostics()
	require.Equal(t, uint64(1), snapshot.Counters.HandoffDialFailed)
	last := snapshot.RecentEvents[len(snapshot.RecentEvents)-1]
	require.Equal(t, "handoff-dial-failed", last.Kind)
	require.Equal(t, "first-write-failed", last.Reason)
	require.NotZero(t, last.HandoffID)
}

func TestVaneDiagnosticsReadDoesNotPrunePolicyState(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	key := vaneMediaTargetKey{target: "googlevideo.com", port: 443}
	expired := clock.Now().Add(-time.Second)
	group.mediaHints[key] = vaneMediaHint{candidate: "alpha", expiresAt: expired}
	group.mediaReconnects[key] = expired
	group.mediaSlowCooldowns[vaneMediaCandidateKey{vaneMediaTargetKey: key, candidate: "alpha"}] = expired
	group.mediaBudgets[key] = vaneMediaBudget{startedAt: clock.Now().Add(-group.media.budgetWindow)}

	first := group.VaneDiagnostics()
	second := group.VaneDiagnostics()
	require.Equal(t, first, second)
	require.Equal(t, VaneDiagnosticRuntime{}, first.Runtime)
	require.Len(t, group.mediaHints, 1)
	require.Len(t, group.mediaReconnects, 1)
	require.Len(t, group.mediaSlowCooldowns, 1)
	require.Len(t, group.mediaBudgets, 1)
}

func TestVaneDiagnosticsReasonsAreVisibleAndBounded(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneDiagnosticsTestStore()
	diagnostics := newVaneDiagnostics("vane", clock, store)

	for i := 0; i < vaneDiagnosticsRecentEventLimit+20; i++ {
		diagnostics.record(vaneDiagnosticRecord{
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
	require.Len(t, snapshot.RecentEvents, vaneDiagnosticsRecentEventLimit)
	require.Equal(t, uint64(vaneDiagnosticsRecentEventLimit+20), snapshot.Counters.ReconnectSuppressed)
	require.Equal(t, uint64(vaneDiagnosticsRecentEventLimit+20), snapshot.Suppressions["no-challenger"])
	for i := 1; i < len(snapshot.RecentEvents); i++ {
		require.Greater(t, snapshot.RecentEvents[i].Sequence, snapshot.RecentEvents[i-1].Sequence)
	}
}

func TestVaneDiagnosticsRestoreValidationAndNilSafety(t *testing.T) {
	clock := newVaneConnTestClock()
	key := vaneDiagnosticsStorageKey("vane")

	for name, payload := range map[string][]byte{
		"invalid json": []byte("{"),
		"wrong schema": []byte(`{"schemaVersion":99,"group":"vane"}`),
		"wrong group":  []byte(`{"schemaVersion":1,"group":"other"}`),
	} {
		t.Run(name, func(t *testing.T) {
			store := newVaneDiagnosticsTestStore()
			store.data[key] = payload
			snapshot := newVaneDiagnostics("vane", clock, store).snapshot()
			require.Equal(t, VaneDiagnosticsSchemaVersion, snapshot.SchemaVersion)
			require.Equal(t, "vane", snapshot.Group)
			require.Empty(t, snapshot.RecentEvents)
		})
	}

	events := make([]VaneDiagnosticEvent, vaneDiagnosticsRecentEventLimit+3)
	for i := range events {
		events[i] = VaneDiagnosticEvent{Sequence: uint64(i + 1)}
	}
	payload, err := json.Marshal(VaneDiagnosticsSnapshot{
		SchemaVersion: VaneDiagnosticsSchemaVersion,
		Group:         "vane",
		RecentEvents:  events,
	})
	require.NoError(t, err)
	store := newVaneDiagnosticsTestStore()
	store.data[key] = payload
	restored := newVaneDiagnostics("vane", clock, store).snapshot()
	require.Len(t, restored.RecentEvents, vaneDiagnosticsRecentEventLimit)
	require.Equal(t, uint64(4), restored.RecentEvents[0].Sequence)
	require.NotNil(t, restored.Suppressions)
	require.NotNil(t, restored.Rejections)

	defaultClock := newVaneDiagnostics("vane", nil, nil)
	require.NotNil(t, defaultClock)
	defaultClock.record(vaneDiagnosticRecord{kind: "future-event", reason: "unknown"})
	require.Equal(t, "future-event", defaultClock.snapshot().RecentEvents[0].Kind)

	var nilDiagnostics *vaneDiagnostics
	nilDiagnostics.record(vaneDiagnosticRecord{kind: "ignored"})
	require.Equal(t, VaneDiagnosticsSnapshot{}, nilDiagnostics.snapshot())
}

func TestVaneDiagnosticsExposePersistenceFailure(t *testing.T) {
	clock := newVaneConnTestClock()
	loadFailure := newVaneDiagnostics("load-failure", clock, vaneDiagnosticsFailStore{loadErr: errors.New("load unavailable")})
	loadSnapshot := loadFailure.snapshot()
	require.False(t, loadSnapshot.Persistence.Available)
	require.Contains(t, loadSnapshot.Persistence.LastError, "load unavailable")

	saveFailure := newVaneDiagnostics("save-failure", clock, vaneDiagnosticsFailStore{saveErr: errors.New("save unavailable")})
	require.True(t, saveFailure.snapshot().Persistence.Available)
	saveFailure.record(vaneDiagnosticRecord{kind: "reconnect-suppressed", reason: "no-challenger", force: true})
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

func TestVaneDiagnosticsRetriesTransientPersistenceFailure(t *testing.T) {
	clock := newVaneConnTestClock()
	store := &vaneDiagnosticsFlakyStore{
		vaneDiagnosticsTestStore: newVaneDiagnosticsTestStore(),
		failures:                 1,
	}
	diagnostics := newVaneDiagnostics("save-retry", clock, store)
	diagnostics.persistInterval = 5 * time.Millisecond
	diagnostics.record(vaneDiagnosticRecord{kind: "reconnect-suppressed", reason: "no-challenger", force: true})

	require.Eventually(t, func() bool { return store.writeCount() == 1 }, time.Second, time.Millisecond)
	diagnostics.waitPersistence()
	require.GreaterOrEqual(t, store.attemptCount(), 2)
	snapshot := diagnostics.snapshot()
	require.True(t, snapshot.Persistence.Available)
	require.Empty(t, snapshot.Persistence.LastError)
	restored := newVaneDiagnostics("save-retry", clock, store).snapshot()
	require.Equal(t, uint64(1), restored.Counters.ReconnectSuppressed)
}

func TestVaneDiagnosticsPersistenceFailureBacksOffForcedEvents(t *testing.T) {
	clock := newVaneConnTestClock()
	store := &vaneDiagnosticsFlakyStore{
		vaneDiagnosticsTestStore: newVaneDiagnosticsTestStore(),
		failures:                 1,
	}
	diagnostics := newVaneDiagnostics("save-backoff", clock, store)
	diagnostics.persistInterval = 100 * time.Millisecond
	diagnostics.record(vaneDiagnosticRecord{kind: "reconnect-suppressed", reason: "no-challenger", force: true})
	diagnostics.waitPersistence()
	require.Equal(t, 1, store.attemptCount())

	for i := 0; i < 16; i++ {
		diagnostics.record(vaneDiagnosticRecord{kind: "reconnect-suppressed", reason: "no-challenger", force: true})
	}
	time.Sleep(20 * time.Millisecond)
	require.Equal(t, 1, store.attemptCount(), "forced events must coalesce behind the retry backoff")
	require.Eventually(t, func() bool { return store.writeCount() == 1 }, time.Second, time.Millisecond)
	diagnostics.waitPersistence()
	require.Equal(t, 2, store.attemptCount())
	require.Equal(t, uint64(17), newVaneDiagnostics("save-backoff", clock, store).snapshot().Counters.ReconnectSuppressed)
}

func TestVaneDiagnosticsExpiredHintDoesNotExposeHandoff(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	metadata := &C.Metadata{Host: "rr-expired.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	key := group.mediaTargetKey(metadata.Host, metadata.DstPort)
	handoff := group.diagnostics.recordReconnectCommit(vaneDiagnosticRecord{
		target: metadata.Host, bucket: key.target, port: metadata.DstPort,
		from: "alpha", to: "beta", bps: 1_000_000,
	})
	group.mediaHints[key] = vaneMediaHint{candidate: "beta", expiresAt: clock.Now().Add(time.Second), handoff: handoff}
	clock.Advance(2 * time.Second)

	_, claimed := group.pickWithHandoff(metadata, vaneTransportTCP, false, true)
	require.Nil(t, claimed)
	require.Zero(t, group.VaneDiagnostics().Counters.HandoffSelections)
}

func TestVaneDiagnosticsHandoffIdentityIsBoundToEachGenerationHint(t *testing.T) {
	clock := newVaneConnTestClock()
	shared := newVaneDiagnostics("reload-shared", clock, newVaneDiagnosticsTestStore())
	newGroup := func() *Vane {
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		group.diagnostics = shared
		return group
	}
	oldGeneration := newGroup()
	newGeneration := newGroup()
	metadata := &C.Metadata{Host: "rr-reload.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	key := oldGeneration.mediaTargetKey(metadata.Host, metadata.DstPort)
	plan := vaneMediaPlan{
		targetKey: key, target: metadata.Host, port: metadata.DstPort,
		current: "alpha", challenger: "beta", currentBPS: 1_000_000, preparedAt: clock.Now(),
	}

	require.Empty(t, oldGeneration.commitMediaReconnectDetailed(plan))
	require.Empty(t, newGeneration.commitMediaReconnectDetailed(plan))
	oldProxy, oldHandoff := oldGeneration.pickWithHandoff(metadata, vaneTransportTCP, false, true)
	newProxy, newHandoff := newGeneration.pickWithHandoff(metadata, vaneTransportTCP, false, true)
	require.Equal(t, "beta", oldProxy.Name())
	require.Equal(t, "beta", newProxy.Name())
	require.NotNil(t, oldHandoff)
	require.NotNil(t, newHandoff)
	require.NotEqual(t, oldHandoff.id, newHandoff.id)
	require.Equal(t, "alpha", oldHandoff.from)
	require.Equal(t, "alpha", newHandoff.from)
	require.Equal(t, uint64(2), shared.snapshot().Counters.ReconnectCommitted)
}

func TestVaneDiagnosticsHandoffIdentityRequiresExactTarget(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	origin := &C.Metadata{Host: "rr-origin.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	unrelated := &C.Metadata{Host: "rr-unrelated.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	key := group.mediaTargetKey(origin.Host, origin.DstPort)
	handoff := group.diagnostics.recordReconnectCommit(vaneDiagnosticRecord{
		target: origin.Host, bucket: key.target, port: origin.DstPort,
		from: "alpha", to: "beta", bps: 1_000_000,
	})
	group.mediaHints[key] = vaneMediaHint{candidate: "beta", expiresAt: clock.Now().Add(time.Minute), handoff: handoff}

	proxy, claimed := group.pickWithHandoff(unrelated, vaneTransportTCP, false, true)
	require.Equal(t, "beta", proxy.Name(), "bucket-level sticky candidate remains reusable")
	require.Nil(t, claimed, "another exact target must not steal the diagnostic identity")
	proxy, claimed = group.pickWithHandoff(origin, vaneTransportTCP, false, true)
	require.Equal(t, "beta", proxy.Name())
	require.Same(t, handoff, claimed)
}

func TestVaneDiagnosticsHandoffIdentityAcceptsRootDotEquivalentTarget(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	beta := newVaneTestProxy("beta", true, true)
	alpha.dialConn = &vaneConnTestConn{}
	beta.dialConn = &vaneConnTestConn{}
	alphaDialed := false
	betaDialed := false
	alpha.dialHook = func() { alphaDialed = true }
	beta.dialHook = func() { betaDialed = true }
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	origin := &C.Metadata{Host: "googlevideo.com", DstPort: 443, NetWork: C.TCP}
	rootDot := &C.Metadata{Host: "GOOGLEVIDEO.COM.", DstPort: 443, NetWork: C.TCP}
	key := group.mediaTargetKey(origin.Host, origin.DstPort)
	handoff := group.diagnostics.recordReconnectCommit(vaneDiagnosticRecord{
		target: origin.Host, bucket: key.target, port: origin.DstPort,
		from: "alpha", to: "beta", bps: 1_000_000,
	})
	group.mediaHints[key] = vaneMediaHint{candidate: "beta", expiresAt: clock.Now().Add(time.Minute), handoff: handoff}

	conn, err := group.DialContext(context.Background(), rootDot)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.False(t, alphaDialed)
	require.True(t, betaDialed)
	require.Equal(t, uint64(1), group.VaneDiagnostics().Counters.HandoffSelections)
}

func TestVaneDiagnosticsNeutralHandoffFailuresAreNotCounted(t *testing.T) {
	t.Run("dial canceled", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		beta.dialErr = context.Canceled
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		metadata := &C.Metadata{Host: "rr-canceled.googlevideo.com", DstPort: 443, NetWork: C.TCP}
		key := group.mediaTargetKey(metadata.Host, metadata.DstPort)
		handoff := group.diagnostics.recordReconnectCommit(vaneDiagnosticRecord{
			target: metadata.Host, bucket: key.target, port: metadata.DstPort,
			from: "alpha", to: "beta", bps: 1_000_000,
		})
		group.mediaHints[key] = vaneMediaHint{candidate: "beta", expiresAt: clock.Now().Add(time.Minute), handoff: handoff}

		_, err := group.DialContext(context.Background(), metadata)
		require.ErrorIs(t, err, context.Canceled)
		require.Zero(t, group.VaneDiagnostics().Counters.HandoffDialFailed)
	})

	t.Run("first write closed pipe", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		beta.dialConn = &vaneEarlyTestConn{vaneConnTestConn: &vaneConnTestConn{
			writeFunc: func([]byte) (int, error) { return 0, io.ErrClosedPipe },
		}}
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		metadata := &C.Metadata{Host: "rr-closed.googlevideo.com", DstPort: 443, NetWork: C.TCP}
		key := group.mediaTargetKey(metadata.Host, metadata.DstPort)
		handoff := group.diagnostics.recordReconnectCommit(vaneDiagnosticRecord{
			target: metadata.Host, bucket: key.target, port: metadata.DstPort,
			from: "alpha", to: "beta", bps: 1_000_000,
		})
		group.mediaHints[key] = vaneMediaHint{candidate: "beta", expiresAt: clock.Now().Add(time.Minute), handoff: handoff}

		conn, err := group.DialContext(context.Background(), metadata)
		require.NoError(t, err)
		_, err = conn.Write([]byte("request"))
		require.ErrorIs(t, err, io.ErrClosedPipe)
		require.Zero(t, group.VaneDiagnostics().Counters.HandoffDialFailed)
	})
}

func TestVaneDiagnosticsRegistryIsLRUBounded(t *testing.T) {
	registry := vaneDiagnosticsRegistryState{entries: make(map[string]*vaneDiagnostics)}
	var first *vaneDiagnostics
	for i := 0; i < vaneDiagnosticsRegistryLimit; i++ {
		diagnostics := newVaneDiagnostics(fmt.Sprintf("bounded-%03d", i), nil, nil)
		if i == 0 {
			first = diagnostics
		}
		registry.Lock()
		registry.addLocked(diagnostics.storageKey, diagnostics)
		registry.Unlock()
	}
	registry.touch(first)
	extra := newVaneDiagnostics("bounded-extra", nil, nil)
	registry.Lock()
	registry.addLocked(extra.storageKey, extra)
	count := len(registry.entries)
	_, keptFirst := registry.entries[first.storageKey]
	_, evictedSecond := registry.entries[vaneDiagnosticsStorageKey("bounded-001")]
	registry.Unlock()

	require.Equal(t, vaneDiagnosticsRegistryLimit, count)
	require.True(t, keptFirst)
	require.False(t, evictedSecond)
}

func TestVaneDiagnosticsRegistryEvictionFlushesDirtySnapshot(t *testing.T) {
	registry := vaneDiagnosticsRegistryState{entries: make(map[string]*vaneDiagnostics)}
	store := newVaneDiagnosticsTestStore()
	dirty := newVaneDiagnostics("dirty-oldest", nil, store)
	registry.Lock()
	registry.addLocked(dirty.storageKey, dirty)
	registry.Unlock()
	dirty.mu.Lock()
	dirty.recordLocked(vaneDiagnosticRecord{kind: "throughput-sample", bps: 8_000_000})
	dirty.mu.Unlock()
	require.Zero(t, store.writeCount())

	for i := 1; i <= vaneDiagnosticsRegistryLimit; i++ {
		diagnostics := newVaneDiagnostics(fmt.Sprintf("dirty-%03d", i), nil, nil)
		registry.Lock()
		registry.addLocked(diagnostics.storageKey, diagnostics)
		registry.Unlock()
	}

	require.Equal(t, 1, store.writeCount())
	restored := newVaneDiagnostics("dirty-oldest", nil, store).snapshot()
	require.Equal(t, uint64(1), restored.Counters.ThroughputSamples)
}

func TestVaneDiagnosticsRegistryEvictionPersistsRecordsArrivingDuringRetirement(t *testing.T) {
	registry := vaneDiagnosticsRegistryState{entries: make(map[string]*vaneDiagnostics)}
	store := &vaneDiagnosticsBlockingStore{
		vaneDiagnosticsTestStore: newVaneDiagnosticsTestStore(),
		entered:                  make(chan struct{}),
		release:                  make(chan struct{}),
	}
	victim := newVaneDiagnostics("retiring-writer", nil, store)
	victim.persistInterval = time.Hour
	registry.Lock()
	require.True(t, registry.addLocked(victim.storageKey, victim))
	registry.Unlock()
	victim.mu.Lock()
	victim.recordLocked(vaneDiagnosticRecord{kind: "throughput-sample", bps: 8_000_000})
	victim.mu.Unlock()
	for i := 1; i < vaneDiagnosticsRegistryLimit; i++ {
		diagnostics := newVaneDiagnostics(fmt.Sprintf("retiring-%03d", i), nil, nil)
		registry.Lock()
		require.True(t, registry.addLocked(diagnostics.storageKey, diagnostics))
		registry.Unlock()
	}

	extra := newVaneDiagnostics("retiring-extra", nil, nil)
	registered := make(chan bool, 1)
	go func() {
		registry.Lock()
		registered <- registry.addLocked(extra.storageKey, extra)
		registry.Unlock()
	}()
	<-store.entered
	victim.record(vaneDiagnosticRecord{kind: "throughput-sample", bps: 4_000_000})
	close(store.release)
	require.True(t, <-registered)

	restored := newVaneDiagnostics("retiring-writer", nil, store).snapshot()
	require.Equal(t, uint64(2), restored.Counters.ThroughputSamples)
	victim.mu.Lock()
	require.True(t, victim.retired)
	require.True(t, victim.detached)
	require.False(t, victim.snapshotData.Persistence.Available)
	victim.mu.Unlock()
}

func TestVaneDiagnosticsRegistryKeepsVictimWhenEvictionFlushFails(t *testing.T) {
	registry := vaneDiagnosticsRegistryState{entries: make(map[string]*vaneDiagnostics)}
	store := &vaneDiagnosticsFlakyStore{
		vaneDiagnosticsTestStore: newVaneDiagnosticsTestStore(),
		failures:                 1,
	}
	victim := newVaneDiagnostics("failed-victim", nil, store)
	victim.persistInterval = time.Hour
	registry.Lock()
	require.True(t, registry.addLocked(victim.storageKey, victim))
	registry.Unlock()
	victim.mu.Lock()
	victim.recordLocked(vaneDiagnosticRecord{kind: "throughput-sample", bps: 8_000_000})
	victim.mu.Unlock()

	for i := 1; i < vaneDiagnosticsRegistryLimit; i++ {
		diagnostics := newVaneDiagnostics(fmt.Sprintf("failed-%03d", i), nil, nil)
		registry.Lock()
		require.True(t, registry.addLocked(diagnostics.storageKey, diagnostics))
		registry.Unlock()
	}
	extra := newVaneDiagnostics("failed-extra", nil, nil)
	registry.Lock()
	registered := registry.addLocked(extra.storageKey, extra)
	_, victimKept := registry.entries[victim.storageKey]
	_, extraAdded := registry.entries[extra.storageKey]
	count := len(registry.entries)
	registry.Unlock()

	require.False(t, registered)
	require.True(t, victimKept)
	require.False(t, extraAdded)
	require.Equal(t, vaneDiagnosticsRegistryLimit, count)
	victim.mu.Lock()
	require.False(t, victim.retired)
	require.False(t, victim.retiring)
	require.NotNil(t, victim.persistTimer)
	victim.persistTimer.Stop()
	victim.persistTimer = nil
	victim.mu.Unlock()
	require.Equal(t, 1, store.attemptCount())
}

func TestVaneDiagnosticsDetachedGenerationCannotOverwriteNewerPersistedState(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneDiagnosticsTestStore()
	group := "retired-latest-" + t.Name()
	key := vaneDiagnosticsStorageKey(group)
	stale := newVaneDiagnostics(group, clock, store)
	stale.record(vaneDiagnosticRecord{kind: "reconnect-suppressed", reason: "first", force: true})
	stale.waitPersistence()
	newer := newVaneDiagnostics(group, clock, store)
	newer.record(vaneDiagnosticRecord{kind: "reconnect-suppressed", reason: "second", force: true})
	newer.waitPersistence()

	stale.mu.Lock()
	stale.retired = true
	stale.detached = true
	stale.store = nil
	stale.snapshotData.Persistence.Available = false
	stale.snapshotData.Persistence.LastError = "diagnostics registry entry evicted"
	stale.mu.Unlock()
	vaneDiagnosticsRegistry.Lock()
	delete(vaneDiagnosticsRegistry.entries, key)
	vaneDiagnosticsRegistry.current.Delete(key)
	vaneDiagnosticsRegistry.Unlock()
	t.Cleanup(func() {
		vaneDiagnosticsRegistry.Lock()
		delete(vaneDiagnosticsRegistry.entries, key)
		vaneDiagnosticsRegistry.current.Delete(key)
		vaneDiagnosticsRegistry.Unlock()
	})

	stale.record(vaneDiagnosticRecord{kind: "reconnect-suppressed", reason: "detached"})
	restored := newVaneDiagnostics(group, clock, store).snapshot()
	require.Equal(t, uint64(2), restored.Counters.ReconnectSuppressed)
	require.Zero(t, restored.Suppressions["detached"])

	current := newVaneDiagnostics(group, clock, store)
	vaneDiagnosticsRegistry.Lock()
	require.True(t, vaneDiagnosticsRegistry.addLocked(key, current))
	vaneDiagnosticsRegistry.Unlock()
	stale.record(vaneDiagnosticRecord{kind: "reconnect-suppressed", reason: "redirected", force: true})
	current.waitPersistence()
	restored = newVaneDiagnostics(group, clock, store).snapshot()
	require.Equal(t, uint64(3), restored.Counters.ReconnectSuppressed)
	require.Equal(t, uint64(1), restored.Suppressions["first"])
	require.Equal(t, uint64(1), restored.Suppressions["second"])
	require.Equal(t, uint64(1), restored.Suppressions["redirected"])
}

func TestVaneDiagnosticsSnapshotDoesNotReactivateRetiredState(t *testing.T) {
	diagnostics := newVaneDiagnostics("retired-read-only", nil, nil)
	diagnostics.record(vaneDiagnosticRecord{kind: "throughput-sample", bps: 8_000_000})
	diagnostics.mu.Lock()
	diagnostics.retired = true
	diagnostics.mu.Unlock()
	vaneDiagnosticsRegistry.Lock()
	delete(vaneDiagnosticsRegistry.entries, diagnostics.storageKey)
	vaneDiagnosticsRegistry.current.Delete(diagnostics.storageKey)
	vaneDiagnosticsRegistry.Unlock()

	first := diagnostics.snapshot()
	second := diagnostics.snapshot()
	require.Equal(t, first, second)
	require.Equal(t, uint64(1), first.Counters.ThroughputSamples)
	diagnostics.mu.Lock()
	require.True(t, diagnostics.retired)
	require.Nil(t, diagnostics.redirect)
	diagnostics.mu.Unlock()
	vaneDiagnosticsRegistry.Lock()
	_, registered := vaneDiagnosticsRegistry.entries[diagnostics.storageKey]
	vaneDiagnosticsRegistry.Unlock()
	require.False(t, registered)
}

func TestVaneDiagnosticsDetachedRecordNeverLoadsStoreSynchronously(t *testing.T) {
	store := &vaneDiagnosticsBlockingLoadStore{
		vaneDiagnosticsTestStore: newVaneDiagnosticsTestStore(),
		entered:                  make(chan struct{}),
		release:                  make(chan struct{}),
	}
	diagnostics := newVaneDiagnostics("detached-no-load", nil, store)
	require.Equal(t, 1, store.loadCount())
	diagnostics.mu.Lock()
	diagnostics.retired = true
	diagnostics.detached = true
	diagnostics.mu.Unlock()
	vaneDiagnosticsRegistry.Lock()
	delete(vaneDiagnosticsRegistry.entries, diagnostics.storageKey)
	vaneDiagnosticsRegistry.current.Delete(diagnostics.storageKey)
	vaneDiagnosticsRegistry.Unlock()

	done := make(chan struct{})
	go func() {
		diagnostics.record(vaneDiagnosticRecord{kind: "throughput-sample", bps: 8_000_000})
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

func TestVaneDiagnosticsRetiredHandleRedirectsOnlyToExplicitCurrent(t *testing.T) {
	group := "retired-redirect-" + t.Name()
	storageKey := vaneDiagnosticsStorageKey(group)
	retired := newVaneDiagnostics(group, nil, nil)
	current := newVaneDiagnostics(group, nil, nil)

	retired.mu.Lock()
	retired.retired = true
	retired.detached = true
	retired.mu.Unlock()
	vaneDiagnosticsRegistry.Lock()
	vaneDiagnosticsRegistry.entries[storageKey] = current
	vaneDiagnosticsRegistry.current.Store(storageKey, current)
	vaneDiagnosticsRegistry.touch(current)
	vaneDiagnosticsRegistry.Unlock()
	t.Cleanup(func() {
		vaneDiagnosticsRegistry.Lock()
		delete(vaneDiagnosticsRegistry.entries, storageKey)
		vaneDiagnosticsRegistry.current.Delete(storageKey)
		vaneDiagnosticsRegistry.Unlock()
	})

	retired.record(vaneDiagnosticRecord{kind: "throughput-sample", bps: 8_000_000})
	require.Equal(t, uint64(1), current.snapshot().Counters.ThroughputSamples)
	require.Equal(t, uint64(1), retired.snapshot().Counters.ThroughputSamples)

	vaneDiagnosticsRegistry.Lock()
	delete(vaneDiagnosticsRegistry.entries, storageKey)
	vaneDiagnosticsRegistry.current.Delete(storageKey)
	vaneDiagnosticsRegistry.Unlock()
	current.mu.Lock()
	current.retired = true
	current.detached = true
	current.redirect = nil
	current.mu.Unlock()

	current.record(vaneDiagnosticRecord{kind: "throughput-sample", bps: 4_000_000})
	require.Equal(t, uint64(2), current.snapshot().Counters.ThroughputSamples)
	current.mu.Lock()
	require.Nil(t, current.redirect)
	current.mu.Unlock()

	replacement := newVaneDiagnostics(group, nil, nil)
	vaneDiagnosticsRegistry.Lock()
	vaneDiagnosticsRegistry.entries[storageKey] = replacement
	vaneDiagnosticsRegistry.current.Store(storageKey, replacement)
	vaneDiagnosticsRegistry.touch(replacement)
	vaneDiagnosticsRegistry.Unlock()
	current.record(vaneDiagnosticRecord{kind: "throughput-sample", bps: 2_000_000})
	require.Equal(t, uint64(1), replacement.snapshot().Counters.ThroughputSamples)
	require.Equal(t, uint64(1), current.snapshot().Counters.ThroughputSamples)
}

func TestVaneMediaReconnectDetailedReasons(t *testing.T) {
	newGroup := func(t *testing.T) (*Vane, *vaneConnTestClock, *vaneTestProxy, *vaneTestProxy, vaneMediaTargetKey) {
		t.Helper()
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		alpha.delay = 20
		beta := newVaneTestProxy("beta", true, true)
		beta.delay = 10
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		return group, clock, alpha, beta, vaneMediaTargetKey{target: "googlevideo.com", port: 443}
	}

	t.Run("prepare cooldown", func(t *testing.T) {
		group, clock, _, _, key := newGroup(t)
		group.mediaReconnects[key] = clock.Now().Add(time.Minute)
		_, reason := group.prepareMediaReconnectDetailed(key, "rr.googlevideo.com", 443, "alpha", 1_000_000)
		require.Equal(t, "reconnect-cooldown", reason)
	})

	t.Run("prepare budget", func(t *testing.T) {
		group, clock, _, _, key := newGroup(t)
		group.mediaBudgets[key] = vaneMediaBudget{startedAt: clock.Now(), count: group.media.budgetMax}
		_, reason := group.prepareMediaReconnectDetailed(key, "rr.googlevideo.com", 443, "alpha", 1_000_000)
		require.Equal(t, "budget-exhausted", reason)
	})

	t.Run("prepare candidate cooldown leaves no challenger", func(t *testing.T) {
		group, clock, _, beta, key := newGroup(t)
		group.mediaSlowCooldowns[vaneMediaCandidateKey{vaneMediaTargetKey: key, candidate: beta.Name(), identity: beta.identity}] = clock.Now().Add(time.Minute)
		_, reason := group.prepareMediaReconnectDetailed(key, "rr.googlevideo.com", 443, "alpha", 1_000_000)
		require.Equal(t, "no-challenger", reason)
	})

	t.Run("prepare ranks known evidence before probe-only candidates", func(t *testing.T) {
		clock := newVaneConnTestClock()
		alpha := newVaneTestProxy("alpha", true, true)
		beta := newVaneTestProxy("beta", true, true)
		beta.delay = 30
		gamma := newVaneTestProxy("gamma", true, true)
		gamma.delay = 10
		delta := newVaneTestProxy("delta", true, true)
		delta.delay = 5
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta, gamma, delta)
		configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
		now := clock.Now()
		group.ensureNodeLocked("beta", now)
		group.ensureNodeControlLocked("beta", now).recentTCPThroughput = vaneRecentThroughput{bitsPerSecond: 5_000_000, observedAt: now}
		group.ensureNodeLocked("gamma", now)
		group.ensureNodeControlLocked("gamma", now).recentTCPThroughput = vaneRecentThroughput{bitsPerSecond: 8_000_000, observedAt: now}
		plan, reason := group.prepareMediaReconnectDetailed(
			vaneMediaTargetKey{target: "googlevideo.com", port: 443},
			"rr.googlevideo.com",
			443,
			"alpha",
			1_000_000,
		)
		require.Empty(t, reason)
		require.Equal(t, "gamma", plan.challenger)
	})

	commitReason := func(t *testing.T, mutate func(*Vane, *vaneConnTestClock, *vaneTestProxy, vaneMediaPlan)) string {
		t.Helper()
		group, clock, _, beta, key := newGroup(t)
		plan, reason := group.prepareMediaReconnectDetailed(key, "rr.googlevideo.com", 443, "alpha", 1_000_000)
		require.Empty(t, reason)
		mutate(group, clock, beta, plan)
		return group.commitMediaReconnectDetailed(plan)
	}

	t.Run("plan expired", func(t *testing.T) {
		reason := commitReason(t, func(group *Vane, clock *vaneConnTestClock, beta *vaneTestProxy, plan vaneMediaPlan) {
			clock.Advance(group.media.hintTTL + time.Second)
		})
		require.Equal(t, "plan-expired", reason)
	})

	t.Run("commit reconnect cooldown", func(t *testing.T) {
		reason := commitReason(t, func(group *Vane, clock *vaneConnTestClock, beta *vaneTestProxy, plan vaneMediaPlan) {
			group.mediaReconnects[plan.targetKey] = clock.Now().Add(time.Minute)
		})
		require.Equal(t, "reconnect-cooldown", reason)
	})

	t.Run("candidate cooldown", func(t *testing.T) {
		reason := commitReason(t, func(group *Vane, clock *vaneConnTestClock, beta *vaneTestProxy, plan vaneMediaPlan) {
			group.cooldowns[vaneCooldownKey{transport: vaneTransportTCP, target: plan.target, port: plan.port, candidate: plan.challenger}] = clock.Now().Add(time.Minute)
		})
		require.Equal(t, "candidate-cooldown", reason)
	})

	t.Run("challenger slow cooldown", func(t *testing.T) {
		reason := commitReason(t, func(group *Vane, clock *vaneConnTestClock, beta *vaneTestProxy, plan vaneMediaPlan) {
			group.mediaSlowCooldowns[vaneMediaCandidateKey{vaneMediaTargetKey: plan.targetKey, candidate: plan.challenger, identity: plan.challengerIdentity}] = clock.Now().Add(time.Minute)
		})
		require.Equal(t, "challenger-slow-cooldown", reason)
	})

	t.Run("challenger evidence degraded", func(t *testing.T) {
		reason := commitReason(t, func(group *Vane, clock *vaneConnTestClock, beta *vaneTestProxy, plan vaneMediaPlan) {
			group.ensureNodeLocked(plan.challenger, clock.Now())
			state := group.ensureNodeControlLocked(plan.challenger, clock.Now())
			state.recentTCPThroughput = vaneRecentThroughput{bitsPerSecond: 100_000, observedAt: clock.Now()}
		})
		require.Equal(t, "challenger-evidence-degraded", reason)
	})

	t.Run("commit budget", func(t *testing.T) {
		reason := commitReason(t, func(group *Vane, clock *vaneConnTestClock, beta *vaneTestProxy, plan vaneMediaPlan) {
			group.mediaBudgets[plan.targetKey] = vaneMediaBudget{startedAt: clock.Now(), count: group.media.budgetMax}
		})
		require.Equal(t, "budget-exhausted", reason)
	})
}

func TestVaneDiagnosticsConcurrentAccountingAndReadOnlySnapshot(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneDiagnosticsTestStore()
	diagnostics := newVaneDiagnostics("vane", clock, store)

	const workers = 32
	const recordsPerWorker = 25
	var wait sync.WaitGroup
	wait.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wait.Done()
			for j := 0; j < recordsPerWorker; j++ {
				diagnostics.record(vaneDiagnosticRecord{
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

	payload, err := store.Load(vaneDiagnosticsStorageKey("vane"))
	require.NoError(t, err)
	var persisted VaneDiagnosticsSnapshot
	require.NoError(t, json.Unmarshal(payload, &persisted))
	require.Equal(t, first.Counters.BufferCreditDeferrals, persisted.Counters.BufferCreditDeferrals,
		"out-of-order async flushes must never overwrite the newest cumulative snapshot")
}

func TestVaneDiagnosticsCoalescesWritesWhileStoreIsBlocked(t *testing.T) {
	clock := newVaneConnTestClock()
	store := &vaneDiagnosticsBlockingStore{
		vaneDiagnosticsTestStore: newVaneDiagnosticsTestStore(),
		entered:                  make(chan struct{}),
		release:                  make(chan struct{}),
	}
	diagnostics := newVaneDiagnostics("vane-coalesced", clock, store)
	diagnostics.record(vaneDiagnosticRecord{kind: "reconnect-suppressed", reason: "no-challenger", force: true})
	<-store.entered
	for i := 0; i < 1000; i++ {
		diagnostics.record(vaneDiagnosticRecord{kind: "reconnect-suppressed", reason: "no-challenger", force: true})
	}
	close(store.release)
	diagnostics.waitPersistence()

	require.Equal(t, 2, store.writeCount(), "one in-flight write plus one latest coalesced snapshot is sufficient")
	payload, err := store.Load(vaneDiagnosticsStorageKey("vane-coalesced"))
	require.NoError(t, err)
	var persisted VaneDiagnosticsSnapshot
	require.NoError(t, json.Unmarshal(payload, &persisted))
	require.Equal(t, uint64(1001), persisted.Counters.ReconnectSuppressed)
}

func TestVaneDiagnosticsRegistryIsDormantUntilActivation(t *testing.T) {
	const groupName = "diagnostics-dormant-until-activation"
	key := vaneDiagnosticsStorageKey(groupName)
	vaneDiagnosticsRegistry.Lock()
	delete(vaneDiagnosticsRegistry.entries, key)
	vaneDiagnosticsRegistry.current.Delete(key)
	vaneDiagnosticsRegistry.Unlock()
	t.Cleanup(func() {
		vaneDiagnosticsRegistry.Lock()
		delete(vaneDiagnosticsRegistry.entries, key)
		vaneDiagnosticsRegistry.current.Delete(key)
		vaneDiagnosticsRegistry.Unlock()
	})

	fallback := newVaneTestProxy("fallback", true, false)
	provider := newVaneTestProvider(newVaneTestProxy("alpha", true, true))
	group, err := NewVane(GroupCommonOption{Name: groupName, URL: C.DefaultTestURL}, VaneOption{}, fallback, []P.ProxyProvider{provider})
	require.NoError(t, err)
	vaneDiagnosticsRegistry.Lock()
	_, registeredBefore := vaneDiagnosticsRegistry.entries[key]
	vaneDiagnosticsRegistry.Unlock()
	require.False(t, registeredBefore, "parse-only construction must not mutate the diagnostics registry")

	ActivateVaneLearningStates(map[string]C.Proxy{groupName: A.NewProxy(group)})
	vaneDiagnosticsRegistry.Lock()
	_, registeredAfter := vaneDiagnosticsRegistry.entries[key]
	vaneDiagnosticsRegistry.Unlock()
	require.True(t, registeredAfter)
}

// PROBE-REASON-001: invalid probe reasons land in counters, so a rotated
// event ring can no longer erase why probes failed, and a snapshot written
// before the field existed restores to an empty (not nil) map.
func TestVaneProbeInvalidReasonsCounter(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneDiagnosticsTestStore()
	diagnostics := newVaneDiagnostics("probe-reasons", clock, store)
	require.Nil(t, diagnostics.snapshot().Counters.ProbeInvalidReasons)

	reasons := []string{"dial-error", "tls-timeout", "header-timeout", "read-timeout", "early-eof", "dial-error"}
	for _, reason := range reasons {
		diagnostics.record(vaneDiagnosticRecord{kind: "race-probe-invalid", reason: reason, force: true})
	}
	diagnostics.record(vaneDiagnosticRecord{kind: "race-probe-success", reason: "cap-hit", totalBytes: 4 << 20, force: true})

	counters := diagnostics.snapshot().Counters
	require.Equal(t, uint64(6), counters.ProbeInvalid)
	require.Equal(t, uint64(1), counters.ProbeSuccess)
	require.Equal(t, map[string]uint64{
		"dial-error": 2, "tls-timeout": 1, "header-timeout": 1, "read-timeout": 1, "early-eof": 1,
	}, counters.ProbeInvalidReasons)

	// The snapshot must own its map: the live counters keep writing while the
	// snapshot is marshalled outside the diagnostics lock.
	diagnostics.record(vaneDiagnosticRecord{kind: "race-probe-invalid", reason: "dial-error", force: true})
	require.Equal(t, map[string]uint64{
		"dial-error": 2, "tls-timeout": 1, "header-timeout": 1, "read-timeout": 1, "early-eof": 1,
	}, counters.ProbeInvalidReasons)
	require.Equal(t, uint64(3), diagnostics.snapshot().Counters.ProbeInvalidReasons["dial-error"])
}

func TestVaneProbeInvalidReasonsRestoreFromOlderSnapshot(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneDiagnosticsTestStore()
	// A snapshot written before the field existed carries no reason map.
	legacy, err := json.Marshal(VaneDiagnosticsSnapshot{
		SchemaVersion: VaneDiagnosticsSchemaVersion,
		Group:         "probe-legacy",
		Counters:      VaneDiagnosticCounters{ProbeCount: 3, ProbeInvalid: 3},
	})
	require.NoError(t, err)
	require.NoError(t, store.Save(vaneDiagnosticsStorageKey("probe-legacy"), legacy))

	diagnostics := newVaneDiagnostics("probe-legacy", clock, store)
	require.Equal(t, uint64(3), diagnostics.snapshot().Counters.ProbeInvalid)
	require.Empty(t, diagnostics.snapshot().Counters.ProbeInvalidReasons)

	diagnostics.record(vaneDiagnosticRecord{kind: "race-probe-invalid", reason: "tls-error", force: true})
	require.Equal(t, map[string]uint64{"tls-error": 1}, diagnostics.snapshot().Counters.ProbeInvalidReasons)
	require.Equal(t, uint64(4), diagnostics.snapshot().Counters.ProbeInvalid)
}
