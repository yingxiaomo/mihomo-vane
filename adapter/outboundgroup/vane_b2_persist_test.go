package outboundgroup

import (
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func vaneB2SampleTarget(now time.Time, ema float64, loss, attempts, suspected int64) vanePersistedB2Target {
	return vanePersistedB2Target{
		Transport: "tcp", TargetScope: "rr.googlevideo.com", Port: 443,
		Candidate: "beta", Identity: "test:beta",
		LossEMA: ema, LossSamples: loss, AttemptCount: attempts, SuspectedStallCount: suspected,
		LastObservedAt: now,
	}
}

// B2-PERSIST-001: the target telemetry survives a snapshot → marshal →
// restore round trip, matched by (target, candidate, identity) — never epoch.
func TestVaneB2TargetPersistenceRoundTrip(t *testing.T) {
	clock := newVaneConnTestClock()
	now := clock.Now().UTC().Add(-time.Minute)
	source := newVaneLearningState("vane-test", clock, nil, time.Hour, 64)
	seedA := vaneB2SampleTarget(now, 0.03, 12, 40, 6)
	seedB := vaneB2SampleTarget(now.Add(-time.Hour), 0.11, 3, 9, 1)
	seedB.TargetScope = "cdn.googlevideo.com" // a distinct (target, candidate) pair
	source.targets["seed-a"] = seedA
	source.targets["seed-b"] = seedB

	snapshot := source.snapshotLocked(clock.Now().UTC())
	payload, err := marshalVaneLearningSnapshot(snapshot)
	require.NoError(t, err)

	restored := newVaneLearningState("vane-test", newVaneConnTestClock(), nil, time.Hour, 64)
	require.NoError(t, restored.restore(payload))

	seed, ok := restored.seedB2Target(vaneTransportTCP, "rr.googlevideo.com", 443, "beta", "test:beta")
	require.True(t, ok, "the newest entry must survive the round trip")
	require.Equal(t, seedA, seed)

	// The restore re-keys by (target, candidate, identity): both entries are
	// reachable, and the lookup never depends on the epoch.
	_, ok = restored.seedB2Target(vaneTransportTCP, "cdn.googlevideo.com", 443, "beta", "test:beta")
	require.True(t, ok)
	require.Len(t, restored.targets, 2)
}

// B2-PERSIST-002: bad entries drop, coordination state never persists, and
// the seed only fills records whose B2 fields are still empty.
func TestVaneB2TargetPersistenceValidation(t *testing.T) {
	clock := newVaneConnTestClock()
	now := clock.Now().UTC().Add(-time.Minute)
	source := newVaneLearningState("vane-test", clock, nil, time.Hour, 64)
	good := vaneB2SampleTarget(now, 0.05, 4, 10, 2)
	source.targets["good"] = good

	snapshot := source.snapshotLocked(clock.Now().UTC())
	snapshot.Targets = append(snapshot.Targets,
		vanePersistedB2Target{Transport: "tcp", TargetScope: "x.example", Port: 443, Candidate: "", Identity: "i", AttemptCount: 1, LastObservedAt: now},
		vanePersistedB2Target{Transport: "tcp", TargetScope: "x.example", Port: 443, Candidate: "beta", Identity: "i", AttemptCount: 1, LastObservedAt: now, LossEMA: 1.5},
		vanePersistedB2Target{Transport: "tcp", TargetScope: "x.example", Port: 443, Candidate: "beta", Identity: "i", AttemptCount: -1, LastObservedAt: now},
		vanePersistedB2Target{Transport: "quic", TargetScope: "x.example", Port: 443, Candidate: "beta", Identity: "i", AttemptCount: 1, LastObservedAt: now},
		vanePersistedB2Target{Transport: "tcp", TargetScope: "x.example", Port: 443, Candidate: "beta", Identity: "i", AttemptCount: 1, LastObservedAt: now.Add(time.Hour)},
		vanePersistedB2Target{Transport: "tcp", TargetScope: "x.example", Port: 443, Candidate: "beta", Identity: "i"},
	)
	payload, err := marshalVaneLearningSnapshot(snapshot)
	require.NoError(t, err)

	restored := newVaneLearningState("vane-test", newVaneConnTestClock(), nil, time.Hour, 64)
	restoreErr := restored.restore(payload)
	require.Error(t, restoreErr, "invalid entries are counted in the diagnostics error")
	seed, ok := restored.seedB2Target(vaneTransportTCP, "rr.googlevideo.com", 443, "beta", "test:beta")
	require.True(t, ok, "the good entry must survive the bad ones")
	require.Equal(t, good, seed)
	require.Len(t, restored.targets, 1, "all six malformed entries must drop")
}

// B2-PERSIST-002: the settle path seeds a B2-empty live record from learning
// and pushes updates back — while the failure fields stay untouched.
func TestVaneB2TargetSeedAndPush(t *testing.T) {
	group, clock, alpha, beta, _ := newVaneRacingEvidenceGroup(t)
	group.mu.Lock()
	for _, proxy := range []C.Proxy{alpha, beta} {
		group.ensureProxyNodeLocked(proxy, clock.Now())
	}
	lease := group.memberLeaseLocked(beta.Name(), beta.identity)
	group.mu.Unlock()
	// The flow settles on beta: candidate and identity must agree, or the
	// prune would eat the live record after every settle.
	flow := newVaneFlow(group, beta.Name(), &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	require.NotNil(t, flow)
	flow.identity = lease.identity
	flow.nodeEpoch = lease.epoch
	failureKey := vaneTargetFailureKey{
		target: flow.targetStateKey,
		member: vaneMemberLease{name: flow.candidate, identity: flow.identity, epoch: flow.nodeEpoch},
	}

	// A failure path created the live record first: streak and blockUntil are
	// coordination state that the seed must never touch.
	group.mu.Lock()
	group.recordTargetFailureLocked(flow.targetStateKey, failureKey.member, clock.Now())
	group.mu.Unlock()

	// Simulate a restored learning mirror for the same pair. The scope is the
	// flow's own bucket key (googlevideo.com), not the request host.
	group.learning.targets[vaneLearningB2TargetKey(
		flow.targetStateKey.transport,
		flow.targetStateKey.targetScope, flow.targetStateKey.port, flow.candidate, flow.identity,
	)] = vaneB2SampleTarget(clock.Now(), 0.07, 8, 30, 5)

	group.recordB2Stall(flow, vaneConnectionCloseObservation{
		WrotePayload: true, TotalReadBytes: 4 * 1024 * 1024,
		ResponseRecorded: true, ResponseBytes: 4 * 1024 * 1024,
		ResponseAt: clock.Now().Add(-30 * time.Second),
	}, clock.Now())

	group.mu.Lock()
	state := group.targetFailures[failureKey]
	group.mu.Unlock()
	require.Equal(t, int64(31), state.attemptCount, "the seed starts the counters, the settle increments them")
	require.Equal(t, int64(6), state.suspectedStallCount)
	require.Equal(t, 0.07, state.lossEMA, "the loss EMA starts from the mirror")
	require.Equal(t, uint8(1), state.streak, "coordination state survives the seed untouched")
	require.True(t, state.blockUntil.After(clock.Now()), "the failure block must stay live")

	// The push mirrored the updated state back to learning.
	pushed, ok := group.learning.seedB2Target(
		flow.targetStateKey.transport,
		flow.targetStateKey.targetScope, flow.targetStateKey.port, flow.candidate, flow.identity)
	require.True(t, ok)
	require.Equal(t, int64(31), pushed.AttemptCount)
	require.Equal(t, int64(6), pushed.SuspectedStallCount)

	// A live record with B2 data is never overwritten by the mirror.
	group.learning.targets[vaneLearningB2TargetKey(
		flow.targetStateKey.transport,
		flow.targetStateKey.targetScope, flow.targetStateKey.port, flow.candidate, flow.identity,
	)] = vaneB2SampleTarget(clock.Now(), 0.9, 100, 500, 400)
	group.recordB2Loss(flow, vaneConnectionCloseObservation{
		WrotePayload: true, TotalReadBytes: 4 * 1024 * 1024, LossRate: 0.02, LossSupported: true,
	}, clock.Now())
	group.mu.Lock()
	state = group.targetFailures[failureKey]
	group.mu.Unlock()
	require.NotEqual(t, 0.9, state.lossEMA, "the mirror must not overwrite live B2 data")
	require.Equal(t, int64(31), state.attemptCount, "a loss settle never touches the attempt counter")
}

// B2-PERSIST-001: under the payload cap the Targets section is the first
// thing dropped, before any node truncation.
func TestVaneB2TargetsSacrificedUnderPayloadCap(t *testing.T) {
	now := time.Now().UTC().Add(-time.Minute)
	source := newVaneLearningState("vane-test", newVaneConnTestClock(), nil, time.Hour, 64)
	for index := 0; index < 50; index++ {
		target := vaneB2SampleTarget(now, 0.01, 1, 1, 0)
		target.TargetScope = string(make([]byte, 4096)) + string(rune('a'+index%26))
		source.targets[string(rune('a'+index%26))] = target
	}
	snapshot := source.snapshotLocked(now)
	snapshot.Nodes = nil // isolate the target payload
	payload, err := marshalVaneLearningSnapshot(snapshot)
	require.NoError(t, err)
	require.LessOrEqual(t, len(payload), vaneLearningPayloadLimit, "dropping targets brings the payload back under the cap")
}
