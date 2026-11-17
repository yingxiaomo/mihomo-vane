package outboundgroup

import (
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// B2-STALL-001: the header-then-stall signature — payload written, first
// response seen, zero bytes afterwards, quiet for at least vaneB2StallMinAge.
func TestVaneB2StallSignature(t *testing.T) {
	drive := func(t *testing.T, steps func(conn *vaneObservedConn, clock *vaneConnTestClock)) vaneConnectionCloseObservation {
		t.Helper()
		clock := newVaneConnTestClock()
		var observation vaneConnectionCloseObservation
		controlled := newVaneControlledConnWithNative(&vaneConnTestConn{}, clock,
			nil, nil, nil, nil,
			func(closeObservation vaneConnectionCloseObservation) { observation = closeObservation },
			nil)
		conn := controlled.(*vaneObservedConn)
		steps(conn, clock)
		require.NoError(t, conn.Close())
		require.NotNil(t, observation.ResponseAt, "the native close must carry the B2 response snapshot")
		return observation
	}

	t.Run("header then silence is a stall", func(t *testing.T) {
		observation := drive(t, func(conn *vaneObservedConn, clock *vaneConnTestClock) {
			conn.observeWrite(clock.Now())
			conn.observeRead(clock.Now(), 1024, false)
			clock.Advance(20 * time.Second)
		})
		require.True(t, vaneB2StallSignature(observation, clockLater(observation.ResponseAt, vaneB2StallMinAge)),
			"zero bytes after the response plus a quiet tail matches the signature")
	})

	t.Run("reads after the response are a client abort", func(t *testing.T) {
		observation := drive(t, func(conn *vaneObservedConn, clock *vaneConnTestClock) {
			conn.observeWrite(clock.Now())
			conn.observeRead(clock.Now(), 1024, false)
			clock.Advance(time.Second)
			conn.observeRead(clock.Now(), 2048, false)
			clock.Advance(20 * time.Second)
		})
		require.False(t, vaneB2StallSignature(observation, observation.ResponseAt.Add(vaneB2StallMinAge)),
			"bytes read after the response mean the client kept going")
		require.Greater(t, observation.TotalReadBytes, observation.ResponseBytes)
	})

	t.Run("quiet below the window is not a stall", func(t *testing.T) {
		observation := drive(t, func(conn *vaneObservedConn, clock *vaneConnTestClock) {
			conn.observeWrite(clock.Now())
			conn.observeRead(clock.Now(), 1024, false)
			clock.Advance(vaneB2StallMinAge - time.Second)
		})
		require.False(t, vaneB2StallSignature(observation, observation.ResponseAt.Add(vaneB2StallMinAge-time.Second)))
	})

	t.Run("no response at all is not a stall", func(t *testing.T) {
		observation := drive(t, func(conn *vaneObservedConn, clock *vaneConnTestClock) {
			conn.observeWrite(clock.Now())
			clock.Advance(time.Minute)
		})
		require.False(t, observation.ResponseRecorded)
		require.False(t, vaneB2StallSignature(observation, observation.ResponseAt.Add(time.Minute)))
	})

	t.Run("response recorded at the write site when a read preceded it", func(t *testing.T) {
		observation := drive(t, func(conn *vaneObservedConn, clock *vaneConnTestClock) {
			conn.beginWrite()
			conn.observeRead(clock.Now(), 1024, false)
			conn.observeWrite(clock.Now())
			clock.Advance(20 * time.Second)
		})
		require.True(t, observation.ResponseRecorded)
		require.Equal(t, int64(1024), observation.ResponseBytes)
		require.True(t, vaneB2StallSignature(observation, observation.ResponseAt.Add(vaneB2StallMinAge)))
	})
}

func clockLater(base time.Time, delta time.Duration) time.Time {
	return base.Add(delta)
}

// B2-STALL-001: attempts count every settlement, suspected stalls only the
// signature matches, and the rate stays zero below the minimum sample count.
func TestVaneB2StallTelemetry(t *testing.T) {
	group, clock, alpha, _, _ := newVaneRacingEvidenceGroup(t)
	group.mu.Lock()
	group.ensureProxyNodeLocked(alpha, clock.Now())
	lease := group.memberLeaseLocked(alpha.Name(), alpha.identity)
	group.mu.Unlock()
	flow := newVaneMediaFlow(group, alpha.Name(), &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	require.NotNil(t, flow)
	flow.identity = lease.identity
	flow.nodeEpoch = lease.epoch

	// Observations anchor to the fake clock's base: the settlement compares
	// closedAt (the fake clock) against ResponseAt.
	base := clock.Now()
	stallObservation := vaneConnectionCloseObservation{
		WrotePayload: true, TotalReadBytes: 4 * 1024 * 1024,
		ResponseRecorded: true, ResponseBytes: 4 * 1024 * 1024,
		ResponseAt: base.Add(-30 * time.Second),
	}
	abortObservation := vaneConnectionCloseObservation{
		WrotePayload: true, TotalReadBytes: 8 * 1024 * 1024,
		ResponseRecorded: true, ResponseBytes: 4 * 1024 * 1024,
		ResponseAt: base.Add(-30 * time.Second),
	}

	// Three stalls and one client abort: the signature must distinguish them.
	for step := 0; step < 3; step++ {
		group.recordB2MediaStall(flow, stallObservation, clock.Now())
		clock.Advance(time.Second)
	}
	group.recordB2MediaStall(flow, abortObservation, clock.Now())
	clock.Advance(time.Second)

	group.mu.Lock()
	key := vaneTargetFailureKey{
		target: flow.targetStateKey,
		member: vaneMemberLease{name: flow.candidate, identity: flow.identity, epoch: flow.nodeEpoch},
	}
	state := group.targetFailures[key]
	group.mu.Unlock()
	require.Equal(t, int64(4), state.attemptCount)
	require.Equal(t, int64(3), state.suspectedStallCount)
	require.Zero(t, state.streak, "stall telemetry must not touch the failure fields")
	require.Zero(t, state.b2StallRate(), "below five samples the rate is zero")

	counters := group.VaneDiagnostics().Counters
	require.Equal(t, uint64(4), counters.B2StallAttempts)
	require.Equal(t, uint64(3), counters.B2StallSuspected)
	require.Equal(t, 1, group.VaneDiagnostics().Runtime.B2StallTargets)

	// The fifth settle crosses the minimum: the rate becomes meaningful.
	group.recordB2MediaStall(flow, stallObservation, clock.Now())
	group.mu.Lock()
	state = group.targetFailures[key]
	group.mu.Unlock()
	require.Equal(t, int64(5), state.attemptCount)
	require.InDelta(t, 0.8, state.b2StallRate(), 1e-12)

	// One more abort, and the rate tracks the new ratio.
	group.recordB2MediaStall(flow, abortObservation, clock.Now())
	group.mu.Lock()
	state = group.targetFailures[key]
	group.mu.Unlock()
	require.Equal(t, int64(6), state.attemptCount)
	require.InDelta(t, 4.0/6.0, state.b2StallRate(), 1e-12)

	// Loss and stall share one record without disturbing each other.
	group.recordB2MediaLoss(flow, vaneConnectionCloseObservation{
		WrotePayload: true, TotalReadBytes: 4 * 1024 * 1024, LossRate: 0.01, LossSupported: true,
	}, clock.Now())
	group.mu.Lock()
	state = group.targetFailures[key]
	group.mu.Unlock()
	require.Equal(t, int64(6), state.attemptCount, "loss settlement must not touch stall counters")
	require.Equal(t, 0.01, state.lossEMA)
	require.Zero(t, state.streak)
}
