package outboundgroup

import (
	"context"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func newVanePolicyTestConn(t *testing.T, clock *vaneConnTestClock) (*vaneConnTestConn, *vaneObservedConn, *atomic.Int32) {
	t.Helper()
	return newVanePolicyTestConnWith(t, clock, &vaneConnTestConn{readFunc: func(payload []byte) (int, error) {
		for index := range payload {
			payload[index] = 7
		}
		return len(payload), nil
	}})
}

func newVanePolicyTestBufferedConn(t *testing.T, clock *vaneConnTestClock, reads int) (*vaneConnTestConn, *vaneObservedConn, *atomic.Int32) {
	t.Helper()
	payload := make([]byte, 32*1024)
	queue := make([]vaneConnTestRead, reads)
	for index := range queue {
		queue[index] = vaneConnTestRead{payload: payload}
	}
	return newVanePolicyTestConnWith(t, clock, &vaneConnTestConn{reads: queue})
}

func newVanePolicyTestConnWith(t *testing.T, clock *vaneConnTestClock, underlying *vaneConnTestConn) (*vaneConnTestConn, *vaneObservedConn, *atomic.Int32) {
	t.Helper()
	actions := &atomic.Int32{}
	wrapped := newVaneControlledConn(underlying, clock, nil, nil, func(vaneThroughputObservation) vanePolicyAction {
		actions.Add(1)
		return func() bool { return true }
	})
	observed, ok := wrapped.(*vaneObservedConn)
	require.True(t, ok)
	return underlying, observed, actions
}

func readVaneDirectPayload(t *testing.T, conn C.Conn, clock *vaneConnTestClock, reads int) {
	t.Helper()
	payload := make([]byte, 64*1024)
	for index := 0; index < reads; index++ {
		if index > 0 {
			clock.Advance(time.Second)
		}
		n, err := conn.Read(payload)
		require.NoError(t, err)
		require.Equal(t, len(payload), n)
	}
}

func readVaneBufferedPayload(t *testing.T, conn C.Conn, clock *vaneConnTestClock, reads int) {
	t.Helper()
	for index := 0; index < reads; index++ {
		if index > 0 {
			clock.Advance(time.Second)
		}
		buffer := buf.New()
		require.NoError(t, conn.ReadBuffer(buffer))
		require.Equal(t, 32*1024, buffer.Len())
		buffer.Release()
	}
}

// RACE-DELIVERY-001 + TARGET-LEASE-001: policy close never preempts direct payload delivery.
func TestVaneObservedConnPolicyCloseNeverPreemptsDirectPayload(t *testing.T) {
	t.Run("baseline direct read never evaluates policy", func(t *testing.T) {
		clock := newVaneConnTestClock()
		underlying, conn, actions := newVanePolicyTestConn(t, clock)
		readVaneDirectPayload(t, conn, clock, 18)
		require.Zero(t, actions.Load(), "without delivered proof the policy callback must not run")
		underlying.mu.Lock()
		require.Zero(t, underlying.closeCalls)
		underlying.mu.Unlock()
	})

	t.Run("racing direct read queues close until next boundary", func(t *testing.T) {
		clock := newVaneConnTestClock()
		underlying, conn, actions := newVanePolicyTestConn(t, clock)
		conn.enableDirectPolicy()
		// Six one-second reads fill the first five-second throughput window.
		readVaneDirectPayload(t, conn, clock, 6)
		require.Equal(t, int32(1), actions.Load(), "the window boundary must produce exactly one policy action")
		underlying.mu.Lock()
		require.Zero(t, underlying.closeCalls, "a direct read must return its bytes before any policy close")
		underlying.mu.Unlock()

		clock.Advance(time.Second)
		payload := make([]byte, 64*1024)
		n, err := conn.Read(payload)
		require.NoError(t, err)
		require.Equal(t, len(payload), n, "the drain boundary must still deliver the payload")
		underlying.mu.Lock()
		require.Equal(t, 1, underlying.closeCalls, "the queued close runs at the next I/O boundary exactly once")
		underlying.mu.Unlock()
	})

	t.Run("racing buffered read queues close until next boundary", func(t *testing.T) {
		clock := newVaneConnTestClock()
		underlying, conn, actions := newVanePolicyTestBufferedConn(t, clock, 7)
		conn.enableDirectPolicy()
		readVaneBufferedPayload(t, conn, clock, 6)
		require.Equal(t, int32(1), actions.Load())
		underlying.mu.Lock()
		require.Zero(t, underlying.closeCalls)
		underlying.mu.Unlock()

		clock.Advance(time.Second)
		buffer := buf.New()
		require.NoError(t, conn.ReadBuffer(buffer))
		require.Equal(t, 32*1024, buffer.Len())
		buffer.Release()
		underlying.mu.Lock()
		require.Equal(t, 1, underlying.closeCalls)
		underlying.mu.Unlock()
	})

	t.Run("delivered counter closes immediately after payload", func(t *testing.T) {
		clock := newVaneConnTestClock()
		underlying, conn, actions := newVanePolicyTestConn(t, clock)
		conn.enableDirectPolicy()
		reader, counters := conn.UnwrapReader()
		payload := make([]byte, 64*1024)
		for index := 0; index < 18; index++ {
			if index > 0 {
				clock.Advance(time.Second)
			}
			n, err := reader.Read(payload)
			require.NoError(t, err)
			for _, counter := range counters {
				counter(int64(n))
			}
		}
		require.Positive(t, actions.Load())
		underlying.mu.Lock()
		require.Equal(t, 1, underlying.closeCalls, "a counted delivery has already reached the destination")
		underlying.mu.Unlock()
	})
}

// RACE-DELIVERY-001: policy submission honors the delivery state.
func TestVaneObservedConnSubmitPolicyActionHonorsDelivery(t *testing.T) {
	clock := newVaneConnTestClock()
	underlying, conn, _ := newVanePolicyTestConn(t, clock)
	conn.submitPolicyAction(func() bool { return true }, false)
	underlying.mu.Lock()
	require.Zero(t, underlying.closeCalls)
	underlying.mu.Unlock()

	clock.Advance(time.Second)
	_, _ = conn.Read(make([]byte, 1024))
	underlying.mu.Lock()
	require.Equal(t, 1, underlying.closeCalls)
	underlying.mu.Unlock()

	underlying, conn, _ = newVanePolicyTestConn(t, clock)
	conn.submitPolicyAction(func() bool { return true }, true)
	underlying.mu.Lock()
	require.Equal(t, 1, underlying.closeCalls)
	underlying.mu.Unlock()
}

// RACE-SHADOW-001: shadow keeps the baseline direct policy disabled.
func TestVaneRacingShadowKeepsDirectPolicyDisabled(t *testing.T) {
	clock := newVaneConnTestClock()
	alphaConn := &vaneConnTestConn{readFunc: func(payload []byte) (int, error) {
		for index := range payload {
			payload[index] = 1
		}
		return len(payload), nil
	}}
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.dialConn = alphaConn
	beta := newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	configureVaneRacingForTest(t, group, vaneRacingShadow)
	conn, err := group.DialContext(t.Context(), &C.Metadata{Host: "rr1.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	require.NoError(t, err)
	observed := conn.(*vaneObservedConn)
	observed.mu.Lock()
	directPolicy := observed.directPolicy
	observed.mu.Unlock()
	require.False(t, directPolicy, "shadow must not enable the racing close path")
}

// RACE-HANDOFF-001 + TARGET-FEEDBACK-001: end-to-end handoff reconnect and preference formation.
func TestVaneRacingOnEndToEndHandoffReconnectAndPreference(t *testing.T) {
	clock := newVaneConnTestClock()
	alphaConn := &vaneConnTestConn{readFunc: func(payload []byte) (int, error) {
		for index := range payload {
			payload[index] = 1
		}
		return len(payload), nil
	}}
	betaConn := &vaneConnTestConn{readFunc: func(payload []byte) (int, error) {
		for index := range payload {
			payload[index] = 2
		}
		return len(payload), nil
	}}
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.delay = 20
	alpha.dialConn = alphaConn
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	beta.dialConn = betaConn
	var betaDials atomic.Int32
	beta.dialHook = func() { betaDials.Add(1) }
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	configureVaneRacingForTest(t, group, vaneRacingOn)
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 40_000_000, capHit: true}
	}
	metadata := &C.Metadata{Host: "rr-live.googlevideo.com", DstPort: 443, NetWork: C.TCP}

	first, err := group.DialContext(t.Context(), metadata)
	require.NoError(t, err)
	readVaneLowWindows(t, first, clock, 3)
	require.Eventually(t, func() bool {
		alphaConn.mu.Lock()
		defer alphaConn.mu.Unlock()
		return alphaConn.closeCalls == 1
	}, 2*time.Second, time.Millisecond, "the race winner must policy-close the slow flow")

	second, err := group.DialContext(t.Context(), metadata)
	require.NoError(t, err)
	require.Equal(t, int32(1), betaDials.Load(), "the reconnect must claim the handoff lease and dial the challenger")

	reader, counters := second.(*vaneObservedConn).UnwrapReader()
	payload := make([]byte, 512*1024)
	for index := 0; index < 12; index++ {
		if index > 0 {
			clock.Advance(time.Second)
		}
		n, readErr := reader.Read(payload)
		require.NoError(t, readErr)
		for _, counter := range counters {
			counter(int64(n))
		}
	}
	key, ok := group.targetKeyForMedia(metadata.Host, metadata.DstPort)
	require.True(t, ok)
	group.mu.Lock()
	preference, preferred := group.targetPreferences[key]
	group.mu.Unlock()
	require.True(t, preferred, "a proven faster reconnect must create a target preference")
	require.Equal(t, "beta", preference.to.name)

	countersSnapshot := group.VaneDiagnostics().Counters
	require.Positive(t, countersSnapshot.HandoffCommitted)
	require.Positive(t, countersSnapshot.ReconnectSelected)
	require.Positive(t, countersSnapshot.HandoffImproved)
	require.NoError(t, first.Close())
	require.NoError(t, second.Close())
}
