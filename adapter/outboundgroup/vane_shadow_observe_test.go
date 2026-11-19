package outboundgroup

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// SHADOW-OBSERVE-001: shadow must be able to observe windows that were never
// delivered to the destination. Without shadowObserve the gate returns before
// onWindow, so a flow that mostly reads directly never accumulates low windows
// and can never schedule a race — shadow would report wouldHandoff=0 forever.
func TestVaneShadowObserveDiscardsAction(t *testing.T) {
	t.Run("shadow observes an undelivered window but discards the action", func(t *testing.T) {
		clock := newVaneConnTestClock()
		underlying, conn, actions := newVanePolicyTestConn(t, clock)
		conn.enableShadowObserve()
		readVaneDirectPayload(t, conn, clock, 6)
		require.Equal(t, int32(1), actions.Load(), "the policy must run on the window boundary")

		underlying.mu.Lock()
		require.Zero(t, underlying.closeCalls, "shadow must never close traffic")
		underlying.mu.Unlock()

		// If the action had been queued, the next read would drain it.
		p := make([]byte, 64*1024)
		if _, err := conn.Read(p); err != nil {
			t.Fatalf("read after shadow window: %v", err)
		}
		underlying.mu.Lock()
		require.Zero(t, underlying.closeCalls, "a discarded action is not queued, so no later read executes it")
		underlying.mu.Unlock()
	})

	t.Run("shadow still closes immediately on a delivered window", func(t *testing.T) {
		clock := newVaneConnTestClock()
		underlying, conn, actions := newVanePolicyTestConn(t, clock)
		conn.enableShadowObserve()
		reader, counters := conn.UnwrapReader()
		payload := make([]byte, 64*1024)
		for index := 0; index < 6; index++ {
			if index > 0 {
				clock.Advance(time.Second)
			}
			n, err := reader.Read(payload)
			require.NoError(t, err)
			for _, counter := range counters {
				counter(int64(n))
			}
		}
		require.Equal(t, int32(1), actions.Load())
		underlying.mu.Lock()
		require.Equal(t, 1, underlying.closeCalls, "a delivered window keeps its existing close behaviour under shadow")
		underlying.mu.Unlock()
	})
}
