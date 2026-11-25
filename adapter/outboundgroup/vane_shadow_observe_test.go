package outboundgroup

import (
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

// SHADOW-OBSERVE-001 / SHADOW-KEPT-01: undelivered windows still reach dry-run observe.
func TestVaneShadowObserveDiscardsAction(t *testing.T) {
	for _, path := range []string{"undelivered", "delivered", "without-shadowObserve"} {
		t.Run(path, func(t *testing.T) {
			clock := newVaneConnTestClock()
			underlying := &vaneConnTestConn{readFunc: func(p []byte) (int, error) { return len(p), nil }}
			alpha, beta := newVaneTestProxy("alpha", true, true), newVaneTestProxy("beta", true, true)
			alpha.dialConn = underlying
			group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
			configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
			configureVaneRacingForTest(t, group, vaneRacingShadow)
			t.Cleanup(func() { _ = group.Close() })
			seedChain01Traffic(t, group, "beta", clock.Now(), 40_000_000)
			metadata := &C.Metadata{Host: "rr-shadow.googlevideo.com", DstPort: 443, NetWork: C.TCP}
			suppressColdPickProbeForTest(t, group, metadata)
			wrapped, err := group.DialContext(t.Context(), metadata)
			require.NoError(t, err)
			conn := wrapped.(*vaneObservedConn)
			t.Cleanup(func() { _ = conn.Close() })
			if path == "without-shadowObserve" {
				conn.shadowObserve = false
			}
			if path == "delivered" {
				readVaneLowWindows(t, conn, clock, 3)
			} else {
				readVaneDirectPayload(t, conn, clock, 18)
			}
			want := 1
			if path == "without-shadowObserve" {
				want = 0
			}
			require.Equal(t, want, countVaneEvents(group, "handoff-would-commit", "baseline"))
			conn.mu.Lock()
			require.Nil(t, conn.pendingAction)
			conn.mu.Unlock()
			underlying.mu.Lock()
			require.Zero(t, underlying.closeCalls)
			underlying.mu.Unlock()
			_, err = conn.Read(make([]byte, 1024))
			require.NoError(t, err)
			underlying.mu.Lock()
			require.Zero(t, underlying.closeCalls, "no queued action closes the next read")
			underlying.mu.Unlock()
		})
	}
}
