package outboundgroup

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// VERIFY-STALL-GRACE: a recently-fast graced low window says nothing about the
// node the flow just landed on — the client was reading fast 30 seconds ago —
// so it must not trigger the landing penalty. Synthetic silence still does
// (existing VERIFY-STALL coverage pins that side).
func TestVaneGracedLowsDoNotPenalizeLanding(t *testing.T) {
	group, clock, flow := newVaneObservationRig(t, vaneSwitchLive)
	key := group.targetScopeKey(flow.target, flow.port)
	now := clock.Now()
	group.mu.Lock()
	group.ledger[key] = vaneSwitchLedger{verifyNode: flow.candidate, verifyAt: now, windowFrom: now, count: 1}
	group.mu.Unlock()

	fast := vaneThroughputObservation{BitsPerSecond: 6_000_000, TotalBytes: 8 * 1024 * 1024, Duration: 4 * time.Second, Age: 20 * time.Second}
	require.Nil(t, flow.observe(fast))
	for i := 0; i < 2; i++ {
		clock.Advance(5 * time.Second)
		low := vaneObservationLowSample()
		low.Duration = 4 * time.Second
		require.Nil(t, flow.observe(low))
	}
	require.Zero(t, countVaneEvents(group, "verify-penalty", ""),
		"a recently-fast graced landing must not cool the node")
	group.mu.Lock()
	cooling := group.nodeCoolingLocked(flow.candidate, clock.Now())
	group.mu.Unlock()
	require.False(t, cooling, "the landing node stays eligible")
}

// STICKY-SWEEP: sticky entries expire after one TTL, but the only prune points
// sit on reconnect paths — the write path must sweep them itself, or the map
// grows with every distinct host ever dialed until a stall happens to prune.
func TestVaneStickySweepExpiresWithoutReconnect(t *testing.T) {
	group, clock, alpha, _, _ := newTargetGroupForTest(t)
	now := clock.Now()
	group.mu.Lock()
	defer group.mu.Unlock()
	for i := 0; i < 8; i++ {
		group.rememberStickyLocked(fmt.Sprintf("host-%d.example.com", i), 443, alpha.Name(), now)
	}
	group.rememberStickyLocked("host-9.example.com", 443, alpha.Name(), now)
	require.Len(t, group.stickiness, 9, "no sweep inside the interval")

	later := now.Add(vaneStickyTTL + vaneStickySweepInterval)
	group.rememberStickyLocked("host-0.example.com", 443, alpha.Name(), later)
	require.Len(t, group.stickiness, 1, "expired stickies are swept by the write path alone")
}
