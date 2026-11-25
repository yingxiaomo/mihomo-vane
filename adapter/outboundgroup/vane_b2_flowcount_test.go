package outboundgroup

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// B2-FLOWCOUNT-001: per-node live flow counts are observation-only —
// flows +1 on successful creation, −1 exactly once on settlement, and the
// runtime snapshot exposes a copy, never the internal map.
func TestVaneB2ActiveFlows(t *testing.T) {
	group, _, alpha, _, _ := newVaneRacingEvidenceGroup(t)
	flowMetadata := &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP}

	flowOne := newVaneFlow(group, alpha.Name(), flowMetadata)
	require.NotNil(t, flowOne)
	flowTwo := newVaneFlow(group, alpha.Name(), flowMetadata)
	require.NotNil(t, flowTwo)

	group.flowsMu.Lock()
	count := group.activeFlows[alpha.Name()]
	group.flowsMu.Unlock()
	require.Equal(t, 2, count, "two live flows hold two counts")

	// Untargeted flows are watched but must not hold a flow count.
	untargeted := newVaneFlow(group, alpha.Name(), &C.Metadata{Host: "example.com", DstPort: 443, NetWork: C.TCP})
	require.NotNil(t, untargeted, "PHASE1: every TCP flow is watched")
	require.False(t, untargeted.counted, "a non-flow holds no B2 count")
	untargeted.releaseActiveFlowCount()
	group.flowsMu.Lock()
	count = group.activeFlows[alpha.Name()]
	group.flowsMu.Unlock()
	require.Equal(t, 2, count)

	// The snapshot must be a copy: mutating it must not touch the group state.
	snapshot := group.VaneDiagnostics()
	require.Equal(t, map[string]int{alpha.Name(): 2}, snapshot.Runtime.B2ActiveFlows)
	snapshot.Runtime.B2ActiveFlows[alpha.Name()] = 99
	group.flowsMu.Lock()
	count = group.activeFlows[alpha.Name()]
	group.flowsMu.Unlock()
	require.Equal(t, 2, count, "the internal map must not leak through the snapshot")

	// Settlement releases exactly once per flow.
	flowOne.releaseActiveFlowCount()
	flowOne.releaseActiveFlowCount()
	group.flowsMu.Lock()
	count = group.activeFlows[alpha.Name()]
	group.flowsMu.Unlock()
	require.Equal(t, 1, count, "double release must not double-free")

	flowTwo.releaseActiveFlowCount()
	group.flowsMu.Lock()
	_, present := group.activeFlows[alpha.Name()]
	group.flowsMu.Unlock()
	require.False(t, present, "a zero count must not linger in the snapshot")
}
