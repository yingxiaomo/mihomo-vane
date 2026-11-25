package outboundgroup

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// B2-FLOWCOUNT-001: per-node live media-flow counts are observation-only —
// flows +1 on successful creation, −1 exactly once on settlement, and the
// runtime snapshot exposes a copy, never the internal map.
func TestVaneB2ActiveMediaFlows(t *testing.T) {
	group, _, alpha, _, _ := newVaneRacingEvidenceGroup(t)
	mediaMetadata := &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP}

	flowOne := newVaneMediaFlow(group, alpha.Name(), mediaMetadata)
	require.NotNil(t, flowOne)
	flowTwo := newVaneMediaFlow(group, alpha.Name(), mediaMetadata)
	require.NotNil(t, flowTwo)

	group.mediaFlowsMu.Lock()
	count := group.mediaActiveFlows[alpha.Name()]
	group.mediaFlowsMu.Unlock()
	require.Equal(t, 2, count, "two live flows hold two counts")

	// Non-media flows are watched but must not hold a media count.
	nonMedia := newVaneMediaFlow(group, alpha.Name(), &C.Metadata{Host: "example.com", DstPort: 443, NetWork: C.TCP})
	require.NotNil(t, nonMedia, "PHASE1: every TCP flow is watched")
	require.False(t, nonMedia.counted, "a non-media flow holds no B2 count")
	nonMedia.releaseActiveFlowCount()
	group.mediaFlowsMu.Lock()
	count = group.mediaActiveFlows[alpha.Name()]
	group.mediaFlowsMu.Unlock()
	require.Equal(t, 2, count)

	// The snapshot must be a copy: mutating it must not touch the group state.
	snapshot := group.VaneDiagnostics()
	require.Equal(t, map[string]int{alpha.Name(): 2}, snapshot.Runtime.B2ActiveMediaFlows)
	snapshot.Runtime.B2ActiveMediaFlows[alpha.Name()] = 99
	group.mediaFlowsMu.Lock()
	count = group.mediaActiveFlows[alpha.Name()]
	group.mediaFlowsMu.Unlock()
	require.Equal(t, 2, count, "the internal map must not leak through the snapshot")

	// Settlement releases exactly once per flow.
	flowOne.releaseActiveFlowCount()
	flowOne.releaseActiveFlowCount()
	group.mediaFlowsMu.Lock()
	count = group.mediaActiveFlows[alpha.Name()]
	group.mediaFlowsMu.Unlock()
	require.Equal(t, 1, count, "double release must not double-free")

	flowTwo.releaseActiveFlowCount()
	group.mediaFlowsMu.Lock()
	_, present := group.mediaActiveFlows[alpha.Name()]
	group.mediaFlowsMu.Unlock()
	require.False(t, present, "a zero count must not linger in the snapshot")
}
