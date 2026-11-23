package outboundgroup

import (
	"testing"
	"time"

	A "github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

// REGISTRY-01: a real reload (a second group with the same name, activated
// through the live entry point) starts from zero and leaves the old group's
// counters alone. Asserting only the new group would also pass if the
// implementation zeroed every counter, so both halves are required.
func TestVaneReloadStartsCountersFromZero(t *testing.T) {
	oldHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(oldHome) })
	useVaneLearningRegistryStoreForTest(t, "vane-test", newVaneLearningTestStore())

	clock := newVaneConnTestClock()
	first, _ := newVaneGroupForTest(clock, 10, time.Hour, newVaneTestProxy("alpha", true, true))
	require.NoError(t, ActivateVaneLearningStates(map[string]C.Proxy{"vane": A.NewProxy(first)}))
	first.diagnostics.record(vaneDiagnosticRecord{kind: "handoff-committed"})
	require.Equal(t, uint64(1), first.VaneDiagnostics().Counters.HandoffCommitted)

	second, _ := newVaneGroupForTest(clock, 10, time.Hour, newVaneTestProxy("alpha", true, true))
	require.NoError(t, ActivateVaneLearningStates(map[string]C.Proxy{"vane": A.NewProxy(second)}))
	require.Equal(t, uint64(1), first.VaneDiagnostics().Counters.HandoffCommitted,
		"activating a second group must not touch the first one's counters")
	require.Zero(t, second.VaneDiagnostics().Counters.HandoffCommitted,
		"a fresh group starts from zero")
}

// RING-01: deleting the ring must not touch the log path — a record still
// reaches the sink.
func TestVaneRecordStillReachesSink(t *testing.T) {
	clock := newVaneConnTestClock()
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, newVaneTestProxy("alpha", true, true))
	group.diagnostics.record(vaneDiagnosticRecord{kind: "handoff-committed"})
	require.Equal(t, 1, countVaneEvents(group, "handoff-committed", ""))
}

// RING-02: exploration token ids come from a counter, monotonic and unique.
func TestVaneExplorationIDsStayMonotonic(t *testing.T) {
	clock := newVaneConnTestClock()
	diagnostics := newVaneDiagnostics("vane-exploration", clock)
	first := diagnostics.recordExplorationSelection(vaneExplorationSelection{transport: vaneTransportTCP, scene: vaneSceneMedia})
	second := diagnostics.recordExplorationSelection(vaneExplorationSelection{transport: vaneTransportTCP, scene: vaneSceneMedia})
	require.NotNil(t, first)
	require.NotNil(t, second)
	require.Equal(t, uint64(1), first.id)
	require.Equal(t, uint64(2), second.id)
}

// RING-03: a baseline handoff token takes its id from the record, not a ring
// sequence.
func TestVaneHandoffTokenIDComesFromRecord(t *testing.T) {
	clock := newVaneConnTestClock()
	diagnostics := newVaneDiagnostics("vane-handoff", clock)
	token := diagnostics.recordReconnectCommit(vaneDiagnosticRecord{kind: "reconnect-committed"})
	require.NotNil(t, token)
	require.Equal(t, vaneBaselineTokenIDBase+1, token.id)
}
