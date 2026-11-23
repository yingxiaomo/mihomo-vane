package outboundgroup

import (
	"context"
	"reflect"
	"syscall"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

// BACKLOG-01: an injected backlog stamp suppresses low-window counting.
// (Injection tests the gate; BACKLOG-08 covers the real collection path.)
func TestVaneBacklogStampSuppressesLowWindow(t *testing.T) {
	group, clock, flow := newVaneObservationRig(t, vaneRacingOn)
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	flow.mu.Lock()
	flow.backloggedAt = clock.Now()
	flow.mu.Unlock()

	require.Nil(t, flow.observe(vaneObservationLowSample()))
	flow.mu.Lock()
	require.Zero(t, flow.lowWindows, "a backlogged window is the client's fault, not the node's")
	flow.mu.Unlock()
	require.Equal(t, 1, countVaneEvents(group, "low-window-graced", "client-backlog"))
	require.Zero(t, countVaneEvents(group, "low-window-graced", "recently-fast"))
	require.Zero(t, countVaneEvents(group, "race-scheduled", ""))

	group.mu.Lock()
	require.Empty(t, group.targetEvidence, "an untrusted window must not write target evidence")
	require.Empty(t, group.targetPreferences)
	group.mu.Unlock()
}

// BACKLOG-02: the synthetic watchdog window is subject to the same gate.
func TestVaneBacklogStampSuppressesSyntheticWindow(t *testing.T) {
	_, clock, flow := newVaneObservationRig(t, vaneRacingOn)
	t.Cleanup(func() {
		if group := flow.group; group != nil {
			dropVaneRecordedEvents(group)
		}
	})
	require.Nil(t, flow.observe(vaneThroughputObservation{BitsPerSecond: 6_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second}))
	clock.Advance(35 * time.Second)

	flow.mu.Lock()
	flow.backloggedAt = clock.Now()
	before := flow.lowWindows
	flow.mu.Unlock()
	flow.observeSyntheticStall(clock.Now())
	flow.mu.Lock()
	require.Equal(t, before, flow.lowWindows, "a stalled-but-backlogged flow gains no low window")
	require.Equal(t, float64(1), flow.lastSample.BitsPerSecond, "the watchdog still synthesises its sample")
	flow.mu.Unlock()
}

// BACKLOG-03: no backlog -> low windows keep accumulating.
func TestVaneBacklogAbsentKeepsCounting(t *testing.T) {
	group, _, flow := newVaneObservationRig(t, vaneRacingOn)
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	for i := 0; i < 3; i++ {
		require.Nil(t, flow.observe(vaneObservationLowSample()))
		flow.mu.Lock()
		require.Equal(t, i+1, flow.lowWindows)
		flow.mu.Unlock()
	}
	require.Equal(t, 1, countVaneEvents(group, "race-scheduled", ""))
	require.Zero(t, countVaneEvents(group, "low-window-graced", ""))
}

// BACKLOG-04: the stamp expires after two watchdog ticks; counting resumes.
func TestVaneBacklogStampExpires(t *testing.T) {
	group, clock, flow := newVaneObservationRig(t, vaneRacingOn)
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	flow.mu.Lock()
	flow.backloggedAt = clock.Now()
	flow.mu.Unlock()
	for i := 0; i < 2; i++ {
		require.Nil(t, flow.observe(vaneObservationLowSample()))
	}
	flow.mu.Lock()
	require.Zero(t, flow.lowWindows)
	flow.backloggedAt = clock.Now().Add(-2*vaneMediaWatchdogTick - time.Second)
	flow.mu.Unlock()

	require.Nil(t, flow.observe(vaneObservationLowSample()))
	flow.mu.Lock()
	require.Equal(t, 1, flow.lowWindows, "an expired stamp must not suppress forever")
	flow.mu.Unlock()
}

// BACKLOG-05: the counting reader splits read from delivered, clamps at zero,
// and stays a bare io.Reader so sing cannot unwrap or splice around it.
func TestVaneBacklogCountReader(t *testing.T) {
	clock := newVaneConnTestClock()
	controlled := newVaneControlledConnWithNative(&vaneConnTestConn{
		readFunc: func(payload []byte) (int, error) { return copy(payload, make([]byte, 100)), nil },
	}, clock, nil, nil, nil, nil, nil, nil, nil)
	conn := controlled.(*vaneObservedConn)
	reader, counters := conn.UnwrapReader()
	require.Len(t, counters, 1)

	require.Zero(t, conn.pendingBacklog())
	n, err := reader.Read(make([]byte, 128))
	require.NoError(t, err)
	require.Equal(t, 100, n)
	require.Equal(t, int64(100), conn.pendingBacklog(), "read but not delivered is backlog")

	counters[0](40)
	require.Equal(t, int64(60), conn.pendingBacklog())
	counters[0](1000)
	require.Zero(t, conn.pendingBacklog(), "delivered more than read (handshake bypass) clamps to zero")

	typ := reflect.TypeOf(reader)
	for _, name := range []string{"ReadBuffer", "UnwrapReader", "ReadCounter", "Upstream", "ReaderReplaceable", "WriterReplaceable"} {
		_, implemented := typ.MethodByName(name)
		require.False(t, implemented, "the counting reader must not implement %s", name)
	}
	_, isSyscall := reader.(syscall.Conn)
	require.False(t, isSyscall, "syscall.Conn would let sing splice past the counter")
}

// BACKLOG-06: a flow with no probe wired behaves exactly as before.
func TestVaneBacklogUnwiredFlow(t *testing.T) {
	group, clock, flow := newVaneObservationRig(t, vaneRacingOn)
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	flow.mu.Lock()
	require.Nil(t, flow.backlogFunc, "the rig never wires a connection")
	flow.mu.Unlock()

	clock.Advance(vaneMediaWatchdogTick)
	group.runMediaWatchdogTick(clock.Now())
	require.Nil(t, flow.observe(vaneObservationLowSample()))
	flow.mu.Lock()
	require.Equal(t, 1, flow.lowWindows)
	flow.mu.Unlock()
}

// BACKLOG-08: the real path — DialContext wires the probe, the relay reads
// without the client draining, and the watchdog tick stamps the flow.
func TestVaneBacklogWiredThroughDialContext(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.dialConn = &vaneConnTestConn{
		readFunc: func(payload []byte) (int, error) { return copy(payload, make([]byte, 4096)), nil },
	}
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	configureVaneRacingForTest(t, group, vaneRacingOn)
	chain01ProductionValues(t, group, 1_000_000)
	t.Cleanup(func() { _ = group.Close() })
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	metadata := &C.Metadata{Host: "rr-backlog.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	suppressColdPickProbeForTest(t, group, metadata)

	conn, err := group.DialContext(context.Background(), metadata)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	observed := conn.(*vaneObservedConn)
	reader, _ := observed.UnwrapReader()
	n, err := reader.Read(make([]byte, 8192))
	require.NoError(t, err)
	require.Positive(t, n)
	require.Positive(t, observed.pendingBacklog(), "bytes read by the relay but never delivered")

	group.mediaFlowsMu.Lock()
	var flow *vaneMediaFlow
	for candidate := range group.mediaFlowSet {
		flow = candidate
	}
	group.mediaFlowsMu.Unlock()
	require.NotNil(t, flow)

	now := clock.Now()
	group.runMediaWatchdogTick(now)
	flow.mu.Lock()
	stamped := flow.backloggedAt
	flow.mu.Unlock()
	require.Equal(t, now, stamped, "the watchdog must see the real backlog through the wiring")
}

// BACKLOG-07: a genuinely slow flow with a drained connection still triggers.
func TestVaneBacklogDrainedSlowFlowStillTriggers(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.dialConn = &vaneConnTestConn{
		readFunc: func(payload []byte) (int, error) { return copy(payload, make([]byte, 4096)), nil },
	}
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	configureVaneRacingForTest(t, group, vaneRacingOn)
	chain01ProductionValues(t, group, 1_000_000)
	t.Cleanup(func() { _ = group.Close() })
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	metadata := &C.Metadata{Host: "rr-backlog-slow.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	suppressColdPickProbeForTest(t, group, metadata)

	conn, err := group.DialContext(context.Background(), metadata)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	observed := conn.(*vaneObservedConn)
	reader, counters := observed.UnwrapReader()
	group.mediaFlowsMu.Lock()
	var flow *vaneMediaFlow
	for candidate := range group.mediaFlowSet {
		flow = candidate
	}
	group.mediaFlowsMu.Unlock()
	require.NotNil(t, flow)

	for i := 0; i < 3; i++ {
		n, err := reader.Read(make([]byte, 4096))
		require.NoError(t, err)
		for _, counter := range counters {
			counter(int64(n)) // the client drains every byte: no backlog
		}
		require.Zero(t, observed.pendingBacklog())
		require.Nil(t, flow.observe(vaneObservationLowSample()))
	}
	require.Equal(t, 1, countVaneEvents(group, "race-scheduled", ""), "a slow flow without backlog must still race")
	require.Zero(t, countVaneEvents(group, "low-window-graced", "client-backlog"))
}
