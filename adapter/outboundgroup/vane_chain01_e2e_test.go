package outboundgroup

// End-to-end integration tests for the CHAIN-01 evidence gate, driven through
// the real connection path (DialContext -> vaneObservedConn -> relay counters
// -> observe windows -> prepare/commit -> policy close -> reconnect ->
// settlement) instead of calling the individual pieces.

import (
	"context"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// chain01E2E is the full production story on real connections:
//
//  1. a slow flow (real reads below the 5 Mbps bar) accumulates low windows;
//  2. the first trigger is blocked by the evidence gate (no-evidence-candidate)
//     because every challenger lacks fresh evidence — the flow is NOT closed;
//  3. shadow/on racing schedules a probe, and the probe's 40 Mbps bound fills
//     the capability cache (the recovery loop);
//  4. the next slow window admits the challenger on capability evidence and
//     commits; the old flow is closed exactly once, the reconnect claims the
//     handoff lease;
//  5. the new flow's real throughput settles the handoff: improved with demand
//     2M, no-gain (and no preference) with demand 10M.
//
// "Real reads" here means the test drives the actual wrapped connection
// (DialContext + UnwrapReader counters), not hand-written plans or observe()
// calls with fabricated samples.
func TestVaneChain01E2ESlowFlowThroughEvidenceGate(t *testing.T) {
	const demand = 2_000_000

	clock := newVaneConnTestClock()
	fill := func(b byte) func([]byte) (int, error) {
		return func(payload []byte) (int, error) {
			for i := range payload {
				payload[i] = b
			}
			return len(payload), nil
		}
	}
	slowConn := &vaneConnTestConn{readFunc: fill(1)}
	fastConn := &vaneConnTestConn{readFunc: fill(2)}
	alpha := newVaneTestProxy("alpha", true, true) // slow node the flow rides on
	alpha.delay = 20
	alpha.dialConn = slowConn
	beta := newVaneTestProxy("beta", true, true) // fast challenger, no evidence yet
	beta.delay = 10
	beta.dialConn = fastConn
	var betaDials atomic.Int32
	beta.dialHook = func() { betaDials.Add(1) }

	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	chain01ProductionValues(t, group, demand)
	configureVaneRacingForTest(t, group, vaneRacingShadow)

	probeCalled := atomic.Bool{}
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		probeCalled.Store(true)
		return vaneProbeResult{
			valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap,
			duration: time.Second, lowerBoundBPS: 40_000_000, capHit: true,
		}
	}

	metadata := &C.Metadata{Host: "rr-chain01.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	first, err := group.DialContext(t.Context(), metadata)
	require.NoError(t, err)
	observed := first.(*vaneObservedConn)
	reader, counters := observed.UnwrapReader()
	payload := make([]byte, 64*1024)

	// Drive the slow flow with real reads: 64 KiB per simulated second is
	// ~0.5 Mbps, every window is low. Windows 1-2 only accumulate; window 3
	// triggers prepare for the first time.
	driveSlow := func(windows int) {
		for i := 0; i < windows*6; i++ {
			if i > 0 {
				clock.Advance(time.Second)
			}
			n, readErr := reader.Read(payload)
			require.NoError(t, readErr)
			require.Equal(t, len(payload), n)
			for _, counter := range counters {
				counter(int64(n))
			}
		}
	}

	// Stage 2: keep the flow slow until the first trigger. Two production
	// gates delay it: minBytes 2 MiB (cumulative) and the buffer-credit guard.
	// Drive 6 windows (~2.3 MiB cumulative at 64 KiB/s) so both pass; the
	// first prepare must be vetoed by the evidence gate.
	driveSlow(6)
	require.Eventually(t, func() bool {
		return group.VaneDiagnostics().Suppressions["no-evidence-candidate"] > 0
	}, 3*time.Second, time.Millisecond, "the first trigger must be suppressed by the evidence gate")
	snapshot := group.VaneDiagnostics()
	require.GreaterOrEqual(t, snapshot.Counters.ReconnectSuppressed, uint64(1))
	require.Zero(t, snapshot.Counters.ReconnectCommitted)
	slowConn.mu.Lock()
	closedSoFar := slowConn.closeCalls
	slowConn.mu.Unlock()
	require.Zero(t, closedSoFar, "no evidence means no close: the slow flow must survive")

	// The recovery loop: shadow scheduled the race and the probe refilled the
	// capability cache with a 40 Mbps bound for beta.
	require.Eventually(t, probeCalled.Load, 2*time.Second, time.Millisecond,
		"shadow must schedule the recovery race after the gate veto")
	require.Eventually(t, func() bool {
		group.racingRuntime.mu.Lock()
		defer group.racingRuntime.mu.Unlock()
		return len(group.racingRuntime.capabilities) > 0
	}, 2*time.Second, time.Millisecond, "the probe bound must land in the capability cache")

	// Stage 3-4: the next slow window admits beta on capability evidence,
	// commits, and policy-closes the old flow exactly once. The buffer-credit
	// gate defers until lowWindows reaches maxLowWindows (4).
	driveSlow(2)
	require.Eventually(t, func() bool {
		slowConn.mu.Lock()
		defer slowConn.mu.Unlock()
		return slowConn.closeCalls == 1
	}, 3*time.Second, time.Millisecond, "capability evidence must unlock the close")
	slowConn.mu.Lock()
	closeCalls := slowConn.closeCalls
	slowConn.mu.Unlock()
	require.Equal(t, 1, closeCalls, "the old flow must be closed exactly once")
	observed.mu.Lock()
	policyClosed := observed.policyClosed
	observed.mu.Unlock()
	require.True(t, policyClosed)

	// The reconnect claims the handoff lease and dials the challenger.
	second, err := group.DialContext(t.Context(), metadata)
	require.NoError(t, err)
	require.Equal(t, int32(1), betaDials.Load(), "the reconnect must land on beta via the hint")

	// Stage 5: the new flow's real throughput settles the handoff. 384 KiB per
	// simulated second is ~3.1 Mbps: above the settlement required
	// (max(0.5 Mbps x 1.25, 2M demand) = 2M), so it records an improvement.
	fastReader, fastCounters := second.(*vaneObservedConn).UnwrapReader()
	fastPayload := make([]byte, 384*1024)
	for i := 0; i < 12; i++ {
		if i > 0 {
			clock.Advance(time.Second)
		}
		n, readErr := fastReader.Read(fastPayload)
		require.NoError(t, readErr)
		for _, counter := range fastCounters {
			counter(int64(n))
		}
	}

	snapshot = group.VaneDiagnostics()
	require.Positive(t, snapshot.Counters.ReconnectCommitted)
	require.Positive(t, snapshot.Counters.HandoffMeasured)
	require.Positive(t, snapshot.Counters.HandoffImproved,
		"~3.1 Mbps real throughput must settle as an improvement over 0.5 Mbps")
	key, ok := group.targetKeyForMedia(metadata.Host, metadata.DstPort)
	require.True(t, ok)
	group.mu.Lock()
	preference, preferred := group.targetPreferences[key]
	group.mu.Unlock()
	require.True(t, preferred, "a proven improvement must create the target preference")
	require.Equal(t, "beta", preference.to.name)

	require.NoError(t, first.Close())
	require.NoError(t, second.Close())
}

// The demand-10M variant: the same physical story, but the challenger's 12.6
// Mbps settles below demand, so the settlement records no-gain, no preference
// is created, and the close itself is vetoed outright (the close bar includes
// demand) — the flow survives on the slow node rather than being cut to a
// node that cannot carry 4K.
func TestVaneChain01E2EDemandGatesTheClose(t *testing.T) {
	const demand = 10_000_000

	clock := newVaneConnTestClock()
	fill := func(payload []byte) (int, error) {
		for i := range payload {
			payload[i] = 1
		}
		return len(payload), nil
	}
	slowConn := &vaneConnTestConn{readFunc: fill}
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.delay = 20
	alpha.dialConn = slowConn
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	chain01ProductionValues(t, group, demand)
	configureVaneRacingForTest(t, group, vaneRacingShadow)
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		// A 6 Mbps probe clears the 5 Mbps slow line but not the 10M
		// demand-inclusive close bar: the gate must hold.
		return vaneProbeResult{
			valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap,
			duration: time.Second, lowerBoundBPS: 6_000_000, capHit: true,
		}
	}

	metadata := &C.Metadata{Host: "rr-demand.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	first, err := group.DialContext(t.Context(), metadata)
	require.NoError(t, err)
	observed := first.(*vaneObservedConn)
	reader, counters := observed.UnwrapReader()
	payload := make([]byte, 64*1024)

	driveSlow := func(windows int) {
		for i := 0; i < windows*6; i++ {
			if i > 0 {
				clock.Advance(time.Second)
			}
			n, readErr := reader.Read(payload)
			require.NoError(t, readErr)
			require.Equal(t, len(payload), n)
			for _, counter := range counters {
				counter(int64(n))
			}
		}
	}

	// Enough windows to pass maxLowWindows and exhaust every buffer-credit
	// deferral: with demand 10M the credit check defers repeatedly
	// (8 MiB*8 - 10M*30s < 10M*5s), so keep driving until the gate speaks.
	for i := 0; i < 8; i++ {
		driveSlow(1)
		snapshot := group.VaneDiagnostics()
		if snapshot.Suppressions["no-evidence-candidate"] > 0 {
			break
		}
	}

	snapshot := group.VaneDiagnostics()
	require.GreaterOrEqual(t, snapshot.Suppressions["no-evidence-candidate"], uint64(1),
		"a 6 Mbps probe cannot justify cutting a 4K flow when demand is 10M")
	require.Zero(t, snapshot.Counters.ReconnectCommitted)
	slowConn.mu.Lock()
	closeCalls := slowConn.closeCalls
	slowConn.mu.Unlock()
	require.Zero(t, closeCalls, "the flow must survive: no candidate clears the demand-inclusive bar")
	require.NoError(t, first.Close())
}
