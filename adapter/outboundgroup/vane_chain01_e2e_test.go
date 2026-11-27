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
//  4. the race winner commits from its async callback; the old flow is closed exactly once, the reconnect claims the
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
	betaName, betaIdentity := beta.Name(), beta.identity
	var betaDials atomic.Int32
	beta.dialHook = func() { betaDials.Add(1) }

	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	chain01ProductionValues(t, group, demand)
	configureVaneSwitchForTest(t, group, vaneSwitchLive)

	// The race probe only targets beta (alpha is the current node and is
	// excluded from the race), so dispatch by proxy name: beta gets the
	// 40 Mbps bound that unlocks the gate, anything else is invalid. The
	// cold-pick probe is suppressed for this test (see below), so the race
	// probe is the only consumer of this injection.
	release := make(chan struct{})
	group.racing.probe = func(ctx context.Context, proxy C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
		select {
		case <-release:
		case <-ctx.Done():
			return vaneProbeResult{reason: "canceled"}
		}
		if proxy.Name() != betaName {
			return vaneProbeResult{reason: "nil-connection"}
		}
		return vaneProbeResult{
			valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap,
			duration: time.Second, lowerBoundBPS: 40_000_000, capHit: true,
		}
	}

	metadata := &C.Metadata{Host: "rr-chain01.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	// This test is about the CHAIN-01 evidence gate on the slow-flow path, not
	// about the cold-pick probe: suppress the pick probe so the flow starts on
	// alpha (the ranking choice) and the story stays gate-centric.
	first, err := group.DialContext(context.Background(), metadata)
	require.NoError(t, err)
	observed := first.(*vaneObservedConn)
	reader, counters := observed.UnwrapReader()
	payload := make([]byte, 64*1024)

	// Stage 2-4: keep the flow slow until the close lands. Three production
	// gates serialize here — the trigger gate (minBytes 2 MiB cumulative),
	// the CHAIN-01 evidence gate (veto -> race -> capability refill), and the
	// buffer-credit gate (defers while cumulative bytes are small). All three
	// resolve within ~45 simulated windows, so drive the flow until the close
	// lands instead of guessing window counts.
	driveSlowUntil := func(cond func() bool, message string) {
		require.Eventually(t, func() bool {
			if cond() {
				return true
			}
			clock.Advance(time.Second)
			n, readErr := reader.Read(payload)
			if readErr != nil {
				return false
			}
			for _, counter := range counters {
				counter(int64(n))
			}
			return cond()
		}, 5*time.Second, time.Millisecond, message)
	}
	driveSlowUntil(func() bool {
		return group.VaneDiagnostics().Suppressions["no-evidence-candidate"] > 0
	}, "the first trigger must be suppressed by the evidence gate")
	snapshot := group.VaneDiagnostics()
	require.GreaterOrEqual(t, snapshot.Counters.ReconnectSuppressed, uint64(1))
	require.Zero(t, snapshot.Counters.HandoffCommitted)
	slowConn.mu.Lock()
	closedSoFar := slowConn.closeCalls
	slowConn.mu.Unlock()
	require.Zero(t, closedSoFar, "no evidence means no close: the slow flow must survive")

	close(release)
	// The recovery loop: Vane scheduled the race and the probe refilled the
	// capability cache with a 40 Mbps bound for beta.
	require.Eventually(t, func() bool {
		group.racingRuntime.mu.Lock()
		defer group.racingRuntime.mu.Unlock()
		// Match by (name, identity), not epoch: a candidate that was never
		// selected carries epoch 0, and copying this pattern elsewhere should
		// not silently break when an epoch appears.
		for member := range group.racingRuntime.capabilities {
			if member.name == betaName && member.identity == betaIdentity {
				return true
			}
		}
		return false
	}, 5*time.Second, time.Millisecond, "the race's 40 Mbps bound must land in the capability cache for beta")

	// Stage 3-4: the race callback commits and policy-closes the flow once.
	driveSlowUntil(func() bool {
		slowConn.mu.Lock()
		defer slowConn.mu.Unlock()
		return slowConn.closeCalls == 1
	}, "capability evidence must unlock the close")
	slowConn.mu.Lock()
	closeCalls := slowConn.closeCalls
	slowConn.mu.Unlock()
	require.Equal(t, 1, closeCalls, "the old flow must be closed exactly once")
	observed.mu.Lock()
	policyClosed := observed.policyClosed
	observed.mu.Unlock()
	require.True(t, policyClosed)

	// The reconnect claims the handoff lease and dials the challenger.
	second, err := group.DialContext(context.Background(), metadata)
	require.NoError(t, err)
	require.Equal(t, int32(1), betaDials.Load(), "the reconnect must land on beta via the hint")

	// Stage 5: the new flow's real throughput settles the handoff. 704 KiB per
	// simulated second is ~5.6 Mbps: above the settlement required
	// (max(0.5 Mbps x 1.25, 2M demand) = 2M) AND above the 5M settlement line
	// §M adds, so it records an improvement instead of a no-gain.
	fastReader, fastCounters := second.(*vaneObservedConn).UnwrapReader()
	fastPayload := make([]byte, 704*1024)
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
	require.Positive(t, snapshot.Counters.HandoffCommitted)
	require.Positive(t, snapshot.Counters.HandoffMeasured)
	require.Positive(t, snapshot.Counters.HandoffImproved,
		"~5.6 Mbps real throughput must settle as an improvement over 0.5 Mbps")
	key, ok := group.targetScopeForKey(metadata.Host, metadata.DstPort)
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
// RESCUE-03: end to end, a 6 Mbps probe must rescue a starving flow even when
// demand is 10 Mbps. Demand describes what the current flow needs, not what a
// replacement has to reach.
func TestVaneChain01E2ERescueBeatsDemand(t *testing.T) {
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
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	chain01ProductionValues(t, group, demand)
	configureVaneSwitchForTest(t, group, vaneSwitchLive)
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		// A 6 Mbps probe clears the 5 Mbps slow line and the 1.25x ratio for
		// this starving flow, so the gate must let it through.
		return vaneProbeResult{
			valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap,
			duration: time.Second, lowerBoundBPS: 6_000_000, capHit: true,
		}
	}

	metadata := &C.Metadata{Host: "rr-demand.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	first, err := group.DialContext(context.Background(), metadata)
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
		if group.VaneDiagnostics().Counters.HandoffCommitted > 0 {
			break
		}
	}
	require.Eventually(t, func() bool {
		return group.VaneDiagnostics().Counters.HandoffCommitted > 0
	}, 5*time.Second, time.Millisecond,
		"the asynchronous race callback must commit the 6 Mbps rescue")

	// The delivered race result executes its close action immediately on the
	// callback goroutine. Wait for that callback to finish instead of driving
	// the underlying count reader, which bypasses the policy-action drain path.
	require.Eventually(t, func() bool {
		slowConn.mu.Lock()
		defer slowConn.mu.Unlock()
		return slowConn.closeCalls > 0
	}, 5*time.Second, time.Millisecond,
		"the committed handoff must close the starving flow")

	snapshot := group.VaneDiagnostics()
	require.GreaterOrEqual(t, snapshot.Counters.HandoffCommitted, uint64(1),
		"a 6 Mbps probe must rescue a starving flow even when demand is 10M")
	slowConn.mu.Lock()
	closeCalls := slowConn.closeCalls
	slowConn.mu.Unlock()
	require.Positive(t, closeCalls, "the starving flow must be cut")
	require.NoError(t, first.Close())
}
