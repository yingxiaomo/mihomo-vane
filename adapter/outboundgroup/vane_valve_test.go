package outboundgroup

// §E acceptance tests (VALVE-01..04): the re-evaluation valve for flows that
// were just switched to and keep producing no qualified samples. The valve
// fires from noteEmptyWindow (two consecutive empty windows), re-runs prepare
// from the switched-to node with the pre-switch speed, skips the reconnect
// cooldown the original commit wrote, and closes the flow early when a
// better-evidenced candidate exists.

import (
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// newValveRig commits a baseline handoff alpha→beta and builds the switched-to
// flow on beta with a real connection wired for policy submission — the same
// wiring DialContext uses, driven by hand for deterministic windows.
func newValveRig(t *testing.T, demandBPS float64) (*Vane, *vaneConnTestClock, *vaneTestProxy, *vaneTestProxy, *vaneTestProxy, *vaneFlow, *vaneObservedConn, *vaneConnTestConn, *C.Metadata, vaneFlowKey) {
	t.Helper()
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.delay = 20
	beta := newVaneTestProxy("beta", true, true)
	beta.delay = 10
	gamma := newVaneTestProxy("gamma", true, true)
	gamma.delay = 30
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta, gamma)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	chain01ProductionValues(t, group, demandBPS)
	configureVaneSwitchForTest(t, group, vaneSwitchLive)
	metadata := &C.Metadata{Host: "rr-valve.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	scopeKey := group.targetScopeKey(metadata.Host, metadata.DstPort)

	// The original switch: alpha→beta, beta holds fresh node evidence.
	seedChain01Traffic(t, group, beta.Name(), clock.Now(), 12_000_000)
	plan, reason := chain01Prepare(t, group, metadata, alpha, 1_600_000)
	require.Empty(t, reason)
	require.Equal(t, beta.Name(), plan.challenger)
	require.Empty(t, group.commitReconnectDetailed(plan))

	// The switched-to flow claims the handoff token on its own connection.
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	require.NotNil(t, decision.handoff)
	require.Equal(t, beta.Name(), decision.proxy.Name())
	underlying := &vaneConnTestConn{}
	observed := newVaneObservedConn(underlying, clock, nil, nil).(*vaneObservedConn)
	flow := newVaneFlow(group, decision.proxy.Name(), metadata, decision.handoff)
	require.NotNil(t, flow)
	flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
	flow.setPolicySubmitter(observed.submitPolicyAction)
	observed.setOnEmptyWindow(flow.noteEmptyWindow)
	return group, clock, alpha, beta, gamma, flow, observed, underlying, metadata, scopeKey
}

// valveEventCount counts reconnect-valve diagnostics records.
func valveEventCount(t *testing.T, group *Vane) int {
	t.Helper()
	return countVaneEvents(group, "reconnect-valve", "")
}

// VALVE-01: two empty windows fire the valve; the re-run prepare finds the
// better-evidenced candidate and the early close commits WITHOUT hitting the
// reconnect cooldown the original commit wrote.
func TestVaneValveClosesToBetterEvidence(t *testing.T) {
	group, clock, _, beta, gamma, flow, observed, _, _, scopeKey := newValveRig(t, 2_000_000)
	seedChain01Traffic(t, group, gamma.Name(), clock.Now(), 12_000_000)

	group.mu.Lock()
	require.NotEmpty(t, group.ledger[scopeKey], "the original commit armed the ledger")
	group.mu.Unlock()

	flow.noteEmptyWindow()
	flow.noteEmptyWindow()

	// The valve re-ran prepare, committed with the skip flag, and closed the
	// flow through the normal policy path.
	require.True(t, observed.policyClosed, "the early close must close the switched-to connection")
	group.mu.Lock()
	hint := group.hints[scopeKey]
	group.mu.Unlock()
	require.Equal(t, gamma.Name(), hint.candidate, "the valve must land on the better-evidenced candidate")
	require.Positive(t, group.VaneDiagnostics().Counters.ReconnectCommitted)
	require.Equal(t, 1, valveEventCount(t, group))
	require.Zero(t, group.VaneDiagnostics().Counters.HandoffNoGain)
	_ = beta
}

// VALVE-02: one valve run per target per throttle window — a second empty
// streak inside the window does nothing, and the throttle expires.
func TestVaneValveThrottlesPerTarget(t *testing.T) {
	group, clock, _, _, _, flow, observed, _, _, _ := newValveRig(t, 2_000_000)
	// No candidate evidence: the first fire records the valve run but finds
	// nothing, leaving the flow alive for the throttle assertions.
	flow.noteEmptyWindow()
	flow.noteEmptyWindow()
	require.False(t, observed.policyClosed)
	require.Equal(t, 1, valveEventCount(t, group))

	// Inside the throttle: two more empty windows do not re-run.
	flow.noteEmptyWindow()
	flow.noteEmptyWindow()
	require.Equal(t, 1, valveEventCount(t, group), "the throttle must suppress the second run")
	require.False(t, observed.policyClosed)

	// The throttle expires: the next streak runs again.
	clock.Advance(11 * time.Minute)
	flow.noteEmptyWindow()
	flow.noteEmptyWindow()
	require.Equal(t, 2, valveEventCount(t, group), "the valve runs again after the throttle expires")
}

// VALVE-03: a flow that did not claim a handoff never arms the valve.
func TestVaneValveDoesNotArmWithoutHandoff(t *testing.T) {
	_, _, _, _, _, flow, observed, _, _, _ := newValveRig(t, 2_000_000)
	flow.switchedTo = false
	flow.noteEmptyWindow()
	flow.noteEmptyWindow()
	require.False(t, observed.policyClosed)
	require.Equal(t, 0, valveEventCount(t, flow.group))
}

// VALVE-04: a qualified sample resets the empty-window streak mid-streak.
func TestVaneValveStreakResetsOnQualifiedSample(t *testing.T) {
	group, _, _, _, _, flow, observed, _, _, _ := newValveRig(t, 2_000_000)

	flow.noteEmptyWindow()
	// A qualified window arrives: observe() runs and clears the streak.
	require.Nil(t, flow.observe(vaneThroughputObservation{
		BitsPerSecond: 12_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second,
	}))
	flow.mu.Lock()
	require.Zero(t, flow.valveEmptyWindows, "the qualified sample must reset the streak")
	flow.mu.Unlock()

	flow.noteEmptyWindow()
	require.False(t, observed.policyClosed, "one empty window after the reset must not fire")
	require.Equal(t, 0, valveEventCount(t, group))
}

// The conn-layer half of §E: a settled 5-second window with no qualified
// sample fires the hook once; a qualified window does not.
func TestVaneConnEmptyWindowHook(t *testing.T) {
	clock := newVaneConnTestClock()
	var empties atomic.Int32
	// Continuous 1KB reads spaced 1s apart (below the 2s idle gap), so each
	// 5-second window settles through the window branch, not the gap branch.
	reads := make([]vaneConnTestRead, 12)
	for i := range reads {
		reads[i] = vaneConnTestRead{payload: make([]byte, 1024)}
	}
	observed := newVaneObservedConn(&vaneConnTestConn{reads: reads}, clock, nil, nil).(*vaneObservedConn)
	observed.setOnEmptyWindow(func() { empties.Add(1) })

	// Window 1: 6KB over 5 seconds — below the sample gate → empty.
	for i := 0; i < 6; i++ {
		if i > 0 {
			clock.Advance(time.Second)
		}
		_, err := observed.Read(make([]byte, 1024))
		require.NoError(t, err)
	}
	require.Equal(t, int32(1), empties.Load(), "6KB in 5s is an empty window")

	// Window 2: 43KB over 5 seconds — a qualified sample, no hook.
	reads[6] = vaneConnTestRead{payload: make([]byte, 40*1024)}
	for i := 0; i < 6; i++ {
		clock.Advance(time.Second)
		buf := make([]byte, 1024)
		if i == 0 {
			buf = make([]byte, 40*1024)
		}
		_, err := observed.Read(buf)
		require.NoError(t, err)
	}
	require.Equal(t, int32(1), empties.Load(), "a qualified window does not fire the hook")
}
