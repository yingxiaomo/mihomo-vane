package outboundgroup

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func TestVaneChurnTargetAndOrderingEdges(t *testing.T) {
	target, port, valid := vaneChurnTarget(nil)
	require.Empty(t, target)
	require.Zero(t, port)
	require.False(t, valid)

	_, _, valid = vaneChurnTarget(&C.Metadata{Host: "api.example.com", NetWork: C.TCP})
	require.False(t, valid)

	ip := netip.MustParseAddr("2001:db8::1")
	target, port, valid = vaneChurnTarget(&C.Metadata{DstIP: ip, DstPort: 443, NetWork: C.TCP})
	require.Equal(t, ip.String(), target)
	require.Equal(t, uint16(443), port)
	require.True(t, valid)
	require.False(t, vaneChurnDNSBootstrap(target, port))
	require.False(t, vaneChurnDNSBootstrap("cdnstatic.example.com", 443))
	require.True(t, vaneChurnDNSBootstrap("dns.example.com", 443))

	now := time.Unix(100, 0)
	older := &vaneChurnState{lastUpdated: now}
	newer := &vaneChurnState{lastUpdated: now.Add(time.Second)}
	require.True(t, churnStateOlder(vaneChurnKey{}, nil, vaneChurnKey{}, older))
	require.False(t, churnStateOlder(vaneChurnKey{}, older, vaneChurnKey{}, nil))
	require.True(t, churnStateOlder(vaneChurnKey{}, older, vaneChurnKey{}, newer))
	require.True(t, churnStateOlder(vaneChurnKey{target: "a"}, older, vaneChurnKey{target: "b"}, older))
	require.True(t, churnStateOlder(vaneChurnKey{target: "a", port: 1}, older, vaneChurnKey{target: "a", port: 2}, older))
	require.True(t, churnStateOlder(vaneChurnKey{target: "a", port: 1, candidate: "a"}, older, vaneChurnKey{target: "a", port: 1, candidate: "b"}, older))
}

func TestVaneChurnShadowDetectsOnlyRepeatedExactPair(t *testing.T) {
	clock := newVaneConnTestClock()
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, newVaneTestProxy("alpha", true, true))
	metadata := &C.Metadata{Host: "Api.Example.COM.", DstPort: 443, NetWork: C.TCP}
	observation := vaneConnectionCloseObservation{
		WrotePayload:   true,
		TotalReadBytes: vaneChurnMaxDownloadBytes - 1,
		Age:            5 * time.Second,
	}

	for i := 0; i < vaneChurnLimit-1; i++ {
		group.observeChurnClose("alpha", metadata, observation)
		clock.Advance(time.Second)
	}
	snapshot := group.VaneDiagnostics()
	require.Equal(t, uint64(vaneChurnLimit-1), snapshot.Counters.ChurnCandidates)
	require.Zero(t, snapshot.Counters.ChurnSuspected)

	group.observeChurnClose("alpha", metadata, observation)
	snapshot = group.VaneDiagnostics()
	require.Equal(t, uint64(vaneChurnLimit), snapshot.Counters.ChurnCandidates)
	require.Equal(t, uint64(1), snapshot.Counters.ChurnSuspected)
	require.Len(t, group.churn, 1)
	last := snapshot.RecentEvents[len(snapshot.RecentEvents)-1]
	require.Equal(t, "churn-suspected", last.Kind)
	require.Equal(t, "api.example.com", last.Target)
	require.Equal(t, uint16(443), last.Port)
	require.Equal(t, "alpha", last.From)
	require.Equal(t, vaneChurnLimit, last.Occurrences)
}

func TestVaneChurnShadowDataResetAndPartitions(t *testing.T) {
	clock := newVaneConnTestClock()
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, newVaneTestProxy("alpha", true, true))
	base := &C.Metadata{Host: "api.example.com", DstPort: 443, NetWork: C.TCP}
	tiny := vaneConnectionCloseObservation{WrotePayload: true, TotalReadBytes: 1, Age: time.Second}
	data := vaneConnectionCloseObservation{TotalReadBytes: vaneChurnMaxDownloadBytes, Age: vaneChurnMaxLifetime + time.Second}

	for i := 0; i < vaneChurnLimit-1; i++ {
		group.observeChurnClose("alpha", base, tiny)
	}
	group.observeChurnClose("alpha", base, data)
	for i := 0; i < vaneChurnLimit-1; i++ {
		group.observeChurnClose("alpha", base, tiny)
	}
	require.Zero(t, group.VaneDiagnostics().Counters.ChurnSuspected)
	require.Equal(t, uint64(1), group.VaneDiagnostics().Counters.ChurnResets)

	variants := []struct {
		candidate string
		metadata  *C.Metadata
	}{
		{candidate: "beta", metadata: base},
		{candidate: "alpha", metadata: &C.Metadata{Host: "other.example.com", DstPort: 443, NetWork: C.TCP}},
		{candidate: "alpha", metadata: &C.Metadata{Host: "api.example.com", DstPort: 8443, NetWork: C.TCP}},
	}
	for _, variant := range variants {
		group.observeChurnClose(variant.candidate, variant.metadata, tiny)
	}
	require.Zero(t, group.VaneDiagnostics().Counters.ChurnSuspected)
}

func TestVaneChurnShadowSuppressionsAndWindow(t *testing.T) {
	clock := newVaneConnTestClock()
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, newVaneTestProxy("alpha", true, true))
	valid := &C.Metadata{Host: "api.example.com", DstPort: 443, NetWork: C.TCP}

	tests := []struct {
		name        string
		metadata    *C.Metadata
		observation vaneConnectionCloseObservation
		reason      string
	}{
		{name: "no payload write", metadata: valid, observation: vaneConnectionCloseObservation{Age: time.Second}, reason: "no-positive-write"},
		{name: "zero age", metadata: valid, observation: vaneConnectionCloseObservation{WrotePayload: true, Age: 0}, reason: "lifetime-outside-window"},
		{name: "maximum age", metadata: valid, observation: vaneConnectionCloseObservation{WrotePayload: true, Age: vaneChurnMaxLifetime}, reason: "lifetime-outside-window"},
		{name: "udp", metadata: &C.Metadata{Host: "api.example.com", DstPort: 443, NetWork: C.UDP}, observation: vaneConnectionCloseObservation{WrotePayload: true, Age: time.Second}, reason: "non-tcp"},
		{name: "internal doh provenance", metadata: &C.Metadata{Type: C.INNER, Host: "resolver.example.com", DstPort: 443, NetWork: C.TCP}, observation: vaneConnectionCloseObservation{WrotePayload: true, Age: time.Second}, reason: "internal-flow"},
		{name: "dns port", metadata: &C.Metadata{Host: "resolver.example.com", DstPort: 853, NetWork: C.TCP}, observation: vaneConnectionCloseObservation{WrotePayload: true, Age: time.Second}, reason: "dns-bootstrap"},
		{name: "doh label", metadata: &C.Metadata{Host: "doh.pub", DstPort: 443, NetWork: C.TCP}, observation: vaneConnectionCloseObservation{WrotePayload: true, Age: time.Second}, reason: "dns-bootstrap"},
		{name: "invalid target", metadata: &C.Metadata{Host: "bad..example.com", DstPort: 443, NetWork: C.TCP}, observation: vaneConnectionCloseObservation{WrotePayload: true, Age: time.Second}, reason: "invalid-target"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			group.observeChurnClose("alpha", test.metadata, test.observation)
		})
	}
	snapshot := group.VaneDiagnostics()
	for _, test := range tests {
		require.NotZero(t, snapshot.ChurnSuppressions[test.reason], test.name)
	}
	require.Zero(t, snapshot.Counters.ChurnCandidates)

	tiny := vaneConnectionCloseObservation{WrotePayload: true, Age: time.Second}
	for i := 0; i < vaneChurnLimit-1; i++ {
		group.observeChurnClose("alpha", valid, tiny)
	}
	clock.Advance(vaneChurnWindow)
	group.observeChurnClose("alpha", valid, tiny)
	require.Zero(t, group.VaneDiagnostics().Counters.ChurnSuspected)
}

func TestVaneChurnShadowStateIsBoundedAndConcurrent(t *testing.T) {
	clock := newVaneConnTestClock()
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, newVaneTestProxy("alpha", true, true))
	tiny := vaneConnectionCloseObservation{WrotePayload: true, Age: time.Second}

	var wait sync.WaitGroup
	for i := 0; i < vaneChurnMaxStates+64; i++ {
		wait.Add(1)
		go func(port int) {
			defer wait.Done()
			group.observeChurnClose("alpha", &C.Metadata{Host: "api.example.com", DstPort: uint16(port + 1), NetWork: C.TCP}, tiny)
		}(i)
	}
	wait.Wait()

	group.churnMu.Lock()
	states := len(group.churn)
	group.churnMu.Unlock()
	require.LessOrEqual(t, states, vaneChurnMaxStates)
}

func TestVaneChurnShadowProductionDialPath(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.dialConn = &vaneConnTestConn{}
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	metadata := &C.Metadata{Host: "api.example.com", DstPort: 443, NetWork: C.TCP}

	for i := 0; i < vaneChurnLimit; i++ {
		conn, err := group.DialContext(context.Background(), metadata)
		require.NoError(t, err)
		_, err = conn.Write([]byte("request"))
		require.NoError(t, err)
		clock.Advance(time.Second)
		require.NoError(t, conn.Close())
	}

	snapshot := group.VaneDiagnostics()
	require.Equal(t, uint64(vaneChurnLimit), snapshot.Counters.ChurnCandidates)
	require.Equal(t, uint64(1), snapshot.Counters.ChurnSuspected)
	require.Equal(t, 0, snapshot.Runtime.ActiveChurnStates)
}

func TestVaneChurnShadowProductionDialPathExcludesInternalFlow(t *testing.T) {
	clock := newVaneConnTestClock()
	alpha := newVaneTestProxy("alpha", true, true)
	alpha.dialConn = &vaneConnTestConn{}
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha)
	metadata := &C.Metadata{Type: C.INNER, Host: "resolver.example.com", DstPort: 443, NetWork: C.TCP}

	for i := 0; i < vaneChurnLimit; i++ {
		conn, err := group.DialContext(context.Background(), metadata)
		require.NoError(t, err)
		_, err = conn.Write([]byte("request"))
		require.NoError(t, err)
		clock.Advance(time.Second)
		require.NoError(t, conn.Close())
	}

	snapshot := group.VaneDiagnostics()
	require.Zero(t, snapshot.Counters.ChurnCandidates)
	require.Zero(t, snapshot.Counters.ChurnSuspected)
	require.Equal(t, uint64(vaneChurnLimit), snapshot.ChurnSuppressions["internal-flow"])
}

func TestVaneObservedConnCloseObservationIsExactlyOnce(t *testing.T) {
	clock := newVaneConnTestClock()
	underlying := &vaneConnTestConn{reads: []vaneConnTestRead{{payload: []byte("reply")}}}
	var observations []vaneConnectionCloseObservation
	wrapped := newVaneControlledConnWithClose(underlying, clock, nil, nil, nil, func(observation vaneConnectionCloseObservation) {
		observations = append(observations, observation)
	})

	_, err := wrapped.Write([]byte("request"))
	require.NoError(t, err)
	clock.Advance(2 * time.Second)
	_, err = wrapped.Read(make([]byte, 16))
	require.NoError(t, err)
	require.NoError(t, wrapped.Close())
	require.NoError(t, wrapped.Close())

	require.Len(t, observations, 1)
	require.True(t, observations[0].WrotePayload)
	require.Equal(t, int64(len("reply")), observations[0].TotalReadBytes)
	require.Equal(t, 2*time.Second, observations[0].Age)
}

func TestVaneObservedConnRelayFenceIncludesLateDeliveredBytes(t *testing.T) {
	clock := newVaneConnTestClock()
	underlying := &vaneConnTestConn{}
	var observations []vaneConnectionCloseObservation
	wrapped := newVaneControlledConnWithClose(underlying, clock, nil, nil, nil, func(observation vaneConnectionCloseObservation) {
		observations = append(observations, observation)
	})
	observed := wrapped.(*vaneObservedConn)

	_, err := wrapped.Write([]byte("request"))
	require.NoError(t, err)
	observed.RelayStarted()
	_, counters := observed.UnwrapReader()
	require.Len(t, counters, 1)

	clock.Advance(time.Second)
	require.NoError(t, wrapped.Close())
	require.Empty(t, observations, "relay still has a delivered-byte callback in flight")
	counters[0](vaneChurnMaxDownloadBytes)
	observed.RelayFinished()

	require.Len(t, observations, 1)
	require.Equal(t, vaneChurnMaxDownloadBytes, observations[0].TotalReadBytes)
	require.Equal(t, time.Second, observations[0].Age)
	require.NoError(t, wrapped.Close())
	require.Len(t, observations, 1)
}

func TestVaneObservedConnPolicyCloseDoesNotFeedChurn(t *testing.T) {
	clock := newVaneConnTestClock()
	underlying := &vaneConnTestConn{reads: []vaneConnTestRead{{payload: make([]byte, vaneThroughputMinPayload)}}}
	var callbacks int
	wrapped := newVaneControlledConnWithClose(underlying, clock, nil, nil, func(vaneThroughputObservation) vanePolicyAction {
		return func() bool { return true }
	}, func(vaneConnectionCloseObservation) {
		callbacks++
	})

	_, err := wrapped.Write([]byte("request"))
	require.NoError(t, err)
	observed := wrapped.(*vaneObservedConn)
	observed.requestAbort(func() bool { return true })
	require.NoError(t, wrapped.Close())
	require.Zero(t, callbacks)
}
