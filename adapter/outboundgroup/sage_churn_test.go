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

func TestSageChurnTargetAndOrderingEdges(t *testing.T) {
	target, port, valid := sageChurnTarget(nil)
	require.Empty(t, target)
	require.Zero(t, port)
	require.False(t, valid)

	_, _, valid = sageChurnTarget(&C.Metadata{Host: "api.example.com", NetWork: C.TCP})
	require.False(t, valid)

	ip := netip.MustParseAddr("2001:db8::1")
	target, port, valid = sageChurnTarget(&C.Metadata{DstIP: ip, DstPort: 443, NetWork: C.TCP})
	require.Equal(t, ip.String(), target)
	require.Equal(t, uint16(443), port)
	require.True(t, valid)
	require.False(t, sageChurnDNSBootstrap(target, port))
	require.False(t, sageChurnDNSBootstrap("cdnstatic.example.com", 443))
	require.True(t, sageChurnDNSBootstrap("dns.example.com", 443))

	now := time.Unix(100, 0)
	older := &sageChurnState{lastUpdated: now}
	newer := &sageChurnState{lastUpdated: now.Add(time.Second)}
	require.True(t, churnStateOlder(sageChurnKey{}, nil, sageChurnKey{}, older))
	require.False(t, churnStateOlder(sageChurnKey{}, older, sageChurnKey{}, nil))
	require.True(t, churnStateOlder(sageChurnKey{}, older, sageChurnKey{}, newer))
	require.True(t, churnStateOlder(sageChurnKey{target: "a"}, older, sageChurnKey{target: "b"}, older))
	require.True(t, churnStateOlder(sageChurnKey{target: "a", port: 1}, older, sageChurnKey{target: "a", port: 2}, older))
	require.True(t, churnStateOlder(sageChurnKey{target: "a", port: 1, candidate: "a"}, older, sageChurnKey{target: "a", port: 1, candidate: "b"}, older))
}

func TestSageChurnShadowDetectsOnlyRepeatedExactPair(t *testing.T) {
	clock := newSageConnTestClock()
	group, _ := newSageGroupForTest(clock, 10, time.Hour, newSageTestProxy("alpha", true, true))
	metadata := &C.Metadata{Host: "Api.Example.COM.", DstPort: 443, NetWork: C.TCP}
	observation := sageConnectionCloseObservation{
		WrotePayload:   true,
		TotalReadBytes: sageChurnMaxDownloadBytes - 1,
		Age:            5 * time.Second,
	}

	for i := 0; i < sageChurnLimit-1; i++ {
		group.observeChurnClose("alpha", metadata, observation)
		clock.Advance(time.Second)
	}
	snapshot := group.SageDiagnostics()
	require.Equal(t, uint64(sageChurnLimit-1), snapshot.Counters.ChurnCandidates)
	require.Zero(t, snapshot.Counters.ChurnSuspected)

	group.observeChurnClose("alpha", metadata, observation)
	snapshot = group.SageDiagnostics()
	require.Equal(t, uint64(sageChurnLimit), snapshot.Counters.ChurnCandidates)
	require.Equal(t, uint64(1), snapshot.Counters.ChurnSuspected)
	require.Len(t, group.churn, 1)
	last := snapshot.RecentEvents[len(snapshot.RecentEvents)-1]
	require.Equal(t, "churn-suspected", last.Kind)
	require.Equal(t, "api.example.com", last.Target)
	require.Equal(t, uint16(443), last.Port)
	require.Equal(t, "alpha", last.From)
	require.Equal(t, sageChurnLimit, last.Occurrences)
}

func TestSageChurnShadowDataResetAndPartitions(t *testing.T) {
	clock := newSageConnTestClock()
	group, _ := newSageGroupForTest(clock, 10, time.Hour, newSageTestProxy("alpha", true, true))
	base := &C.Metadata{Host: "api.example.com", DstPort: 443, NetWork: C.TCP}
	tiny := sageConnectionCloseObservation{WrotePayload: true, TotalReadBytes: 1, Age: time.Second}
	data := sageConnectionCloseObservation{TotalReadBytes: sageChurnMaxDownloadBytes, Age: sageChurnMaxLifetime + time.Second}

	for i := 0; i < sageChurnLimit-1; i++ {
		group.observeChurnClose("alpha", base, tiny)
	}
	group.observeChurnClose("alpha", base, data)
	for i := 0; i < sageChurnLimit-1; i++ {
		group.observeChurnClose("alpha", base, tiny)
	}
	require.Zero(t, group.SageDiagnostics().Counters.ChurnSuspected)
	require.Equal(t, uint64(1), group.SageDiagnostics().Counters.ChurnResets)

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
	require.Zero(t, group.SageDiagnostics().Counters.ChurnSuspected)
}

func TestSageChurnShadowSuppressionsAndWindow(t *testing.T) {
	clock := newSageConnTestClock()
	group, _ := newSageGroupForTest(clock, 10, time.Hour, newSageTestProxy("alpha", true, true))
	valid := &C.Metadata{Host: "api.example.com", DstPort: 443, NetWork: C.TCP}

	tests := []struct {
		name        string
		metadata    *C.Metadata
		observation sageConnectionCloseObservation
		reason      string
	}{
		{name: "no payload write", metadata: valid, observation: sageConnectionCloseObservation{Age: time.Second}, reason: "no-positive-write"},
		{name: "zero age", metadata: valid, observation: sageConnectionCloseObservation{WrotePayload: true, Age: 0}, reason: "lifetime-outside-window"},
		{name: "maximum age", metadata: valid, observation: sageConnectionCloseObservation{WrotePayload: true, Age: sageChurnMaxLifetime}, reason: "lifetime-outside-window"},
		{name: "udp", metadata: &C.Metadata{Host: "api.example.com", DstPort: 443, NetWork: C.UDP}, observation: sageConnectionCloseObservation{WrotePayload: true, Age: time.Second}, reason: "non-tcp"},
		{name: "internal doh provenance", metadata: &C.Metadata{Type: C.INNER, Host: "resolver.example.com", DstPort: 443, NetWork: C.TCP}, observation: sageConnectionCloseObservation{WrotePayload: true, Age: time.Second}, reason: "internal-flow"},
		{name: "dns port", metadata: &C.Metadata{Host: "resolver.example.com", DstPort: 853, NetWork: C.TCP}, observation: sageConnectionCloseObservation{WrotePayload: true, Age: time.Second}, reason: "dns-bootstrap"},
		{name: "doh label", metadata: &C.Metadata{Host: "doh.pub", DstPort: 443, NetWork: C.TCP}, observation: sageConnectionCloseObservation{WrotePayload: true, Age: time.Second}, reason: "dns-bootstrap"},
		{name: "invalid target", metadata: &C.Metadata{Host: "bad..example.com", DstPort: 443, NetWork: C.TCP}, observation: sageConnectionCloseObservation{WrotePayload: true, Age: time.Second}, reason: "invalid-target"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			group.observeChurnClose("alpha", test.metadata, test.observation)
		})
	}
	snapshot := group.SageDiagnostics()
	for _, test := range tests {
		require.NotZero(t, snapshot.ChurnSuppressions[test.reason], test.name)
	}
	require.Zero(t, snapshot.Counters.ChurnCandidates)

	tiny := sageConnectionCloseObservation{WrotePayload: true, Age: time.Second}
	for i := 0; i < sageChurnLimit-1; i++ {
		group.observeChurnClose("alpha", valid, tiny)
	}
	clock.Advance(sageChurnWindow)
	group.observeChurnClose("alpha", valid, tiny)
	require.Zero(t, group.SageDiagnostics().Counters.ChurnSuspected)
}

func TestSageChurnShadowStateIsBoundedAndConcurrent(t *testing.T) {
	clock := newSageConnTestClock()
	group, _ := newSageGroupForTest(clock, 10, time.Hour, newSageTestProxy("alpha", true, true))
	tiny := sageConnectionCloseObservation{WrotePayload: true, Age: time.Second}

	var wait sync.WaitGroup
	for i := 0; i < sageChurnMaxStates+64; i++ {
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
	require.LessOrEqual(t, states, sageChurnMaxStates)
}

func TestSageChurnShadowProductionDialPath(t *testing.T) {
	clock := newSageConnTestClock()
	alpha := newSageTestProxy("alpha", true, true)
	alpha.dialConn = &sageConnTestConn{}
	group, _ := newSageGroupForTest(clock, 10, time.Hour, alpha)
	metadata := &C.Metadata{Host: "api.example.com", DstPort: 443, NetWork: C.TCP}

	for i := 0; i < sageChurnLimit; i++ {
		conn, err := group.DialContext(context.Background(), metadata)
		require.NoError(t, err)
		_, err = conn.Write([]byte("request"))
		require.NoError(t, err)
		clock.Advance(time.Second)
		require.NoError(t, conn.Close())
	}

	snapshot := group.SageDiagnostics()
	require.Equal(t, uint64(sageChurnLimit), snapshot.Counters.ChurnCandidates)
	require.Equal(t, uint64(1), snapshot.Counters.ChurnSuspected)
	require.Equal(t, 0, snapshot.Runtime.ActiveChurnStates)
}

func TestSageChurnShadowProductionDialPathExcludesInternalFlow(t *testing.T) {
	clock := newSageConnTestClock()
	alpha := newSageTestProxy("alpha", true, true)
	alpha.dialConn = &sageConnTestConn{}
	group, _ := newSageGroupForTest(clock, 10, time.Hour, alpha)
	metadata := &C.Metadata{Type: C.INNER, Host: "resolver.example.com", DstPort: 443, NetWork: C.TCP}

	for i := 0; i < sageChurnLimit; i++ {
		conn, err := group.DialContext(context.Background(), metadata)
		require.NoError(t, err)
		_, err = conn.Write([]byte("request"))
		require.NoError(t, err)
		clock.Advance(time.Second)
		require.NoError(t, conn.Close())
	}

	snapshot := group.SageDiagnostics()
	require.Zero(t, snapshot.Counters.ChurnCandidates)
	require.Zero(t, snapshot.Counters.ChurnSuspected)
	require.Equal(t, uint64(sageChurnLimit), snapshot.ChurnSuppressions["internal-flow"])
}

func TestSageChurnShadowPersistsDiagnostics(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageDiagnosticsTestStore()
	group, _ := newSageGroupForTest(clock, 10, time.Hour, newSageTestProxy("alpha", true, true))
	group.diagnostics = newSageDiagnostics(group.Name(), clock, store)
	metadata := &C.Metadata{Host: "api.example.com", DstPort: 443, NetWork: C.TCP}
	observation := sageConnectionCloseObservation{WrotePayload: true, Age: time.Second}
	group.observeChurnClose("alpha", &C.Metadata{Host: "doh.pub", DstPort: 443, NetWork: C.TCP}, observation)
	for i := 0; i < sageChurnLimit; i++ {
		group.observeChurnClose("alpha", metadata, observation)
	}

	group.diagnostics.waitPersistence()
	restored := newSageDiagnostics(group.Name(), clock, store).snapshot()
	require.Equal(t, uint64(sageChurnLimit), restored.Counters.ChurnCandidates)
	require.Equal(t, uint64(1), restored.Counters.ChurnSuspected)
	require.Equal(t, uint64(1), restored.ChurnSuppressions["dns-bootstrap"])
	require.Equal(t, "churn-suspected", restored.RecentEvents[len(restored.RecentEvents)-1].Kind)
}

func TestSageObservedConnCloseObservationIsExactlyOnce(t *testing.T) {
	clock := newSageConnTestClock()
	underlying := &sageConnTestConn{reads: []sageConnTestRead{{payload: []byte("reply")}}}
	var observations []sageConnectionCloseObservation
	wrapped := newSageControlledConnWithClose(underlying, clock, nil, nil, nil, func(observation sageConnectionCloseObservation) {
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

func TestSageObservedConnRelayFenceIncludesLateDeliveredBytes(t *testing.T) {
	clock := newSageConnTestClock()
	underlying := &sageConnTestConn{}
	var observations []sageConnectionCloseObservation
	wrapped := newSageControlledConnWithClose(underlying, clock, nil, nil, nil, func(observation sageConnectionCloseObservation) {
		observations = append(observations, observation)
	})
	observed := wrapped.(*sageObservedConn)

	_, err := wrapped.Write([]byte("request"))
	require.NoError(t, err)
	observed.RelayStarted()
	_, counters := observed.UnwrapReader()
	require.Len(t, counters, 1)

	clock.Advance(time.Second)
	require.NoError(t, wrapped.Close())
	require.Empty(t, observations, "relay still has a delivered-byte callback in flight")
	counters[0](sageChurnMaxDownloadBytes)
	observed.RelayFinished()

	require.Len(t, observations, 1)
	require.Equal(t, sageChurnMaxDownloadBytes, observations[0].TotalReadBytes)
	require.Equal(t, time.Second, observations[0].Age)
	require.NoError(t, wrapped.Close())
	require.Len(t, observations, 1)
}

func TestSageObservedConnPolicyCloseDoesNotFeedChurn(t *testing.T) {
	clock := newSageConnTestClock()
	underlying := &sageConnTestConn{reads: []sageConnTestRead{{payload: make([]byte, sageThroughputMinPayload)}}}
	var callbacks int
	wrapped := newSageControlledConnWithClose(underlying, clock, nil, nil, func(sageThroughputObservation) sagePolicyAction {
		return func() bool { return true }
	}, func(sageConnectionCloseObservation) {
		callbacks++
	})

	_, err := wrapped.Write([]byte("request"))
	require.NoError(t, err)
	observed := wrapped.(*sageObservedConn)
	observed.requestAbort(func() bool { return true })
	require.NoError(t, wrapped.Close())
	require.Zero(t, callbacks)
}
