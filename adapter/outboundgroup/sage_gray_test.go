package outboundgroup

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func enableSageGrayForTest(group *Sage) {
	group.gray = newSageGrayObserver(true, group.clock, group.diagnostics)
}

func sageGrayTestSelection(transport sageTransport) sageGraySelection {
	return sageGraySelection{
		candidate:             "alpha",
		identity:              "test:alpha",
		transport:             transport,
		reportedAliveAtSelect: true,
	}
}

func sageGrayTestMetadata(network C.NetWork) *C.Metadata {
	return &C.Metadata{Host: "api.example.com", DstPort: 443, NetWork: network}
}

func newSageGrayTestObserver() (*sageGrayObserver, *sageConnTestClock, *sageDiagnostics) {
	clock := newSageConnTestClock()
	diagnostics := newSageDiagnostics("gray-test", clock, nil)
	return newSageGrayObserver(true, clock, diagnostics), clock, diagnostics
}

func TestSageGrayAttemptExclusionContract(t *testing.T) {
	validSelection := sageGrayTestSelection(sageTransportTCP)
	validMetadata := sageGrayTestMetadata(C.TCP)
	tests := []struct {
		name      string
		selection sageGraySelection
		metadata  *C.Metadata
		reason    string
	}{
		{
			name:      "missing member identity wins over probe state",
			selection: sageGraySelection{candidate: "alpha", transport: sageTransportTCP},
			metadata:  validMetadata,
			reason:    "missing-member-identity",
		},
		{
			name:      "probe did not report selected member alive",
			selection: sageGraySelection{candidate: "alpha", identity: "test:alpha", transport: sageTransportTCP},
			metadata:  validMetadata,
			reason:    "probe-not-reported-alive",
		},
		{
			name:      "internal flow precedes target validation",
			selection: validSelection,
			metadata:  &C.Metadata{Type: C.INNER, Host: "bad..example.com", DstPort: 443, NetWork: C.TCP},
			reason:    "internal-flow",
		},
		{
			name:      "invalid target",
			selection: validSelection,
			metadata:  &C.Metadata{Host: "bad..example.com", DstPort: 443, NetWork: C.TCP},
			reason:    "invalid-target",
		},
		{
			name:      "dns bootstrap port 53",
			selection: validSelection,
			metadata:  &C.Metadata{Host: "resolver.example.com", DstPort: 53, NetWork: C.TCP},
			reason:    "dns-bootstrap",
		},
		{
			name:      "dns bootstrap port 853",
			selection: validSelection,
			metadata:  &C.Metadata{Host: "resolver.example.com", DstPort: 853, NetWork: C.TCP},
			reason:    "dns-bootstrap",
		},
		{
			name:      "dns bootstrap dns label",
			selection: validSelection,
			metadata:  &C.Metadata{Host: "dns.pub", DstPort: 443, NetWork: C.TCP},
			reason:    "dns-bootstrap",
		},
		{
			name:      "dns bootstrap doh label",
			selection: validSelection,
			metadata:  &C.Metadata{Host: "doh.pub", DstPort: 443, NetWork: C.TCP},
			reason:    "dns-bootstrap",
		},
		{
			name:      "dns bootstrap dot label",
			selection: validSelection,
			metadata:  &C.Metadata{Host: "dot.pub", DstPort: 443, NetWork: C.TCP},
			reason:    "dns-bootstrap",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observer, _, diagnostics := newSageGrayTestObserver()
			require.Nil(t, observer.newAttempt(test.selection, test.metadata))
			snapshot := diagnostics.snapshot()
			require.Equal(t, uint64(1), snapshot.GrayFailure.Exclusions.Attempt[test.reason])
			require.Equal(t, uint64(1), grayExclusionTotal(snapshot.GrayFailure.Exclusions.Attempt))
			require.Zero(t, snapshot.GrayFailure.Counters.AttemptEligible)
		})
	}

	observer, _, diagnostics := newSageGrayTestObserver()
	attempt := observer.newAttempt(validSelection, validMetadata)
	require.NotNil(t, attempt)
	attempt.settle("neutral")
	attempt.settle("failure")
	snapshot := diagnostics.snapshot()
	require.Equal(t, uint64(1), snapshot.GrayFailure.Exclusions.Attempt["neutral-outcome"])
	require.Zero(t, snapshot.GrayFailure.Counters.AttemptEligible, "exactly-once neutral settlement must not later become failure")

	observer, _, diagnostics = newSageGrayTestObserver()
	cdnAttempt := observer.newAttempt(validSelection, &C.Metadata{Host: "cdnstatic.example.com", DstPort: 443, NetWork: C.TCP})
	require.NotNil(t, cdnAttempt)
	cdnAttempt.settle("success")
	require.Equal(t, uint64(1), diagnostics.snapshot().GrayFailure.Counters.AttemptSucceeded)
}

func TestSageGrayCloseExclusionContract(t *testing.T) {
	validSelection := sageGrayTestSelection(sageTransportTCP)
	validMetadata := sageGrayTestMetadata(C.TCP)
	validObservation := sageConnectionCloseObservation{WrotePayload: true, TotalReadBytes: 1, Age: time.Second}
	tests := []struct {
		name        string
		selection   sageGraySelection
		metadata    *C.Metadata
		observation sageConnectionCloseObservation
		reason      string
	}{
		{
			name:        "non tcp wins first",
			selection:   sageGraySelection{transport: sageTransportUDP},
			metadata:    sageGrayTestMetadata(C.UDP),
			observation: validObservation,
			reason:      "non-tcp",
		},
		{
			name:        "missing member identity",
			selection:   sageGraySelection{candidate: "alpha", transport: sageTransportTCP, reportedAliveAtSelect: true},
			metadata:    validMetadata,
			observation: validObservation,
			reason:      "missing-member-identity",
		},
		{
			name:        "probe did not report selected member alive",
			selection:   sageGraySelection{candidate: "alpha", identity: "test:alpha", transport: sageTransportTCP},
			metadata:    validMetadata,
			observation: validObservation,
			reason:      "probe-not-reported-alive",
		},
		{
			name:        "internal flow",
			selection:   validSelection,
			metadata:    &C.Metadata{Type: C.INNER, Host: "resolver.example.com", DstPort: 443, NetWork: C.TCP},
			observation: validObservation,
			reason:      "internal-flow",
		},
		{
			name:        "invalid target",
			selection:   validSelection,
			metadata:    &C.Metadata{Host: "bad..example.com", DstPort: 443, NetWork: C.TCP},
			observation: validObservation,
			reason:      "invalid-target",
		},
		{
			name:        "missing metadata is invalid target after tcp provenance",
			selection:   validSelection,
			metadata:    nil,
			observation: validObservation,
			reason:      "invalid-target",
		},
		{
			name:        "dns bootstrap",
			selection:   validSelection,
			metadata:    &C.Metadata{Host: "dns.pub", DstPort: 443, NetWork: C.TCP},
			observation: validObservation,
			reason:      "dns-bootstrap",
		},
		{
			name:        "policy close",
			selection:   validSelection,
			metadata:    validMetadata,
			observation: sageConnectionCloseObservation{WrotePayload: true, PolicyClosed: true, Age: time.Second},
			reason:      "policy-close",
		},
		{
			name:        "no positive write",
			selection:   validSelection,
			metadata:    validMetadata,
			observation: sageConnectionCloseObservation{Age: time.Second},
			reason:      "no-positive-write",
		},
		{
			name:        "lifetime outside window",
			selection:   validSelection,
			metadata:    validMetadata,
			observation: sageConnectionCloseObservation{WrotePayload: true, Age: sageChurnMaxLifetime},
			reason:      "lifetime-outside-window",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observer, _, diagnostics := newSageGrayTestObserver()
			observer.recordClose(test.selection, test.metadata, test.observation)
			snapshot := diagnostics.snapshot()
			require.Equal(t, uint64(1), snapshot.GrayFailure.Exclusions.Close[test.reason])
			require.Equal(t, uint64(1), grayExclusionTotal(snapshot.GrayFailure.Exclusions.Close))
			require.Zero(t, snapshot.GrayFailure.Counters.CloseEligible)
		})
	}

	observer, _, diagnostics := newSageGrayTestObserver()
	observer.recordClose(validSelection, validMetadata, validObservation)
	observer.recordClose(validSelection, validMetadata, sageConnectionCloseObservation{
		WrotePayload: true, TotalReadBytes: sageChurnMaxDownloadBytes, Age: time.Second,
	})
	snapshot := diagnostics.snapshot()
	require.Equal(t, SageDiagnosticGrayCounters{
		CloseEligible: 2,
		CloseProgress: 1,
		CloseTiny:     1,
	}, snapshot.GrayFailure.Counters)
}

func TestSageGrayWindowDenominatorsAndAlertLevels(t *testing.T) {
	t.Run("snapshot publishes the frozen contract", func(t *testing.T) {
		observer, _, diagnostics := newSageGrayTestObserver()
		snapshot := observer.snapshot(diagnostics.snapshot().GrayFailure)
		require.True(t, snapshot.Enabled)
		require.Equal(t, "member-transport", snapshot.Scope)
		require.True(t, snapshot.CorrelationOnly)
		require.False(t, snapshot.ProbeFreshnessAvailable)
		require.Equal(t, int64(30_000), snapshot.BucketMS)
		require.Equal(t, int64(300_000), snapshot.ShortWindowMS)
		require.Equal(t, int64(900_000), snapshot.LongWindowMS)
		require.Equal(t, 512, snapshot.MaxSeries)
		require.Equal(t, sageGrayLevelInsufficient, snapshot.CurrentLevel)
		require.Equal(t, sageGrayThresholds(), snapshot.Thresholds)
		require.Equal(t, newSageGrayExclusions(), snapshot.Exclusions)

		diagnostics.record(sageDiagnosticRecord{kind: "gray-attempt-excluded", reason: "unknown-reason"})
		snapshot = observer.snapshot(diagnostics.snapshot().GrayFailure)
		require.Equal(t, newSageGrayExclusions(), snapshot.Exclusions, "unknown persisted keys must not extend the fixed endpoint schema")
	})

	t.Run("bucket inclusion is exact at short long and right boundaries", func(t *testing.T) {
		observer, clock, diagnostics := newSageGrayTestObserver()
		selection := sageGrayTestSelection(sageTransportTCP)
		base := time.Unix(1_800_000_000, 0).UTC().Truncate(sageGrayBucketWidth)
		setClock := func(now time.Time) {
			clock.mu.Lock()
			clock.now = now
			clock.mu.Unlock()
		}
		for _, event := range []struct {
			at      time.Time
			outcome string
		}{
			{base.Add(-sageGrayLongWindow), "success"},
			{base.Add(-sageGrayLongWindow + sageGrayBucketWidth), "failure"},
			{base.Add(-sageGrayShortWindow), "success"},
			{base.Add(-sageGrayShortWindow + sageGrayBucketWidth), "failure"},
			{base.Add(sageGrayBucketWidth - time.Second), "success"},
		} {
			setClock(event.at)
			observer.recordAttempt(selection, event.outcome)
		}
		key := sageGraySeriesKey{identity: selection.identity, transport: selection.transport}
		observer.series[key].buckets[base.Add(sageGrayBucketWidth).Unix()] = &sageGrayBucket{
			start:          base.Add(sageGrayBucketWidth),
			attemptFailure: 1,
		}
		setClock(base.Add(sageGrayBucketWidth - time.Second))
		snapshot := observer.snapshot(diagnostics.snapshot().GrayFailure)
		require.Len(t, snapshot.Series, 1)
		require.Equal(t, uint64(2), snapshot.Series[0].ShortWindow.Attempt.Denominator)
		require.Equal(t, uint64(1), snapshot.Series[0].ShortWindow.Attempt.Failures)
		require.Equal(t, uint64(4), snapshot.Series[0].LongWindow.Attempt.Denominator)
		require.Equal(t, uint64(2), snapshot.Series[0].LongWindow.Attempt.Failures)
		require.Equal(t, base.Add(-sageGrayShortWindow+sageGrayBucketWidth), snapshot.Series[0].ShortWindow.Start)
		require.Equal(t, base.Add(sageGrayBucketWidth), snapshot.Series[0].ShortWindow.EndExclusive)
	})

	t.Run("insufficient and normal denominator boundary", func(t *testing.T) {
		observer, _, diagnostics := newSageGrayTestObserver()
		selection := sageGrayTestSelection(sageTransportTCP)
		for i := uint64(0); i < sageGrayAttemptSufficientDenominator-1; i++ {
			observer.recordAttempt(selection, "success")
		}
		snapshot := observer.snapshot(diagnostics.snapshot().GrayFailure)
		require.Equal(t, sageGrayLevelInsufficient, snapshot.CurrentLevel)
		require.Equal(t, sageGrayAttemptSufficientDenominator-1, snapshot.Series[0].LongWindow.Attempt.Denominator)

		observer.recordAttempt(selection, "success")
		snapshot = observer.snapshot(diagnostics.snapshot().GrayFailure)
		require.Equal(t, sageGrayLevelNormal, snapshot.CurrentLevel)
		require.Equal(t, sageGrayAttemptSufficientDenominator, snapshot.Series[0].LongWindow.Attempt.Denominator)
	})

	t.Run("alert gates cover below exact and above boundaries", func(t *testing.T) {
		attemptWindow := func(denominator, failures uint64) SageDiagnosticGrayWindow {
			window := SageDiagnosticGrayWindow{}
			window.Attempt.Failures = failures
			window.Attempt.Successes = denominator - failures
			finishSageGrayWindow(&window)
			return window
		}
		closeWindow := func(denominator, tiny uint64) SageDiagnosticGrayWindow {
			window := SageDiagnosticGrayWindow{}
			window.Close.Tiny = tiny
			window.Close.Progress = denominator - tiny
			finishSageGrayWindow(&window)
			return window
		}
		cases := []struct {
			name     string
			short    SageDiagnosticGrayWindow
			long     SageDiagnosticGrayWindow
			expected string
		}{
			{"attempt watch below", attemptWindow(20, 2), attemptWindow(20, 2), sageGrayLevelNormal},
			{"attempt watch exact", attemptWindow(20, 3), attemptWindow(20, 3), sageGrayLevelWatch},
			{"attempt watch above", attemptWindow(21, 4), attemptWindow(21, 4), sageGrayLevelWatch},
			{"attempt suspected below", attemptWindow(20, 4), attemptWindow(50, 8), sageGrayLevelWatch},
			{"attempt suspected exact", attemptWindow(20, 5), attemptWindow(50, 8), sageGrayLevelSuspected},
			{"attempt suspected above", attemptWindow(21, 6), attemptWindow(51, 9), sageGrayLevelSuspected},
			{"close watch below", closeWindow(8, 3), closeWindow(8, 3), sageGrayLevelNormal},
			{"close watch exact", closeWindow(8, 4), closeWindow(8, 4), sageGrayLevelWatch},
			{"close watch above", closeWindow(9, 5), closeWindow(9, 5), sageGrayLevelWatch},
			{"close suspected below", closeWindow(12, 7), closeWindow(20, 10), sageGrayLevelWatch},
			{"close suspected exact", closeWindow(12, 8), closeWindow(20, 10), sageGrayLevelSuspected},
			{"close suspected above", closeWindow(13, 9), closeWindow(21, 11), sageGrayLevelSuspected},
		}
		for _, test := range cases {
			t.Run(test.name, func(t *testing.T) {
				level, _ := sageGrayAlertLevel(test.short, test.long)
				require.Equal(t, test.expected, level)
			})
		}
	})

	t.Run("attempt watch and suspected use separate short and long denominators", func(t *testing.T) {
		observer, _, diagnostics := newSageGrayTestObserver()
		selection := sageGrayTestSelection(sageTransportTCP)
		for i := 0; i < 17; i++ {
			observer.recordAttempt(selection, "success")
		}
		for i := 0; i < 3; i++ {
			observer.recordAttempt(selection, "failure")
		}
		snapshot := observer.snapshot(diagnostics.snapshot().GrayFailure)
		require.Equal(t, sageGrayLevelWatch, snapshot.Series[0].Level)
		require.Equal(t, []string{"attempt-short-disagreement"}, snapshot.Series[0].Reasons)
		require.InDelta(t, 0.15, snapshot.Series[0].ShortWindow.Attempt.FailureRate, 1e-12)

		observer, clock, diagnostics := newSageGrayTestObserver()
		for i := 0; i < 27; i++ {
			observer.recordAttempt(selection, "success")
		}
		for i := 0; i < 3; i++ {
			observer.recordAttempt(selection, "failure")
		}
		clock.Advance(6 * time.Minute)
		for i := 0; i < 15; i++ {
			observer.recordAttempt(selection, "success")
		}
		for i := 0; i < 5; i++ {
			observer.recordAttempt(selection, "failure")
		}
		snapshot = observer.snapshot(diagnostics.snapshot().GrayFailure)
		require.Equal(t, sageGrayLevelSuspected, snapshot.Series[0].Level)
		require.Equal(t, []string{"attempt-sustained-disagreement"}, snapshot.Series[0].Reasons)
		require.Equal(t, uint64(20), snapshot.Series[0].ShortWindow.Attempt.Denominator)
		require.Equal(t, uint64(50), snapshot.Series[0].LongWindow.Attempt.Denominator)
	})

	t.Run("close watch and sustained disagreement", func(t *testing.T) {
		observer, clock, diagnostics := newSageGrayTestObserver()
		selection := sageGrayTestSelection(sageTransportTCP)
		for i := 0; i < 4; i++ {
			observer.recordBucket(selection, "close-progress")
			observer.recordDiagnostic(sageDiagnosticRecord{kind: "gray-close-progress"})
			observer.recordBucket(selection, "close-tiny")
			observer.recordDiagnostic(sageDiagnosticRecord{kind: "gray-close-tiny"})
		}
		snapshot := observer.snapshot(diagnostics.snapshot().GrayFailure)
		require.Equal(t, sageGrayLevelWatch, snapshot.Series[0].Level)
		require.Equal(t, uint64(8), snapshot.Series[0].ShortWindow.Close.Denominator)
		require.InDelta(t, 0.5, snapshot.Series[0].ShortWindow.Close.TinyRate, 1e-12)

		observer, clock, diagnostics = newSageGrayTestObserver()
		for i := 0; i < 6; i++ {
			observer.recordBucket(selection, "close-progress")
		}
		for i := 0; i < 2; i++ {
			observer.recordBucket(selection, "close-tiny")
		}
		clock.Advance(6 * time.Minute)
		for i := 0; i < 4; i++ {
			observer.recordBucket(selection, "close-progress")
		}
		for i := 0; i < 8; i++ {
			observer.recordBucket(selection, "close-tiny")
		}
		snapshot = observer.snapshot(diagnostics.snapshot().GrayFailure)
		require.Equal(t, sageGrayLevelSuspected, snapshot.Series[0].Level)
		require.Equal(t, []string{"close-sustained-disagreement"}, snapshot.Series[0].Reasons)
		require.Equal(t, uint64(12), snapshot.Series[0].ShortWindow.Close.Denominator)
		require.Equal(t, uint64(20), snapshot.Series[0].LongWindow.Close.Denominator)
	})
}

func TestSageGrayBucketsIdentityIsolationBoundsAndReadOnlySnapshot(t *testing.T) {
	observer, clock, diagnostics := newSageGrayTestObserver()
	selection := sageGrayTestSelection(sageTransportTCP)
	observer.recordAttempt(selection, "success")

	now := clock.Now().UTC()
	bucketStart := now.Truncate(sageGrayBucketWidth)
	snapshot := observer.snapshot(diagnostics.snapshot().GrayFailure)
	require.Equal(t, bucketStart.Add(-sageGrayShortWindow+sageGrayBucketWidth), snapshot.Series[0].ShortWindow.Start)
	require.Equal(t, bucketStart.Add(sageGrayBucketWidth), snapshot.Series[0].ShortWindow.EndExclusive)
	require.Equal(t, sageGrayMemberID(selection.identity), snapshot.Series[0].MemberID)

	replacement := selection
	replacement.identity = "test:alpha-replacement"
	udp := selection
	udp.transport = sageTransportUDP
	observer.recordAttempt(replacement, "success")
	observer.recordAttempt(udp, "success")
	snapshot = observer.snapshot(diagnostics.snapshot().GrayFailure)
	require.Len(t, snapshot.Series, 3, "same-name replacement and transport must have isolated series")

	clock.Advance(sageGrayLongWindow + sageGrayBucketWidth)
	before := len(observer.series)
	first := observer.snapshot(diagnostics.snapshot().GrayFailure)
	second := observer.snapshot(diagnostics.snapshot().GrayFailure)
	require.Empty(t, first.Series)
	require.Equal(t, first, second)
	require.Equal(t, before, len(observer.series), "GET snapshot must not prune or mutate rolling state")

	bounded, _, boundedDiagnostics := newSageGrayTestObserver()
	evictedIdentity := ""
	evictedMemberID := ""
	lastIdentity := ""
	for index := 0; index < sageGrayMaxSeries+1; index++ {
		item := selection
		item.identity = "identity-" + string(rune(index+1))
		lastIdentity = item.identity
		if index < sageGrayMaxSeries {
			memberID := sageGrayMemberID(item.identity)
			if evictedIdentity == "" || memberID < evictedMemberID {
				evictedIdentity, evictedMemberID = item.identity, memberID
			}
		}
		bounded.recordAttempt(item, "success")
	}
	require.Len(t, bounded.series, sageGrayMaxSeries)
	_, retainedEvicted := bounded.series[sageGraySeriesKey{identity: evictedIdentity, transport: sageTransportTCP}]
	_, retainedNewest := bounded.series[sageGraySeriesKey{identity: lastIdentity, transport: sageTransportTCP}]
	require.False(t, retainedEvicted, "same-time eviction must use the documented deterministic member token tie-break")
	require.True(t, retainedNewest)
	require.Equal(t, uint64(sageGrayMaxSeries+1), boundedDiagnostics.snapshot().GrayFailure.Counters.AttemptEligible, "series eviction must not erase cumulative counters")
}

func TestSageGrayProductionOutcomeIntegration(t *testing.T) {
	t.Run("tcp immediate failure and neutral cancellation stay separate", func(t *testing.T) {
		clock := newSageConnTestClock()
		proxy := newSageTestProxy("alpha", true, true)
		proxy.dialErr = errors.New("dial failed")
		group, _ := newSageGroupForTest(clock, 10, time.Hour, proxy)
		enableSageGrayForTest(group)
		metadata := sageGrayTestMetadata(C.TCP)

		_, err := group.DialContext(context.Background(), metadata)
		require.Error(t, err)
		proxy.dialErr = context.Canceled
		_, err = group.DialContext(context.Background(), metadata)
		require.ErrorIs(t, err, context.Canceled)

		snapshot := group.SageDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptEligible)
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptFailed)
		require.Equal(t, uint64(1), snapshot.GrayFailure.Exclusions.Attempt["neutral-outcome"])
	})

	t.Run("tcp immediate success and relay-fenced late bytes settle once", func(t *testing.T) {
		clock := newSageConnTestClock()
		proxy := newSageTestProxy("alpha", true, true)
		proxy.dialConn = &sageConnTestConn{}
		group, _ := newSageGroupForTest(clock, 10, time.Hour, proxy)
		enableSageGrayForTest(group)
		metadata := sageGrayTestMetadata(C.TCP)

		conn, err := group.DialContext(context.Background(), metadata)
		require.NoError(t, err)
		_, err = conn.Write([]byte("request"))
		require.NoError(t, err)
		observed := conn.(*sageObservedConn)
		observed.RelayStarted()
		_, counters := observed.UnwrapReader()
		require.Len(t, counters, 1)
		clock.Advance(time.Second)
		require.NoError(t, conn.Close())
		require.Zero(t, group.SageDiagnostics().GrayFailure.Counters.CloseEligible, "close must wait for Relay-delivered byte callbacks")
		counters[0](sageChurnMaxDownloadBytes)
		observed.RelayFinished()
		require.NoError(t, conn.Close())

		snapshot := group.SageDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptSucceeded)
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.CloseProgress)
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.CloseEligible)
		require.Zero(t, snapshot.GrayFailure.Counters.CloseTiny)
	})

	t.Run("deferred tcp failure and no-send close are complete", func(t *testing.T) {
		clock := newSageConnTestClock()
		proxy := newSageTestProxy("alpha", true, true)
		proxy.dialConn = &sageEarlyTestConn{sageConnTestConn: &sageConnTestConn{
			writeFunc: func([]byte) (int, error) { return 0, errors.New("handshake failed") },
		}}
		group, _ := newSageGroupForTest(clock, 10, time.Hour, proxy)
		enableSageGrayForTest(group)

		conn, err := group.DialContext(context.Background(), sageGrayTestMetadata(C.TCP))
		require.NoError(t, err)
		_, err = conn.Write([]byte("request"))
		require.Error(t, err)
		require.NoError(t, conn.Close())
		snapshot := group.SageDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptFailed)

		proxy.dialErr = nil
		proxy.dialConn = &sageEarlyTestConn{sageConnTestConn: &sageConnTestConn{}}
		conn, err = group.DialContext(context.Background(), sageGrayTestMetadata(C.TCP))
		require.NoError(t, err)
		require.NoError(t, conn.Close())
		snapshot = group.SageDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Exclusions.Attempt["neutral-outcome"])
	})

	t.Run("udp first datagram and no-send close partition outcomes", func(t *testing.T) {
		clock := newSageConnTestClock()
		proxy := newSageTestProxy("alpha", true, true)
		proxy.packetConn = &sagePacketConnTestFake{}
		group, _ := newSageGroupForTest(clock, 10, time.Hour, proxy)
		enableSageGrayForTest(group)
		metadata := sageGrayTestMetadata(C.UDP)

		packetConn, err := group.ListenPacketContext(context.Background(), metadata)
		require.NoError(t, err)
		_, err = packetConn.WriteTo([]byte("datagram"), sageConnTestAddr("remote"))
		require.NoError(t, err)
		require.NoError(t, packetConn.Close())

		proxy.packetConn = &sagePacketConnTestFake{}
		packetConn, err = group.ListenPacketContext(context.Background(), metadata)
		require.NoError(t, err)
		require.NoError(t, packetConn.Close())
		require.NoError(t, packetConn.Close())

		snapshot := group.SageDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptSucceeded)
		require.Equal(t, uint64(1), snapshot.GrayFailure.Exclusions.Attempt["neutral-outcome"])
	})

	t.Run("udp datagram failure is eligible failure", func(t *testing.T) {
		clock := newSageConnTestClock()
		proxy := newSageTestProxy("alpha", true, true)
		proxy.packetConn = &sagePacketConnTestFake{writeFunc: func([]byte, net.Addr) (int, error) {
			return 0, errors.New("send failed")
		}}
		group, _ := newSageGroupForTest(clock, 10, time.Hour, proxy)
		enableSageGrayForTest(group)
		packetConn, err := group.ListenPacketContext(context.Background(), sageGrayTestMetadata(C.UDP))
		require.NoError(t, err)
		_, err = packetConn.WriteTo([]byte("datagram"), sageConnTestAddr("remote"))
		require.Error(t, err)
		require.NoError(t, packetConn.Close())
		snapshot := group.SageDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptEligible)
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptFailed)
	})

	t.Run("in-flight tcp positive write wins over concurrent close", func(t *testing.T) {
		clock := newSageConnTestClock()
		started := make(chan struct{})
		release := make(chan struct{})
		proxy := newSageTestProxy("alpha", true, true)
		proxy.dialConn = &sageEarlyTestConn{sageConnTestConn: &sageConnTestConn{
			writeFunc: func(payload []byte) (int, error) {
				close(started)
				<-release
				return len(payload), nil
			},
		}}
		group, _ := newSageGroupForTest(clock, 10, time.Hour, proxy)
		enableSageGrayForTest(group)
		conn, err := group.DialContext(context.Background(), sageGrayTestMetadata(C.TCP))
		require.NoError(t, err)
		writeDone := make(chan error, 1)
		go func() {
			_, writeErr := conn.Write([]byte("request"))
			writeDone <- writeErr
		}()
		<-started
		require.NoError(t, conn.Close())
		close(release)
		require.NoError(t, <-writeDone)
		snapshot := group.SageDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptSucceeded)
		require.Zero(t, snapshot.GrayFailure.Exclusions.Attempt["neutral-outcome"])
	})

	t.Run("udp listen failure and neutral cancellation stay separate", func(t *testing.T) {
		clock := newSageConnTestClock()
		proxy := newSageTestProxy("alpha", true, true)
		proxy.packetErr = errors.New("listen failed")
		group, _ := newSageGroupForTest(clock, 10, time.Hour, proxy)
		enableSageGrayForTest(group)
		metadata := sageGrayTestMetadata(C.UDP)
		_, err := group.ListenPacketContext(context.Background(), metadata)
		require.Error(t, err)
		proxy.packetErr = context.Canceled
		_, err = group.ListenPacketContext(context.Background(), metadata)
		require.ErrorIs(t, err, context.Canceled)
		snapshot := group.SageDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptFailed)
		require.Equal(t, uint64(1), snapshot.GrayFailure.Exclusions.Attempt["neutral-outcome"])
	})

	t.Run("in-flight udp positive datagram wins over concurrent close", func(t *testing.T) {
		clock := newSageConnTestClock()
		started := make(chan struct{})
		release := make(chan struct{})
		proxy := newSageTestProxy("alpha", true, true)
		proxy.packetConn = &sagePacketConnTestFake{writeFunc: func(payload []byte, _ net.Addr) (int, error) {
			close(started)
			<-release
			return len(payload), nil
		}}
		group, _ := newSageGroupForTest(clock, 10, time.Hour, proxy)
		enableSageGrayForTest(group)
		packetConn, err := group.ListenPacketContext(context.Background(), sageGrayTestMetadata(C.UDP))
		require.NoError(t, err)
		writeDone := make(chan error, 1)
		go func() {
			_, writeErr := packetConn.WriteTo([]byte("datagram"), sageConnTestAddr("remote"))
			writeDone <- writeErr
		}()
		<-started
		require.NoError(t, packetConn.Close())
		close(release)
		require.NoError(t, <-writeDone)
		snapshot := group.SageDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptSucceeded)
		require.Zero(t, snapshot.GrayFailure.Exclusions.Attempt["neutral-outcome"])
	})

	t.Run("all-dead fallback is excluded even when dial returns", func(t *testing.T) {
		clock := newSageConnTestClock()
		proxy := newSageTestProxy("alpha", false, true)
		proxy.dialConn = &sageConnTestConn{}
		group, _ := newSageGroupForTest(clock, 10, time.Hour, proxy)
		enableSageGrayForTest(group)
		conn, err := group.DialContext(context.Background(), sageGrayTestMetadata(C.TCP))
		require.NoError(t, err)
		require.NoError(t, conn.Close())
		snapshot := group.SageDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Exclusions.Attempt["probe-not-reported-alive"])
		require.Zero(t, snapshot.GrayFailure.Counters.AttemptEligible)
	})
	t.Run("same-name replacement keeps delayed old attempt in old identity series", func(t *testing.T) {
		clock := newSageConnTestClock()
		proxy := newSageTestProxy("alpha", true, true)
		proxy.identity = "test:alpha-old"
		proxy.dialConn = &sageEarlyTestConn{sageConnTestConn: &sageConnTestConn{}}
		group, _ := newSageGroupForTest(clock, 10, time.Hour, proxy)
		enableSageGrayForTest(group)
		metadata := sageGrayTestMetadata(C.TCP)
		oldConn, err := group.DialContext(context.Background(), metadata)
		require.NoError(t, err)

		proxy.identity = "test:alpha-new"
		proxy.dialConn = &sageConnTestConn{}
		newConn, err := group.DialContext(context.Background(), metadata)
		require.NoError(t, err)
		_, err = oldConn.Write([]byte("old request"))
		require.NoError(t, err)
		require.NoError(t, oldConn.Close())
		require.NoError(t, newConn.Close())

		snapshot := group.SageDiagnostics()
		require.Equal(t, uint64(2), snapshot.GrayFailure.Counters.AttemptSucceeded)
		require.Len(t, snapshot.GrayFailure.Series, 2)
		memberIDs := []string{snapshot.GrayFailure.Series[0].MemberID, snapshot.GrayFailure.Series[1].MemberID}
		require.ElementsMatch(t, []string{sageGrayMemberID("test:alpha-old"), sageGrayMemberID("test:alpha-new")}, memberIDs)
	})
}

func TestSageGrayShadowDoesNotChangeSelectionOrPolicyState(t *testing.T) {
	clockOff := newSageConnTestClock()
	clockOn := newSageConnTestClock()
	alphaOff := newSageTestProxy("alpha", true, true)
	betaOff := newSageTestProxy("beta", true, true)
	alphaOn := newSageTestProxy("alpha", true, true)
	betaOn := newSageTestProxy("beta", true, true)
	alphaOff.dialConn, alphaOn.dialConn = &sageConnTestConn{}, &sageConnTestConn{}
	betaOff.dialConn, betaOn.dialConn = &sageConnTestConn{}, &sageConnTestConn{}
	off, _ := newSageGroupForTest(clockOff, 10, time.Hour, alphaOff, betaOff)
	on, _ := newSageGroupForTest(clockOn, 10, time.Hour, alphaOn, betaOn)
	enableSageGrayForTest(on)
	metadata := sageGrayTestMetadata(C.TCP)

	require.Equal(t, off.pickDecision(metadata, sageTransportTCP, false, false).proxy.Name(), on.pickDecision(metadata, sageTransportTCP, false, false).proxy.Name())
	offConn, offErr := off.DialContext(context.Background(), metadata)
	onConn, onErr := on.DialContext(context.Background(), metadata)
	require.Equal(t, offErr, onErr)
	require.Equal(t, offConn.Chains(), onConn.Chains())
	_, offErr = offConn.Write([]byte("request"))
	_, onErr = onConn.Write([]byte("request"))
	require.Equal(t, offErr, onErr)
	clockOff.Advance(time.Second)
	clockOn.Advance(time.Second)
	require.Equal(t, offConn.Close(), onConn.Close())

	alphaOff.packetConn, alphaOn.packetConn = &sagePacketConnTestFake{}, &sagePacketConnTestFake{}
	betaOff.packetConn, betaOn.packetConn = &sagePacketConnTestFake{}, &sagePacketConnTestFake{}
	udpMetadata := sageGrayTestMetadata(C.UDP)
	offPacket, offErr := off.ListenPacketContext(context.Background(), udpMetadata)
	onPacket, onErr := on.ListenPacketContext(context.Background(), udpMetadata)
	require.Equal(t, offErr, onErr)
	require.Equal(t, offPacket.Chains(), onPacket.Chains())
	_, offErr = offPacket.WriteTo([]byte("datagram"), sageConnTestAddr("remote"))
	_, onErr = onPacket.WriteTo([]byte("datagram"), sageConnTestAddr("remote"))
	require.Equal(t, offErr, onErr)
	require.Equal(t, offPacket.Close(), onPacket.Close())

	require.Equal(t, sagePolicySnapshotForGrayTest(off), sagePolicySnapshotForGrayTest(on))
	require.Equal(t, off.pickDecision(metadata, sageTransportTCP, false, false).proxy.Name(), on.pickDecision(metadata, sageTransportTCP, false, false).proxy.Name())
	require.False(t, off.SageDiagnostics().GrayFailure.Enabled)
	require.True(t, on.SageDiagnostics().GrayFailure.Enabled)
	require.Zero(t, off.SageDiagnostics().GrayFailure.Counters.AttemptEligible)
	require.Equal(t, uint64(2), on.SageDiagnostics().GrayFailure.Counters.AttemptEligible)
}

type sageGrayPolicySnapshot struct {
	anchors           map[sageAnchorKey]sageAnchor
	cooldowns         map[sageCooldownKey]time.Time
	explorationScopes [sageExplorationScopeCount]sageExplorationScopeState
	churn             map[sageChurnKey]sageChurnState
	tcp               sageMetricsSnapshot
	udp               sageMetricsSnapshot
}

func sagePolicySnapshotForGrayTest(group *Sage) sageGrayPolicySnapshot {
	now := group.clock.Now()
	result := sageGrayPolicySnapshot{
		anchors:   make(map[sageAnchorKey]sageAnchor),
		cooldowns: make(map[sageCooldownKey]time.Time),
		churn:     make(map[sageChurnKey]sageChurnState),
	}
	group.mu.Lock()
	for key, value := range group.anchors {
		result.anchors[key] = value
	}
	for key, value := range group.cooldowns {
		result.cooldowns[key] = value
	}
	result.explorationScopes = group.explorationScopes
	if state := group.nodes["alpha"]; state != nil {
		result.tcp = state.snapshot(sageTransportTCP, now)
		result.udp = state.snapshot(sageTransportUDP, now)
	}
	group.mu.Unlock()
	group.churnMu.Lock()
	for key, value := range group.churn {
		if value != nil {
			result.churn[key] = sageChurnState{stamps: append([]time.Time(nil), value.stamps...), lastUpdated: value.lastUpdated}
		}
	}
	group.churnMu.Unlock()
	return result
}

func TestSageGrayDiagnosticsPersistenceAndV1Compatibility(t *testing.T) {
	clock := newSageConnTestClock()
	store := newSageDiagnosticsTestStore()
	diagnostics := newSageDiagnostics("gray-persist", clock, store)
	diagnostics.record(sageDiagnosticRecord{kind: "gray-attempt-succeeded"})
	diagnostics.record(sageDiagnosticRecord{kind: "gray-attempt-excluded", reason: "neutral-outcome", force: true})
	diagnostics.waitPersistence()

	restored := newSageDiagnostics("gray-persist", clock, store).snapshot()
	require.Equal(t, uint64(1), restored.GrayFailure.Counters.AttemptEligible)
	require.Equal(t, uint64(1), restored.GrayFailure.Counters.AttemptSucceeded)
	require.Equal(t, uint64(1), restored.GrayFailure.Exclusions.Attempt["neutral-outcome"])
	require.Empty(t, restored.GrayFailure.Series)
	require.Equal(t, SageDiagnosticsSchemaVersion, restored.SchemaVersion)

	oldStore := newSageDiagnosticsTestStore()
	oldPayload := []byte(`{"schemaVersion":1,"group":"gray-old","since":"2026-11-15T00:00:00Z","updatedAt":"2026-11-15T00:00:00Z","counters":{"mediaFlows":7},"suppressions":{"legacy":2},"recentEvents":[{"sequence":3,"time":"2026-11-15T00:00:00Z","kind":"legacy-event"}]}`)
	require.NoError(t, oldStore.Save(sageDiagnosticsStorageKey("gray-old"), oldPayload))
	old := newSageDiagnostics("gray-old", clock, oldStore).snapshot()
	require.Equal(t, SageDiagnosticsSchemaVersion, old.SchemaVersion)
	require.Equal(t, uint64(7), old.Counters.MediaFlows)
	require.Equal(t, uint64(2), old.Suppressions["legacy"])
	require.Equal(t, "legacy-event", old.RecentEvents[0].Kind)
	require.NotNil(t, old.GrayFailure.Exclusions.Attempt)
	require.NotNil(t, old.GrayFailure.Exclusions.Close)
	require.Zero(t, old.GrayFailure.Counters.AttemptEligible)
}

func TestSageDiagnosticsReadDoesNotPruneExpiredChurnState(t *testing.T) {
	clock := newSageConnTestClock()
	group, _ := newSageGroupForTest(clock, 10, time.Hour, newSageTestProxy("alpha", true, true))
	key := sageChurnKey{candidate: "alpha", target: "example.com", port: 443}
	group.churn[key] = &sageChurnState{
		stamps:      []time.Time{clock.Now().Add(-sageChurnWindow - time.Second)},
		lastUpdated: clock.Now().Add(-sageChurnWindow - time.Second),
	}

	before := sagePolicySnapshotForGrayTest(group)
	first := group.SageDiagnostics()
	second := group.SageDiagnostics()
	after := sagePolicySnapshotForGrayTest(group)
	require.Zero(t, first.Runtime.ActiveChurnStates)
	require.Equal(t, first, second)
	require.Equal(t, before, after, "diagnostic GET must not prune policy-owned churn state")
	require.Len(t, group.churn, 1)
}

func grayExclusionTotal(values map[string]uint64) uint64 {
	var total uint64
	for _, value := range values {
		total += value
	}
	return total
}
