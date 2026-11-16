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

func enableVaneGrayForTest(group *Vane) {
	group.gray = newVaneGrayObserver(true, group.clock, group.diagnostics)
}

func vaneGrayTestSelection(transport vaneTransport) vaneGraySelection {
	return vaneGraySelection{
		candidate:             "alpha",
		identity:              "test:alpha",
		transport:             transport,
		reportedAliveAtSelect: true,
	}
}

func vaneGrayTestMetadata(network C.NetWork) *C.Metadata {
	return &C.Metadata{Host: "api.example.com", DstPort: 443, NetWork: network}
}

func newVaneGrayTestObserver() (*vaneGrayObserver, *vaneConnTestClock, *vaneDiagnostics) {
	clock := newVaneConnTestClock()
	diagnostics := newVaneDiagnostics("gray-test", clock, nil)
	return newVaneGrayObserver(true, clock, diagnostics), clock, diagnostics
}

func TestVaneGrayAttemptExclusionContract(t *testing.T) {
	validSelection := vaneGrayTestSelection(vaneTransportTCP)
	validMetadata := vaneGrayTestMetadata(C.TCP)
	tests := []struct {
		name      string
		selection vaneGraySelection
		metadata  *C.Metadata
		reason    string
	}{
		{
			name:      "missing member identity wins over probe state",
			selection: vaneGraySelection{candidate: "alpha", transport: vaneTransportTCP},
			metadata:  validMetadata,
			reason:    "missing-member-identity",
		},
		{
			name:      "probe did not report selected member alive",
			selection: vaneGraySelection{candidate: "alpha", identity: "test:alpha", transport: vaneTransportTCP},
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
			observer, _, diagnostics := newVaneGrayTestObserver()
			require.Nil(t, observer.newAttempt(test.selection, test.metadata))
			snapshot := diagnostics.snapshot()
			require.Equal(t, uint64(1), snapshot.GrayFailure.Exclusions.Attempt[test.reason])
			require.Equal(t, uint64(1), grayExclusionTotal(snapshot.GrayFailure.Exclusions.Attempt))
			require.Zero(t, snapshot.GrayFailure.Counters.AttemptEligible)
		})
	}

	observer, _, diagnostics := newVaneGrayTestObserver()
	attempt := observer.newAttempt(validSelection, validMetadata)
	require.NotNil(t, attempt)
	attempt.settle("neutral")
	attempt.settle("failure")
	snapshot := diagnostics.snapshot()
	require.Equal(t, uint64(1), snapshot.GrayFailure.Exclusions.Attempt["neutral-outcome"])
	require.Zero(t, snapshot.GrayFailure.Counters.AttemptEligible, "exactly-once neutral settlement must not later become failure")

	observer, _, diagnostics = newVaneGrayTestObserver()
	cdnAttempt := observer.newAttempt(validSelection, &C.Metadata{Host: "cdnstatic.example.com", DstPort: 443, NetWork: C.TCP})
	require.NotNil(t, cdnAttempt)
	cdnAttempt.settle("success")
	require.Equal(t, uint64(1), diagnostics.snapshot().GrayFailure.Counters.AttemptSucceeded)
}

func TestVaneGrayCloseExclusionContract(t *testing.T) {
	validSelection := vaneGrayTestSelection(vaneTransportTCP)
	validMetadata := vaneGrayTestMetadata(C.TCP)
	validObservation := vaneConnectionCloseObservation{WrotePayload: true, TotalReadBytes: 1, Age: time.Second}
	tests := []struct {
		name        string
		selection   vaneGraySelection
		metadata    *C.Metadata
		observation vaneConnectionCloseObservation
		reason      string
	}{
		{
			name:        "non tcp wins first",
			selection:   vaneGraySelection{transport: vaneTransportUDP},
			metadata:    vaneGrayTestMetadata(C.UDP),
			observation: validObservation,
			reason:      "non-tcp",
		},
		{
			name:        "missing member identity",
			selection:   vaneGraySelection{candidate: "alpha", transport: vaneTransportTCP, reportedAliveAtSelect: true},
			metadata:    validMetadata,
			observation: validObservation,
			reason:      "missing-member-identity",
		},
		{
			name:        "probe did not report selected member alive",
			selection:   vaneGraySelection{candidate: "alpha", identity: "test:alpha", transport: vaneTransportTCP},
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
			observation: vaneConnectionCloseObservation{WrotePayload: true, PolicyClosed: true, Age: time.Second},
			reason:      "policy-close",
		},
		{
			name:        "no positive write",
			selection:   validSelection,
			metadata:    validMetadata,
			observation: vaneConnectionCloseObservation{Age: time.Second},
			reason:      "no-positive-write",
		},
		{
			name:        "lifetime outside window",
			selection:   validSelection,
			metadata:    validMetadata,
			observation: vaneConnectionCloseObservation{WrotePayload: true, Age: vaneChurnMaxLifetime},
			reason:      "lifetime-outside-window",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observer, _, diagnostics := newVaneGrayTestObserver()
			observer.recordClose(test.selection, test.metadata, test.observation)
			snapshot := diagnostics.snapshot()
			require.Equal(t, uint64(1), snapshot.GrayFailure.Exclusions.Close[test.reason])
			require.Equal(t, uint64(1), grayExclusionTotal(snapshot.GrayFailure.Exclusions.Close))
			require.Zero(t, snapshot.GrayFailure.Counters.CloseEligible)
		})
	}

	observer, _, diagnostics := newVaneGrayTestObserver()
	observer.recordClose(validSelection, validMetadata, validObservation)
	observer.recordClose(validSelection, validMetadata, vaneConnectionCloseObservation{
		WrotePayload: true, TotalReadBytes: vaneChurnMaxDownloadBytes, Age: time.Second,
	})
	snapshot := diagnostics.snapshot()
	require.Equal(t, VaneDiagnosticGrayCounters{
		CloseEligible: 2,
		CloseProgress: 1,
		CloseTiny:     1,
	}, snapshot.GrayFailure.Counters)
}

func TestVaneGrayWindowDenominatorsAndAlertLevels(t *testing.T) {
	t.Run("snapshot publishes the frozen contract", func(t *testing.T) {
		observer, _, diagnostics := newVaneGrayTestObserver()
		snapshot := observer.snapshot(diagnostics.snapshot().GrayFailure)
		require.True(t, snapshot.Enabled)
		require.Equal(t, "member-transport", snapshot.Scope)
		require.True(t, snapshot.CorrelationOnly)
		require.False(t, snapshot.ProbeFreshnessAvailable)
		require.Equal(t, int64(30_000), snapshot.BucketMS)
		require.Equal(t, int64(300_000), snapshot.ShortWindowMS)
		require.Equal(t, int64(900_000), snapshot.LongWindowMS)
		require.Equal(t, 512, snapshot.MaxSeries)
		require.Equal(t, vaneGrayLevelInsufficient, snapshot.CurrentLevel)
		require.Equal(t, vaneGrayThresholds(), snapshot.Thresholds)
		require.Equal(t, newVaneGrayExclusions(), snapshot.Exclusions)

		diagnostics.record(vaneDiagnosticRecord{kind: "gray-attempt-excluded", reason: "unknown-reason"})
		snapshot = observer.snapshot(diagnostics.snapshot().GrayFailure)
		require.Equal(t, newVaneGrayExclusions(), snapshot.Exclusions, "unknown persisted keys must not extend the fixed endpoint schema")
	})

	t.Run("bucket inclusion is exact at short long and right boundaries", func(t *testing.T) {
		observer, clock, diagnostics := newVaneGrayTestObserver()
		selection := vaneGrayTestSelection(vaneTransportTCP)
		base := time.Unix(1_800_000_000, 0).UTC().Truncate(vaneGrayBucketWidth)
		setClock := func(now time.Time) {
			clock.mu.Lock()
			clock.now = now
			clock.mu.Unlock()
		}
		for _, event := range []struct {
			at      time.Time
			outcome string
		}{
			{base.Add(-vaneGrayLongWindow), "success"},
			{base.Add(-vaneGrayLongWindow + vaneGrayBucketWidth), "failure"},
			{base.Add(-vaneGrayShortWindow), "success"},
			{base.Add(-vaneGrayShortWindow + vaneGrayBucketWidth), "failure"},
			{base.Add(vaneGrayBucketWidth - time.Second), "success"},
		} {
			setClock(event.at)
			observer.recordAttempt(selection, event.outcome)
		}
		key := vaneGraySeriesKey{identity: selection.identity, transport: selection.transport}
		observer.series[key].buckets[base.Add(vaneGrayBucketWidth).Unix()] = &vaneGrayBucket{
			start:          base.Add(vaneGrayBucketWidth),
			attemptFailure: 1,
		}
		setClock(base.Add(vaneGrayBucketWidth - time.Second))
		snapshot := observer.snapshot(diagnostics.snapshot().GrayFailure)
		require.Len(t, snapshot.Series, 1)
		require.Equal(t, uint64(2), snapshot.Series[0].ShortWindow.Attempt.Denominator)
		require.Equal(t, uint64(1), snapshot.Series[0].ShortWindow.Attempt.Failures)
		require.Equal(t, uint64(4), snapshot.Series[0].LongWindow.Attempt.Denominator)
		require.Equal(t, uint64(2), snapshot.Series[0].LongWindow.Attempt.Failures)
		require.Equal(t, base.Add(-vaneGrayShortWindow+vaneGrayBucketWidth), snapshot.Series[0].ShortWindow.Start)
		require.Equal(t, base.Add(vaneGrayBucketWidth), snapshot.Series[0].ShortWindow.EndExclusive)
	})

	t.Run("insufficient and normal denominator boundary", func(t *testing.T) {
		observer, _, diagnostics := newVaneGrayTestObserver()
		selection := vaneGrayTestSelection(vaneTransportTCP)
		for i := uint64(0); i < vaneGrayAttemptSufficientDenominator-1; i++ {
			observer.recordAttempt(selection, "success")
		}
		snapshot := observer.snapshot(diagnostics.snapshot().GrayFailure)
		require.Equal(t, vaneGrayLevelInsufficient, snapshot.CurrentLevel)
		require.Equal(t, vaneGrayAttemptSufficientDenominator-1, snapshot.Series[0].LongWindow.Attempt.Denominator)

		observer.recordAttempt(selection, "success")
		snapshot = observer.snapshot(diagnostics.snapshot().GrayFailure)
		require.Equal(t, vaneGrayLevelNormal, snapshot.CurrentLevel)
		require.Equal(t, vaneGrayAttemptSufficientDenominator, snapshot.Series[0].LongWindow.Attempt.Denominator)
	})

	t.Run("alert gates cover below exact and above boundaries", func(t *testing.T) {
		attemptWindow := func(denominator, failures uint64) VaneDiagnosticGrayWindow {
			window := VaneDiagnosticGrayWindow{}
			window.Attempt.Failures = failures
			window.Attempt.Successes = denominator - failures
			finishVaneGrayWindow(&window)
			return window
		}
		closeWindow := func(denominator, tiny uint64) VaneDiagnosticGrayWindow {
			window := VaneDiagnosticGrayWindow{}
			window.Close.Tiny = tiny
			window.Close.Progress = denominator - tiny
			finishVaneGrayWindow(&window)
			return window
		}
		cases := []struct {
			name     string
			short    VaneDiagnosticGrayWindow
			long     VaneDiagnosticGrayWindow
			expected string
		}{
			{"attempt watch below", attemptWindow(20, 2), attemptWindow(20, 2), vaneGrayLevelNormal},
			{"attempt watch exact", attemptWindow(20, 3), attemptWindow(20, 3), vaneGrayLevelWatch},
			{"attempt watch above", attemptWindow(21, 4), attemptWindow(21, 4), vaneGrayLevelWatch},
			{"attempt suspected below", attemptWindow(20, 4), attemptWindow(50, 8), vaneGrayLevelWatch},
			{"attempt suspected exact", attemptWindow(20, 5), attemptWindow(50, 8), vaneGrayLevelSuspected},
			{"attempt suspected above", attemptWindow(21, 6), attemptWindow(51, 9), vaneGrayLevelSuspected},
			{"close watch below", closeWindow(8, 3), closeWindow(8, 3), vaneGrayLevelNormal},
			{"close watch exact", closeWindow(8, 4), closeWindow(8, 4), vaneGrayLevelWatch},
			{"close watch above", closeWindow(9, 5), closeWindow(9, 5), vaneGrayLevelWatch},
			{"close suspected below", closeWindow(12, 7), closeWindow(20, 10), vaneGrayLevelWatch},
			{"close suspected exact", closeWindow(12, 8), closeWindow(20, 10), vaneGrayLevelSuspected},
			{"close suspected above", closeWindow(13, 9), closeWindow(21, 11), vaneGrayLevelSuspected},
		}
		for _, test := range cases {
			t.Run(test.name, func(t *testing.T) {
				level, _ := vaneGrayAlertLevel(test.short, test.long)
				require.Equal(t, test.expected, level)
			})
		}
	})

	t.Run("attempt watch and suspected use separate short and long denominators", func(t *testing.T) {
		observer, _, diagnostics := newVaneGrayTestObserver()
		selection := vaneGrayTestSelection(vaneTransportTCP)
		for i := 0; i < 17; i++ {
			observer.recordAttempt(selection, "success")
		}
		for i := 0; i < 3; i++ {
			observer.recordAttempt(selection, "failure")
		}
		snapshot := observer.snapshot(diagnostics.snapshot().GrayFailure)
		require.Equal(t, vaneGrayLevelWatch, snapshot.Series[0].Level)
		require.Equal(t, []string{"attempt-short-disagreement"}, snapshot.Series[0].Reasons)
		require.InDelta(t, 0.15, snapshot.Series[0].ShortWindow.Attempt.FailureRate, 1e-12)

		observer, clock, diagnostics := newVaneGrayTestObserver()
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
		require.Equal(t, vaneGrayLevelSuspected, snapshot.Series[0].Level)
		require.Equal(t, []string{"attempt-sustained-disagreement"}, snapshot.Series[0].Reasons)
		require.Equal(t, uint64(20), snapshot.Series[0].ShortWindow.Attempt.Denominator)
		require.Equal(t, uint64(50), snapshot.Series[0].LongWindow.Attempt.Denominator)
	})

	t.Run("close watch and sustained disagreement", func(t *testing.T) {
		observer, clock, diagnostics := newVaneGrayTestObserver()
		selection := vaneGrayTestSelection(vaneTransportTCP)
		for i := 0; i < 4; i++ {
			observer.recordBucket(selection, "close-progress")
			observer.recordDiagnostic(vaneDiagnosticRecord{kind: "gray-close-progress"})
			observer.recordBucket(selection, "close-tiny")
			observer.recordDiagnostic(vaneDiagnosticRecord{kind: "gray-close-tiny"})
		}
		snapshot := observer.snapshot(diagnostics.snapshot().GrayFailure)
		require.Equal(t, vaneGrayLevelWatch, snapshot.Series[0].Level)
		require.Equal(t, uint64(8), snapshot.Series[0].ShortWindow.Close.Denominator)
		require.InDelta(t, 0.5, snapshot.Series[0].ShortWindow.Close.TinyRate, 1e-12)

		observer, clock, diagnostics = newVaneGrayTestObserver()
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
		require.Equal(t, vaneGrayLevelSuspected, snapshot.Series[0].Level)
		require.Equal(t, []string{"close-sustained-disagreement"}, snapshot.Series[0].Reasons)
		require.Equal(t, uint64(12), snapshot.Series[0].ShortWindow.Close.Denominator)
		require.Equal(t, uint64(20), snapshot.Series[0].LongWindow.Close.Denominator)
	})
}

func TestVaneGrayBucketsIdentityIsolationBoundsAndReadOnlySnapshot(t *testing.T) {
	observer, clock, diagnostics := newVaneGrayTestObserver()
	selection := vaneGrayTestSelection(vaneTransportTCP)
	observer.recordAttempt(selection, "success")

	now := clock.Now().UTC()
	bucketStart := now.Truncate(vaneGrayBucketWidth)
	snapshot := observer.snapshot(diagnostics.snapshot().GrayFailure)
	require.Equal(t, bucketStart.Add(-vaneGrayShortWindow+vaneGrayBucketWidth), snapshot.Series[0].ShortWindow.Start)
	require.Equal(t, bucketStart.Add(vaneGrayBucketWidth), snapshot.Series[0].ShortWindow.EndExclusive)
	require.Equal(t, vaneGrayMemberID(selection.identity), snapshot.Series[0].MemberID)

	replacement := selection
	replacement.identity = "test:alpha-replacement"
	udp := selection
	udp.transport = vaneTransportUDP
	observer.recordAttempt(replacement, "success")
	observer.recordAttempt(udp, "success")
	snapshot = observer.snapshot(diagnostics.snapshot().GrayFailure)
	require.Len(t, snapshot.Series, 3, "same-name replacement and transport must have isolated series")

	clock.Advance(vaneGrayLongWindow + vaneGrayBucketWidth)
	before := len(observer.series)
	first := observer.snapshot(diagnostics.snapshot().GrayFailure)
	second := observer.snapshot(diagnostics.snapshot().GrayFailure)
	require.Empty(t, first.Series)
	require.Equal(t, first, second)
	require.Equal(t, before, len(observer.series), "GET snapshot must not prune or mutate rolling state")

	bounded, _, boundedDiagnostics := newVaneGrayTestObserver()
	evictedIdentity := ""
	evictedMemberID := ""
	lastIdentity := ""
	for index := 0; index < vaneGrayMaxSeries+1; index++ {
		item := selection
		item.identity = "identity-" + string(rune(index+1))
		lastIdentity = item.identity
		if index < vaneGrayMaxSeries {
			memberID := vaneGrayMemberID(item.identity)
			if evictedIdentity == "" || memberID < evictedMemberID {
				evictedIdentity, evictedMemberID = item.identity, memberID
			}
		}
		bounded.recordAttempt(item, "success")
	}
	require.Len(t, bounded.series, vaneGrayMaxSeries)
	_, retainedEvicted := bounded.series[vaneGraySeriesKey{identity: evictedIdentity, transport: vaneTransportTCP}]
	_, retainedNewest := bounded.series[vaneGraySeriesKey{identity: lastIdentity, transport: vaneTransportTCP}]
	require.False(t, retainedEvicted, "same-time eviction must use the documented deterministic member token tie-break")
	require.True(t, retainedNewest)
	require.Equal(t, uint64(vaneGrayMaxSeries+1), boundedDiagnostics.snapshot().GrayFailure.Counters.AttemptEligible, "series eviction must not erase cumulative counters")
}

func TestVaneGrayProductionOutcomeIntegration(t *testing.T) {
	t.Run("tcp immediate failure and neutral cancellation stay separate", func(t *testing.T) {
		clock := newVaneConnTestClock()
		proxy := newVaneTestProxy("alpha", true, true)
		proxy.dialErr = errors.New("dial failed")
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, proxy)
		enableVaneGrayForTest(group)
		metadata := vaneGrayTestMetadata(C.TCP)

		_, err := group.DialContext(context.Background(), metadata)
		require.Error(t, err)
		proxy.dialErr = context.Canceled
		_, err = group.DialContext(context.Background(), metadata)
		require.ErrorIs(t, err, context.Canceled)

		snapshot := group.VaneDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptEligible)
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptFailed)
		require.Equal(t, uint64(1), snapshot.GrayFailure.Exclusions.Attempt["neutral-outcome"])
	})

	t.Run("tcp immediate success and relay-fenced late bytes settle once", func(t *testing.T) {
		clock := newVaneConnTestClock()
		proxy := newVaneTestProxy("alpha", true, true)
		proxy.dialConn = &vaneConnTestConn{}
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, proxy)
		enableVaneGrayForTest(group)
		metadata := vaneGrayTestMetadata(C.TCP)

		conn, err := group.DialContext(context.Background(), metadata)
		require.NoError(t, err)
		_, err = conn.Write([]byte("request"))
		require.NoError(t, err)
		observed := conn.(*vaneObservedConn)
		observed.RelayStarted()
		_, counters := observed.UnwrapReader()
		require.Len(t, counters, 1)
		clock.Advance(time.Second)
		require.NoError(t, conn.Close())
		require.Zero(t, group.VaneDiagnostics().GrayFailure.Counters.CloseEligible, "close must wait for Relay-delivered byte callbacks")
		counters[0](vaneChurnMaxDownloadBytes)
		observed.RelayFinished()
		require.NoError(t, conn.Close())

		snapshot := group.VaneDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptSucceeded)
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.CloseProgress)
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.CloseEligible)
		require.Zero(t, snapshot.GrayFailure.Counters.CloseTiny)
	})

	t.Run("deferred tcp failure and no-send close are complete", func(t *testing.T) {
		clock := newVaneConnTestClock()
		proxy := newVaneTestProxy("alpha", true, true)
		proxy.dialConn = &vaneEarlyTestConn{vaneConnTestConn: &vaneConnTestConn{
			writeFunc: func([]byte) (int, error) { return 0, errors.New("handshake failed") },
		}}
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, proxy)
		enableVaneGrayForTest(group)

		conn, err := group.DialContext(context.Background(), vaneGrayTestMetadata(C.TCP))
		require.NoError(t, err)
		_, err = conn.Write([]byte("request"))
		require.Error(t, err)
		require.NoError(t, conn.Close())
		snapshot := group.VaneDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptFailed)

		proxy.dialErr = nil
		proxy.dialConn = &vaneEarlyTestConn{vaneConnTestConn: &vaneConnTestConn{}}
		conn, err = group.DialContext(context.Background(), vaneGrayTestMetadata(C.TCP))
		require.NoError(t, err)
		require.NoError(t, conn.Close())
		snapshot = group.VaneDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Exclusions.Attempt["neutral-outcome"])
	})

	t.Run("udp first datagram and no-send close partition outcomes", func(t *testing.T) {
		clock := newVaneConnTestClock()
		proxy := newVaneTestProxy("alpha", true, true)
		proxy.packetConn = &vanePacketConnTestFake{}
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, proxy)
		enableVaneGrayForTest(group)
		metadata := vaneGrayTestMetadata(C.UDP)

		packetConn, err := group.ListenPacketContext(context.Background(), metadata)
		require.NoError(t, err)
		_, err = packetConn.WriteTo([]byte("datagram"), vaneConnTestAddr("remote"))
		require.NoError(t, err)
		require.NoError(t, packetConn.Close())

		proxy.packetConn = &vanePacketConnTestFake{}
		packetConn, err = group.ListenPacketContext(context.Background(), metadata)
		require.NoError(t, err)
		require.NoError(t, packetConn.Close())
		require.NoError(t, packetConn.Close())

		snapshot := group.VaneDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptSucceeded)
		require.Equal(t, uint64(1), snapshot.GrayFailure.Exclusions.Attempt["neutral-outcome"])
	})

	t.Run("udp datagram failure is eligible failure", func(t *testing.T) {
		clock := newVaneConnTestClock()
		proxy := newVaneTestProxy("alpha", true, true)
		proxy.packetConn = &vanePacketConnTestFake{writeFunc: func([]byte, net.Addr) (int, error) {
			return 0, errors.New("send failed")
		}}
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, proxy)
		enableVaneGrayForTest(group)
		packetConn, err := group.ListenPacketContext(context.Background(), vaneGrayTestMetadata(C.UDP))
		require.NoError(t, err)
		_, err = packetConn.WriteTo([]byte("datagram"), vaneConnTestAddr("remote"))
		require.Error(t, err)
		require.NoError(t, packetConn.Close())
		snapshot := group.VaneDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptEligible)
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptFailed)
	})

	t.Run("in-flight tcp positive write wins over concurrent close", func(t *testing.T) {
		clock := newVaneConnTestClock()
		started := make(chan struct{})
		release := make(chan struct{})
		proxy := newVaneTestProxy("alpha", true, true)
		proxy.dialConn = &vaneEarlyTestConn{vaneConnTestConn: &vaneConnTestConn{
			writeFunc: func(payload []byte) (int, error) {
				close(started)
				<-release
				return len(payload), nil
			},
		}}
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, proxy)
		enableVaneGrayForTest(group)
		conn, err := group.DialContext(context.Background(), vaneGrayTestMetadata(C.TCP))
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
		snapshot := group.VaneDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptSucceeded)
		require.Zero(t, snapshot.GrayFailure.Exclusions.Attempt["neutral-outcome"])
	})

	t.Run("udp listen failure and neutral cancellation stay separate", func(t *testing.T) {
		clock := newVaneConnTestClock()
		proxy := newVaneTestProxy("alpha", true, true)
		proxy.packetErr = errors.New("listen failed")
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, proxy)
		enableVaneGrayForTest(group)
		metadata := vaneGrayTestMetadata(C.UDP)
		_, err := group.ListenPacketContext(context.Background(), metadata)
		require.Error(t, err)
		proxy.packetErr = context.Canceled
		_, err = group.ListenPacketContext(context.Background(), metadata)
		require.ErrorIs(t, err, context.Canceled)
		snapshot := group.VaneDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptFailed)
		require.Equal(t, uint64(1), snapshot.GrayFailure.Exclusions.Attempt["neutral-outcome"])
	})

	t.Run("in-flight udp positive datagram wins over concurrent close", func(t *testing.T) {
		clock := newVaneConnTestClock()
		started := make(chan struct{})
		release := make(chan struct{})
		proxy := newVaneTestProxy("alpha", true, true)
		proxy.packetConn = &vanePacketConnTestFake{writeFunc: func(payload []byte, _ net.Addr) (int, error) {
			close(started)
			<-release
			return len(payload), nil
		}}
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, proxy)
		enableVaneGrayForTest(group)
		packetConn, err := group.ListenPacketContext(context.Background(), vaneGrayTestMetadata(C.UDP))
		require.NoError(t, err)
		writeDone := make(chan error, 1)
		go func() {
			_, writeErr := packetConn.WriteTo([]byte("datagram"), vaneConnTestAddr("remote"))
			writeDone <- writeErr
		}()
		<-started
		require.NoError(t, packetConn.Close())
		close(release)
		require.NoError(t, <-writeDone)
		snapshot := group.VaneDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Counters.AttemptSucceeded)
		require.Zero(t, snapshot.GrayFailure.Exclusions.Attempt["neutral-outcome"])
	})

	t.Run("all-dead fallback is excluded even when dial returns", func(t *testing.T) {
		clock := newVaneConnTestClock()
		proxy := newVaneTestProxy("alpha", false, true)
		proxy.dialConn = &vaneConnTestConn{}
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, proxy)
		enableVaneGrayForTest(group)
		conn, err := group.DialContext(context.Background(), vaneGrayTestMetadata(C.TCP))
		require.NoError(t, err)
		require.NoError(t, conn.Close())
		snapshot := group.VaneDiagnostics()
		require.Equal(t, uint64(1), snapshot.GrayFailure.Exclusions.Attempt["probe-not-reported-alive"])
		require.Zero(t, snapshot.GrayFailure.Counters.AttemptEligible)
	})
	t.Run("same-name replacement keeps delayed old attempt in old identity series", func(t *testing.T) {
		clock := newVaneConnTestClock()
		proxy := newVaneTestProxy("alpha", true, true)
		proxy.identity = "test:alpha-old"
		proxy.dialConn = &vaneEarlyTestConn{vaneConnTestConn: &vaneConnTestConn{}}
		group, _ := newVaneGroupForTest(clock, 10, time.Hour, proxy)
		enableVaneGrayForTest(group)
		metadata := vaneGrayTestMetadata(C.TCP)
		oldConn, err := group.DialContext(context.Background(), metadata)
		require.NoError(t, err)

		proxy.identity = "test:alpha-new"
		proxy.dialConn = &vaneConnTestConn{}
		newConn, err := group.DialContext(context.Background(), metadata)
		require.NoError(t, err)
		_, err = oldConn.Write([]byte("old request"))
		require.NoError(t, err)
		require.NoError(t, oldConn.Close())
		require.NoError(t, newConn.Close())

		snapshot := group.VaneDiagnostics()
		require.Equal(t, uint64(2), snapshot.GrayFailure.Counters.AttemptSucceeded)
		require.Len(t, snapshot.GrayFailure.Series, 2)
		memberIDs := []string{snapshot.GrayFailure.Series[0].MemberID, snapshot.GrayFailure.Series[1].MemberID}
		require.ElementsMatch(t, []string{vaneGrayMemberID("test:alpha-old"), vaneGrayMemberID("test:alpha-new")}, memberIDs)
	})
}

func TestVaneGrayShadowDoesNotChangeSelectionOrPolicyState(t *testing.T) {
	clockOff := newVaneConnTestClock()
	clockOn := newVaneConnTestClock()
	alphaOff := newVaneTestProxy("alpha", true, true)
	betaOff := newVaneTestProxy("beta", true, true)
	alphaOn := newVaneTestProxy("alpha", true, true)
	betaOn := newVaneTestProxy("beta", true, true)
	alphaOff.dialConn, alphaOn.dialConn = &vaneConnTestConn{}, &vaneConnTestConn{}
	betaOff.dialConn, betaOn.dialConn = &vaneConnTestConn{}, &vaneConnTestConn{}
	off, _ := newVaneGroupForTest(clockOff, 10, time.Hour, alphaOff, betaOff)
	on, _ := newVaneGroupForTest(clockOn, 10, time.Hour, alphaOn, betaOn)
	enableVaneGrayForTest(on)
	metadata := vaneGrayTestMetadata(C.TCP)

	require.Equal(t, off.pickDecision(metadata, vaneTransportTCP, false, false).proxy.Name(), on.pickDecision(metadata, vaneTransportTCP, false, false).proxy.Name())
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

	alphaOff.packetConn, alphaOn.packetConn = &vanePacketConnTestFake{}, &vanePacketConnTestFake{}
	betaOff.packetConn, betaOn.packetConn = &vanePacketConnTestFake{}, &vanePacketConnTestFake{}
	udpMetadata := vaneGrayTestMetadata(C.UDP)
	offPacket, offErr := off.ListenPacketContext(context.Background(), udpMetadata)
	onPacket, onErr := on.ListenPacketContext(context.Background(), udpMetadata)
	require.Equal(t, offErr, onErr)
	require.Equal(t, offPacket.Chains(), onPacket.Chains())
	_, offErr = offPacket.WriteTo([]byte("datagram"), vaneConnTestAddr("remote"))
	_, onErr = onPacket.WriteTo([]byte("datagram"), vaneConnTestAddr("remote"))
	require.Equal(t, offErr, onErr)
	require.Equal(t, offPacket.Close(), onPacket.Close())

	require.Equal(t, vanePolicySnapshotForGrayTest(off), vanePolicySnapshotForGrayTest(on))
	require.Equal(t, off.pickDecision(metadata, vaneTransportTCP, false, false).proxy.Name(), on.pickDecision(metadata, vaneTransportTCP, false, false).proxy.Name())
	require.False(t, off.VaneDiagnostics().GrayFailure.Enabled)
	require.True(t, on.VaneDiagnostics().GrayFailure.Enabled)
	require.Zero(t, off.VaneDiagnostics().GrayFailure.Counters.AttemptEligible)
	require.Equal(t, uint64(2), on.VaneDiagnostics().GrayFailure.Counters.AttemptEligible)
}

type vaneGrayPolicySnapshot struct {
	anchors           map[vaneAnchorKey]vaneAnchor
	cooldowns         map[vaneCooldownKey]time.Time
	explorationScopes [vaneExplorationScopeCount]vaneExplorationScopeState
	churn             map[vaneChurnKey]vaneChurnState
	tcp               vaneMetricsSnapshot
	udp               vaneMetricsSnapshot
}

func vanePolicySnapshotForGrayTest(group *Vane) vaneGrayPolicySnapshot {
	now := group.clock.Now()
	result := vaneGrayPolicySnapshot{
		anchors:   make(map[vaneAnchorKey]vaneAnchor),
		cooldowns: make(map[vaneCooldownKey]time.Time),
		churn:     make(map[vaneChurnKey]vaneChurnState),
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
		result.tcp = state.snapshot(vaneTransportTCP, now)
		result.udp = state.snapshot(vaneTransportUDP, now)
	}
	group.mu.Unlock()
	group.churnMu.Lock()
	for key, value := range group.churn {
		if value != nil {
			result.churn[key] = vaneChurnState{stamps: append([]time.Time(nil), value.stamps...), lastUpdated: value.lastUpdated}
		}
	}
	group.churnMu.Unlock()
	return result
}

func TestVaneGrayDiagnosticsPersistenceAndV1Compatibility(t *testing.T) {
	clock := newVaneConnTestClock()
	store := newVaneDiagnosticsTestStore()
	diagnostics := newVaneDiagnostics("gray-persist", clock, store)
	diagnostics.record(vaneDiagnosticRecord{kind: "gray-attempt-succeeded"})
	diagnostics.record(vaneDiagnosticRecord{kind: "gray-attempt-excluded", reason: "neutral-outcome", force: true})
	diagnostics.waitPersistence()

	restored := newVaneDiagnostics("gray-persist", clock, store).snapshot()
	require.Equal(t, uint64(1), restored.GrayFailure.Counters.AttemptEligible)
	require.Equal(t, uint64(1), restored.GrayFailure.Counters.AttemptSucceeded)
	require.Equal(t, uint64(1), restored.GrayFailure.Exclusions.Attempt["neutral-outcome"])
	require.Empty(t, restored.GrayFailure.Series)
	require.Equal(t, VaneDiagnosticsSchemaVersion, restored.SchemaVersion)

	oldStore := newVaneDiagnosticsTestStore()
	oldPayload := []byte(`{"schemaVersion":1,"group":"gray-old","since":"2026-11-15T00:00:00Z","updatedAt":"2026-11-15T00:00:00Z","counters":{"mediaFlows":7},"suppressions":{"legacy":2},"recentEvents":[{"sequence":3,"time":"2026-11-15T00:00:00Z","kind":"legacy-event"}]}`)
	require.NoError(t, oldStore.Save(vaneDiagnosticsStorageKey("gray-old"), oldPayload))
	old := newVaneDiagnostics("gray-old", clock, oldStore).snapshot()
	require.Equal(t, VaneDiagnosticsSchemaVersion, old.SchemaVersion)
	require.Equal(t, uint64(7), old.Counters.MediaFlows)
	require.Equal(t, uint64(2), old.Suppressions["legacy"])
	require.Equal(t, "legacy-event", old.RecentEvents[0].Kind)
	require.NotNil(t, old.GrayFailure.Exclusions.Attempt)
	require.NotNil(t, old.GrayFailure.Exclusions.Close)
	require.Zero(t, old.GrayFailure.Counters.AttemptEligible)
}

func TestVaneDiagnosticsReadDoesNotPruneExpiredChurnState(t *testing.T) {
	clock := newVaneConnTestClock()
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, newVaneTestProxy("alpha", true, true))
	key := vaneChurnKey{candidate: "alpha", target: "example.com", port: 443}
	group.churn[key] = &vaneChurnState{
		stamps:      []time.Time{clock.Now().Add(-vaneChurnWindow - time.Second)},
		lastUpdated: clock.Now().Add(-vaneChurnWindow - time.Second),
	}

	before := vanePolicySnapshotForGrayTest(group)
	first := group.VaneDiagnostics()
	second := group.VaneDiagnostics()
	after := vanePolicySnapshotForGrayTest(group)
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
