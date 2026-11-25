package outboundgroup

import (
	"context"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// B2-STEP3-004 (test lock, no production change): a race that produces no
// winner still installs the 30s no-winner suppression, so one slow flow cannot
// re-run an empty race on every low window. Step 3 gives this path a second
// way to end with no candidates — every challenger excluded by its loss record
// — so the behaviour is pinned here.
func TestVaneB2Step3EmptySnapshotInstallsSuppression(t *testing.T) {
	group, clock, _, beta, gamma := newVaneRacingEvidenceGroup(t)
	var probes atomic.Int32
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		probes.Add(1)
		return vaneProbeResult{valid: true, reason: "cap-hit", bytes: vaneRacingProbeByteCap, duration: time.Second, lowerBoundBPS: 80_000_000, capHit: true}
	}

	request := newVaneB2Step3RaceRequest(t, group)
	for _, proxy := range []*vaneTestProxy{beta, gamma} {
		member := seedVaneB2CandidateEvidence(t, group, proxy, 8_000_000)
		// Every challenger is over the loss line, so the snapshot comes back
		// empty exactly the way Step 3 intends.
		seedVaneB2FailureState(t, group, request, member, func(state *vaneTargetFailureState) {
			state.lossEMA, state.lossSamples = 0.50, 8
		})
	}

	scheduled, reason := group.scheduleReconnectRace(request, func(vaneRaceResult) {
		t.Error("an all-degraded snapshot must not produce a winner")
	})
	require.True(t, scheduled, reason)
	waitVaneRaceIdle(t, group)
	require.Zero(t, probes.Load(), "no excluded challenger may be probed")
	require.Positive(t, group.VaneDiagnostics().Counters.RaceNoWinner)

	// The suppression window rejects the next race for the same target.
	scheduled, reason = group.scheduleReconnectRace(request, func(vaneRaceResult) {})
	require.False(t, scheduled, "a repeat race inside the suppression window must be refused")
	require.Equal(t, "no-winner-cooldown", reason)

	// Once the window expires the target may race again.
	clock.Advance(vaneRacingNoWinnerCooldown + time.Second)
	scheduled, reason = group.scheduleReconnectRace(request, func(vaneRaceResult) {})
	require.True(t, scheduled, reason)
	waitVaneRaceIdle(t, group)
}
