package outboundgroup

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func runVaneRacingFixRound(t *testing.T, group *Vane, request vaneRaceRequest) vaneRaceResult {
	t.Helper()
	var result vaneRaceResult
	done := make(chan struct{})
	scheduled, reason := group.scheduleReconnectRace(request, func(winner vaneRaceResult) {
		result = winner
	}, func() { close(done) })
	require.True(t, scheduled, reason)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("race did not finish")
	}
	return result
}

func TestVaneRacingProbeRotationReachesLaterCandidate(t *testing.T) {
	clock := newVaneConnTestClock()
	proxies := []C.Proxy{newVaneTestProxy("alpha", true, true)}
	const challengerCount = 9
	for i := 0; i < challengerCount; i++ {
		proxies = append(proxies, newVaneTestProxy(fmt.Sprintf("node-%02d", i), true, true))
	}
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, proxies...)
	t.Cleanup(func() { _ = group.Close() })
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	configureVaneSwitchForTest(t, group, vaneSwitchLive)
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})

	var mu sync.Mutex
	calls := make(map[string]int)
	var roundCalls []string
	finalPeerStarted := make(chan struct{})
	group.racing.probe = func(ctx context.Context, proxy C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
		mu.Lock()
		calls[proxy.Name()]++
		roundCalls = append(roundCalls, proxy.Name())
		if proxy.Name() == "node-00" && calls[proxy.Name()] == 2 {
			close(finalPeerStarted)
		}
		mu.Unlock()
		if proxy.Name() == "node-08" {
			// Both final-round probes must enter before the winner can cancel
			// its peer. The peer returns a fixed charged result, then the
			// engine drains it before signaling that the round is done.
			select {
			case <-finalPeerStarted:
			case <-ctx.Done():
				return vaneProbeResult{reason: "canceled"}
			}
			return vaneProbeResult{valid: true, bytes: 8192, duration: time.Second, lowerBoundBPS: 30_000_000}
		}
		return vaneProbeResult{reason: "response-error", bytes: 1024}
	}
	for round := 0; round < 5; round++ {
		mu.Lock()
		roundCalls = nil
		mu.Unlock()
		result := runVaneRacingFixRound(t, group, request)
		mu.Lock()
		actual := append([]string(nil), roundCalls...)
		mu.Unlock()
		expected := []string{fmt.Sprintf("node-%02d", round*2), fmt.Sprintf("node-%02d", (round*2+1)%challengerCount)}
		require.ElementsMatch(t, expected, actual, "round %d must advance past previously attempted challengers", round)
		if round < 4 {
			require.Empty(t, result.winner.name)
		} else {
			require.Equal(t, "node-08", result.winner.name, "the ninth challenger must not remain hidden behind eight invalid front candidates")
		}
		clock.Advance(vaneRacingNoWinnerCooldown + time.Second)
	}
	mu.Lock()
	t.Logf("probes after five rounds: %v", calls)
	mu.Unlock()
	group.racingRuntime.mu.Lock()
	budget := group.racingRuntime.budget
	group.racingRuntime.mu.Unlock()
	require.Equal(t, int64(9*1024+8192), budget.used, "invalid and winning probes charge actual bytes, not reservations")
	require.Zero(t, budget.reserved)
	require.LessOrEqual(t, budget.used, group.racing.budgetBytesHour)
	group.mu.Lock()
	for _, proxy := range proxies[1:] {
		require.Nil(t, group.nodes[proxy.Name()], "probe rotation must not create business health evidence")
	}
	require.Empty(t, group.targetFailures)
	group.mu.Unlock()
}

func TestVaneRacingProbeRotationIsTargetScoped(t *testing.T) {
	clock := newVaneConnTestClock()
	proxies := []C.Proxy{
		newVaneTestProxy("alpha", true, true),
		newVaneTestProxy("beta", true, true),
		newVaneTestProxy("charlie", true, true),
		newVaneTestProxy("delta", true, true),
		newVaneTestProxy("xray", true, true),
		newVaneTestProxy("yankee", true, true),
	}
	group, _ := newVaneGroupForTest(clock, 16, time.Hour, proxies...)
	t.Cleanup(func() { _ = group.Close() })
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	configureVaneSwitchForTest(t, group, vaneSwitchLive)
	requestA := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	requestB := requestA
	requestB.target = "other.example"
	requestB.targetKey.targetScope = requestB.target
	// Real target evidence can leave two sites with different eligible pools.
	// Activity at B must not reset A to the same invalid front candidates.
	group.mu.Lock()
	for _, proxy := range proxies[1:] {
		key := requestB.targetKey
		if proxy.Name() == "xray" || proxy.Name() == "yankee" {
			key = requestA.targetKey
		}
		group.recordTargetEvidenceLocked(key, group.memberLeaseLocked(proxy.Name(), vaneProxyPersistentIdentity(proxy)), 1000, false, clock.Now())
	}
	group.mu.Unlock()
	var mu sync.Mutex
	var calls []string
	group.racing.probe = func(_ context.Context, proxy C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
		mu.Lock()
		calls = append(calls, proxy.Name())
		mu.Unlock()
		if proxy.Name() == "delta" {
			return vaneProbeResult{valid: true, bytes: 4096, duration: time.Second, lowerBoundBPS: 30_000_000}
		}
		return vaneProbeResult{reason: "response-error", bytes: 1024}
	}
	for index, round := range []struct {
		request  vaneRaceRequest
		expected []string
		winner   string
	}{
		{requestA, []string{"beta", "charlie"}, ""},
		{requestB, []string{"xray", "yankee"}, ""},
		{requestA, []string{"delta", "beta"}, "delta"},
	} {
		calls = nil
		result := runVaneRacingFixRound(t, group, round.request)
		require.ElementsMatch(t, round.expected, calls, "interleaved round %d", index)
		require.Equal(t, round.winner, result.winner.name)
		clock.Advance(vaneRacingNoWinnerCooldown + time.Second)
	}
}

func newVaneRacingFixGroup(t *testing.T) (*Vane, *vaneConnTestClock, *vaneTestProvider, []C.Proxy, vaneRaceRequest) {
	t.Helper()
	clock := newVaneConnTestClock()
	proxies := []C.Proxy{
		newVaneTestProxy("alpha", true, true),
		newVaneTestProxy("beta", true, true),
		newVaneTestProxy("charlie", true, true),
		newVaneTestProxy("delta", true, true),
		newVaneTestProxy("echo", true, true),
	}
	group, provider := newVaneGroupForTest(clock, 16, time.Hour, proxies...)
	t.Cleanup(func() { _ = group.Close() })
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	configureVaneSwitchForTest(t, group, vaneSwitchLive)
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	return group, clock, provider, proxies, request
}

func TestVaneRacingProbeRotationRetriesFailedPool(t *testing.T) {
	group, clock, _, _, request := newVaneRacingFixGroup(t)
	var mu sync.Mutex
	var calls []string
	betaCalls := 0
	group.racing.probe = func(_ context.Context, proxy C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, proxy.Name())
		if proxy.Name() == "beta" {
			betaCalls++
			if betaCalls == 2 {
				return vaneProbeResult{valid: true, bytes: 4096, lowerBoundBPS: 30_000_000}
			}
		}
		return vaneProbeResult{reason: "response-error", bytes: 1024}
	}
	for index, expected := range [][]string{{"beta", "charlie"}, {"delta", "echo"}, {"beta", "charlie"}} {
		calls = nil
		result := runVaneRacingFixRound(t, group, request)
		require.ElementsMatch(t, expected, calls, "round %d", index)
		if index < 2 {
			require.Empty(t, result.winner.name)
		} else {
			require.Equal(t, "beta", result.winner.name, "a failed pool must remain retryable when a candidate recovers")
		}
		clock.Advance(vaneRacingNoWinnerCooldown + time.Second)
	}
}

func TestVaneRacingProbeCursorExpiryAndMembership(t *testing.T) {
	for _, test := range []struct {
		name     string
		elapsed  time.Duration
		change   string
		expected []string
	}{
		{name: "fresh", elapsed: 31 * time.Second, expected: []string{"delta", "echo"}},
		{name: "before idle expiry", elapsed: vaneRacingProbeCursorTTL - time.Nanosecond, expected: []string{"delta", "echo"}},
		{name: "idle expiry", elapsed: vaneRacingProbeCursorTTL, expected: []string{"beta", "charlie"}},
		{name: "new identity", elapsed: 31 * time.Second, change: "identity", expected: []string{"beta", "charlie"}},
		// AUDIT-2026-11-28: an innocent epoch bump (ranking selected the node
		// between rounds) no longer resets the rotation — only a real identity
		// replacement does.
		{name: "new epoch", elapsed: 31 * time.Second, change: "epoch", expected: []string{"delta", "echo"}},
		{name: "removed member", elapsed: 31 * time.Second, change: "removed", expected: []string{"beta", "delta"}},
		{name: "fresh slow cache", elapsed: 31 * time.Second, change: "capability", expected: []string{"beta", "delta"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			group, clock, provider, proxies, request := newVaneRacingFixGroup(t)
			var mu sync.Mutex
			var calls []string
			group.racing.probe = func(_ context.Context, proxy C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
				mu.Lock()
				calls = append(calls, proxy.Name())
				mu.Unlock()
				return vaneProbeResult{reason: "response-error"}
			}
			runVaneRacingFixRound(t, group, request)
			require.ElementsMatch(t, []string{"beta", "charlie"}, calls)
			calls = nil
			clock.Advance(test.elapsed)
			switch test.change {
			case "identity":
				replacement := newVaneTestProxy("charlie", true, true)
				replacement.identity = "replacement:charlie"
				proxies[2] = replacement
				provider.setProxies(proxies...)
				group.refreshNodeIdentities(provider.Proxies())
			case "epoch":
				group.mu.Lock()
				group.learning.mu.Lock()
				group.ensureProxyNodeLocked(proxies[2], clock.Now())
				group.learning.mu.Unlock()
				group.mu.Unlock()
			case "removed":
				provider.setProxies(proxies[0], proxies[1], proxies[3], proxies[4])
				group.refreshNodeIdentities(provider.Proxies())
			case "capability":
				seedVaneCapability(group, clock, proxies[2].(*vaneTestProxy), 1000)
			}
			runVaneRacingFixRound(t, group, request)
			require.ElementsMatch(t, test.expected, calls)
		})
	}
}

func TestVaneRacingProbeCursorUsesFundedAttempts(t *testing.T) {
	group, clock, _, _, request := newVaneRacingFixGroup(t)
	var mu sync.Mutex
	var calls []string
	group.racing.probe = func(_ context.Context, proxy C.Proxy, _ *url.URL, limit int64) vaneProbeResult {
		mu.Lock()
		calls = append(calls, proxy.Name())
		mu.Unlock()
		return vaneProbeResult{reason: "response-error", bytes: limit}
	}
	group.racing.budgetBytesHour = vaneRacingProbeByteCap
	runVaneRacingFixRound(t, group, request)
	require.Equal(t, []string{"beta"}, calls)
	group.racingRuntime.mu.Lock()
	cursor := group.racingRuntime.probeCursors[request.targetKey]
	budget := group.racingRuntime.budget
	group.racingRuntime.mu.Unlock()
	require.Equal(t, "beta", cursor.member.name, "a one-probe reservation must not advance past the unfunded second candidate")
	require.Equal(t, vaneRacingProbeByteCap, budget.used)
	require.Zero(t, budget.reserved)

	clock.Advance(vaneRacingNoWinnerCooldown + time.Second)
	calls = nil
	runVaneRacingFixRound(t, group, request)
	require.Empty(t, calls, "exhausted budget must not call a probe")
	group.racingRuntime.mu.Lock()
	require.Equal(t, cursor, group.racingRuntime.probeCursors[request.targetKey], "denied budget must not advance or extend the target cursor")
	group.racingRuntime.mu.Unlock()

	clock.Advance(vaneRacingNoWinnerCooldown + time.Second)
	group.racing.budgetBytesHour = vaneDefaultRacingBudgetMBHour * 1024 * 1024
	runVaneRacingFixRound(t, group, request)
	require.ElementsMatch(t, []string{"charlie", "delta"}, calls)
}

func TestVaneRacingProbeCursorIgnoresCanceledRound(t *testing.T) {
	group, clock, _, _, request := newVaneRacingFixGroup(t)
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		return vaneProbeResult{reason: "response-error"}
	}
	runVaneRacingFixRound(t, group, request)
	group.racingRuntime.mu.Lock()
	cursor := group.racingRuntime.probeCursors[request.targetKey]
	group.racingRuntime.mu.Unlock()
	require.Equal(t, "charlie", cursor.member.name)
	clock.Advance(vaneRacingNoWinnerCooldown + time.Second)

	started := make(chan struct{}, vaneRacingMaxChallengers)
	exited := make(chan struct{}, vaneRacingMaxChallengers)
	group.racing.probe = func(ctx context.Context, _ C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
		started <- struct{}{}
		<-ctx.Done()
		exited <- struct{}{}
		return vaneProbeResult{reason: "canceled", bytes: 1024}
	}
	done := make(chan struct{})
	scheduled, reason := group.scheduleReconnectRace(request, func(vaneRaceResult) { t.Error("canceled round must not choose a winner") }, func() { close(done) })
	require.True(t, scheduled, reason)
	for i := 0; i < vaneRacingMaxChallengers; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("probe did not start")
		}
	}
	group.racingRuntime.mu.Lock()
	cancel := group.racingRuntime.activeTasks[group.racingRuntime.nextTaskID]
	group.racingRuntime.mu.Unlock()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled race did not finish")
	}
	for i := 0; i < vaneRacingMaxChallengers; i++ {
		<-exited
	}
	require.Eventually(t, func() bool {
		group.racingRuntime.mu.Lock()
		defer group.racingRuntime.mu.Unlock()
		return group.racingRuntime.budget.reserved == 0
	}, time.Second, time.Millisecond)
	group.racingRuntime.mu.Lock()
	require.Equal(t, cursor, group.racingRuntime.probeCursors[request.targetKey])
	require.Equal(t, int64(2*1024), group.racingRuntime.budget.used, "cancellation still charges actual bytes")
	group.racingRuntime.mu.Unlock()
}

func TestVaneRacingProbeCursorStateBoundedAndExpires(t *testing.T) {
	group, clock, _, _, request := newVaneRacingFixGroup(t)
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		return vaneProbeResult{reason: "response-error"}
	}
	oldest := request.targetKey
	oldest.targetScope = "cursor-0000.example"
	for index := 0; index < vaneTargetStateLimit+17; index++ {
		request.target = fmt.Sprintf("cursor-%04d.example", index)
		request.targetKey.targetScope = request.target
		runVaneRacingFixRound(t, group, request)
		group.racingRuntime.mu.Lock()
		count := len(group.racingRuntime.probeCursors)
		group.racingRuntime.mu.Unlock()
		require.LessOrEqual(t, count, vaneTargetStateLimit)
		clock.Advance(time.Nanosecond)
	}
	group.racingRuntime.mu.Lock()
	_, oldestKept := group.racingRuntime.probeCursors[oldest]
	_, newestKept := group.racingRuntime.probeCursors[request.targetKey]
	count := len(group.racingRuntime.probeCursors)
	group.racingRuntime.mu.Unlock()
	require.Equal(t, vaneTargetStateLimit, count)
	require.False(t, oldestKept)
	require.True(t, newestKept)

	clock.Advance(vaneRacingProbeCursorTTL)
	request.target = "after-expiry.example"
	request.targetKey.targetScope = request.target
	runVaneRacingFixRound(t, group, request)
	group.racingRuntime.mu.Lock()
	count = len(group.racingRuntime.probeCursors)
	budget := group.racingRuntime.budget
	group.racingRuntime.mu.Unlock()
	require.Equal(t, 1, count, "a new target must also reclaim expired cursors for other targets")
	require.Zero(t, budget.used)
	require.Zero(t, budget.reserved)
}

func TestVaneRacingNoWinnerStateExpiresAcrossTargets(t *testing.T) {
	clock := newVaneConnTestClock()
	group, _ := newVaneGroupForTest(clock, 2, time.Hour, newVaneTestProxy("alpha", true, true))
	t.Cleanup(func() { _ = group.Close() })
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	configureVaneSwitchForTest(t, group, vaneSwitchLive)
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	for i := 0; i < 1100; i++ {
		request.target = fmt.Sprintf("expired-%04d.example", i)
		request.targetKey.targetScope = request.target
		result := runVaneRacingFixRound(t, group, request)
		require.Empty(t, result.winner.name)
		clock.Advance(vaneRacingNoWinnerCooldown + time.Second)
	}
	group.racingRuntime.mu.Lock()
	count := len(group.racingRuntime.noWinnerUntil)
	budget := group.racingRuntime.budget
	group.racingRuntime.mu.Unlock()
	require.LessOrEqual(t, count, 1, "a new target must reclaim expired cooldowns for all other targets")
	require.Zero(t, budget.used)
	require.Zero(t, budget.reserved)
}

func TestVaneRacingNoWinnerStateBounded(t *testing.T) {
	clock := newVaneConnTestClock()
	group, _ := newVaneGroupForTest(clock, 2, time.Hour, newVaneTestProxy("alpha", true, true))
	t.Cleanup(func() { _ = group.Close() })
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	configureVaneSwitchForTest(t, group, vaneSwitchLive)
	request := newVaneRaceRequestForTest(t, group, &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
	oldestKey := request.targetKey
	oldestKey.targetScope = "bounded-0000.example"
	for i := 0; i < vaneTargetStateLimit+17; i++ {
		request.target = fmt.Sprintf("bounded-%04d.example", i)
		request.targetKey.targetScope = request.target
		runVaneRacingFixRound(t, group, request)
		clock.Advance(time.Nanosecond)
		group.racingRuntime.mu.Lock()
		count := len(group.racingRuntime.noWinnerUntil)
		group.racingRuntime.mu.Unlock()
		require.LessOrEqual(t, count, vaneTargetStateLimit, "fresh target churn must never leave the map above its cap")
	}
	group.racingRuntime.mu.Lock()
	_, oldestKept := group.racingRuntime.noWinnerUntil[oldestKey]
	_, newestKept := group.racingRuntime.noWinnerUntil[request.targetKey]
	count := len(group.racingRuntime.noWinnerUntil)
	group.racingRuntime.mu.Unlock()
	require.Equal(t, vaneTargetStateLimit, count)
	require.False(t, oldestKept, "capacity eviction must discard the earliest expiry")
	require.True(t, newestKept)
	scheduled, reason := group.scheduleReconnectRace(request, func(vaneRaceResult) {})
	require.False(t, scheduled)
	require.Equal(t, "no-winner-cooldown", reason)

	clock.Advance(vaneRacingNoWinnerCooldown)
	runVaneRacingFixRound(t, group, request)
	group.racingRuntime.mu.Lock()
	count = len(group.racingRuntime.noWinnerUntil)
	group.racingRuntime.mu.Unlock()
	require.Equal(t, 1, count, "all expired entries must be reclaimed before installing the current target cooldown")
}

// TEST-RACE-DRAIN-SURPLUS-01 (audit 2026-11-28): a probe that completed
// (cap-hit) before the winner fired is a paid measurement — its capability
// must be banked so the next round does not re-probe the same node, and the
// diagnostic must not label it canceled.
func TestVaneRacingDrainedProbeBanksCapability(t *testing.T) {
	group, _, _, _, request := newVaneRacingFixGroup(t)
	var mu sync.Mutex
	var calls []string
	winnerDone := make(chan struct{})
	group.racing.probe = func(_ context.Context, proxy C.Proxy, _ *url.URL, _ int64) vaneProbeResult {
		mu.Lock()
		calls = append(calls, proxy.Name())
		name := proxy.Name()
		mu.Unlock()
		if name == "beta" {
			return vaneProbeResult{valid: true, reason: "cap-hit", bytes: 4 << 20, lowerBoundBPS: 40_000_000}
		}
		if name == "charlie" {
			// Stay in flight until the winner callback runs, then complete —
			// its outcome can only land in the winner's drain loop.
			<-winnerDone
			return vaneProbeResult{valid: true, reason: "cap-hit", bytes: 4 << 20, lowerBoundBPS: 1_500_000}
		}
		return vaneProbeResult{reason: "response-error", bytes: 1024}
	}

	var result vaneRaceResult
	done := make(chan struct{})
	scheduled, reason := group.scheduleReconnectRace(request, func(winner vaneRaceResult) {
		// Close the gate before taking mu: the gated probe may still hold mu
		// until its result returns, and locking first would deadlock the round.
		close(winnerDone)
		mu.Lock()
		result = winner
		mu.Unlock()
	}, func() { close(done) })
	require.True(t, scheduled, reason)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("race did not finish")
	}
	mu.Lock()
	winnerName := result.winner.name
	mu.Unlock()
	require.Equal(t, "beta", winnerName)
	require.ElementsMatch(t, []string{"beta", "charlie"}, calls)

	group.racingRuntime.mu.Lock()
	var charlieBPS float64
	var charlieFound bool
	for lease, record := range group.racingRuntime.capabilities {
		if lease.name == "charlie" {
			charlieFound, charlieBPS = true, record.lowerBoundBPS
		}
	}
	group.racingRuntime.mu.Unlock()
	require.True(t, charlieFound, "the drained probe's capability must be banked")
	require.Equal(t, 1_500_000.0, charlieBPS)
	require.Equal(t, 1, countVaneEvents(group, "race-probe-surplus", "cap-hit"))
	require.Zero(t, countVaneEvents(group, "race-probe-canceled", "cap-hit"))
}
