package outboundgroup

import (
	"bytes"
	"context"
	"net/url"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func newVaneObservationRig(t *testing.T, mode vaneSwitchMode) (*Vane, *vaneConnTestClock, *vaneFlow) {
	t.Helper()
	clock := newVaneConnTestClock()
	alpha, beta := newVaneTestProxy("alpha", true, true), newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneFlowForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com")
	configureVaneSwitchForTest(t, group, mode)
	chain01ProductionValues(t, group, 1_000_000)
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		return vaneProbeResult{reason: "test-no-winner"}
	}
	t.Cleanup(func() { _ = group.Close() })
	metadata := &C.Metadata{Host: "rr-observe.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	suppressColdPickProbeForTest(t, group, metadata)
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	flow := newVaneFlow(group, decision.proxy.Name(), metadata)
	require.NotNil(t, flow)
	flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
	return group, clock, flow
}

func vaneObservationLowSample() vaneThroughputObservation {
	return vaneThroughputObservation{BitsPerSecond: 1_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second}
}

// stallToleranceForTest reports how long this flow may stay silent before the
// watchdog synthesizes a window. Tests advance to the real threshold instead of
// hard-coding a duration that now depends on how many bytes the flow banked.
func stallToleranceForTest(t *testing.T, flow *vaneFlow) time.Duration {
	t.Helper()
	flow.mu.Lock()
	defer flow.mu.Unlock()
	return flow.stallToleranceLocked()
}

// FAST-GRACE-01: a graced low still counts toward the streak, so a pulsing
// node (one fast window every 30s, silence in between) can no longer defer the
// switch forever. The grace only decides when the switch fires, it no longer
// freezes the counter (STALL-STREAK).
func TestVaneFastGraceDefersStreak(t *testing.T) {
	for _, mode := range []vaneSwitchMode{vaneSwitchObserve, vaneSwitchLive} {
		t.Run(mode.String(), func(t *testing.T) {
			group, clock, flow := newVaneObservationRig(t, mode)
			require.Nil(t, flow.observe(vaneThroughputObservation{BitsPerSecond: 6_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second}))
			for i := 0; i < 3; i++ {
				clock.Advance(5 * time.Second)
				require.Nil(t, flow.observe(vaneObservationLowSample()))
				flow.mu.Lock()
				count := flow.lowWindows
				flow.mu.Unlock()
				require.Equal(t, i+1, count, "graced lows still count toward the streak")
			}
			require.Equal(t, 3, countVaneEvents(group, "low-window-graced", "recently-fast"))
			require.Equal(t, 1, countVaneEvents(group, "race-scheduled", ""))
		})
	}
}

// FAST-GRACE-02: grace expires exactly at 30s; triggering still reaches the race.
func TestVaneFastGraceExpiresAndCloses(t *testing.T) {
	for _, mode := range []vaneSwitchMode{vaneSwitchObserve, vaneSwitchLive} {
		t.Run(mode.String(), func(t *testing.T) {
			group, clock, flow := newVaneObservationRig(t, mode)
			require.Nil(t, flow.observe(vaneThroughputObservation{BitsPerSecond: 6_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second}))
			clock.Advance(29 * time.Second)
			require.Nil(t, flow.observe(vaneObservationLowSample()))
			clock.Advance(time.Second)
			// The graced low at 29s already counted, so the next two lows take
			// the streak from 2 to 3 and reach the race gate.
			for i := 0; i < 2; i++ {
				require.Nil(t, flow.observe(vaneObservationLowSample()))
				flow.mu.Lock()
				count := flow.lowWindows
				flow.mu.Unlock()
				require.Equal(t, i+2, count, "the graced low before the expiry already counted")
			}
			require.Equal(t, 1, countVaneEvents(group, "race-scheduled", ""))
			require.Equal(t, 1, countVaneEvents(group, "reconnect-suppressed", "no-evidence-candidate"))
		})
	}
}

// FAST-GRACE-03: never-fast flows still trigger on the third low window.
func TestVaneFastGraceInactiveWithoutFastSample(t *testing.T) {
	for _, mode := range []vaneSwitchMode{vaneSwitchObserve, vaneSwitchLive} {
		t.Run(mode.String(), func(t *testing.T) {
			group, _, flow := newVaneObservationRig(t, mode)
			for i := 0; i < 3; i++ {
				require.Nil(t, flow.observe(vaneObservationLowSample()))
			}
			require.Equal(t, 1, countVaneEvents(group, "race-scheduled", ""))
			require.Zero(t, countVaneEvents(group, "low-window-graced", ""))
		})
	}
}

// WATCHDOG-01: 10s silence adds a positive synthetic low and reaches prepare/race.
func TestVaneStallWatchdogSynthesizesWindows(t *testing.T) {
	for _, mode := range []vaneSwitchMode{vaneSwitchObserve, vaneSwitchLive} {
		t.Run(mode.String(), func(t *testing.T) {
			group, clock, flow := newVaneObservationRig(t, mode)
			require.Nil(t, flow.observe(vaneObservationLowSample()))
			require.Nil(t, flow.observe(vaneObservationLowSample()))
			tol := stallToleranceForTest(t, flow)
			clock.Advance(tol - time.Second)
			group.runFlowWatchdogTick(clock.Now())
			flow.mu.Lock()
			count := flow.lowWindows
			flow.mu.Unlock()
			require.Equal(t, 2, count, "still inside the tolerated silence")
			clock.Advance(2 * time.Second)
			group.runFlowWatchdogTick(clock.Now())
			flow.mu.Lock()
			require.Equal(t, group.flow.lowWindows, flow.lowWindows, "a tolerated stall promotes the streak to the trigger line")
			require.Equal(t, float64(1), flow.lastSample.BitsPerSecond)
			require.True(t, flow.lastSample.untrusted)
			require.Equal(t, vaneObservationLowSample().TotalBytes, flow.lastSample.TotalBytes)
			require.Equal(t, 20*time.Second+tol+time.Second, flow.lastSample.Age)
			flow.mu.Unlock()
			require.Equal(t, 1, countVaneEvents(group, "race-scheduled", ""))
		})
	}
}

// WATCHDOG-02: closed, aborted, never-sampled and zero-clock flows are untouched.
func TestVaneStallWatchdogSkipsInactiveFlows(t *testing.T) {
	for _, mode := range []vaneSwitchMode{vaneSwitchObserve, vaneSwitchLive} {
		for _, state := range []string{"never-sampled", "closed", "aborted", "zero-clock"} {
			t.Run(mode.String()+"/"+state, func(t *testing.T) {
				group, clock, flow := newVaneObservationRig(t, mode)
				want := 0
				if state != "never-sampled" {
					require.Nil(t, flow.observe(vaneObservationLowSample()))
					want = 1
				}
				flow.mu.Lock()
				if state == "closed" {
					flow.closed = true
				}
				if state == "aborted" {
					flow.aborted = true
				}
				if state == "zero-clock" {
					flow.lastSampleAt = time.Time{}
				}
				flow.mu.Unlock()
				clock.Advance(time.Minute)
				group.runFlowWatchdogTick(clock.Now())
				flow.mu.Lock()
				count := flow.lowWindows
				flow.mu.Unlock()
				if state == "zero-clock" {
					// ZERO-SAMPLE: no sample ever existed, so the watchdog ages the
					// flow from its creation and promotes the streak.
					require.Equal(t, group.flow.lowWindows, count, "a zero-sample flow is judged after the silence")
				} else {
					require.Equal(t, want, count)
				}
				require.Zero(t, countVaneEvents(group, "race-scheduled", ""))
			})
		}
	}
}

// WATCHDOG-03: synthetic lows obey recently-fast grace, in both modes. The
// grace records the window but no longer freezes the streak (STALL-STREAK), so
// a single synthetic window counts once instead of vanishing.
func TestVaneStallWatchdogRespectsGrace(t *testing.T) {
	for _, mode := range []vaneSwitchMode{vaneSwitchObserve, vaneSwitchLive} {
		t.Run(mode.String(), func(t *testing.T) {
			group, clock, flow := newVaneObservationRig(t, mode)
			require.Nil(t, flow.observe(vaneThroughputObservation{BitsPerSecond: 6_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second}))
			clock.Advance(stallToleranceForTest(t, flow) + time.Second)
			group.runFlowWatchdogTick(clock.Now())
			flow.mu.Lock()
			count := flow.lowWindows
			flow.mu.Unlock()
			require.Equal(t, group.flow.lowWindows, count, "a tolerated stall promotes the streak to the trigger line")
			require.Zero(t, countVaneEvents(group, "low-window-graced", "recently-fast"))
			require.Equal(t, 1, countVaneEvents(group, "race-scheduled", ""), "a tolerated stall goes straight to the trigger")
		})
	}
}

// WATCHDOG lifecycle: exercise the real 5s ticker, unregister and cancellation.
func TestVaneStallWatchdogRealTickerLifecycle(t *testing.T) {
	for _, mode := range []vaneSwitchMode{vaneSwitchObserve, vaneSwitchLive} {
		t.Run(mode.String(), func(t *testing.T) {
			label := t.Name()
			var group *Vane
			var clock *vaneConnTestClock
			var flow *vaneFlow
			// Labels follow the spawned goroutine; unrelated watchdog exits cannot change this verdict.
			pprof.Do(t.Context(), pprof.Labels("vane-watchdog-test", label), func(context.Context) {
				group, clock, flow = newVaneObservationRig(t, mode)
			})
			watching := func() bool {
				var profile bytes.Buffer
				require.NoError(t, pprof.Lookup("goroutine").WriteTo(&profile, 1))
				for _, stack := range strings.Split(profile.String(), "\n\n") {
					if strings.Contains(stack, strconv.Quote(label)) && strings.Contains(stack, "flowWatchdogLoop") {
						return true
					}
				}
				return false
			}
			require.Eventually(t, watching, time.Second, time.Millisecond)
			require.Nil(t, flow.observe(vaneObservationLowSample()))
			clock.Advance(stallToleranceForTest(t, flow) + time.Second)
			require.Eventually(t, func() bool { flow.mu.Lock(); defer flow.mu.Unlock(); return flow.lastSample.BitsPerSecond == 1 }, vaneWatchdogTick+2*time.Second, 10*time.Millisecond, "real ticker must synthesize a window")
			flow.markClosed()
			flow.releaseActiveFlowCount()
			group.flowsMu.Lock()
			require.Empty(t, group.flowSet)
			require.Empty(t, group.activeFlows)
			group.flowsMu.Unlock()
			require.NoError(t, group.Close())
			require.Eventually(t, func() bool { return !watching() }, time.Second, time.Millisecond, "Close cancels this group's actual watchdog goroutine")
		})
	}
}

// FAST-GRACE-02/03: preserve the original actionable-plan assertion with trusted evidence.
func TestVaneFastGraceKnownGoodContract(t *testing.T) {
	for _, mode := range []vaneSwitchMode{vaneSwitchObserve, vaneSwitchLive} {
		for _, history := range []string{"expired", "never-fast"} {
			t.Run(mode.String()+"/"+history, func(t *testing.T) {
				group, clock, flow := newVaneObservationRig(t, mode)
				seedChain01Traffic(t, group, "beta", clock.Now(), 40_000_000)
				if history == "expired" {
					require.Nil(t, flow.observe(vaneThroughputObservation{BitsPerSecond: 6_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second}))
					clock.Advance(vaneFastGrace)
				}
				require.Nil(t, flow.observe(vaneObservationLowSample()))
				require.Nil(t, flow.observe(vaneObservationLowSample()))
				action := flow.observe(vaneObservationLowSample())
				if mode == vaneSwitchLive {
					require.NotNil(t, action, "three trusted lows still produce an executable known-good plan")
					require.True(t, action())
					require.True(t, flow.policyAborted())
					require.Equal(t, uint64(1), group.VaneDiagnostics().Counters.HandoffCommitted)
				} else {
					require.Nil(t, action)
					require.Equal(t, 1, countVaneEvents(group, "handoff-would-commit", "baseline"))
					require.Zero(t, group.VaneDiagnostics().Counters.HandoffCommitted)
				}
			})
		}
	}
}

// Untrusted high samples must not refresh a preference, either.
func TestVaneUntrustedHighSampleDoesNotRefreshPreference(t *testing.T) {
	for _, mode := range []vaneSwitchMode{vaneSwitchObserve, vaneSwitchLive} {
		t.Run(mode.String(), func(t *testing.T) {
			group, clock, flow := newVaneObservationRig(t, mode)
			member := vaneMemberLease{name: flow.candidate, identity: flow.identity, epoch: flow.nodeEpoch}
			pref := vaneTargetPreference{to: member, expiresAt: clock.Now().Add(time.Minute), updatedAt: clock.Now()}
			group.mu.Lock()
			group.targetPreferences[flow.targetStateKey] = pref
			group.mu.Unlock()
			clock.Advance(time.Second)
			require.Nil(t, flow.observe(vaneThroughputObservation{BitsPerSecond: 6_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second, untrusted: true}))
			group.mu.Lock()
			require.Empty(t, group.targetEvidence)
			require.Equal(t, pref, group.targetPreferences[flow.targetStateKey])
			group.mu.Unlock()
		})
	}
}

// STALL-STREAK-01: a node that alternates one fast burst with silence no longer
// resets the streak, so a pulsing but stalled node still reaches the switch.
// This is the live rr4 case: a 30Mbps burst every 30s kept the flow graced for
// minutes while the stream itself never resumed.
func TestVaneFlowPulsingNodeStillTriggers(t *testing.T) {
	group, _, flow := newVaneObservationRig(t, vaneSwitchLive)
	fast := vaneThroughputObservation{BitsPerSecond: 6_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second}
	for i := 0; i < 2; i++ {
		require.Nil(t, flow.observe(fast))
		require.Nil(t, flow.observe(vaneObservationLowSample()))
		require.Nil(t, flow.observe(vaneObservationLowSample()))
	}
	flow.mu.Lock()
	count := flow.lowWindows
	flow.mu.Unlock()
	require.Equal(t, 3, count, "each fast window decays one low, the two lows after it add them back")
	require.Equal(t, 1, countVaneEvents(group, "race-scheduled", ""))
}

// CREDIT-STALL-01: a synthetic (zero-byte) window must not be deferred by the
// cumulative buffer credit earned before the stream stopped. A connection that
// downloaded a lot early shows a large negative credit once it goes silent, and
// the old gate read that as "buffer still has slack" and waited forever.
func TestVaneFlowSyntheticWindowIgnoresBufferCredit(t *testing.T) {
	group, clock, flow := newVaneObservationRig(t, vaneSwitchLive)
	// 2MiB in 20s is far below the 1Mbps demand, so creditBits is negative.
	require.Nil(t, flow.observe(vaneThroughputObservation{BitsPerSecond: 1_000_000, TotalBytes: 2 * 1024 * 1024, Age: 20 * time.Second}))
	flow.mu.Lock()
	flow.lowWindows = 2
	flow.mu.Unlock()

	clock.Advance(stallToleranceForTest(t, flow) + time.Second)
	group.runFlowWatchdogTick(clock.Now())

	require.Zero(t, countVaneEvents(group, "buffer-credit-deferred", ""),
		"a synthetic window must not be deferred by stale credit")
	flow.mu.Lock()
	require.Equal(t, group.flow.lowWindows, flow.lowWindows, "a tolerated stall promotes the streak to the trigger line")
	flow.mu.Unlock()
}

// PHASE2-01: a TCP flow whose target is not a configured target scope is now
// watched AND may be switched — it owns a per-host target scope, so a stalled
// download can be rescued the same way a video flow is. It is still kept out of
// the target-scoped bookkeeping (no count, no target evidence).
func TestVaneUntargetedFlowWatchedAndCanSwitch(t *testing.T) {
	group, _, _ := newVaneObservationRig(t, vaneSwitchLive)
	dropVaneRecordedEvents(group)
	t.Cleanup(func() { dropVaneRecordedEvents(group) })

	flow := newVaneFlow(group, "alpha", &C.Metadata{Host: "rr.example.com", DstPort: 443, NetWork: C.TCP})
	require.NotNil(t, flow, "PHASE2: every TCP flow is watched")
	t.Cleanup(flow.releaseActiveFlowCount)
	require.False(t, flow.targetScoped, "a plain host is not a flow")
	require.Equal(t, "rr.example.com", flow.targetKey.target, "a untargeted host gets its own target scope")
	require.False(t, flow.counted, "a non-flow holds no media count")

	for i := 0; i < 3; i++ {
		require.Nil(t, flow.observe(vaneObservationLowSample()))
	}
	flow.mu.Lock()
	count := flow.lowWindows
	flow.mu.Unlock()
	require.Equal(t, 3, count, "the non-flow still counts low windows")

	// PHASE2: a starving non-flow now reaches the switch path, so a race
	// or a suppression is expected rather than forbidden.
	armed := countVaneEvents(group, "race-scheduled", "") +
		countVaneEvents(group, "reconnect-prepared", "") +
		countVaneEvents(group, "reconnect-suppressed", "")
	require.Greater(t, armed, 0, "a starving non-flow must reach the switch path")
}

// STALL-TOLERANCE-01: the tolerated silence scales with the playback time the
// already-read bytes cover, so a DASH gap on a big flow is ignored while a
// flow that died early is switched quickly.
func TestVaneStallToleranceScalesWithBufferedBytes(t *testing.T) {
	_, _, flow := newVaneObservationRig(t, vaneSwitchLive)
	flow.mu.Lock()
	flow.lastSample = vaneThroughputObservation{TotalBytes: 500 * 1024 * 1024}
	huge := flow.stallToleranceLocked()
	flow.lastSample = vaneThroughputObservation{TotalBytes: 1024 * 1024}
	tiny := flow.stallToleranceLocked()
	flow.mu.Unlock()
	require.Equal(t, vaneStallToleranceMax, huge, "a huge buffer must clamp to the ceiling")
	require.Equal(t, vaneStallToleranceMin, tiny, "a small flow must clamp to the floor")
}

// SWITCH-EVIDENCE-01: a non-flow that moved very little data never
// triggers a switch, no matter how low its measured rate looks.
func TestVaneUntargetedFlowNeedsEnoughBytesToSwitch(t *testing.T) {
	group, _, flow := newVaneObservationRig(t, vaneSwitchLive)
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	flow.mu.Lock()
	flow.targetScoped = false
	flow.lowWindows = group.flow.lowWindows
	flow.mu.Unlock()
	require.Nil(t, flow.observe(vaneThroughputObservation{
		BitsPerSecond: 1_000_000,
		TotalBytes:    4 * 1024 * 1024,
		Age:           20 * time.Second,
	}))
	require.Zero(t, countVaneEvents(group, "race-scheduled", ""), "4 MiB is too little to blame the node")
}

// STICKY-FAMILY-01: a page and its CDN share one sticky choice because the
// rule set scopes them into the same bucket. Without this, a switch could leave
// the page on one exit and the video on another — two IPs for one account.
func TestVaneStickyIsScopedByRuleSetFamily(t *testing.T) {
	group, clock, _ := newVaneObservationRig(t, vaneSwitchLive)
	now := clock.Now()
	group.mu.Lock()
	group.rememberStickyLocked("www.googlevideo.com", 443, "alpha", now)
	name, identity, ok := group.stickyChoiceLocked("rr1.googlevideo.com", 443, now)
	group.mu.Unlock()
	require.True(t, ok, "the CDN host must inherit the family choice")
	require.Equal(t, "alpha", name)
	require.NotEmpty(t, identity, "the sticky record must carry the identity it was made for")
}

func TestVaneSyntheticWindowRespectsClientBacklog(t *testing.T) {
	group, clock, flow := newVaneObservationRig(t, vaneSwitchLive)
	dropVaneRecordedEvents(group)
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	// BACKLOG-FIRST: two low windows are on the streak when the client stops
	// reading (tab backgrounded, player paused). The socket goes silent, so the
	// watchdog synthesizes a window; it must be excused as client backlog, not
	// counted toward the switch threshold.
	flow.observe(vaneObservationLowSample())
	flow.observe(vaneObservationLowSample())
	flow.mu.Lock()
	flow.backloggedAt = clock.Now()
	flow.mu.Unlock()
	clock.Advance(stallToleranceForTest(t, flow))
	group.runFlowWatchdogTick(clock.Now())
	flow.mu.Lock()
	count := flow.lowWindows
	flow.mu.Unlock()
	require.Zero(t, count, "a synthetic window under client backlog must not fill the streak")
	require.Zero(t, countVaneEvents(group, "race-scheduled", ""), "backlog silence must not schedule a race")
}

func TestVaneSmallFlowStallStillSwitches(t *testing.T) {
	group, _, flow := newVaneObservationRig(t, vaneSwitchLive)
	dropVaneRecordedEvents(group)
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	// LOW-VOLUME: a phone stops at a few dozen KiB, far below the 2 MiB sample
	// gate and below the 8 MiB initial-connection gate. A fully silent socket is
	// still a dead connection.
	flow.mu.Lock()
	flow.lowWindows = 2
	// TARGET-SCOPED: only a flow the config named as a switch candidate owns the
	// low-volume exception; an unconfigured flow keeps the 8 MiB gate (next test).
	flow.targetScoped = true
	flow.mu.Unlock()
	flow.observe(vaneThroughputObservation{
		BitsPerSecond: 1,
		synthetic:     true,
		untrusted:     true,
		TotalBytes:    64 * 1024,
		Age:           60 * time.Second,
	})
	signals := countVaneEvents(group, "race-scheduled", "") + countVaneEvents(group, "reconnect-suppressed", "")
	require.NotZero(t, signals, "a small but silent flow must reach the switch decision")
}

func TestVaneUnscopedSmallFlowIsNotSwitched(t *testing.T) {
	group, _, flow := newVaneObservationRig(t, vaneSwitchLive)
	dropVaneRecordedEvents(group)
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	// TARGET-SCOPED: an API host on a keep-alive connection goes idle for a
	// while; that silence is not a stalled segment, and reconnecting it would
	// also tear down every sibling on the same connection.
	flow.mu.Lock()
	flow.lowWindows = 4
	flow.targetScoped = false
	flow.mu.Unlock()
	flow.observe(vaneThroughputObservation{
		BitsPerSecond: 1,
		synthetic:     true,
		untrusted:     true,
		TotalBytes:    512 * 1024,
		Age:           200 * time.Second,
	})
	signals := countVaneEvents(group, "race-scheduled", "") + countVaneEvents(group, "reconnect-suppressed", "")
	require.Zero(t, signals, "an unconfigured flow must not be switched on a few hundred KiB")
}

func TestVaneZeroSampleFlowJudgedAfterSilence(t *testing.T) {
	group, _, flow := newVaneObservationRig(t, vaneSwitchLive)
	dropVaneRecordedEvents(group)
	t.Cleanup(func() { dropVaneRecordedEvents(group) })
	// ZERO-SAMPLE: a connection that never produced a single 32 KiB window is
	// invisible to the sample path. After a long silence it still counts.
	flow.observe(vaneThroughputObservation{
		BitsPerSecond: 1,
		synthetic:     true,
		untrusted:     true,
		TotalBytes:    0,
		Age:           vaneZeroSampleSilence + time.Second,
	})
	signals := countVaneEvents(group, "race-scheduled", "") + countVaneEvents(group, "reconnect-suppressed", "")
	require.NotZero(t, signals, "a zero-sample flow must still be judged after a long silence")
	// STREAK-WRITEBACK: the commit path re-reads the flow's streak, so the
	// synthetic trigger has to persist it instead of promoting a local copy —
	// otherwise every attempt is rejected downstream as "flow-recovered".
	flow.mu.Lock()
	streak := flow.lowWindows
	flow.mu.Unlock()
	require.Equal(t, group.flow.lowWindows, streak, "the synthetic trigger must reach the commit path")
}

func TestVaneSyntheticStallPenalizesLanding(t *testing.T) {
	group, clock, flow := newVaneObservationRig(t, vaneSwitchLive)
	t.Cleanup(func() { dropVaneRecordedEvents(group) })

	flow.mu.Lock()
	flow.lowWindows = 2
	targetKey, candidate := flow.targetKey, flow.candidate
	flow.mu.Unlock()

	group.mu.Lock()
	group.ledger[targetKey] = vaneSwitchLedger{
		windowFrom: clock.Now(),
		lastSwitch: clock.Now(),
		verifyNode: candidate,
		verifyAt:   clock.Now(),
	}
	group.mu.Unlock()

	// A silent flow cannot supply throughput evidence, but it is still evidence
	// about the node it landed on.
	flow.observe(vaneThroughputObservation{
		BitsPerSecond: 1,
		synthetic:     true,
		untrusted:     true,
		TotalBytes:    0,
		Age:           2 * time.Minute,
	})

	group.mu.Lock()
	cooling := group.nodeCoolingLocked(candidate, clock.Now())
	group.mu.Unlock()
	require.True(t, cooling, "a landing that returns nothing must be cooled")
}
