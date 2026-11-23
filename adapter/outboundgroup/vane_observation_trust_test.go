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

func newVaneObservationRig(t *testing.T, mode vaneRacingMode) (*Vane, *vaneConnTestClock, *vaneMediaFlow) {
	t.Helper()
	clock := newVaneConnTestClock()
	alpha, beta := newVaneTestProxy("alpha", true, true), newVaneTestProxy("beta", true, true)
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	configureVaneRacingForTest(t, group, mode)
	chain01ProductionValues(t, group, 1_000_000)
	group.racing.probe = func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult {
		return vaneProbeResult{reason: "test-no-winner"}
	}
	t.Cleanup(func() { _ = group.Close() })
	metadata := &C.Metadata{Host: "rr-observe.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	suppressColdPickProbeForTest(t, group, metadata)
	decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
	flow := newVaneMediaFlow(group, decision.proxy.Name(), metadata)
	require.NotNil(t, flow)
	flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
	return group, clock, flow
}

func vaneObservationLowSample() vaneThroughputObservation {
	return vaneThroughputObservation{BitsPerSecond: 1_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second}
}

// FAST-GRACE-01: preserve the original strict zero-streak assertion in both modes.
func TestVaneFastGraceDefersStreak(t *testing.T) {
	for _, mode := range []vaneRacingMode{vaneRacingShadow, vaneRacingOn} {
		t.Run(mode.String(), func(t *testing.T) {
			group, clock, flow := newVaneObservationRig(t, mode)
			require.Nil(t, flow.observe(vaneThroughputObservation{BitsPerSecond: 6_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second}))
			for i := 0; i < 3; i++ {
				clock.Advance(5 * time.Second)
				require.Nil(t, flow.observe(vaneObservationLowSample()))
				flow.mu.Lock()
				count := flow.lowWindows
				flow.mu.Unlock()
				require.Zero(t, count, "graced lows must not accumulate")
			}
			require.Equal(t, 3, countVaneEvents(group, "low-window-graced", "recently-fast"))
			require.Zero(t, countVaneEvents(group, "race-scheduled", ""))
		})
	}
}

// FAST-GRACE-02: grace expires exactly at 30s; triggering still reaches the race.
func TestVaneFastGraceExpiresAndCloses(t *testing.T) {
	for _, mode := range []vaneRacingMode{vaneRacingShadow, vaneRacingOn} {
		t.Run(mode.String(), func(t *testing.T) {
			group, clock, flow := newVaneObservationRig(t, mode)
			require.Nil(t, flow.observe(vaneThroughputObservation{BitsPerSecond: 6_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second}))
			clock.Advance(29 * time.Second)
			require.Nil(t, flow.observe(vaneObservationLowSample()))
			clock.Advance(time.Second)
			for i := 0; i < 3; i++ {
				require.Nil(t, flow.observe(vaneObservationLowSample()))
				flow.mu.Lock()
				count := flow.lowWindows
				flow.mu.Unlock()
				require.Equal(t, i+1, count)
			}
			require.Equal(t, 1, countVaneEvents(group, "race-scheduled", ""))
			require.Equal(t, 1, countVaneEvents(group, "reconnect-suppressed", "no-evidence-candidate"))
		})
	}
}

// FAST-GRACE-03: never-fast flows still trigger on the third low window.
func TestVaneFastGraceInactiveWithoutFastSample(t *testing.T) {
	for _, mode := range []vaneRacingMode{vaneRacingShadow, vaneRacingOn} {
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
	for _, mode := range []vaneRacingMode{vaneRacingShadow, vaneRacingOn} {
		t.Run(mode.String(), func(t *testing.T) {
			group, clock, flow := newVaneObservationRig(t, mode)
			require.Nil(t, flow.observe(vaneObservationLowSample()))
			require.Nil(t, flow.observe(vaneObservationLowSample()))
			clock.Advance(9 * time.Second)
			group.runMediaWatchdogTick(clock.Now())
			flow.mu.Lock()
			count := flow.lowWindows
			flow.mu.Unlock()
			require.Equal(t, 2, count)
			clock.Advance(time.Second)
			group.runMediaWatchdogTick(clock.Now())
			flow.mu.Lock()
			require.Equal(t, 3, flow.lowWindows)
			require.Equal(t, float64(1), flow.lastSample.BitsPerSecond)
			require.True(t, flow.lastSample.untrusted)
			require.Equal(t, vaneObservationLowSample().TotalBytes, flow.lastSample.TotalBytes)
			require.Equal(t, 30*time.Second, flow.lastSample.Age)
			flow.mu.Unlock()
			require.Equal(t, 1, countVaneEvents(group, "race-scheduled", ""))
		})
	}
}

// WATCHDOG-02: closed, aborted, never-sampled and zero-clock flows are untouched.
func TestVaneStallWatchdogSkipsInactiveFlows(t *testing.T) {
	for _, mode := range []vaneRacingMode{vaneRacingShadow, vaneRacingOn} {
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
				group.runMediaWatchdogTick(clock.Now())
				flow.mu.Lock()
				count := flow.lowWindows
				flow.mu.Unlock()
				require.Equal(t, want, count)
				require.Zero(t, countVaneEvents(group, "race-scheduled", ""))
			})
		}
	}
}

// WATCHDOG-03: synthetic lows obey recently-fast grace, in both modes.
func TestVaneStallWatchdogRespectsGrace(t *testing.T) {
	for _, mode := range []vaneRacingMode{vaneRacingShadow, vaneRacingOn} {
		t.Run(mode.String(), func(t *testing.T) {
			group, clock, flow := newVaneObservationRig(t, mode)
			require.Nil(t, flow.observe(vaneThroughputObservation{BitsPerSecond: 6_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second}))
			clock.Advance(vaneMediaStallSilence)
			group.runMediaWatchdogTick(clock.Now())
			flow.mu.Lock()
			count := flow.lowWindows
			flow.mu.Unlock()
			require.Zero(t, count)
			require.Equal(t, 1, countVaneEvents(group, "low-window-graced", "recently-fast"))
		})
	}
}

// WATCHDOG lifecycle: exercise the real 5s ticker, unregister and cancellation.
func TestVaneStallWatchdogRealTickerLifecycle(t *testing.T) {
	for _, mode := range []vaneRacingMode{vaneRacingShadow, vaneRacingOn} {
		t.Run(mode.String(), func(t *testing.T) {
			label := t.Name()
			var group *Vane
			var clock *vaneConnTestClock
			var flow *vaneMediaFlow
			// Labels follow the spawned goroutine; unrelated watchdog exits cannot change this verdict.
			pprof.Do(t.Context(), pprof.Labels("vane-watchdog-test", label), func(context.Context) {
				group, clock, flow = newVaneObservationRig(t, mode)
			})
			watching := func() bool {
				var profile bytes.Buffer
				require.NoError(t, pprof.Lookup("goroutine").WriteTo(&profile, 1))
				for _, stack := range strings.Split(profile.String(), "\n\n") {
					if strings.Contains(stack, strconv.Quote(label)) && strings.Contains(stack, "mediaWatchdogLoop") {
						return true
					}
				}
				return false
			}
			require.Eventually(t, watching, time.Second, time.Millisecond)
			require.Nil(t, flow.observe(vaneObservationLowSample()))
			clock.Advance(vaneMediaStallSilence)
			require.Eventually(t, func() bool { flow.mu.Lock(); defer flow.mu.Unlock(); return flow.lowWindows == 2 }, vaneMediaWatchdogTick+2*time.Second, 10*time.Millisecond, "real ticker must synthesize a window")
			flow.markClosed()
			flow.releaseActiveFlowCount()
			group.mediaFlowsMu.Lock()
			require.Empty(t, group.mediaFlowSet)
			require.Empty(t, group.mediaActiveFlows)
			group.mediaFlowsMu.Unlock()
			require.NoError(t, group.Close())
			require.Eventually(t, func() bool { return !watching() }, time.Second, time.Millisecond, "Close cancels this group's actual watchdog goroutine")
		})
	}
}

// FAST-GRACE-02/03: preserve the original actionable-plan assertion with trusted evidence.
func TestVaneFastGraceKnownGoodContract(t *testing.T) {
	for _, mode := range []vaneRacingMode{vaneRacingShadow, vaneRacingOn} {
		for _, history := range []string{"expired", "never-fast"} {
			t.Run(mode.String()+"/"+history, func(t *testing.T) {
				group, clock, flow := newVaneObservationRig(t, mode)
				seedChain01Traffic(t, group, "beta", clock.Now(), 40_000_000)
				if history == "expired" {
					require.Nil(t, flow.observe(vaneThroughputObservation{BitsPerSecond: 6_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second}))
					clock.Advance(vaneMediaFastGrace)
				}
				require.Nil(t, flow.observe(vaneObservationLowSample()))
				require.Nil(t, flow.observe(vaneObservationLowSample()))
				action := flow.observe(vaneObservationLowSample())
				if mode == vaneRacingOn {
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
	for _, mode := range []vaneRacingMode{vaneRacingShadow, vaneRacingOn} {
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
