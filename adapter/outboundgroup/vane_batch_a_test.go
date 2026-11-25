package outboundgroup

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/stretchr/testify/require"
)

// VANE-CONFIG-01: reject presence, not a decoded value, before registering providers.
func TestVaneConfigRejectsLegacyRacingPresence(t *testing.T) {
	for _, key := range []string{"racing", "RACING", "RaCiNg"} {
		for _, value := range []any{"on", "shadow", "off", "", nil, false, 0} {
			t.Run(fmt.Sprintf("%s/%v", key, value), func(t *testing.T) {
				providers := map[string]P.ProxyProvider{}
				_, err := ParseProxyGroup(map[string]any{
					"name": "legacy", "type": "vane", "proxies": []string{"alpha"}, key: value,
				}, map[string]C.Proxy{"COMPATIBLE": newVaneTestProxy("COMPATIBLE", true, false), "alpha": newVaneTestProxy("alpha", true, true)}, providers, nil, nil)
				require.ErrorContains(t, err, "racing")
				require.ErrorContains(t, err, "vane")
				require.ErrorContains(t, err, "replace")
				require.Empty(t, providers)
			})
		}
	}
}

// VANE-CONFIG-02 / VANE-OFF-01 / VANE-ON-01: the real parser and DialContext wiring.
func TestVaneConfigSwitchRunsActualRace(t *testing.T) {
	for _, setting := range []string{"omitted", "null", "false", "true"} {
		t.Run(setting, func(t *testing.T) {
			clock := newVaneConnTestClock()
			underlying := &vaneConnTestConn{readFunc: func(p []byte) (int, error) { return len(p), nil }}
			alpha, beta := newVaneTestProxy("alpha", true, true), newVaneTestProxy("beta", true, true)
			alpha.dialConn, alpha.delay, beta.delay = underlying, 20, 10
			config := map[string]any{
				"name": "switch-" + setting, "type": "vane", "proxies": []string{"alpha", "beta"},
				"scene-rules": []string{"DOMAIN-SUFFIX,googlevideo.com,media"}, "media-reconnect": true,
				"media-demand-bps": "1M",
			}
			if setting != "omitted" {
				config["vane"] = setting == "true"
			}
			if setting == "null" {
				config["vane"] = nil
			}
			parsed, err := ParseProxyGroup(config, map[string]C.Proxy{
				"COMPATIBLE": newVaneTestProxy("COMPATIBLE", true, false), "alpha": alpha, "beta": beta,
			}, map[string]P.ProxyProvider{}, nil, nil)
			require.NoError(t, err)
			group := parsed.(*Vane)
			installVaneEventRecorder(group)
			t.Cleanup(func() { _ = group.Close() })
			wantMode := vaneRacingOn
			if setting == "false" {
				wantMode = vaneRacingShadow
			}
			require.Equal(t, wantMode, group.racing.mode)
			group.clock, group.diagnostics.clock = clock, clock
			// Three real low windows meet unchanged production age/size/credit gates.
			var calls atomic.Int32
			entered, release := make(chan struct{}, 1), make(chan struct{})
			group.racing.probe = func(ctx context.Context, proxy C.Proxy, _ *url.URL, limit int64) vaneProbeResult {
				calls.Add(1)
				if proxy.Name() != "beta" || limit != vaneRacingProbeByteCap {
					return vaneProbeResult{reason: "unexpected-candidate"}
				}
				entered <- struct{}{}
				select {
				case <-release:
					return vaneProbeResult{valid: true, reason: "cap-hit", bytes: limit, duration: time.Second, lowerBoundBPS: 40_000_000, capHit: true}
				case <-ctx.Done():
					return vaneProbeResult{reason: "canceled"}
				}
			}
			metadata := &C.Metadata{Host: "rr-switch.googlevideo.com", DstPort: 443, NetWork: C.TCP}
			suppressColdPickProbeForTest(t, group, metadata)
			conn, err := group.DialContext(t.Context(), metadata)
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })
			observed := conn.(*vaneObservedConn)
			reader, counters := observed.UnwrapReader()
			for i := 0; i < 18; i++ {
				if i > 0 {
					clock.Advance(time.Second)
				}
				n, err := reader.Read(make([]byte, 256*1024))
				require.NoError(t, err)
				for _, counter := range counters {
					counter(int64(n))
				}
			}
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("slow flow did not schedule race")
			}
			require.Equal(t, 1, countVaneEvents(group, "race-scheduled", ""))
			require.Equal(t, 1, countVaneEvents(group, "reconnect-suppressed", "no-evidence-candidate"))
			underlying.mu.Lock()
			before := underlying.closeCalls
			underlying.mu.Unlock()
			require.Zero(t, before)
			close(release)
			require.Eventually(t, func() bool {
				group.racingRuntime.mu.Lock()
				defer group.racingRuntime.mu.Unlock()
				return !group.racingRuntime.inFlight
			}, time.Second, time.Millisecond)
			require.Equal(t, int32(1), calls.Load())
			group.racingRuntime.mu.Lock()
			require.Len(t, group.racingRuntime.capabilities, 1)
			for member, cap := range group.racingRuntime.capabilities {
				require.Equal(t, "beta", member.name)
				require.Equal(t, float64(40_000_000), cap.lowerBoundBPS)
			}
			require.Equal(t, vaneRacingProbeByteCap, group.racingRuntime.budget.used)
			require.Zero(t, group.racingRuntime.budget.reserved)
			group.racingRuntime.mu.Unlock()
			require.Equal(t, 1, countVaneEvents(group, "handoff-would-commit", "probe"))
			underlying.mu.Lock()
			closes := underlying.closeCalls
			underlying.mu.Unlock()
			if setting == "false" {
				require.Zero(t, closes)
				require.Zero(t, group.VaneDiagnostics().Counters.ReconnectCommitted)
				group.mu.Lock()
				require.Empty(t, group.targetHandoffs)
				require.Empty(t, group.mediaHints)
				require.Empty(t, group.mediaSlowCooldowns)
				group.mu.Unlock()
				_, err = conn.Read(make([]byte, 1024))
				require.NoError(t, err, "dry-run connection remains readable")
			} else {
				require.Equal(t, 1, closes, "async callback closes without another low window")
				group.mu.Lock()
				require.Len(t, group.targetHandoffs, 1)
				require.True(t, group.mediaReconnects[group.mediaTargetKey(metadata.Host, metadata.DstPort)].After(clock.Now()))
				group.mu.Unlock()
			}
		})
	}
}

// VANE-OFF-01: an evidence-backed baseline plan must also be observation-only.
func TestVaneOffObserveKnownGoodNeverCloses(t *testing.T) {
	clock := newVaneConnTestClock()
	underlying := &vaneConnTestConn{readFunc: func(p []byte) (int, error) { return len(p), nil }}
	alpha, beta := newVaneTestProxy("alpha", true, true), newVaneTestProxy("beta", true, true)
	alpha.dialConn = underlying
	group, _ := newVaneGroupForTest(clock, 10, time.Hour, alpha, beta)
	configureVaneMediaForTest(t, group, "DOMAIN-SUFFIX,googlevideo.com,media")
	configureVaneRacingForTest(t, group, vaneRacingShadow)
	t.Cleanup(func() { _ = group.Close() })
	seedChain01Traffic(t, group, "beta", clock.Now(), 40_000_000)
	metadata := &C.Metadata{Host: "rr-known.googlevideo.com", DstPort: 443, NetWork: C.TCP}
	suppressColdPickProbeForTest(t, group, metadata)
	conn, err := group.DialContext(t.Context(), metadata)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	readVaneLowWindows(t, conn, clock, 3)
	underlying.mu.Lock()
	closes := underlying.closeCalls
	underlying.mu.Unlock()
	require.Zero(t, closes)
	require.Equal(t, 1, countVaneEvents(group, "handoff-would-commit", "baseline"))
	require.Zero(t, group.VaneDiagnostics().Counters.ReconnectCommitted)
	group.mu.Lock()
	require.Empty(t, group.mediaHints)
	require.Empty(t, group.targetHandoffs)
	require.Empty(t, group.mediaReconnects)
	require.Empty(t, group.mediaSlowCooldowns)
	group.mu.Unlock()
}

// VANE-OFF-02: prove prepare succeeded and reached the flow submission gate.
func TestVaneOffValveNeverSubmitsKnownGoodAction(t *testing.T) {
	group, clock, _, _, gamma, flow, observed, underlying, metadata, _ := newValveRig(t, 2_000_000)
	t.Cleanup(func() { _ = group.Close() })
	configureVaneRacingForTest(t, group, vaneRacingShadow)
	seedChain01Traffic(t, group, gamma.Name(), clock.Now(), 40_000_000)
	key := group.mediaTargetKey(metadata.Host, metadata.DstPort)
	plan, reason := group.prepareMediaReconnectForNodeDetailedSkipCooldown(key, metadata.Host, metadata.DstPort, flow.candidate, flow.identity, flow.nodeEpoch, flow.valveCurrentBPS, true)
	require.Empty(t, reason)
	require.True(t, plan.knownGood)
	require.Equal(t, gamma.Name(), plan.challenger)
	var submissions atomic.Int32
	flow.setPolicySubmitter(func(action vanePolicyAction, delivered bool) {
		submissions.Add(1)
		observed.submitPolicyAction(action, delivered)
	})
	before := group.VaneDiagnostics().Counters.ReconnectCommitted
	flow.noteEmptyWindow()
	flow.noteEmptyWindow()
	require.Equal(t, 1, countVaneEvents(group, "reconnect-valve", ""))
	for _, event := range vaneRecordedEvents(group) {
		if event.Kind == "reconnect-valve" {
			require.Empty(t, event.Reason)
			require.Equal(t, gamma.Name(), event.To)
		}
	}
	require.Equal(t, 1, countVaneEvents(group, "handoff-would-commit", "dry-run"))
	require.Zero(t, submissions.Load())
	underlying.mu.Lock()
	closes := underlying.closeCalls
	underlying.mu.Unlock()
	require.Zero(t, closes)
	require.Equal(t, before, group.VaneDiagnostics().Counters.ReconnectCommitted)
}

// GRACE-NO-EVIDENCE-01 / WATCHDOG-NO-EVIDENCE-01: pin every settlement residue.
func TestVaneUntrustedObservationPreservesHealthAndHandoff(t *testing.T) {
	for _, mode := range []vaneRacingMode{vaneRacingOn, vaneRacingShadow} {
		for _, source := range []string{"grace", "watchdog"} {
			t.Run(mode.String()+"/"+source, func(t *testing.T) {
				group, clock, _, beta, metadata := newTargetGroupForTest(t)
				t.Cleanup(func() { _ = group.Close() })
				suppressColdPickProbeForTest(t, group, metadata)
				plan := prepareTargetHandoffForTest(t, group, metadata, beta)
				plan.currentBPS = 4_000_000
				require.Empty(t, group.commitTargetHandoff(plan))
				decision := group.pickDecision(t.Context(), metadata, vaneTransportTCP, false, true)
				require.NotNil(t, decision.handoff)
				flow := newVaneMediaFlow(group, decision.proxy.Name(), metadata)
				flow.identity, flow.nodeEpoch = decision.identity, decision.nodeEpoch
				fast := vaneThroughputObservation{BitsPerSecond: 6_000_000, TotalBytes: 8 * 1024 * 1024, Age: 20 * time.Second}
				if source == "watchdog" {
					fast.BitsPerSecond = 2_000_000
				}
				require.Nil(t, flow.observe(fast))
				// A just-claimed token waits for the next sample; it must be detached, not settled.
				flow.handoff = decision.handoff
				configureVaneRacingForTest(t, group, mode)
				member := decision.handoff.toLease
				key := flow.targetStateKey
				group.mu.Lock()
				pref := vaneTargetPreference{to: member, expiresAt: clock.Now().Add(time.Minute), updatedAt: clock.Now()}
				group.targetPreferences[key] = pref
				evidence := group.targetEvidence[vaneTargetEvidenceKey{target: key, member: member}]
				failureKey := vaneTargetFailureKey{target: key, member: member}
				failure := vaneTargetFailureState{capBPS: 12_000_000, capSamples: 2, capAt: clock.Now(), lossSamples: 3, attemptCount: 4, suspectedStallCount: 1}
				group.targetFailures[failureKey] = failure
				lease := group.targetHandoffs[key]
				cooldown := group.mediaReconnects[flow.targetKey]
				slowKey := vaneMediaCandidateKey{vaneMediaTargetKey: flow.targetKey, candidate: member.name, identity: member.identity}
				slowCount := len(group.mediaSlowCooldowns)
				group.mu.Unlock()
				b2Before := group.VaneDiagnostics().Counters
				if source == "grace" {
					clock.Advance(5 * time.Second)
					require.Nil(t, flow.observe(vaneThroughputObservation{BitsPerSecond: 2_000_000, TotalBytes: fast.TotalBytes, Age: 25 * time.Second}))
				} else {
					clock.Advance(vaneMediaStallSilence)
					group.runMediaWatchdogTick(clock.Now())
				}
				flow.mu.Lock()
				if source == "grace" {
					// A graced window still counts once (STALL-STREAK); the
					// grace only keeps the switch from firing on this window.
					require.Equal(t, 1, flow.lowWindows)
				} else {
					require.Equal(t, 2, flow.lowWindows)
					require.Equal(t, float64(1), flow.lastSample.BitsPerSecond)
				}
				require.Nil(t, flow.handoff, "摘取/清空仍执行；lease留到TTL")
				flow.mu.Unlock()
				group.mu.Lock()
				require.Equal(t, evidence, group.targetEvidence[vaneTargetEvidenceKey{target: key, member: member}])
				require.Equal(t, pref, group.targetPreferences[key])
				require.Equal(t, failure, group.targetFailures[failureKey], "capBPS and B2 telemetry unchanged")
				require.Equal(t, lease, group.targetHandoffs[key])
				require.True(t, lease.expiresAt.After(clock.Now()), "the untrusted window arrives while the claimed lease is still valid")
				require.Equal(t, cooldown, group.mediaReconnects[flow.targetKey])
				require.Equal(t, slowCount, len(group.mediaSlowCooldowns))
				require.Zero(t, group.mediaSlowCooldowns[slowKey])
				group.mu.Unlock()
				b2After := group.VaneDiagnostics().Counters
				require.Equal(t, b2Before.B2LossSamples, b2After.B2LossSamples)
				require.Equal(t, b2Before.B2StallAttempts, b2After.B2StallAttempts)
				require.Equal(t, b2Before.B2StallSuspected, b2After.B2StallSuspected)
				require.Zero(t, countVaneEvents(group, "handoff-no-gain", ""))
				require.Zero(t, countVaneEvents(group, "handoff-measured", ""))
				require.Zero(t, countVaneEvents(group, "race-scheduled", ""))
			})
		}
	}
}

// OFF-PROBE-DELETED-01: actual source/AST absence, not an un-compilable reference.
func TestVaneOffProbeDeletedSourceContract(t *testing.T) {
	_, err := os.Stat("vane_offprobe_test.go")
	require.True(t, os.IsNotExist(err), "off-only test file must be deleted")
	paths, err := filepath.Glob("*.go")
	require.NoError(t, err)
	for _, path := range paths {

		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		require.NoError(t, err)
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				require.NotContains(t, []string{"vaneRacingOff", "scheduleEvidenceProbe", "runEvidenceProbe", "clearEvidenceProbeInflight", "evidenceProbeUntil", "evidenceProbeInflight", "vaneMediaEvidenceProbeThrottle"}, id.Name, path)
			}
			return true
		})
	}
}

// SHADOW-KEPT-01: a capability-backed, non-knownGood plan still runs the race.
func TestVaneOffObserveCapabilityPlanStaysDryRun(t *testing.T) {
	group, clock, flow := newVaneObservationRig(t, vaneRacingShadow)
	member := vaneMemberLease{name: "beta", identity: group.nodeIdentities["beta"]}
	seedChain01Capability(t, group, member, 40_000_000, clock.Now())
	plan, reason := group.prepareMediaReconnectForNodeDetailed(flow.targetKey, flow.target, flow.port, flow.candidate, flow.identity, flow.nodeEpoch, 1_000_000)
	require.Empty(t, reason)
	require.False(t, plan.knownGood)
	var submitted atomic.Int32
	flow.setPolicySubmitter(func(vanePolicyAction, bool) { submitted.Add(1) })
	for i := 0; i < 3; i++ {
		require.Nil(t, flow.observe(vaneObservationLowSample()))
	}
	require.Eventually(t, func() bool { return countVaneEvents(group, "handoff-would-commit", "capability-cache") == 1 }, time.Second, time.Millisecond)
	require.Equal(t, 1, countVaneEvents(group, "handoff-would-commit", "baseline"))
	require.Zero(t, submitted.Load())
	group.mu.Lock()
	require.Empty(t, group.targetHandoffs)
	require.Empty(t, group.mediaHints)
	require.Empty(t, group.mediaReconnects)
	group.mu.Unlock()
}

func TestVaneLegacyRacingKeyDoesNotAffectOtherGroupTypes(t *testing.T) {
	_, err := ParseProxyGroup(map[string]any{"name": "select", "type": "select", "proxies": []string{"alpha"}, "racing": "on"},
		map[string]C.Proxy{"COMPATIBLE": newVaneTestProxy("COMPATIBLE", true, false), "alpha": newVaneTestProxy("alpha", true, true)}, map[string]P.ProxyProvider{}, nil, nil)
	require.NoError(t, err)
}
