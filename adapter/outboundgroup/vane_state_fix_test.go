package outboundgroup

import (
	"context"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func TestVaneSharedNodeSnapshotsAcrossReload(t *testing.T) {
	for _, path := range []string{"diagnostics", "target-hint", "hint"} {
		t.Run(path, func(t *testing.T) {
			clock := newVaneConnTestClock()
			proxy := newVaneTestProxy("alpha", true, true)
			owner := newVaneLearningState("vane-test", clock, nil, time.Hour, 16)
			oldGroup, _ := newVaneGroupForTest(clock, 16, time.Hour, proxy)
			oldGroup.attachLearningState(owner, activateVaneLearningState(owner, time.Hour, 16))
			oldDecision := oldGroup.pickDecision(context.Background(), nil, vaneTransportTCP, false, true)
			for _, transport := range []vaneTransport{vaneTransportTCP, vaneTransportUDP} {
				oldGroup.observeThroughputEpochIdentity(proxy.Name(), proxy.identity, oldDecision.nodeEpoch, transport, clock.Now(), 6_000_000)
			}

			newGroup, _ := newVaneGroupForTest(clock, 16, time.Hour, proxy)
			newGroup.attachLearningState(owner, activateVaneLearningState(owner, time.Hour, 16))
			newGroup.pick(nil, vaneTransportTCP, false, true)
			require.Same(t, oldGroup.nodes[proxy.Name()], newGroup.nodes[proxy.Name()], "reload generations must share the canonical node")
			t.Cleanup(func() {
				_ = oldGroup.Close()
				_ = newGroup.Close()
				dropVaneRecordedEvents(oldGroup)
				dropVaneRecordedEvents(newGroup)
			})

			metadata := &C.Metadata{Host: "snapshot.example", DstPort: 443, NetWork: C.TCP}
			if path != "diagnostics" {
				configureVaneFlowForTest(t, newGroup, "DOMAIN,snapshot.example")
				newGroup.switchMode = vaneSwitchLive
				newGroup.mu.Lock()
				if path == "target-hint" {
					key, ok := newGroup.targetScopeForKey(metadata.Host, metadata.DstPort)
					require.True(t, ok)
					newGroup.targetPreferences[key] = vaneTargetPreference{
						to:        newGroup.memberLeaseLocked(proxy.Name(), proxy.identity),
						expiresAt: clock.Now().Add(time.Hour), updatedAt: clock.Now(),
					}
				} else {
					key := newGroup.targetScopeKey(metadata.Host, metadata.DstPort)
					newGroup.hints[key] = vaneHint{candidate: proxy.Name(), identity: proxy.identity, expiresAt: clock.Now().Add(time.Hour)}
				}
				newGroup.mu.Unlock()
			}

			// An old flow is still allowed to append passive samples after reload.
			// The new group's own mutex cannot protect those shared node fields.
			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for i := 0; i < 1000; i++ {
					for _, transport := range []vaneTransport{vaneTransportTCP, vaneTransportUDP} {
						oldGroup.observeThroughputEpochIdentity(proxy.Name(), proxy.identity, oldDecision.nodeEpoch, transport, clock.Now(), float64(6_000_000+i))
					}
				}
			}()
			close(start)
			for i := 0; i < 1000; i++ {
				if path == "diagnostics" {
					_ = newGroup.VaneDiagnostics()
				} else {
					newGroup.pick(metadata, vaneTransportTCP, false, true)
				}
			}
			wg.Wait()

			profiles := newGroup.VaneDiagnostics().Runtime.ThroughputProfiles
			require.Positive(t, profiles[proxy.Name()].TCP.P10BPS)
			require.Positive(t, profiles[proxy.Name()].UDP.P10BPS)
			if path != "diagnostics" {
				require.Equal(t, 1000, countVaneEvents(newGroup, "pick-scored", path), "exercise the early-return snapshot, not the regular ranking return")
			}
		})
	}
}

func TestVaneColdPickStickyIdentity(t *testing.T) {
	t.Run("first pick records the selected endpoint identity", func(t *testing.T) {
		clock := newVaneConnTestClock()
		beta := newVaneTestProxy("beta", true, true)
		group, _ := newVaneGroupForTest(clock, 16, time.Hour, beta)
		t.Cleanup(func() {
			_ = group.Close()
			dropVaneRecordedEvents(group)
		})
		metadata := &C.Metadata{Host: "sticky.example", DstPort: 443, NetWork: C.TCP}
		require.Same(t, beta, group.pick(metadata, vaneTransportTCP, false, true))
		group.mu.Lock()
		name, identity, ok := group.stickyChoiceLocked(metadata.Host, metadata.DstPort, clock.Now())
		group.mu.Unlock()
		require.True(t, ok)
		require.Equal(t, beta.Name(), name)
		require.Equal(t, beta.identity, identity)
	})

	t.Run("same name replacement does not inherit the old endpoint sticky", func(t *testing.T) {
		clock := newVaneConnTestClock()
		oldBeta := newVaneTestProxy("beta", true, true)
		group, provider := newVaneGroupForTest(clock, 16, time.Hour, oldBeta)
		t.Cleanup(func() {
			_ = group.Close()
			dropVaneRecordedEvents(group)
		})
		metadata := &C.Metadata{Host: "sticky.example", DstPort: 443, NetWork: C.TCP}
		require.Same(t, oldBeta, group.pick(metadata, vaneTransportTCP, false, true))
		alpha := newVaneTestProxy("alpha", true, true)
		newBeta := newVaneTestProxy("beta", true, true)
		newBeta.identity = "test:beta-replacement"
		provider.setProxies(alpha, newBeta)
		clock.Advance(time.Second)
		// Both new endpoints have the same cold score; alpha wins the normal
		// name tie-break. A stale name-only sticky incorrectly forces newBeta.
		require.Same(t, alpha, group.pick(metadata, vaneTransportTCP, false, true))
	})
}
