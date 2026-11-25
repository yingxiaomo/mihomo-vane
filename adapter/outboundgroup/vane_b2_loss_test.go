package outboundgroup

import (
	"fmt"
	"math"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

// B2-LOSS-001: the loss EMA is observation-only telemetry — it never acts as
// a failure, samples come only from big-transfer settlements, unsupported
// reads count as unsupported without fabricating a sample, and recording runs
// regardless of the racing mode.
func TestVaneB2LossTelemetry(t *testing.T) {
	observation := func(lossRate float64, supported bool, totalBytes int64) vaneConnectionCloseObservation {
		return vaneConnectionCloseObservation{
			WrotePayload: true, TotalReadBytes: totalBytes,
			LossRate: lossRate, LossSupported: supported,
		}
	}
	b2Flow := func(t *testing.T, withRacing bool) (*Vane, *vaneFlow, *vaneConnTestClock) {
		t.Helper()
		group, clock, alpha, _, _ := newVaneRacingEvidenceGroup(t)
		if !withRacing {
			group.racing.mode = vaneRacingShadow
		}
		group.mu.Lock()
		group.ensureProxyNodeLocked(alpha, clock.Now())
		lease := group.memberLeaseLocked(alpha.Name(), alpha.identity)
		group.mu.Unlock()
		flow := newVaneFlow(group, alpha.Name(), &C.Metadata{Host: "rr.googlevideo.com", DstPort: 443, NetWork: C.TCP})
		require.NotNil(t, flow)
		flow.identity = lease.identity
		flow.nodeEpoch = lease.epoch
		return group, flow, clock
	}
	b2Key := func(flow *vaneFlow) vaneTargetFailureKey {
		return vaneTargetFailureKey{
			target: flow.targetStateKey,
			member: vaneMemberLease{name: flow.candidate, identity: flow.identity, epoch: flow.nodeEpoch},
		}
	}

	t.Run("first sample becomes the estimate, later samples decay", func(t *testing.T) {
		state := vaneTargetFailureState{}
		now := time.Now()
		state.b2FeedLoss(0.02, now)
		require.Equal(t, 0.02, state.lossEMA)
		require.Equal(t, int64(1), state.lossSamples)
		state.b2FeedLoss(0.06, now)
		alpha := vaneB2LossAlphaBase / (1 + vaneB2LossAlphaDecay)
		require.InDelta(t, 0.02+alpha*(0.06-0.02), state.lossEMA, 1e-12)
	})

	t.Run("clamp and reject", func(t *testing.T) {
		state := vaneTargetFailureState{}
		state.b2FeedLoss(2, time.Now())
		require.Equal(t, 1.0, state.lossEMA)
		require.Equal(t, int64(1), state.lossSamples)
		state.b2FeedLoss(-3, time.Now())
		alpha := vaneB2LossAlphaBase / (1 + vaneB2LossAlphaDecay)
		require.InDelta(t, alpha*0+(1-alpha), state.lossEMA, 1e-12, "clamped sample feeds the EMA")
		samples := state.lossSamples
		state.b2FeedLoss(math.NaN(), time.Now())
		state.b2FeedLoss(math.Inf(1), time.Now())
		require.Equal(t, samples, state.lossSamples, "NaN and Inf are no-samples")
		require.InDelta(t, alpha*0+(1-alpha), state.lossEMA, 1e-12)
	})

	t.Run("big transfer records, small transfer does not", func(t *testing.T) {
		group, flow, clock := b2Flow(t, true)
		group.recordB2Loss(flow, observation(0.01, true, 4*1024*1024), clock.Now())
		group.mu.Lock()
		state := group.targetFailures[b2Key(flow)]
		group.mu.Unlock()
		require.Equal(t, int64(1), state.lossSamples)
		require.Equal(t, 0.01, state.lossEMA)
		require.Zero(t, state.streak, "observation must not touch the failure fields")
		require.True(t, state.lastFailureAt.IsZero())

		group.recordB2Loss(flow, observation(0.01, true, 1024), clock.Now())
		group.mu.Lock()
		state = group.targetFailures[b2Key(flow)]
		group.mu.Unlock()
		require.Equal(t, int64(1), state.lossSamples, "small transfers stay out")
	})

	t.Run("unsupported read counts unsupported, no sample", func(t *testing.T) {
		group, flow, clock := b2Flow(t, true)
		group.recordB2Loss(flow, observation(0, false, 4*1024*1024), clock.Now())
		group.mu.Lock()
		state := group.targetFailures[b2Key(flow)]
		group.mu.Unlock()
		require.Zero(t, state.lossSamples, "unsupported must not fabricate a sample")
		require.Equal(t, uint64(1), group.VaneDiagnostics().Counters.B2LossUnsupported)
		require.Zero(t, group.VaneDiagnostics().Counters.B2LossSamples)
	})

	t.Run("observation never acts as failure", func(t *testing.T) {
		group, flow, clock := b2Flow(t, true)
		group.recordB2Loss(flow, observation(0.01, true, 4*1024*1024), clock.Now())
		group.mu.Lock()
		_, blocked := group.targetMemberBlockedLocked(flow.targetStateKey, b2Key(flow).member, clock.Now())
		group.mu.Unlock()
		require.False(t, blocked, "an observation-only record must not block the member")
		require.Equal(t, 1, group.VaneDiagnostics().Runtime.B2LossTargets)
	})

	t.Run("racing off does not stop recording", func(t *testing.T) {
		group, flow, clock := b2Flow(t, false)
		group.recordB2Loss(flow, observation(0.02, true, 4*1024*1024), clock.Now())
		group.mu.Lock()
		state := group.targetFailures[b2Key(flow)]
		group.mu.Unlock()
		require.Equal(t, int64(1), state.lossSamples)
		require.Equal(t, uint64(1), group.VaneDiagnostics().Counters.B2LossSamples)
	})

	t.Run("observation records evict by observation freshness", func(t *testing.T) {
		group, flow, clock := b2Flow(t, true)
		now := clock.Now()
		old := now.Add(-2 * time.Hour)
		late := now.Add(time.Hour)
		group.recordB2Loss(flow, observation(0.01, true, 4*1024*1024), late)

		group.mu.Lock()
		base := flow.targetStateKey
		member := b2Key(flow).member
		for index := 0; index < vaneTargetStateLimit+1; index++ {
			key := vaneTargetKey{transport: base.transport, targetScope: fmt.Sprintf("rr%04d.example.com", index), port: 443}
			group.targetFailures[vaneTargetFailureKey{target: key, member: member}] = vaneTargetFailureState{streak: 1, lastFailureAt: old, blockUntil: old}
		}
		group.pruneTargetStateLocked(now)
		_, observationKept := group.targetFailures[vaneTargetFailureKey{target: base, member: member}]
		group.mu.Unlock()
		require.True(t, observationKept, "observation-fresh record survives the cap trim")
	})
}
