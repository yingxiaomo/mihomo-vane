package outboundgroup

import (
	"context"
	"sort"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// This file holds the test-only Vane wrappers moved out of vane.go
// (TEST-WRAP-001): production paths go through the Epoch/Identity variants
// directly, so these non-Epoch forms only exist for tests.
// Signatures and behavior are unchanged from the move.

func (a *Vane) recordDialFailure(ctx context.Context, metadata *C.Metadata, transport vaneTransport, proxy C.Proxy, err error, now time.Time) {
	a.recordDialFailureEpoch(ctx, metadata, transport, proxy, vaneProxyPersistentIdentity(proxy), 0, err, now)
}

func (a *Vane) recordDialSuccess(metadata *C.Metadata, transport vaneTransport, candidate, identity string, now time.Time) {
	a.recordDialSuccessEpoch(metadata, transport, candidate, identity, 0, now)
}

func (a *Vane) observeConnect(candidate string, transport vaneTransport, now time.Time, elapsed time.Duration) {
	a.observeConnectIdentity(candidate, a.nodeIdentity(candidate), transport, now, elapsed)
}

func (a *Vane) observeResponse(candidate string, transport vaneTransport, now time.Time, elapsed time.Duration) {
	a.observeResponseIdentity(candidate, a.nodeIdentity(candidate), transport, now, elapsed)
}

func (a *Vane) observeThroughput(candidate string, transport vaneTransport, now time.Time, bitsPerSecond float64) {
	a.observeThroughputIdentity(candidate, a.nodeIdentity(candidate), transport, now, bitsPerSecond)
}

// vaneCooledNodes lists the nodes that still sit on their own cooldown. NODE-
// COOLDOWN: the node is the failing unit, so its cooldown answers for every
// target it could serve.
func vaneCooledNodes(group *Vane) []string {
	group.mu.Lock()
	defer group.mu.Unlock()
	return vaneCooledNodesLocked(group)
}

// vaneCooledNodesLocked is the same list for callers that already hold a.mu.
func vaneCooledNodesLocked(group *Vane) []string {
	now := group.clock.Now()
	var names []string
	for name, state := range group.nodes {
		if state != nil && state.cooldown.After(now) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// vaneCoolNodeForTest puts a node on cooldown the way a switch does.
func vaneCoolNodeForTest(group *Vane, name string, until time.Time) {
	group.mu.Lock()
	defer group.mu.Unlock()
	group.coolNodeLocked(name, until, true)
}

// suppressColdPickProbeForTest keeps the call sites in older tests readable:
// the cold-pick probe is gone, so a pick no longer spends budget on
// capability evidence and there is nothing left to suppress.
func suppressColdPickProbeForTest(t *testing.T, group *Vane, metadata *C.Metadata) {
	t.Helper()
	_ = group
	_ = metadata
}
