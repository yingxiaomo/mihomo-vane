package tunnel

import (
	"fmt"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/stretchr/testify/require"
)

func TestProxyPublicationAndReadersAreSynchronized(t *testing.T) {
	const iterations = 1000
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		for i := 0; i < iterations; i++ {
			UpdateProxiesWithCommit(
				map[string]C.Proxy{fmt.Sprintf("proxy-%d", i): nil},
				map[string]P.ProxyProvider{},
				nil,
			)
		}
	}()
	go func() {
		defer wait.Done()
		for i := 0; i < iterations; i++ {
			snapshot := Proxies()
			snapshot["caller-owned"] = nil
			_ = Providers()
			_ = Tunnel.Proxies()
			_ = Tunnel.Providers()
		}
	}()
	wait.Wait()

	_, leaked := Proxies()["caller-owned"]
	require.False(t, leaked, "public getters must not expose the mutable published map")
}

// lockProbeRule blocks inside Match so a test can prove the caller holds
// configMux.RLock while RuleProviders is entered.
type lockProbeRule struct {
	entered chan struct{}
	proceed chan struct{}
	once    sync.Once
	seen    map[string]bool
}

func (r *lockProbeRule) RuleType() C.RuleType { return C.MATCH }

func (r *lockProbeRule) Match(*C.Metadata, C.RuleMatchHelper) (bool, string) {
	r.once.Do(func() { close(r.entered) })
	<-r.proceed
	if r.seen != nil {
		for name := range RuleProviders() {
			r.seen[name] = true
		}
	}
	return false, ""
}

func (r *lockProbeRule) Adapter() string         { return "DIRECT" }
func (r *lockProbeRule) Payload() string         { return "lock-probe" }
func (r *lockProbeRule) ProviderNames() []string { return nil }

// snapshotTunnelRules restores the package-level routing state after a test.
// These tests mutate globals and must not call t.Parallel().
func snapshotTunnelRules(t *testing.T) {
	t.Helper()
	configMux.RLock()
	oldRules, oldSubRules := rules, subRules
	configMux.RUnlock()
	ruleProvidersMu.RLock()
	oldRuleProviders := ruleProviders
	ruleProvidersMu.RUnlock()
	t.Cleanup(func() {
		configMux.Lock()
		rules, subRules = oldRules, oldSubRules
		configMux.Unlock()
		ruleProvidersMu.Lock()
		ruleProviders = oldRuleProviders
		ruleProvidersMu.Unlock()
	})
}

func setTunnelRulesForTest(ruleList []C.Rule, providers map[string]P.RuleProvider) {
	configMux.Lock()
	rules = ruleList
	subRules = nil
	configMux.Unlock()
	ruleProvidersMu.Lock()
	ruleProviders = providers
	ruleProvidersMu.Unlock()
}

func waitForQueuedRuleWriter(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if configMux.TryRLock() {
			configMux.RUnlock()
		} else {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("UpdateRules did not queue on configMux")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestRuleProvidersNestedUnderMatchDoesNotDeadlock is LOCK-01: a RuleSet match
// runs while match holds configMux.RLock; RuleProviders must not re-enter
// configMux once a writer is queued.
func TestRuleProvidersNestedUnderMatchDoesNotDeadlock(t *testing.T) {
	snapshotTunnelRules(t)
	probe := &lockProbeRule{entered: make(chan struct{}), proceed: make(chan struct{})}
	setTunnelRulesForTest([]C.Rule{probe}, map[string]P.RuleProvider{"old": nil})

	matchDone := make(chan struct{})
	go func() {
		defer close(matchDone)
		_, _, _ = match(&C.Metadata{Host: "lock-probe.example"}, C.RuleMatchHelper{})
	}()
	select {
	case <-probe.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("match did not reach the probe rule")
	}

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		UpdateRules([]C.Rule{}, nil, map[string]P.RuleProvider{"new": nil})
	}()
	waitForQueuedRuleWriter(t)

	close(probe.proceed)
	select {
	case <-matchDone:
	case <-time.After(3 * time.Second):
		t.Fatal("match deadlocked in a nested RuleProviders read")
	}
	select {
	case <-writerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("UpdateRules did not finish after match released configMux")
	}
}

// TestRuleProvidersSnapshotStaysConsistentAcrossQueuedUpdate is LOCK-03: while
// match holds configMux.RLock, a queued UpdateRules cannot publish a new
// provider map, so the nested read sees the old snapshot.
func TestRuleProvidersSnapshotStaysConsistentAcrossQueuedUpdate(t *testing.T) {
	snapshotTunnelRules(t)
	probe := &lockProbeRule{
		entered: make(chan struct{}),
		proceed: make(chan struct{}),
		seen:    make(map[string]bool),
	}
	setTunnelRulesForTest([]C.Rule{probe}, map[string]P.RuleProvider{"old": nil})

	matchDone := make(chan struct{})
	go func() {
		defer close(matchDone)
		_, _, _ = match(&C.Metadata{Host: "lock-probe.example"}, C.RuleMatchHelper{})
	}()
	select {
	case <-probe.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("match did not reach the probe rule")
	}

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		UpdateRules([]C.Rule{}, nil, map[string]P.RuleProvider{"new": nil})
	}()
	waitForQueuedRuleWriter(t)

	close(probe.proceed)
	select {
	case <-matchDone:
	case <-time.After(3 * time.Second):
		t.Fatal("match deadlocked in a nested RuleProviders read")
	}
	require.True(t, probe.seen["old"], "nested read must see the pre-update snapshot")
	require.False(t, probe.seen["new"], "queued update must not leak into the in-flight evaluation")

	select {
	case <-writerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("UpdateRules did not finish")
	}
	require.Contains(t, RuleProviders(), "new")
	require.NotContains(t, RuleProviders(), "old")
}
