package outboundgroup

import (
	"net/netip"
	"strings"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// Churn shadow observations intentionally do not affect ranking, cooldowns,
// anchors, health, or connection ownership. The thresholds mirror the proven
// PLD service-stall signature, but the result is named "suspected" because the
// proxy core cannot prove why an application closed a short connection.
const (
	sageChurnLimit            = 4
	sageChurnWindow           = 5 * time.Minute
	sageChurnMaxDownloadBytes = int64(1024)
	sageChurnMaxLifetime      = 30 * time.Second
	sageChurnMaxStates        = 4096
)

type sageChurnKey struct {
	target    string
	port      uint16
	candidate string
}

type sageChurnState struct {
	stamps      []time.Time
	lastUpdated time.Time
}

func sageChurnTarget(metadata *C.Metadata) (string, uint16, bool) {
	if metadata == nil || metadata.DstPort == 0 {
		return "", 0, false
	}
	if host := metadata.RuleHost(); host != "" {
		normalized, valid := normalizeSageDomain(host)
		return normalized, metadata.DstPort, valid
	}
	if metadata.DstIP.IsValid() {
		return metadata.DstIP.String(), metadata.DstPort, true
	}
	return "", metadata.DstPort, false
}

func sageChurnDNSBootstrap(target string, port uint16) bool {
	if port == 53 || port == 853 {
		return true
	}
	if _, err := netip.ParseAddr(target); err == nil {
		return false
	}
	for _, label := range strings.Split(target, ".") {
		if label == "dot" || label == "doh" || label == "dns" {
			return true
		}
	}
	return false
}

func (a *Sage) observeChurnClose(candidate string, metadata *C.Metadata, observation sageConnectionCloseObservation) {
	if a == nil || a.diagnostics == nil {
		return
	}
	reason := ""
	if metadata == nil || metadata.NetWork != C.TCP {
		reason = "non-tcp"
	} else if metadata.Type == C.INNER {
		reason = "internal-flow"
	}
	target, port, validTarget := sageChurnTarget(metadata)
	if reason == "" && !validTarget {
		reason = "invalid-target"
	}
	if reason == "" && sageChurnDNSBootstrap(target, port) {
		reason = "dns-bootstrap"
	}
	if reason != "" {
		a.diagnostics.record(sageDiagnosticRecord{kind: "churn-suppressed", reason: reason})
		return
	}

	now := a.clock.Now()
	key := sageChurnKey{target: target, port: port, candidate: candidate}
	// A data-carrying settlement is positive evidence for this exact pair and
	// resets prior tiny-close suspicion regardless of wrapper age or whether a
	// client payload write was visible. Check it before candidate-only gates.
	if observation.TotalReadBytes >= sageChurnMaxDownloadBytes {
		reset := false
		a.churnMu.Lock()
		if state := a.churn[key]; state != nil && len(state.stamps) > 0 {
			delete(a.churn, key)
			reset = true
		}
		a.churnMu.Unlock()
		if reset {
			a.diagnostics.record(sageDiagnosticRecord{kind: "churn-reset"})
		}
		return
	}

	if !observation.WrotePayload {
		reason = "no-positive-write"
	} else if observation.Age <= 0 || observation.Age >= sageChurnMaxLifetime {
		reason = "lifetime-outside-window"
	}
	if reason != "" {
		a.diagnostics.record(sageDiagnosticRecord{kind: "churn-suppressed", reason: reason})
		return
	}

	occurrences := 0
	a.churnMu.Lock()
	a.pruneChurnLocked(now)
	state := a.churn[key]
	if state == nil {
		if len(a.churn) >= sageChurnMaxStates {
			a.evictOldestChurnLocked()
		}
		state = &sageChurnState{}
		a.churn[key] = state
	}
	cutoff := now.Add(-sageChurnWindow)
	kept := state.stamps[:0]
	for _, stamp := range state.stamps {
		if stamp.After(cutoff) {
			kept = append(kept, stamp)
		}
	}
	state.stamps = append(kept, now)
	state.lastUpdated = now
	if len(state.stamps) >= sageChurnLimit {
		occurrences = len(state.stamps)
		state.stamps = state.stamps[:0]
	}
	a.churnMu.Unlock()

	a.diagnostics.record(sageDiagnosticRecord{kind: "churn-candidate"})
	if occurrences > 0 {
		a.diagnostics.record(sageDiagnosticRecord{
			kind:        "churn-suspected",
			target:      target,
			port:        port,
			from:        candidate,
			totalBytes:  observation.TotalReadBytes,
			age:         observation.Age,
			occurrences: occurrences,
			force:       true,
		})
	}
}

func (a *Sage) pruneChurnLocked(now time.Time) {
	cutoff := now.Add(-sageChurnWindow)
	for key, state := range a.churn {
		if state == nil || !state.lastUpdated.After(cutoff) {
			delete(a.churn, key)
		}
	}
}

func (a *Sage) evictOldestChurnLocked() {
	var oldestKey sageChurnKey
	var oldestState *sageChurnState
	found := false
	for key, state := range a.churn {
		if !found || churnStateOlder(key, state, oldestKey, oldestState) {
			oldestKey, oldestState, found = key, state, true
		}
	}
	if found {
		delete(a.churn, oldestKey)
	}
}

func churnStateOlder(leftKey sageChurnKey, left *sageChurnState, rightKey sageChurnKey, right *sageChurnState) bool {
	if left == nil || right == nil {
		return left == nil && right != nil
	}
	if !left.lastUpdated.Equal(right.lastUpdated) {
		return left.lastUpdated.Before(right.lastUpdated)
	}
	if leftKey.target != rightKey.target {
		return leftKey.target < rightKey.target
	}
	if leftKey.port != rightKey.port {
		return leftKey.port < rightKey.port
	}
	return leftKey.candidate < rightKey.candidate
}

func (a *Sage) activeChurnStates(now time.Time) int {
	cutoff := now.Add(-sageChurnWindow)
	a.churnMu.Lock()
	active := 0
	for _, state := range a.churn {
		if state != nil && len(state.stamps) > 0 && state.lastUpdated.After(cutoff) {
			active++
		}
	}
	a.churnMu.Unlock()
	return active
}
