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
	vaneChurnLimit            = 4
	vaneChurnWindow           = 5 * time.Minute
	vaneChurnMaxDownloadBytes = int64(1024)
	vaneChurnMaxLifetime      = 30 * time.Second
	vaneChurnMaxStates        = 4096
)

type vaneChurnKey struct {
	target    string
	port      uint16
	candidate string
}

type vaneChurnState struct {
	stamps      []time.Time
	lastUpdated time.Time
}

func vaneChurnTarget(metadata *C.Metadata) (string, uint16, bool) {
	if metadata == nil || metadata.DstPort == 0 {
		return "", 0, false
	}
	if host := metadata.RuleHost(); host != "" {
		normalized, valid := normalizeVaneDomain(host)
		return normalized, metadata.DstPort, valid
	}
	if metadata.DstIP.IsValid() {
		return metadata.DstIP.String(), metadata.DstPort, true
	}
	return "", metadata.DstPort, false
}

func vaneChurnDNSBootstrap(target string, port uint16) bool {
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

func (a *Vane) observeChurnClose(candidate string, metadata *C.Metadata, observation vaneConnectionCloseObservation) {
	if a == nil || a.diagnostics == nil {
		return
	}
	reason := ""
	if metadata == nil || metadata.NetWork != C.TCP {
		reason = "non-tcp"
	} else if metadata.Type == C.INNER {
		reason = "internal-flow"
	}
	target, port, validTarget := vaneChurnTarget(metadata)
	if reason == "" && !validTarget {
		reason = "invalid-target"
	}
	if reason == "" && vaneChurnDNSBootstrap(target, port) {
		reason = "dns-bootstrap"
	}
	if reason != "" {
		a.diagnostics.record(vaneDiagnosticRecord{kind: "churn-suppressed", reason: reason})
		return
	}

	now := a.clock.Now()
	key := vaneChurnKey{target: target, port: port, candidate: candidate}
	// A data-carrying settlement is positive evidence for this exact pair and
	// resets prior tiny-close suspicion regardless of wrapper age or whether a
	// client payload write was visible. Check it before candidate-only gates.
	if observation.TotalReadBytes >= vaneChurnMaxDownloadBytes {
		reset := false
		a.churnMu.Lock()
		if state := a.churn[key]; state != nil && len(state.stamps) > 0 {
			delete(a.churn, key)
			reset = true
		}
		a.churnMu.Unlock()
		if reset {
			a.diagnostics.record(vaneDiagnosticRecord{kind: "churn-reset"})
		}
		return
	}

	if !observation.WrotePayload {
		reason = "no-positive-write"
	} else if observation.Age <= 0 || observation.Age >= vaneChurnMaxLifetime {
		reason = "lifetime-outside-window"
	}
	if reason != "" {
		a.diagnostics.record(vaneDiagnosticRecord{kind: "churn-suppressed", reason: reason})
		return
	}

	occurrences := 0
	a.churnMu.Lock()
	a.pruneChurnLocked(now)
	state := a.churn[key]
	if state == nil {
		if len(a.churn) >= vaneChurnMaxStates {
			a.evictOldestChurnLocked()
		}
		state = &vaneChurnState{}
		a.churn[key] = state
	}
	cutoff := now.Add(-vaneChurnWindow)
	kept := state.stamps[:0]
	for _, stamp := range state.stamps {
		if stamp.After(cutoff) {
			kept = append(kept, stamp)
		}
	}
	state.stamps = append(kept, now)
	state.lastUpdated = now
	if len(state.stamps) >= vaneChurnLimit {
		occurrences = len(state.stamps)
		state.stamps = state.stamps[:0]
	}
	a.churnMu.Unlock()

	a.diagnostics.record(vaneDiagnosticRecord{kind: "churn-candidate"})
	if occurrences > 0 {
		a.diagnostics.record(vaneDiagnosticRecord{
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

func (a *Vane) pruneChurnLocked(now time.Time) {
	cutoff := now.Add(-vaneChurnWindow)
	for key, state := range a.churn {
		if state == nil || !state.lastUpdated.After(cutoff) {
			delete(a.churn, key)
		}
	}
}

func (a *Vane) evictOldestChurnLocked() {
	var oldestKey vaneChurnKey
	var oldestState *vaneChurnState
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

func churnStateOlder(leftKey vaneChurnKey, left *vaneChurnState, rightKey vaneChurnKey, right *vaneChurnState) bool {
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

func (a *Vane) activeChurnStates(now time.Time) int {
	cutoff := now.Add(-vaneChurnWindow)
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
