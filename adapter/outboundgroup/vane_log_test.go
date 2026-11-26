package outboundgroup

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/log"
	"github.com/stretchr/testify/require"
)

// uniqueVaneLogTarget gives each case its own target, so a [vane] line from a
// concurrent test can never be counted as ours: the log is process-global.
func uniqueVaneLogTarget(t *testing.T, name string) string {
	t.Helper()
	return fmt.Sprintf("%s-%d.googlevideo.com", name, time.Now().UnixNano())
}

func collectVaneLogs(t *testing.T, sub <-chan log.Event, target string, wait time.Duration) []log.Event {
	t.Helper()
	var events []log.Event
	deadline := time.After(wait)
	for {
		select {
		case event := <-sub:
			if strings.Contains(event.Payload, "[vane]") && strings.Contains(event.Payload, "target="+target) {
				events = append(events, event)
			}
		case <-deadline:
			return events
		}
	}
}

// LOG-VANE-TAG-01: a suppression travels as one Info line with a fixed field
// order, so `grep '[vane]'` answers "why did it not switch".
func TestVaneLogTag(t *testing.T) {
	clock := newVaneConnTestClock()
	diagnostics := newVaneDiagnostics("log-test", clock)
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)
	target := uniqueVaneLogTarget(t, "rr")

	diagnostics.record(vaneDiagnosticRecord{
		kind: "reconnect-suppressed", target: target, port: 443,
		from: "alpha", reason: "no-evidence-candidate", bps: 4_000_000,
		lowWindows: 3, lowSignal: "latency", latencyMillis: 800,
	})

	events := collectVaneLogs(t, sub, target, 300*time.Millisecond)
	require.Len(t, events, 1)
	require.Equal(t, log.INFO, events[0].LogLevel)
	line := events[0].Payload
	for _, want := range []string{
		"[vane]", "kind=reconnect-suppressed", "target=" + target, "port=443",
		"from=alpha", "bps=4000000", "reason=no-evidence-candidate",
		"signal=latency", "latencyMs=800", "lowWindows=3",
	} {
		require.Contains(t, line, want)
	}
}

// LOG-VANE-TAG-02: a committed handoff logs from and to.
func TestVaneLogTagHandoff(t *testing.T) {
	clock := newVaneConnTestClock()
	diagnostics := newVaneDiagnostics("log-test", clock)
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)
	target := uniqueVaneLogTarget(t, "rr-handoff")

	diagnostics.record(vaneDiagnosticRecord{
		kind: "handoff-measured", target: target, from: "alpha", to: "beta", bps: 15_000_000,
	})
	events := collectVaneLogs(t, sub, target, 300*time.Millisecond)
	require.Len(t, events, 1)
	require.Contains(t, events[0].Payload, "from=alpha")
	require.Contains(t, events[0].Payload, "to=beta")
}

// LOG-DEDUP-01: same (kind,target,reason) collapses within the window, but a
// different reason on the same target still shows up — that pair is exactly
// how "why not switched" is diagnosed.
func TestVaneLogDedup(t *testing.T) {
	clock := newVaneConnTestClock()
	diagnostics := newVaneDiagnostics("log-test", clock)
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)
	target := uniqueVaneLogTarget(t, "rr-dedup")

	base := vaneDiagnosticRecord{kind: "reconnect-suppressed", target: target, bps: 1}
	first := base
	first.reason = "no-challenger"
	second := base
	second.reason = "no-evidence-candidate"

	diagnostics.record(first)
	diagnostics.record(first)
	clock.Advance(time.Second)
	diagnostics.record(second)

	events := collectVaneLogs(t, sub, target, 300*time.Millisecond)
	require.Len(t, events, 2)
	require.Contains(t, events[0].Payload, "reason=no-challenger")
	require.Contains(t, events[1].Payload, "reason=no-evidence-candidate")

	// Past the window the same triple logs again.
	clock.Advance(vaneLogDedupWindow + time.Second)
	diagnostics.record(first)
	events = collectVaneLogs(t, sub, target, 300*time.Millisecond)
	require.Len(t, events, 1)
	require.Contains(t, events[0].Payload, "reason=no-challenger")
}

// LOG-COUNTERS-01: the counters stay readable from the API even though the
// event itself only goes to the log.
func TestVaneLogCountersStay(t *testing.T) {
	clock := newVaneConnTestClock()
	diagnostics := newVaneDiagnostics("log-test", clock)
	diagnostics.record(vaneDiagnosticRecord{kind: "handoff-committed"})
	diagnostics.record(vaneDiagnosticRecord{kind: "handoff-improved"})
	snapshot := diagnostics.snapshot()
	require.Equal(t, uint64(1), snapshot.Counters.HandoffCommitted)
	require.Equal(t, uint64(1), snapshot.Counters.HandoffImproved)
	require.Zero(t, snapshot.Counters.PickProbeCount, "the cold-pick probe is gone, so the counter never moves")
}
