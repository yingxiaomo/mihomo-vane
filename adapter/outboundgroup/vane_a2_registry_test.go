package outboundgroup

import (
	"fmt"
	"testing"
	"time"

	"github.com/metacubex/mihomo/log"
	"github.com/stretchr/testify/require"
)

// The registry keeps counters alive across a reload; at capacity it must evict
// the least recently used entry without touching persistence.
func TestVaneDiagnosticsRegistryEvictsOldest(t *testing.T) {
	vaneDiagnosticsRegistry.Lock()
	previous := vaneDiagnosticsRegistry.entries
	vaneDiagnosticsRegistry.entries = make(map[string]*vaneDiagnostics)
	vaneDiagnosticsRegistry.Unlock()
	t.Cleanup(func() {
		vaneDiagnosticsRegistry.Lock()
		vaneDiagnosticsRegistry.entries = previous
		vaneDiagnosticsRegistry.Unlock()
	})

	clock := newVaneConnTestClock()
	for index := 0; index <= vaneDiagnosticsRegistryLimit; index++ {
		key := fmt.Sprintf("group-%03d", index)
		vaneDiagnosticsRegistry.Lock()
		vaneDiagnosticsRegistry.addLocked(key, newVaneDiagnostics(key, clock))
		vaneDiagnosticsRegistry.Unlock()
	}
	vaneDiagnosticsRegistry.Lock()
	count := len(vaneDiagnosticsRegistry.entries)
	_, oldestKept := vaneDiagnosticsRegistry.entries["group-000"]
	newest := vaneDiagnosticsRegistry.entries[fmt.Sprintf("group-%03d", vaneDiagnosticsRegistryLimit)]
	vaneDiagnosticsRegistry.Unlock()
	require.Equal(t, vaneDiagnosticsRegistryLimit, count)
	require.False(t, oldestKept)
	require.NotNil(t, newest)
}

// The dedupe map is bounded: a long run of distinct keys must reset it instead
// of growing without limit.
func TestVaneLogDedupeMapResets(t *testing.T) {
	level := log.Level()
	log.SetLevel(log.SILENT)
	t.Cleanup(func() { log.SetLevel(level) })

	clock := newVaneConnTestClock()
	diagnostics := newVaneDiagnostics("dedupe-reset", clock)
	for index := 0; index < 600; index++ {
		diagnostics.record(vaneDiagnosticRecord{
			kind: "reconnect-suppressed", target: fmt.Sprintf("rr-%03d.googlevideo.com", index),
			reason: "no-challenger",
		})
		clock.Advance(time.Millisecond)
	}
	diagnostics.mu.Lock()
	size := len(diagnostics.logDedupe)
	diagnostics.mu.Unlock()
	require.LessOrEqual(t, size, 512)
}

// After a reload the retired instance forwards to the live one, so counters
// written by flows that still hold the old pointer are not lost.
func TestVaneDiagnosticsActiveRedirectsAfterReload(t *testing.T) {
	clock := newVaneConnTestClock()
	key := vaneDiagnosticsRegistryKey("reload")
	old := newVaneDiagnostics("reload", clock)
	old.detached = true
	live := newVaneDiagnostics("reload", clock)

	vaneDiagnosticsRegistry.Lock()
	previous, had := vaneDiagnosticsRegistry.entries[key]
	vaneDiagnosticsRegistry.entries[key] = live
	vaneDiagnosticsRegistry.current.Store(key, live)
	vaneDiagnosticsRegistry.Unlock()
	t.Cleanup(func() {
		vaneDiagnosticsRegistry.Lock()
		vaneDiagnosticsRegistry.current.Delete(key)
		if had {
			vaneDiagnosticsRegistry.entries[key] = previous
		} else {
			delete(vaneDiagnosticsRegistry.entries, key)
		}
		vaneDiagnosticsRegistry.Unlock()
	})

	require.Same(t, live, old.active())
	old.record(vaneDiagnosticRecord{kind: "handoff-committed"})
	require.Equal(t, uint64(1), live.snapshot().Counters.HandoffCommitted)

	var nilDiagnostics *vaneDiagnostics
	require.Empty(t, nilDiagnostics.snapshot().Group)
	require.Nil(t, nilDiagnostics.active())
}

