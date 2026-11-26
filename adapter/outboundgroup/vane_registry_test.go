package outboundgroup

import (
	"fmt"
	"testing"
	"time"

	"github.com/metacubex/mihomo/log"
	"github.com/stretchr/testify/require"
)

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

	var nilDiagnostics *vaneDiagnostics
	require.Empty(t, nilDiagnostics.snapshot().Group)
}
