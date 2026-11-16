package outboundgroup

import (
	"bufio"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func testVaneNativeCollector(t *testing.T) *vaneNativeCollector {
	t.Helper()
	collector := &vaneNativeCollector{
		spec: vaneNativeCollectorSpec{
			directory: t.TempDir(), queueSize: 32, maxFileSize: 1 << 20,
			maxFileAge: time.Hour, flushInterval: 10 * time.Millisecond,
		},
		runID: "test-run", privacyKey: []byte("0123456789abcdef0123456789abcdef"), privacyKeyID: "test-key",
		control: make(chan vaneNativeEvent, 32), segment: make(chan vaneNativeEvent, 32),
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	go collector.run()
	t.Cleanup(func() {
		collector.stopOnce.Do(func() { close(collector.stop) })
		<-collector.done
	})
	return collector
}

func vaneNativeMetadata() *C.Metadata {
	return &C.Metadata{
		NetWork:   C.TCP,
		DstIP:     netip.MustParseAddr("1.1.1.1"),
		DstIPASN:  "AS13335 Cloudflare",
		DstPort:   443,
		Host:      "r1.googlevideo.com",
		SniffHost: ".googlevideo.com",
	}
}

func TestVaneNativeFeatureVectorIsStableAndIdentityFree(t *testing.T) {
	proxy := newVaneTestProxy("节点A", true, true)
	proxy.delay = 80
	features := prepareVaneNativeFeatures(vaneNativeMetadata(), proxy, "vane-main")
	require.Equal(t, [8]float64{0, 1, 6.095824562432225, 66, 464, 706, 190, float64(proxy.Type())}, features)

	replacement := newVaneTestProxy("另一个名字", true, true)
	replacement.identity = "replacement-config"
	replacement.delay = proxy.delay
	require.Equal(t, features, prepareVaneNativeFeatures(vaneNativeMetadata(), replacement, "vane-main"))
}

func readVaneNativeEvents(t *testing.T, directory string) []vaneNativeEvent {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(directory, "*.jsonl.ready"))
	require.NoError(t, err)
	require.Len(t, paths, 1)
	file, err := os.Open(paths[0])
	require.NoError(t, err)
	defer file.Close()
	var events []vaneNativeEvent
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event vaneNativeEvent
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &event))
		events = append(events, event)
	}
	require.NoError(t, scanner.Err())
	return events
}

func TestVaneNativeCollectorWritesLosslessClosedStream(t *testing.T) {
	collector := testVaneNativeCollector(t)
	proxy := newVaneTestProxy("display-name-must-not-leak", true, true)
	proxy.identity = "stable-identity-must-not-leak"
	vane, _ := newVaneGroupForTest(newVaneConnTestClock(), vaneDefaultMaxStates, vaneDefaultStateTTL, proxy)
	vane.collector = collector
	vane.testURL = C.DefaultTestURL
	now := time.Unix(1800000000, 0)
	attempt := vane.newNativeAttempt(vanePickDecision{proxy: proxy, identity: proxy.identity}, vaneNativeMetadata(), vaneTransportTCP, now)
	require.NotNil(t, attempt)
	attempt.setup(now.Add(40*time.Millisecond), 40*time.Millisecond, "returned", false)
	attempt.response(now.Add(70*time.Millisecond), 70*time.Millisecond)
	attempt.throughput(now.Add(3*time.Second), vaneThroughputObservation{BitsPerSecond: 2_000_000, Bytes: 750_000, Duration: 3 * time.Second, TotalBytes: 750_000}, "gap")
	attempt.outcome(now.Add(4*time.Second), "success", "dial_return", "none")
	attempt.end(now.Add(5*time.Second), "closed", vaneConnectionCloseObservation{WrotePayload: true, TotalReadBytes: 750_000, Age: 5 * time.Second})
	collector.stopOnce.Do(func() { close(collector.stop) })
	<-collector.done

	events := readVaneNativeEvents(t, collector.spec.directory)
	require.Len(t, events, 8) // header + six attempt events + footer
	require.Equal(t, "file_header", events[0].EventType)
	require.Equal(t, vaneNativeFeatureSchema, events[0].FeatureSchema)
	footer := events[len(events)-1]
	require.Equal(t, "file_footer", footer.EventType)
	require.Equal(t, uint64(6), footer.WrittenEvents)
	require.Zero(t, footer.DroppedControl)
	require.Zero(t, footer.DroppedSegment)
	require.Zero(t, footer.IncompleteAttempts)
	require.Equal(t, uint64(1), footer.FirstEventSeq)
	require.Equal(t, uint64(6), footer.LastEventSeq)

	seen := map[string]vaneNativeEvent{}
	for _, event := range events[1 : len(events)-1] {
		seen[event.EventType] = event
		require.Equal(t, vaneNativeSourceSchema, event.SourceSchema)
		require.Equal(t, vaneNativeFeatureSchema, event.FeatureSchema)
		require.NotEmpty(t, event.EventID)
		require.NotContains(t, event.NodeID, "stable-identity")
		require.NotContains(t, event.GroupID, "vane-main")
	}
	require.Equal(t, 40.0, seen["setup"].Value)
	require.Equal(t, 70.0, seen["response"].Value)
	require.Equal(t, 2_000_000.0, seen["throughput"].Value)
	require.Equal(t, "success", seen["outcome"].Outcome)
	payload, err := os.ReadFile(filepath.Join(collector.spec.directory, mustSingleNativeFile(t, collector.spec.directory)))
	require.NoError(t, err)
	require.NotContains(t, string(payload), "display-name-must-not-leak")
	require.NotContains(t, string(payload), "stable-identity-must-not-leak")
}

func mustSingleNativeFile(t *testing.T, directory string) string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	return entries[0].Name()
}

func TestVaneNativeCollectorDropAccountingIsNonBlocking(t *testing.T) {
	collector := &vaneNativeCollector{runID: "drop", control: make(chan vaneNativeEvent, 1), segment: make(chan vaneNativeEvent, 1), stop: make(chan struct{})}
	collector.nextEvent(vaneNativeEvent{EventType: "decision"}, false)
	collector.nextEvent(vaneNativeEvent{EventType: "setup"}, false)
	collector.nextEvent(vaneNativeEvent{EventType: "throughput"}, true)
	collector.nextEvent(vaneNativeEvent{EventType: "throughput"}, true)
	require.Equal(t, uint64(1), collector.droppedControl.Load())
	require.Equal(t, uint64(1), collector.droppedSegment.Load())
	require.Equal(t, uint64(4), collector.sequence.Load())
}

func TestVaneNativeCollectorReferencesDrainOnlyAfterLastOwner(t *testing.T) {
	collector := testVaneNativeCollector(t)
	collector.registryKey = t.Name()
	collector.references = 2
	vaneNativeCollectorRegistry.Lock()
	vaneNativeCollectorRegistry.entries[collector.registryKey] = collector
	vaneNativeCollectorRegistry.Unlock()
	releaseVaneNativeCollector(collector)
	require.False(t, collector.stopped)
	releaseVaneNativeCollector(collector)
	require.True(t, collector.stopped)
	vaneNativeCollectorRegistry.Lock()
	_, exists := vaneNativeCollectorRegistry.entries[collector.registryKey]
	vaneNativeCollectorRegistry.Unlock()
	require.False(t, exists)
}

func TestVaneNativeShutdownMarksIncompleteAttempts(t *testing.T) {
	collector := testVaneNativeCollector(t)
	require.True(t, collector.beginAttempt())
	collector.nextEvent(vaneNativeEvent{EventType: "decision"}, false)
	collector.stopOnce.Do(func() {
		collector.ingressMu.Lock()
		collector.stopped = true
		collector.incompleteAttempts.Store(collector.activeAttempts.Load())
		close(collector.stop)
		collector.ingressMu.Unlock()
	})
	require.False(t, collector.beginAttempt())
	collector.finishAttempt(vaneNativeEvent{EventType: "attempt_end"})
	<-collector.done
	events := readVaneNativeEvents(t, collector.spec.directory)
	footer := events[len(events)-1]
	require.Equal(t, int64(1), footer.IncompleteAttempts)
	require.Zero(t, footer.DroppedControl)
	require.Zero(t, collector.droppedControl.Load())
	require.Zero(t, collector.activeAttempts.Load())
}

func TestVaneNativeRecoveryNeverPromotesUnverifiableFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "vane-native-v1.run.1.1.jsonl.open")
	require.NoError(t, os.WriteFile(path, []byte("{\"complete\":true}\n{\"partial\":"), 0o600))
	require.NoError(t, recoverVaneNativeOpenFiles(directory))
	_, err := os.Stat(strings.TrimSuffix(path, ".open") + ".ready")
	require.ErrorIs(t, err, os.ErrNotExist)
	recovered := strings.TrimSuffix(path, ".open") + ".recovered"
	payload, err := os.ReadFile(recovered)
	require.NoError(t, err)
	require.Equal(t, "{\"complete\":true}\n", string(payload))
}

func TestVaneNativeCollectorConfigIsExplicit(t *testing.T) {
	spec, err := newVaneNativeCollectorSpec(false, "", 0, 0, 0, 0)
	require.NoError(t, err)
	require.Nil(t, spec)
	_, err = newVaneNativeCollectorSpec(false, t.TempDir(), 0, 0, 0, 0)
	require.ErrorContains(t, err, "collect-events")
	_, err = newVaneNativeCollectorSpec(true, "", -1, 0, 0, 0)
	require.ErrorContains(t, err, "queue-size")
	_, err = newVaneNativeCollectorSpec(true, "", 1, 1024, 0, 0)
	require.ErrorContains(t, err, "max-file-size")
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocked, []byte("x"), 0o600))
	_, err = acquireVaneNativeCollector(&vaneNativeCollectorSpec{directory: blocked, queueSize: 1, maxFileSize: 1 << 20, maxFileAge: time.Hour, flushInterval: time.Second})
	require.ErrorContains(t, err, "collector directory")
}
