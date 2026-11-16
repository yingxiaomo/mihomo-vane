package outboundgroup

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func testSageNativeCollector(t *testing.T) *sageNativeCollector {
	t.Helper()
	collector := &sageNativeCollector{
		spec: sageNativeCollectorSpec{
			directory: t.TempDir(), queueSize: 32, maxFileSize: 1 << 20,
			maxFileAge: time.Hour, flushInterval: 10 * time.Millisecond,
		},
		runID: "test-run", privacyKey: []byte("0123456789abcdef0123456789abcdef"), privacyKeyID: "test-key",
		control: make(chan sageNativeEvent, 32), segment: make(chan sageNativeEvent, 32),
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	go collector.run()
	t.Cleanup(func() {
		collector.stopOnce.Do(func() { close(collector.stop) })
		<-collector.done
	})
	return collector
}

func readSageNativeEvents(t *testing.T, directory string) []sageNativeEvent {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(directory, "*.jsonl.ready"))
	require.NoError(t, err)
	require.Len(t, paths, 1)
	file, err := os.Open(paths[0])
	require.NoError(t, err)
	defer file.Close()
	var events []sageNativeEvent
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event sageNativeEvent
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &event))
		events = append(events, event)
	}
	require.NoError(t, scanner.Err())
	return events
}

func TestSageNativeCollectorWritesLosslessClosedStream(t *testing.T) {
	collector := testSageNativeCollector(t)
	proxy := newSageTestProxy("display-name-must-not-leak", true, true)
	proxy.identity = "stable-identity-must-not-leak"
	sage, _ := newSageGroupForTest(newSageConnTestClock(), sageDefaultMaxStates, sageDefaultStateTTL, proxy)
	sage.collector = collector
	sage.testURL = C.DefaultTestURL
	now := time.Unix(1800000000, 0)
	attempt := sage.newNativeAttempt(sagePickDecision{proxy: proxy, identity: proxy.identity}, sagePriorMetadata(), sageTransportTCP, now)
	require.NotNil(t, attempt)
	attempt.setup(now.Add(40*time.Millisecond), 40*time.Millisecond, "returned", false)
	attempt.response(now.Add(70*time.Millisecond), 70*time.Millisecond)
	attempt.throughput(now.Add(3*time.Second), sageThroughputObservation{BitsPerSecond: 2_000_000, Bytes: 750_000, Duration: 3 * time.Second, TotalBytes: 750_000}, "gap")
	attempt.outcome(now.Add(4*time.Second), "success", "dial_return", "none")
	attempt.end(now.Add(5*time.Second), "closed", sageConnectionCloseObservation{WrotePayload: true, TotalReadBytes: 750_000, Age: 5 * time.Second})
	collector.stopOnce.Do(func() { close(collector.stop) })
	<-collector.done

	events := readSageNativeEvents(t, collector.spec.directory)
	require.Len(t, events, 8) // header + six attempt events + footer
	require.Equal(t, "file_header", events[0].EventType)
	require.Equal(t, sageNativeFeatureSchema, events[0].FeatureSchema)
	footer := events[len(events)-1]
	require.Equal(t, "file_footer", footer.EventType)
	require.Equal(t, uint64(6), footer.WrittenEvents)
	require.Zero(t, footer.DroppedControl)
	require.Zero(t, footer.DroppedSegment)
	require.Zero(t, footer.IncompleteAttempts)
	require.Equal(t, uint64(1), footer.FirstEventSeq)
	require.Equal(t, uint64(6), footer.LastEventSeq)

	seen := map[string]sageNativeEvent{}
	for _, event := range events[1 : len(events)-1] {
		seen[event.EventType] = event
		require.Equal(t, sageNativeSourceSchema, event.SourceSchema)
		require.Equal(t, sageNativeFeatureSchema, event.FeatureSchema)
		require.NotEmpty(t, event.EventID)
		require.NotContains(t, event.NodeID, "stable-identity")
		require.NotContains(t, event.GroupID, "sage-main")
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

func TestSageNativeCollectorDropAccountingIsNonBlocking(t *testing.T) {
	collector := &sageNativeCollector{runID: "drop", control: make(chan sageNativeEvent, 1), segment: make(chan sageNativeEvent, 1), stop: make(chan struct{})}
	collector.nextEvent(sageNativeEvent{EventType: "decision"}, false)
	collector.nextEvent(sageNativeEvent{EventType: "setup"}, false)
	collector.nextEvent(sageNativeEvent{EventType: "throughput"}, true)
	collector.nextEvent(sageNativeEvent{EventType: "throughput"}, true)
	require.Equal(t, uint64(1), collector.droppedControl.Load())
	require.Equal(t, uint64(1), collector.droppedSegment.Load())
	require.Equal(t, uint64(4), collector.sequence.Load())
}

func TestSageNativeCollectorReferencesDrainOnlyAfterLastOwner(t *testing.T) {
	collector := testSageNativeCollector(t)
	collector.registryKey = t.Name()
	collector.references = 2
	sageNativeCollectorRegistry.Lock()
	sageNativeCollectorRegistry.entries[collector.registryKey] = collector
	sageNativeCollectorRegistry.Unlock()
	releaseSageNativeCollector(collector)
	require.False(t, collector.stopped)
	releaseSageNativeCollector(collector)
	require.True(t, collector.stopped)
	sageNativeCollectorRegistry.Lock()
	_, exists := sageNativeCollectorRegistry.entries[collector.registryKey]
	sageNativeCollectorRegistry.Unlock()
	require.False(t, exists)
}

func TestSageNativeShutdownMarksIncompleteAttempts(t *testing.T) {
	collector := testSageNativeCollector(t)
	require.True(t, collector.beginAttempt())
	collector.nextEvent(sageNativeEvent{EventType: "decision"}, false)
	collector.stopOnce.Do(func() {
		collector.ingressMu.Lock()
		collector.stopped = true
		collector.incompleteAttempts.Store(collector.activeAttempts.Load())
		close(collector.stop)
		collector.ingressMu.Unlock()
	})
	require.False(t, collector.beginAttempt())
	collector.finishAttempt(sageNativeEvent{EventType: "attempt_end"})
	<-collector.done
	events := readSageNativeEvents(t, collector.spec.directory)
	footer := events[len(events)-1]
	require.Equal(t, int64(1), footer.IncompleteAttempts)
	require.Zero(t, footer.DroppedControl)
	require.Zero(t, collector.droppedControl.Load())
	require.Zero(t, collector.activeAttempts.Load())
}

func TestSageNativeRecoveryNeverPromotesUnverifiableFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "sage-native-v1.run.1.1.jsonl.open")
	require.NoError(t, os.WriteFile(path, []byte("{\"complete\":true}\n{\"partial\":"), 0o600))
	require.NoError(t, recoverSageNativeOpenFiles(directory))
	_, err := os.Stat(strings.TrimSuffix(path, ".open") + ".ready")
	require.ErrorIs(t, err, os.ErrNotExist)
	recovered := strings.TrimSuffix(path, ".open") + ".recovered"
	payload, err := os.ReadFile(recovered)
	require.NoError(t, err)
	require.Equal(t, "{\"complete\":true}\n", string(payload))
}

func TestSageNativeCollectorConfigIsExplicit(t *testing.T) {
	spec, err := newSageNativeCollectorSpec(false, "", 0, 0, 0, 0)
	require.NoError(t, err)
	require.Nil(t, spec)
	_, err = newSageNativeCollectorSpec(false, t.TempDir(), 0, 0, 0, 0)
	require.ErrorContains(t, err, "collect-events")
	_, err = newSageNativeCollectorSpec(true, "", -1, 0, 0, 0)
	require.ErrorContains(t, err, "queue-size")
	_, err = newSageNativeCollectorSpec(true, "", 1, 1024, 0, 0)
	require.ErrorContains(t, err, "max-file-size")
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocked, []byte("x"), 0o600))
	_, err = acquireSageNativeCollector(&sageNativeCollectorSpec{directory: blocked, queueSize: 1, maxFileSize: 1 << 20, maxFileAge: time.Hour, flushInterval: time.Second})
	require.ErrorContains(t, err, "collector directory")
}

// This opt-in test writes a production-format fixture for the cross-language
// trainer/Go-loader interoperability gate.
func TestSageNativeGenerateTrainingFixture(t *testing.T) {
	directory := os.Getenv("SAGE_NATIVE_FIXTURE_DIR")
	if directory == "" {
		t.Skip("SAGE_NATIVE_FIXTURE_DIR is not set")
	}
	require.NoError(t, os.MkdirAll(directory, 0o700))
	collector := &sageNativeCollector{
		spec:  sageNativeCollectorSpec{directory: directory, queueSize: 4096, maxFileSize: 64 << 20, maxFileAge: time.Hour, flushInterval: 10 * time.Millisecond},
		runID: "native-e2e", privacyKey: []byte("0123456789abcdef0123456789abcdef"), privacyKeyID: "e2e-key",
		control: make(chan sageNativeEvent, 4096), segment: make(chan sageNativeEvent, 4096), stop: make(chan struct{}), done: make(chan struct{}),
	}
	go collector.run()
	proxy := newSageTestProxy("fixture-node", true, true)
	proxy.identity = "fixture-stable-node"
	sage, _ := newSageGroupForTest(newSageConnTestClock(), sageDefaultMaxStates, sageDefaultStateTTL, proxy)
	sage.collector = collector
	base := time.Unix(1_800_000_000, 0)
	for index := 0; index < 180; index++ {
		metadata := sagePriorMetadata()
		metadata.Host = fmt.Sprintf("cdn%d.example.com", index%17)
		metadata.DstIPASN = fmt.Sprintf("AS%d fixture", 1000+index%13)
		metadata.DstPort = uint16(400 + index%200)
		now := base.Add(time.Duration(index) * 10 * time.Second)
		attempt := sage.newNativeAttempt(sagePickDecision{proxy: proxy, identity: proxy.identity}, metadata, sageTransportTCP, now)
		connect := time.Duration(40+(index%17)*10) * time.Millisecond
		response := time.Duration(65+(index%17)*15) * time.Millisecond
		attempt.setup(now.Add(connect), connect, "returned", false)
		attempt.response(now.Add(response), response)
		attempt.throughput(now.Add(3*time.Second), sageThroughputObservation{BitsPerSecond: 1_000_000 + float64(index%17)*100_000, Bytes: 300_000, Duration: 2500 * time.Millisecond, TotalBytes: 300_000}, "window")
		attempt.throughput(now.Add(6*time.Second), sageThroughputObservation{BitsPerSecond: 1_100_000 + float64(index%17)*100_000, Bytes: 350_000, Duration: 2600 * time.Millisecond, TotalBytes: 650_000}, "window")
		if index%17 >= 14 {
			attempt.outcome(now.Add(7*time.Second), "failure", "fixture", "other")
		} else {
			attempt.outcome(now.Add(7*time.Second), "success", "fixture", "none")
		}
		attempt.end(now.Add(8*time.Second), "closed", sageConnectionCloseObservation{WrotePayload: true, TotalReadBytes: 650_000, Age: 8 * time.Second})
	}
	collector.stopOnce.Do(func() { close(collector.stop) })
	<-collector.done
	paths, err := filepath.Glob(filepath.Join(directory, "*.jsonl.ready"))
	require.NoError(t, err)
	require.NotEmpty(t, paths)
}
