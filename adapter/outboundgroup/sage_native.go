package outboundgroup

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

const (
	sageNativeSourceSchema  = "sage-native-events-v1"
	sageNativeFeatureSchema = "sage-prior-native-features-v1"

	sageNativeDefaultQueueSize   = 4096
	sageNativeDefaultMaxFileSize = int64(64 << 20)
	sageNativeDefaultMaxFileAge  = time.Hour
	sageNativeDefaultFlush       = time.Second
	sageNativeMaximumQueueSize   = 1 << 20
	sageNativeMaximumFileSize    = int64(4 << 30)
)

type sageNativeCollectorSpec struct {
	directory     string
	queueSize     int
	maxFileSize   int64
	maxFileAge    time.Duration
	flushInterval time.Duration
}

type sageNativeEvent struct {
	SourceSchema       string     `json:"source_schema"`
	FeatureSchema      string     `json:"feature_schema,omitempty"`
	RunID              string     `json:"run_id"`
	EventSeq           uint64     `json:"event_seq"`
	EventID            string     `json:"event_id"`
	EventType          string     `json:"event_type"`
	ObservedUnixNano   int64      `json:"observed_unix_nano"`
	AttemptID          string     `json:"attempt_id,omitempty"`
	DecisionUnixNano   int64      `json:"decision_unix_nano,omitempty"`
	GroupID            string     `json:"group_id,omitempty"`
	NodeID             string     `json:"node_id,omitempty"`
	NodeIDStable       bool       `json:"node_id_stable,omitempty"`
	Transport          string     `json:"transport,omitempty"`
	Scene              string     `json:"scene,omitempty"`
	Features           [8]float64 `json:"features,omitempty"`
	Exploration        bool       `json:"exploration,omitempty"`
	Handoff            bool       `json:"handoff,omitempty"`
	SetupStatus        string     `json:"setup_status,omitempty"`
	Deferred           bool       `json:"deferred_availability,omitempty"`
	Outcome            string     `json:"outcome,omitempty"`
	Boundary           string     `json:"boundary,omitempty"`
	ErrorClass         string     `json:"error_class,omitempty"`
	Metric             string     `json:"metric,omitempty"`
	Value              float64    `json:"value,omitempty"`
	ElapsedNano        int64      `json:"elapsed_nano,omitempty"`
	Bytes              int64      `json:"bytes,omitempty"`
	TotalBytes         int64      `json:"total_bytes,omitempty"`
	SegmentIndex       uint64     `json:"segment_index,omitempty"`
	EndReason          string     `json:"end_reason,omitempty"`
	WrotePayload       bool       `json:"wrote_payload,omitempty"`
	DroppedControl     uint64     `json:"dropped_control,omitempty"`
	DroppedSegment     uint64     `json:"dropped_segment,omitempty"`
	IncompleteAttempts int64      `json:"incomplete_attempts,omitempty"`
	WrittenEvents      uint64     `json:"written_events,omitempty"`
	FirstEventSeq      uint64     `json:"first_event_seq,omitempty"`
	LastEventSeq       uint64     `json:"last_event_seq,omitempty"`
	PrivacyKeyID       string     `json:"privacy_key_id,omitempty"`
}

type sageNativeCollector struct {
	spec sageNativeCollectorSpec

	runID        string
	privacyKey   []byte
	privacyKeyID string
	registryKey  string
	references   int

	sequence           atomic.Uint64
	attempts           atomic.Uint64
	activeAttempts     atomic.Int64
	incompleteAttempts atomic.Int64
	droppedControl     atomic.Uint64
	droppedSegment     atomic.Uint64

	control   chan sageNativeEvent
	segment   chan sageNativeEvent
	stop      chan struct{}
	done      chan struct{}
	started   chan error
	stopOnce  sync.Once
	ingressMu sync.RWMutex
	stopped   bool
}

var sageNativeCollectorRegistry = struct {
	sync.Mutex
	entries map[string]*sageNativeCollector
}{entries: make(map[string]*sageNativeCollector)}

var sageNativeCollectorAcquireMu sync.Mutex

func newSageNativeCollectorSpec(enabled bool, directory string, queueSize int, maxFileSize int64, maxFileAgeSeconds, flushSeconds int) (*sageNativeCollectorSpec, error) {
	if !enabled {
		if directory != "" || queueSize != 0 || maxFileSize != 0 || maxFileAgeSeconds != 0 || flushSeconds != 0 {
			return nil, errors.New("sage collector options require collect-events: true")
		}
		return nil, nil
	}
	if directory == "" {
		directory = filepath.Join(C.Path.HomeDir(), "sage-events")
	} else {
		directory = C.Path.Resolve(directory)
	}
	if !C.Path.IsSafePath(directory) {
		return nil, C.Path.ErrNotSafePath(directory)
	}
	if queueSize == 0 {
		queueSize = sageNativeDefaultQueueSize
	}
	if queueSize < 1 || queueSize > sageNativeMaximumQueueSize {
		return nil, fmt.Errorf("collector-queue-size must be between 1 and %d", sageNativeMaximumQueueSize)
	}
	if maxFileSize == 0 {
		maxFileSize = sageNativeDefaultMaxFileSize
	}
	if maxFileSize < 1<<20 || maxFileSize > sageNativeMaximumFileSize {
		return nil, fmt.Errorf("collector-max-file-size must be between %d and %d", 1<<20, sageNativeMaximumFileSize)
	}
	maxFileAge := sageNativeDefaultMaxFileAge
	if maxFileAgeSeconds != 0 {
		if maxFileAgeSeconds < 1 || maxFileAgeSeconds > sageMaximumConfigSeconds {
			return nil, fmt.Errorf("collector-max-file-age must be between 1 and %d", sageMaximumConfigSeconds)
		}
		maxFileAge = time.Duration(maxFileAgeSeconds) * time.Second
	}
	flushInterval := sageNativeDefaultFlush
	if flushSeconds != 0 {
		if flushSeconds < 1 || flushSeconds > 300 {
			return nil, errors.New("collector-flush-interval must be between 1 and 300")
		}
		flushInterval = time.Duration(flushSeconds) * time.Second
	}
	return &sageNativeCollectorSpec{
		directory: filepath.Clean(directory), queueSize: queueSize,
		maxFileSize: maxFileSize, maxFileAge: maxFileAge, flushInterval: flushInterval,
	}, nil
}

func (s *sageNativeCollectorSpec) key() string {
	if s == nil {
		return ""
	}
	return fmt.Sprintf("%s\x00%d\x00%d\x00%d\x00%d", s.directory, s.queueSize, s.maxFileSize, s.maxFileAge, s.flushInterval)
}

func acquireSageNativeCollector(spec *sageNativeCollectorSpec) (*sageNativeCollector, error) {
	if spec == nil {
		return nil, nil
	}
	sageNativeCollectorAcquireMu.Lock()
	defer sageNativeCollectorAcquireMu.Unlock()
	key := spec.key()
	sageNativeCollectorRegistry.Lock()
	if existing := sageNativeCollectorRegistry.entries[key]; existing != nil {
		existing.references++
		sageNativeCollectorRegistry.Unlock()
		return existing, nil
	}
	sageNativeCollectorRegistry.Unlock()
	digest := sha256.Sum256([]byte(key))
	ownedSpec := *spec
	ownedSpec.directory = filepath.Join(spec.directory, "g-"+hex.EncodeToString(digest[:6]))
	if err := os.MkdirAll(ownedSpec.directory, 0o700); err != nil {
		return nil, fmt.Errorf("create collector directory: %w", err)
	}
	privacyKey, privacyKeyID, err := sageNativePrivacyKey()
	if err != nil {
		return nil, fmt.Errorf("load privacy key: %w", err)
	}
	if err := recoverSageNativeOpenFiles(ownedSpec.directory); err != nil {
		return nil, fmt.Errorf("recover collector files: %w", err)
	}
	collector := &sageNativeCollector{
		spec:         ownedSpec,
		runID:        sageNativeRandomID(16),
		privacyKey:   privacyKey,
		privacyKeyID: privacyKeyID,
		registryKey:  key,
		references:   1,
		control:      make(chan sageNativeEvent, spec.queueSize),
		segment:      make(chan sageNativeEvent, spec.queueSize),
		stop:         make(chan struct{}), done: make(chan struct{}), started: make(chan error, 1),
	}
	go collector.run()
	if err := <-collector.started; err != nil {
		return nil, err
	}
	sageNativeCollectorRegistry.Lock()
	sageNativeCollectorRegistry.entries[key] = collector
	sageNativeCollectorRegistry.Unlock()
	return collector, nil
}

func releaseSageNativeCollector(collector *sageNativeCollector) {
	if collector == nil {
		return
	}
	sageNativeCollectorRegistry.Lock()
	current := sageNativeCollectorRegistry.entries[collector.registryKey]
	if current != collector || collector.references < 1 {
		sageNativeCollectorRegistry.Unlock()
		return
	}
	collector.references--
	if collector.references != 0 {
		sageNativeCollectorRegistry.Unlock()
		return
	}
	delete(sageNativeCollectorRegistry.entries, collector.registryKey)
	sageNativeCollectorRegistry.Unlock()
	collector.stopOnce.Do(func() {
		collector.ingressMu.Lock()
		collector.stopped = true
		collector.incompleteAttempts.Store(collector.activeAttempts.Load())
		close(collector.stop)
		collector.ingressMu.Unlock()
	})
	<-collector.done
}

func sageNativeRandomID(size int) string {
	payload := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, payload); err != nil {
		digest := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
		payload = digest[:size]
	}
	return hex.EncodeToString(payload)
}

func (c *sageNativeCollector) nextEvent(event sageNativeEvent, segment bool) {
	if c == nil {
		return
	}
	c.ingressMu.RLock()
	defer c.ingressMu.RUnlock()
	c.nextEventLocked(event, segment)
}

func (c *sageNativeCollector) nextEventLocked(event sageNativeEvent, segment bool) {
	if c.stopped {
		// The completeness snapshot is immutable after stop. Attempts alive at
		// the shutdown fence are represented by incomplete_attempts; callbacks
		// after a terminal attempt are outside this collection interval.
		return
	}
	event.SourceSchema = sageNativeSourceSchema
	event.RunID = c.runID
	event.EventSeq = c.sequence.Add(1)
	event.EventID = fmt.Sprintf("%s:%d", c.runID, event.EventSeq)
	queue := c.control
	if segment {
		queue = c.segment
	}
	select {
	case queue <- event:
	default:
		if segment {
			c.droppedSegment.Add(1)
		} else {
			c.droppedControl.Add(1)
		}
	}
}

func (c *sageNativeCollector) beginAttempt() bool {
	if c == nil {
		return false
	}
	c.ingressMu.RLock()
	defer c.ingressMu.RUnlock()
	if c.stopped {
		return false
	}
	c.activeAttempts.Add(1)
	return true
}

func (c *sageNativeCollector) finishAttempt(event sageNativeEvent) {
	if c == nil {
		return
	}
	c.ingressMu.RLock()
	defer c.ingressMu.RUnlock()
	c.nextEventLocked(event, false)
	c.activeAttempts.Add(-1)
}

func (c *sageNativeCollector) token(domain, value string) string {
	if c == nil || len(c.privacyKey) == 0 || value == "" {
		return ""
	}
	mac := hmac.New(sha256.New, c.privacyKey)
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func (c *sageNativeCollector) run() {
	defer close(c.done)
	signalStarted := func(err error) {
		if c.started != nil {
			c.started <- err
			close(c.started)
		}
	}
	var file *os.File
	var writer *bufio.Writer
	var path string
	var openedAt time.Time
	var bytesWritten int64
	var firstSeq, lastSeq uint64
	var fileEvents uint64
	var fileFailed bool
	index := uint64(0)
	dropEvent := func(event sageNativeEvent) {
		if event.EventType == "throughput" {
			c.droppedSegment.Add(1)
		} else {
			c.droppedControl.Add(1)
		}
	}

	closeFile := func() {
		if file == nil {
			return
		}
		footer := sageNativeEvent{
			SourceSchema: sageNativeSourceSchema, RunID: c.runID,
			EventType: "file_footer", ObservedUnixNano: time.Now().UnixNano(),
			WrittenEvents: fileEvents, DroppedControl: c.droppedControl.Load(),
			DroppedSegment: c.droppedSegment.Load(), FirstEventSeq: firstSeq,
			LastEventSeq: lastSeq, PrivacyKeyID: c.privacyKeyID,
			IncompleteAttempts: c.incompleteAttempts.Load(),
		}
		payload, marshalErr := json.Marshal(footer)
		if marshalErr != nil {
			fileFailed = true
		} else if _, writeErr := writer.Write(append(payload, '\n')); writeErr != nil {
			fileFailed = true
		}
		if flushErr := writer.Flush(); flushErr != nil {
			fileFailed = true
		}
		if syncErr := file.Sync(); syncErr != nil {
			fileFailed = true
		}
		if closeErr := file.Close(); closeErr != nil {
			fileFailed = true
		}
		targetSuffix := ".ready"
		if fileFailed {
			targetSuffix = ".failed"
		}
		target := strings.TrimSuffix(path, ".open") + targetSuffix
		if renameErr := os.Rename(path, target); renameErr != nil {
			fileFailed = true
		}
		file, writer, path = nil, nil, ""
		bytesWritten, firstSeq, lastSeq, fileEvents, fileFailed = 0, 0, 0, 0, false
	}
	openFile := func(now time.Time) error {
		index++
		name := fmt.Sprintf("sage-native-v1.%s.%d.%d.jsonl.open", c.runID, now.Unix(), index)
		path = filepath.Join(c.spec.directory, name)
		opened, openErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if openErr != nil {
			return openErr
		}
		file = opened
		writer = bufio.NewWriterSize(file, 256<<10)
		openedAt = now
		header := sageNativeEvent{
			SourceSchema: sageNativeSourceSchema, FeatureSchema: sageNativeFeatureSchema,
			RunID: c.runID, EventType: "file_header", ObservedUnixNano: now.UnixNano(),
			PrivacyKeyID: c.privacyKeyID,
		}
		payload, _ := json.Marshal(header)
		written, writeErr := writer.Write(append(payload, '\n'))
		bytesWritten = int64(written)
		if writeErr != nil {
			fileFailed = true
		}
		return writeErr
	}
	writeEvent := func(event sageNativeEvent) {
		now := time.Now()
		if file == nil {
			if err := openFile(now); err != nil {
				log.Errorln("Sage native collector cannot open output: %s", err.Error())
				dropEvent(event)
				return
			}
		}
		payload, err := json.Marshal(event)
		if err != nil {
			dropEvent(event)
			return
		}
		if bytesWritten+int64(len(payload)+1) > c.spec.maxFileSize || now.Sub(openedAt) >= c.spec.maxFileAge {
			closeFile()
			if err := openFile(now); err != nil {
				log.Errorln("Sage native collector cannot rotate output: %s", err.Error())
				dropEvent(event)
				return
			}
		}
		written, err := writer.Write(append(payload, '\n'))
		if err != nil {
			if !fileFailed {
				log.Errorln("Sage native collector write failed: %s", err.Error())
			}
			fileFailed = true
			dropEvent(event)
			return
		}
		bytesWritten += int64(written)
		if firstSeq == 0 || event.EventSeq < firstSeq {
			firstSeq = event.EventSeq
		}
		if event.EventSeq > lastSeq {
			lastSeq = event.EventSeq
		}
		fileEvents++
	}
	if err := openFile(time.Now()); err != nil {
		signalStarted(fmt.Errorf("open collector output: %w", err))
		return
	}
	if err := writer.Flush(); err != nil {
		fileFailed = true
		closeFile()
		signalStarted(fmt.Errorf("flush collector header: %w", err))
		return
	}
	if err := file.Sync(); err != nil {
		fileFailed = true
		closeFile()
		signalStarted(fmt.Errorf("sync collector header: %w", err))
		return
	}
	signalStarted(nil)

	ticker := time.NewTicker(c.spec.flushInterval)
	defer ticker.Stop()
	for {
		// Prefer lifecycle/control events without starving segment events.
		select {
		case event := <-c.control:
			writeEvent(event)
			continue
		default:
		}
		select {
		case event := <-c.control:
			writeEvent(event)
		case event := <-c.segment:
			writeEvent(event)
		case <-ticker.C:
			if writer != nil {
				if err := writer.Flush(); err != nil {
					if !fileFailed {
						log.Errorln("Sage native collector flush failed: %s", err.Error())
					}
					fileFailed = true
				}
			}
		case <-c.stop:
			for {
				select {
				case event := <-c.control:
					writeEvent(event)
					continue
				default:
				}
				select {
				case event := <-c.segment:
					writeEvent(event)
				default:
					closeFile()
					return
				}
			}
		}
	}
}

func sageNativePrivacyKey() ([]byte, string, error) {
	path := filepath.Join(C.Path.HomeDir(), "sage-native.key")
	payload, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		payload = make([]byte, 32)
		if _, err = io.ReadFull(rand.Reader, payload); err != nil {
			return nil, "", err
		}
		file, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if errors.Is(createErr, os.ErrExist) {
			payload, err = os.ReadFile(path)
		} else if createErr == nil {
			_, err = file.Write(payload)
			if closeErr := file.Close(); err == nil {
				err = closeErr
			}
		} else {
			err = createErr
		}
	}
	if err != nil {
		return nil, "", err
	}
	if len(payload) != 32 {
		return nil, "", fmt.Errorf("sage native privacy key has invalid size %d", len(payload))
	}
	digest := sha256.Sum256(payload)
	return payload, hex.EncodeToString(digest[:8]), nil
}

func recoverSageNativeOpenFiles(directory string) error {
	matches, err := filepath.Glob(filepath.Join(directory, "sage-native-v1.*.jsonl.open"))
	if err != nil {
		return err
	}
	sort.Strings(matches)
	for _, path := range matches {
		completeSize, found, scanErr := sageNativeLastCompleteLine(path)
		if scanErr != nil {
			return scanErr
		}
		if !found {
			if removeErr := os.Remove(path); removeErr != nil {
				return removeErr
			}
			continue
		}
		if truncateErr := os.Truncate(path, completeSize); truncateErr != nil {
			return truncateErr
		}
		// A crash-recovered file has no trustworthy footer/drop counters. Keep
		// its complete lines for diagnostics, but never advertise it as a
		// lossless training input.
		if renameErr := os.Rename(path, strings.TrimSuffix(path, ".open")+".recovered"); renameErr != nil {
			return renameErr
		}
	}
	return nil
}

func sageNativeLastCompleteLine(path string) (int64, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return 0, false, err
	}
	const blockSize = int64(64 << 10)
	buffer := make([]byte, blockSize)
	for end := info.Size(); end > 0; {
		start := end - blockSize
		if start < 0 {
			start = 0
		}
		length := end - start
		read, readErr := file.ReadAt(buffer[:length], start)
		if readErr != nil && readErr != io.EOF {
			return 0, false, readErr
		}
		if index := bytes.LastIndexByte(buffer[:read], '\n'); index >= 0 {
			return start + int64(index) + 1, true, nil
		}
		end = start
	}
	return 0, false, nil
}

func FlushSageNativeCollectorsContext(ctx context.Context) error {
	sageNativeCollectorRegistry.Lock()
	collectors := make([]*sageNativeCollector, 0, len(sageNativeCollectorRegistry.entries))
	for _, collector := range sageNativeCollectorRegistry.entries {
		collectors = append(collectors, collector)
	}
	sageNativeCollectorRegistry.Unlock()
	for _, collector := range collectors {
		collector.stopOnce.Do(func() {
			collector.ingressMu.Lock()
			collector.stopped = true
			collector.incompleteAttempts.Store(collector.activeAttempts.Load())
			close(collector.stop)
			collector.ingressMu.Unlock()
		})
	}
	for _, collector := range collectors {
		select {
		case <-collector.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func FlushSageNativeCollectors() error {
	return FlushSageNativeCollectorsContext(context.Background())
}

type sageNativeAttempt struct {
	collector        *sageNativeCollector
	id               string
	decisionUnixNano int64
	groupID          string
	nodeID           string
	nodeIDStable     bool
	transport        string
	scene            string
	features         [8]float64
	exploration      bool
	handoff          bool

	outcomeOnce  sync.Once
	responseOnce sync.Once
	endOnce      sync.Once
	segmentIndex atomic.Uint64
}

func (a *Sage) newNativeAttempt(decision sagePickDecision, metadata *C.Metadata, transport sageTransport, now time.Time) *sageNativeAttempt {
	collector := a.collector
	if collector == nil || decision.proxy == nil || metadata == nil {
		return nil
	}
	featuresSlice := prepareSagePriorFeatures(metadata, decision.proxy, a.Name(), a.testURL, now)
	if len(featuresSlice) != 8 {
		return nil
	}
	var features [8]float64
	copy(features[:], featuresSlice)
	if !collector.beginAttempt() {
		return nil
	}
	attempt := &sageNativeAttempt{
		collector:        collector,
		id:               fmt.Sprintf("%s:a%d", collector.runID, collector.attempts.Add(1)),
		decisionUnixNano: now.UnixNano(), groupID: collector.token("group", a.Name()),
		nodeID:       collector.token("node", decision.identity),
		nodeIDStable: decision.identity != "" && !strings.HasPrefix(decision.identity, "instance:"),
		transport:    sageNativeTransportName(transport), scene: sageNativeSceneName(classifySageScene(metadata, a.rules)),
		features: features, exploration: decision.exploration != nil, handoff: decision.handoff != nil,
	}
	attempt.emit(sageNativeEvent{EventType: "decision"}, false, now)
	return attempt
}

func (a *sageNativeAttempt) decorate(event sageNativeEvent, now time.Time) sageNativeEvent {
	if a == nil || a.collector == nil {
		return event
	}
	event.FeatureSchema = sageNativeFeatureSchema
	event.ObservedUnixNano = now.UnixNano()
	event.AttemptID = a.id
	event.DecisionUnixNano = a.decisionUnixNano
	event.GroupID, event.NodeID, event.NodeIDStable = a.groupID, a.nodeID, a.nodeIDStable
	event.Transport, event.Scene, event.Features = a.transport, a.scene, a.features
	event.Exploration, event.Handoff = a.exploration, a.handoff
	return event
}

func (a *sageNativeAttempt) emit(event sageNativeEvent, segment bool, now time.Time) {
	if a == nil || a.collector == nil {
		return
	}
	a.collector.nextEvent(a.decorate(event, now), segment)
}

func (a *sageNativeAttempt) setup(now time.Time, elapsed time.Duration, status string, deferred bool) {
	if a == nil {
		return
	}
	a.emit(sageNativeEvent{EventType: "setup", SetupStatus: status, Deferred: deferred, Metric: "connect", ElapsedNano: elapsed.Nanoseconds(), Value: float64(elapsed) / float64(time.Millisecond)}, false, now)
}

func (a *sageNativeAttempt) outcome(now time.Time, outcome, boundary, errorClass string) {
	if a == nil {
		return
	}
	a.outcomeOnce.Do(func() {
		value := 0.0
		if outcome == "failure" {
			value = 1
		}
		a.emit(sageNativeEvent{EventType: "outcome", Outcome: outcome, Boundary: boundary, ErrorClass: errorClass, Metric: "failure", Value: value}, false, now)
	})
}

func (a *sageNativeAttempt) response(now time.Time, elapsed time.Duration) {
	if a == nil {
		return
	}
	a.responseOnce.Do(func() {
		a.emit(sageNativeEvent{EventType: "response", Metric: "response", ElapsedNano: elapsed.Nanoseconds(), Value: float64(elapsed) / float64(time.Millisecond)}, false, now)
	})
}

func (a *sageNativeAttempt) throughput(now time.Time, observation sageThroughputObservation, reason string) {
	if a == nil {
		return
	}
	a.emit(sageNativeEvent{EventType: "throughput", Metric: "throughput", Value: observation.BitsPerSecond, ElapsedNano: observation.Duration.Nanoseconds(), Bytes: observation.Bytes, TotalBytes: observation.TotalBytes, SegmentIndex: a.segmentIndex.Add(1), EndReason: reason}, true, now)
}

func (a *sageNativeAttempt) end(now time.Time, reason string, observation sageConnectionCloseObservation) {
	if a == nil {
		return
	}
	a.endOnce.Do(func() {
		event := a.decorate(sageNativeEvent{EventType: "attempt_end", EndReason: reason, ElapsedNano: observation.Age.Nanoseconds(), WrotePayload: observation.WrotePayload, TotalBytes: observation.TotalReadBytes}, now)
		a.collector.finishAttempt(event)
	})
}

func sageNativeTransportName(transport sageTransport) string {
	if transport == sageTransportUDP {
		return "udp"
	}
	return "tcp"
}

func sageNativeSceneName(scene sageScene) string {
	switch scene {
	case sageSceneInteractive:
		return "interactive"
	case sageSceneMedia:
		return "media"
	case sageSceneBulk:
		return "bulk"
	default:
		return "default"
	}
}

func sageNativeErrorClass(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, C.ErrNotSupport) {
		return "unsupported"
	}
	if errors.Is(err, io.ErrClosedPipe) {
		return "closed"
	}
	return "other"
}
