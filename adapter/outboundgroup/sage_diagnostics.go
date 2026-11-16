package outboundgroup

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/log"
)

const (
	SageDiagnosticsSchemaVersion    = 2
	sageDiagnosticsOldestSchema     = 1
	sageDiagnosticsRecentEventLimit = 64
	sageDiagnosticsRegistryLimit    = 256
	sageDiagnosticsPersistInterval  = 30 * time.Second
)

// SageDiagnosticCounters contains cumulative Sage observations.
// Counters survive config reloads and process restarts when the profile cache is
// available. They are observations only and never participate in selection.
type SageDiagnosticCounters struct {
	MediaFlows            uint64 `json:"mediaFlows"`
	ThroughputSamples     uint64 `json:"throughputSamples"`
	LowThroughputSamples  uint64 `json:"lowThroughputSamples"`
	BufferCreditDeferrals uint64 `json:"bufferCreditDeferrals"`
	ReconnectSuppressed   uint64 `json:"reconnectSuppressed"`
	ReconnectPrepared     uint64 `json:"reconnectPrepared"`
	ReconnectCommitted    uint64 `json:"reconnectCommitted"`
	ReconnectRejected     uint64 `json:"reconnectRejected"`
	HandoffSelections     uint64 `json:"handoffSelections"`
	HandoffMeasured       uint64 `json:"handoffMeasured"`
	HandoffDialFailed     uint64 `json:"handoffDialFailed"`
	ChurnCandidates       uint64 `json:"churnCandidates"`
	ChurnSuspected        uint64 `json:"churnSuspected"`
	ChurnResets           uint64 `json:"churnResets"`
	ExplorationSelections uint64 `json:"explorationSelections"`
	ExplorationSucceeded  uint64 `json:"explorationSucceeded"`
	ExplorationFailed     uint64 `json:"explorationFailed"`
	ExplorationNeutral    uint64 `json:"explorationNeutral"`
}

type SageDiagnosticPersistence struct {
	Available     bool      `json:"available"`
	LastSuccessAt time.Time `json:"lastSuccessAt,omitempty"`
	LastError     string    `json:"lastError,omitempty"`
}

// SageDiagnosticEvent is a bounded, credential-free Sage decision event.
// Throughput values are bits per second, byte counts are bytes, and ages are
// milliseconds.
type SageDiagnosticEvent struct {
	Sequence               uint64    `json:"sequence"`
	HandoffID              uint64    `json:"handoffId,omitempty"`
	ExplorationID          uint64    `json:"explorationId,omitempty"`
	Time                   time.Time `json:"time"`
	Kind                   string    `json:"kind"`
	Reason                 string    `json:"reason,omitempty"`
	Transport              string    `json:"transport,omitempty"`
	Scene                  string    `json:"scene,omitempty"`
	Target                 string    `json:"target,omitempty"`
	Port                   uint16    `json:"port,omitempty"`
	From                   string    `json:"from,omitempty"`
	To                     string    `json:"to,omitempty"`
	BPS                    float64   `json:"bps,omitempty"`
	PreviousBPS            float64   `json:"previousBps,omitempty"`
	TotalBytes             int64     `json:"totalBytes,omitempty"`
	AgeMS                  int64     `json:"ageMs,omitempty"`
	LowWindows             int       `json:"lowWindows,omitempty"`
	Occurrences            int       `json:"occurrences,omitempty"`
	EvidenceCoverageMicros int64     `json:"evidenceCoverageMicros,omitempty"`
	ScopeEligibleOrdinal   uint64    `json:"scopeEligibleOrdinal,omitempty"`
}

type SageDiagnosticConfig struct {
	PriorEnabled                  bool     `json:"priorEnabled,omitempty"`
	PriorConnectConfidence        float64  `json:"priorConnectConfidence,omitempty"`
	PriorResponseConfidence       float64  `json:"priorResponseConfidence,omitempty"`
	PriorThroughputConfidence     float64  `json:"priorThroughputConfidence,omitempty"`
	PriorFailureConfidence        float64  `json:"priorFailureConfidence,omitempty"`
	PriorFeatureSchema            string   `json:"priorFeatureSchema,omitempty"`
	PriorSourceSchema             string   `json:"priorSourceSchema,omitempty"`
	PriorSourceEventUnix          int64    `json:"priorSourceEventUnix,omitempty"`
	PriorManifestSHA256           string   `json:"priorManifestSha256,omitempty"`
	PriorConnectSHA256            string   `json:"priorConnectSha256,omitempty"`
	PriorResponseSHA256           string   `json:"priorResponseSha256,omitempty"`
	PriorThroughputSHA256         string   `json:"priorThroughputSha256,omitempty"`
	PriorFailureSHA256            string   `json:"priorFailureSha256,omitempty"`
	MediaEnabled                  bool     `json:"mediaEnabled"`
	MediaDomains                  []string `json:"mediaDomains"`
	LowThroughputBPS              float64  `json:"lowThroughputBps"`
	LowWindows                    int      `json:"lowWindows"`
	MaxLowWindows                 int      `json:"maxLowWindows"`
	MinAgeMS                      int64    `json:"minAgeMs"`
	MinBytes                      int64    `json:"minBytes"`
	DemandBPS                     float64  `json:"demandBps"`
	BufferGuardMS                 int64    `json:"bufferGuardMs"`
	ReconnectCooldownMS           int64    `json:"reconnectCooldownMs"`
	SlowCooldownMS                int64    `json:"slowCooldownMs"`
	HintTTLMS                     int64    `json:"hintTtlMs"`
	ReconnectBudget               int      `json:"reconnectBudget"`
	BudgetWindowMS                int64    `json:"budgetWindowMs"`
	ChurnShadowEnabled            bool     `json:"churnShadowEnabled"`
	ChurnWindowMS                 int64    `json:"churnWindowMs"`
	ChurnLimit                    int      `json:"churnLimit"`
	ChurnMaxBytes                 int64    `json:"churnMaxBytes"`
	ChurnMaxAgeMS                 int64    `json:"churnMaxAgeMs"`
	ExplorationEnabled            bool     `json:"explorationEnabled"`
	ExplorationInterval           int      `json:"explorationInterval"`
	GrayFailureObservationEnabled bool     `json:"grayFailureObservationEnabled"`
}

type SageDiagnosticExplorationScope struct {
	Transport             string `json:"transport"`
	Scene                 string `json:"scene"`
	EligibleSelections    uint64 `json:"eligibleSelections"`
	ExplorationSelections uint64 `json:"explorationSelections"`
	SinceLastExploration  uint64 `json:"sinceLastExploration"`
	NextIn                uint64 `json:"nextIn"`
}

type SageDiagnosticRuntime struct {
	ActiveHints              int                              `json:"activeHints"`
	ActiveReconnectCooldowns int                              `json:"activeReconnectCooldowns"`
	ActiveSlowCooldowns      int                              `json:"activeSlowCooldowns"`
	ActiveBudgets            int                              `json:"activeBudgets"`
	ActiveChurnStates        int                              `json:"activeChurnStates"`
	ExplorationSince         time.Time                        `json:"explorationSince,omitempty"`
	ExplorationScopes        []SageDiagnosticExplorationScope `json:"explorationScopes,omitempty"`
}

// SageDiagnosticsSnapshot is returned by GET /group/{name}/sage.
// PlayerTelemetryAvailable remains false until an application-side player
// supplies rebuffer data; transport recovery must not be described as no-stall.
type SageDiagnosticsSnapshot struct {
	SchemaVersion            int                       `json:"schemaVersion"`
	Group                    string                    `json:"group"`
	Since                    time.Time                 `json:"since"`
	UpdatedAt                time.Time                 `json:"updatedAt"`
	PlayerTelemetryAvailable bool                      `json:"playerTelemetryAvailable"`
	Persistence              SageDiagnosticPersistence `json:"persistence"`
	LearningPersistence      SageLearningPersistence   `json:"learningPersistence"`
	Counters                 SageDiagnosticCounters    `json:"counters"`
	Suppressions             map[string]uint64         `json:"suppressions"`
	Rejections               map[string]uint64         `json:"rejections"`
	ChurnSuppressions        map[string]uint64         `json:"churnSuppressions"`
	RecentEvents             []SageDiagnosticEvent     `json:"recentEvents"`
	GrayFailure              SageDiagnosticGrayFailure `json:"grayFailure"`
	Config                   SageDiagnosticConfig      `json:"config"`
	Runtime                  SageDiagnosticRuntime     `json:"runtime"`
}

// SageDiagnosticsProvider is the read-only Controller capability exposed by
// Sage groups.
type SageDiagnosticsProvider interface {
	SageDiagnostics() SageDiagnosticsSnapshot
}

type sageDiagnosticsStore interface {
	Load(key string) ([]byte, error)
	Save(key string, payload []byte) error
}

type sageCacheDiagnosticsStore struct{}

func (sageCacheDiagnosticsStore) Load(key string) ([]byte, error) {
	return cachefile.Cache().GetSageDiagnostics(key)
}

func (sageCacheDiagnosticsStore) Save(key string, payload []byte) error {
	return cachefile.Cache().SetSageDiagnostics(key, payload)
}

type sageHandoffToken struct {
	id          uint64
	target      string
	bucket      string
	port        uint16
	from        string
	to          string
	previousBPS float64
}

type sageDiagnostics struct {
	mu              sync.Mutex
	clock           sageClock
	store           sageDiagnosticsStore
	storageKey      string
	revision        uint64
	lastScheduled   time.Time
	persistInterval time.Duration
	persistTimer    *time.Timer
	snapshotData    SageDiagnosticsSnapshot
	retired         bool
	detached        bool
	retiring        bool
	redirect        *sageDiagnostics
	lastAccess      atomic.Uint64
	persistRetryAt  time.Time

	persistMu         sync.Mutex
	persistRunning    bool
	pendingRevision   uint64
	pendingPayload    []byte
	processedRevision uint64
	persistWG         sync.WaitGroup
}

type sageDiagnosticRecord struct {
	kind                   string
	reason                 string
	target                 string
	bucket                 string
	port                   uint16
	from                   string
	to                     string
	handoffID              uint64
	explorationID          uint64
	transport              string
	scene                  string
	bps                    float64
	previousBPS            float64
	totalBytes             int64
	age                    time.Duration
	lowWindows             int
	occurrences            int
	evidenceCoverageMicros int64
	scopeEligibleOrdinal   uint64
	low                    bool
	force                  bool
}

type sageDiagnosticsRegistryState struct {
	sync.Mutex
	entries map[string]*sageDiagnostics
	current sync.Map
	access  atomic.Uint64
}

var sageDiagnosticsRegistry = sageDiagnosticsRegistryState{entries: make(map[string]*sageDiagnostics)}

func sageDiagnosticsStorageKey(group string) string {
	sum := sha256.Sum256([]byte(group))
	return "sage-diag-v1:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func (r *sageDiagnosticsRegistryState) touch(diagnostics *sageDiagnostics) {
	if diagnostics != nil {
		diagnostics.lastAccess.Store(r.access.Add(1))
	}
}

func (r *sageDiagnosticsRegistryState) addLocked(key string, diagnostics *sageDiagnostics) bool {
	if current := r.entries[key]; current != nil {
		r.touch(current)
		return current == diagnostics
	}
	if len(r.entries) >= sageDiagnosticsRegistryLimit {
		var victimKey string
		var victim *sageDiagnostics
		var oldest uint64
		for candidateKey, candidate := range r.entries {
			access := candidate.lastAccess.Load()
			if victim == nil || access < oldest {
				victimKey, victim, oldest = candidateKey, candidate, access
			}
		}
		if victim != nil {
			victim.mu.Lock()
			victim.retiring = true
			if victim.persistTimer != nil {
				victim.persistTimer.Stop()
				victim.persistTimer = nil
			}
			targetRevision := victim.revision
			if victim.store != nil {
				victim.schedulePersistLocked(victim.clock.Now().UTC())
			}
			victim.mu.Unlock()

			for {
				victim.persistWG.Wait()
				victim.persistMu.Lock()
				processedRevision := victim.processedRevision
				victim.persistMu.Unlock()

				victim.mu.Lock()
				if victim.store != nil && processedRevision < targetRevision {
					victim.retiring = false
					if victim.persistTimer == nil {
						delay := victim.persistRetryAt.Sub(victim.clock.Now().UTC())
						if delay <= 0 {
							delay = victim.persistInterval
							if delay <= 0 {
								delay = sageDiagnosticsPersistInterval
							}
						}
						victim.persistTimer = time.AfterFunc(delay, victim.flushDelayed)
					}
					victim.mu.Unlock()
					return false
				}
				if victim.store != nil && processedRevision < victim.revision {
					targetRevision = victim.revision
					victim.schedulePersistLocked(victim.clock.Now().UTC())
					victim.mu.Unlock()
					continue
				}
				victim.retired = true
				victim.detached = true
				victim.retiring = false
				victim.store = nil
				victim.snapshotData.Persistence.Available = false
				victim.snapshotData.Persistence.LastError = "diagnostics registry entry evicted"
				victim.mu.Unlock()
				delete(r.entries, victimKey)
				r.current.Delete(victimKey)
				break
			}
		}
	}
	r.entries[key] = diagnostics
	r.current.Store(key, diagnostics)
	r.touch(diagnostics)
	return true
}

func (d *sageDiagnostics) active() *sageDiagnostics {
	if d == nil {
		return nil
	}
	for {
		d.mu.Lock()
		if d.redirect != nil {
			next := d.redirect
			d.mu.Unlock()
			d = next
			continue
		}
		if d.retiring {
			d.mu.Unlock()
			return d
		}
		if !d.retired && !d.detached {
			d.mu.Unlock()
			sageDiagnosticsRegistry.touch(d)
			return d
		}
		detached := d.detached
		storageKey := d.storageKey
		d.mu.Unlock()

		value, ok := sageDiagnosticsRegistry.current.Load(storageKey)
		current, _ := value.(*sageDiagnostics)
		if ok && current != nil && current != d {
			d.mu.Lock()
			d.redirect = current
			d.mu.Unlock()
			sageDiagnosticsRegistry.touch(current)
			d = current
			continue
		}
		if detached {
			return d
		}
		return nil
	}
}

func sharedSageDiagnostics(group string, clock sageClock) *sageDiagnostics {
	key := sageDiagnosticsStorageKey(group)
	sageDiagnosticsRegistry.Lock()
	defer sageDiagnosticsRegistry.Unlock()
	if diagnostics := sageDiagnosticsRegistry.entries[key]; diagnostics != nil {
		sageDiagnosticsRegistry.touch(diagnostics)
		return diagnostics
	}
	diagnostics := newSageDiagnostics(group, clock, sageCacheDiagnosticsStore{})
	if !sageDiagnosticsRegistry.addLocked(key, diagnostics) {
		diagnostics.disablePersistence("diagnostics registry capacity unavailable")
	}
	return diagnostics
}

func (d *sageDiagnostics) disablePersistence(reason string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	if d.persistTimer != nil {
		d.persistTimer.Stop()
		d.persistTimer = nil
	}
	d.store = nil
	d.detached = true
	d.snapshotData.Persistence.Available = false
	d.snapshotData.Persistence.LastError = reason
	d.mu.Unlock()
}

func newSageDiagnostics(group string, clock sageClock, store sageDiagnosticsStore) *sageDiagnostics {
	if clock == nil {
		clock = sageSystemClock{}
	}
	now := clock.Now().UTC()
	diagnostics := &sageDiagnostics{
		clock:           clock,
		store:           store,
		storageKey:      sageDiagnosticsStorageKey(group),
		persistInterval: sageDiagnosticsPersistInterval,
		snapshotData: SageDiagnosticsSnapshot{
			SchemaVersion:     SageDiagnosticsSchemaVersion,
			Group:             group,
			Since:             now,
			UpdatedAt:         now,
			Suppressions:      make(map[string]uint64),
			Rejections:        make(map[string]uint64),
			ChurnSuppressions: make(map[string]uint64),
			RecentEvents:      make([]SageDiagnosticEvent, 0, sageDiagnosticsRecentEventLimit),
			GrayFailure: SageDiagnosticGrayFailure{
				Exclusions: newSageGrayExclusions(),
			},
		},
		lastScheduled: now,
	}
	if store == nil {
		diagnostics.snapshotData.Persistence.LastError = "persistence disabled"
		return diagnostics
	}
	payload, loadErr := store.Load(diagnostics.storageKey)
	if loadErr != nil {
		diagnostics.snapshotData.Persistence.LastError = loadErr.Error()
		log.Warnln("Sage: diagnostics persistence unavailable for group %s: %s", group, loadErr.Error())
		return diagnostics
	}
	diagnostics.snapshotData.Persistence.Available = true
	if len(payload) == 0 {
		return diagnostics
	}
	var restored SageDiagnosticsSnapshot
	if err := json.Unmarshal(payload, &restored); err != nil || restored.SchemaVersion < sageDiagnosticsOldestSchema || restored.SchemaVersion > SageDiagnosticsSchemaVersion || restored.Group != group {
		if err != nil {
			log.Warnln("Sage: ignore invalid diagnostics for group %s: %s", group, err.Error())
		} else {
			log.Warnln("Sage: ignore incompatible diagnostics for group %s", group)
		}
		return diagnostics
	}
	if restored.Suppressions == nil {
		restored.Suppressions = make(map[string]uint64)
	}
	if restored.Rejections == nil {
		restored.Rejections = make(map[string]uint64)
	}
	if restored.ChurnSuppressions == nil {
		restored.ChurnSuppressions = make(map[string]uint64)
	}
	restored.GrayFailure.Exclusions = normalizeSageGrayExclusions(restored.GrayFailure.Exclusions)
	// Rolling gray-failure buckets are generation-local. Persist only the
	// cumulative counters and exclusion totals.
	restored.GrayFailure.Series = nil
	restored.GrayFailure.Enabled = false
	if len(restored.RecentEvents) > sageDiagnosticsRecentEventLimit {
		restored.RecentEvents = append([]SageDiagnosticEvent(nil), restored.RecentEvents[len(restored.RecentEvents)-sageDiagnosticsRecentEventLimit:]...)
	}
	restored.SchemaVersion = SageDiagnosticsSchemaVersion
	restored.Config = SageDiagnosticConfig{}
	restored.Runtime = SageDiagnosticRuntime{}
	restored.LearningPersistence = SageLearningPersistence{}
	restored.PlayerTelemetryAvailable = false
	restored.Persistence.Available = true
	restored.Persistence.LastError = ""
	diagnostics.snapshotData = restored
	diagnostics.lastScheduled = now
	return diagnostics
}

func (d *sageDiagnostics) record(record sageDiagnosticRecord) {
	if d == nil {
		return
	}
	for {
		current := d.active()
		if current == nil {
			return
		}
		if current != d {
			d = current
			continue
		}
		d.mu.Lock()
		if d.redirect != nil {
			d.mu.Unlock()
			continue
		}
		if d.retired && !d.detached {
			d.mu.Unlock()
			return
		}
		d.recordLocked(record)
		d.mu.Unlock()
		return
	}
}

func (d *sageDiagnostics) recordReconnectCommit(record sageDiagnosticRecord) *sageHandoffToken {
	if d == nil {
		return nil
	}
	for {
		current := d.active()
		if current == nil {
			return nil
		}
		if current != d {
			d = current
			continue
		}
		d.mu.Lock()
		if d.redirect != nil {
			d.mu.Unlock()
			continue
		}
		if d.retired && !d.detached {
			d.mu.Unlock()
			return nil
		}
		record.kind = "reconnect-committed"
		record.force = true
		record.handoffID = uint64(1)
		if events := d.snapshotData.RecentEvents; len(events) > 0 {
			record.handoffID = events[len(events)-1].Sequence + 1
		}
		event := d.recordLocked(record)
		d.mu.Unlock()
		return &sageHandoffToken{
			id:          event.Sequence,
			target:      normalizeSageMediaTarget(record.target),
			bucket:      record.bucket,
			port:        record.port,
			from:        record.from,
			to:          record.to,
			previousBPS: record.bps,
		}
	}
}

func (d *sageDiagnostics) recordExplorationSelection(selection sageExplorationSelection) *sageExplorationToken {
	if d == nil {
		return nil
	}
	for {
		current := d.active()
		if current == nil {
			return nil
		}
		if current != d {
			d = current
			continue
		}
		d.mu.Lock()
		if d.redirect != nil {
			d.mu.Unlock()
			continue
		}
		if d.retired && !d.detached {
			d.mu.Unlock()
			return nil
		}
		record := sageDiagnosticRecord{
			kind:                   "exploration-selected",
			transport:              selection.transport.String(),
			scene:                  selection.scene.String(),
			target:                 selection.target,
			port:                   selection.port,
			from:                   selection.fromAnchor,
			to:                     selection.toCandidate,
			evidenceCoverageMicros: selection.evidenceCoverageMicros,
			scopeEligibleOrdinal:   selection.scopeEligibleOrdinal,
			explorationID:          1,
		}
		if events := d.snapshotData.RecentEvents; len(events) > 0 {
			record.explorationID = events[len(events)-1].Sequence + 1
		}
		event := d.recordLocked(record)
		d.mu.Unlock()
		return &sageExplorationToken{
			diagnostics:            d,
			id:                     event.Sequence,
			transport:              selection.transport,
			scene:                  selection.scene,
			target:                 selection.target,
			port:                   selection.port,
			fromAnchor:             selection.fromAnchor,
			toCandidate:            selection.toCandidate,
			evidenceCoverageMicros: selection.evidenceCoverageMicros,
			scopeEligibleOrdinal:   selection.scopeEligibleOrdinal,
		}
	}
}

func (d *sageDiagnostics) recordLocked(record sageDiagnosticRecord) SageDiagnosticEvent {
	now := d.clock.Now().UTC()
	d.snapshotData.UpdatedAt = now
	d.revision++

	switch record.kind {
	case "media-flow-started":
		d.snapshotData.Counters.MediaFlows++
	case "throughput-sample":
		d.snapshotData.Counters.ThroughputSamples++
		if record.low {
			d.snapshotData.Counters.LowThroughputSamples++
		}
	case "buffer-credit-deferred":
		d.snapshotData.Counters.BufferCreditDeferrals++
	case "reconnect-suppressed":
		d.snapshotData.Counters.ReconnectSuppressed++
		d.snapshotData.Suppressions[record.reason]++
	case "reconnect-prepared":
		d.snapshotData.Counters.ReconnectPrepared++
	case "reconnect-committed":
		d.snapshotData.Counters.ReconnectCommitted++
	case "reconnect-rejected":
		d.snapshotData.Counters.ReconnectRejected++
		d.snapshotData.Rejections[record.reason]++
	case "handoff-selected":
		d.snapshotData.Counters.HandoffSelections++
	case "handoff-measured":
		d.snapshotData.Counters.HandoffMeasured++
	case "handoff-dial-failed":
		d.snapshotData.Counters.HandoffDialFailed++
	case "churn-candidate":
		d.snapshotData.Counters.ChurnCandidates++
	case "churn-suspected":
		d.snapshotData.Counters.ChurnSuspected++
	case "churn-reset":
		d.snapshotData.Counters.ChurnResets++
	case "churn-suppressed":
		d.snapshotData.ChurnSuppressions[record.reason]++
	case "exploration-selected":
		d.snapshotData.Counters.ExplorationSelections++
	case "exploration-succeeded":
		d.snapshotData.Counters.ExplorationSucceeded++
	case "exploration-failed":
		d.snapshotData.Counters.ExplorationFailed++
	case "exploration-neutral":
		d.snapshotData.Counters.ExplorationNeutral++
	case "gray-attempt-succeeded":
		d.snapshotData.GrayFailure.Counters.AttemptEligible++
		d.snapshotData.GrayFailure.Counters.AttemptSucceeded++
	case "gray-attempt-failed":
		d.snapshotData.GrayFailure.Counters.AttemptEligible++
		d.snapshotData.GrayFailure.Counters.AttemptFailed++
	case "gray-close-progress":
		d.snapshotData.GrayFailure.Counters.CloseEligible++
		d.snapshotData.GrayFailure.Counters.CloseProgress++
	case "gray-close-tiny":
		d.snapshotData.GrayFailure.Counters.CloseEligible++
		d.snapshotData.GrayFailure.Counters.CloseTiny++
	case "gray-attempt-excluded":
		if sageGrayKnownExclusion("attempt", record.reason) {
			d.snapshotData.GrayFailure.Exclusions.Attempt[record.reason]++
		}
	case "gray-close-excluded":
		if sageGrayKnownExclusion("close", record.reason) {
			d.snapshotData.GrayFailure.Exclusions.Close[record.reason]++
		}
	}

	var event SageDiagnosticEvent
	if record.kind != "throughput-sample" && record.kind != "churn-candidate" && record.kind != "churn-reset" && record.kind != "churn-suppressed" &&
		!strings.HasPrefix(record.kind, "gray-") {
		event = d.appendEventLocked(record, now)
	}
	if d.store != nil && !d.retiring {
		d.queuePersistenceLocked(now, record.force)
	}
	return event
}

func (d *sageDiagnostics) appendEventLocked(record sageDiagnosticRecord, now time.Time) SageDiagnosticEvent {
	sequence := uint64(1)
	if events := d.snapshotData.RecentEvents; len(events) > 0 {
		sequence = events[len(events)-1].Sequence + 1
	}
	event := SageDiagnosticEvent{
		Sequence:               sequence,
		HandoffID:              record.handoffID,
		ExplorationID:          record.explorationID,
		Time:                   now,
		Kind:                   record.kind,
		Reason:                 record.reason,
		Transport:              record.transport,
		Scene:                  record.scene,
		Target:                 record.target,
		Port:                   record.port,
		From:                   record.from,
		To:                     record.to,
		BPS:                    record.bps,
		PreviousBPS:            record.previousBPS,
		TotalBytes:             record.totalBytes,
		AgeMS:                  record.age.Milliseconds(),
		LowWindows:             record.lowWindows,
		Occurrences:            record.occurrences,
		EvidenceCoverageMicros: record.evidenceCoverageMicros,
		ScopeEligibleOrdinal:   record.scopeEligibleOrdinal,
	}
	d.snapshotData.RecentEvents = append(d.snapshotData.RecentEvents, event)
	if excess := len(d.snapshotData.RecentEvents) - sageDiagnosticsRecentEventLimit; excess > 0 {
		copy(d.snapshotData.RecentEvents, d.snapshotData.RecentEvents[excess:])
		d.snapshotData.RecentEvents = d.snapshotData.RecentEvents[:sageDiagnosticsRecentEventLimit]
	}
	return event
}

func (d *sageDiagnostics) schedulePersistLocked(now time.Time) {
	if d.persistTimer != nil {
		d.persistTimer.Stop()
		d.persistTimer = nil
	}
	d.persistRetryAt = time.Time{}
	payload, err := json.Marshal(d.snapshotData)
	if err != nil {
		log.Warnln("Sage: marshal diagnostics for group %s failed: %s", d.snapshotData.Group, err.Error())
		return
	}
	revision := d.revision
	d.lastScheduled = now
	d.persistMu.Lock()
	if revision > d.pendingRevision {
		d.pendingRevision = revision
		d.pendingPayload = payload
	}
	if !d.persistRunning {
		d.persistRunning = true
		d.persistWG.Add(1)
		go d.persistLoop()
	}
	d.persistMu.Unlock()
}

func (d *sageDiagnostics) queuePersistenceLocked(now time.Time, force bool) {
	interval := d.persistInterval
	if interval <= 0 {
		interval = sageDiagnosticsPersistInterval
	}
	if d.persistRetryAt.After(now) {
		if d.persistTimer == nil {
			d.persistTimer = time.AfterFunc(d.persistRetryAt.Sub(now), d.flushDelayed)
		}
		return
	}
	elapsed := now.Sub(d.lastScheduled)
	if elapsed < 0 {
		elapsed = 0
	}
	if force || elapsed >= interval {
		d.schedulePersistLocked(now)
		return
	}
	if d.persistTimer == nil {
		d.persistTimer = time.AfterFunc(interval-elapsed, d.flushDelayed)
	}
}

func (d *sageDiagnostics) flushDelayed() {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.persistTimer = nil
	if d.store != nil && !d.retired && !d.retiring {
		d.schedulePersistLocked(d.clock.Now().UTC())
	}
	d.mu.Unlock()
}

func (d *sageDiagnostics) persistLoop() {
	defer d.persistWG.Done()
	for {
		d.persistMu.Lock()
		if d.pendingRevision == 0 {
			d.persistRunning = false
			d.persistMu.Unlock()
			return
		}
		revision := d.pendingRevision
		payload := d.pendingPayload
		d.pendingRevision = 0
		d.pendingPayload = nil
		if revision <= d.processedRevision {
			d.persistMu.Unlock()
			continue
		}
		d.persistMu.Unlock()
		err := d.store.Save(d.storageKey, payload)
		if err == nil {
			d.persistMu.Lock()
			if revision > d.processedRevision {
				d.processedRevision = revision
			}
			d.persistMu.Unlock()
		}

		now := d.clock.Now().UTC()
		d.mu.Lock()
		if err != nil {
			d.persistMu.Lock()
			if revision > d.pendingRevision {
				d.pendingRevision = revision
				d.pendingPayload = payload
			}
			d.persistRunning = false
			d.persistMu.Unlock()
			d.snapshotData.Persistence.Available = false
			d.snapshotData.Persistence.LastError = err.Error()
			log.Warnln("Sage: persist diagnostics for group %s failed: %s", d.snapshotData.Group, err.Error())
			interval := d.persistInterval
			if interval <= 0 {
				interval = sageDiagnosticsPersistInterval
			}
			d.persistRetryAt = now.Add(interval)
			if d.persistTimer == nil && !d.retired && !d.retiring {
				d.persistTimer = time.AfterFunc(interval, d.flushDelayed)
			}
		} else {
			d.persistRetryAt = time.Time{}
			d.snapshotData.Persistence.Available = true
			d.snapshotData.Persistence.LastSuccessAt = now
			d.snapshotData.Persistence.LastError = ""
		}
		d.mu.Unlock()
		if err != nil {
			return
		}
	}
}

func (d *sageDiagnostics) waitPersistence() {
	if d == nil {
		return
	}
	d.persistWG.Wait()
}

func (d *sageDiagnostics) snapshot() SageDiagnosticsSnapshot {
	if d == nil {
		return SageDiagnosticsSnapshot{}
	}
	for {
		d.mu.Lock()
		if d.redirect != nil {
			next := d.redirect
			d.mu.Unlock()
			d = next
			continue
		}
		snapshot := cloneSageDiagnosticsSnapshot(d.snapshotData)
		d.mu.Unlock()
		return snapshot
	}
}

func cloneSageDiagnosticsSnapshot(source SageDiagnosticsSnapshot) SageDiagnosticsSnapshot {
	cloned := source
	cloned.Suppressions = make(map[string]uint64, len(source.Suppressions))
	for reason, count := range source.Suppressions {
		cloned.Suppressions[reason] = count
	}
	cloned.Rejections = make(map[string]uint64, len(source.Rejections))
	for reason, count := range source.Rejections {
		cloned.Rejections[reason] = count
	}
	cloned.ChurnSuppressions = make(map[string]uint64, len(source.ChurnSuppressions))
	for reason, count := range source.ChurnSuppressions {
		cloned.ChurnSuppressions[reason] = count
	}
	cloned.RecentEvents = append([]SageDiagnosticEvent(nil), source.RecentEvents...)
	cloned.GrayFailure.Exclusions.Attempt = make(map[string]uint64, len(source.GrayFailure.Exclusions.Attempt))
	for reason, count := range source.GrayFailure.Exclusions.Attempt {
		cloned.GrayFailure.Exclusions.Attempt[reason] = count
	}
	cloned.GrayFailure.Exclusions.Close = make(map[string]uint64, len(source.GrayFailure.Exclusions.Close))
	for reason, count := range source.GrayFailure.Exclusions.Close {
		cloned.GrayFailure.Exclusions.Close[reason] = count
	}
	cloned.GrayFailure.Series = append([]SageDiagnosticGraySeries(nil), source.GrayFailure.Series...)
	for index := range cloned.GrayFailure.Series {
		cloned.GrayFailure.Series[index].Reasons = append([]string(nil), source.GrayFailure.Series[index].Reasons...)
	}
	cloned.Config.MediaDomains = append([]string(nil), source.Config.MediaDomains...)
	cloned.Runtime.ExplorationScopes = append([]SageDiagnosticExplorationScope(nil), source.Runtime.ExplorationScopes...)
	return cloned
}
