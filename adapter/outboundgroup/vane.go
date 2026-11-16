package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

const (
	vaneDefaultSwitchMargin  = 0.05
	vaneDefaultCooldown      = 30 * time.Second
	vaneDefaultStateTTL      = 24 * time.Hour
	vaneDefaultMaxStates     = 1024
	vaneDefaultMaxCooldowns  = 4096
	vaneMaximumConfigSeconds = int((365 * 24 * time.Hour) / time.Second)
)

type VaneOption struct {
	CollectEvents          bool     `group:"collect-events,omitempty"`
	CollectorDir           string   `group:"collector-dir,omitempty"`
	CollectorQueueSize     int      `group:"collector-queue-size,omitempty"`
	CollectorMaxFileSize   int64    `group:"collector-max-file-size,omitempty"`
	CollectorMaxFileAge    int      `group:"collector-max-file-age,omitempty"`
	CollectorFlushInterval int      `group:"collector-flush-interval,omitempty"`
	SceneRules             []string `group:"scene-rules,omitempty"`
	SwitchMargin           float64  `group:"switch-margin,omitempty"`
	TargetCooldown         int      `group:"target-cooldown,omitempty"`
	StateTTL               int      `group:"state-ttl,omitempty"`
	MaxStates              int      `group:"max-states,omitempty"`
	Exploration            bool     `group:"exploration,omitempty"`
	ExplorationInterval    int      `group:"exploration-interval,omitempty"`
	GrayFailureObservation bool     `group:"gray-failure-observation,omitempty"`
	MediaReconnect         bool     `group:"media-reconnect,omitempty"`
	MediaReconnectDomains  []string `group:"media-reconnect-domains,omitempty"`
	MediaLowThroughput     int64    `group:"media-low-throughput,omitempty"`
	MediaLowWindows        int      `group:"media-low-windows,omitempty"`
	MediaMaxLowWindows     int      `group:"media-max-low-windows,omitempty"`
	MediaMinAge            int      `group:"media-min-age,omitempty"`
	MediaMinBytes          int64    `group:"media-min-bytes,omitempty"`
	MediaDemandBPS         int64    `group:"media-demand-bps,omitempty"`
	MediaBufferGuard       int      `group:"media-buffer-guard,omitempty"`
	MediaReconnectCooldown int      `group:"media-reconnect-cooldown,omitempty"`
	MediaSlowCooldown      int      `group:"media-slow-cooldown,omitempty"`
	MediaHintTTL           int      `group:"media-hint-ttl,omitempty"`
	MediaChallengerRatio   float64  `group:"media-challenger-ratio,omitempty"`
	MediaReconnectBudget   int      `group:"media-reconnect-budget,omitempty"`
	MediaBudgetWindow      int      `group:"media-budget-window,omitempty"`
}

type vaneTransport uint8

const (
	vaneTransportTCP vaneTransport = iota
	vaneTransportUDP
)

type vaneNodeState struct {
	name     string
	identity string
	epoch    uint64
	tcp      vaneMetrics
	udp      vaneMetrics
	// lastObservedAt is durable retention metadata. It is not selection
	// evidence and restoring it must never refresh the node's lifetime.
	lastObservedAt time.Time
}

// vaneNodeControlState is generation-local policy state. None of these
// fields may survive a reload or appear in the durable learning payload.
type vaneNodeControlState struct {
	recentTCPThroughput vaneRecentThroughput
	lastExplored        [vaneExplorationScopeCount]uint64
	lastSeen            time.Time
}

type vaneRecentThroughput struct {
	bitsPerSecond float64
	observedAt    time.Time
}

func (s *vaneNodeState) metrics(transport vaneTransport) *vaneMetrics {
	if transport == vaneTransportUDP {
		return &s.udp
	}
	return &s.tcp
}

func (s vaneNodeState) snapshot(transport vaneTransport, now time.Time) vaneMetricsSnapshot {
	if transport == vaneTransportUDP {
		return s.udp.snapshot(now)
	}
	return s.tcp.snapshot(now)
}

type vaneAnchorKey struct {
	transport vaneTransport
	scene     vaneScene
}

type vaneAnchor struct {
	name        string
	scoreMicros int64
}

type vaneCooldownKey struct {
	transport vaneTransport
	target    string
	port      uint16
	candidate string
	identity  string
}

type vaneRankedProxy struct {
	proxy C.Proxy
	vaneCandidateScore
	cooldownUntil          time.Time
	evidenceCoverageMicros int64
}

type vanePickDecision struct {
	proxy                    C.Proxy
	identity                 string
	nodeEpoch                uint64
	reportedAliveAtSelection bool
	handoff                  *vaneHandoffToken
	exploration              *vaneExplorationToken
}

type Vane struct {
	*GroupBase

	disableUDP         bool
	testURL            string
	expectedStatus     string
	rules              []vaneSceneRule
	switchMargin       int64
	targetCooldown     time.Duration
	stateTTL           time.Duration
	maxStates          int
	clock              vaneClock
	media              vaneMediaConfig
	exploration        vaneExplorationConfig
	collectorSpec      *vaneNativeCollectorSpec
	collector          *vaneNativeCollector
	collectorReleased  bool
	explorationSince   time.Time
	diagnostics        *vaneDiagnostics
	gray               *vaneGrayObserver
	learning           *vaneLearningState
	learningGeneration uint64
	activationMu       sync.Mutex
	learningActivated  bool

	mu                 sync.Mutex
	nodes              map[string]*vaneNodeState
	nodeControls       map[string]*vaneNodeControlState
	nodeIdentities     map[string]string
	anchors            map[vaneAnchorKey]vaneAnchor
	cooldowns          map[vaneCooldownKey]time.Time
	mediaHints         map[vaneMediaTargetKey]vaneMediaHint
	mediaReconnects    map[vaneMediaTargetKey]time.Time
	mediaSlowCooldowns map[vaneMediaCandidateKey]time.Time
	mediaBudgets       map[vaneMediaTargetKey]vaneMediaBudget
	explorationScopes  [vaneExplorationScopeCount]vaneExplorationScopeState
	explorationOrdinal uint64

	churnMu sync.Mutex
	churn   map[vaneChurnKey]*vaneChurnState
}

func NewVane(option GroupCommonOption, vaneOption VaneOption, emptyFallback C.Proxy, providers []P.ProxyProvider) (*Vane, error) {
	if emptyFallback == nil {
		return nil, errors.New("empty fallback proxy not exist")
	}

	rules, err := parseVaneSceneRules(vaneOption.SceneRules)
	if err != nil {
		return nil, err
	}

	switchMargin := vaneOption.SwitchMargin
	if switchMargin == 0 {
		switchMargin = vaneDefaultSwitchMargin
	}
	if switchMargin < 0 || switchMargin > 1 {
		return nil, fmt.Errorf("switch-margin must be between 0 and 1")
	}

	targetCooldown, err := vaneDurationOption("target-cooldown", vaneOption.TargetCooldown, vaneDefaultCooldown)
	if err != nil {
		return nil, err
	}
	stateTTL, err := vaneDurationOption("state-ttl", vaneOption.StateTTL, vaneDefaultStateTTL)
	if err != nil {
		return nil, err
	}
	maxStates := vaneOption.MaxStates
	if maxStates == 0 {
		maxStates = vaneDefaultMaxStates
	}
	if maxStates < 0 {
		return nil, fmt.Errorf("max-states must not be negative")
	}
	exploration, err := newVaneExplorationConfig(vaneOption.Exploration, vaneOption.ExplorationInterval)
	if err != nil {
		return nil, err
	}
	media, err := newVaneMediaConfig(vaneOption)
	if err != nil {
		return nil, err
	}
	collectorSpec, err := newVaneNativeCollectorSpec(
		vaneOption.CollectEvents,
		vaneOption.CollectorDir,
		vaneOption.CollectorQueueSize,
		vaneOption.CollectorMaxFileSize,
		vaneOption.CollectorMaxFileAge,
		vaneOption.CollectorFlushInterval,
	)
	if err != nil {
		return nil, err
	}
	group := newVaneWithClock(option, emptyFallback, providers, rules, switchMargin, targetCooldown, stateTTL, maxStates, vaneSystemClock{})
	group.media = media
	group.exploration = exploration
	group.collectorSpec = collectorSpec
	group.gray = newVaneGrayObserver(vaneOption.GrayFailureObservation, group.clock, group.diagnostics)
	return group, nil
}

func newVaneWithClock(
	option GroupCommonOption,
	emptyFallback C.Proxy,
	providers []P.ProxyProvider,
	rules []vaneSceneRule,
	switchMargin float64,
	targetCooldown time.Duration,
	stateTTL time.Duration,
	maxStates int,
	clock vaneClock,
) *Vane {
	if clock == nil {
		clock = vaneSystemClock{}
	}
	group := &Vane{
		GroupBase: NewGroupBase(GroupBaseOption{
			Name:           option.Name,
			Type:           C.Vane,
			Hidden:         option.Hidden,
			Icon:           option.Icon,
			Filter:         option.Filter,
			ExcludeFilter:  option.ExcludeFilter,
			ExcludeType:    option.ExcludeType,
			TestTimeout:    option.TestTimeout,
			MaxFailedTimes: option.MaxFailedTimes,
			EmptyFallback:  emptyFallback,
			Providers:      providers,
		}),
		disableUDP:         option.DisableUDP,
		testURL:            option.URL,
		expectedStatus:     option.ExpectedStatus,
		rules:              rules,
		switchMargin:       int64(switchMargin*1_000_000 + 0.5),
		targetCooldown:     targetCooldown,
		stateTTL:           stateTTL,
		maxStates:          maxStates,
		clock:              clock,
		media:              defaultVaneMediaConfig(),
		explorationSince:   clock.Now().UTC(),
		diagnostics:        newVaneDiagnostics(option.Name, clock, nil),
		anchors:            make(map[vaneAnchorKey]vaneAnchor),
		cooldowns:          make(map[vaneCooldownKey]time.Time),
		mediaHints:         make(map[vaneMediaTargetKey]vaneMediaHint),
		mediaReconnects:    make(map[vaneMediaTargetKey]time.Time),
		mediaSlowCooldowns: make(map[vaneMediaCandidateKey]time.Time),
		mediaBudgets:       make(map[vaneMediaTargetKey]vaneMediaBudget),
		nodes:              make(map[string]*vaneNodeState),
		nodeControls:       make(map[string]*vaneNodeControlState),
		nodeIdentities:     make(map[string]string),
		churn:              make(map[vaneChurnKey]*vaneChurnState),
	}
	group.gray = newVaneGrayObserver(false, clock, group.diagnostics)
	learning := newVaneLearningState(option.Name, clock, nil, stateTTL, maxStates)
	group.attachLearningState(learning, learning.generation)
	group.refreshNodeIdentities(group.GetProxies(false))
	return group
}

func (a *Vane) attachLearningState(learning *vaneLearningState, generation uint64) {
	if learning == nil {
		learning = newVaneLearningState(a.Name(), a.clock, nil, a.stateTTL, a.maxStates)
	}
	a.learning = learning
	a.learningGeneration = generation
}

type vaneLearningActivationEntry struct {
	group       *Vane
	owner       *vaneLearningState
	diagnostics *vaneDiagnostics
	collector   *vaneNativeCollector
}

type VaneLearningActivation struct {
	entries []vaneLearningActivationEntry
	err     error
}

func (b *VaneLearningActivation) Err() error {
	if b == nil {
		return nil
	}
	return b.err
}

// PrepareVaneLearningStates performs persistence I/O before the tunnel
// publication lock is taken. It does not advance any active generation.
func PrepareVaneLearningStates(proxies map[string]C.Proxy) *VaneLearningActivation {
	batch := &VaneLearningActivation{}
	for _, proxy := range proxies {
		if vane, ok := proxy.Adapter().(*Vane); ok {
			vane.activationMu.Lock()
			activated := vane.learningActivated
			vane.activationMu.Unlock()
			if !activated {
				owner := acquireVaneLearningState(vane.Name(), vane.clock, vane.stateTTL, vane.maxStates)
				diagnostics := sharedVaneDiagnostics(vane.Name(), vane.clock)
				collector, err := acquireVaneNativeCollector(vane.collectorSpec)
				if err != nil {
					batch.err = errors.Join(batch.err, fmt.Errorf("vane %q native collector: %w", vane.Name(), err))
					continue
				}
				batch.entries = append(batch.entries, vaneLearningActivationEntry{group: vane, owner: owner, diagnostics: diagnostics, collector: collector})
			}
		}
	}
	if batch.err != nil {
		for _, entry := range batch.entries {
			releaseVaneNativeCollector(entry.collector)
		}
		batch.entries = nil
	}
	return batch
}

// Commit advances generations and attaches owners. Callers publish the proxy
// map under the same outer lock so routing cannot observe mismatched states.
func (b *VaneLearningActivation) Commit() {
	if b == nil {
		return
	}
	for _, entry := range b.entries {
		a := entry.group
		a.activationMu.Lock()
		if !a.learningActivated {
			generation := activateVaneLearningState(entry.owner, a.stateTTL, a.maxStates)
			a.mu.Lock()
			a.attachLearningState(entry.owner, generation)
			a.diagnostics = entry.diagnostics
			a.gray.setDiagnostics(entry.diagnostics)
			a.collector = entry.collector
			a.collectorReleased = false
			a.learningActivated = true
			a.mu.Unlock()
		}
		a.activationMu.Unlock()
	}
}

// ActivateVaneLearningStates remains the direct activation entry point for
// tests and embedders that do not publish through tunnel.UpdateProxies.
func ActivateVaneLearningStates(proxies map[string]C.Proxy) error {
	activation := PrepareVaneLearningStates(proxies)
	if err := activation.Err(); err != nil {
		return err
	}
	activation.Commit()
	return nil
}

func ReleaseVaneNativeCollectors(proxies map[string]C.Proxy) {
	for _, proxy := range proxies {
		if vane, ok := proxy.Adapter().(*Vane); ok {
			_ = vane.Close()
		}
	}
}

func vaneDurationOption(name string, seconds int, fallback time.Duration) (time.Duration, error) {
	if seconds < 0 {
		return 0, fmt.Errorf("%s must not be negative", name)
	}
	if seconds == 0 {
		return fallback, nil
	}
	if seconds > vaneMaximumConfigSeconds {
		return 0, fmt.Errorf("%s is too large", name)
	}
	return time.Duration(seconds) * time.Second, nil
}

func (a *Vane) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	decision := a.pickDecision(metadata, vaneTransportTCP, true, true)
	proxy, handoff, exploration := decision.proxy, decision.handoff, decision.exploration
	identity, nodeEpoch := decision.identity, decision.nodeEpoch
	start := a.clock.Now()
	attempt := a.newNativeAttempt(decision, metadata, vaneTransportTCP, start)
	grayAttempt := a.gray.newAttempt(vaneGraySelection{
		candidate: decision.proxy.Name(), identity: identity, transport: vaneTransportTCP,
		reportedAliveAtSelect: decision.reportedAliveAtSelection,
	}, metadata)
	conn, err := proxy.DialContext(ctx, metadata)
	finished := a.clock.Now()
	if err != nil {
		neutral := vaneNeutralDialError(ctx, err)
		attempt.setup(finished, vaneElapsed(start, finished), "error", false)
		if neutral {
			attempt.outcome(finished, "neutral", "dial_error", vaneNativeErrorClass(err))
			grayAttempt.settle("neutral")
			exploration.settle("exploration-neutral", "dial-neutral")
		} else {
			attempt.outcome(finished, "failure", "dial_error", vaneNativeErrorClass(err))
			grayAttempt.settle("failure")
			exploration.settle("exploration-failed", "dial-failed")
		}
		if handoff != nil && !vaneNeutralDialError(ctx, err) {
			a.diagnostics.record(vaneDiagnosticRecord{
				kind:        "handoff-dial-failed",
				reason:      "dial-failed",
				handoffID:   handoff.id,
				target:      handoff.target,
				bucket:      handoff.bucket,
				port:        handoff.port,
				from:        handoff.from,
				to:          handoff.to,
				previousBPS: handoff.previousBPS,
				force:       true,
			})
		}
		a.recordDialFailureEpoch(ctx, metadata, vaneTransportTCP, proxy, identity, nodeEpoch, err, finished)
		attempt.end(finished, "dial_error", vaneConnectionCloseObservation{Age: vaneElapsed(start, finished)})
		return nil, err
	}

	deferredAvailability := N.NeedHandshake(conn)
	attempt.setup(finished, vaneElapsed(start, finished), "returned", deferredAvailability)
	a.observeConnectEpochIdentity(proxy.Name(), identity, nodeEpoch, vaneTransportTCP, finished, vaneElapsed(start, finished))
	conn.AppendToChains(a)
	mediaFlow := newVaneMediaFlow(a, proxy.Name(), metadata, handoff)
	if mediaFlow != nil {
		mediaFlow.identity = identity
		mediaFlow.nodeEpoch = nodeEpoch
	}

	if deferredAvailability {
		conn = newFirstWriteVaneCallbackConn(conn, func(writeErr error) {
			now := a.clock.Now()
			if writeErr == nil {
				attempt.outcome(now, "success", "first_positive_write", "none")
				grayAttempt.settle("success")
				a.recordDialSuccessEpoch(metadata, vaneTransportTCP, proxy.Name(), identity, nodeEpoch, now)
				a.onDialSuccess()
				exploration.settle("exploration-succeeded", "first-write-succeeded")
				return
			}
			if mediaFlow != nil && mediaFlow.policyAborted() {
				attempt.outcome(now, "neutral", "policy_abort", "closed")
				grayAttempt.settle("neutral")
				exploration.settle("exploration-neutral", "policy-aborted")
				return
			}
			if vaneNeutralDialError(ctx, writeErr) {
				attempt.outcome(now, "neutral", "first_positive_write", vaneNativeErrorClass(writeErr))
				grayAttempt.settle("neutral")
				exploration.settle("exploration-neutral", "first-write-neutral")
				if mediaFlow != nil {
					mediaFlow.discardHandoff()
				}
				return
			}
			if mediaFlow != nil {
				mediaFlow.failHandoff("first-write-failed")
			}
			exploration.settle("exploration-failed", "first-write-failed")
			attempt.outcome(now, "failure", "first_positive_write", vaneNativeErrorClass(writeErr))
			grayAttempt.settle("failure")
			a.recordDialFailureEpoch(ctx, metadata, vaneTransportTCP, proxy, identity, nodeEpoch, writeErr, now)
		})
	} else {
		attempt.outcome(finished, "success", "dial_return", "none")
		grayAttempt.settle("success")
		a.recordDialSuccessEpoch(metadata, vaneTransportTCP, proxy.Name(), identity, nodeEpoch, finished)
		a.onDialSuccess()
		exploration.settle("exploration-succeeded", "dial-succeeded")
	}

	var onWindow func(vaneThroughputObservation) vanePolicyAction
	if mediaFlow != nil {
		onWindow = mediaFlow.observe
	}
	var churnMetadata *C.Metadata
	if metadata != nil {
		churnMetadata = &C.Metadata{
			Type:    metadata.Type,
			Host:    metadata.RuleHost(),
			DstIP:   metadata.DstIP,
			DstPort: metadata.DstPort,
			NetWork: metadata.NetWork,
		}
	}
	return newVaneControlledConnWithNative(conn, a.clock,
		func(elapsed time.Duration) {
			now := a.clock.Now()
			a.observeResponseEpochIdentity(proxy.Name(), identity, nodeEpoch, vaneTransportTCP, now, elapsed)
			attempt.response(now, elapsed)
		},
		func(bitsPerSecond float64) {
			a.observeThroughputEpochIdentity(proxy.Name(), identity, nodeEpoch, vaneTransportTCP, a.clock.Now(), bitsPerSecond)
		},
		onWindow,
		func(observation vaneConnectionCloseObservation) {
			a.observeChurnClose(proxy.Name(), churnMetadata, observation)
			a.gray.recordClose(vaneGraySelection{
				candidate: proxy.Name(), identity: identity, transport: vaneTransportTCP,
				reportedAliveAtSelect: decision.reportedAliveAtSelection,
			}, churnMetadata, observation)
		},
		func(observation vaneConnectionCloseObservation) {
			reason := "caller_close"
			if observation.PolicyClosed {
				reason = "policy_close"
			}
			attempt.end(a.clock.Now(), reason, observation)
		},
		func(observation vaneThroughputObservation, reason string) {
			attempt.throughput(a.clock.Now(), observation, reason)
		}), nil
}

func (a *Vane) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	decision := a.pickDecision(metadata, vaneTransportUDP, true, true)
	proxy, exploration := decision.proxy, decision.exploration
	identity, nodeEpoch := decision.identity, decision.nodeEpoch
	start := a.clock.Now()
	attempt := a.newNativeAttempt(decision, metadata, vaneTransportUDP, start)
	grayAttempt := a.gray.newAttempt(vaneGraySelection{
		candidate: decision.proxy.Name(), identity: identity, transport: vaneTransportUDP,
		reportedAliveAtSelect: decision.reportedAliveAtSelection,
	}, metadata)
	packetConn, err := proxy.ListenPacketContext(ctx, metadata)
	finished := a.clock.Now()
	if err != nil {
		neutral := vaneNeutralDialError(ctx, err)
		attempt.setup(finished, vaneElapsed(start, finished), "error", true)
		if neutral {
			attempt.outcome(finished, "neutral", "listen_error", vaneNativeErrorClass(err))
			grayAttempt.settle("neutral")
			exploration.settle("exploration-neutral", "listen-neutral")
		} else {
			attempt.outcome(finished, "failure", "listen_error", vaneNativeErrorClass(err))
			grayAttempt.settle("failure")
			exploration.settle("exploration-failed", "listen-failed")
		}
		a.recordDialFailureEpoch(ctx, metadata, vaneTransportUDP, proxy, identity, nodeEpoch, err, finished)
		attempt.end(finished, "listen_error", vaneConnectionCloseObservation{Age: vaneElapsed(start, finished)})
		return nil, err
	}

	attempt.setup(finished, vaneElapsed(start, finished), "returned", true)
	a.observeConnectEpochIdentity(proxy.Name(), identity, nodeEpoch, vaneTransportUDP, finished, vaneElapsed(start, finished))
	packetConn.AppendToChains(a)
	return newFirstPacketWriteVaneCallbackConnWithClose(packetConn, func(writeErr error) {
		now := a.clock.Now()
		if writeErr == nil {
			attempt.outcome(now, "success", "first_positive_datagram", "none")
			grayAttempt.settle("success")
			a.recordDialSuccessEpoch(metadata, vaneTransportUDP, proxy.Name(), identity, nodeEpoch, now)
			a.onDialSuccess()
			exploration.settle("exploration-succeeded", "first-packet-succeeded")
			return
		}
		if vaneNeutralDialError(ctx, writeErr) {
			attempt.outcome(now, "neutral", "first_positive_datagram", vaneNativeErrorClass(writeErr))
			grayAttempt.settle("neutral")
			exploration.settle("exploration-neutral", "first-packet-neutral")
		} else {
			attempt.outcome(now, "failure", "first_positive_datagram", vaneNativeErrorClass(writeErr))
			grayAttempt.settle("failure")
			exploration.settle("exploration-failed", "first-packet-failed")
		}
		a.recordDialFailureEpoch(ctx, metadata, vaneTransportUDP, proxy, identity, nodeEpoch, writeErr, now)
	}, func() {
		now := a.clock.Now()
		attempt.end(now, "caller_close", vaneConnectionCloseObservation{Age: vaneElapsed(start, now)})
	}), nil
}

func (a *Vane) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	transport := vaneTransportTCP
	if metadata != nil && metadata.NetWork == C.UDP {
		transport = vaneTransportUDP
	}
	// Unwrap is used by rule and protocol inspection. It must not mutate anchors,
	// evidence, cooldowns or candidate freshness.
	return a.pick(metadata, transport, touch, false)
}

func (a *Vane) Now() string {
	return a.pick(nil, vaneTransportTCP, false, false).Name()
}

func (a *Vane) SupportUDP() bool {
	if a.disableUDP {
		return false
	}
	for _, proxy := range a.GetProxies(false) {
		if proxy.SupportUDP() {
			return true
		}
	}
	return false
}

func (a *Vane) IsL3Protocol(metadata *C.Metadata) bool {
	transport := vaneTransportTCP
	if metadata != nil && metadata.NetWork == C.UDP {
		transport = vaneTransportUDP
	}
	return a.pick(metadata, transport, false, false).IsL3Protocol(metadata)
}

func (a *Vane) MarshalJSON() ([]byte, error) {
	all := make([]string, 0)
	for _, proxy := range a.GetProxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type":           a.Type().String(),
		"now":            a.Now(),
		"all":            all,
		"testUrl":        a.testURL,
		"expectedStatus": a.expectedStatus,
		"hidden":         a.Hidden(),
		"icon":           a.Icon(),
		"emptyFallback":  a.EmptyFallback().Name(),
	})
}

func (a *Vane) VaneDiagnostics() VaneDiagnosticsSnapshot {
	snapshot := a.diagnostics.snapshot()
	snapshot.Config = VaneDiagnosticConfig{
		MediaEnabled:                  a.media.enabled,
		MediaDomains:                  append([]string(nil), a.media.domains...),
		LowThroughputBPS:              a.media.lowThroughputBPS,
		LowWindows:                    a.media.lowWindows,
		MaxLowWindows:                 a.media.maxLowWindows,
		MinAgeMS:                      a.media.minAge.Milliseconds(),
		MinBytes:                      a.media.minBytes,
		DemandBPS:                     a.media.demandBPS,
		BufferGuardMS:                 a.media.bufferGuard.Milliseconds(),
		ReconnectCooldownMS:           a.media.reconnectCooldown.Milliseconds(),
		SlowCooldownMS:                a.media.slowCooldown.Milliseconds(),
		HintTTLMS:                     a.media.hintTTL.Milliseconds(),
		ReconnectBudget:               a.media.budgetMax,
		BudgetWindowMS:                a.media.budgetWindow.Milliseconds(),
		ChurnShadowEnabled:            true,
		ChurnWindowMS:                 vaneChurnWindow.Milliseconds(),
		ChurnLimit:                    vaneChurnLimit,
		ChurnMaxBytes:                 vaneChurnMaxDownloadBytes,
		ChurnMaxAgeMS:                 vaneChurnMaxLifetime.Milliseconds(),
		ExplorationEnabled:            a.exploration.enabled,
		ExplorationInterval:           int(a.exploration.interval),
		GrayFailureObservationEnabled: a.gray.isEnabled(),
	}

	now := a.clock.Now()
	a.mu.Lock()
	for _, hint := range a.mediaHints {
		if hint.expiresAt.After(now) {
			snapshot.Runtime.ActiveHints++
		}
	}
	for _, until := range a.mediaReconnects {
		if until.After(now) {
			snapshot.Runtime.ActiveReconnectCooldowns++
		}
	}
	for _, until := range a.mediaSlowCooldowns {
		if until.After(now) {
			snapshot.Runtime.ActiveSlowCooldowns++
		}
	}
	for _, budget := range a.mediaBudgets {
		if budget.startedAt.Add(a.media.budgetWindow).After(now) {
			snapshot.Runtime.ActiveBudgets++
		}
	}
	if a.exploration.enabled {
		snapshot.Runtime.ExplorationSince = a.explorationSince
		snapshot.Runtime.ExplorationScopes = make([]VaneDiagnosticExplorationScope, 0, vaneExplorationScopeCount)
		for index, state := range a.explorationScopes {
			transport, scene := vaneExplorationScopeValues(index)
			nextIn := a.exploration.interval - state.sinceLastExploration
			snapshot.Runtime.ExplorationScopes = append(snapshot.Runtime.ExplorationScopes, VaneDiagnosticExplorationScope{
				Transport:             transport.String(),
				Scene:                 scene.String(),
				EligibleSelections:    state.eligibleSelections,
				ExplorationSelections: state.explorationSelections,
				SinceLastExploration:  state.sinceLastExploration,
				NextIn:                nextIn,
			})
		}
	}
	a.mu.Unlock()
	snapshot.Runtime.ActiveChurnStates = a.activeChurnStates(now)
	snapshot.GrayFailure = a.gray.snapshot(snapshot.GrayFailure)
	snapshot.LearningPersistence = a.learning.status()
	return snapshot
}

func (a *Vane) Providers() []P.ProxyProvider { return a.providers }
func (a *Vane) Proxies() []C.Proxy           { return a.GetProxies(false) }

func (a *Vane) Close() error {
	// Learning generations share one canonical durable owner. The native
	// collector has independent reference counting, so a changed collector
	// spec can drain without stopping a collector reused by the new group.
	a.activationMu.Lock()
	var collector *vaneNativeCollector
	if !a.collectorReleased {
		collector = a.collector
		a.collectorReleased = true
	}
	a.activationMu.Unlock()
	releaseVaneNativeCollector(collector)
	return nil
}

func (a *Vane) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (map[string]uint16, error) {
	return a.GroupBase.URLTest(ctx, url, expectedStatus)
}

func (a *Vane) pick(metadata *C.Metadata, transport vaneTransport, touch, commit bool) C.Proxy {
	return a.pickInternalDecision(metadata, transport, touch, commit, false).proxy
}

func (a *Vane) pickWithHandoff(metadata *C.Metadata, transport vaneTransport, touch, commit bool) (C.Proxy, *vaneHandoffToken) {
	decision := a.pickInternalDecision(metadata, transport, touch, commit, true)
	return decision.proxy, decision.handoff
}

func (a *Vane) pickDecision(metadata *C.Metadata, transport vaneTransport, touch, commit bool) vanePickDecision {
	return a.pickInternalDecision(metadata, transport, touch, commit, true)
}

func (a *Vane) pickInternalDecision(metadata *C.Metadata, transport vaneTransport, touch, commit, claimHandoff bool) vanePickDecision {
	proxies := a.GetProxies(touch)
	if commit {
		a.refreshNodeIdentities(proxies)
	}
	compatible := make([]C.Proxy, 0, len(proxies))
	for _, proxy := range proxies {
		if transport == vaneTransportUDP && (a.disableUDP || !proxy.SupportUDP()) {
			continue
		}
		compatible = append(compatible, proxy)
	}
	if len(compatible) == 0 {
		return vanePickDecision{proxy: a.EmptyFallback()}
	}

	alive := make([]C.Proxy, 0, len(compatible))
	for _, proxy := range compatible {
		if proxy.AliveForTestUrl(a.testURL) {
			alive = append(alive, proxy)
		}
	}
	hasAlive := len(alive) > 0
	if hasAlive {
		compatible = alive
	}

	now := a.clock.Now()
	scene := classifyVaneScene(metadata, a.rules)
	target, port := vaneTarget(metadata)

	a.mu.Lock()
	a.learning.mu.Lock()
	if commit && transport == vaneTransportTCP && scene == vaneSceneMedia {
		if hinted, handoff := a.takeMediaHintLocked(target, port, compatible, now, claimHandoff); hinted != nil {
			state := a.ensureProxyNodeLocked(hinted, now)
			a.pruneLocked(now, proxies)
			a.learning.markDirtyLocked(now)
			a.learning.mu.Unlock()
			a.mu.Unlock()
			targetKey := a.mediaTargetKey(target, port)
			record := vaneDiagnosticRecord{
				kind:   "handoff-selected",
				target: target,
				bucket: targetKey.target,
				port:   port,
				to:     hinted.Name(),
				force:  true,
			}
			if handoff != nil {
				record.handoffID = handoff.id
				record.from = handoff.from
				record.previousBPS = handoff.previousBPS
			}
			a.diagnostics.record(record)
			return vanePickDecision{proxy: hinted, identity: state.identity, nodeEpoch: state.epoch, reportedAliveAtSelection: hasAlive, handoff: handoff}
		}
	}
	ranked := make([]vaneRankedProxy, 0, len(compatible))
	for _, proxy := range compatible {
		snapshot := vaneMetricsSnapshot{}
		identity := vaneProxyPersistentIdentity(proxy)
		state := a.nodes[proxy.Name()]
		if state != nil && state.identity != identity {
			state = nil
		}
		if state == nil {
			key := vaneLearningNodeKey(proxy.Name(), identity)
			state = a.learning.nodes[key]
			if state != nil && now.Sub(state.lastObservedAt) >= a.stateTTL {
				if commit {
					a.deleteLearningNodeLocked(key, state)
				}
				state = nil
			}
			if commit && state != nil {
				a.nodes[proxy.Name()] = state
			}
		}
		if state != nil {
			snapshot = state.snapshot(transport, now)
		}
		key := vaneCooldownKey{transport: transport, target: target, port: port, candidate: proxy.Name(), identity: identity}
		until := a.cooldownUntilLocked(key, now, commit)
		if transport == vaneTransportTCP && scene == vaneSceneMedia {
			if mediaUntil := a.mediaCooldownUntilLockedWithCleanup(target, port, proxy.Name(), vaneProxyPersistentIdentity(proxy), now, commit); mediaUntil.After(until) {
				until = mediaUntil
			}
		}
		ranked = append(ranked, vaneRankedProxy{
			proxy: proxy,
			vaneCandidateScore: vaneCandidateScore{
				name:        proxy.Name(),
				scoreMicros: scoreVaneMetrics(scene, snapshot),
			},
			cooldownUntil:          until,
			evidenceCoverageMicros: vaneEvidenceCoverageMicros(snapshot, transport, scene),
		})
	}

	sort.Slice(ranked, func(i, j int) bool {
		return compareVaneCandidateScores(ranked[i].vaneCandidateScore, ranked[j].vaneCandidateScore) < 0
	})

	anchorKey := vaneAnchorKey{transport: transport, scene: scene}
	anchor := a.anchors[anchorKey]
	anchorCoolingAnywhere := false
	if anchor.name != "" {
		for _, candidate := range ranked {
			if candidate.name == anchor.name {
				identity := vaneProxyPersistentIdentity(candidate.proxy)
				anchorCoolingAnywhere = a.candidateCoolingLocked(transport, anchor.name, identity, now, commit)
				if transport == vaneTransportTCP && scene == vaneSceneMedia {
					anchorCoolingAnywhere = anchorCoolingAnywhere || a.mediaCandidateCoolingLockedWithCleanup(anchor.name, vaneProxyPersistentIdentity(candidate.proxy), now, commit)
				}
				break
			}
		}
	}
	ranked = vanePreferAvailable(ranked)

	chosen := ranked[0]
	if anchor.name != "" {
		for _, candidate := range ranked {
			if candidate.name != anchor.name || candidate.cooldownUntil.After(now) {
				continue
			}
			if candidate.name == chosen.name || chosen.scoreMicros+a.switchMargin >= candidate.scoreMicros {
				chosen = candidate
			}
			break
		}
	}
	baseline := chosen
	var explorationSelection *vaneExplorationSelection
	if commit {
		explorationSelection = a.maybeSelectExplorationLocked(
			metadata, transport, scene, now, target, port, ranked, baseline, anchor, anchorCoolingAnywhere, hasAlive,
		)
		if explorationSelection != nil {
			for _, candidate := range ranked {
				if candidate.name == explorationSelection.toCandidate {
					chosen = candidate
					break
				}
			}
		}
	}

	var selectedState *vaneNodeState
	if commit {
		// A target-scoped failure is a one-off bypass, not evidence that the
		// scene's healthy global preference should change for every target. An
		// explicit exploration is an observation allocation, not an anchor vote.
		if explorationSelection == nil && (!anchorCoolingAnywhere || anchor.name == "" || chosen.name == anchor.name) {
			a.anchors[anchorKey] = vaneAnchor{name: chosen.name, scoreMicros: chosen.scoreMicros}
		}
		selectedState = a.ensureProxyNodeLocked(chosen.proxy, now)
		// State liveness follows provider membership, not this selection's
		// temporary health or transport-compatible subset.
		a.pruneLocked(now, proxies)
		a.learning.markDirtyLocked(now)
	}
	a.learning.mu.Unlock()
	a.mu.Unlock()
	decision := vanePickDecision{proxy: chosen.proxy}
	decision.reportedAliveAtSelection = hasAlive
	if selectedState != nil {
		decision.identity = selectedState.identity
		decision.nodeEpoch = selectedState.epoch
	}
	if explorationSelection != nil {
		decision.exploration = a.diagnostics.recordExplorationSelection(*explorationSelection)
	}
	return decision
}

func (a *Vane) cooldownUntilLocked(key vaneCooldownKey, now time.Time, cleanup bool) time.Time {
	until := a.cooldowns[key]
	keys := []vaneCooldownKey{key}
	if key.identity != "" {
		legacy := key
		legacy.identity = ""
		keys = append(keys, legacy)
		if legacyUntil := a.cooldowns[legacy]; legacyUntil.After(until) {
			until = legacyUntil
		}
	}
	if !until.After(now) {
		if cleanup {
			for _, candidateKey := range keys {
				if candidateUntil := a.cooldowns[candidateKey]; !candidateUntil.After(now) {
					delete(a.cooldowns, candidateKey)
				}
			}
		}
		return time.Time{}
	}
	return until
}

func (a *Vane) candidateCoolingLocked(transport vaneTransport, candidate, identity string, now time.Time, cleanup bool) bool {
	cooling := false
	for key, until := range a.cooldowns {
		if !until.After(now) {
			if cleanup {
				delete(a.cooldowns, key)
			}
			continue
		}
		if key.transport == transport && key.candidate == candidate && (identity == "" || key.identity == "" || key.identity == identity) {
			cooling = true
		}
	}
	return cooling
}

// vanePreferAvailable keeps score order when at least one candidate is not
// cooling down. If all candidates are cooling down, the earliest expiry wins;
// score and name remain deterministic tie breakers.
func vanePreferAvailable(ranked []vaneRankedProxy) []vaneRankedProxy {
	available := make([]vaneRankedProxy, 0, len(ranked))
	cooling := make([]vaneRankedProxy, 0, len(ranked))
	for _, candidate := range ranked {
		if candidate.cooldownUntil.IsZero() {
			available = append(available, candidate)
		} else {
			cooling = append(cooling, candidate)
		}
	}
	if len(available) > 0 {
		return available
	}
	sort.Slice(cooling, func(i, j int) bool {
		if !cooling[i].cooldownUntil.Equal(cooling[j].cooldownUntil) {
			return cooling[i].cooldownUntil.Before(cooling[j].cooldownUntil)
		}
		return compareVaneCandidateScores(cooling[i].vaneCandidateScore, cooling[j].vaneCandidateScore) < 0
	})
	return cooling
}

func vaneTarget(metadata *C.Metadata) (string, uint16) {
	if metadata == nil {
		return "", 0
	}
	if host := strings.ToLower(strings.TrimSuffix(metadata.RuleHost(), ".")); host != "" {
		return host, metadata.DstPort
	}
	if metadata.DstIP.IsValid() {
		return metadata.DstIP.String(), metadata.DstPort
	}
	return "", metadata.DstPort
}

func vaneElapsed(start, end time.Time) time.Duration {
	if end.Before(start) {
		return 0
	}
	return end.Sub(start)
}

func vaneNeutralDialError(ctx context.Context, err error) bool {
	_ = ctx
	if errors.Is(err, C.ErrNotSupport) || errors.Is(err, context.Canceled) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	return false
}

func (a *Vane) recordDialFailure(ctx context.Context, metadata *C.Metadata, transport vaneTransport, proxy C.Proxy, err error, now time.Time) {
	a.recordDialFailureEpoch(ctx, metadata, transport, proxy, vaneProxyPersistentIdentity(proxy), 0, err, now)
}

func (a *Vane) recordDialFailureEpoch(ctx context.Context, metadata *C.Metadata, transport vaneTransport, proxy C.Proxy, identity string, nodeEpoch uint64, err error, now time.Time) {
	if vaneNeutralDialError(ctx, err) {
		return
	}
	a.mu.Lock()
	a.learning.mu.Lock()
	state := a.ensureNodeIdentityEpochLocked(proxy.Name(), identity, nodeEpoch, now)
	if state == nil {
		a.learning.mu.Unlock()
		a.mu.Unlock()
		return
	}
	state.metrics(transport).observeFailure(now, true)
	a.learning.markDirtyLocked(now)
	if a.nodeIdentityIsCurrentLocked(proxy.Name(), identity) {
		target, port := vaneTarget(metadata)
		key := vaneCooldownKey{transport: transport, target: target, port: port, candidate: proxy.Name(), identity: identity}
		a.cooldowns[key] = now.Add(a.targetCooldown)
		a.pruneCooldownsLocked(now)
	}
	a.learning.mu.Unlock()
	a.mu.Unlock()
	a.onDialFailed(proxy.Type(), err, a.healthCheck)
}

func (a *Vane) recordDialSuccess(metadata *C.Metadata, transport vaneTransport, candidate, identity string, now time.Time) {
	a.recordDialSuccessEpoch(metadata, transport, candidate, identity, 0, now)
}

func (a *Vane) recordDialSuccessEpoch(metadata *C.Metadata, transport vaneTransport, candidate, identity string, nodeEpoch uint64, now time.Time) {
	a.mu.Lock()
	a.learning.mu.Lock()
	state := a.ensureNodeIdentityEpochLocked(candidate, identity, nodeEpoch, now)
	if state == nil {
		a.learning.mu.Unlock()
		a.mu.Unlock()
		return
	}
	state.metrics(transport).observeFailure(now, false)
	a.learning.markDirtyLocked(now)
	if a.nodeIdentityIsCurrentLocked(candidate, identity) {
		target, port := vaneTarget(metadata)
		delete(a.cooldowns, vaneCooldownKey{transport: transport, target: target, port: port, candidate: candidate, identity: identity})
	}
	a.learning.mu.Unlock()
	a.mu.Unlock()
}

func (a *Vane) nodeIdentity(name string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.nodeIdentities[name]
}

func (a *Vane) observeConnect(candidate string, transport vaneTransport, now time.Time, elapsed time.Duration) {
	a.observeConnectIdentity(candidate, a.nodeIdentity(candidate), transport, now, elapsed)
}

func (a *Vane) observeConnectIdentity(candidate, identity string, transport vaneTransport, now time.Time, elapsed time.Duration) {
	a.observeConnectEpochIdentity(candidate, identity, 0, transport, now, elapsed)
}

func (a *Vane) observeConnectEpochIdentity(candidate, identity string, nodeEpoch uint64, transport vaneTransport, now time.Time, elapsed time.Duration) {
	a.mu.Lock()
	a.learning.mu.Lock()
	state := a.ensureNodeIdentityEpochLocked(candidate, identity, nodeEpoch, now)
	if state == nil {
		a.learning.mu.Unlock()
		a.mu.Unlock()
		return
	}
	state.metrics(transport).observeConnect(now, elapsed)
	a.learning.markDirtyLocked(now)
	a.learning.mu.Unlock()
	a.mu.Unlock()
}

func (a *Vane) observeResponse(candidate string, transport vaneTransport, now time.Time, elapsed time.Duration) {
	a.observeResponseIdentity(candidate, a.nodeIdentity(candidate), transport, now, elapsed)
}

func (a *Vane) observeResponseIdentity(candidate, identity string, transport vaneTransport, now time.Time, elapsed time.Duration) {
	a.observeResponseEpochIdentity(candidate, identity, 0, transport, now, elapsed)
}

func (a *Vane) observeResponseEpochIdentity(candidate, identity string, nodeEpoch uint64, transport vaneTransport, now time.Time, elapsed time.Duration) {
	a.mu.Lock()
	a.learning.mu.Lock()
	state := a.ensureNodeIdentityEpochLocked(candidate, identity, nodeEpoch, now)
	if state == nil {
		a.learning.mu.Unlock()
		a.mu.Unlock()
		return
	}
	state.metrics(transport).observeResponse(now, elapsed)
	a.learning.markDirtyLocked(now)
	a.learning.mu.Unlock()
	a.mu.Unlock()
}

func (a *Vane) observeThroughput(candidate string, transport vaneTransport, now time.Time, bitsPerSecond float64) {
	a.observeThroughputIdentity(candidate, a.nodeIdentity(candidate), transport, now, bitsPerSecond)
}

func (a *Vane) observeThroughputIdentity(candidate, identity string, transport vaneTransport, now time.Time, bitsPerSecond float64) {
	a.observeThroughputEpochIdentity(candidate, identity, 0, transport, now, bitsPerSecond)
}

func (a *Vane) observeThroughputEpochIdentity(candidate, identity string, nodeEpoch uint64, transport vaneTransport, now time.Time, bitsPerSecond float64) {
	a.mu.Lock()
	a.learning.mu.Lock()
	state := a.ensureNodeIdentityEpochLocked(candidate, identity, nodeEpoch, now)
	if state == nil {
		a.learning.mu.Unlock()
		a.mu.Unlock()
		return
	}
	state.metrics(transport).observeThroughput(now, bitsPerSecond)
	if transport == vaneTransportTCP && a.nodeIdentityIsCurrentLocked(candidate, identity) {
		a.ensureNodeControlLocked(candidate, now).recentTCPThroughput = vaneRecentThroughput{bitsPerSecond: bitsPerSecond, observedAt: now}
	}
	a.learning.markDirtyLocked(now)
	a.learning.mu.Unlock()
	a.mu.Unlock()
}

type vanePersistentIdentityProxy interface {
	PersistentIdentity() string
}

func vaneProxyPersistentIdentity(proxy C.Proxy) string {
	if proxy == nil {
		return ""
	}
	if identified, ok := proxy.(vanePersistentIdentityProxy); ok {
		return identified.PersistentIdentity()
	}
	return ""
}

func (a *Vane) refreshNodeIdentities(proxies []C.Proxy) {
	identities := make(map[string]string, len(proxies))
	for _, proxy := range proxies {
		identities[proxy.Name()] = vaneProxyPersistentIdentity(proxy)
	}
	a.mu.Lock()
	for name := range a.nodeIdentities {
		if _, exists := identities[name]; !exists {
			delete(a.nodeIdentities, name)
			delete(a.nodes, name)
			delete(a.nodeControls, name)
		}
	}
	for name, identity := range identities {
		if previous, exists := a.nodeIdentities[name]; exists && previous != identity {
			delete(a.nodes, name)
			delete(a.nodeControls, name)
		}
		a.nodeIdentities[name] = identity
	}
	a.mu.Unlock()
}

func (a *Vane) ensureProxyNodeLocked(proxy C.Proxy, now time.Time) *vaneNodeState {
	identity := vaneProxyPersistentIdentity(proxy)
	a.nodeIdentities[proxy.Name()] = identity
	return a.ensureNodeIdentityLocked(proxy.Name(), identity, now)
}

func (a *Vane) ensureNodeLocked(name string, now time.Time) *vaneNodeState {
	return a.ensureNodeIdentityLocked(name, a.nodeIdentities[name], now)
}

func (a *Vane) ensureNodeIdentityLocked(name, identity string, now time.Time) *vaneNodeState {
	return a.ensureNodeIdentityEpochLocked(name, identity, 0, now)
}

// ensureNodeIdentityEpochLocked binds current work when expectedEpoch is zero.
// Delayed callbacks may update only the exact incarnation selected by a flow.
func (a *Vane) ensureNodeIdentityEpochLocked(name, identity string, expectedEpoch uint64, now time.Time) *vaneNodeState {
	if state := a.nodes[name]; state != nil && state.identity == identity {
		if expectedEpoch != 0 && state.epoch != expectedEpoch {
			return nil
		}
		state.lastObservedAt = now
		a.ensureNodeControlLocked(name, now)
		return state
	}
	key := vaneLearningNodeKey(name, identity)
	state := a.learning.nodes[key]
	if state == nil {
		epoch := a.learning.nodeEpochs[key]
		if epoch == 0 {
			epoch = 1
			a.learning.nodeEpochs[key] = epoch
		}
		if expectedEpoch != 0 && expectedEpoch != epoch {
			return nil
		}
		state = &vaneNodeState{name: name, identity: identity, epoch: epoch, lastObservedAt: now}
		a.learning.nodes[key] = state
	} else {
		if expectedEpoch != 0 && state.epoch != expectedEpoch {
			return nil
		}
		state.lastObservedAt = now
	}
	// A late callback for an identity that has already been replaced may append
	// durable evidence to its old record, but it must not rebind or recreate the
	// current generation's control state.
	if a.nodeIdentityIsCurrentLocked(name, identity) {
		a.nodes[name] = state
		a.ensureNodeControlLocked(name, now)
	}
	return state
}

func (a *Vane) deleteLearningNodeLocked(key string, state *vaneNodeState) {
	if state == nil {
		state = a.learning.nodes[key]
	}
	delete(a.learning.nodes, key)
	epoch := a.learning.nodeEpochs[key] + 1
	if epoch == 0 {
		epoch = 1
	}
	a.learning.nodeEpochs[key] = epoch
	if state != nil && a.nodes[state.name] == state {
		delete(a.nodes, state.name)
		delete(a.nodeControls, state.name)
	}
}

func (a *Vane) nodeIdentityIsCurrentLocked(name, identity string) bool {
	current, exists := a.nodeIdentities[name]
	return exists && current == identity
}

func (a *Vane) ensureNodeControlLocked(name string, now time.Time) *vaneNodeControlState {
	if state := a.nodeControls[name]; state != nil {
		state.lastSeen = now
		return state
	}
	state := &vaneNodeControlState{lastSeen: now}
	a.nodeControls[name] = state
	return state
}

func (a *Vane) pruneLocked(now time.Time, active []C.Proxy) {
	if a.learningGeneration != a.learning.generation {
		return
	}
	activeKeys := make(map[string]struct{}, len(active))
	for _, proxy := range active {
		activeKeys[vaneLearningNodeKey(proxy.Name(), vaneProxyPersistentIdentity(proxy))] = struct{}{}
	}
	for key, state := range a.learning.nodes {
		if _, ok := activeKeys[key]; ok {
			continue
		}
		if now.Sub(state.lastObservedAt) >= a.stateTTL {
			a.deleteLearningNodeLocked(key, state)
		}
	}
	if len(a.learning.nodes) <= a.maxStates {
		return
	}

	type staleNode struct {
		key  string
		seen time.Time
	}
	stale := make([]staleNode, 0, len(a.learning.nodes))
	for key, state := range a.learning.nodes {
		if _, ok := activeKeys[key]; !ok {
			stale = append(stale, staleNode{key: key, seen: state.lastObservedAt})
		}
	}
	sort.Slice(stale, func(i, j int) bool {
		if !stale[i].seen.Equal(stale[j].seen) {
			return stale[i].seen.Before(stale[j].seen)
		}
		return stale[i].key < stale[j].key
	})
	for _, node := range stale {
		if len(a.learning.nodes) <= a.maxStates {
			break
		}
		state := a.learning.nodes[node.key]
		a.deleteLearningNodeLocked(node.key, state)
	}
}

func (a *Vane) pruneCooldownsLocked(now time.Time) {
	for key, until := range a.cooldowns {
		if !until.After(now) {
			delete(a.cooldowns, key)
		}
	}
	if len(a.cooldowns) <= vaneDefaultMaxCooldowns {
		return
	}
	type cooldown struct {
		key   vaneCooldownKey
		until time.Time
	}
	entries := make([]cooldown, 0, len(a.cooldowns))
	for key, until := range a.cooldowns {
		entries = append(entries, cooldown{key: key, until: until})
	}
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].until.Equal(entries[j].until) {
			return entries[i].until.Before(entries[j].until)
		}
		left := entries[i].key
		right := entries[j].key
		leftKey := strconv.Itoa(int(left.transport)) + "\x00" + left.target + "\x00" + strconv.Itoa(int(left.port)) + "\x00" + left.candidate
		rightKey := strconv.Itoa(int(right.transport)) + "\x00" + right.target + "\x00" + strconv.Itoa(int(right.port)) + "\x00" + right.candidate
		return leftKey < rightKey
	})
	for _, entry := range entries[:len(entries)-vaneDefaultMaxCooldowns] {
		delete(a.cooldowns, entry.key)
	}
}
