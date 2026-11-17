package outboundgroup

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

const (
	vaneDefaultRacingURL          = "https://speed.cloudflare.com/__down?bytes=4194304"
	vaneDefaultRacingBudgetMBHour = int64(120)
	vaneRacingProbeByteCap        = int64(4 * 1024 * 1024)
	vaneRacingProbeTimeout        = 4 * time.Second
	vaneRacingMaxChallengers      = 2
	vaneRacingCapabilityTTL       = 10 * time.Minute
	vaneRacingNoWinnerCooldown    = 30 * time.Second
	vaneRacingMinimumReservation  = int64(64 * 1024)
)

type vaneRacingMode uint8

const (
	vaneRacingOff vaneRacingMode = iota
	vaneRacingShadow
	vaneRacingOn
)

func (m vaneRacingMode) String() string {
	switch m {
	case vaneRacingShadow:
		return "shadow"
	case vaneRacingOn:
		return "on"
	default:
		return "off"
	}
}

type vaneRacingConfig struct {
	mode            vaneRacingMode
	url             *url.URL
	budgetBytesHour int64
	probe           vaneProbeFunc
}

type vaneProbeFunc func(context.Context, C.Proxy, *url.URL, int64) vaneProbeResult

type vaneCapabilityRecord struct {
	member        vaneMemberLease
	lowerBoundBPS float64
	bytes         int64
	observedAt    time.Time
}

type vaneRaceRequest struct {
	targetKey   vaneTargetKey
	mediaKey    vaneMediaTargetKey
	target      string
	port        uint16
	current     vaneMemberLease
	currentBPS  float64
	requiredBPS float64
	totalBytes  int64
	age         time.Duration
	lowWindows  int
	generation  uint64
	requestedAt time.Time
}

type vaneRaceResult struct {
	request       vaneRaceRequest
	taskID        uint64
	winner        vaneMemberLease
	lowerBoundBPS float64
	source        string
}

type vaneRaceCandidate struct {
	proxy         C.Proxy
	member        vaneMemberLease
	targetBPS     float64
	targetFresh   bool
	capabilityBPS float64
	capFresh      bool
	scoreMicros   int64
	blockUntil    time.Time
}

type vaneProbeResult struct {
	valid         bool
	reason        string
	bytes         int64
	duration      time.Duration
	lowerBoundBPS float64
	capHit        bool
}

type vaneRacingBudget struct {
	startedAt time.Time
	used      int64
	reserved  int64
}

type vaneRacingRuntime struct {
	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	inFlight      bool
	nextTaskID    uint64
	activeTasks   map[uint64]context.CancelFunc
	capabilities  map[vaneMemberLease]vaneCapabilityRecord
	noWinnerUntil map[vaneTargetKey]time.Time
	budget        vaneRacingBudget
	closed        bool
}

func newVaneRacingConfig(option VaneOption) (vaneRacingConfig, error) {
	config := vaneRacingConfig{mode: vaneRacingOff, budgetBytesHour: vaneDefaultRacingBudgetMBHour * 1024 * 1024}
	switch strings.ToLower(strings.TrimSpace(option.Racing)) {
	case "", "off":
		config.mode = vaneRacingOff
	case "shadow":
		config.mode = vaneRacingShadow
	case "on":
		config.mode = vaneRacingOn
	default:
		return vaneRacingConfig{}, fmt.Errorf("racing must be off, shadow, or on")
	}
	rawURL := strings.TrimSpace(option.RacingURL)
	if rawURL == "" {
		rawURL = vaneDefaultRacingURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Hostname() == "" {
		return vaneRacingConfig{}, fmt.Errorf("racing-url must be a complete HTTPS URL without userinfo")
	}
	if parsed.Fragment != "" {
		return vaneRacingConfig{}, fmt.Errorf("racing-url must not contain a fragment")
	}
	config.url = parsed
	if option.RacingBudgetMBHour < 0 {
		return vaneRacingConfig{}, fmt.Errorf("racing-budget-mb-hour must not be negative")
	}
	if option.RacingBudgetMBHour > 0 {
		if option.RacingBudgetMBHour > int64(^uint64(0)>>1)/(1024*1024) {
			return vaneRacingConfig{}, fmt.Errorf("racing-budget-mb-hour is too large")
		}
		config.budgetBytesHour = option.RacingBudgetMBHour * 1024 * 1024
	}
	config.probe = probeVaneCapability
	return config, nil
}

func newVaneRacingRuntime() vaneRacingRuntime {
	ctx, cancel := context.WithCancel(context.Background())
	return vaneRacingRuntime{
		ctx:           ctx,
		cancel:        cancel,
		activeTasks:   make(map[uint64]context.CancelFunc),
		capabilities:  make(map[vaneMemberLease]vaneCapabilityRecord),
		noWinnerUntil: make(map[vaneTargetKey]time.Time),
	}
}

func (a *Vane) stopRacing() {
	a.racingRuntime.mu.Lock()
	if a.racingRuntime.closed {
		a.racingRuntime.mu.Unlock()
		return
	}
	a.racingRuntime.closed = true
	cancel := a.racingRuntime.cancel
	cancels := make([]context.CancelFunc, 0, len(a.racingRuntime.activeTasks))
	for _, taskCancel := range a.racingRuntime.activeTasks {
		cancels = append(cancels, taskCancel)
	}
	a.racingRuntime.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	for _, taskCancel := range cancels {
		taskCancel()
	}
}

func (a *Vane) racingGenerationCurrent(generation uint64) bool {
	a.mu.Lock()
	a.learning.mu.Lock()
	current := generation == a.learningGeneration && generation == a.learning.generation
	a.learning.mu.Unlock()
	a.mu.Unlock()
	a.racingRuntime.mu.Lock()
	closed := a.racingRuntime.closed
	a.racingRuntime.mu.Unlock()
	return current && !closed
}

func (a *Vane) scheduleMediaRace(request vaneRaceRequest, callback func(vaneRaceResult)) (bool, string) {
	if a.racing.mode == vaneRacingOff || callback == nil || request.targetKey.targetScope == "" {
		return false, "racing-off"
	}
	now := a.clock.Now()
	a.racingRuntime.mu.Lock()
	if a.racingRuntime.closed {
		a.racingRuntime.mu.Unlock()
		return false, "group-closed"
	}
	if a.racingRuntime.inFlight {
		a.racingRuntime.mu.Unlock()
		return false, "race-in-flight"
	}
	if until := a.racingRuntime.noWinnerUntil[request.targetKey]; until.After(now) {
		a.racingRuntime.mu.Unlock()
		return false, "no-winner-cooldown"
	}
	delete(a.racingRuntime.noWinnerUntil, request.targetKey)
	a.racingRuntime.inFlight = true
	a.racingRuntime.nextTaskID++
	taskID := a.racingRuntime.nextTaskID
	ctx, cancel := context.WithCancel(a.racingRuntime.ctx)
	a.racingRuntime.activeTasks[taskID] = cancel
	a.racingRuntime.mu.Unlock()

	a.diagnostics.record(vaneDiagnosticRecord{
		kind:       "race-scheduled",
		handoffID:  taskID,
		target:     request.target,
		bucket:     request.targetKey.targetScope,
		port:       request.port,
		from:       request.current.name,
		bps:        request.currentBPS,
		totalBytes: request.totalBytes,
		age:        request.age,
		lowWindows: request.lowWindows,
	})
	go a.runMediaRace(ctx, cancel, taskID, request, callback)
	return true, ""
}

func (a *Vane) finishRaceTask(taskID uint64, request vaneRaceRequest, noWinner, stale bool) {
	now := a.clock.Now()
	a.racingRuntime.mu.Lock()
	delete(a.racingRuntime.activeTasks, taskID)
	a.racingRuntime.inFlight = false
	// A stale race says nothing about the current candidates, so it must not
	// suppress the next race for this target.
	if noWinner && !stale && !a.racingRuntime.closed {
		a.racingRuntime.noWinnerUntil[request.targetKey] = now.Add(vaneRacingNoWinnerCooldown)
	}
	a.racingRuntime.mu.Unlock()
}

func (a *Vane) runMediaRace(ctx context.Context, cancel context.CancelFunc, taskID uint64, request vaneRaceRequest, callback func(vaneRaceResult)) {
	defer cancel()
	noWinner := true
	stale := false
	defer func() { a.finishRaceTask(taskID, request, noWinner, stale) }()
	a.diagnostics.record(vaneDiagnosticRecord{
		kind:      "race-started",
		handoffID: taskID,
		target:    request.target,
		bucket:    request.targetKey.targetScope,
		port:      request.port,
		from:      request.current.name,
		bps:       request.currentBPS,
	})

	candidates, reason := a.snapshotRaceCandidates(request)
	if reason != "" {
		if reason == "stale-generation" {
			stale = true
			a.recordRaceDiscardedStale(request, "", taskID)
		} else {
			a.recordRaceNoWinner(request, reason, taskID)
		}
		return
	}
	for _, candidate := range candidates {
		if candidate.targetFresh && candidate.targetBPS >= request.requiredBPS {
			if !a.validateRaceWinner(request, candidate.member) {
				stale = true
				a.recordRaceDiscardedStale(request, candidate.member.name, taskID)
				return
			}
			noWinner = false
			a.recordRaceQualified(request, taskID, candidate.member, candidate.targetBPS, "target-evidence")
			callback(vaneRaceResult{request: request, taskID: taskID, winner: candidate.member, lowerBoundBPS: candidate.targetBPS, source: "target-evidence"})
			return
		}
	}
	for _, candidate := range candidates {
		if candidate.capFresh && candidate.capabilityBPS >= request.requiredBPS {
			if !a.validateRaceWinner(request, candidate.member) {
				stale = true
				a.recordRaceDiscardedStale(request, candidate.member.name, taskID)
				return
			}
			noWinner = false
			a.recordRaceQualified(request, taskID, candidate.member, candidate.capabilityBPS, "capability-cache")
			callback(vaneRaceResult{request: request, taskID: taskID, winner: candidate.member, lowerBoundBPS: candidate.capabilityBPS, source: "capability-cache"})
			return
		}
	}

	probeCandidates := make([]vaneRaceCandidate, 0, vaneRacingMaxChallengers)
	for _, candidate := range candidates {
		if candidate.capFresh {
			continue
		}
		probeCandidates = append(probeCandidates, candidate)
		if len(probeCandidates) == vaneRacingMaxChallengers {
			break
		}
	}
	if len(probeCandidates) == 0 {
		a.recordRaceNoWinner(request, "cached-below-required", taskID)
		return
	}

	limits := a.reserveRaceBudget(len(probeCandidates), a.clock.Now())
	if len(limits) == 0 {
		a.diagnostics.record(vaneDiagnosticRecord{kind: "race-budget-denied", handoffID: taskID, target: request.target, bucket: request.targetKey.targetScope, port: request.port, from: request.current.name, force: true})
		a.recordRaceNoWinner(request, "budget-denied", taskID)
		return
	}
	probeCandidates = probeCandidates[:len(limits)]

	type outcome struct {
		candidate vaneRaceCandidate
		result    vaneProbeResult
		limit     int64
	}
	outcomes := make(chan outcome, len(probeCandidates))
	probeCtx, probeCancel := context.WithCancel(ctx)
	defer probeCancel()
	for index, candidate := range probeCandidates {
		limit := limits[index]
		go func(candidate vaneRaceCandidate, limit int64) {
			probe := a.racing.probe
			if probe == nil {
				probe = probeVaneCapability
			}
			result := probe(probeCtx, candidate.proxy, a.racing.url, limit)
			a.settleRaceBudget(limit, result.bytes)
			outcomes <- outcome{candidate: candidate, result: result, limit: limit}
		}(candidate, limit)
	}

	remaining := len(probeCandidates)
	for remaining > 0 {
		select {
		case <-ctx.Done():
			a.diagnostics.record(vaneDiagnosticRecord{kind: "race-canceled", reason: "group-canceled", handoffID: taskID, target: request.target, bucket: request.targetKey.targetScope, port: request.port, from: request.current.name, force: true})
			return
		case outcome := <-outcomes:
			remaining--
			result := outcome.result
			kind := "race-probe-invalid"
			if result.valid {
				kind = "race-probe-success"
			} else if errors.Is(probeCtx.Err(), context.Canceled) && result.reason == "canceled" {
				kind = "race-probe-canceled"
			}
			a.diagnostics.record(vaneDiagnosticRecord{
				kind:       kind,
				reason:     result.reason,
				handoffID:  taskID,
				target:     request.target,
				bucket:     request.targetKey.targetScope,
				port:       request.port,
				from:       request.current.name,
				to:         outcome.candidate.member.name,
				bps:        result.lowerBoundBPS,
				totalBytes: result.bytes,
				age:        result.duration,
			})
			if result.valid && a.validateRaceWinner(request, outcome.candidate.member) {
				a.racingRuntime.mu.Lock()
				a.racingRuntime.capabilities[outcome.candidate.member] = vaneCapabilityRecord{
					member: outcome.candidate.member, lowerBoundBPS: result.lowerBoundBPS, bytes: result.bytes, observedAt: a.clock.Now(),
				}
				a.pruneCapabilitiesLocked(a.clock.Now())
				a.racingRuntime.mu.Unlock()
			}
			if !result.valid || result.lowerBoundBPS < request.requiredBPS {
				continue
			}
			if !a.validateRaceWinner(request, outcome.candidate.member) {
				stale = true
				a.recordRaceDiscardedStale(request, outcome.candidate.member.name, taskID)
				continue
			}
			probeCancel()
			noWinner = false
			a.recordRaceQualified(request, taskID, outcome.candidate.member, result.lowerBoundBPS, "probe")
			callback(vaneRaceResult{request: request, taskID: taskID, winner: outcome.candidate.member, lowerBoundBPS: result.lowerBoundBPS, source: "probe"})
			for remaining > 0 {
				canceledOutcome := <-outcomes
				remaining--
				a.diagnostics.record(vaneDiagnosticRecord{
					kind: "race-probe-canceled", reason: canceledOutcome.result.reason, handoffID: taskID,
					target: request.target, bucket: request.targetKey.targetScope, port: request.port,
					from: request.current.name, to: canceledOutcome.candidate.member.name,
					totalBytes: canceledOutcome.result.bytes, age: canceledOutcome.result.duration,
				})
			}
			return
		}
	}
	a.recordRaceNoWinner(request, "no-qualified-challenger", taskID)
}

func (a *Vane) snapshotRaceCandidates(request vaneRaceRequest) ([]vaneRaceCandidate, string) {
	proxies := a.GetProxies(false)
	type healthyProxy struct {
		proxy C.Proxy
		alive bool
	}
	healthy := make([]healthyProxy, 0, len(proxies))
	for _, proxy := range proxies {
		healthy = append(healthy, healthyProxy{proxy: proxy, alive: proxy.AliveForTestUrl(a.testURL)})
	}
	now := a.clock.Now()
	candidates := make([]vaneRaceCandidate, 0, len(proxies))
	a.mu.Lock()
	a.learning.mu.Lock()
	if request.generation != a.learningGeneration || request.generation != a.learning.generation || !a.memberLeaseCurrentLocked(request.current) {
		a.learning.mu.Unlock()
		a.mu.Unlock()
		return nil, "stale-generation"
	}
	for _, item := range healthy {
		proxy := item.proxy
		identity := vaneProxyPersistentIdentity(proxy)
		if proxy.Name() == request.current.name || !item.alive || identity == "" {
			continue
		}
		member := a.memberLeaseLocked(proxy.Name(), identity)
		if member.epoch == 0 {
			if epoch := a.learning.nodeEpochs[vaneLearningNodeKey(member.name, member.identity)]; epoch != 0 {
				member.epoch = epoch
			}
		}
		snapshot := vaneMetricsSnapshot{}
		if state := a.nodes[proxy.Name()]; state != nil && state.identity == identity {
			snapshot = state.snapshot(vaneTransportTCP, now)
		}
		targetBPS, targetFresh := a.targetEvidenceLocked(request.targetKey, member, now)
		blockUntil, _ := a.targetMemberBlockedLocked(request.targetKey, member, now)
		legacyKey := vaneMediaCandidateKey{vaneMediaTargetKey: request.mediaKey, candidate: member.name, identity: member.identity}
		if until := a.mediaSlowCooldowns[legacyKey]; until.After(blockUntil) {
			blockUntil = until
		}
		candidates = append(candidates, vaneRaceCandidate{
			proxy: proxy, member: member, targetBPS: targetBPS, targetFresh: targetFresh,
			scoreMicros: scoreVaneMetrics(vaneSceneMedia, snapshot), blockUntil: blockUntil,
		})
	}
	a.learning.mu.Unlock()
	a.mu.Unlock()
	if len(candidates) == 0 {
		return nil, "no-challenger"
	}

	a.racingRuntime.mu.Lock()
	for index := range candidates {
		capability, ok := a.racingRuntime.capabilities[candidates[index].member]
		if ok && !capability.observedAt.IsZero() && now.Sub(capability.observedAt) <= vaneRacingCapabilityTTL {
			candidates[index].capFresh = true
			candidates[index].capabilityBPS = capability.lowerBoundBPS
		}
	}
	a.racingRuntime.mu.Unlock()

	available := candidates[:0]
	blocked := make([]vaneRaceCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.blockUntil.After(now) {
			blocked = append(blocked, candidate)
		} else {
			available = append(available, candidate)
		}
	}
	if len(available) == 0 {
		sort.Slice(blocked, func(i, j int) bool {
			if !blocked[i].blockUntil.Equal(blocked[j].blockUntil) {
				return blocked[i].blockUntil.Before(blocked[j].blockUntil)
			}
			return blocked[i].member.name < blocked[j].member.name
		})
		available = append(available, blocked[0])
	}
	candidates = available
	sort.SliceStable(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if left.targetFresh != right.targetFresh {
			return left.targetFresh
		}
		if left.targetFresh && left.targetBPS != right.targetBPS {
			return left.targetBPS > right.targetBPS
		}
		if left.capFresh != right.capFresh {
			return left.capFresh
		}
		if left.capFresh && left.capabilityBPS != right.capabilityBPS {
			return left.capabilityBPS > right.capabilityBPS
		}
		if left.scoreMicros != right.scoreMicros {
			return left.scoreMicros < right.scoreMicros
		}
		return left.member.name < right.member.name
	})
	return candidates, ""
}

func (a *Vane) validateRaceWinner(request vaneRaceRequest, member vaneMemberLease) bool {
	if !a.racingGenerationCurrent(request.generation) {
		return false
	}
	release, ok := a.lockVaneMediaIdentities(map[string]string{
		request.current.name: request.current.identity,
		member.name:          member.identity,
	})
	if !ok {
		return false
	}
	defer release()
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.memberLeaseCurrentLocked(request.current) && a.memberLeaseCurrentLocked(member)
}

func (a *Vane) reserveRaceBudget(count int, now time.Time) []int64 {
	if count <= 0 {
		return nil
	}
	a.racingRuntime.mu.Lock()
	defer a.racingRuntime.mu.Unlock()
	budget := &a.racingRuntime.budget
	if budget.startedAt.IsZero() || (!budget.startedAt.Add(time.Hour).After(now) && budget.reserved == 0) {
		*budget = vaneRacingBudget{startedAt: now}
	}
	available := a.racing.budgetBytesHour - budget.used - budget.reserved
	limits := make([]int64, 0, count)
	for len(limits) < count && available >= vaneRacingMinimumReservation {
		limit := vaneRacingProbeByteCap
		if available < limit {
			limit = available
		}
		limits = append(limits, limit)
		budget.reserved += limit
		available -= limit
	}
	return limits
}

func (a *Vane) settleRaceBudget(reserved, actual int64) {
	if actual < 0 {
		actual = 0
	}
	if actual > reserved {
		actual = reserved
	}
	a.racingRuntime.mu.Lock()
	if a.racingRuntime.budget.reserved >= reserved {
		a.racingRuntime.budget.reserved -= reserved
	} else {
		a.racingRuntime.budget.reserved = 0
	}
	a.racingRuntime.budget.used += actual
	a.racingRuntime.mu.Unlock()
}

func (a *Vane) pruneCapabilitiesLocked(now time.Time) {
	for key, record := range a.racingRuntime.capabilities {
		if record.observedAt.IsZero() || now.Sub(record.observedAt) > vaneRacingCapabilityTTL {
			delete(a.racingRuntime.capabilities, key)
		}
	}
	if len(a.racingRuntime.capabilities) <= vaneTargetStateLimit {
		return
	}
	type entry struct {
		key     vaneMemberLease
		time    time.Time
		keyText string
	}
	entries := make([]entry, 0, len(a.racingRuntime.capabilities))
	for key, value := range a.racingRuntime.capabilities {
		entries = append(entries, entry{key: key, time: value.observedAt, keyText: fmt.Sprint(key)})
	}
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].time.Equal(entries[j].time) {
			return entries[i].time.Before(entries[j].time)
		}
		return entries[i].keyText < entries[j].keyText
	})
	for i := 0; i < len(entries)-vaneTargetStateLimit; i++ {
		delete(a.racingRuntime.capabilities, entries[i].key)
	}
}

func (a *Vane) recordRaceQualified(request vaneRaceRequest, taskID uint64, member vaneMemberLease, bps float64, source string) {
	a.diagnostics.record(vaneDiagnosticRecord{
		kind:      "race-candidate-qualified",
		reason:    source,
		handoffID: taskID,
		target:    request.target,
		bucket:    request.targetKey.targetScope,
		port:      request.port,
		from:      request.current.name,
		to:        member.name,
		bps:       bps,
		force:     true,
	})
}

func (a *Vane) recordRaceNoWinner(request vaneRaceRequest, reason string, taskID uint64) {
	a.diagnostics.record(vaneDiagnosticRecord{
		kind:      "race-no-winner",
		reason:    reason,
		handoffID: taskID,
		target:    request.target,
		bucket:    request.targetKey.targetScope,
		port:      request.port,
		from:      request.current.name,
		bps:       request.currentBPS,
		force:     true,
	})
}

// recordRaceDiscardedStale marks a race whose result belonged to a superseded
// generation. It never suppresses future races: a stale outcome says nothing
// about the current candidates.
func (a *Vane) recordRaceDiscardedStale(request vaneRaceRequest, to string, taskID uint64) {
	a.diagnostics.record(vaneDiagnosticRecord{
		kind:      "race-canceled",
		reason:    "stale-generation",
		handoffID: taskID,
		target:    request.target,
		bucket:    request.targetKey.targetScope,
		port:      request.port,
		from:      request.current.name,
		to:        to,
		force:     true,
	})
}

func probeVaneCapability(ctx context.Context, proxy C.Proxy, endpoint *url.URL, byteLimit int64) vaneProbeResult {
	return probeVaneCapabilityWithTLSConfig(ctx, proxy, endpoint, byteLimit, nil)
}

// vaneRaceLeaseID renders the log-friendly lease ID of a race-sourced handoff
// so one string identifies the race behind a committed lease.
func vaneRaceLeaseID(generation, taskID uint64) string {
	if taskID == 0 {
		return ""
	}
	return fmt.Sprintf("vane-race-%d-%d", generation, taskID)
}

func probeVaneCapabilityWithTLSConfig(ctx context.Context, proxy C.Proxy, endpoint *url.URL, byteLimit int64, tlsConfig *tls.Config) vaneProbeResult {
	if proxy == nil || endpoint == nil || endpoint.Scheme != "https" || byteLimit <= 0 {
		return vaneProbeResult{reason: "invalid-request"}
	}
	probeCtx, cancel := context.WithTimeout(ctx, vaneRacingProbeTimeout)
	defer cancel()
	port := uint16(443)
	if rawPort := endpoint.Port(); rawPort != "" {
		parsed, err := strconv.ParseUint(rawPort, 10, 16)
		if err != nil || parsed == 0 {
			return vaneProbeResult{reason: "invalid-port"}
		}
		port = uint16(parsed)
	}
	metadata := &C.Metadata{NetWork: C.TCP, Type: C.INNER}
	if err := metadata.SetRemoteAddress(net.JoinHostPort(endpoint.Hostname(), strconv.Itoa(int(port)))); err != nil {
		return vaneProbeResult{reason: "invalid-address"}
	}
	conn, err := proxy.DialContext(probeCtx, metadata)
	if err != nil {
		if errors.Is(probeCtx.Err(), context.Canceled) {
			return vaneProbeResult{reason: "canceled"}
		}
		if errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
			return vaneProbeResult{reason: "dial-timeout"}
		}
		return vaneProbeResult{reason: "dial-error"}
	}
	if conn == nil {
		return vaneProbeResult{reason: "nil-connection"}
	}
	defer conn.Close()
	stopCancel := context.AfterFunc(probeCtx, func() { _ = conn.Close() })
	defer stopCancel()
	_ = conn.SetDeadline(time.Now().Add(vaneRacingProbeTimeout))
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	tlsConfig.ServerName = endpoint.Hostname()
	tlsConfig.MinVersion = tls.VersionTLS12
	tlsConfig.NextProtos = []string{"http/1.1"}
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(probeCtx); err != nil {
		if errors.Is(probeCtx.Err(), context.Canceled) {
			return vaneProbeResult{reason: "canceled"}
		}
		if errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
			return vaneProbeResult{reason: "tls-timeout"}
		}
		return vaneProbeResult{reason: "tls-error"}
	}
	if negotiated := tlsConn.ConnectionState().NegotiatedProtocol; negotiated != "" && negotiated != "http/1.1" {
		return vaneProbeResult{reason: "alpn-mismatch"}
	}
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return vaneProbeResult{reason: "request-error"}
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", "mihomo-vane-racing/1")
	request.Close = true
	if err := request.Write(tlsConn); err != nil {
		if errors.Is(probeCtx.Err(), context.Canceled) {
			return vaneProbeResult{reason: "canceled"}
		}
		return vaneProbeResult{reason: "write-error"}
	}
	response, err := http.ReadResponse(bufio.NewReader(tlsConn), request)
	if err != nil {
		if errors.Is(probeCtx.Err(), context.Canceled) {
			return vaneProbeResult{reason: "canceled"}
		}
		if errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
			return vaneProbeResult{reason: "header-timeout"}
		}
		return vaneProbeResult{reason: "response-error"}
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return vaneProbeResult{reason: "redirect-disallowed"}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return vaneProbeResult{reason: "non-2xx"}
	}
	started := time.Now()
	buffer := make([]byte, 32*1024)
	var total int64
	for total < byteLimit {
		want := int64(len(buffer))
		if remaining := byteLimit - total; remaining < want {
			want = remaining
		}
		n, readErr := response.Body.Read(buffer[:want])
		if n > 0 {
			total += int64(n)
		}
		if total >= byteLimit {
			duration := time.Since(started)
			if duration <= 0 {
				duration = time.Nanosecond
			}
			return vaneProbeResult{
				valid: true, reason: "cap-hit", bytes: total, duration: duration,
				lowerBoundBPS: 8 * float64(total) / duration.Seconds(), capHit: true,
			}
		}
		if readErr != nil {
			duration := time.Since(started)
			if total == 0 && errors.Is(readErr, io.EOF) {
				return vaneProbeResult{reason: "zero-bytes", duration: duration}
			}
			if errors.Is(probeCtx.Err(), context.Canceled) {
				return vaneProbeResult{reason: "canceled", bytes: total, duration: duration}
			}
			if errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
				return vaneProbeResult{reason: "read-timeout", bytes: total, duration: duration}
			}
			if errors.Is(readErr, io.EOF) {
				return vaneProbeResult{reason: "early-eof", bytes: total, duration: duration}
			}
			return vaneProbeResult{reason: "read-error", bytes: total, duration: duration}
		}
		if n == 0 {
			return vaneProbeResult{reason: "zero-progress", bytes: total, duration: time.Since(started)}
		}
	}
	return vaneProbeResult{reason: "internal-error", bytes: total, duration: time.Since(started)}
}
