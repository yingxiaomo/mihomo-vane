package outboundgroup

import (
	"math"
	"sort"
	"time"
)

// Passive per-node throughput statistics — a 10th
// percentile, a rolling peak and an hourly profile. Everything here is
// observation only: selection never reads this struct, and scoreVaneMetrics
// is untouched. The feed is the RAW bps sample — the log-clamped value the
// scoring EMA sees never enters the profile.

const (
	vaneThroughputProfileRingSize    = 32
	vaneThroughputProfileRingWindow  = 6 * time.Hour
	vaneThroughputProfilePeakWindow  = 24 * time.Hour
	vaneThroughputProfileBucketCount = 24
	// Same shape as the loss EMA: early evidence weighs more, later
	// samples only nudge the estimate.
	vaneThroughputProfileAlphaBase  = 0.4
	vaneThroughputProfileAlphaDecay = 0.05
)

type vaneThroughputProfileSample struct {
	bps float64
	at  time.Time
}

type vaneThroughputProfileBucket struct {
	ema     float64
	samples int64
}

// vaneThroughputProfile holds the passive statistics for one node and one transport. It has
// no internal lock: callers feed it under the lock that already guards the
// owning vaneMetrics (the selector lock, like the scoring EMAs).
type vaneThroughputProfile struct {
	ring    [vaneThroughputProfileRingSize]vaneThroughputProfileSample
	ringAt  int
	ringLen int
	peakBPS float64
	peakAt  time.Time
	buckets [vaneThroughputProfileBucketCount]vaneThroughputProfileBucket
}

// observe folds one raw throughput sample into the ring, the peak and the
// hourly bucket. NaN, Inf and non-positive samples are rejected outright:
// they enter none of the three statistics.
func (p *vaneThroughputProfile) observe(now time.Time, bitsPerSecond float64) {
	if math.IsNaN(bitsPerSecond) || math.IsInf(bitsPerSecond, 0) || bitsPerSecond <= 0 {
		return
	}
	p.ring[p.ringAt] = vaneThroughputProfileSample{bps: bitsPerSecond, at: now}
	p.ringAt = (p.ringAt + 1) % vaneThroughputProfileRingSize
	if p.ringLen < vaneThroughputProfileRingSize {
		p.ringLen++
	}
	// An expired peak counts as nonexistent: the next sample becomes the new
	// peak even when it is lower than the stale one.
	peakExpired := !p.peakAt.IsZero() && now.Sub(p.peakAt) > vaneThroughputProfilePeakWindow
	if p.peakAt.IsZero() || peakExpired || bitsPerSecond > p.peakBPS {
		p.peakBPS = bitsPerSecond
		p.peakAt = now
	}
	bucket := &p.buckets[vaneThroughputProfileHourBucket(now)]
	if bucket.samples == 0 {
		bucket.ema = bitsPerSecond
	} else {
		alpha := vaneThroughputProfileAlphaBase / (1 + vaneThroughputProfileAlphaDecay*float64(bucket.samples))
		bucket.ema += alpha * (bitsPerSecond - bucket.ema)
	}
	bucket.samples++
}

// vaneThroughputProfileHourBucket maps a timestamp onto its local-hour bucket.
func vaneThroughputProfileHourBucket(now time.Time) int {
	return now.Local().Hour() % vaneThroughputProfileBucketCount
}

// percentile10 reads the 10th percentile of the bps samples inside the 6h
// window: sort the surviving samples, take index floor(0.1·(n-1)). The read
// is pure — diagnostics must never mutate selection state, so the ring is
// copied, not trimmed.
func (p *vaneThroughputProfile) percentile10(now time.Time) (float64, bool) {
	windowStart := now.Add(-vaneThroughputProfileRingWindow)
	samples := make([]float64, 0, p.ringLen)
	for index := 0; index < p.ringLen; index++ {
		idx := (p.ringAt - p.ringLen + index + vaneThroughputProfileRingSize) % vaneThroughputProfileRingSize
		if p.ring[idx].at.Before(windowStart) {
			continue
		}
		samples = append(samples, p.ring[idx].bps)
	}
	if len(samples) == 0 {
		return 0, false
	}
	sort.Float64s(samples)
	return samples[(len(samples)-1)/10], true
}

// peak reads the rolling peak. A peak older than 24h reads as nonexistent.
func (p *vaneThroughputProfile) peak(now time.Time) (float64, bool) {
	if p.peakAt.IsZero() || now.Sub(p.peakAt) > vaneThroughputProfilePeakWindow {
		return 0, false
	}
	return p.peakBPS, true
}

// hourProfile copies the 24 hourly-bucket EMAs.
func (p *vaneThroughputProfile) hourProfile() [vaneThroughputProfileBucketCount]float64 {
	var profile [vaneThroughputProfileBucketCount]float64
	for index := range p.buckets {
		profile[index] = p.buckets[index].ema
	}
	return profile
}

// hasData reports whether any throughput sample ever reached this struct.
func (p *vaneThroughputProfile) hasData() bool {
	return p.ringLen > 0
}

// Persistence. The throughput profile rides in the learning snapshot
// per node and transport as an additive omitempty field — old snapshots
// without it restore an empty profile and relearn from traffic.

type vanePersistedProfileRingSample struct {
	BPS float64   `json:"bps"`
	At  time.Time `json:"at"`
}

type vanePersistedProfile struct {
	Ring      []vanePersistedProfileRingSample          `json:"ring,omitempty"`
	PeakBPS   float64                                   `json:"peakBps,omitempty"`
	PeakAt    time.Time                                 `json:"peakAt,omitempty"`
	BucketEMA [vaneThroughputProfileBucketCount]float64 `json:"bucketEma"`
	BucketN   [vaneThroughputProfileBucketCount]int64   `json:"bucketN"`
}

// persistVaneProfile snapshots the profile: ring samples in ascending time order
// (expired ones dropped — they cannot contribute to any read anymore), the
// peak as-is (restore-time expiry reads handle staleness), buckets with their
// counts. A profile without data returns nil so the field stays omitted.
func persistVaneThroughputProfile(p *vaneThroughputProfile, now time.Time) *vanePersistedProfile {
	if p == nil || !p.hasData() {
		return nil
	}
	persisted := &vanePersistedProfile{PeakBPS: p.peakBPS, PeakAt: p.peakAt}
	windowStart := now.Add(-vaneThroughputProfileRingWindow)
	for index := 0; index < p.ringLen; index++ {
		idx := (p.ringAt - p.ringLen + index + vaneThroughputProfileRingSize) % vaneThroughputProfileRingSize
		if p.ring[idx].at.Before(windowStart) {
			continue
		}
		persisted.Ring = append(persisted.Ring, vanePersistedProfileRingSample{BPS: p.ring[idx].bps, At: p.ring[idx].at})
	}
	for bucketIndex := range p.buckets {
		persisted.BucketEMA[bucketIndex] = p.buckets[bucketIndex].ema
		persisted.BucketN[bucketIndex] = p.buckets[bucketIndex].samples
	}
	return persisted
}

// restoreVaneProfile rebuilds the profile from a snapshot. Ring samples feed the
// ring directly (not through observe: re-folding them would corrupt the peak
// and the buckets). Validation mirrors the node standard — NaN/Inf/<=0 and
// future-skewed timestamps drop; buckets with a positive count but a
// non-positive estimate clear; the bucket counts halve once so a rebuilt
// profile adapts quickly to post-restart traffic.
func restoreVaneThroughputProfile(persisted *vanePersistedProfile, now time.Time) vaneThroughputProfile {
	var p vaneThroughputProfile
	if persisted == nil {
		return p
	}
	for _, sample := range persisted.Ring {
		if math.IsNaN(sample.BPS) || math.IsInf(sample.BPS, 0) || sample.BPS <= 0 ||
			sample.At.IsZero() || sample.At.After(now.Add(vaneLearningFutureSkew)) {
			continue
		}
		p.ring[p.ringAt] = vaneThroughputProfileSample{bps: sample.BPS, at: sample.At}
		p.ringAt = (p.ringAt + 1) % vaneThroughputProfileRingSize
		if p.ringLen < vaneThroughputProfileRingSize {
			p.ringLen++
		}
	}
	if !math.IsNaN(persisted.PeakBPS) && !math.IsInf(persisted.PeakBPS, 0) && persisted.PeakBPS > 0 && !persisted.PeakAt.IsZero() {
		p.peakBPS = persisted.PeakBPS
		p.peakAt = persisted.PeakAt
	}
	for index := 0; index < vaneThroughputProfileBucketCount; index++ {
		ema, samples := persisted.BucketEMA[index], persisted.BucketN[index]
		if math.IsNaN(ema) || math.IsInf(ema, 0) || ema <= 0 || samples <= 0 {
			continue
		}
		halved := samples / 2
		if halved < 1 {
			halved = 1
		}
		p.buckets[index] = vaneThroughputProfileBucket{ema: ema, samples: halved}
	}
	return p
}

// vaneDiagnosticTransportProfile renders one transport's passive profile for the
// diagnostics snapshot. Pure read, same as percentile10.
func vaneDiagnosticTransportProfile(p *vaneThroughputProfile, now time.Time) VaneDiagnosticTransportProfile {
	transport := VaneDiagnosticTransportProfile{}
	if p10, ok := p.percentile10(now); ok {
		transport.P10BPS = p10
	}
	if peak, ok := p.peak(now); ok {
		transport.PeakBPS = peak
		transport.PeakAt = p.peakAt
	}
	profile := p.hourProfile()
	transport.Hours = profile[:]
	return transport
}
