package outboundgroup

import (
	"math"
	"sort"
	"time"
)

// Round6 item 1: P5 passive per-node throughput statistics — a 10th
// percentile, a rolling peak and an hourly profile. Everything here is
// observation only: selection never reads this struct, and scoreVaneMetrics
// is untouched. The feed is the RAW bps sample — the log-clamped value the
// scoring EMA sees never enters P5.

const (
	vaneP5RingSize    = 32
	vaneP5RingWindow  = 6 * time.Hour
	vaneP5PeakWindow  = 24 * time.Hour
	vaneP5BucketCount = 24
	// Same shape as the B2 loss EMA: early evidence weighs more, later
	// samples only nudge the estimate.
	vaneP5AlphaBase  = 0.4
	vaneP5AlphaDecay = 0.05
)

type vaneP5Sample struct {
	bps float64
	at  time.Time
}

type vaneP5Bucket struct {
	ema     float64
	samples int64
}

// vaneP5 holds the passive statistics for one node and one transport. It has
// no internal lock: callers feed it under the lock that already guards the
// owning vaneMetrics (the selector lock, like the scoring EMAs).
type vaneP5 struct {
	ring    [vaneP5RingSize]vaneP5Sample
	ringAt  int
	ringLen int
	peakBPS float64
	peakAt  time.Time
	buckets [vaneP5BucketCount]vaneP5Bucket
}

// observe folds one raw throughput sample into the ring, the peak and the
// hourly bucket. NaN, Inf and non-positive samples are rejected outright:
// they enter none of the three statistics.
func (p *vaneP5) observe(now time.Time, bitsPerSecond float64) {
	if math.IsNaN(bitsPerSecond) || math.IsInf(bitsPerSecond, 0) || bitsPerSecond <= 0 {
		return
	}
	p.ring[p.ringAt] = vaneP5Sample{bps: bitsPerSecond, at: now}
	p.ringAt = (p.ringAt + 1) % vaneP5RingSize
	if p.ringLen < vaneP5RingSize {
		p.ringLen++
	}
	// An expired peak counts as nonexistent: the next sample becomes the new
	// peak even when it is lower than the stale one.
	peakExpired := !p.peakAt.IsZero() && now.Sub(p.peakAt) > vaneP5PeakWindow
	if p.peakAt.IsZero() || peakExpired || bitsPerSecond > p.peakBPS {
		p.peakBPS = bitsPerSecond
		p.peakAt = now
	}
	bucket := &p.buckets[vaneP5HourBucket(now)]
	if bucket.samples == 0 {
		bucket.ema = bitsPerSecond
	} else {
		alpha := vaneP5AlphaBase / (1 + vaneP5AlphaDecay*float64(bucket.samples))
		bucket.ema += alpha * (bitsPerSecond - bucket.ema)
	}
	bucket.samples++
}

// vaneP5HourBucket maps a timestamp onto its local-hour bucket.
func vaneP5HourBucket(now time.Time) int {
	return now.Local().Hour() % vaneP5BucketCount
}

// percentile10 reads the 10th percentile of the bps samples inside the 6h
// window: sort the surviving samples, take index floor(0.1·(n-1)). The read
// is pure — diagnostics must never mutate selection state, so the ring is
// copied, not trimmed.
func (p *vaneP5) percentile10(now time.Time) (float64, bool) {
	windowStart := now.Add(-vaneP5RingWindow)
	samples := make([]float64, 0, p.ringLen)
	for index := 0; index < p.ringLen; index++ {
		idx := (p.ringAt - p.ringLen + index + vaneP5RingSize) % vaneP5RingSize
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
func (p *vaneP5) peak(now time.Time) (float64, bool) {
	if p.peakAt.IsZero() || now.Sub(p.peakAt) > vaneP5PeakWindow {
		return 0, false
	}
	return p.peakBPS, true
}

// hourProfile copies the 24 hourly-bucket EMAs.
func (p *vaneP5) hourProfile() [vaneP5BucketCount]float64 {
	var profile [vaneP5BucketCount]float64
	for index := range p.buckets {
		profile[index] = p.buckets[index].ema
	}
	return profile
}

// hasData reports whether any throughput sample ever reached this struct.
func (p *vaneP5) hasData() bool {
	return p.ringLen > 0
}

// vaneDiagnosticP5Transport renders one transport's passive profile for the
// diagnostics snapshot. Pure read, same as percentile10.
func vaneDiagnosticP5Transport(p *vaneP5, now time.Time) VaneDiagnosticP5Transport {
	transport := VaneDiagnosticP5Transport{}
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
