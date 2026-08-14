package metrics

import (
	"math/bits"
	"sync/atomic"
)

// Histogram records a value distribution over log-linear buckets and answers
// percentiles on demand, without keeping every sample. 32 octaves x 4
// sub-buckets = 128 buckets; the relative error is bounded by the bucket width
// (~12.5%), which is plenty for operational p50/p99. Same design as the
// server-side wazuh_metrics AtomicHistogram (docu/09, docu/11).
type Histogram struct {
	buckets [128]uint64
	count   uint64
	sum     uint64
	min     uint64
	max     uint64
}

// NewHistogram returns a ready histogram (min starts at max-uint64).
func NewHistogram() *Histogram {
	return &Histogram{min: ^uint64(0)}
}

// Observe records one value (microseconds, bytes, …). Lock-free.
func (h *Histogram) Observe(v uint64) {
	atomic.AddUint64(&h.buckets[bucketIndex(v)], 1)
	atomic.AddUint64(&h.count, 1)
	atomic.AddUint64(&h.sum, v)
	for {
		cur := atomic.LoadUint64(&h.max)
		if v <= cur || atomic.CompareAndSwapUint64(&h.max, cur, v) {
			break
		}
	}
	for {
		cur := atomic.LoadUint64(&h.min)
		if v >= cur || atomic.CompareAndSwapUint64(&h.min, cur, v) {
			break
		}
	}
}

// Snapshot is a point-in-time aggregate.
type Snapshot struct {
	Count uint64  `json:"count"`
	Sum   uint64  `json:"sum"`
	Min   uint64  `json:"min"`
	Max   uint64  `json:"max"`
	P50   uint64  `json:"p50"`
	P90   uint64  `json:"p90"`
	P95   uint64  `json:"p95"`
	P99   uint64  `json:"p99"`
	Avg   float64 `json:"avg"`
}

// Snapshot computes the aggregate over one consistent read of the buckets.
func (h *Histogram) Snapshot() Snapshot {
	var counts [128]uint64
	var total uint64
	for i := range counts {
		counts[i] = atomic.LoadUint64(&h.buckets[i])
		total += counts[i]
	}
	s := Snapshot{
		Count: atomic.LoadUint64(&h.count),
		Sum:   atomic.LoadUint64(&h.sum),
	}
	if total == 0 {
		return s
	}
	s.Min = atomic.LoadUint64(&h.min)
	s.Max = atomic.LoadUint64(&h.max)
	s.Avg = float64(s.Sum) / float64(s.Count)

	percentile := func(q float64) uint64 {
		rank := uint64(q * float64(total))
		if rank < total {
			rank++
		}
		var acc uint64
		for i := range counts {
			acc += counts[i]
			if acc >= rank {
				return bucketMid(i)
			}
		}
		return bucketMid(len(counts) - 1)
	}
	s.P50 = percentile(0.50)
	s.P90 = percentile(0.90)
	s.P95 = percentile(0.95)
	s.P99 = percentile(0.99)
	return s
}

const subBits = 2

func bucketIndex(v uint64) int {
	octave := uint(bits.Len64(v|1) - 1)
	var sub uint64
	if octave >= subBits {
		sub = (v >> (octave - subBits)) & 3
	} else {
		sub = v & 3
	}
	idx := int(octave<<subBits) | int(sub)
	if idx >= 128 {
		return 127
	}
	return idx
}

func bucketMid(idx int) uint64 {
	octave := uint(idx >> subBits)
	sub := uint64(idx & 3)
	if octave < subBits {
		return sub
	}
	lower := (4 + sub) << (octave - subBits)
	width := uint64(1) << (octave - subBits)
	return lower + width/2
}
