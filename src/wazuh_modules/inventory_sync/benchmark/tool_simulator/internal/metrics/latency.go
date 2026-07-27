package metrics

import (
	"math"
	"sort"
	"sync"
)

// LatencyHist accumulates float64 observations. It is unbounded — the
// Python sender does the same (sessions × seconds is small enough). Use
// Reservoir for unbounded workloads if memory becomes an issue.
type LatencyHist struct {
	mu      sync.Mutex
	samples []float64
}

// NewLatencyHist returns an empty histogram.
func NewLatencyHist() *LatencyHist { return &LatencyHist{samples: make([]float64, 0, 256)} }

// Observe appends one sample.
func (h *LatencyHist) Observe(ms float64) {
	if math.IsNaN(ms) || math.IsInf(ms, 0) {
		return
	}
	h.mu.Lock()
	h.samples = append(h.samples, ms)
	h.mu.Unlock()
}

// LatencyStats matches the JSON shape Python emits under
// sender_summary.json.latency_ms.*.
type LatencyStats struct {
	Count int     `json:"count"`
	P50   float64 `json:"p50,omitempty"`
	P90   float64 `json:"p90,omitempty"`
	P95   float64 `json:"p95,omitempty"`
	P99   float64 `json:"p99,omitempty"`
	Max   float64 `json:"max,omitempty"`
	Avg   float64 `json:"avg,omitempty"`
}

// Snapshot returns the current percentile + summary stats. Empty
// histograms return just {"count":0}.
func (h *LatencyHist) Snapshot() LatencyStats {
	h.mu.Lock()
	s := make([]float64, len(h.samples))
	copy(s, h.samples)
	h.mu.Unlock()
	if len(s) == 0 {
		return LatencyStats{Count: 0}
	}
	sort.Float64s(s)
	q := func(p int) float64 {
		k := int(round(float64(p) / 100.0 * float64(len(s)-1)))
		if k < 0 {
			k = 0
		}
		if k >= len(s) {
			k = len(s) - 1
		}
		return round2(s[k])
	}
	sum := 0.0
	for _, v := range s {
		sum += v
	}
	return LatencyStats{
		Count: len(s),
		P50:   q(50),
		P90:   q(90),
		P95:   q(95),
		P99:   q(99),
		Max:   round2(s[len(s)-1]),
		Avg:   round2(sum / float64(len(s))),
	}
}

func round(x float64) float64  { return math.Floor(x + 0.5) }
func round2(x float64) float64 { return math.Round(x*100) / 100 }
