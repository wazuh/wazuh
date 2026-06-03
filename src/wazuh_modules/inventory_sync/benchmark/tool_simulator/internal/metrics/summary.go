package metrics

import (
	"encoding/json"
	"os"
	"time"
)

// SummaryMeta carries the run metadata.
type SummaryMeta struct {
	ScenarioName    string  `json:"scenario_name"`
	ScenarioPath    string  `json:"scenario_path"`
	Manager         string  `json:"manager"`
	Port            int     `json:"port"`
	RegPort         int     `json:"reg_port"`
	TotalAgents     int     `json:"total_agents"`
	AgentsRegistered int    `json:"agents_registered"`
	ParallelAgents  int     `json:"parallel_agents"`
	RepeatUntil     int     `json:"repeat_until"`
	DrainTimeout    int     `json:"drain_timeout"`
	StartTime       string  `json:"start_time"`
	EndTime         string  `json:"end_time"`
	DurationSec     float64 `json:"duration_sec"`
	Sender          string  `json:"sender"`
	Version         string  `json:"version"`
}

// Summary is the JSON shape consumed by result_summary.py.
type Summary struct {
	Meta      SummaryMeta              `json:"meta"`
	Messages  map[string]int64         `json:"messages"`
	LatencyMS map[string]LatencyStats  `json:"latency_ms"`
}

// WriteSummary persists the final cumulative counters + latency
// histograms to a JSON file. `tStart` and `tEnd` bound the run; everything
// else comes from cumulative + the LatencyHist snapshots.
func (c *Counters) WriteSummary(path string, meta SummaryMeta, tStart, tEnd time.Time, includeEngine bool) error {
	cum := c.Cumulative()
	startStats, endStats, sessStats := c.LatencySummaries()

	msgs := make(map[string]int64, int(counterCount))
	for i, name := range PythonHeader {
		msgs[name] = cum[i]
	}
	if includeEngine {
		base := len(PythonHeader)
		for i, name := range EngineHeader {
			msgs[name] = cum[base+i]
		}
	}

	meta.StartTime = tStart.UTC().Format(time.RFC3339)
	meta.EndTime = tEnd.UTC().Format(time.RFC3339)
	meta.DurationSec = round3(tEnd.Sub(tStart).Seconds())

	s := Summary{
		Meta:     meta,
		Messages: msgs,
		LatencyMS: map[string]LatencyStats{
			"start_ack":    startStats,
			"end_ack":      endStats,
			"session_full": sessStats,
		},
	}
	buf, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, buf, 0644)
}

func round3(x float64) float64 {
	return float64(int64(x*1000+0.5)) / 1000.0
}
