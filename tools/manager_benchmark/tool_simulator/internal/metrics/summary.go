package metrics

import (
	"encoding/json"
	"os"
)

// Meta is the reproducibility block of sender_summary.json. The runner fills it.
type Meta struct {
	ScenarioName      string  `json:"scenario_name"`
	ScenarioPath      string  `json:"scenario_path"`
	Mode              string  `json:"mode"`
	Manager           string  `json:"manager"`
	Port              int     `json:"port"`
	RegPort           int     `json:"reg_port"`
	Target            string  `json:"target"`
	ClusterName       string  `json:"cluster_name"`
	AgentsRequested   int     `json:"agents_requested"`
	AgentsEnrolled    int     `json:"agents_enrolled"`
	AgentsFailed      int     `json:"agents_failed"`
	ConcurrentAgents  int     `json:"concurrent_agents"`
	RPSTarget         float64 `json:"requests_per_second_target"`
	KeepaliveInterval string  `json:"keepalive_interval"`
	ControlEnabled    bool    `json:"control_enabled"`
	ConnectionReuse   bool    `json:"connection_reuse"`
	Compression       string  `json:"compression"`
	DocumentSeed      uint64  `json:"document_seed"`
	StartTime         string  `json:"start_time"`
	EndTime           string  `json:"end_time"`
	DurationSec       float64 `json:"duration_sec"`
	SenderVersion     string  `json:"sender_version"`
	GoVersion         string  `json:"go_version"`
}

// WriteSummary serializes the whole run record to path. extra carries caller
// sections merged at the top level (today: the "expected" verdict); nil adds
// nothing.
func (r *Registry) WriteSummary(path string, meta Meta, extra map[string]any) error {
	global := r.GlobalSnapshot()
	doc := map[string]any{
		"meta":       meta,
		"totals":     bucketJSON(global),
		"by_fleet":   snapshotMapJSON(r.FleetSnapshots()),
		"by_lane":    snapshotMapJSON(r.LaneSnapshots()),
		"throughput": throughputJSON(global.C, meta.DurationSec, meta.RPSTarget),
		"latency_ms": latencyJSON(global),
	}
	for k, v := range extra {
		doc[k] = v
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func bucketJSON(s CountersSnapshot) map[string]any {
	c := s.C
	return map[string]any{
		"sessions": map[string]any{
			"sent": c.SessionsSent, "ok": c.SessionsOK, "noop": c.SessionsNoop,
			"s400": c.S400, "s401": c.S401, "s403": c.S403, "s409": c.S409, "s413": c.S413,
			"s500": c.S500, "s503": c.S503, "s503_retry_after": c.S503RetryAfter,
			"other": c.SessOther, "abandoned_on_drain": c.AbandonedOnDrain,
			"retries_feed": c.RetriesFeed, "retries_503": c.Retries503,
			"retries_exhausted": c.RetriesExhausted, "transport_errors": c.TransportErrors,
			"bytes_sent": c.BytesSent, "documents_sent": c.DocumentsSent,
		},
		"stateless": map[string]any{
			"sent": c.StatelessSent, "s202": c.St202, "s400": c.StBad400,
			"s413": c.StBad413, "s503": c.St503, "other": c.StOther, "events_sent": c.EventsSent,
		},
		// s200 is "queued", not "scanned": see RecordScanVD.
		"scan": map[string]any{
			"sent": c.ScanSent, "s200": c.Scan200, "s409": c.Scan409,
			"s503": c.Scan503, "other": c.ScanOther,
		},
		"control": map[string]any{
			"startup_ok": c.StartupOK, "startup_err": c.StartupErr,
			"notify_ok": c.NotifyOK, "notify_err": c.NotifyErr,
			"shutdown_ok": c.ShutdownOK, "shutdown_err": c.ShutdownErr,
		},
		"deletes":    map[string]any{"ok": c.DeletesOK, "err": c.DeletesErr},
		"latency_ms": latencyJSON(s),
	}
}

func snapshotMapJSON(m map[string]CountersSnapshot) map[string]any {
	out := make(map[string]any, len(m))
	for name, s := range m {
		out[name] = bucketJSON(s)
	}
	return out
}

func latencyJSON(s CountersSnapshot) map[string]any {
	out := make(map[string]any, len(s.Hists))
	for kind, hs := range s.Hists {
		if hs.Count == 0 {
			continue // do not clutter the summary with empty distributions
		}
		out[kind] = map[string]any{
			"count": hs.Count, "p50": msFloat(hs.P50), "p90": msFloat(hs.P90),
			"p95": msFloat(hs.P95), "p99": msFloat(hs.P99), "max": msFloat(hs.Max),
			"avg": hs.Avg / 1000.0,
		}
	}
	return out
}

func throughputJSON(c Counters, durationSec, rpsTarget float64) map[string]any {
	perSec := func(n uint64) float64 {
		if durationSec <= 0 {
			return 0
		}
		return float64(n) / durationSec
	}
	out := map[string]any{
		"sessions_per_second":  perSec(c.SessionsSent),
		"mib_per_second":       perSec(c.BytesSent) / (1024 * 1024),
		"documents_per_second": perSec(c.DocumentsSent),
		"events_per_second":    perSec(c.EventsSent),
	}
	if rpsTarget > 0 {
		out["achieved_vs_target"] = perSec(c.SessionsSent) / rpsTarget
	} else {
		out["achieved_vs_target"] = nil // unlimited: no target to divide by
	}
	return out
}

func msFloat(us uint64) float64 { return float64(us) / 1000.0 }
