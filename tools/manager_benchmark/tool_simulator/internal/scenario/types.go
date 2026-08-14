// Package scenario loads and strictly validates a run description. The model is
// lanes and fleets (docu/07-scenario-schema.md): a run may put heterogeneous
// load on the manager at once, so a scenario names reusable lanes and one or
// more fleets that each run a set of those lanes in parallel.
package scenario

import (
	"encoding/json"
	"fmt"
	"time"
)

// Duration unmarshals a Go duration string ("20s", "5m").
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// Scenario is the whole run description.
type Scenario struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Mode        string            `json:"mode"` // "uds" | "agent" | "" (supplied per run)
	Defaults    Defaults          `json:"defaults"`
	Lanes       map[string][]Step `json:"lanes"`
	Fleets      []Fleet           `json:"fleets"`
	Pacing      Pacing            `json:"pacing"`
	Expected    *Expected         `json:"expected"`
}

// Defaults are inherited by every fleet and step unless overridden.
type Defaults struct {
	Module      string   `json:"module"`
	Option      string   `json:"option"`
	// ClusterName is the only cluster field a session declares. cluster_node was
	// retired: the manager never validated it and is dropping its last consumer,
	// and the value the tool used to send was read out of the manager's own
	// config and handed straight back to it. See the conventions in docu/07.
	ClusterName string   `json:"cluster_name"`
	Documents   *DocSpec `json:"documents"`
	Control     Control  `json:"control"`
	Retry       Retry    `json:"retry"`
	// Compression encodes every /stateful session body. "" (absent) is the
	// DEFAULT: zstd whenever the transport supports it -- that is what a real
	// 5.x agent does -- and plain in uds mode, whose ingress has no decoder.
	// "none" opts out explicitly; "zstd" forces it and therefore requires
	// agent mode. remoted decompresses before relaying, and the CMAC signs the
	// compressed bytes (they ARE the wire bytes), matching its contract. `raw`
	// steps are never compressed: their bodies must reach the server
	// byte-exact. CompressionFor resolves the effective value.
	Compression string `json:"compression"`
}

// CompressionFor resolves the effective session-body encoding for a transport
// mode: the default follows what a real agent would do on that transport.
func (d Defaults) CompressionFor(mode string) string {
	switch d.Compression {
	case "none":
		return ""
	case "":
		if mode == "agent" {
			return "zstd"
		}
		return ""
	default:
		return d.Compression
	}
}

// Retry governs re-sending a /stateful session the server answered 503 WITHOUT
// a Retry-After header (backpressure: pipeline full, scan lane full, indexer
// unhealthy). Retrying is what a real agent does, so it defaults to ON; the
// scenarios whose purpose is to COUNT sheds disable it explicitly. The
// 503+Retry-After path (feed still downloading) keeps its own rules: the header
// dictates the delay and --feed-timeout bounds the budget.
//
// Pointer fields distinguish "absent" (take the default) from an explicit
// false/0 in the file.
type Retry struct {
	Enabled     *bool    `json:"enabled"`      // default true
	Interval    Duration `json:"interval"`     // delay between attempts; default 500ms
	MaxAttempts *int     `json:"max_attempts"` // total send attempts; default 10, 0 = unbounded
}

// RetryEnabled reports whether bare-503 sessions are re-sent (default true).
func (r Retry) RetryEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

// RetryInterval is the delay between bare-503 attempts (default 500ms).
func (r Retry) RetryInterval() time.Duration {
	if r.Interval.D() <= 0 {
		return 500 * time.Millisecond
	}
	return r.Interval.D()
}

// RetryMaxAttempts is the total number of send attempts for one session
// (default 10). Zero means unbounded: only the drain/context stops the loop.
func (r Retry) RetryMaxAttempts() int {
	if r.MaxAttempts == nil {
		return 10
	}
	if *r.MaxAttempts < 0 {
		return 0
	}
	return *r.MaxAttempts
}

// DocSpecDefault returns the default document spec (may be nil).
func (d Defaults) DocSpecDefault() *DocSpec { return d.Documents }

// Control governs the keepalive traffic (agent mode only).
type Control struct {
	Enabled           bool     `json:"enabled"`
	KeepaliveInterval Duration `json:"keepalive_interval"`
	SendHostInfo      bool     `json:"send_host_info"`
	StartupVersion    string   `json:"startup_version"`
}

// Fleet is a group of agents sharing a lane set and a metadata profile.
type Fleet struct {
	Name    string    `json:"name"`
	Agents  int       `json:"agents"`
	FirstID int       `json:"first_id"`
	Lanes   []string  `json:"lanes"`
	Start   StartMeta `json:"start"`
}

// StartMeta is the per-fleet metadata stamped onto that fleet's sessions.
type StartMeta struct {
	Architecture string `json:"architecture"`
	OSName       string `json:"osname"`
	OSPlatform   string `json:"osplatform"`
	OSType       string `json:"ostype"`
	OSVersion    string `json:"osversion"`
	AgentVersion string `json:"agentversion"`
}

// Step is one action a lane walks. Its kind selects which fields matter.
type Step struct {
	Kind      string   `json:"kind"`
	Module    string   `json:"module"`
	Option    string   `json:"option"`
	Indices   []string `json:"indices"`
	Documents *DocSpec `json:"documents"`
	Contexts  *DocSpec `json:"contexts"`
	GlobalVer uint64   `json:"global_version"`
	// FeedOffset overrides the feed offset a VD step declares: Start.feed_offset
	// for a VDFirst/VDSync session, or the request body's feed_offset for a
	// "scan_vd" step (the same resolution order, so one field pins both). Nil
	// (the default) defers to -vd-feed-offset, or the value the agent's
	// keepalive loop learned from /control's vd_feed_offset (agent mode only
	// -- see docu/03-control-protocol.md); a pointer distinguishes "not set"
	// from "deliberately set to 0" (e.g. a version_mismatch contract test
	// against a manager whose real offset has already moved past zero).
	FeedOffset   *uint64  `json:"feed_offset,omitempty"`
	Checksum     string   `json:"checksum"` // "correct" | "mismatch" | literal
	Raw          string   `json:"raw"`      // for kind "raw": not_full_session|garbage|empty|oversized
	Dump         string   `json:"dump"`     // path to a captured-session dump to replay (kind delta/full_resync)
	RepeatCount  int      `json:"repeat_count"`
	RepeatDelay  Duration `json:"repeat_delay"`
	InitialDelay Duration `json:"initial_delay"`

	// Engine-stream fields (kind "engine").
	Engine   string `json:"engine"`   // path to a sample log file
	Location string `json:"location"` // source path stamped on events
	// EventsPerSecond caps EACH agent's own REAL event rate independently (0 =
	// unlimited): every agent running the lane paces itself against its own
	// budget, so N agents deliver up to N*EventsPerSecond to the manager in
	// aggregate. The limiter charges one token per event, so the cap does not
	// depend on how events are grouped into requests.
	EventsPerSecond float64 `json:"events_per_second"`
	// EventsPerBatch is how many events ride one /stateless request. 0 sends
	// the whole sample file as a single batch. One runStep pass always ships the
	// entire file, split into ceil(lines/batch) requests.
	EventsPerBatch int `json:"events_per_batch"`
}

// DocSpec controls document (or context) generation for a step.
//
// There is deliberately no `with_checksum` knob: every generated document
// carries checksum.hash.sha1, because every real one does (see
// source.Documents). It was retired rather than defaulted to true, so a
// scenario that still sets it fails to load instead of implying the sender
// has a checksum-less mode.
type DocSpec struct {
	Count     int `json:"count"`
	SizeBytes int `json:"size_bytes"`
}

// Pacing is the run-level load shape.
type Pacing struct {
	ConcurrentAgents  int      `json:"concurrent_agents"`
	RequestsPerSecond float64  `json:"requests_per_second"`
	RepeatUntil       Duration `json:"repeat_until"`
	DrainTimeout      Duration `json:"drain_timeout"`
}

// Assertion is one expectation on a final counter: operator -> value, with
// operators "eq", "gte" and "lte". More than one operator forms a conjunction
// (e.g. {"gte": 1, "lte": 5}).
type Assertion map[string]uint64

// Expected is the scenario's optional contract verdict (docu/09): assertions on
// the run's FINAL total counters, evaluated after the run. Only counters --
// statuses and counts are properties of the protocol contract and hold on any
// hardware, unlike latency or throughput, which belong to the machine. A
// scenario without this block keeps the tool's default stance: record
// everything, judge nothing.
//
// Group keys are the counter names of the summary's `totals` section (plus the
// derived "s5xx" = s500 + s503 under sessions); internal/verdict owns the name
// tables and validates them at load time.
type Expected struct {
	Sessions         map[string]Assertion `json:"sessions"`
	Stateless        map[string]Assertion `json:"stateless"`
	Control          map[string]Assertion `json:"control"`
	Deletes          map[string]Assertion `json:"deletes"`
	Scan             map[string]Assertion `json:"scan"`
	TransportErrors  Assertion            `json:"transport_errors"`
	RetriesExhausted Assertion            `json:"retries_exhausted"`
}
