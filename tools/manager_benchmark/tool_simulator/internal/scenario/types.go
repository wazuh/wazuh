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
}

// Defaults are inherited by every fleet and step unless overridden.
type Defaults struct {
	Module      string   `json:"module"`
	Option      string   `json:"option"`
	MaxEPS      float64  `json:"max_eps"`
	ClusterName string   `json:"cluster_name"`
	ClusterNode string   `json:"cluster_node"`
	Documents   *DocSpec `json:"documents"`
	Control     Control  `json:"control"`
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
	Kind         string   `json:"kind"`
	Module       string   `json:"module"`
	Option       string   `json:"option"`
	Indices      []string `json:"indices"`
	Documents    *DocSpec `json:"documents"`
	Contexts     *DocSpec `json:"contexts"`
	GlobalVer    uint64   `json:"global_version"`
	Checksum     string   `json:"checksum"` // "correct" | "mismatch" | literal
	Raw          string   `json:"raw"`      // for kind "raw": not_full_session|garbage|empty|oversized
	Dump         string   `json:"dump"`     // path to a captured-session dump to replay (kind delta/full_resync)
	RepeatCount  int      `json:"repeat_count"`
	RepeatDelay  Duration `json:"repeat_delay"`
	InitialDelay Duration `json:"initial_delay"`

	// Engine-stream fields (kind "engine").
	Engine                 string  `json:"engine"`   // path to a sample log file
	Location               string  `json:"location"` // source path stamped on events
	MaxEPS                 float64 `json:"max_eps"`
	Loop                   bool    `json:"loop"`
	RunWhileSiblingsActive bool    `json:"run_while_siblings_active"`
}

// DocSpec controls document (or context) generation for a step.
type DocSpec struct {
	Count        int  `json:"count"`
	SizeBytes    int  `json:"size_bytes"`
	WithChecksum bool `json:"with_checksum"`
}

// Pacing is the run-level load shape.
type Pacing struct {
	ConcurrentAgents  int      `json:"concurrent_agents"`
	RequestsPerSecond float64  `json:"requests_per_second"`
	RepeatUntil       Duration `json:"repeat_until"`
	DrainTimeout      Duration `json:"drain_timeout"`
}
