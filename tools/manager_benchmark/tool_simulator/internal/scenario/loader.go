package scenario

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/engine"
)

// Known step kinds, so a typo is a load-time error, not a silent no-op.
// Concurrency is expressed with LANES (a fleet's lanes run in parallel), never
// with a step kind: an earlier "parallel" kind was accepted here without an
// implementation and silently degraded to a delta.
var validKinds = map[string]bool{
	"delta": true, "cleans": true, "checksum": true,
	"metadata": true, "groups": true, "full_resync": true,
	"delete_agent": true, "engine": true, "raw": true,
	"scan_vd": true, "cacerts": true, "enroll_https": true,
}

// Load reads and strictly validates a scenario file. Unknown fields and unknown
// step kinds are refused: a typo must not silently produce a different
// measurement (docu/07). modeOverride, when non-empty, replaces the file's mode.
func Load(path, modeOverride string) (*Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Scenario
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("scenario %s: %w", path, err)
	}

	if modeOverride != "" {
		s.Mode = modeOverride
	}
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("scenario %s: %w", path, err)
	}
	if err := s.checkFiles(path); err != nil {
		return nil, fmt.Errorf("scenario %s: %w", path, err)
	}
	return &s, nil
}

// checkFiles makes --validate catch a typo'd engine or dump path: every
// referenced file is resolved relative to the scenario's directory and stat'd.
func (s *Scenario) checkFiles(scenarioPath string) error {
	base := filepath.Dir(scenarioPath)
	resolve := func(p string) string {
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(base, p)
	}
	for _, steps := range s.Lanes {
		for _, step := range steps {
			for _, ref := range []string{step.Engine, step.Dump} {
				if ref == "" {
					continue
				}
				if _, err := os.Stat(resolve(ref)); err != nil {
					return fmt.Errorf("referenced file not found: %s", ref)
				}
			}
		}
	}
	return nil
}

func (s *Scenario) validate() error {
	switch s.Mode {
	case "uds", "agent":
	default:
		return fmt.Errorf("mode must be \"uds\" or \"agent\", got %q", s.Mode)
	}
	if len(s.Fleets) == 0 {
		return fmt.Errorf("no fleets")
	}
	if s.Defaults.Retry.Interval.D() < 0 {
		return fmt.Errorf("retry.interval must not be negative")
	}
	switch s.Defaults.Compression {
	case "", "none", "zstd":
	default:
		return fmt.Errorf("compression must be \"zstd\", \"none\" or absent, got %q", s.Defaults.Compression)
	}
	// Absent degrades to plain in uds mode on its own (CompressionFor); only an
	// EXPLICIT zstd is a contradiction worth refusing.
	if s.Defaults.Compression == "zstd" && s.Mode != "agent" {
		return fmt.Errorf("compression: \"zstd\" needs agent mode: remoted decompresses zstd bodies, " +
			"but the inventory sync server's UDS ingress has no decoder")
	}

	for _, fleet := range s.Fleets {
		if fleet.Agents <= 0 {
			return fmt.Errorf("fleet %q: agents must be > 0", fleet.Name)
		}
		if len(fleet.Lanes) == 0 {
			return fmt.Errorf("fleet %q: no lanes", fleet.Name)
		}
		for _, laneName := range fleet.Lanes {
			steps, ok := s.Lanes[laneName]
			if !ok {
				return fmt.Errorf("fleet %q references unknown lane %q", fleet.Name, laneName)
			}
			for i, step := range steps {
				if err := s.validateStep(fleet.Name, laneName, i, step); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// validateHeader refuses a header shape the run could not send as written: a
// negative knob, an unknown id position, a padding size some agent of the
// fleet cannot reach, or, in agent mode, a header remoted would answer 400.
func (s *Scenario) validateHeader(where, fleetName string, h *engine.HeaderSpec) error {
	if h == nil {
		return nil
	}
	if h.Profile != "" && h.Profile != engine.ProfileAgent {
		return fmt.Errorf("%s: header.profile must be %q or absent, got %q", where, engine.ProfileAgent, h.Profile)
	}
	if h.Profile == engine.ProfileAgent && h.IDPosition != "" {
		return fmt.Errorf("%s: header.id_position does not apply to the %q profile, whose members are sorted by name as the agent sends them",
			where, engine.ProfileAgent)
	}
	for _, knob := range []struct {
		name  string
		value int
	}{
		{"pad_bytes", h.PadBytes}, {"extra_fields", h.ExtraFields},
		{"off_path_fields", h.OffPathFields}, {"change_every", h.ChangeEvery},
	} {
		if knob.value < 0 {
			return fmt.Errorf("%s: header.%s must not be negative", where, knob.name)
		}
	}
	if h.IDPosition != "" && h.IDPosition != "first" && h.IDPosition != "last" {
		return fmt.Errorf("%s: header.id_position must be \"first\" or \"last\", got %q", where, h.IDPosition)
	}
	minBytes := engine.MinHeaderBytesFor(s.widestHeaderInfo(fleetName), h)
	if h.PadBytes > 0 && h.PadBytes < minBytes {
		return fmt.Errorf("%s: header.pad_bytes %d is below the %d bytes this header needs", where, h.PadBytes, minBytes)
	}
	if s.Mode == "agent" {
		size := minBytes
		if h.PadBytes > size {
			size = h.PadBytes
		}
		if size > engine.MaxStatelessHeaderBytes {
			return fmt.Errorf("%s: header of %d bytes exceeds remoted's %d-byte H-line cap (every batch would be answered 400)",
				where, size, engine.MaxStatelessHeaderBytes)
		}
	}
	return nil
}

// widestHeaderInfo bounds what an "agent" profile header of fleetName carries:
// the fleet's start block and cluster name as written, and a 64-character
// agent name, wider than any name the sender generates.
func (s *Scenario) widestHeaderInfo(fleetName string) *engine.AgentInfo {
	for _, f := range s.Fleets {
		if f.Name != fleetName {
			continue
		}
		name := strings.Repeat("n", 64)
		return &engine.AgentInfo{
			Name: name, Version: "v" + f.Start.AgentVersion, Groups: []string{"default"},
			Architecture: f.Start.Architecture, Hostname: name,
			OSName: f.Start.OSName, OSPlatform: f.Start.OSPlatform,
			OSType: f.Start.OSType, OSVersion: f.Start.OSVersion,
			ClusterName: s.Defaults.ClusterName,
		}
	}
	return nil
}

func (s *Scenario) validateStep(fleet, lane string, i int, step Step) error {
	where := fmt.Sprintf("fleet %q lane %q step %d", fleet, lane, i)
	if !validKinds[step.Kind] {
		return fmt.Errorf("%s: unknown kind %q", where, step.Kind)
	}
	if step.Kind == "engine" {
		// Agent mode posts to remoted's POST /stateless; uds mode posts straight
		// to the engine's POST /events/enriched on --socket (docu/13).
		if step.Engine == "" || step.Location == "" {
			return fmt.Errorf("%s: engine step needs \"engine\" and \"location\"", where)
		}
		if step.EventsPerSecond < 0 {
			return fmt.Errorf("%s: events_per_second must not be negative", where)
		}
		if step.EventsPerBatch < 0 {
			return fmt.Errorf("%s: events_per_batch must not be negative", where)
		}
		if err := s.validateHeader(where, fleet, step.Header); err != nil {
			return err
		}
		if err := validateBatching(where, step); err != nil {
			return err
		}
	}
	if step.Kind != "engine" && step.Header != nil {
		return fmt.Errorf("%s: header only applies to engine steps", where)
	}
	if step.Kind != "engine" && (step.Batching != "" || step.BatchSizeBytes != 0 || step.BatchInterval != 0 ||
		step.RetryMaxAttempts != 0 || step.StartJitter != nil) {
		return fmt.Errorf("%s: batching, batch_size_bytes, batch_interval, retry_max_attempts and start_jitter only apply to engine steps", where)
	}
	if step.Kind != "engine" && (step.EventsPerSecond != 0 || step.EventsPerBatch != 0) {
		return fmt.Errorf("%s: events_per_second/events_per_batch only apply to engine steps", where)
	}
	if step.Kind == "delete_agent" && s.Mode != "uds" {
		return fmt.Errorf("%s: delete_agent is uds-mode only", where)
	}
	if step.Kind == "scan_vd" {
		// The re-scan request is an authenticated route on REMOTED; the module's
		// Unix socket has no /scan/vd at all, so a uds scenario asking for one
		// is a scenario bug, not a run that measures less.
		if s.Mode != "agent" {
			return fmt.Errorf("%s: scan_vd is agent-mode only (POST /scan/vd is a remoted route)", where)
		}
		// A scan request carries only type and feed_offset: anything describing
		// documents or a payload on this step means the author expected it to
		// send inventory too.
		if step.Documents != nil || step.Contexts != nil || step.Dump != "" ||
			step.Module != "" || step.Option != "" || len(step.Indices) > 0 ||
			step.Checksum != "" || step.Raw != "" || step.GlobalVer != 0 {
			return fmt.Errorf("%s: scan_vd only takes feed_offset and the timing fields "+
				"(it sends {\"type\":\"feed_update\",\"feed_offset\":N}, no session payload)", where)
		}
	}
	if step.Kind == "cacerts" {
		// GET /cacerts is a remoted route (the CA that signs the listener's own
		// certificate); the module's Unix socket has nothing of the sort.
		if s.Mode != "agent" {
			return fmt.Errorf("%s: cacerts is agent-mode only (GET /cacerts is a remoted route)", where)
		}
		// No body, no parameters: only the timing fields make sense on this step.
		if step.Documents != nil || step.Contexts != nil || step.Dump != "" ||
			step.Module != "" || step.Option != "" || len(step.Indices) > 0 ||
			step.Checksum != "" || step.Raw != "" || step.GlobalVer != 0 || step.FeedOffset != nil {
			return fmt.Errorf("%s: cacerts only takes the timing fields "+
				"(it sends a body-less GET /cacerts, nothing else)", where)
		}
	}
	if step.Kind == "enroll_https" {
		// POST /enroll with an enrollment-token bearer is a remoted route; the module's Unix
		// socket has nothing of the sort. The token itself is environment config
		// (--enroll-token-file / WAZUH_ENROLLMENT_TOKEN), never a scenario field.
		if s.Mode != "agent" {
			return fmt.Errorf("%s: enroll_https is agent-mode only (POST /enroll is a remoted route)", where)
		}
		if step.Documents != nil || step.Contexts != nil || step.Dump != "" ||
			step.Module != "" || step.Option != "" || len(step.Indices) > 0 ||
			step.Checksum != "" || step.Raw != "" || step.GlobalVer != 0 || step.FeedOffset != nil {
			return fmt.Errorf("%s: enroll_https only takes the timing fields "+
				"(it enrolls one fresh agent name per repetition with the enrollment token given on the command line)", where)
		}
	}
	if (step.Kind == "metadata" || step.Kind == "groups") && len(step.Indices) == 0 {
		return fmt.Errorf("%s: %s needs indices", where, step.Kind)
	}
	if step.Dump != "" && step.Kind != "delta" && step.Kind != "full_resync" {
		return fmt.Errorf("%s: dump is only valid on delta or full_resync (got %q)", where, step.Kind)
	}
	return nil
}

// LaneModule returns the module for a step, falling back to the defaults.
func (s *Scenario) LaneModule(step Step) string {
	if step.Module != "" {
		return step.Module
	}
	return s.Defaults.Module
}

// LaneOption returns the option for a step, falling back to the defaults.
func (s *Scenario) LaneOption(step Step) string {
	if step.Option != "" {
		return step.Option
	}
	return s.Defaults.Option
}

// validateBatching refuses an engine step's batching knobs that the run could
// not honour: an unknown mode, a negative size, interval, budget or jitter, an
// agent-only knob on a "count" step, or an events_per_batch on an "agent" step
// (whose batches are sized by bytes, as the agent's are).
func validateBatching(where string, step Step) error {
	switch step.Batching {
	case "", BatchingCount, BatchingAgent:
	default:
		return fmt.Errorf("%s: batching must be %q or %q, got %q", where, BatchingCount, BatchingAgent, step.Batching)
	}
	if step.BatchSizeBytes < 0 || step.BatchInterval < 0 || step.RetryMaxAttempts < 0 {
		return fmt.Errorf("%s: batch_size_bytes, batch_interval and retry_max_attempts must not be negative", where)
	}
	if step.StartJitter != nil && *step.StartJitter < 0 {
		return fmt.Errorf("%s: start_jitter must not be negative", where)
	}
	if step.AgentBatching() {
		if step.EventsPerSecond <= 0 {
			return fmt.Errorf("%s: %q batching needs events_per_second > 0: the buffer fills at that rate", where, BatchingAgent)
		}
		if step.EventsPerBatch != 0 {
			return fmt.Errorf("%s: events_per_batch does not apply to %q batching, which flushes by batch_size_bytes or batch_interval", where, BatchingAgent)
		}
		return nil
	}
	if step.BatchSizeBytes != 0 || step.BatchInterval != 0 || step.RetryMaxAttempts != 0 {
		return fmt.Errorf("%s: batch_size_bytes, batch_interval and retry_max_attempts need batching %q", where, BatchingAgent)
	}
	return nil
}
