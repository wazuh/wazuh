package scenario

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Known step kinds, so a typo is a load-time error, not a silent no-op.
// Concurrency is expressed with LANES (a fleet's lanes run in parallel), never
// with a step kind: an earlier "parallel" kind was accepted here without an
// implementation and silently degraded to a delta.
var validKinds = map[string]bool{
	"delta": true, "cleans": true, "checksum": true,
	"metadata": true, "groups": true, "full_resync": true,
	"delete_agent": true, "engine": true, "raw": true,
	"scan_vd": true,
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

func (s *Scenario) validateStep(fleet, lane string, i int, step Step) error {
	where := fmt.Sprintf("fleet %q lane %q step %d", fleet, lane, i)
	if !validKinds[step.Kind] {
		return fmt.Errorf("%s: unknown kind %q", where, step.Kind)
	}
	if step.Kind == "engine" {
		if s.Mode != "agent" {
			return fmt.Errorf("%s: engine streams need agent mode", where)
		}
		if step.Engine == "" || step.Location == "" {
			return fmt.Errorf("%s: engine step needs \"engine\" and \"location\"", where)
		}
		if step.EventsPerSecond < 0 {
			return fmt.Errorf("%s: events_per_second must not be negative", where)
		}
		if step.EventsPerBatch < 0 {
			return fmt.Errorf("%s: events_per_batch must not be negative", where)
		}
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
