package runner

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/control"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/fbbuild"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/scenario"
)

// now is the current unix time, for the request timestamp.
func now() int64 { return time.Now().Unix() }

// us converts a duration to microseconds for the histograms.
func us(d time.Duration) uint64 { return uint64(d.Microseconds()) }

func truncate(b []byte) string {
	const max = 200
	if len(b) > max {
		return string(b[:max]) + "…"
	}
	return string(b)
}

// sleepCtx sleeps for d, or returns early if ctx is cancelled.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// startFor builds the Start metadata for a session, layering fleet metadata over
// the module/option/cluster from the step and defaults.
func (a *agent) startFor(lane string, step scenario.Step) fbbuild.Start {
	scn := a.r.scn
	option := optionEnum(scn.LaneOption(step))
	s := fbbuild.Start{
		Module:        scn.LaneModule(step),
		Mode:          fbbuild.ModeModuleDelta,
		Option:        option,
		Indices:       indicesFor(scn, step),
		AgentID:       a.id,
		AgentName:     a.name,
		AgentVersion:  firstNonEmpty(a.fleet.Start.AgentVersion, "5.0.0"),
		Architecture:  firstNonEmpty(a.fleet.Start.Architecture, "x86_64"),
		Hostname:      a.name,
		OSName:        firstNonEmpty(a.fleet.Start.OSName, "Ubuntu"),
		OSPlatform:    firstNonEmpty(a.fleet.Start.OSPlatform, "ubuntu"),
		OSType:        firstNonEmpty(a.fleet.Start.OSType, "linux"),
		OSVersion:     firstNonEmpty(a.fleet.Start.OSVersion, "22.04"),
		Groups:        []string{"default"},
		GlobalVersion: step.GlobalVer,
		ClusterName:   a.r.clusterName(),
	}
	// feed_offset only means anything to a VD-flagged session -- see
	// agent.feedOffsetFor for the resolution order.
	if option == fbbuild.OptionVDFirst || option == fbbuild.OptionVDSync {
		s.FeedOffset = a.feedOffsetFor(step)
	}
	return s
}

func (a *agent) hostInfo() *control.HostInfo {
	m := a.fleet.Start
	return &control.HostInfo{
		Hostname:     a.name,
		IP:           "127.0.0.1",
		Architecture: firstNonEmpty(m.Architecture, "x86_64"),
		OSName:       firstNonEmpty(m.OSName, "Ubuntu"),
		OSVersion:    firstNonEmpty(m.OSVersion, "22.04"),
		OSPlatform:   firstNonEmpty(m.OSPlatform, "ubuntu"),
		OSType:       firstNonEmpty(m.OSType, "linux"),
	}
}

// docKey namespaces generated document ids by agent, lane and module, so no two
// lanes or agents collide and the run is reproducible.
func (a *agent) docKey(lane string, step scenario.Step) string {
	return a.id + "-" + lane + "-" + a.r.scn.LaneModule(step)
}

// -- step shaping ---------------------------------------------------------

func optionEnum(s string) fbbuild.Option {
	switch s {
	case "vdfirst", "VDFirst":
		return fbbuild.OptionVDFirst
	case "vdsync", "VDSync":
		return fbbuild.OptionVDSync
	default:
		return fbbuild.OptionSync
	}
}

func modeFor(step scenario.Step, delta, check fbbuild.Mode) fbbuild.Mode {
	if step.Kind == "metadata" || step.Kind == "groups" {
		// "metadata"/"groups" default to delta; a "*_check" hint could pick check.
		return delta
	}
	return delta
}

func indicesFor(scn *scenario.Scenario, step scenario.Step) []string {
	if len(step.Indices) > 0 {
		return step.Indices
	}
	return nil
}

func cleanIndices(scn *scenario.Scenario, step scenario.Step) []string {
	if len(step.Indices) > 0 {
		return step.Indices
	}
	return []string{"wazuh-states-inventory-packages"}
}

func firstIndex(scn *scenario.Scenario, step scenario.Step) string {
	if len(step.Indices) > 0 {
		return step.Indices[0]
	}
	return "wazuh-states-inventory-packages"
}

// cleansStep and deltaStep split a full_resync into its two ordinary sessions.
func cleansStep(step scenario.Step) scenario.Step {
	out := step
	out.Kind = "cleans"
	return out
}

func deltaStep(step scenario.Step) scenario.Step {
	out := step
	out.Kind = "delta"
	return out
}

func replaceKind(step scenario.Step, kind string) scenario.Step {
	out := step
	out.Kind = kind
	return out
}

// rawOverride returns a deliberately invalid body for a "raw" step, or nil.
func rawOverride(step scenario.Step) []byte {
	if step.Kind != "raw" {
		return nil
	}
	switch step.Raw {
	case "empty":
		return []byte{}
	case "garbage", "":
		return []byte("this is not a flatbuffer at all")
	case "oversized":
		return make([]byte, 1) // size is asserted by the transport budget, not the body
	default: // "not_full_session" and anything else: junk bytes
		return []byte("not a full session message")
	}
}

// -- misc -----------------------------------------------------------------

func fleetPrefix(f scenario.Fleet) string {
	if f.Name != "" {
		return f.Name
	}
	return "bench"
}

func clusterNameFromScenario(scn *scenario.Scenario) string { return scn.Defaults.ClusterName }

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func isAbs(p string) bool { return filepath.IsAbs(p) }

func joinDir(base, rel string) string { return filepath.Join(filepath.Dir(base), rel) }

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}
