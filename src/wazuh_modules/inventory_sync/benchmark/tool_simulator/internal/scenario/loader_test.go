package scenario

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAllCommittedScenarios(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// scenario tests live at .../benchmark/tool_simulator/internal/scenario/,
	// so benchmark/ is three levels up.
	benchDir := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	scnDir := filepath.Join(benchDir, "scenarios")
	entries, err := os.ReadDir(scnDir)
	if err != nil {
		t.Fatal(err)
	}
	loaded := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		// Negative test scenarios (those that must fail to load) are
		// named with the "_invalid" infix and verified by dedicated
		// "must reject" tests below.
		if strings.Contains(e.Name(), "_invalid") {
			continue
		}
		full := filepath.Join(scnDir, e.Name())
		s, err := Load(full, LoaderOptions{BenchDir: benchDir})
		if err != nil {
			t.Errorf("Load(%s): %v", e.Name(), err)
			continue
		}
		if s.Behavior.TotalAgents < 1 {
			t.Errorf("%s: total_agents=%d", e.Name(), s.Behavior.TotalAgents)
		}
		if len(s.Lanes) == 0 {
			t.Errorf("%s: no lanes", e.Name())
		}
		loaded++
	}
	if loaded == 0 {
		t.Fatal("no scenarios were loaded")
	}
	t.Logf("loaded %d committed scenarios OK", loaded)
}

// TestLoadEngineSiblingsRequiresNonEngineLane covers the negative
// scenario shipped at scenarios/engine_invalid_all_engine.json: a
// fleet with only engine lanes (one of which has
// run_while_siblings_active=true) must be rejected by the loader.
func TestLoadEngineSiblingsRequiresNonEngineLane(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	benchDir := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	full := filepath.Join(benchDir, "scenarios", "engine_invalid_all_engine.json")
	_, err = Load(full, LoaderOptions{BenchDir: benchDir})
	if err == nil {
		t.Fatal("expected Load to reject scenario, got nil error")
	}
	if !strings.Contains(err.Error(), "run_while_siblings_active") {
		t.Fatalf("expected error mentioning run_while_siblings_active, got: %v", err)
	}
}

// TestLoadEngineRejectsRepeatCount: engine steps with repeat_count > 1
// must be rejected at load time (the engine controls iteration via
// `loop` and `duration`).
func TestLoadEngineRejectsRepeatCount(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "x.log")
	_ = os.WriteFile(logPath, []byte("x\n"), 0644)
	scn := `{
  "lanes": {
    "l": [ { "engine": "x.log", "max_eps": 10, "repeat_count": 3 } ]
  },
  "total_agents": 1
}`
	p := filepath.Join(dir, "s.json")
	_ = os.WriteFile(p, []byte(scn), 0644)
	_, err := Load(p, LoaderOptions{BenchDir: dir})
	if err == nil || !strings.Contains(err.Error(), "repeat_count must be 1") {
		t.Fatalf("expected rejection of repeat_count>1, got: %v", err)
	}
}

// TestLoadEngineIgnoresInventoryDefaults: when a scenario's top-level
// `defaults` block contains inventory-only knobs (session_type,
// use_databatch, ack_timeout_retry, etc.), the loader must strip them
// before merging into engine steps. Mixed scenarios (engine + inventory
// lanes) should load cleanly even with rich defaults.
func TestLoadEngineIgnoresInventoryDefaults(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "x.log")
	_ = os.WriteFile(logPath, []byte("a\n"), 0644)
	scn := `{
  "defaults": {
    "session_type": "delta",
    "use_databatch": true,
    "ack_timeout_retry": 0,
    "offline_retry": 0,
    "end_ack_timeout": 60
  },
  "lanes": {
    "engine": [
      { "engine": "x.log", "max_eps": 10 }
    ],
    "inv": [ { "kind": "fim_file" } ]
  },
  "total_agents": 1
}`
	p := filepath.Join(dir, "s.json")
	_ = os.WriteFile(p, []byte(scn), 0644)
	s, err := Load(p, LoaderOptions{BenchDir: dir})
	if err != nil {
		t.Fatalf("Load: %v (expected engine step to ignore inventory-only defaults)", err)
	}
	if s.Lanes["engine"][0].Kind != SourceKindEngine {
		t.Errorf("engine step Kind = %v, want SourceKindEngine", s.Lanes["engine"][0].Kind)
	}
	// Defaults must still reach the inventory step.
	inv := s.Lanes["inv"][0]
	if inv.SessionType != SessionDelta {
		t.Errorf("inventory step SessionType = %q, want %q", inv.SessionType, SessionDelta)
	}
	if !inv.UseDatabatch {
		t.Errorf("inventory step UseDatabatch = false, want true (from defaults)")
	}
}

// TestLoadEngineDurationDefaultsAndOverride: duration defaults to 0
// (no time limit) and can be set per-step.
func TestLoadEngineDurationAndSiblings(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "x.log")
	_ = os.WriteFile(logPath, []byte("x\n"), 0644)
	scn := `{
  "lanes": {
    "l": [
      { "engine": "x.log", "max_eps": 10, "duration": 7.5, "run_while_siblings_active": true },
      { "kind": "fim_file" }
    ]
  },
  "total_agents": 1
}`
	p := filepath.Join(dir, "s.json")
	_ = os.WriteFile(p, []byte(scn), 0644)
	s, err := Load(p, LoaderOptions{BenchDir: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	step := s.Lanes["l"][0]
	if step.EngineDuration != 7.5 {
		t.Errorf("EngineDuration = %v, want 7.5", step.EngineDuration)
	}
	if !step.EngineRunWhileSiblings {
		t.Errorf("EngineRunWhileSiblings = false, want true")
	}
}

func TestLoadEngineStep(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "syslog.log")
	if err := os.WriteFile(logPath, []byte("line 1\nline 2\n"), 0644); err != nil {
		t.Fatal(err)
	}
	scn := `{
  "name": "engine-smoke",
  "lanes": {
    "engine": [
      { "engine": "syslog.log", "max_eps": 100, "loop": false, "location": "custom" }
    ]
  },
  "total_agents": 1
}`
	scnPath := filepath.Join(dir, "scn.json")
	if err := os.WriteFile(scnPath, []byte(scn), 0644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(scnPath, LoaderOptions{BenchDir: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	step := s.Lanes["engine"][0]
	if step.Kind != SourceKindEngine {
		t.Fatalf("kind = %v", step.Kind)
	}
	if step.MaxEPS != 100 || step.EngineLoop != false || step.EngineLocation != "custom" {
		t.Fatalf("got %+v", step)
	}
	if step.EnginePath != logPath {
		t.Fatalf("EnginePath = %s, want %s", step.EnginePath, logPath)
	}
}

func TestLoadEngineRejectsInventoryFields(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "x.log")
	_ = os.WriteFile(logPath, []byte("x\n"), 0644)
	scn := `{
  "lanes": {
    "l": [ { "engine": "x.log", "max_eps": 10, "module": "fim" } ]
  },
  "total_agents": 1
}`
	p := filepath.Join(dir, "s.json")
	_ = os.WriteFile(p, []byte(scn), 0644)
	_, err := Load(p, LoaderOptions{BenchDir: dir})
	if err == nil || !strings.Contains(err.Error(), "module") {
		t.Fatalf("expected rejection mentioning `module`, got: %v", err)
	}
}

func TestLoadEngineRequiresMaxEPS(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "x.log")
	_ = os.WriteFile(logPath, []byte("x\n"), 0644)
	scn := `{ "lanes": { "l": [ { "engine": "x.log" } ] }, "total_agents": 1 }`
	p := filepath.Join(dir, "s.json")
	_ = os.WriteFile(p, []byte(scn), 0644)
	_, err := Load(p, LoaderOptions{BenchDir: dir})
	if err == nil || !strings.Contains(err.Error(), "max_eps") {
		t.Fatalf("expected rejection mentioning max_eps, got: %v", err)
	}
}

func TestLoadStepXORViolation(t *testing.T) {
	dir := t.TempDir()
	scn := `{ "lanes": { "l": [ { "kind": "fim_file", "engine": "x" } ] }, "total_agents": 1 }`
	p := filepath.Join(dir, "s.json")
	_ = os.WriteFile(p, []byte(scn), 0644)
	_, err := Load(p, LoaderOptions{BenchDir: dir})
	if err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("expected XOR violation, got: %v", err)
	}
}

func TestLoadRejectsFleetsPlusTotalAgents(t *testing.T) {
	dir := t.TempDir()
	scn := `{
  "lanes": { "l": [{"kind":"fim_file"}] },
  "total_agents": 2,
  "fleets": [{"name":"a","agents":1,"lanes":["l"]}]
}`
	p := filepath.Join(dir, "s.json")
	_ = os.WriteFile(p, []byte(scn), 0644)
	_, err := Load(p, LoaderOptions{BenchDir: dir})
	if err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("expected rejection, got: %v", err)
	}
}

// TestLoadOfflineRetry_Defaults: a step without explicit offline_retry /
// offline_retry_delay gets the historical defaults (-1, 1.0).
func TestLoadOfflineRetry_Defaults(t *testing.T) {
	dir := t.TempDir()
	scn := `{
  "lanes": { "l": [{"kind":"fim_file"}] },
  "total_agents": 1
}`
	p := filepath.Join(dir, "s.json")
	_ = os.WriteFile(p, []byte(scn), 0644)
	s, err := Load(p, LoaderOptions{BenchDir: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	step := s.Lanes["l"][0]
	if step.OfflineRetry != -1 {
		t.Errorf("OfflineRetry default = %d, want -1", step.OfflineRetry)
	}
	if step.OfflineRetryDelay != 1.0 {
		t.Errorf("OfflineRetryDelay default = %v, want 1.0", step.OfflineRetryDelay)
	}
}

// TestLoadOfflineRetry_InheritsFromDefaults: a step gets the values from
// the top-level `defaults` block when it doesn't override them.
func TestLoadOfflineRetry_InheritsFromDefaults(t *testing.T) {
	dir := t.TempDir()
	scn := `{
  "defaults": { "offline_retry": 3, "offline_retry_delay": 0.5 },
  "lanes": { "l": [{"kind":"fim_file"}] },
  "total_agents": 1
}`
	p := filepath.Join(dir, "s.json")
	_ = os.WriteFile(p, []byte(scn), 0644)
	s, err := Load(p, LoaderOptions{BenchDir: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	step := s.Lanes["l"][0]
	if step.OfflineRetry != 3 {
		t.Errorf("OfflineRetry from defaults = %d, want 3", step.OfflineRetry)
	}
	if step.OfflineRetryDelay != 0.5 {
		t.Errorf("OfflineRetryDelay from defaults = %v, want 0.5", step.OfflineRetryDelay)
	}
}

// TestLoadOfflineRetry_StepOverridesDefaults: per-step values take
// precedence over the scenario-wide defaults.
func TestLoadOfflineRetry_StepOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	scn := `{
  "defaults": { "offline_retry": 3, "offline_retry_delay": 0.5 },
  "lanes": { "l": [{"kind":"fim_file","offline_retry":0,"offline_retry_delay":2.5}] },
  "total_agents": 1
}`
	p := filepath.Join(dir, "s.json")
	_ = os.WriteFile(p, []byte(scn), 0644)
	s, err := Load(p, LoaderOptions{BenchDir: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	step := s.Lanes["l"][0]
	if step.OfflineRetry != 0 {
		t.Errorf("OfflineRetry override = %d, want 0", step.OfflineRetry)
	}
	if step.OfflineRetryDelay != 2.5 {
		t.Errorf("OfflineRetryDelay override = %v, want 2.5", step.OfflineRetryDelay)
	}
}

// TestLoadAckTimeout_Defaults: when not set, all four ack-timeout related
// fields take their respective defaults (0 for the overrides, -1/1.0 for
// the retry knobs).
func TestLoadAckTimeout_Defaults(t *testing.T) {
	dir := t.TempDir()
	scn := `{
  "lanes": { "l": [{"kind":"fim_file"}] },
  "total_agents": 1
}`
	p := filepath.Join(dir, "s.json")
	_ = os.WriteFile(p, []byte(scn), 0644)
	s, err := Load(p, LoaderOptions{BenchDir: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	step := s.Lanes["l"][0]
	if step.StartAckTimeout != 0 {
		t.Errorf("StartAckTimeout default = %v, want 0", step.StartAckTimeout)
	}
	if step.EndAckTimeout != 0 {
		t.Errorf("EndAckTimeout default = %v, want 0", step.EndAckTimeout)
	}
	if step.AckTimeoutRetry != -1 {
		t.Errorf("AckTimeoutRetry default = %d, want -1", step.AckTimeoutRetry)
	}
	if step.AckTimeoutRetryDelay != 1.0 {
		t.Errorf("AckTimeoutRetryDelay default = %v, want 1.0", step.AckTimeoutRetryDelay)
	}
}

// TestLoadAckTimeout_InheritsAndOverrides: defaults block sets values,
// step-level overrides take precedence.
func TestLoadAckTimeout_InheritsAndOverrides(t *testing.T) {
	dir := t.TempDir()
	scn := `{
  "defaults": {
    "start_ack_timeout": 7.5,
    "end_ack_timeout": 60,
    "ack_timeout_retry": 5,
    "ack_timeout_retry_delay": 0.5
  },
  "lanes": {
    "inherits": [{"kind":"fim_file"}],
    "overrides": [{"kind":"fim_file","start_ack_timeout":2,"ack_timeout_retry":0}]
  },
  "total_agents": 1
}`
	p := filepath.Join(dir, "s.json")
	_ = os.WriteFile(p, []byte(scn), 0644)
	s, err := Load(p, LoaderOptions{BenchDir: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	inh := s.Lanes["inherits"][0]
	if inh.StartAckTimeout != 7.5 || inh.EndAckTimeout != 60 ||
		inh.AckTimeoutRetry != 5 || inh.AckTimeoutRetryDelay != 0.5 {
		t.Errorf("inherits: got %+v", inh)
	}
	ovr := s.Lanes["overrides"][0]
	if ovr.StartAckTimeout != 2 {
		t.Errorf("overrides StartAckTimeout = %v, want 2", ovr.StartAckTimeout)
	}
	if ovr.EndAckTimeout != 60 {
		t.Errorf("overrides EndAckTimeout = %v, want 60 (inherited)", ovr.EndAckTimeout)
	}
	if ovr.AckTimeoutRetry != 0 {
		t.Errorf("overrides AckTimeoutRetry = %d, want 0", ovr.AckTimeoutRetry)
	}
	if ovr.AckTimeoutRetryDelay != 0.5 {
		t.Errorf("overrides AckTimeoutRetryDelay = %v, want 0.5 (inherited)", ovr.AckTimeoutRetryDelay)
	}
}

// TestLoadAckTimeout_RejectsInvalidValues: negative timeouts and
// out-of-range retries are rejected.
func TestLoadAckTimeout_RejectsInvalidValues(t *testing.T) {
	cases := []struct {
		name string
		scn  string
		need string
	}{
		{
			"start_ack_timeout<0",
			`{"lanes":{"l":[{"kind":"fim_file","start_ack_timeout":-1}]},"total_agents":1}`,
			"start_ack_timeout",
		},
		{
			"end_ack_timeout<0",
			`{"lanes":{"l":[{"kind":"fim_file","end_ack_timeout":-2.5}]},"total_agents":1}`,
			"end_ack_timeout",
		},
		{
			"ack_timeout_retry<-1",
			`{"lanes":{"l":[{"kind":"fim_file","ack_timeout_retry":-5}]},"total_agents":1}`,
			"ack_timeout_retry",
		},
		{
			"ack_timeout_retry_delay<0",
			`{"lanes":{"l":[{"kind":"fim_file","ack_timeout_retry_delay":-0.1}]},"total_agents":1}`,
			"ack_timeout_retry_delay",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "s.json")
			_ = os.WriteFile(p, []byte(tc.scn), 0644)
			_, err := Load(p, LoaderOptions{BenchDir: dir})
			if err == nil || !strings.Contains(err.Error(), tc.need) {
				t.Fatalf("expected rejection mentioning %q, got: %v", tc.need, err)
			}
		})
	}
}

// TestLoadOfflineRetry_RejectsInvalidValues: negative offline_retry (other
// than -1) and negative offline_retry_delay are rejected at load time.
func TestLoadOfflineRetry_RejectsInvalidValues(t *testing.T) {
	cases := []struct {
		name string
		scn  string
		need string
	}{
		{
			"offline_retry=-2",
			`{"lanes":{"l":[{"kind":"fim_file","offline_retry":-2}]},"total_agents":1}`,
			"offline_retry",
		},
		{
			"offline_retry_delay=-0.5",
			`{"lanes":{"l":[{"kind":"fim_file","offline_retry_delay":-0.5}]},"total_agents":1}`,
			"offline_retry_delay",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "s.json")
			_ = os.WriteFile(p, []byte(tc.scn), 0644)
			_, err := Load(p, LoaderOptions{BenchDir: dir})
			if err == nil || !strings.Contains(err.Error(), tc.need) {
				t.Fatalf("expected rejection mentioning %q, got: %v", tc.need, err)
			}
		})
	}
}
