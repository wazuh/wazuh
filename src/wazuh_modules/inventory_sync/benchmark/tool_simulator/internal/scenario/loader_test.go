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
