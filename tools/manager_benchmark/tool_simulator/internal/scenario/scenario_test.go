package scenario

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func boolPtr(v bool) *bool { return &v }
func intPtr(v int) *int    { return &v }

// The retry defaults ARE the contract with scenario authors: absent block =
// retry like an agent (on, 500ms, 10 attempts); explicit values win.
func TestRetryDefaults(t *testing.T) {
	var r Retry
	if !r.RetryEnabled() {
		t.Fatal("retry must default to enabled: re-POSTing a shed session is what an agent does")
	}
	if got := r.RetryInterval(); got != 500*time.Millisecond {
		t.Fatalf("default interval must be 500ms, got %v", got)
	}
	if got := r.RetryMaxAttempts(); got != 10 {
		t.Fatalf("default max_attempts must be 10, got %d", got)
	}

	r = Retry{Enabled: boolPtr(false), MaxAttempts: intPtr(0)}
	if r.RetryEnabled() {
		t.Fatal("an explicit false must win over the default")
	}
	if got := r.RetryMaxAttempts(); got != 0 {
		t.Fatalf("an explicit 0 means unbounded, got %d", got)
	}
}

func loadFromLiteral(t *testing.T, body string) (*Scenario, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scenario.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return Load(path, "")
}

const minimalUDS = `{
  "name": "t", "mode": "uds",
  "lanes": {"main": [%s]},
  "fleets": [{"name": "f", "agents": 1, "first_id": 1, "lanes": ["main"]}]%s
}`

func TestLoaderRefusesTheRetiredKnobs(t *testing.T) {
	// DisallowUnknownFields is what turns a stale scenario into a load error
	// instead of a silently different measurement.
	for _, body := range []string{
		`{"kind": "delta", "loop": true}`,
		`{"kind": "delta", "run_while_siblings_active": true}`,
		`{"kind": "parallel"}`,
	} {
		if _, err := loadFromLiteral(t, sprintf(minimalUDS, body, "")); err == nil {
			t.Fatalf("step %s must be refused", body)
		}
	}
	if _, err := loadFromLiteral(t,
		`{"name":"t","mode":"uds","defaults":{"max_eps":75},"lanes":{"main":[{"kind":"delta"}]},"fleets":[{"name":"f","agents":1,"lanes":["main"]}]}`); err == nil {
		t.Fatal("defaults.max_eps was retired and must be refused")
	}
}

func TestLoaderConstrainsTheEventFieldsToEngineSteps(t *testing.T) {
	if _, err := loadFromLiteral(t, sprintf(minimalUDS, `{"kind": "delta", "events_per_second": 5}`, "")); err == nil ||
		!strings.Contains(err.Error(), "engine") {
		t.Fatalf("events_per_second on a delta step must be refused, got %v", err)
	}
	if _, err := loadFromLiteral(t, sprintf(minimalUDS, `{"kind": "delta"}`, `, "defaults": {"retry": {"interval": "-1s"}}`)); err == nil ||
		!strings.Contains(err.Error(), "retry.interval") {
		t.Fatalf("a negative retry interval must be refused, got %v", err)
	}
}

func TestLoaderAcceptsRetryAndExpected(t *testing.T) {
	scn, err := loadFromLiteral(t, `{
	  "name": "t", "mode": "uds",
	  "defaults": {"retry": {"enabled": false, "interval": "250ms", "max_attempts": 3}},
	  "lanes": {"main": [{"kind": "delta"}]},
	  "fleets": [{"name": "f", "agents": 1, "lanes": ["main"]}],
	  "expected": {"sessions": {"ok": {"gte": 1}, "s5xx": {"eq": 0}}}
	}`)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if scn.Defaults.Retry.RetryEnabled() || scn.Defaults.Retry.RetryInterval() != 250*time.Millisecond ||
		scn.Defaults.Retry.RetryMaxAttempts() != 3 {
		t.Fatalf("retry block not honored: %+v", scn.Defaults.Retry)
	}
	if scn.Expected == nil || len(scn.Expected.Sessions) != 2 {
		t.Fatalf("expected block not parsed: %+v", scn.Expected)
	}
}

func sprintf(format string, args ...any) string {
	out := format
	for _, a := range args {
		out = strings.Replace(out, "%s", a.(string), 1)
	}
	return out
}
