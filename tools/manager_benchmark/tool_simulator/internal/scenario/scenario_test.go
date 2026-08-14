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
		// with_checksum was retired, not defaulted: every generated document
		// carries checksum.hash.sha1 because every real one does, so a file
		// still asking for it must fail loudly rather than read as a knob.
		`{"kind": "delta", "documents": {"count": 1, "with_checksum": true}}`,
		`{"kind": "delta", "documents": {"count": 1, "with_checksum": false}}`,
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
	// cluster_node too: the manager never validated it and is dropping its last
	// consumer, and the value the tool used to send was read out of the manager's
	// own config -- a scenario declaring it must fail, not silently be ignored.
	if _, err := loadFromLiteral(t,
		`{"name":"t","mode":"uds","defaults":{"cluster_name":"c","cluster_node":"node01"},"lanes":{"main":[{"kind":"delta"}]},"fleets":[{"name":"f","agents":1,"lanes":["main"]}]}`); err == nil {
		t.Fatal("defaults.cluster_node was retired and must be refused")
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

// A scan_vd step is a request to remoted, not a session, so the loader has to
// refuse the two ways an author can get it wrong: asking for it where the route
// does not exist (uds), and describing a payload it will never send.
func TestLoaderConstrainsScanVD(t *testing.T) {
	if _, err := loadFromLiteral(t, sprintf(minimalUDS, `{"kind": "scan_vd"}`, "")); err == nil ||
		!strings.Contains(err.Error(), "agent-mode only") {
		t.Fatalf("scan_vd in uds mode must be refused (POST /scan/vd is a remoted route), got %v", err)
	}

	const minimalAgent = `{
	  "name": "t", "mode": "agent",
	  "lanes": {"main": [%s]},
	  "fleets": [{"name": "f", "agents": 1, "first_id": 1, "lanes": ["main"]}]
	}`
	for _, body := range []string{
		`{"kind": "scan_vd", "documents": {"count": 5}}`,
		`{"kind": "scan_vd", "dump": "../whatever.json"}`,
		`{"kind": "scan_vd", "module": "syscollector_vd"}`,
		`{"kind": "scan_vd", "option": "VDFirst"}`,
		`{"kind": "scan_vd", "indices": ["wazuh-states-inventory-packages"]}`,
	} {
		if _, err := loadFromLiteral(t, sprintf(minimalAgent, body)); err == nil {
			t.Errorf("scan_vd carrying a payload field must be refused: %s", body)
		}
	}

	// What it DOES take: the timing fields and a feed_offset override (the
	// deliberate-409 contract case).
	scn, err := loadFromLiteral(t, sprintf(minimalAgent,
		`{"kind": "scan_vd", "initial_delay": "60s", "repeat_count": 2, "repeat_delay": "5s", "feed_offset": 1}`))
	if err != nil {
		t.Fatalf("a well-formed scan_vd step must load: %v", err)
	}
	step := scn.Lanes["main"][0]
	if step.InitialDelay.D() != time.Minute || step.RepeatCount != 2 ||
		step.FeedOffset == nil || *step.FeedOffset != 1 {
		t.Fatalf("scan_vd fields not honored: %+v", step)
	}
}

func sprintf(format string, args ...any) string {
	out := format
	for _, a := range args {
		out = strings.Replace(out, "%s", a.(string), 1)
	}
	return out
}

func TestLoaderConstrainsCompression(t *testing.T) {
	// Unknown value refused by name.
	if _, err := loadFromLiteral(t, sprintf(minimalUDS, `{"kind": "delta"}`,
		`, "defaults": {"compression": "gzip"}`)); err == nil || !strings.Contains(err.Error(), "gzip") {
		t.Fatalf("an unknown compression must be refused by name, got %v", err)
	}
	// EXPLICIT zstd in uds mode refused: the UDS ingress has no decoder.
	if _, err := loadFromLiteral(t, sprintf(minimalUDS, `{"kind": "delta"}`,
		`, "defaults": {"compression": "zstd"}`)); err == nil || !strings.Contains(err.Error(), "agent mode") {
		t.Fatalf("explicit zstd over uds must be refused, got %v", err)
	}
	// "none" loads anywhere; an ABSENT value loads anywhere too (it resolves
	// per transport instead of erroring).
	if _, err := loadFromLiteral(t, sprintf(minimalUDS, `{"kind": "delta"}`,
		`, "defaults": {"compression": "none"}`)); err != nil {
		t.Fatalf(`"none" must load in uds mode: %v`, err)
	}
	scn, err := loadFromLiteral(t, `{
	  "name": "t", "mode": "agent",
	  "defaults": {"compression": "zstd"},
	  "lanes": {"main": [{"kind": "delta"}]},
	  "fleets": [{"name": "f", "agents": 1, "lanes": ["main"]}]
	}`)
	if err != nil || scn.Defaults.Compression != "zstd" {
		t.Fatalf("zstd in agent mode must load: %v, %+v", err, scn)
	}
}

// feed_offset is a pointer so a scenario can force a version_mismatch test by
// declaring it explicitly as 0 -- that must stay distinguishable from a step
// that never mentions the field at all (deferring to -vd-feed-offset or the
// agent's learned value; see runner.agent.feedOffsetFor).
func TestLoaderParsesFeedOffset(t *testing.T) {
	scn, err := loadFromLiteral(t, sprintf(minimalUDS,
		`{"kind": "delta", "option": "VDFirst", "feed_offset": 0}`, ""))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	step := scn.Lanes["main"][0]
	if step.FeedOffset == nil {
		t.Fatal("an explicit feed_offset of 0 must still be present (non-nil), not absent")
	}
	if *step.FeedOffset != 0 {
		t.Fatalf("feed_offset = %d, want 0", *step.FeedOffset)
	}

	scn, err = loadFromLiteral(t, sprintf(minimalUDS, `{"kind": "delta"}`, ""))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if scn.Lanes["main"][0].FeedOffset != nil {
		t.Fatalf("an absent feed_offset must stay nil, got %v", *scn.Lanes["main"][0].FeedOffset)
	}
}

// The DEFAULT is what a real agent does on each transport: zstd over remoted,
// plain over the local socket. "none" opts out; an explicit "zstd" sticks.
func TestCompressionForResolvesTheDefaultPerTransport(t *testing.T) {
	var d Defaults
	if got := d.CompressionFor("agent"); got != "zstd" {
		t.Fatalf("absent must default to zstd in agent mode, got %q", got)
	}
	if got := d.CompressionFor("uds"); got != "" {
		t.Fatalf("absent must stay plain in uds mode, got %q", got)
	}
	d.Compression = "none"
	if got := d.CompressionFor("agent"); got != "" {
		t.Fatalf(`"none" must win over the agent-mode default, got %q`, got)
	}
	d.Compression = "zstd"
	if got := d.CompressionFor("agent"); got != "zstd" {
		t.Fatalf("explicit zstd must stick, got %q", got)
	}
}
