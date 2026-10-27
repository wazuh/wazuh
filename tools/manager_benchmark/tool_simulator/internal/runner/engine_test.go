package runner

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/engine"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/scenario"
)

type engineRequest struct {
	path, agentID, contentType, body string
}

// fakeEngine serves POST /events/enriched on a Unix socket the way the engine
// does: 200 with an empty body. It records every request it receives.
func fakeEngine(t *testing.T) (string, func() []engineRequest) {
	t.Helper()
	return fakeSocket(t, http.StatusOK)
}

// fakeSocket answers every request with status and records it.
func fakeSocket(t *testing.T, status int) (string, func() []engineRequest) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "engine-ingest-http.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []engineRequest
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, engineRequest{r.URL.Path, r.Header.Get("X-Wazuh-Agent-Id"), r.Header.Get("Content-Type"), string(body)})
		mu.Unlock()
		w.WriteHeader(status)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock, func() []engineRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]engineRequest(nil), got...)
	}
}

func udsEngineRunner(t *testing.T, sock string, firstID int) (*Runner, scenario.Step) {
	t.Helper()
	sample := filepath.Join(t.TempDir(), "sample.log")
	if err := os.WriteFile(sample, []byte("one\ntwo\nthree\nfour\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	step := scenario.Step{Kind: "engine", Engine: sample, Location: "syslog", EventsPerBatch: 1,
		Header: &engine.HeaderSpec{ChangeEvery: 2}}
	r := New(Config{
		Scenario: &scenario.Scenario{
			Name: "engine-direct-test", Mode: "uds",
			Lanes:  map[string][]scenario.Step{"engine": {step}},
			Fleets: []scenario.Fleet{{Name: "linux", Agents: 1, FirstID: firstID, Lanes: []string{"engine"}}},
		},
		Mode: "uds", Socket: sock, Timeout: 5 * time.Second,
	})
	return r, step
}

// A uds engine step is a direct engine producer: it must post to the engine's
// own route and carry the agent id outside the body, as remoted does.
func TestUDSEngineStepPostsToTheEngineWithTheCarrier(t *testing.T) {
	sock, received := fakeEngine(t)
	r, step := udsEngineRunner(t, sock, 7)

	agents, err := r.buildAgents(context.Background())
	if err != nil {
		t.Fatalf("buildAgents: %v", err)
	}
	agents[0].runEngine(context.Background(), "engine", step)

	reqs := received()
	if len(reqs) != 4 {
		t.Fatalf("requests = %d, want one per event (events_per_batch 1)", len(reqs))
	}
	for i, req := range reqs {
		if req.path != "/events/enriched" || req.agentID != "007" || req.contentType != "application/x-ndjson" {
			t.Errorf("request %d = path %q, X-Wazuh-Agent-Id %q, Content-Type %q", i, req.path, req.agentID, req.contentType)
		}
		if !strings.HasPrefix(req.body, `H {"wazuh":{"agent":{"id":"007",`) {
			t.Errorf("request %d: H line must carry the same canonical id: %q", i, req.body)
		}
	}
	// change_every 2: batches 0,1 share a header; batch 2 has the next one.
	header := func(i int) string { return strings.SplitN(reqs[i].body, "\n", 2)[0] }
	if header(0) != header(1) || header(1) == header(2) {
		t.Errorf("header must change every 2 batches: %q", []string{header(0), header(1), header(2)})
	}
	// The engine's 200 lands in the same success bucket as remoted's 202.
	if g := r.reg.GlobalSnapshot().C; g.St202 != 4 || g.StOther != 0 || g.EventsSent != 4 {
		t.Errorf("counters: s202=%d other=%d events=%d, want 4/0/4", g.St202, g.StOther, g.EventsSent)
	}
}

func TestUDSIdsAreCanonical(t *testing.T) {
	sock, _ := fakeEngine(t)
	for _, tc := range []struct {
		first int
		want  string
	}{{1, "001"}, {42, "042"}, {100, "100"}, {24000, "24000"}} {
		r, _ := udsEngineRunner(t, sock, tc.first)
		agents, err := r.buildAgents(context.Background())
		if err != nil {
			t.Fatalf("buildAgents: %v", err)
		}
		if agents[0].id != tc.want {
			t.Errorf("first_id %d: id %q, want %q", tc.first, agents[0].id, tc.want)
		}
	}
}

// A uds run has one --socket, inventory-sync's by default. Engine batches sent
// there are answered 404 and would all be lost, so the run must stop instead of
// counting them as "other".
func TestUDSEngineStepOnTheWrongSocketInvalidatesTheRun(t *testing.T) {
	sock, received := fakeSocket(t, http.StatusNotFound)
	r, step := udsEngineRunner(t, sock, 7)

	agents, err := r.buildAgents(context.Background())
	if err != nil {
		t.Fatalf("buildAgents: %v", err)
	}
	agents[0].runEngine(context.Background(), "engine", step)

	if len(received()) != 1 {
		t.Fatalf("requests = %d, want the run to stop at the first 404", len(received()))
	}
	if r.failErr == nil || !strings.Contains(r.failErr.Error(), "engine ingest socket") {
		t.Fatalf("failErr = %v, want the --socket hint", r.failErr)
	}
}

// An "agent" profile header carries what a real agent of that fleet reports
// about itself, and stays byte-identical from batch to batch.
func TestAgentProfileHeaderCarriesTheFleetMetadata(t *testing.T) {
	sock, received := fakeEngine(t)
	r, step := udsEngineRunner(t, sock, 7)
	r.scn.Defaults.ClusterName = "cluster01"
	r.scn.Fleets[0].Start = scenario.StartMeta{Architecture: "x86_64", OSName: "Ubuntu", OSPlatform: "ubuntu",
		OSType: "linux", OSVersion: "22.04", AgentVersion: "5.0.0"}
	step.Header = &engine.HeaderSpec{Profile: engine.ProfileAgent}

	agents, err := r.buildAgents(context.Background())
	if err != nil {
		t.Fatalf("buildAgents: %v", err)
	}
	agents[0].runEngine(context.Background(), "engine", step)

	reqs := received()
	want := `H {"wazuh":{"agent":{"groups":["default"],"host":{"architecture":"x86_64","hostname":"bench-linux-0007",` +
		`"os":{"name":"Ubuntu","platform":"ubuntu","type":"linux","version":"22.04"}},"id":"007",` +
		`"name":"bench-linux-0007","version":"v5.0.0"},"cluster":{"name":"cluster01"}}}`
	for i, req := range reqs {
		if got := strings.SplitN(req.body, "\n", 2)[0]; got != want {
			t.Fatalf("request %d H line:\n got %s\nwant %s", i, got, want)
		}
	}
	if len(reqs) != 4 {
		t.Fatalf("requests = %d, want 4", len(reqs))
	}
}
