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

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/scenario"
)

// scriptedSocket answers the i-th request with statuses[i] (the last status
// repeats) and records every request body.
func scriptedSocket(t *testing.T, statuses ...int) (string, func() []string) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "engine-ingest-http.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var bodies []string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		i := len(bodies)
		bodies = append(bodies, string(body))
		mu.Unlock()
		w.WriteHeader(statuses[min(i, len(statuses)-1)])
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), bodies...)
	}
}

// agentBatchRun runs one pass of an "agent"-batching engine step over n
// sample lines ("line-00".."line-<n-1>") against sock, and returns the runner.
func agentBatchRun(t *testing.T, sock string, n int, tune func(*scenario.Step)) *Runner {
	t.Helper()
	var lines []string
	for i := 0; i < n; i++ {
		lines = append(lines, "line-"+string(rune('0'+i/10))+string(rune('0'+i%10)))
	}
	sample := filepath.Join(t.TempDir(), "sample.log")
	if err := os.WriteFile(sample, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	zero := scenario.Duration(0)
	step := scenario.Step{Kind: "engine", Engine: sample, Location: "syslog", Batching: scenario.BatchingAgent,
		EventsPerSecond: 1000, BatchInterval: scenario.Duration(time.Hour), StartJitter: &zero}
	if tune != nil {
		tune(&step)
	}
	r := New(Config{
		Scenario: &scenario.Scenario{
			Name: "agent-batching-test", Mode: "uds",
			Lanes:  map[string][]scenario.Step{"engine": {step}},
			Fleets: []scenario.Fleet{{Name: "linux", Agents: 1, FirstID: 7, Lanes: []string{"engine"}}},
		},
		Mode: "uds", Socket: sock, Timeout: 5 * time.Second, Seed: 42,
	})
	agents, err := r.buildAgents(context.Background())
	if err != nil {
		t.Fatalf("buildAgents: %v", err)
	}
	agents[0].runEngine(context.Background(), "engine", step)
	return r
}

// eventLines returns the "E" lines of a batch body.
func eventLines(body string) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		if strings.HasPrefix(l, "E ") {
			out = append(out, l)
		}
	}
	return out
}

// The size trigger: no request carries more "E" bytes than batch_size_bytes,
// events keep their order, and the last pass drains what is left.
func TestAgentBatchingFlushesBySizeAndDrainsOnTheLastPass(t *testing.T) {
	sock, received := scriptedSocket(t, http.StatusOK)
	size := 3 * eventLineBytes("syslog", "line-00")
	r := agentBatchRun(t, sock, 10, func(s *scenario.Step) { s.BatchSizeBytes = size })

	var got []string
	for i, body := range received() {
		events := eventLines(body)
		bytes := 0
		for _, e := range events {
			bytes += len(e) + 1
		}
		if len(events) == 0 || bytes > size {
			t.Errorf("request %d carries %d events / %d bytes, want 1..%d bytes", i, len(events), bytes, size)
		}
		got = append(got, events...)
	}
	if len(received()) != 4 || len(got) != 10 || got[0] != "E 1:syslog:line-00" || got[9] != "E 1:syslog:line-09" {
		t.Fatalf("requests = %d, events = %v; want 4 requests carrying line-00..line-09 in order", len(received()), got)
	}
	if c := r.reg.GlobalSnapshot().C; c.St202 != 4 || c.EventsSent != 10 || c.EventsDropped != 0 {
		t.Errorf("counters: s202=%d events=%d dropped=%d, want 4/10/0", c.St202, c.EventsSent, c.EventsDropped)
	}
}

// The interval trigger: with a size never reached, a slow producer still
// flushes every batch_interval instead of waiting for the end of the pass.
func TestAgentBatchingFlushesOnTheInterval(t *testing.T) {
	sock, received := scriptedSocket(t, http.StatusOK)
	agentBatchRun(t, sock, 10, func(s *scenario.Step) {
		s.EventsPerSecond = 50 // 10 events over 200 ms
		s.BatchInterval = scenario.Duration(60 * time.Millisecond)
	})
	total := 0
	for _, body := range received() {
		total += len(eventLines(body))
	}
	if len(received()) < 2 || total != 10 {
		t.Fatalf("requests = %d carrying %d events; want several interval flushes carrying all 10", len(received()), total)
	}
}

// A 503 is retried with the same batch, as the agent's RetrySender does, and
// the events are counted once, not once per try.
func TestAgentBatchingRetriesA503WithTheSameBatch(t *testing.T) {
	defer func(base time.Duration) { agentBackoffBase = base }(agentBackoffBase)
	agentBackoffBase = time.Millisecond
	sock, received := scriptedSocket(t, http.StatusServiceUnavailable, http.StatusServiceUnavailable, http.StatusOK)
	r := agentBatchRun(t, sock, 5, nil)

	reqs := received()
	if len(reqs) != 3 || reqs[0] != reqs[1] || reqs[1] != reqs[2] {
		t.Fatalf("requests = %d; want the same batch tried 3 times", len(reqs))
	}
	c := r.reg.GlobalSnapshot().C
	if c.St503 != 2 || c.St202 != 1 || c.StatelessRetries != 2 || c.StatelessRetriesExhausted != 0 || c.EventsSent != 5 {
		t.Errorf("counters: s503=%d s202=%d retries=%d exhausted=%d events=%d, want 2/1/2/0/5",
			c.St503, c.St202, c.StatelessRetries, c.StatelessRetriesExhausted, c.EventsSent)
	}
}

// With the try budget spent, the batch stays buffered (the agent keeps it) and
// the final drain gives up instead of holding the run open.
func TestAgentBatchingKeepsAnUndeliverableBatchAndStopsDraining(t *testing.T) {
	defer func(base time.Duration) { agentBackoffBase = base }(agentBackoffBase)
	agentBackoffBase = time.Millisecond
	sock, received := scriptedSocket(t, http.StatusServiceUnavailable)
	r := agentBatchRun(t, sock, 5, func(s *scenario.Step) { s.RetryMaxAttempts = 2 })

	if len(received()) != 2 {
		t.Fatalf("requests = %d, want the 2 tries of one flush", len(received()))
	}
	if c := r.reg.GlobalSnapshot().C; c.StatelessRetriesExhausted != 1 || c.StatelessRetries != 1 {
		t.Errorf("counters: exhausted=%d retries=%d, want 1/1", c.StatelessRetriesExhausted, c.StatelessRetries)
	}
}

// Past the buffer cap (batch size x 4) the newest event is dropped and counted.
func TestAgentBatchingDropsTheNewestEventAtTheBufferCap(t *testing.T) {
	r := New(Config{Scenario: &scenario.Scenario{Name: "cap", Mode: "uds"}, Mode: "uds"})
	a := &agent{r: r, fleet: scenario.Fleet{Name: "linux"}, id: "007"}
	st := a.engineStream("engine")
	per := eventLineBytes("syslog", "x")
	for i := 0; i < 5; i++ {
		st.add(a, "engine", "syslog", "x", 4*per)
	}
	if len(st.lines) != 4 || st.bytes != 4*per {
		t.Fatalf("buffered %d events / %d bytes, want 4 / %d", len(st.lines), st.bytes, 4*per)
	}
	if c := r.reg.GlobalSnapshot().C; c.EventsDropped != 1 {
		t.Errorf("events_dropped = %d, want 1", c.EventsDropped)
	}
	if n := st.snapshot(per - 1); n != 1 {
		t.Errorf("snapshot below one event's size = %d, want 1 (never fewer than one)", n)
	}
	st.consume(3)
	if len(st.lines) != 1 || st.bytes != per {
		t.Errorf("after consume: %d events / %d bytes, want 1 / %d", len(st.lines), st.bytes, per)
	}
}

// The start jitter is applied once per lane and stays within its bound.
func TestStartJitterIsBoundedAndAppliedOnce(t *testing.T) {
	r := New(Config{Scenario: &scenario.Scenario{Name: "jitter", Mode: "uds"}, Mode: "uds", Seed: 7})
	a := &agent{r: r, id: "007"}
	st := a.engineStream("engine")
	start := time.Now()
	if err := a.applyStartJitter(context.Background(), st, 40*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if first := time.Since(start); first > 200*time.Millisecond {
		t.Errorf("first wait %v exceeds the 40ms jitter by far", first)
	}
	start = time.Now()
	_ = a.applyStartJitter(context.Background(), st, time.Hour)
	if again := time.Since(start); again > 50*time.Millisecond {
		t.Errorf("second call waited %v; the jitter must apply once", again)
	}
}

// The full-jitter backoff never exceeds min(cap, base * 2^attempt).
func TestAgentBackoffStaysUnderItsCeiling(t *testing.T) {
	r := New(Config{Scenario: &scenario.Scenario{Name: "backoff", Mode: "uds"}, Mode: "uds", Seed: 3})
	st := (&agent{r: r, id: "007"}).engineStream("engine")
	for i, ceiling := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 32 * time.Second, 60 * time.Second, 60 * time.Second} {
		if d := st.nextBackoff(); d < 0 || d > ceiling {
			t.Errorf("attempt %d: delay %v outside [0, %v]", i, d, ceiling)
		}
	}
}
