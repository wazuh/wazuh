package agent

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/wire"
)

// TestBuildKeepaliveJSON_MinimalShape asserts the keepalive JSON has
// exactly the fields the user approved (agent.{id,name,version,groups,
// merged_sum}) — nothing extra, and it parses cleanly.
func TestBuildKeepaliveJSON_MinimalShape(t *testing.T) {
	c := &Conn{
		identity: Identity{ID: "042", Name: "bench-test-agent"},
	}
	// Pre-populate the merged_sum to a known value.
	md5 := "c1eecf3d9af9e29bc7baba0a4f2cdc8b"
	c.mergedSum.Store(&md5)

	jsonStr := c.buildKeepaliveJSON([]string{"default"})

	var parsed struct {
		Version string `json:"version"`
		Agent   struct {
			ID         string   `json:"id"`
			Name       string   `json:"name"`
			Version    string   `json:"version"`
			MergedSum  string   `json:"merged_sum"`
			Groups     []string `json:"groups"`
		} `json:"agent"`
		Host    map[string]any `json:"host"`
		Cluster map[string]any `json:"cluster"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, jsonStr)
	}
	if parsed.Version != "1.0" {
		t.Errorf("version = %q, want 1.0", parsed.Version)
	}
	if parsed.Agent.ID != "042" {
		t.Errorf("agent.id = %q", parsed.Agent.ID)
	}
	if parsed.Agent.Name != "bench-test-agent" {
		t.Errorf("agent.name = %q", parsed.Agent.Name)
	}
	if parsed.Agent.Version != wire.AgentVersion {
		t.Errorf("agent.version = %q, want %q", parsed.Agent.Version, wire.AgentVersion)
	}
	if parsed.Agent.MergedSum != md5 {
		t.Errorf("agent.merged_sum = %q", parsed.Agent.MergedSum)
	}
	if len(parsed.Agent.Groups) != 1 || parsed.Agent.Groups[0] != "default" {
		t.Errorf("agent.groups = %v", parsed.Agent.Groups)
	}
	if parsed.Host != nil {
		t.Errorf("minimal keepalive should not include host: %v", parsed.Host)
	}
	if parsed.Cluster != nil {
		t.Errorf("minimal keepalive should not include cluster: %v", parsed.Cluster)
	}
}

// TestBuildKeepaliveJSON_EmptyMergedSum is the first-keepalive case: the
// reader has not seen `#!-up file` yet, so merged_sum is "".
func TestBuildKeepaliveJSON_EmptyMergedSum(t *testing.T) {
	c := &Conn{identity: Identity{ID: "1", Name: "a"}}
	js := c.buildKeepaliveJSON([]string{"default"})
	var parsed struct {
		Agent struct {
			MergedSum string `json:"merged_sum"`
		} `json:"agent"`
	}
	if err := json.Unmarshal([]byte(js), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, js)
	}
	if parsed.Agent.MergedSum != "" {
		t.Errorf("merged_sum should be empty, got %q", parsed.Agent.MergedSum)
	}
}

// TestWriteJSONString_EscapesProperly covers the minimal escaping table.
func TestWriteJSONString_EscapesProperly(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`plain`, `"plain"`},
		{`with "quote"`, `"with \"quote\""`},
		{`back\slash`, `"back\\slash"`},
		{"tab\there", `"tab\there"`},
		{"line\nfeed", `"line\nfeed"`},
		{"\x01ctrl", "\"\\u0001ctrl\""},
	}
	for _, tc := range cases {
		var b strings.Builder
		writeJSONString(&b, tc.in)
		if b.String() != tc.want {
			t.Errorf("in=%q: got %s, want %s", tc.in, b.String(), tc.want)
		}
	}
}

// TestParseFileUpdate_HappyPath: a well-formed `#!-up file <md5> merged.mg\n...`
// payload updates mergedSum and fires the observer.
func TestParseFileUpdate_HappyPath(t *testing.T) {
	c := &Conn{}
	var fired atomic.Int32
	c.SetMergedSumObserver(func(string) { fired.Add(1) })

	md5 := "abcdef0123456789abcdef0123456789"
	body := []byte("#!-up file " + md5 + " merged.mg\nthe rest is ignored")
	c.parseFileUpdate(body)

	if c.MergedSum() != md5 {
		t.Errorf("MergedSum = %q, want %q", c.MergedSum(), md5)
	}
	if fired.Load() != 1 {
		t.Errorf("observer fired %d times, want 1", fired.Load())
	}

	// Second push with the SAME md5 should NOT re-fire (avoid double-counting).
	c.parseFileUpdate(body)
	if fired.Load() != 1 {
		t.Errorf("observer fired %d times after duplicate, want 1", fired.Load())
	}

	// Push with a DIFFERENT md5 fires again.
	md5b := "00000000000000000000000000000000"
	c.parseFileUpdate([]byte("#!-up file " + md5b + " merged.mg\nx"))
	if c.MergedSum() != md5b {
		t.Errorf("MergedSum after update = %q", c.MergedSum())
	}
	if fired.Load() != 2 {
		t.Errorf("observer fired %d times after second hash, want 2", fired.Load())
	}
}

// TestParseFileUpdate_Truncated: malformed inputs are silently ignored
// (no panic, no mergedSum update).
func TestParseFileUpdate_Truncated(t *testing.T) {
	c := &Conn{}
	cases := [][]byte{
		[]byte("#!-up file "),             // no body
		[]byte("#!-up file shortmd5 m\n"), // md5 too short
		[]byte("#!-up file " + "g123456789012345678901234567890" + " m\n"), // non-hex chars (g)
	}
	for i, in := range cases {
		c.parseFileUpdate(in)
		if c.MergedSum() != "" {
			t.Errorf("case %d: MergedSum should stay empty, got %q", i, c.MergedSum())
		}
	}
}

// TestKeepaliveTickerEmitsAtRate stands up a fake remoted listener and
// verifies the ticker sends frames at the configured cadence and stops
// promptly on cancellation.
func TestKeepaliveTickerEmitsAtRate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var frameCount atomic.Int64
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, err := wire.ReadFrame(conn); err != nil {
				if err != io.EOF {
					t.Log("read:", err)
				}
				return
			}
			frameCount.Add(1)
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	identity := Identity{ID: "001", Name: "bench-test", ManagerKey: "deadbeefdeadbeefdeadbeefdeadbeef"}
	c := New(identity, host, port)
	if err := c.Dial(2 * time.Second); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	ctx := context.Background()
	var tickCount atomic.Int64
	stop := c.StartKeepalive(ctx, KeepaliveOptions{
		Interval: 50 * time.Millisecond,
		Groups:   []string{"default"},
		OnTick: func(r KeepaliveResult) {
			if r.Err == nil {
				tickCount.Add(1)
			}
		},
	})

	// 500ms / 50ms = ~10 ticks; allow some scheduling slack.
	time.Sleep(500 * time.Millisecond)
	ticks := tickCount.Load()
	if ticks < 7 || ticks > 14 {
		t.Errorf("ticks in 500ms = %d, want ~10", ticks)
	}

	// Cancel and make sure no more frames go out.
	stop()
	time.Sleep(50 * time.Millisecond)
	before := tickCount.Load()
	time.Sleep(200 * time.Millisecond)
	if tickCount.Load() != before {
		t.Errorf("ticker still emitted after stop: before=%d after=%d", before, tickCount.Load())
	}

	// Frames received by the fake remoted = startup (1) + keepalives (>=7).
	got := frameCount.Load()
	if got < 8 {
		t.Errorf("fake remoted received %d frames, want >= 8 (1 startup + ~10 keepalives)", got)
	}
}

// TestStartKeepalive_ZeroIntervalNoOp confirms that interval=0 returns
// immediately and never emits.
func TestStartKeepalive_ZeroIntervalNoOp(t *testing.T) {
	c := &Conn{identity: Identity{ID: "x", Name: "y"}}
	fired := false
	stop := c.StartKeepalive(context.Background(), KeepaliveOptions{
		Interval: 0,
		OnTick:   func(KeepaliveResult) { fired = true },
	})
	defer stop()
	time.Sleep(100 * time.Millisecond)
	if fired {
		t.Error("OnTick fired with Interval=0")
	}
}
