package engine

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/agent"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/metrics"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/scenario"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/wire"
)

// TestEngineSource_SingleFile_NoLoop reads a file with 5 lines, no loop,
// and asserts exactly 5 frames arrive at a fake "remoted" listener with
// the expected `1:<location>:<line>` content.
func TestEngineSource_SingleFile_NoLoop(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "syslog.log")
	lines := []string{
		"Jun  1 00:00:01 host A",
		"Jun  1 00:00:02 host B",
		"Jun  1 00:00:03 host C",
		"Jun  1 00:00:04 host D",
		"Jun  1 00:00:05 host E",
	}
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(logPath, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}

	// Fake remoted server: accept one connection, decode each frame.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	identity := agent.Identity{ID: "001", Name: "bench-test", ManagerKey: "deadbeefdeadbeefdeadbeefdeadbeef"}
	aesKey := wire.DeriveAESKey(identity.ManagerKey, identity.Name, identity.ID)

	receivedC := make(chan string, 16)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// First frame is the control message — drain it.
		_, _ = wire.ReadFrame(conn)
		for {
			frame, err := wire.ReadFrame(conn)
			if err != nil {
				if err != io.EOF {
					t.Log("read:", err)
				}
				return
			}
			payload, err := wire.DecodeFrame(aesKey, frame)
			if err != nil {
				t.Logf("decode: %v", err)
				continue
			}
			receivedC <- string(payload)
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	conn := agent.New(identity, host, port)
	if err := conn.Dial(2 * time.Second); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	step := scenario.Step{
		Kind:           scenario.SourceKindEngine,
		EnginePath:     logPath,
		EngineLocation: "syslog",
		EngineLoop:     false,
		MaxEPS:         10000,
	}
	src := New(step)
	c := metrics.New()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := src.Run(ctx, conn, c); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Collect frames with a small deadline.
	got := make([]string, 0, len(lines))
	deadline := time.After(1 * time.Second)
collect:
	for {
		select {
		case payload := <-receivedC:
			got = append(got, payload)
			if len(got) == len(lines) {
				break collect
			}
		case <-deadline:
			break collect
		}
	}
	if len(got) != len(lines) {
		t.Fatalf("got %d frames, want %d:\n%v", len(got), len(lines), got)
	}
	for i, line := range lines {
		want := "1:syslog:" + line
		if got[i] != want {
			t.Fatalf("frame %d:\n  got:  %q\n  want: %q", i, got[i], want)
		}
	}

	// Counters reflect the activity.
	cum := c.Cumulative()
	if cum[metrics.CEngineEventsSent] != int64(len(lines)) {
		t.Fatalf("engine_events_sent = %d, want %d", cum[metrics.CEngineEventsSent], len(lines))
	}
	if cum[metrics.CMessagesSent] != int64(len(lines)) {
		t.Fatalf("messages_sent = %d, want %d", cum[metrics.CMessagesSent], len(lines))
	}
	if cum[metrics.CEngineFilesEOFWrap] != 0 {
		t.Fatalf("eof_wrap should be 0 with loop=false, got %d", cum[metrics.CEngineFilesEOFWrap])
	}
}

// TestEngineSource_Loop_RewindsOnEOF reads a tiny file with loop=true
// and confirms more frames arrive than the file holds, and that
// engine_files_eof_wrap counter advances.
func TestEngineSource_Loop_RewindsOnEOF(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "small.log")
	if err := os.WriteFile(logPath, []byte("a\nb\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	identity := agent.Identity{ID: "001", Name: "bench-test", ManagerKey: "k"}
	frameCount := int64(0)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		for {
			_, err := wire.ReadFrame(r)
			if err != nil {
				return
			}
			atomic.AddInt64(&frameCount, 1)
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	conn := agent.New(identity, host, port)
	if err := conn.Dial(2 * time.Second); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	step := scenario.Step{
		Kind:           scenario.SourceKindEngine,
		EnginePath:     logPath,
		EngineLocation: "loc",
		EngineLoop:     true,
		MaxEPS:         200,
	}
	src := New(step)
	cm := metrics.New()
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	_ = src.Run(ctx, conn, cm)

	cum := cm.Cumulative()
	if cum[metrics.CEngineEventsSent] < 4 {
		t.Fatalf("engine_events_sent = %d, want >= 4 in 0.6s @ 200 eps with 2-line loop",
			cum[metrics.CEngineEventsSent])
	}
	if cum[metrics.CEngineFilesEOFWrap] < 1 {
		t.Fatalf("eof_wrap = %d, want >= 1", cum[metrics.CEngineFilesEOFWrap])
	}
}
