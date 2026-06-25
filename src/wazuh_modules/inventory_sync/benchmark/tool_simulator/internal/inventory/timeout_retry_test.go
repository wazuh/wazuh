package inventory

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/agent"
	fb "github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/fb/Wazuh/SyncSchema"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/metrics"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/scenario"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/wire"
)

// silentRemoted is a fake manager that drops Start frames for the first
// `dropStarts` Starts it receives, then replies normally. Used to
// simulate the manager's input queue dropping messages under pressure.
type silentRemoted struct {
	t          *testing.T
	addr       string
	aesKey     []byte
	agentID    string
	moduleID   string
	dropStarts int32
	dropEnds   int32
	startsRcv  atomic.Int64
	endsRcv    atomic.Int64
	stopC      chan struct{}
}

func startSilentRemoted(t *testing.T, identity agent.Identity, moduleID string, dropStarts, dropEnds int32) *silentRemoted {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fr := &silentRemoted{
		t:          t,
		addr:       ln.Addr().String(),
		aesKey:     wire.DeriveAESKey(identity.ManagerKey, identity.Name, identity.ID),
		agentID:    identity.ID,
		moduleID:   moduleID,
		dropStarts: dropStarts,
		dropEnds:   dropEnds,
		stopC:      make(chan struct{}),
	}
	go fr.acceptLoop(ln)
	return fr
}

func (fr *silentRemoted) Stop() { close(fr.stopC) }

func (fr *silentRemoted) acceptLoop(ln net.Listener) {
	defer ln.Close()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	go func() {
		<-fr.stopC
		conn.Close()
	}()

	var sessionID uint64
	for {
		frame, err := wire.ReadFrame(conn)
		if err != nil {
			return
		}
		payload, err := wire.DecodeFrame(fr.aesKey, frame)
		if err != nil {
			continue
		}
		if len(payload) < 4 || payload[0] != 's' || payload[1] != ':' {
			continue
		}
		secondColon := -1
		for i := 2; i < len(payload); i++ {
			if payload[i] == ':' {
				secondColon = i
				break
			}
		}
		if secondColon < 0 {
			continue
		}
		fbBytes := payload[secondColon+1:]
		msg := fb.GetRootAsMessage(fbBytes, 0)
		switch msg.ContentType() {
		case fb.MessageTypeStart:
			fr.startsRcv.Add(1)
			if atomic.AddInt32(&fr.dropStarts, -1) >= 0 {
				// silently drop — simulator should time out and retry
				continue
			}
			sessionID++
			_ = fr.sendStartAck(conn, sessionID, fb.StatusOk)
		case fb.MessageTypeEnd:
			fr.endsRcv.Add(1)
			if atomic.AddInt32(&fr.dropEnds, -1) >= 0 {
				continue
			}
			tbl := new(flatbuffers.Table)
			msg.Content(tbl)
			endMsg := new(fb.End)
			endMsg.Init(tbl.Bytes, tbl.Pos)
			_ = fr.sendEndAck(conn, endMsg.Session(), fb.StatusOk)
		}
	}
}

func (fr *silentRemoted) sendStartAck(conn net.Conn, sessionID uint64, status fb.Status) error {
	b := flatbuffers.NewBuilder(64)
	fb.StartAckStart(b)
	fb.StartAckAddStatus(b, status)
	fb.StartAckAddSession(b, sessionID)
	off := fb.StartAckEnd(b)
	fb.MessageStart(b)
	fb.MessageAddContentType(b, fb.MessageTypeStartAck)
	fb.MessageAddContent(b, off)
	b.Finish(fb.MessageEnd(b))
	payload := "#!-" + fr.moduleID + " " + string(b.FinishedBytes())
	frame, err := wire.EncodeText(fr.aesKey, fr.agentID, payload)
	if err != nil {
		return err
	}
	return wire.WriteFrame(conn, frame)
}

func (fr *silentRemoted) sendEndAck(conn net.Conn, sessionID uint64, status fb.Status) error {
	b := flatbuffers.NewBuilder(64)
	fb.EndAckStart(b)
	fb.EndAckAddStatus(b, status)
	fb.EndAckAddSession(b, sessionID)
	off := fb.EndAckEnd(b)
	fb.MessageStart(b)
	fb.MessageAddContentType(b, fb.MessageTypeEndAck)
	fb.MessageAddContent(b, off)
	b.Finish(fb.MessageEnd(b))
	payload := "#!-" + fr.moduleID + " " + string(b.FinishedBytes())
	frame, err := wire.EncodeText(fr.aesKey, fr.agentID, payload)
	if err != nil {
		return err
	}
	return wire.WriteFrame(conn, frame)
}

// timeoutStep builds a step configured for short StartAck/EndAck timeouts
// so the tests run fast.
func timeoutStep(retry int, retryDelay float64) scenario.Step {
	st := baseStep()
	st.StartAckTimeout = 0.25 // 250ms
	st.EndAckTimeout = 0.25
	st.AckTimeoutRetry = retry
	st.AckTimeoutRetryDelay = retryDelay
	return st
}

// connectTo dials the fake remoted and returns the connected Conn,
// auto-cleaned at test end.
func connectTo(t *testing.T, addr string, identity agent.Identity) *agent.Conn {
	t.Helper()
	host, port := hostPort(t, addr)
	conn := agent.New(identity, host, port)
	if err := conn.Dial(2 * time.Second); err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.StartReader(context.Background())
	return conn
}

// Case A: ack_timeout_retry=-1 (default) — first Start dropped → session
// fails immediately, no retry.
func TestAckTimeoutRetry_Disabled_AbortsOnFirstTimeout(t *testing.T) {
	identity := agent.Identity{ID: "001", Name: "bench-test", ManagerKey: "deadbeefdeadbeefdeadbeefdeadbeef"}
	fr := startSilentRemoted(t, identity, "fim_sync", 1, 0)
	defer fr.Stop()

	step := timeoutStep(-1, 0.05)
	conn := connectTo(t, fr.addr, identity)

	c := metrics.New()
	src := New(step, basePayload())
	err := src.Run(context.Background(), conn, c)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	cum := c.Cumulative()
	if cum[metrics.CSessionsFailed] != 1 {
		t.Errorf("sessions_failed = %d, want 1", cum[metrics.CSessionsFailed])
	}
	if fr.startsRcv.Load() != 1 {
		t.Errorf("starts received = %d, want 1 (no retry)", fr.startsRcv.Load())
	}
}

// Case B: ack_timeout_retry=3, manager drops 2 Starts then replies Ok.
// Session completes after 2 retries; no End drops, so it ends cleanly.
func TestAckTimeoutRetry_Start_CompletesAfterRetries(t *testing.T) {
	identity := agent.Identity{ID: "001", Name: "bench-test", ManagerKey: "deadbeefdeadbeefdeadbeefdeadbeef"}
	fr := startSilentRemoted(t, identity, "fim_sync", 2, 0)
	defer fr.Stop()

	step := timeoutStep(3, 0.01)
	conn := connectTo(t, fr.addr, identity)

	c := metrics.New()
	src := New(step, basePayload())
	if err := src.Run(context.Background(), conn, c); err != nil {
		t.Fatalf("Run: %v", err)
	}
	cum := c.Cumulative()
	if cum[metrics.CSessionsCompleted] != 1 {
		t.Errorf("sessions_completed = %d, want 1", cum[metrics.CSessionsCompleted])
	}
	if fr.startsRcv.Load() != 3 {
		t.Errorf("starts received = %d, want 3 (2 dropped + 1 acked)", fr.startsRcv.Load())
	}
	if cum[metrics.CStartRetries] < 2 {
		t.Errorf("start_retries = %d, want >= 2", cum[metrics.CStartRetries])
	}
}

// Case C: ack_timeout_retry=2, manager drops 5 Starts. Budget exhausted.
func TestAckTimeoutRetry_Start_BudgetExhausted(t *testing.T) {
	identity := agent.Identity{ID: "001", Name: "bench-test", ManagerKey: "deadbeefdeadbeefdeadbeefdeadbeef"}
	fr := startSilentRemoted(t, identity, "fim_sync", 5, 0)
	defer fr.Stop()

	step := timeoutStep(2, 0.01)
	conn := connectTo(t, fr.addr, identity)

	c := metrics.New()
	src := New(step, basePayload())
	err := src.Run(context.Background(), conn, c)
	if err == nil {
		t.Fatal("expected timeout error after budget exhaustion")
	}
	cum := c.Cumulative()
	if cum[metrics.CSessionsFailed] != 1 {
		t.Errorf("sessions_failed = %d, want 1", cum[metrics.CSessionsFailed])
	}
	if fr.startsRcv.Load() != 2 {
		t.Errorf("starts received = %d, want 2 (the retry budget)", fr.startsRcv.Load())
	}
}

// Case D: ack_timeout_retry=3, manager replies Start Ok but drops first
// End → end gets retried → session completes.
func TestAckTimeoutRetry_End_CompletesAfterRetry(t *testing.T) {
	identity := agent.Identity{ID: "001", Name: "bench-test", ManagerKey: "deadbeefdeadbeefdeadbeefdeadbeef"}
	fr := startSilentRemoted(t, identity, "fim_sync", 0, 1)
	defer fr.Stop()

	step := timeoutStep(3, 0.01)
	conn := connectTo(t, fr.addr, identity)

	c := metrics.New()
	src := New(step, basePayload())
	if err := src.Run(context.Background(), conn, c); err != nil {
		t.Fatalf("Run: %v", err)
	}
	cum := c.Cumulative()
	if cum[metrics.CSessionsCompleted] != 1 {
		t.Errorf("sessions_completed = %d, want 1", cum[metrics.CSessionsCompleted])
	}
	if cum[metrics.CEndRetries] < 1 {
		t.Errorf("end_retries = %d, want >= 1", cum[metrics.CEndRetries])
	}
	if fr.endsRcv.Load() != 2 {
		t.Errorf("ends received = %d, want 2 (1 dropped + 1 acked)", fr.endsRcv.Load())
	}
}

// Case E: ack_timeout_retry=0 (unlimited), manager drops 10 Ends then
// replies — session completes after many retries.
func TestAckTimeoutRetry_End_Unlimited(t *testing.T) {
	identity := agent.Identity{ID: "001", Name: "bench-test", ManagerKey: "deadbeefdeadbeefdeadbeefdeadbeef"}
	fr := startSilentRemoted(t, identity, "fim_sync", 0, 10)
	defer fr.Stop()

	step := timeoutStep(0, 0.005) // unlimited, fast delay
	conn := connectTo(t, fr.addr, identity)

	c := metrics.New()
	src := New(step, basePayload())
	if err := src.Run(context.Background(), conn, c); err != nil {
		t.Fatalf("Run: %v", err)
	}
	cum := c.Cumulative()
	if cum[metrics.CSessionsCompleted] != 1 {
		t.Errorf("sessions_completed = %d, want 1", cum[metrics.CSessionsCompleted])
	}
	if cum[metrics.CEndRetries] < 10 {
		t.Errorf("end_retries = %d, want >= 10", cum[metrics.CEndRetries])
	}
}

// Case F: per-step start_ack_timeout overrides the package default.
// Without the override the package default (15 s) would govern; the
// per-step 100 ms must win and make the test finish fast.
func TestAckTimeoutOverride_ShortensWait(t *testing.T) {
	identity := agent.Identity{ID: "001", Name: "bench-test", ManagerKey: "deadbeefdeadbeefdeadbeefdeadbeef"}
	fr := startSilentRemoted(t, identity, "fim_sync", 1, 0) // drop 1 Start, no retry → must time out fast
	defer fr.Stop()

	step := baseStep()
	step.StartAckTimeout = 0.10 // 100ms per-step override
	step.AckTimeoutRetry = -1
	conn := connectTo(t, fr.addr, identity)

	c := metrics.New()
	src := New(step, basePayload())

	t0 := time.Now()
	_ = src.Run(context.Background(), conn, c)
	elapsed := time.Since(t0)
	if elapsed > 2*time.Second {
		t.Errorf("Run elapsed %s, expected ~100ms — per-step override not applied", elapsed)
	}
}
