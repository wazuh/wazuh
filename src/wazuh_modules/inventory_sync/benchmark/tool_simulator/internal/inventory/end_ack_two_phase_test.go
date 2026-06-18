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
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/wire"
)

// endStager is a fake manager whose End-ack behavior is driven by a
// per-End reply script. For each End received, it consumes the next
// entry from `endScript` and emits the listed EndAck statuses with
// the listed delays. When the script is exhausted, additional Ends
// are silently dropped (simulating a manager queue full).
//
// Start frames always get an immediate StatusOk.
type endStager struct {
	t        *testing.T
	addr     string
	aesKey   []byte
	agentID  string
	moduleID string

	// endScript[i] is the response plan for the i-th End received.
	// Empty slice → drop the End silently (no ack of any kind).
	endScript [][]endAck

	startsRcv atomic.Int64
	endsRcv   atomic.Int64

	stopC chan struct{}
}

type endAck struct {
	delay  time.Duration
	status fb.Status
}

func startEndStager(t *testing.T, identity agent.Identity, moduleID string, endScript [][]endAck) *endStager {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fr := &endStager{
		t:         t,
		addr:      ln.Addr().String(),
		aesKey:    wire.DeriveAESKey(identity.ManagerKey, identity.Name, identity.ID),
		agentID:   identity.ID,
		moduleID:  moduleID,
		endScript: endScript,
		stopC:     make(chan struct{}),
	}
	go fr.acceptLoop(ln)
	return fr
}

func (fr *endStager) Stop() { close(fr.stopC) }

func (fr *endStager) acceptLoop(ln net.Listener) {
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
			sessionID++
			_ = fr.sendStartAck(conn, sessionID, fb.StatusOk)
		case fb.MessageTypeEnd:
			idx := fr.endsRcv.Add(1) - 1
			tbl := new(flatbuffers.Table)
			msg.Content(tbl)
			endMsg := new(fb.End)
			endMsg.Init(tbl.Bytes, tbl.Pos)
			session := endMsg.Session()
			// Out-of-script Ends are dropped silently.
			if int(idx) >= len(fr.endScript) {
				continue
			}
			plan := fr.endScript[idx]
			go func(plan []endAck, session uint64) {
				for _, step := range plan {
					select {
					case <-time.After(step.delay):
					case <-fr.stopC:
						return
					}
					if err := fr.sendEndAck(conn, session, step.status); err != nil {
						return
					}
				}
			}(plan, session)
		}
	}
}

func (fr *endStager) sendStartAck(conn net.Conn, sessionID uint64, status fb.Status) error {
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

func (fr *endStager) sendEndAck(conn net.Conn, sessionID uint64, status fb.Status) error {
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

// Case 1: no Status_Processing arrives → the SHORT timeout fires fast.
// With AckTimeoutRetry=-1 and end_ack_processing_timeout=150ms,
// end_ack_timeout=10s, the wait must abort in ~150ms, NOT in 10s.
// Verifies that Phase 1 uses the short window.
func TestEndAckTwoPhase_NoProcessing_UsesShortTimeout(t *testing.T) {
	identity := agent.Identity{ID: "001", Name: "bench-test", ManagerKey: "deadbeefdeadbeefdeadbeefdeadbeef"}
	// endScript empty for the first End → silently dropped.
	fr := startEndStager(t, identity, "fim_sync", [][]endAck{{}})
	defer fr.Stop()

	step := baseStep()
	step.StartAckTimeout = 1.0
	step.EndAckProcessingTimeout = 0.15 // 150ms Phase 1
	step.EndAckTimeout = 10.0           // 10s Phase 2 — must NOT be used here
	step.AckTimeoutRetry = -1
	conn := connectTo(t, fr.addr, identity)

	c := metrics.New()
	src := New(step, basePayload())

	t0 := time.Now()
	err := src.Run(context.Background(), conn, c)
	elapsed := time.Since(t0)

	if err == nil {
		t.Fatal("expected EndAck timeout error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("elapsed=%s; Phase 1 short timeout NOT honored (expected ~150ms, got close to EndAckTimeout)", elapsed)
	}
	cum := c.Cumulative()
	if cum[metrics.CSessionsFailed] != 1 {
		t.Errorf("sessions_failed=%d, want 1", cum[metrics.CSessionsFailed])
	}
	if cum[metrics.CEndAckProcessing] != 0 {
		t.Errorf("end_ack_processing=%d, want 0 (no Processing ever received)", cum[metrics.CEndAckProcessing])
	}
}

// Case 2: Processing arrives, then NO Ok → the LONG timeout governs.
// With end_ack_processing_timeout=80ms and end_ack_timeout=500ms,
// the wait must NOT fail in 80ms (Phase 2 is active), but must
// eventually fail in ~500ms.
func TestEndAckTwoPhase_AfterProcessing_UsesLongTimeout(t *testing.T) {
	identity := agent.Identity{ID: "001", Name: "bench-test", ManagerKey: "deadbeefdeadbeefdeadbeefdeadbeef"}
	// First End: Processing immediately, then never finalize.
	fr := startEndStager(t, identity, "fim_sync", [][]endAck{
		{{delay: 10 * time.Millisecond, status: fb.StatusProcessing}},
	})
	defer fr.Stop()

	step := baseStep()
	step.StartAckTimeout = 1.0
	step.EndAckProcessingTimeout = 0.08 // 80ms Phase 1
	step.EndAckTimeout = 0.5            // 500ms Phase 2
	step.AckTimeoutRetry = -1
	conn := connectTo(t, fr.addr, identity)

	c := metrics.New()
	src := New(step, basePayload())

	t0 := time.Now()
	err := src.Run(context.Background(), conn, c)
	elapsed := time.Since(t0)

	if err == nil {
		t.Fatal("expected EndAck timeout error, got nil")
	}
	// Must be at least the Phase 2 window — not the Phase 1 window.
	if elapsed < 400*time.Millisecond {
		t.Errorf("elapsed=%s; Phase 2 long timeout NOT honored (failed too fast — Phase 1 timeout applied after Processing?)", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Errorf("elapsed=%s; way over Phase 2 budget (500ms)", elapsed)
	}
	cum := c.Cumulative()
	if cum[metrics.CEndAckProcessing] != 1 {
		t.Errorf("end_ack_processing=%d, want 1", cum[metrics.CEndAckProcessing])
	}
	if cum[metrics.CSessionsFailed] != 1 {
		t.Errorf("sessions_failed=%d, want 1", cum[metrics.CSessionsFailed])
	}
}

// Case 3: Processing then Ok within the long window → session completes.
// Phase 1 must NOT fire even though end_ack_processing_timeout is short.
func TestEndAckTwoPhase_ProcessingThenOk_Completes(t *testing.T) {
	identity := agent.Identity{ID: "001", Name: "bench-test", ManagerKey: "deadbeefdeadbeefdeadbeefdeadbeef"}
	fr := startEndStager(t, identity, "fim_sync", [][]endAck{
		{
			{delay: 10 * time.Millisecond, status: fb.StatusProcessing},
			{delay: 300 * time.Millisecond, status: fb.StatusOk}, // 300ms after Processing
		},
	})
	defer fr.Stop()

	step := baseStep()
	step.StartAckTimeout = 1.0
	step.EndAckProcessingTimeout = 0.10 // 100ms Phase 1
	step.EndAckTimeout = 1.0            // 1s Phase 2 — covers the 300ms gap
	step.AckTimeoutRetry = -1
	conn := connectTo(t, fr.addr, identity)

	c := metrics.New()
	src := New(step, basePayload())

	if err := src.Run(context.Background(), conn, c); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	cum := c.Cumulative()
	if cum[metrics.CSessionsCompleted] != 1 {
		t.Errorf("sessions_completed=%d, want 1", cum[metrics.CSessionsCompleted])
	}
	if cum[metrics.CEndAckProcessing] != 1 {
		t.Errorf("end_ack_processing=%d, want 1", cum[metrics.CEndAckProcessing])
	}
	if cum[metrics.CEndAckOk] != 1 {
		t.Errorf("end_ack_ok=%d, want 1", cum[metrics.CEndAckOk])
	}
}

// Case 4: Phase 1 timeout triggers retry → second End gets Processing → Ok.
// With ack_timeout_retry=3, the first End is dropped, the SHORT Phase 1
// timeout fires fast, the simulator resends End, the second End gets
// Processing+Ok. Total elapsed must be close to Phase 1 timeout +
// processing delay + ok delay, NOT the full Phase 2 budget per try.
func TestEndAckTwoPhase_ShortTimeoutTriggersRetry(t *testing.T) {
	identity := agent.Identity{ID: "001", Name: "bench-test", ManagerKey: "deadbeefdeadbeefdeadbeefdeadbeef"}
	fr := startEndStager(t, identity, "fim_sync", [][]endAck{
		{}, // first End: drop silently
		{   // second End: Processing then Ok
			{delay: 10 * time.Millisecond, status: fb.StatusProcessing},
			{delay: 50 * time.Millisecond, status: fb.StatusOk},
		},
	})
	defer fr.Stop()

	step := baseStep()
	step.StartAckTimeout = 1.0
	step.EndAckProcessingTimeout = 0.10 // 100ms — short, fires fast on dropped End
	step.EndAckTimeout = 5.0            // 5s — if mistakenly used, the test would be slow
	step.AckTimeoutRetry = 3
	step.AckTimeoutRetryDelay = 0.01 // 10ms between retries
	conn := connectTo(t, fr.addr, identity)

	c := metrics.New()
	src := New(step, basePayload())

	t0 := time.Now()
	if err := src.Run(context.Background(), conn, c); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	elapsed := time.Since(t0)

	// First End times out at Phase 1 (~100ms); retry; second End Ok in ~60ms.
	// Should be well under 1s — definitely under Phase 2 worst-case.
	if elapsed > 2*time.Second {
		t.Errorf("elapsed=%s; Phase 1 timeout didn't trigger retry fast (looks like Phase 2 ran for the dropped End)", elapsed)
	}
	cum := c.Cumulative()
	if cum[metrics.CSessionsCompleted] != 1 {
		t.Errorf("sessions_completed=%d, want 1", cum[metrics.CSessionsCompleted])
	}
	if cum[metrics.CEndRetries] < 1 {
		t.Errorf("end_retries=%d, want >= 1", cum[metrics.CEndRetries])
	}
	if got := fr.endsRcv.Load(); got < 2 {
		t.Errorf("ends received=%d, want >= 2 (first dropped + retry acked)", got)
	}
}
