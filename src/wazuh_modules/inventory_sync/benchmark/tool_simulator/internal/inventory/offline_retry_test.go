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

// fakeRemoted is a single-connection fake manager that:
//   1. Drains the startup control frame
//   2. For each Start it receives, sends back a StartAck whose status is
//      determined by the next entry in `replies`
//   3. After the last "Ok" reply, sends an EndAck Ok so the runner can
//      complete the session cleanly (when applicable)
//
// `replies` is a queue of fb.Status values, consumed one per inbound
// Start. When exhausted, every additional Start gets Status_Offline.
type fakeRemoted struct {
	t        *testing.T
	addr     string
	aesKey   []byte
	agentID  string
	moduleID string

	replies   []fb.Status
	startsRcv atomic.Int64
	endsRcv   atomic.Int64

	stopC chan struct{}
}

func startFakeRemotedOfflineCycler(t *testing.T, identity agent.Identity, moduleID string, replies []fb.Status) *fakeRemoted {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fr := &fakeRemoted{
		t:        t,
		addr:     ln.Addr().String(),
		aesKey:   wire.DeriveAESKey(identity.ManagerKey, identity.Name, identity.ID),
		agentID:  identity.ID,
		moduleID: moduleID,
		replies:  replies,
		stopC:    make(chan struct{}),
	}
	go fr.acceptLoop(ln)
	return fr
}

func (fr *fakeRemoted) Stop() { close(fr.stopC) }

func (fr *fakeRemoted) acceptLoop(ln net.Listener) {
	defer ln.Close()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	// Drain the startup control frame and any keepalives.
	go func() {
		<-fr.stopC
		conn.Close()
	}()

	replyIdx := 0
	var lastSessionID uint64
	for {
		frame, err := wire.ReadFrame(conn)
		if err != nil {
			// Don't t.Logf here — this goroutine may outlive the test
			// when Stop() races with a pending ReadFrame, and calling
			// the testing.T after FAIL/PASS panics.
			return
		}
		payload, err := wire.DecodeFrame(fr.aesKey, frame)
		if err != nil {
			continue
		}
		// Only react to `s:<moduleID>:<fb>` (inventory_sync) frames.
		if len(payload) < 4 || payload[0] != 's' || payload[1] != ':' {
			continue
		}
		// Find the second ':'.
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
			status := fb.StatusOffline // exhausted → Offline forever
			if replyIdx < len(fr.replies) {
				status = fr.replies[replyIdx]
				replyIdx++
			}
			lastSessionID++
			if err := fr.sendStartAck(conn, lastSessionID, status); err != nil {
				return
			}
		case fb.MessageTypeEnd:
			fr.endsRcv.Add(1)
			tbl := new(flatbuffers.Table)
			msg.Content(tbl)
			endMsg := new(fb.End)
			endMsg.Init(tbl.Bytes, tbl.Pos)
			if err := fr.sendEndAck(conn, endMsg.Session(), fb.StatusOk); err != nil {
				return
			}
		}
	}
}

func (fr *fakeRemoted) sendStartAck(conn net.Conn, sessionID uint64, status fb.Status) error {
	b := flatbuffers.NewBuilder(64)
	fb.StartAckStart(b)
	fb.StartAckAddStatus(b, status)
	fb.StartAckAddSession(b, sessionID)
	off := fb.StartAckEnd(b)
	fb.MessageStart(b)
	fb.MessageAddContentType(b, fb.MessageTypeStartAck)
	fb.MessageAddContent(b, off)
	b.Finish(fb.MessageEnd(b))
	fbBytes := b.FinishedBytes()
	// Inbound shape: "#!-<tag> <fb_bytes>"
	payload := "#!-" + fr.moduleID + " " + string(fbBytes)
	frame, err := wire.EncodeText(fr.aesKey, fr.agentID, payload)
	if err != nil {
		return err
	}
	return wire.WriteFrame(conn, frame)
}

func (fr *fakeRemoted) sendEndAck(conn net.Conn, sessionID uint64, status fb.Status) error {
	b := flatbuffers.NewBuilder(64)
	fb.EndAckStart(b)
	fb.EndAckAddStatus(b, status)
	fb.EndAckAddSession(b, sessionID)
	off := fb.EndAckEnd(b)
	fb.MessageStart(b)
	fb.MessageAddContentType(b, fb.MessageTypeEndAck)
	fb.MessageAddContent(b, off)
	b.Finish(fb.MessageEnd(b))
	fbBytes := b.FinishedBytes()
	payload := "#!-" + fr.moduleID + " " + string(fbBytes)
	frame, err := wire.EncodeText(fr.aesKey, fr.agentID, payload)
	if err != nil {
		return err
	}
	return wire.WriteFrame(conn, frame)
}

// hostPort splits "host:port" into (host, port).
func hostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port := 0
	for _, c := range p {
		port = port*10 + int(c-'0')
	}
	return host, port
}

// newRunnableSource builds a minimal Source + connected Conn pointing at
// the fake remoted. Cleans up via t.Cleanup. Returns the Source, Conn,
// and a fresh Counters.
func newRunnableSource(t *testing.T, step scenario.Step, payload *PayloadInfo, fr *fakeRemoted, identity agent.Identity) (*Source, *agent.Conn, *metrics.Counters) {
	t.Helper()
	host, port := hostPort(t, fr.addr)
	conn := agent.New(identity, host, port)
	if err := conn.Dial(2 * time.Second); err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.StartReader(context.Background())
	// Tight timeouts so tests fail fast on the unhappy path.
	if step.StartAckTimeout == 0 {
		step.StartAckTimeout = 2.0
	}
	if step.EndAckTimeout == 0 {
		step.EndAckTimeout = 2.0
	}
	return New(step, payload), conn, metrics.New()
}

func basePayload() *PayloadInfo {
	return &PayloadInfo{
		Kind:     "static",
		Module:   "fim",
		Mode:     scenario.ModeModuleDelta,
		Option:   scenario.OptionSync,
		Indices:  []string{"wazuh-states-fim-files"},
		DataSize: 0,
		Template: []byte("{}"),
	}
}

func baseStep() scenario.Step {
	return scenario.Step{
		Kind:          scenario.SourceKindStatic,
		PayloadKind:   "fim_file",
		SessionType:   scenario.SessionDelta,
		SyncMode:      scenario.ModeModuleDelta,
		DataSize:      0, // no DataValues — just Start+End
		MaxEPS:        0,
		Index:         "wazuh-states-fim-files",
		Module:        "fim",
		PostDataDelay: 0, // explicit "no pause" — keep tests fast
	}
}

// Case 1: offline_retry=-1, first reply is Offline → fail immediately,
// no retry.
func TestOfflineRetry_Disabled_AbortOnFirstOffline(t *testing.T) {
	identity := agent.Identity{ID: "001", Name: "bench-test", ManagerKey: "deadbeefdeadbeefdeadbeefdeadbeef"}
	fr := startFakeRemotedOfflineCycler(t, identity, "fim_sync", []fb.Status{fb.StatusOffline})
	defer fr.Stop()

	step := baseStep()
	step.OfflineRetry = -1
	src, conn, c := newRunnableSource(t, step, basePayload(), fr, identity)
	_ = conn

	_ = src.Run(context.Background(), conn, c)
	cum := c.Cumulative()

	if got := fr.startsRcv.Load(); got != 1 {
		t.Errorf("fake remoted received %d Start frames, want 1", got)
	}
	if cum[metrics.CSessionsFailed] != 1 || cum[metrics.CSessionsCompleted] != 0 {
		t.Errorf("failed/completed = %d/%d, want 1/0",
			cum[metrics.CSessionsFailed], cum[metrics.CSessionsCompleted])
	}
	if cum[metrics.CStartAckOffline] != 1 {
		t.Errorf("start_ack_offline = %d, want 1", cum[metrics.CStartAckOffline])
	}
	if cum[metrics.CStartRetries] != 0 {
		t.Errorf("start_retries = %d, want 0", cum[metrics.CStartRetries])
	}
}

// Case 2: offline_retry=3, manager replies Offline twice then Ok →
// session completes after 2 retries.
func TestOfflineRetry_Bounded_CompletesAfterRetries(t *testing.T) {
	identity := agent.Identity{ID: "001", Name: "bench-test", ManagerKey: "deadbeefdeadbeefdeadbeefdeadbeef"}
	fr := startFakeRemotedOfflineCycler(t, identity, "fim_sync",
		[]fb.Status{fb.StatusOffline, fb.StatusOffline, fb.StatusOk})
	defer fr.Stop()

	step := baseStep()
	step.OfflineRetry = 3
	step.OfflineRetryDelay = 0.01 // 10ms, keep the test fast
	src, conn, c := newRunnableSource(t, step, basePayload(), fr, identity)

	_ = src.Run(context.Background(), conn, c)
	cum := c.Cumulative()

	if got := fr.startsRcv.Load(); got != 3 {
		t.Errorf("fake remoted received %d Start frames, want 3", got)
	}
	if cum[metrics.CSessionsCompleted] != 1 || cum[metrics.CSessionsFailed] != 0 {
		t.Errorf("completed/failed = %d/%d, want 1/0",
			cum[metrics.CSessionsCompleted], cum[metrics.CSessionsFailed])
	}
	if cum[metrics.CStartAckOffline] != 2 {
		t.Errorf("start_ack_offline = %d, want 2", cum[metrics.CStartAckOffline])
	}
	if cum[metrics.CStartAckOk] != 1 {
		t.Errorf("start_ack_ok = %d, want 1", cum[metrics.CStartAckOk])
	}
	if cum[metrics.CStartRetries] != 2 {
		t.Errorf("start_retries = %d, want 2", cum[metrics.CStartRetries])
	}
}

// Case 3: offline_retry=3, manager replies Offline 4 times → all 3
// attempts exhausted, session fails.
func TestOfflineRetry_Bounded_BudgetExhausted(t *testing.T) {
	identity := agent.Identity{ID: "001", Name: "bench-test", ManagerKey: "deadbeefdeadbeefdeadbeefdeadbeef"}
	fr := startFakeRemotedOfflineCycler(t, identity, "fim_sync",
		[]fb.Status{fb.StatusOffline, fb.StatusOffline, fb.StatusOffline, fb.StatusOffline})
	defer fr.Stop()

	step := baseStep()
	step.OfflineRetry = 3
	step.OfflineRetryDelay = 0.01
	src, conn, c := newRunnableSource(t, step, basePayload(), fr, identity)

	_ = src.Run(context.Background(), conn, c)
	cum := c.Cumulative()

	if got := fr.startsRcv.Load(); got != 3 {
		t.Errorf("fake remoted received %d Start frames, want 3 (offline_retry budget)", got)
	}
	if cum[metrics.CSessionsFailed] != 1 || cum[metrics.CSessionsCompleted] != 0 {
		t.Errorf("failed/completed = %d/%d, want 1/0",
			cum[metrics.CSessionsFailed], cum[metrics.CSessionsCompleted])
	}
	if cum[metrics.CStartAckOffline] != 3 {
		t.Errorf("start_ack_offline = %d, want 3", cum[metrics.CStartAckOffline])
	}
	if cum[metrics.CStartRetries] != 2 {
		// 3 attempts → 2 retries (between attempt 1→2 and 2→3)
		t.Errorf("start_retries = %d, want 2", cum[metrics.CStartRetries])
	}
}

// Case 4: offline_retry=0 (unlimited), 10 Offlines then Ok → completes.
func TestOfflineRetry_Unlimited_EventuallyCompletes(t *testing.T) {
	identity := agent.Identity{ID: "001", Name: "bench-test", ManagerKey: "deadbeefdeadbeefdeadbeefdeadbeef"}
	replies := make([]fb.Status, 11)
	for i := 0; i < 10; i++ {
		replies[i] = fb.StatusOffline
	}
	replies[10] = fb.StatusOk
	fr := startFakeRemotedOfflineCycler(t, identity, "fim_sync", replies)
	defer fr.Stop()

	step := baseStep()
	step.OfflineRetry = 0 // unlimited
	step.OfflineRetryDelay = 0.005
	src, conn, c := newRunnableSource(t, step, basePayload(), fr, identity)

	_ = src.Run(context.Background(), conn, c)
	cum := c.Cumulative()

	if got := fr.startsRcv.Load(); got != 11 {
		t.Errorf("fake remoted received %d Start frames, want 11", got)
	}
	if cum[metrics.CSessionsCompleted] != 1 {
		t.Errorf("sessions_completed = %d, want 1", cum[metrics.CSessionsCompleted])
	}
	if cum[metrics.CStartRetries] != 10 {
		t.Errorf("start_retries = %d, want 10", cum[metrics.CStartRetries])
	}
}

// Case 5: offline_retry=0 + ctx cancelled mid-retry → returns ctx.Err().
func TestOfflineRetry_Unlimited_RespectsCancellation(t *testing.T) {
	identity := agent.Identity{ID: "001", Name: "bench-test", ManagerKey: "deadbeefdeadbeefdeadbeefdeadbeef"}
	replies := make([]fb.Status, 1000)
	for i := range replies {
		replies[i] = fb.StatusOffline
	}
	fr := startFakeRemotedOfflineCycler(t, identity, "fim_sync", replies)
	defer fr.Stop()

	step := baseStep()
	step.OfflineRetry = 0
	step.OfflineRetryDelay = 0.05
	src, conn, c := newRunnableSource(t, step, basePayload(), fr, identity)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	err := src.Run(ctx, conn, c)
	if err == nil {
		t.Fatalf("expected ctx.Err(), got nil")
	}
	cum := c.Cumulative()
	if cum[metrics.CSessionsFailed] != 1 {
		t.Errorf("sessions_failed = %d, want 1", cum[metrics.CSessionsFailed])
	}
	if cum[metrics.CStartAckOffline] < 1 {
		t.Errorf("start_ack_offline = %d, want >= 1 (some attempts happened before cancel)",
			cum[metrics.CStartAckOffline])
	}
}
