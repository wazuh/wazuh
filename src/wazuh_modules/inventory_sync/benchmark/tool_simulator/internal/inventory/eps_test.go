package inventory

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/agent"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/metrics"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/pacing"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/scenario"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/wire"
)

// TestSendItemsBatched_ThrottlesPerBatchNotPerItem verifies that max_eps
// is enforced per WIRE MESSAGE (DataBatch frame), not per DataValue item
// inside the batch. Sends 1000 items with max_eps=20 batched into ~few
// big batches — should complete in well under a second on the wire
// rather than 1000/20 = 50 seconds.
func TestSendItemsBatched_ThrottlesPerBatchNotPerItem(t *testing.T) {
	// Fake remoted that counts frames received.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	frameCount := int64(0)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			_, err := wire.ReadFrame(conn)
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

	identity := agent.Identity{ID: "001", Name: "bench-test", ManagerKey: "deadbeefdeadbeefdeadbeefdeadbeef"}
	conn := agent.New(identity, host, port)
	if err := conn.Dial(2 * time.Second); err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// 1000 small items → ~3 batches of ~330 items (each batch < 60 KB).
	items := make([]Item, 1000)
	for i := range items {
		items[i] = Item{
			Seq:       uint64(i),
			Operation: scenario.OperationUpsert,
			ID:        "doc",
			Index:     "wazuh-states-fim-files",
			Data:      []byte(`{"x":1}`),
		}
	}
	src := &Source{
		step:     scenario.Step{UseDatabatch: true, MaxEPS: 20},
		payload:  &PayloadInfo{Module: "fim", Kind: "dump", Items: items},
		moduleID: "fim_sync",
		lim:      pacing.New(20),
	}
	c := metrics.New()

	t0 := time.Now()
	if err := src.sendItemsBatched(context.Background(), conn, 0, items, c); err != nil {
		t.Fatalf("sendItemsBatched: %v", err)
	}
	elapsed := time.Since(t0)

	// Give remoted a moment to drain the TCP buffer.
	time.Sleep(200 * time.Millisecond)
	got := atomic.LoadInt64(&frameCount)

	// Expect ~3-5 batches sent at 20/s = throttled, but the WALL CLOCK
	// must be way under per-item pacing (1000/20 = 50s). 5 seconds is a
	// generous upper bound that still fails if we accidentally throttle
	// per item.
	if elapsed > 5*time.Second {
		t.Errorf("sendItemsBatched took %s (>5s) — looks like per-item throttling regressed", elapsed)
	}
	// Account for the startup control message that Dial() emitted.
	dataBatchFrames := got - 1
	if dataBatchFrames < 1 || dataBatchFrames > 20 {
		t.Errorf("got %d DataBatch frames, expected 2..20 for 1000 small items @ 60KB target", dataBatchFrames)
	}
	t.Logf("OK: %d frames in %s @ max_eps=20 (per-batch throttle)", dataBatchFrames, elapsed)
}
