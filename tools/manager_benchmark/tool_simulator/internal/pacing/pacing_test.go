package pacing

import (
	"context"
	"testing"
	"time"
)

func TestUnlimitedIsANoOp(t *testing.T) {
	l := New(0)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := l.Wait(ctx); err != nil {
		t.Fatalf("unlimited Wait must not block: %v", err)
	}
	if err := l.WaitN(ctx, 1_000_000); err != nil {
		t.Fatalf("unlimited WaitN must not block: %v", err)
	}
	l.EnsureBurst(500) // must not panic on the nil inner limiter
}

// A batch must be charged its real cost: after EnsureBurst admits one full
// batch, a second immediate batch has to wait for ~batch/eps seconds. This is
// exactly the property that keeps events_per_second in event units.
func TestWaitNChargesTheWholeBatch(t *testing.T) {
	const eps = 1000.0
	const batch = 100
	l := New(eps)
	l.EnsureBurst(batch)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := l.WaitN(ctx, batch); err != nil { // first batch rides the burst
		t.Fatalf("first batch: %v", err)
	}
	begin := time.Now()
	if err := l.WaitN(ctx, batch); err != nil {
		t.Fatalf("second batch: %v", err)
	}
	elapsed := time.Since(begin)
	// 100 events at 1000 eps = 100ms of tokens. Allow generous slack downward
	// (the burst may have partially refilled) but reject a free pass.
	if elapsed < 50*time.Millisecond {
		t.Fatalf("second batch of %d at %.0f eps must wait ~100ms, waited %v", batch, eps, elapsed)
	}
}

func TestEnsureBurstNeverLowers(t *testing.T) {
	l := New(10_000)
	l.EnsureBurst(64)
	l.EnsureBurst(8) // a smaller later batch must not shrink the admitted size

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := l.WaitN(ctx, 64); err != nil {
		t.Fatalf("burst of 64 must remain admissible: %v", err)
	}
}
