// Package pacing wraps rate limiting. There is one shared session limiter for
// the whole run and one per engine lane, so log volume and inventory volume are
// dialed independently (docu/08-concurrency-and-pacing.md).
package pacing

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

// Limiter gates traffic to a target rate. A zero or negative rate means
// unlimited (correct for saturation), in which case Wait/WaitN are no-ops.
type Limiter struct {
	l *rate.Limiter

	mu    sync.Mutex
	burst int
}

// New builds a limiter for eps units per second; eps <= 0 is unlimited.
func New(eps float64) *Limiter {
	if eps <= 0 {
		return &Limiter{} // nil inner => unlimited
	}
	// Burst of 1: a leaky bucket, not a token hoard, so the achieved rate does
	// not spike above target after an idle stretch. EnsureBurst raises it when
	// a caller needs to charge whole batches atomically.
	return &Limiter{l: rate.NewLimiter(rate.Limit(eps), 1), burst: 1}
}

// Wait blocks until the limiter admits one unit, or ctx is done.
func (l *Limiter) Wait(ctx context.Context) error {
	if l.l == nil {
		return nil
	}
	return l.l.Wait(ctx)
}

// WaitN blocks until the limiter admits n units at once, or ctx is done. This
// is how a batch of n events is charged at its REAL cost: the rate stays in
// event units no matter how events are grouped into requests. Callers must
// have raised the burst to at least n via EnsureBurst, or WaitN errors.
func (l *Limiter) WaitN(ctx context.Context, n int) error {
	if l.l == nil || n <= 0 {
		return nil
	}
	return l.l.WaitN(ctx, n)
}

// EnsureBurst raises the burst to at least n (never lowers it). The burst is
// the largest batch the limiter can admit atomically; raising it does not
// change the sustained rate, only how much of it a single WaitN may claim.
func (l *Limiter) EnsureBurst(n int) {
	if l.l == nil || n <= 1 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if n > l.burst {
		l.l.SetBurst(n)
		l.burst = n
	}
}
