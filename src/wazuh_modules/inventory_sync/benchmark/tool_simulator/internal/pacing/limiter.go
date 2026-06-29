// Package pacing wraps golang.org/x/time/rate for the leaky-bucket EPS
// pacing the Python sender implements in SessionRunner._eps_throttle.
// See docu/07-concurrency-and-pacing.md.
package pacing

import (
	"context"

	"golang.org/x/time/rate"
)

// Limiter caps events per second. cap == 0 ⇒ uncapped (Wait returns
// immediately).
type Limiter struct {
	lim *rate.Limiter
}

// New returns a leaky-bucket limiter at `cap` events/sec, burst=1 to
// match the Python sender's "no bursting" behaviour.
func New(cap int) *Limiter {
	if cap <= 0 {
		return &Limiter{lim: nil}
	}
	return &Limiter{lim: rate.NewLimiter(rate.Limit(cap), 1)}
}

// Wait blocks until one token is available (or ctx is canceled).
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil || l.lim == nil {
		return ctx.Err()
	}
	return l.lim.Wait(ctx)
}
