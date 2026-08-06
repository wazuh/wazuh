// Package pacing wraps rate limiting. There is one shared session limiter for
// the whole run and one per engine lane, so log volume and inventory volume are
// dialed independently (docu/08-concurrency-and-pacing.md).
package pacing

import (
	"context"

	"golang.org/x/time/rate"
)

// Limiter gates requests to a target rate. A zero or negative rate means
// unlimited (correct for saturation), in which case Wait is a no-op.
type Limiter struct {
	l *rate.Limiter
}

// New builds a limiter for eps events per second; eps <= 0 is unlimited.
func New(eps float64) *Limiter {
	if eps <= 0 {
		return &Limiter{} // nil inner => unlimited
	}
	// Burst of 1: a leaky bucket, not a token hoard, so the achieved rate does
	// not spike above target after an idle stretch.
	return &Limiter{l: rate.NewLimiter(rate.Limit(eps), 1)}
}

// Wait blocks until the limiter admits one event, or ctx is done.
func (l *Limiter) Wait(ctx context.Context) error {
	if l.l == nil {
		return nil
	}
	return l.l.Wait(ctx)
}
