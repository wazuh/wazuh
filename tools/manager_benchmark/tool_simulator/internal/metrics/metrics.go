// Package metrics records every outcome a run produces and formats the
// artifacts. It is the only package that knows a run is sliced by lane and
// fleet: every count and histogram is recorded at three granularities (global,
// per fleet, per lane) so the summary is one code path (docu/09, docu/11).
//
// The rule is keep everything, judge nothing: there is no verdict here.
package metrics

import "sync/atomic"

// Counters holds every count column of bench.csv, in field order matching the
// documented header. All updated with atomics.
type Counters struct {
	SessionsSent, SessionsOK, SessionsNoop                        uint64
	S409, S400, S403, S413, S500, S503, S503RetryAfter, SessOther uint64

	StatelessSent, St202, StBad400, StBad413, St503, StOther, EventsSent uint64

	RetriesFeed, TransportErrors uint64
	BytesSent, DocumentsSent     uint64

	StartupOK, StartupErr, NotifyOK, NotifyErr, ShutdownOK, ShutdownErr uint64
	DeletesOK, DeletesErr                                               uint64

	AbandonedOnDrain uint64
}

// bucket is the counters plus latency histograms for one granularity.
type bucket struct {
	c     Counters
	hists map[string]*Histogram // "session","stateless","notify","startup"
}

func newBucket() *bucket {
	return &bucket{hists: map[string]*Histogram{
		"session":   NewHistogram(),
		"stateless": NewHistogram(),
		"notify":    NewHistogram(),
		"startup":   NewHistogram(),
	}}
}

// Registry is the run's whole record.
type Registry struct {
	global *bucket
	fleets map[string]*bucket
	lanes  map[string]*bucket
}

// NewRegistry pre-creates a bucket per fleet and per lane, so the hot path never
// allocates or locks a map.
func NewRegistry(fleetNames, laneNames []string) *Registry {
	r := &Registry{
		global: newBucket(),
		fleets: make(map[string]*bucket, len(fleetNames)),
		lanes:  make(map[string]*bucket, len(laneNames)),
	}
	for _, f := range fleetNames {
		r.fleets[f] = newBucket()
	}
	for _, l := range laneNames {
		r.lanes[l] = newBucket()
	}
	return r
}

// forEach applies fn to the global bucket and the (fleet, lane) buckets that
// exist. A missing fleet/lane (e.g. a synthetic uds id) is simply skipped.
func (r *Registry) forEach(fleet, lane string, fn func(*bucket)) {
	fn(r.global)
	if b, ok := r.fleets[fleet]; ok {
		fn(b)
	}
	if b, ok := r.lanes[lane]; ok {
		fn(b)
	}
}

func (r *Registry) add(fleet, lane string, pick func(*Counters) *uint64, n uint64) {
	r.forEach(fleet, lane, func(b *bucket) { atomic.AddUint64(pick(&b.c), n) })
}

// RecordSession classifies a /stateful outcome by status and the noop flag,
// records its latency, and adds the payload sizes.
func (r *Registry) RecordSession(fleet, lane string, status int, noop bool, retryAfter bool, latencyUS, bytes, docs uint64) {
	r.add(fleet, lane, func(c *Counters) *uint64 { return &c.SessionsSent }, 1)
	r.add(fleet, lane, func(c *Counters) *uint64 { return &c.BytesSent }, bytes)
	r.add(fleet, lane, func(c *Counters) *uint64 { return &c.DocumentsSent }, docs)
	r.observe(fleet, lane, "session", latencyUS)

	switch status {
	case 200:
		r.add(fleet, lane, func(c *Counters) *uint64 { return &c.SessionsOK }, 1)
		if noop {
			r.add(fleet, lane, func(c *Counters) *uint64 { return &c.SessionsNoop }, 1)
		}
	case 400:
		r.add(fleet, lane, func(c *Counters) *uint64 { return &c.S400 }, 1)
	case 403:
		r.add(fleet, lane, func(c *Counters) *uint64 { return &c.S403 }, 1)
	case 409:
		r.add(fleet, lane, func(c *Counters) *uint64 { return &c.S409 }, 1)
	case 413:
		r.add(fleet, lane, func(c *Counters) *uint64 { return &c.S413 }, 1)
	case 500:
		r.add(fleet, lane, func(c *Counters) *uint64 { return &c.S500 }, 1)
	case 503:
		r.add(fleet, lane, func(c *Counters) *uint64 { return &c.S503 }, 1)
		if retryAfter {
			r.add(fleet, lane, func(c *Counters) *uint64 { return &c.S503RetryAfter }, 1)
		}
	default:
		r.add(fleet, lane, func(c *Counters) *uint64 { return &c.SessOther }, 1)
	}
}

// RecordFeedRetry counts one feed-not-ready re-send.
func (r *Registry) RecordFeedRetry(fleet, lane string) {
	r.add(fleet, lane, func(c *Counters) *uint64 { return &c.RetriesFeed }, 1)
}

// RecordStateless classifies a /stateless outcome and records its latency.
func (r *Registry) RecordStateless(fleet, lane string, status int, events uint64, latencyUS uint64) {
	r.add(fleet, lane, func(c *Counters) *uint64 { return &c.StatelessSent }, 1)
	r.add(fleet, lane, func(c *Counters) *uint64 { return &c.EventsSent }, events)
	r.observe(fleet, lane, "stateless", latencyUS)
	switch status {
	case 202:
		r.add(fleet, lane, func(c *Counters) *uint64 { return &c.St202 }, 1)
	case 400:
		r.add(fleet, lane, func(c *Counters) *uint64 { return &c.StBad400 }, 1)
	case 413:
		r.add(fleet, lane, func(c *Counters) *uint64 { return &c.StBad413 }, 1)
	case 503:
		r.add(fleet, lane, func(c *Counters) *uint64 { return &c.St503 }, 1)
	default:
		r.add(fleet, lane, func(c *Counters) *uint64 { return &c.StOther }, 1)
	}
}

// RecordControl records a startup/notify/shutdown outcome and latency.
func (r *Registry) RecordControl(fleet, kind string, ok bool, latencyUS uint64) {
	r.observe(fleet, "", kind, latencyUS)
	pick := map[[2]string]func(*Counters) *uint64{
		{"startup", "ok"}:   func(c *Counters) *uint64 { return &c.StartupOK },
		{"startup", "err"}:  func(c *Counters) *uint64 { return &c.StartupErr },
		{"notify", "ok"}:    func(c *Counters) *uint64 { return &c.NotifyOK },
		{"notify", "err"}:   func(c *Counters) *uint64 { return &c.NotifyErr },
		{"shutdown", "ok"}:  func(c *Counters) *uint64 { return &c.ShutdownOK },
		{"shutdown", "err"}: func(c *Counters) *uint64 { return &c.ShutdownErr },
	}
	res := "ok"
	if !ok {
		res = "err"
	}
	if f := pick[[2]string{kind, res}]; f != nil {
		r.add(fleet, "", f, 1)
	}
}

// RecordDelete records a DELETE /agents outcome.
func (r *Registry) RecordDelete(fleet, lane string, ok bool) {
	if ok {
		r.add(fleet, lane, func(c *Counters) *uint64 { return &c.DeletesOK }, 1)
	} else {
		r.add(fleet, lane, func(c *Counters) *uint64 { return &c.DeletesErr }, 1)
	}
}

// RecordTransportError counts a response that never arrived.
func (r *Registry) RecordTransportError(fleet, lane string) {
	r.add(fleet, lane, func(c *Counters) *uint64 { return &c.TransportErrors }, 1)
}

// RecordAbandoned counts a session still in flight at drain timeout.
func (r *Registry) RecordAbandoned(fleet, lane string) {
	r.add(fleet, lane, func(c *Counters) *uint64 { return &c.AbandonedOnDrain }, 1)
}

func (r *Registry) observe(fleet, lane, kind string, us uint64) {
	r.forEach(fleet, lane, func(b *bucket) {
		if h := b.hists[kind]; h != nil {
			h.Observe(us)
		}
	})
}

// TransportErrorTotal reads the global transport-error count (for the exit-code
// decision).
func (r *Registry) TransportErrorTotal() uint64 {
	return atomic.LoadUint64(&r.global.c.TransportErrors)
}
