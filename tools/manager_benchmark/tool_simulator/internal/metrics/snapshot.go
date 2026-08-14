package metrics

import "sync/atomic"

// CountersSnapshot is a consistent-enough read of one bucket's counters.
type CountersSnapshot struct {
	C     Counters
	Hists map[string]Snapshot
}

func snapshotBucket(b *bucket) CountersSnapshot {
	load := func(p *uint64) uint64 { return atomic.LoadUint64(p) }
	src := &b.c
	out := Counters{
		SessionsSent: load(&src.SessionsSent), SessionsOK: load(&src.SessionsOK), SessionsNoop: load(&src.SessionsNoop),
		S409: load(&src.S409), S400: load(&src.S400), S401: load(&src.S401), S403: load(&src.S403), S413: load(&src.S413),
		S500: load(&src.S500), S503: load(&src.S503), S503RetryAfter: load(&src.S503RetryAfter), SessOther: load(&src.SessOther),
		StatelessSent: load(&src.StatelessSent), St202: load(&src.St202), StBad400: load(&src.StBad400),
		StBad413: load(&src.StBad413), St503: load(&src.St503), StOther: load(&src.StOther), EventsSent: load(&src.EventsSent),
		ScanSent: load(&src.ScanSent), Scan200: load(&src.Scan200), Scan409: load(&src.Scan409),
		Scan503: load(&src.Scan503), ScanOther: load(&src.ScanOther),
		RetriesFeed: load(&src.RetriesFeed), Retries503: load(&src.Retries503),
		RetriesExhausted: load(&src.RetriesExhausted), TransportErrors: load(&src.TransportErrors),
		BytesSent: load(&src.BytesSent), DocumentsSent: load(&src.DocumentsSent),
		StartupOK: load(&src.StartupOK), StartupErr: load(&src.StartupErr), NotifyOK: load(&src.NotifyOK),
		NotifyErr: load(&src.NotifyErr), ShutdownOK: load(&src.ShutdownOK), ShutdownErr: load(&src.ShutdownErr),
		DeletesOK: load(&src.DeletesOK), DeletesErr: load(&src.DeletesErr),
		AbandonedOnDrain: load(&src.AbandonedOnDrain),
	}
	hists := make(map[string]Snapshot, len(b.hists))
	for k, h := range b.hists {
		hists[k] = h.Snapshot()
	}
	return CountersSnapshot{C: out, Hists: hists}
}

// GlobalSnapshot reads the run-wide bucket.
func (r *Registry) GlobalSnapshot() CountersSnapshot { return snapshotBucket(r.global) }

// FleetSnapshots reads every fleet bucket.
func (r *Registry) FleetSnapshots() map[string]CountersSnapshot {
	out := make(map[string]CountersSnapshot, len(r.fleets))
	for name, b := range r.fleets {
		out[name] = snapshotBucket(b)
	}
	return out
}

// LaneSnapshots reads every lane bucket.
func (r *Registry) LaneSnapshots() map[string]CountersSnapshot {
	out := make(map[string]CountersSnapshot, len(r.lanes))
	for name, b := range r.lanes {
		out[name] = snapshotBucket(b)
	}
	return out
}
