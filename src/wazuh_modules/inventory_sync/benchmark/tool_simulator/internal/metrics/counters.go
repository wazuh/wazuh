// Package metrics implements the atomic counter set, latency histograms,
// the bench.csv writer and the final sender_summary.json. Column set
// mirrors Python's COUNTER_FIELDS to preserve result_summary.py
// compatibility. The Go sender additionally emits the engine_* columns
// described in docu/12-engine-event-streams.md when --report-engine=true.
package metrics

import "sync/atomic"

// CounterField identifies one counter slot. Order matters: it determines
// the CSV column order.
type CounterField int

const (
	CMessagesSent CounterField = iota
	CSessionsStarted
	CSessionsCompleted
	CSessionsFailed
	CStartAckOk
	CStartAckOffline
	CStartAckError
	CEndAckOk
	CEndAckOffline
	CEndAckError
	CEndAckProcessing
	CReqRet
	CMissingRangesTotal
	CMessagesDropped
	CStartRetries
	// engine_* (Go-only, optional via --report-engine).
	CEngineEventsSent
	CEngineFilesEOFWrap
	CEngineSendErrors
	// Control-message counters (Go-only, also opt-in via --report-engine).
	// Track the keepalive/shutdown chatter the agent maintains with the
	// manager outside the inventory_sync session loop.
	CKeepalivesSent
	CKeepaliveErrors
	CShutdownsSent
	CMergedSumUpdates
	// CEndRetries counts End frames re-sent because the previous attempt
	// timed out (manager's input queue may have dropped it). Independent
	// from CStartRetries which still counts Start-side retries (offline
	// + timeout).
	CEndRetries
	// CEngineLinesTooLong counts lines silently skipped because their
	// resulting inner_event would exceed Wazuh remoted's decompression
	// buffer (OS_MAXSTR = 65536). Sending such a frame causes ReadSecMSG
	// to return KS_CORRUPT and remoted closes the TCP connection.
	CEngineLinesTooLong

	counterCount // sentinel; keep last
)

// PythonHeader is the bench.csv header subset that the Python sender
// produces. result_summary.py relies on these column names exactly.
var PythonHeader = []string{
	"messages_sent",
	"sessions_started",
	"sessions_completed",
	"sessions_failed",
	"start_ack_ok",
	"start_ack_offline",
	"start_ack_error",
	"end_ack_ok",
	"end_ack_offline",
	"end_ack_error",
	"end_ack_processing",
	"reqret",
	"missing_ranges_total",
	"messages_dropped",
	"start_retries",
}

// EngineHeader is the Go-only addendum, opt-in via --report-engine. The
// column order MUST match the CounterField enum order in this file.
var EngineHeader = []string{
	"engine_events_sent",
	"engine_files_eof_wrap",
	"engine_send_errors",
	"keepalives_sent",
	"keepalive_errors",
	"shutdowns_sent",
	"merged_sum_updates",
	"end_retries",
	"engine_lines_too_long",
}

// LatencyKind identifies a latency series.
type LatencyKind int

const (
	LStartAck LatencyKind = iota
	LEndAck
	LSessionFull
)

// Counters holds the atomic per-tick counters and the cumulative totals.
type Counters struct {
	tick       [counterCount]atomic.Int64
	cumulative [counterCount]atomic.Int64

	// Latency observations (in milliseconds). Appended under their own
	// mutex elsewhere; here we keep slices guarded by a Latencies wrapper.
	latStart   *LatencyHist
	latEnd     *LatencyHist
	latSession *LatencyHist
}

// New returns a freshly-zeroed Counters.
func New() *Counters {
	return &Counters{
		latStart:   NewLatencyHist(),
		latEnd:     NewLatencyHist(),
		latSession: NewLatencyHist(),
	}
}

// Add increments both the per-tick and the cumulative slot atomically.
func (c *Counters) Add(field CounterField, delta int64) {
	if int(field) >= int(counterCount) {
		return
	}
	c.tick[field].Add(delta)
	c.cumulative[field].Add(delta)
}

// Inc is Add(field, 1).
func (c *Counters) Inc(field CounterField) { c.Add(field, 1) }

// SwapTick swaps the per-tick counters to zero, returning the values that
// were accumulated since the last call.
func (c *Counters) SwapTick() [counterCount]int64 {
	var out [counterCount]int64
	for i := 0; i < int(counterCount); i++ {
		out[i] = c.tick[i].Swap(0)
	}
	return out
}

// Cumulative returns a snapshot of the cumulative totals (no reset).
func (c *Counters) Cumulative() [counterCount]int64 {
	var out [counterCount]int64
	for i := 0; i < int(counterCount); i++ {
		out[i] = c.cumulative[i].Load()
	}
	return out
}

// RecordLatency appends one observation in milliseconds. Negative values
// are dropped (matches Python).
func (c *Counters) RecordLatency(k LatencyKind, ms float64) {
	if ms < 0 {
		return
	}
	switch k {
	case LStartAck:
		c.latStart.Observe(ms)
	case LEndAck:
		c.latEnd.Observe(ms)
	case LSessionFull:
		c.latSession.Observe(ms)
	}
}

// LatencySummaries returns a snapshot of all three histograms.
func (c *Counters) LatencySummaries() (start, end, session LatencyStats) {
	return c.latStart.Snapshot(), c.latEnd.Snapshot(), c.latSession.Snapshot()
}
