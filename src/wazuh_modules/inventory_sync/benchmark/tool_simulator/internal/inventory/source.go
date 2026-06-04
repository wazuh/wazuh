package inventory

import (
	"context"
	"fmt"
	"time"

	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/agent"
	fb "github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/fb/Wazuh/SyncSchema"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/fbbuild"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/metrics"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/pacing"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/scenario"
)

// Default timeouts and pacing. Mirror the Python SessionRunner constants
// where applicable; can be overridden per-session via Options.
const (
	DefaultStartAckTimeout = 15 * time.Second
	DefaultEndAckTimeout   = 120 * time.Second
	// DefaultPostDataDelay is the pause inserted between the last data
	// message and the End message of a session. Gives the manager time
	// to drain its handleData queue so the End hits the gapSet-empty
	// branch (which sets processingTime + emits Status_Ok directly),
	// instead of needing a ReqRet round. Set to 0 to send End back-to-
	// back with the last DataValue.
	DefaultPostDataDelay = 1 * time.Second
	// MaxRetransmitRounds caps how many times we'll respond to a ReqRet
	// before declaring the session failed. Matches Python's MAX_RETRANSMIT.
	MaxRetransmitRounds = 5
)

// Options controls per-Source behavior beyond what the scenario step
// carries. CLI flags / scenario knobs flow through here.
type Options struct {
	// StartAckTimeout is how long the runner waits for the manager's
	// StartAck before giving up. 0 means use DefaultStartAckTimeout.
	StartAckTimeout time.Duration
	// EndAckTimeout is how long the runner waits for the manager's
	// terminal EndAck (Status_Ok / _Error / _Offline). The timer is
	// extended each time a Status_Processing arrives. 0 means use
	// DefaultEndAckTimeout.
	EndAckTimeout time.Duration
	// PostDataDelay is the pause inserted before EACH End send — both
	// the initial End (after the data body completes) AND every End that
	// follows a ReqRet retransmission. A non-zero value reduces the
	// chance of triggering a ReqRet round in the first place. Setting to
	// a negative value (e.g. -1) means "use the default 1s"; 0 (the zero
	// value) means "no pause at all". Use PostDataDelaySet to make the
	// distinction explicit when threading through Config.
	PostDataDelay time.Duration
	// PostDataDelaySet, when true, takes PostDataDelay verbatim (allowing
	// the operator to explicitly request 0s). When false, the default
	// (DefaultPostDataDelay) is applied. This matters because we want
	// 0-value time.Duration to remain a valid "no pause" choice rather
	// than triggering the default.
	PostDataDelaySet bool
}

func (o Options) startAckTimeout() time.Duration {
	if o.StartAckTimeout > 0 {
		return o.StartAckTimeout
	}
	return DefaultStartAckTimeout
}

func (o Options) endAckTimeout() time.Duration {
	if o.EndAckTimeout > 0 {
		return o.EndAckTimeout
	}
	return DefaultEndAckTimeout
}

// postDataDelay returns the configured delay, honoring the "explicitly
// zero" case via PostDataDelaySet.
func (o Options) postDataDelay() time.Duration {
	if o.PostDataDelaySet {
		if o.PostDataDelay < 0 {
			return 0
		}
		return o.PostDataDelay
	}
	return DefaultPostDataDelay
}

// Source drives one inventory_sync session per Run() call. SessionType=delta
// is the only fully-implemented variant at this time; modulecheck/dataclean
// fall through to the same Start/End wrapping but skip the data body.
type Source struct {
	step    scenario.Step
	payload *PayloadInfo
	opts    Options

	// lim is recreated at the start of every Run() call so the EPS cap is
	// enforced strictly per-session (matching Python, which constructs a
	// fresh SessionRunner per iteration — benchmark_sender.py:1544).
	// Keeping a single limiter on the Source would let idle time between
	// sessions silently accumulate tokens.
	lim *pacing.Limiter

	moduleID string // routing tag, e.g. "syscollector_sync"
}

// New returns an inventory Source. payload should have been loaded once
// and may be shared across Run() iterations (caller's choice).
func New(step scenario.Step, payload *PayloadInfo, opts Options) *Source {
	return &Source{
		step:     step,
		payload:  payload,
		opts:     opts,
		moduleID: moduleIDFor(payload.Module, payload.Option),
		// lim is left nil — Run() builds a fresh one per session.
	}
}

// Label identifies the source in logs.
func (s *Source) Label() string {
	if s.step.Kind == scenario.SourceKindDump {
		return "dump:" + s.step.PayloadDumpPath
	}
	return "kind:" + string(s.step.PayloadKind)
}

// Run drives one Start→Data→End→EndAck cycle, with full bookkeeping.
func (s *Source) Run(ctx context.Context, conn *agent.Conn, c *metrics.Counters) error {
	// Fresh per-session EPS limiter (matches Python's SessionRunner — a
	// new instance per iteration with _eps_t0 reset to None). Without
	// this the bucket would carry tokens across the gap between
	// repeat_count iterations and the first DataValue of the next
	// session could burst past the cap.
	s.lim = pacing.New(s.step.MaxEPS)

	c.Inc(metrics.CSessionsStarted)

	identity := conn.Identity()
	indices := s.payload.Indices
	if len(indices) == 0 && s.step.Index != "" {
		indices = []string{s.step.Index}
	}

	// Build + send Start, capture session id via callback.
	startBytes := fbbuild.BuildStart(
		s.payload.Module, fb.Mode(s.payload.Mode), uint64(s.payload.DataSize),
		fb.Option(s.payload.Option), identity.ID, identity.Name, "5.0.0", indices,
	)
	tStart := time.Now()
	ackC := make(chan ackResult, 1)
	pending, err := conn.SendStart(s.moduleID, startBytes, func(session uint64, status fb.Status) {
		ackC <- ackResult{session: session, status: status}
	})
	if err != nil {
		c.Inc(metrics.CSessionsFailed)
		return fmt.Errorf("send Start: %w", err)
	}
	c.Inc(metrics.CMessagesSent)

	// Await StartAck.
	var sessionID uint64
	startAckT := s.opts.startAckTimeout()
	select {
	case <-ctx.Done():
		pending.Cancel() // FIFO orphan removal
		c.Inc(metrics.CSessionsFailed)
		return ctx.Err()
	case <-time.After(startAckT):
		pending.Cancel() // FIFO orphan removal — critical for session-id correctness
		c.Inc(metrics.CSessionsFailed)
		c.Inc(metrics.CStartRetries) // surfaced as a hint to the operator
		return fmt.Errorf("StartAck timeout after %s", startAckT)
	case ack := <-ackC:
		c.RecordLatency(metrics.LStartAck, float64(time.Since(tStart).Milliseconds()))
		switch ack.status {
		case fb.StatusOk:
			c.Inc(metrics.CStartAckOk)
			sessionID = ack.session
		case fb.StatusOffline:
			c.Inc(metrics.CStartAckOffline)
			c.Inc(metrics.CSessionsFailed)
			return nil
		default:
			c.Inc(metrics.CStartAckError)
			c.Inc(metrics.CSessionsFailed)
			return nil
		}
	}

	// Register inbound callback for EndAck/ReqRet on this session.
	endC := make(chan fbbuild.Inbound, 4)
	conn.RegisterSession(sessionID, func(in fbbuild.Inbound) {
		select {
		case endC <- in:
		default:
			// drop excess; reqret backpressure is acceptable
		}
	})
	defer conn.UnregisterSession(sessionID)

	// Send data body.
	if err := s.sendDataBody(ctx, conn, sessionID, c); err != nil {
		c.Inc(metrics.CSessionsFailed)
		return err
	}

	// Pause before End so the manager finishes draining its handleData
	// queue first — see Options.PostDataDelay. Same pause is reused on
	// every End we send (initial and post-ReqRet) for consistency.
	if err := sleepCtx(ctx, s.opts.postDataDelay()); err != nil {
		c.Inc(metrics.CSessionsFailed)
		return err
	}

	// Send End.
	tEnd := time.Now()
	if err := conn.SendBinary(s.moduleID, fbbuild.BuildEnd(sessionID)); err != nil {
		c.Inc(metrics.CSessionsFailed)
		return fmt.Errorf("send End: %w", err)
	}
	c.Inc(metrics.CMessagesSent)

	// Await terminal EndAck (Status_Processing → keep waiting). Inbound
	// ReqRet messages trigger a retransmit round + another End. Capped at
	// MaxRetransmitRounds to avoid pathological loops.
	endAckT := s.opts.endAckTimeout()
	deadline := time.NewTimer(endAckT)
	defer deadline.Stop()
	retransmits := 0
	for {
		select {
		case <-ctx.Done():
			c.Inc(metrics.CSessionsFailed)
			return ctx.Err()
		case <-deadline.C:
			c.Inc(metrics.CSessionsFailed)
			return fmt.Errorf("EndAck timeout after %s", endAckT)
		case in := <-endC:
			if in.Type == fb.MessageTypeReqRet {
				c.Inc(metrics.CReqRet)
				c.Add(metrics.CMissingRangesTotal, int64(len(in.Ranges)))
				if retransmits >= MaxRetransmitRounds {
					c.Add(metrics.CMessagesDropped, int64(countSeqs(in.Ranges)))
					c.Inc(metrics.CSessionsFailed)
					return fmt.Errorf("ReqRet budget exhausted after %d rounds", retransmits)
				}
				retransmits++
				if err := s.handleReqRet(ctx, conn, sessionID, in.Ranges, c); err != nil {
					c.Inc(metrics.CSessionsFailed)
					return fmt.Errorf("retransmit: %w", err)
				}
				// Re-send End so the manager re-runs its gap check.
				//
				// NOTE: the manager's `agentSession::handleData` enqueues
				// the indexer push when the last gap-filling DataValue
				// arrives, but it does NOT set `processingTime`. The
				// subsequent handleEnd then short-circuits via
				// `m_endEnqueued == true` and likewise does not set it.
				// The session DOES complete successfully (Status_Ok is
				// sent and the indexer flush happens), but the manager
				// stats log misreports `reason=abandoned` /
				// `start_to_processing=-1`. The authoritative source of
				// truth is this sender's `sessions_completed` /
				// `end_ack_ok` counters. See docu/09 §"ReqRet stats
				// quirk" for the manager-side fix.
				if err := sleepCtx(ctx, s.opts.postDataDelay()); err != nil {
					c.Inc(metrics.CSessionsFailed)
					return err
				}
				tEnd = time.Now()
				if err := conn.SendBinary(s.moduleID, fbbuild.BuildEnd(sessionID)); err != nil {
					c.Inc(metrics.CSessionsFailed)
					return fmt.Errorf("send End (retransmit): %w", err)
				}
				c.Inc(metrics.CMessagesSent)
				// Reset the deadline — we just did real work.
				if !deadline.Stop() {
					<-deadline.C
				}
				deadline.Reset(endAckT)
				continue
			}
			if in.Type != fb.MessageTypeEndAck {
				continue
			}
			c.RecordLatency(metrics.LEndAck, float64(time.Since(tEnd).Milliseconds()))
			c.RecordLatency(metrics.LSessionFull, float64(time.Since(tStart).Milliseconds()))
			switch in.Status {
			case fb.StatusOk:
				c.Inc(metrics.CEndAckOk)
				c.Inc(metrics.CSessionsCompleted)
				return nil
			case fb.StatusProcessing:
				c.Inc(metrics.CEndAckProcessing)
				// Keep waiting for a terminal ack.
				if !deadline.Stop() {
					<-deadline.C
				}
				deadline.Reset(endAckT)
			case fb.StatusOffline:
				c.Inc(metrics.CEndAckOffline)
				c.Inc(metrics.CSessionsFailed)
				return nil
			default:
				c.Inc(metrics.CEndAckError)
				c.Inc(metrics.CSessionsFailed)
				return nil
			}
		}
	}
}

// countSeqs returns the total number of sequence numbers across all
// inclusive ranges.
func countSeqs(ranges []fbbuild.SeqRange) int {
	n := 0
	for _, r := range ranges {
		if r.End >= r.Begin {
			n += int(r.End-r.Begin) + 1
		}
	}
	return n
}

// sleepCtx waits for d to elapse, returning ctx.Err() if the context is
// canceled first. d <= 0 returns immediately.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// handleReqRet resends the items whose seq numbers fall in the requested
// ranges, paced by the same per-session EPS limiter as the original send.
// Items are always emitted as individual DataValue messages (not batched)
// since retransmissions are typically sparse.
func (s *Source) handleReqRet(ctx context.Context, conn *agent.Conn, sessionID uint64, ranges []fbbuild.SeqRange, c *metrics.Counters) error {
	// Build a lookup of seq → Item once. For dumps, the items list is
	// fixed; for static kinds the items are generated on the fly so we
	// just regenerate matching seqs from the template.
	resend := func(seq uint64) error {
		var it Item
		if s.payload.Kind == "dump" {
			for _, candidate := range s.payload.Items {
				if candidate.Seq == seq {
					it = candidate
					goto found
				}
			}
			return nil // unknown seq — best effort, skip
		} else {
			// static kind: regenerate the item that was originally sent
			// for this seq. Index from the step, data from the template.
			it = Item{
				Seq:       seq,
				Operation: scenario.OperationUpsert,
				ID:        fmt.Sprintf("doc-%d", seq),
				Index:     s.step.Index,
				Data:      s.payload.Template,
			}
		}
	found:
		if err := s.lim.Wait(ctx); err != nil {
			return err
		}
		buf := fbbuild.BuildDataValue(sessionID, it.Seq, fb.Operation(it.Operation),
			it.ID, it.Index, it.Data)
		if err := conn.SendBinary(s.moduleID, buf); err != nil {
			return err
		}
		c.Inc(metrics.CMessagesSent)
		return nil
	}
	for _, r := range ranges {
		if r.End < r.Begin {
			continue
		}
		for seq := r.Begin; seq <= r.End; seq++ {
			if err := resend(seq); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Source) sendDataBody(ctx context.Context, conn *agent.Conn, sessionID uint64, c *metrics.Counters) error {
	switch s.step.SessionType {
	case scenario.SessionDelta, "": // default = delta
	default:
		// modulecheck/dataclean: skip data body for now; the wrapping
		// state machine still drives Start/End/EndAck so the manager sees
		// a complete session. Full body support is a TODO.
		return nil
	}

	if s.payload.Kind == "dump" {
		return s.sendItems(ctx, conn, sessionID, s.payload.Items, c)
	}
	// static kind: send DataSize copies of the template.
	if s.payload.DataSize <= 0 {
		return nil
	}
	items := make([]Item, s.payload.DataSize)
	for i := range items {
		items[i] = Item{
			Seq:       uint64(i),
			Operation: scenario.OperationUpsert,
			ID:        fmt.Sprintf("doc-%d", i),
			Index:     s.step.Index,
			Data:      s.payload.Template,
		}
	}
	return s.sendItems(ctx, conn, sessionID, items, c)
}

// Batching policy mirrors Python's SessionRunner._send_data_as_batches
// (benchmark_sender.py:1261) and ultimately the real agent's
// MAX_BATCH_PAYLOAD in shared_modules/sync_protocol. Same numbers in
// both senders → same item-per-batch count given the same dump.
const (
	batchTargetBytes     = 60 * 1024 // DEFAULT_BATCH_MAX_BYTES
	fbOverheadPerItem    = 80        // FB_OVERHEAD_PER_ITEM
	batchMessageOverhead = 128       // BATCH_MESSAGE_OVERHEAD
)

func (s *Source) sendItems(ctx context.Context, conn *agent.Conn, sessionID uint64, items []Item, c *metrics.Counters) error {
	if s.step.UseDatabatch {
		return s.sendItemsBatched(ctx, conn, sessionID, items, c)
	}
	for _, it := range items {
		if err := s.lim.Wait(ctx); err != nil {
			return err
		}
		buf := fbbuild.BuildDataValue(sessionID, it.Seq, fb.Operation(it.Operation),
			it.ID, it.Index, it.Data)
		if err := conn.SendBinary(s.moduleID, buf); err != nil {
			return err
		}
		c.Inc(metrics.CMessagesSent)
	}
	return nil
}

func (s *Source) sendItemsBatched(ctx context.Context, conn *agent.Conn, sessionID uint64, items []Item, c *metrics.Counters) error {
	batch := make([]fbbuild.BatchItem, 0, 32)
	batchEst := batchMessageOverhead
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		// max_eps is a wire-message cap, not an item cap. A DataBatch is
		// ONE wire message regardless of how many DataValues it carries —
		// mirrors Python's SessionRunner._send (benchmark_sender.py:1083)
		// which calls _eps_throttle() exactly once per wire send. So we
		// wait for a single token here, not len(batch).
		if err := s.lim.Wait(ctx); err != nil {
			return err
		}
		buf := fbbuild.BuildDataBatch(sessionID, batch)
		if err := conn.SendBinary(s.moduleID, buf); err != nil {
			return err
		}
		c.Inc(metrics.CMessagesSent)
		batch = batch[:0]
		batchEst = batchMessageOverhead
		return nil
	}
	for _, it := range items {
		bi := fbbuild.BatchItem{
			Seq: it.Seq, Operation: fb.Operation(it.Operation),
			DocID: it.ID, Index: it.Index, Data: it.Data,
		}
		itemSize := fbOverheadPerItem + len(it.ID) + len(it.Index) + len(it.Data)
		if len(batch) > 0 && batchEst+itemSize > batchTargetBytes {
			if err := flush(); err != nil {
				return err
			}
		}
		batch = append(batch, bi)
		batchEst += itemSize
	}
	return flush()
}

// moduleIDFor returns the routing tag the manager uses to dispatch the
// frame: "s:<module>_sync:<fbBytes>". Mirrors Python verbatim — see
// benchmark_sender.py SessionRunner._send / _send_start, which always
// uses f"{self.module}_sync" regardless of option / VD / etc. Examples:
//
//	module = "syscollector"        → "syscollector_sync"
//	module = "syscollector_vd"     → "syscollector_vd_sync"
//	module = "fim"                 → "fim_sync"
//	module = "sca"                 → "sca_sync"
//
// The `opt` argument is unused but kept in the signature for clarity at
// the call site (and as a hook if Python's rule ever changes).
func moduleIDFor(module string, opt scenario.Option) string {
	_ = opt
	return module + "_sync"
}

// ackResult is a private channel value.
type ackResult struct {
	session uint64
	status  fb.Status
}
