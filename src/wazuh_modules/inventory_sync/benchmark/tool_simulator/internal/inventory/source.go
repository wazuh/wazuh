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

// Timeouts mirror the Python SessionRunner constants.
const (
	startAckTimeout = 15 * time.Second
	endAckTimeout   = 120 * time.Second
)

// Source drives one inventory_sync session per Run() call. SessionType=delta
// is the only fully-implemented variant at this time; modulecheck/dataclean
// fall through to the same Start/End wrapping but skip the data body.
type Source struct {
	step    scenario.Step
	payload *PayloadInfo

	lim *pacing.Limiter

	moduleID string // routing tag, e.g. "syscollector_sync"
}

// New returns an inventory Source. payload should have been loaded once
// and may be shared across Run() iterations (caller's choice).
func New(step scenario.Step, payload *PayloadInfo) *Source {
	return &Source{
		step:     step,
		payload:  payload,
		lim:      pacing.New(step.MaxEPS),
		moduleID: moduleIDFor(payload.Module, payload.Option),
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
// ReqRet handling is not yet implemented for the Go port — see FR-9 in
// docu/02-functional-requirements.md.
func (s *Source) Run(ctx context.Context, conn *agent.Conn, c *metrics.Counters) error {
	c.Inc(metrics.CSessionsStarted)

	identity := conn.Identity()
	indices := s.payload.Indices
	if len(indices) == 0 && s.step.Index != "" {
		indices = []string{s.step.Index}
	}

	// Build + send Start, capture session id via callback.
	startBytes := fbbuild.BuildStart(
		s.payload.Module, fb.Mode(s.payload.Mode), uint64(s.payload.DataSize),
		fb.Option(s.payload.Option), identity.ID, identity.Name, "4.8.0", indices,
	)
	tStart := time.Now()
	ackC := make(chan ackResult, 1)
	if err := conn.SendStart(s.moduleID, startBytes, func(session uint64, status fb.Status) {
		ackC <- ackResult{session: session, status: status}
	}); err != nil {
		c.Inc(metrics.CSessionsFailed)
		return fmt.Errorf("send Start: %w", err)
	}
	c.Inc(metrics.CMessagesSent)

	// Await StartAck.
	var sessionID uint64
	select {
	case <-ctx.Done():
		c.Inc(metrics.CSessionsFailed)
		return ctx.Err()
	case <-time.After(startAckTimeout):
		c.Inc(metrics.CSessionsFailed)
		c.Inc(metrics.CStartRetries) // surfaced as a hint to the operator
		return fmt.Errorf("StartAck timeout")
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

	// Send End.
	tEnd := time.Now()
	if err := conn.SendBinary(s.moduleID, fbbuild.BuildEnd(sessionID)); err != nil {
		c.Inc(metrics.CSessionsFailed)
		return fmt.Errorf("send End: %w", err)
	}
	c.Inc(metrics.CMessagesSent)

	// Await terminal EndAck (Status_Processing → keep waiting).
	deadline := time.NewTimer(endAckTimeout)
	defer deadline.Stop()
	for {
		select {
		case <-ctx.Done():
			c.Inc(metrics.CSessionsFailed)
			return ctx.Err()
		case <-deadline.C:
			c.Inc(metrics.CSessionsFailed)
			return fmt.Errorf("EndAck timeout")
		case in := <-endC:
			if in.Type != fb.MessageTypeEndAck {
				// e.g. ReqRet — full retransmit support is a TODO.
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
				deadline.Reset(endAckTimeout)
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

const batchTargetBytes = 60 * 1024

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
	approxSize := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		// EPS pacing applies per item, but we throttle once per batch:
		// burst at most batchTargetBytes worth of items, then wait.
		for i := 0; i < len(batch); i++ {
			if err := s.lim.Wait(ctx); err != nil {
				return err
			}
		}
		buf := fbbuild.BuildDataBatch(sessionID, batch)
		if err := conn.SendBinary(s.moduleID, buf); err != nil {
			return err
		}
		c.Inc(metrics.CMessagesSent)
		batch = batch[:0]
		approxSize = 0
		return nil
	}
	for _, it := range items {
		bi := fbbuild.BatchItem{
			Seq: it.Seq, Operation: fb.Operation(it.Operation),
			DocID: it.ID, Index: it.Index, Data: it.Data,
		}
		itemSize := len(it.Data) + len(it.ID) + len(it.Index) + 32 // rough overhead
		if approxSize+itemSize > batchTargetBytes && len(batch) > 0 {
			if err := flush(); err != nil {
				return err
			}
		}
		batch = append(batch, bi)
		approxSize += itemSize
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

