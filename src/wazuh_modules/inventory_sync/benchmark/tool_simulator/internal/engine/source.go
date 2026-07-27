// Package engine implements the engine-event Source: read lines from a
// file and emit one frame per line, paced by max_eps, looping at EOF if
// requested. Wire format: identifier_blob = "1:<location>:<line>".
// See docu/12-engine-event-streams.md.
package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/agent"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/metrics"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/pacing"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/scenario"
)

// siblingsPollEvery is how often the per-line loop polls the siblings
// counter when run_while_siblings_active is on. Tuned by the user:
// once every 20 line-sends is responsive (~40ms at MaxEPS=500) without
// adding noticeable atomic-load overhead.
const siblingsPollEvery = 20

// Source streams one line per "engine event" frame.
type Source struct {
	path     string
	location string
	maxEPS   int
	loop     bool

	// Termination knobs (zero values keep the legacy behavior of running
	// until ctx is cancelled OR EOF when !loop).
	duration       time.Duration
	waitSiblings   bool
	siblingsCount  *atomic.Int32 // nil unless waitSiblings is true and the runner injected one

	lim *pacing.Limiter
}

// New returns an engine Source built from a fully-resolved Step.
//
// `siblings` is the per-agent counter of non-engine lanes still in
// progress. The runner is responsible for incrementing it before
// launching lane goroutines and decrementing it on lane exit. Pass nil
// when the step did not opt into run_while_siblings_active — Source
// then ignores siblings entirely.
func New(step scenario.Step, siblings *atomic.Int32) *Source {
	loc := step.EngineLocation
	if loc == "" {
		base := filepath.Base(step.EnginePath)
		loc = strings.TrimSuffix(base, filepath.Ext(base))
	}
	s := &Source{
		path:     step.EnginePath,
		location: loc,
		maxEPS:   step.MaxEPS,
		loop:     step.EngineLoop,
		lim:      pacing.New(step.MaxEPS),
	}
	if step.EngineDuration > 0 {
		s.duration = time.Duration(step.EngineDuration * float64(time.Second))
	}
	if step.EngineRunWhileSiblings {
		s.waitSiblings = true
		s.siblingsCount = siblings // may be nil if runner forgot — Source then degrades to no-op (matches legacy)
	}
	return s
}

// Label identifies the source in logs.
func (s *Source) Label() string {
	return "engine:" + filepath.Base(s.path)
}

// terminationReason is the cause that made Run() return nil. Used for
// the one-line logInfo summary at end of step.
type terminationReason string

const (
	reasonEOF       terminationReason = "eof"
	reasonDuration  terminationReason = "duration"
	reasonSiblings  terminationReason = "siblings"
	reasonCtx       terminationReason = "ctx"
)

// errSiblingsExit is the sentinel that runOnce returns when the
// siblings poll observes counter <= 0 (only when waitSiblings is on).
var errSiblingsExit = errors.New("engine: siblings completed")

// Run reads the file line-by-line at most max_eps per second and writes
// each line as an engine-event frame on the shared conn. Returns nil on
// any of the documented termination causes (EOF when !loop, duration
// deadline, siblings completed, ctx cancelled). Always emits a one-line
// info log summarising what cut the step.
func (s *Source) Run(ctx context.Context, conn *agent.Conn, c *metrics.Counters) error {
	tStart := time.Now()
	var eventsSent uint64
	reason := reasonCtx // overwritten by whichever condition actually fires

	// Install duration deadline (whichever-first composition with the
	// other terminators).
	if s.duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.duration)
		defer cancel()
	}

	defer func() {
		log.Printf("engine step terminated: file=%s location=%s reason=%s events_sent=%d elapsed=%.3fs",
			filepath.Base(s.path), s.location, reason, eventsSent, time.Since(tStart).Seconds())
	}()

	// Pre-check siblings: if the runner set the counter to 0 already
	// (e.g., all non-engine lanes finished before engine even started),
	// terminate immediately with reason=siblings.
	if s.waitSiblings && s.siblingsCount != nil && s.siblingsCount.Load() <= 0 {
		reason = reasonSiblings
		return nil
	}

	for {
		err := s.runOnce(ctx, conn, c, &eventsSent)
		switch {
		case err == nil:
			// EOF (file fully read this pass).
			if !s.loop {
				reason = reasonEOF
				return nil
			}
			c.Inc(metrics.CEngineFilesEOFWrap)
			// Re-check terminators before rewinding the file.
			if cerr := ctx.Err(); cerr != nil {
				reason = classifyCtxErr(cerr, s.duration > 0)
				return nil
			}
			if s.waitSiblings && s.siblingsCount != nil && s.siblingsCount.Load() <= 0 {
				reason = reasonSiblings
				return nil
			}
			// Loop: rewind happens at top of next runOnce (it reopens).
		case errors.Is(err, errSiblingsExit):
			reason = reasonSiblings
			return nil
		case errors.Is(err, context.DeadlineExceeded):
			reason = reasonDuration
			return nil
		case errors.Is(err, context.Canceled):
			reason = reasonCtx
			return ctx.Err() // propagate cancel up so callers can stop
		default:
			// Real I/O / send error — propagate.
			reason = reasonCtx
			return err
		}
	}
}

func classifyCtxErr(err error, hasDuration bool) terminationReason {
	if errors.Is(err, context.DeadlineExceeded) && hasDuration {
		return reasonDuration
	}
	return reasonCtx
}

// runOnce reads the file from the start. Returns nil on EOF, ctx errors
// when ctx is done, errSiblingsExit when the siblings counter dropped
// to 0 mid-stream (only when waitSiblings is on).
func (s *Source) runOnce(ctx context.Context, conn *agent.Conn, c *metrics.Counters, eventsSent *uint64) error {
	f, err := os.Open(s.path)
	if err != nil {
		return fmt.Errorf("engine: open %s: %w", s.path, err)
	}
	defer f.Close()

	r := bufio.NewReaderSize(f, 64*1024)
	var sinceSiblingsCheck int
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Siblings check every N lines (cheap atomic load).
		if s.waitSiblings && s.siblingsCount != nil {
			if sinceSiblingsCheck >= siblingsPollEvery {
				sinceSiblingsCheck = 0
				if s.siblingsCount.Load() <= 0 {
					return errSiblingsExit
				}
			}
		}
		line, err := r.ReadString('\n')
		if line != "" {
			// Strip trailing newline (keep \r if present in the file content).
			if line[len(line)-1] == '\n' {
				line = line[:len(line)-1]
			}
			if werr := s.lim.Wait(ctx); werr != nil {
				return werr
			}
			payload := "1:" + s.location + ":" + line
			if werr := conn.SendText(payload); werr != nil {
				c.Inc(metrics.CEngineSendErrors)
				return werr
			}
			c.Inc(metrics.CEngineEventsSent)
			c.Inc(metrics.CMessagesSent)
			*eventsSent++
			sinceSiblingsCheck++
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("engine: read %s: %w", s.path, err)
		}
	}
}
