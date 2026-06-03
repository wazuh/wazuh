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
	"os"
	"path/filepath"
	"strings"

	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/agent"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/metrics"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/pacing"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/scenario"
)

// Source streams one line per "engine event" frame.
type Source struct {
	path     string
	location string
	maxEPS   int
	loop     bool

	lim *pacing.Limiter
}

// New returns an engine Source built from a fully-resolved Step.
func New(step scenario.Step) *Source {
	loc := step.EngineLocation
	if loc == "" {
		base := filepath.Base(step.EnginePath)
		loc = strings.TrimSuffix(base, filepath.Ext(base))
	}
	return &Source{
		path:     step.EnginePath,
		location: loc,
		maxEPS:   step.MaxEPS,
		loop:     step.EngineLoop,
		lim:      pacing.New(step.MaxEPS),
	}
}

// Label identifies the source in logs.
func (s *Source) Label() string {
	return "engine:" + filepath.Base(s.path)
}

// Run reads the file line-by-line at most max_eps per second and writes
// each line as an engine-event frame on the shared conn. On EOF it
// rewinds and continues if loop=true, else returns nil. ctx cancellation
// is honored at every read + send.
func (s *Source) Run(ctx context.Context, conn *agent.Conn, c *metrics.Counters) error {
	for {
		if err := s.runOnce(ctx, conn, c); err != nil {
			return err
		}
		if !s.loop {
			return nil
		}
		c.Inc(metrics.CEngineFilesEOFWrap)
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

func (s *Source) runOnce(ctx context.Context, conn *agent.Conn, c *metrics.Counters) error {
	f, err := os.Open(s.path)
	if err != nil {
		return fmt.Errorf("engine: open %s: %w", s.path, err)
	}
	defer f.Close()

	r := bufio.NewReaderSize(f, 64*1024)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, err := r.ReadString('\n')
		if line != "" {
			// Strip trailing newline (keep \r if present in the file content).
			if line[len(line)-1] == '\n' {
				line = line[:len(line)-1]
			}
			if err := s.lim.Wait(ctx); err != nil {
				return err
			}
			payload := "1:" + s.location + ":" + line
			if werr := conn.SendText(payload); werr != nil {
				c.Inc(metrics.CEngineSendErrors)
				return werr
			}
			c.Inc(metrics.CEngineEventsSent)
			c.Inc(metrics.CMessagesSent)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("engine: read %s: %w", s.path, err)
		}
	}
}
