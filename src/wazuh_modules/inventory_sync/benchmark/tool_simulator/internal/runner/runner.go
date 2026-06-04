// Package runner wires agents → lanes → sources, honouring repeat_count,
// initial_delay, repeat_delay, parallel_agents, and repeat_until. See
// docu/04-agent-state-machine.md and docu/07-concurrency-and-pacing.md.
package runner

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/agent"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/engine"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/inventory"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/metrics"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/scenario"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/source"
)

// Config holds the runtime knobs (CLI-derived + scenario-derived).
type Config struct {
	Manager  string
	Port     int
	RegPort  int
	KeyWait  time.Duration
	BenchDir string // resolves sample_payloads/ for static kinds

	// Inventory session timeouts. Zero values fall back to the
	// inventory package defaults (15s start, 120s end).
	StartAckTimeout time.Duration
	EndAckTimeout   time.Duration

	// KeepaliveInterval is how often each agent emits a `#!-<JSON>`
	// control keepalive. 0 disables the ticker entirely (no keepalives,
	// only the initial startup + shutdown frames).
	KeepaliveInterval time.Duration

	// PostDataDelay is the pause inserted between the last data message
	// of a session and its End (applied for both the initial End and
	// every End following a ReqRet). Use PostDataDelaySet=true together
	// with PostDataDelay=0 to explicitly disable the pause; otherwise
	// the inventory package's default (1s) is used.
	PostDataDelay    time.Duration
	PostDataDelaySet bool
}

// Run launches all agents, runs the scenario, and returns when every
// agent has finished (or ctx is canceled).
func Run(ctx context.Context, scn *scenario.Scenario, cfg Config, c *metrics.Counters) (int, error) {
	// Pre-load payloads per (lane, step) — share across agents to avoid
	// re-parsing dumps N times.
	cache, err := buildPayloadCache(scn, cfg.BenchDir)
	if err != nil {
		return 0, err
	}

	// Build the assignment table: each agent_idx → list of lane names.
	assignments := buildAssignments(scn)
	totalAgents := len(assignments)

	// Concurrency cap (semaphore).
	parallel := scn.Behavior.ParallelAgents
	var sem chan struct{}
	if parallel > 0 {
		sem = make(chan struct{}, parallel)
	}

	// Deadline for repeat_until (0 = single pass).
	var deadline time.Time
	if scn.Behavior.RepeatUntil > 0 {
		deadline = time.Now().Add(time.Duration(scn.Behavior.RepeatUntil) * time.Second)
	}

	var wg sync.WaitGroup
	var registered int
	var regMu sync.Mutex

	for i := 0; i < totalAgents; i++ {
		i := i
		lanes := assignments[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			if sem != nil {
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
			}
			runAgent(ctx, i, lanes, scn, cfg, c, cache, deadline, &registered, &regMu)
		}()
	}
	wg.Wait()
	return registered, nil
}

func buildAssignments(scn *scenario.Scenario) [][]string {
	var out [][]string
	for _, f := range scn.Fleets {
		for i := 0; i < f.Agents; i++ {
			out = append(out, append([]string{}, f.Lanes...))
		}
	}
	return out
}

// payloadKey identifies one resolved step uniquely.
type payloadKey struct {
	Lane    string
	StepIdx int
}

// payloadCache holds per-step inventory payloads (engine steps don't need it).
type payloadCache map[payloadKey]*inventory.PayloadInfo

func buildPayloadCache(scn *scenario.Scenario, benchDir string) (payloadCache, error) {
	cache := make(payloadCache)
	for laneName, steps := range scn.Lanes {
		for _, step := range steps {
			if step.Kind == scenario.SourceKindEngine {
				continue
			}
			info, err := inventory.LoadForStep(step, benchDir)
			if err != nil {
				return nil, fmt.Errorf("scenario: %w", err)
			}
			cache[payloadKey{laneName, step.StepIdx}] = info
		}
	}
	return cache, nil
}

func runAgent(ctx context.Context, idx int, lanes []string, scn *scenario.Scenario,
	cfg Config, c *metrics.Counters, cache payloadCache, deadline time.Time,
	registered *int, regMu *sync.Mutex) {

	name := fmt.Sprintf("bench-%04d-%s", idx, randHex12())
	id, err := agent.Register(cfg.Manager, cfg.RegPort, name, 15*time.Second)
	if err != nil {
		log.Printf("agent %d: register failed: %v", idx, err)
		return
	}
	regMu.Lock()
	*registered++
	regMu.Unlock()

	// --key-wait
	if cfg.KeyWait > 0 {
		select {
		case <-time.After(cfg.KeyWait):
		case <-ctx.Done():
			return
		}
	}

	invOpts := inventory.Options{
		StartAckTimeout:  cfg.StartAckTimeout,
		EndAckTimeout:    cfg.EndAckTimeout,
		PostDataDelay:    cfg.PostDataDelay,
		PostDataDelaySet: cfg.PostDataDelaySet,
	}

	for {
		conn := agent.New(id, cfg.Manager, cfg.Port)
		if err := conn.Dial(15 * time.Second); err != nil {
			log.Printf("agent %d: connect failed: %v", idx, err)
			return
		}
		// Forward merged_sum updates from the reader to the metrics
		// counter. Installed BEFORE StartReader so we never miss the
		// first `#!-up file` push.
		conn.SetMergedSumObserver(func(string) {
			c.Inc(metrics.CMergedSumUpdates)
		})
		conn.StartReader(ctx)

		// Keepalive ticker: emits `#!-<JSON>` every cfg.KeepaliveInterval
		// for as long as the iteration runs. The first keepalive ships
		// `merged_sum=""`, which prompts the manager to push us the
		// shared file; we record the hash and report it on subsequent
		// keepalives, breaking the "not synced" loop.
		stopKeepalive := conn.StartKeepalive(ctx, agent.KeepaliveOptions{
			Interval: cfg.KeepaliveInterval,
			Groups:   []string{"default"},
			OnTick: func(r agent.KeepaliveResult) {
				if r.Err != nil {
					c.Inc(metrics.CKeepaliveErrors)
				} else {
					c.Inc(metrics.CKeepalivesSent)
				}
			},
		})

		runIteration(ctx, conn, lanes, scn, c, cache, invOpts)

		// Stop the ticker first so it doesn't race with the shutdown
		// frame for the sendMu. Then send the farewell control message
		// — best-effort, error is informational only.
		stopKeepalive()
		if err := conn.SendShutdown(); err == nil {
			c.Inc(metrics.CShutdownsSent)
		}
		conn.Close()
		if !shouldRepeat(deadline) {
			return
		}
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return
		}
	}
}

func shouldRepeat(deadline time.Time) bool {
	if deadline.IsZero() {
		return false
	}
	return time.Now().Before(deadline)
}

func runIteration(ctx context.Context, conn *agent.Conn, lanes []string, scn *scenario.Scenario,
	c *metrics.Counters, cache payloadCache, invOpts inventory.Options) {
	var wg sync.WaitGroup
	for _, laneName := range lanes {
		laneName := laneName
		steps, ok := scn.Lanes[laneName]
		if !ok {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			runLane(ctx, conn, laneName, steps, c, cache, invOpts)
		}()
	}
	wg.Wait()
}

func runLane(ctx context.Context, conn *agent.Conn, laneName string, steps []scenario.Step,
	c *metrics.Counters, cache payloadCache, invOpts inventory.Options) {
	for _, step := range steps {
		if err := runStep(ctx, conn, laneName, step, c, cache, invOpts); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("lane %s step %d: %v", laneName, step.StepIdx, err)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

func runStep(ctx context.Context, conn *agent.Conn, laneName string, step scenario.Step,
	c *metrics.Counters, cache payloadCache, invOpts inventory.Options) error {

	src := buildSource(step, cache, invOpts)
	if src == nil {
		return fmt.Errorf("nil source")
	}

	if step.InitialDelay > 0 {
		select {
		case <-time.After(time.Duration(step.InitialDelay * float64(time.Second))):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for i := 0; i < step.RepeatCount; i++ {
		if err := src.Run(ctx, conn, c); err != nil {
			if ctx.Err() != nil {
				return err
			}
			// Log + continue; per-iter failures don't kill the lane.
		}
		if i < step.RepeatCount-1 && step.RepeatDelay > 0 {
			select {
			case <-time.After(time.Duration(step.RepeatDelay * float64(time.Second))):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}

func buildSource(step scenario.Step, cache payloadCache, opts inventory.Options) source.Source {
	if step.Kind == scenario.SourceKindEngine {
		return engine.New(step)
	}
	info := cache[payloadKey{step.Lane, step.StepIdx}]
	if info == nil {
		return nil
	}
	return inventory.New(step, info, opts)
}
