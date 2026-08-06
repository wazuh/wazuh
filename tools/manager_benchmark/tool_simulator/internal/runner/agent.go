package runner

import (
	"context"
	"sync"
	"time"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/control"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/scenario"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/wire"
)

// agent is one simulated agent: its identity, its client, its fleet's lanes and
// its keepalive loop.
type agent struct {
	r       *Runner
	fleet   scenario.Fleet
	id      string
	name    string
	client  *wire.Client
	seqBase uint64 // namespaces this agent's generated document ids
}

// run drives the agent through its Active phase: startup, then the keepalive
// loop and every lane in parallel, until ctx is done (drain).
func (a *agent) run(ctx context.Context) {
	if a.r.mode == "agent" && a.r.controlEnabled() {
		res, err := control.Startup(a.client, a.startupVersion(), now())
		a.r.reg.RecordControl(a.fleet.Name, "startup", err == nil, us(res.Latency))
		if err != nil {
			a.r.fatalf("agent %s startup: %v", a.id, err)
			return
		}
	}

	var wg sync.WaitGroup
	if a.r.mode == "agent" && a.r.controlEnabled() {
		wg.Add(1)
		go func() { defer wg.Done(); a.keepaliveLoop(ctx) }()
	}
	for _, laneName := range a.fleet.Lanes {
		steps := a.r.scn.Lanes[laneName]
		wg.Add(1)
		go func(lane string, steps []scenario.Step) {
			defer wg.Done()
			a.laneLoop(ctx, lane, steps)
		}(laneName, steps)
	}
	wg.Wait()

	if a.r.mode == "agent" && a.r.controlEnabled() {
		res, err := control.Shutdown(a.client, now())
		a.r.reg.RecordControl(a.fleet.Name, "shutdown", err == nil, us(res.Latency))
	}
}

func (a *agent) keepaliveLoop(ctx context.Context) {
	interval := a.r.scn.Defaults.Control.KeepaliveInterval.D()
	if interval <= 0 {
		interval = 20 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var host *control.HostInfo
			if a.r.scn.Defaults.Control.SendHostInfo {
				host = a.hostInfo()
			}
			res, err := control.Notify(a.client, a.startupVersion(), host, now())
			// A 401/400 is run-invalidating; anything else (including a slow
			// answer) is a recorded result, and the loop continues.
			if perr, ok := err.(*control.ErrProtocol); ok {
				a.r.fatalf("agent %s notify: %v", a.id, perr)
				return
			}
			a.r.reg.RecordControl(a.fleet.Name, "notify", err == nil, us(res.Latency))
		}
	}
}

// laneLoop walks a lane's steps, honoring repeat/initial delays, until ctx is
// done. An engine lane marked run_while_siblings_active is not special here:
// the shared ctx cancels it at drain like everything else.
func (a *agent) laneLoop(ctx context.Context, lane string, steps []scenario.Step) {
	repeatUntil := a.r.scn.Pacing.RepeatUntil.D()
	deadline := time.Time{}
	if repeatUntil > 0 {
		deadline = a.r.start.Add(repeatUntil)
	}
	for {
		for _, step := range steps {
			if ctx.Err() != nil {
				return
			}
			if err := sleepCtx(ctx, step.InitialDelay.D()); err != nil {
				return
			}
			reps := step.RepeatCount
			if reps <= 0 {
				reps = 1
			}
			for i := 0; i < reps; i++ {
				if ctx.Err() != nil {
					return
				}
				a.runStep(ctx, lane, step)
				if i < reps-1 {
					if err := sleepCtx(ctx, step.RepeatDelay.D()); err != nil {
						return
					}
				}
			}
		}
		if deadline.IsZero() || time.Now().After(deadline) {
			return
		}
	}
}

func (a *agent) runStep(ctx context.Context, lane string, step scenario.Step) {
	if step.Kind == "engine" {
		a.runEngine(ctx, lane, step)
		return
	}
	if step.Kind == "full_resync" {
		// D19: Cleans of the module's indices, then a delta with the dataset.
		a.runSession(ctx, lane, cleansStep(step))
		a.runSession(ctx, lane, deltaStep(step))
		return
	}
	if step.Kind == "delete_agent" {
		a.runDelete(ctx, lane)
		return
	}
	a.runSession(ctx, lane, step)
}
