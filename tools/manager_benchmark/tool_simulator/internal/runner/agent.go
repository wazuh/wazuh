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
		res, err := a.startupWhenAuthenticated(ctx)
		a.r.reg.RecordControl(a.fleet.Name, "startup", err == nil, us(res.Latency))
		if err != nil {
			a.r.fatalf("agent %s startup: %v", a.id, err)
			return
		}
	}

	// The keepalive loop is periodic with no end of its own, so it is tied to a
	// context cancelled once this agent's lanes finish. Without that, a one-pass
	// run (repeat_until 0) would never return and the run's duration -- which the
	// throughput figures divide by -- would only reflect an external timeout.
	keepaliveCtx, stopKeepalive := context.WithCancel(ctx)
	defer stopKeepalive()

	var keepalive sync.WaitGroup
	if a.r.mode == "agent" && a.r.controlEnabled() {
		keepalive.Add(1)
		go func() { defer keepalive.Done(); a.keepaliveLoop(keepaliveCtx) }()
	}

	var lanes sync.WaitGroup
	for _, laneName := range a.fleet.Lanes {
		steps := a.r.scn.Lanes[laneName]
		lanes.Add(1)
		go func(lane string, steps []scenario.Step) {
			defer lanes.Done()
			a.laneLoop(ctx, lane, steps)
		}(laneName, steps)
	}
	lanes.Wait()

	stopKeepalive()
	keepalive.Wait()

	if a.r.mode == "agent" && a.r.controlEnabled() {
		res, err := control.Shutdown(a.client, now())
		a.r.reg.RecordControl(a.fleet.Name, "shutdown", err == nil, us(res.Latency))
	}
}

// startupWhenAuthenticated sends startup, retrying while remoted answers 401.
//
// A freshly enrolled agent is unknown to remoted until it reloads client.keys, and
// that reload does NOT happen on a predictable schedule -- gaps far longer than
// `remoted.keyupdate_interval` are normal, and they grow with fleet size. A fixed
// sleep is therefore the wrong tool: this waits for the manager to actually accept
// the signature, bounded by the same budget, so a run either starts authenticated
// or fails saying so.
func (a *agent) startupWhenAuthenticated(ctx context.Context) (control.Result, error) {
	deadline := time.Now().Add(a.r.readinessBudget())
	const probeDelay = 2 * time.Second
	for {
		res, err := control.Startup(a.client, a.startupVersion(), now())
		if err == nil || res.Status != 401 || time.Now().After(deadline) {
			return res, err
		}
		if err := sleepCtx(ctx, probeDelay); err != nil {
			return res, err
		}
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
