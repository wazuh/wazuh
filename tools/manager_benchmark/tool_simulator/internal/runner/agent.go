package runner

import (
	"context"
	"sync"
	"sync/atomic"
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

	// vdFeedOffset is the last vd_feed_offset a notify reported (agent mode
	// only; stays 0 in uds mode, which has no /control to learn it from).
	// Written by keepaliveLoop, read by the lane goroutines building
	// VDFirst/VDSync sessions -- atomic because those run concurrently.
	vdFeedOffset atomic.Uint64

	// firstNotify is closed once a notify has actually reported a
	// vd_feed_offset. The keepalive loop and the lane goroutines start
	// together, so firing the first notify "immediately" is not enough on its
	// own: a VD lane with no initial_delay can build its VDFirst session in the
	// same instant and read the zero value, which the manager then rejects with
	// 409 version_mismatch. A VD step waits on this instead of racing it.
	firstNotify chan struct{}
	notifyOnce  sync.Once
	// ctx is this agent's run context, so the wait above is cancelled with the
	// run instead of outliving it.
	ctx context.Context
}

// vdOffsetWait bounds how long a VD step waits for the first /control notify to
// report an offset. Generous relative to a notify round trip (milliseconds) and
// still finite, so a control path that never answers degrades to "declare what
// we know" rather than hanging the lane.
const vdOffsetWait = 30 * time.Second

// run drives the agent through its Active phase: startup, then the keepalive
// loop and every lane in parallel, until ctx is done (drain).
func (a *agent) run(ctx context.Context) {
	a.ctx = ctx
	a.firstNotify = make(chan struct{})
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
		interval = 10 * time.Second
	}
	// Fire once immediately: a real agent's first notify lands well before the
	// steady-state interval elapses, and this is a VD lane's only chance to
	// learn a real vd_feed_offset before its first (often initial_delay: 0)
	// VDFirst step runs -- ticker.C otherwise wouldn't fire until `interval`
	// in, leaving every early VD session at the zero value.
	if ctx.Err() == nil {
		a.notify()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !a.notify() {
				return
			}
		}
	}
}

// notify sends one keepalive and records it. Returns false on a
// run-invalidating protocol error (the caller stops the loop).
func (a *agent) notify() bool {
	var host *control.HostInfo
	if a.r.scn.Defaults.Control.SendHostInfo {
		host = a.hostInfo()
	}
	res, err := control.Notify(a.client, a.startupVersion(), host, now())
	// A 401/400 is run-invalidating; anything else (including a slow
	// answer) is a recorded result, and the loop continues.
	if perr, ok := err.(*control.ErrProtocol); ok {
		a.r.fatalf("agent %s notify: %v", a.id, perr)
		return false
	}
	if err == nil {
		a.vdFeedOffset.Store(res.VDFeedOffset)
		a.notifyOnce.Do(func() { close(a.firstNotify) })
	}
	a.r.reg.RecordControl(a.fleet.Name, "notify", err == nil, us(res.Latency))
	return true
}

// feedOffsetFor resolves Start.feed_offset for a VDFirst/VDSync step: the
// step's own override wins, then the CLI's -vd-feed-offset, then whatever
// this agent's keepalive loop has learned so far (0 before the first notify,
// or always, in uds mode -- see the Config.VDFeedOffset doc).
func (a *agent) feedOffsetFor(step scenario.Step) uint64 {
	if step.FeedOffset != nil {
		return *step.FeedOffset
	}
	if v := a.r.vdFeedOffsetOverride(); v != 0 {
		return v
	}
	a.awaitFirstNotify()
	return a.vdFeedOffset.Load()
}

// awaitFirstNotify blocks until this agent's keepalive loop has learned a
// vd_feed_offset from /control, bounded by vdOffsetWait and by the run's own
// cancellation. A no-op outside agent mode with control enabled: there is no
// /control to learn anything from, and waiting would just stall the lane.
func (a *agent) awaitFirstNotify() {
	if a.r.mode != "agent" || !a.r.controlEnabled() || a.firstNotify == nil {
		return
	}
	timer := time.NewTimer(vdOffsetWait)
	defer timer.Stop()
	done := a.ctx.Done()
	select {
	case <-a.firstNotify:
	case <-done:
	case <-timer.C:
	}
}

// laneLoop walks a lane's steps, honoring repeat/initial delays, until ctx is
// done. Engine lanes are not special here: the shared ctx cancels them at
// drain like everything else.
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
	if step.Kind == "scan_vd" {
		a.runScanVD(ctx, lane, step)
		return
	}
	a.runSession(ctx, lane, step)
}
