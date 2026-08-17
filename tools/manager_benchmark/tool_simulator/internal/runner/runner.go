// Package runner admits agents, runs each agent's keepalive loop and lanes in
// parallel, and drains within a bounded window (docu/06, docu/08). It owns the
// exit-code decision: non-zero only for run-invalidating conditions, never for
// a success ratio (docu/10).
package runner

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/control"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/metrics"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/pacing"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/scenario"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/source"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/wire"
)

// Config is everything the runner needs that is not in the scenario.
type Config struct {
	Scenario     *scenario.Scenario
	ScenarioPath string
	Mode         string
	Manager      string
	Port         int
	RegPort      int
	Socket       string
	FeedTimeout  time.Duration
	DrainTimeout time.Duration
	Timeout      time.Duration
	EnrollSettle time.Duration
	Cluster      string // overrides the scenario's cluster name (environment config)
	// Compression overrides the scenario's defaults.compression: "zstd" forces
	// it on, "none" forces it off, "" keeps the scenario's value. A CLI knob
	// (like Cluster) because it belongs to the pair under test, and it is what
	// makes the with/without-compression A/B one scenario instead of two.
	Compression string
	Reuse       bool
	Seed        uint64
	SenderVer   string
	// VDFeedOffset overrides Start.feed_offset for every VDFirst/VDSync step
	// that doesn't set its own (environment config, like Cluster). 0 means "no
	// override" -- defer to the step, then to what agent mode's keepalive loop
	// learned from /control (uds mode has no such signal, so 0 there means
	// every VD session declares offset 0, matching a target that has none).
	VDFeedOffset uint64
}

// Runner holds run-wide state.
type Runner struct {
	cfg            Config
	scn            *scenario.Scenario
	mode           string
	reg            *metrics.Registry
	sessionLimiter *pacing.Limiter
	feedTimeout    time.Duration
	start          time.Time
	seed           uint64

	agentsActive int64
	inFlight     int64 // requests currently awaiting a response (drain accounting)

	engineMu    sync.Mutex
	engineFiles map[string][]string            // cached sample log lines by path
	engineLim   map[string]*pacing.Limiter     // per-agent engine limiter, keyed by agentID|lane|eps
	dumps       map[string]*source.DumpSession // cached captured-session dumps by path

	failOnce sync.Once
	failErr  error
	cancel   context.CancelFunc

	enrolled int
	failed   int
}

// New builds a runner and its metric registry from the scenario's fleets/lanes.
func New(cfg Config) *Runner {
	scn := cfg.Scenario
	fleetNames := make([]string, 0, len(scn.Fleets))
	laneSet := map[string]bool{}
	for _, f := range scn.Fleets {
		fleetNames = append(fleetNames, f.Name)
		for _, l := range f.Lanes {
			laneSet[l] = true
		}
	}
	laneNames := make([]string, 0, len(laneSet))
	for l := range laneSet {
		laneNames = append(laneNames, l)
	}
	return &Runner{
		cfg:            cfg,
		scn:            scn,
		mode:           cfg.Mode,
		reg:            metrics.NewRegistry(fleetNames, laneNames),
		sessionLimiter: pacing.New(scn.Pacing.RequestsPerSecond),
		feedTimeout:    cfg.FeedTimeout,
		seed:           cfg.Seed,
		engineFiles:    map[string][]string{},
		engineLim:      map[string]*pacing.Limiter{},
		dumps:          map[string]*source.DumpSession{},
	}
}

// Registry exposes the metric registry (for the CSV writer and the summary).
func (r *Runner) Registry() *metrics.Registry { return r.reg }

// AgentsActive is the live count, for the CSV writer.
func (r *Runner) AgentsActive() int { return int(atomic.LoadInt64(&r.agentsActive)) }

// Run enrolls the fleet, then runs it under a concurrency cap until the
// scenario's duration or a signal triggers drain. Returns the exit code.
func (r *Runner) Run(ctx context.Context) int {
	r.start = time.Now()
	ctx, r.cancel = context.WithCancel(ctx)
	defer r.cancel()

	agents, err := r.buildAgents(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "setup: %v\n", err)
		return 2
	}

	// A freshly enrolled fleet is unknown to remoted until it reloads client.keys,
	// and that reload happens on remoted's own schedule -- gaps of well over a
	// minute are normal, far longer than `remoted.keyupdate_interval` suggests. So
	// rather than sleep a guessed interval, wait until the manager actually accepts
	// a signature, then start measuring. This runs whether or not the scenario
	// enables control traffic: without it, a control-less scenario would spend the
	// whole run answering 401 and measure nothing.
	if r.mode == "agent" && len(agents) > 0 {
		if err := r.waitUntilAuthenticated(ctx, agents[0]); err != nil {
			fmt.Fprintf(os.Stderr, "setup: %v\n", err)
			return 2
		}
		// The clock restarts here: enrollment and waiting for the keystore are
		// setup, not load, and counting them would deflate every throughput figure.
		r.start = time.Now()
	}

	// Overall deadline: repeat_until, else one pass. Drain is layered on top.
	if until := r.scn.Pacing.RepeatUntil.D(); until > 0 {
		timer := time.AfterFunc(until, r.cancel)
		defer timer.Stop()
	}

	sem := make(chan struct{}, r.concurrency(len(agents)))
	var wg sync.WaitGroup
	for i := range agents {
		select {
		case <-ctx.Done():
		default:
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(a *agent) {
			defer wg.Done()
			defer func() { <-sem }()
			atomic.AddInt64(&r.agentsActive, 1)
			defer atomic.AddInt64(&r.agentsActive, -1)
			a.run(ctx)
		}(agents[i])
	}

	// A one-pass run ends when every agent finishes; a repeat/duration run ends
	// when the context is cancelled (its timer or a signal), after which drain
	// gives in-flight work a bounded window.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		// Natural completion: nothing left in flight.
	case <-ctx.Done():
		select {
		case <-done:
		case <-time.After(r.drainTimeout()):
			// The drain window closed with requests still awaiting a response:
			// report them (AC-J) instead of letting the run read as complete.
			if left := atomic.LoadInt64(&r.inFlight); left > 0 {
				r.reg.RecordAbandonedN(uint64(left))
			}
		}
	}

	if r.failErr != nil {
		fmt.Fprintf(os.Stderr, "run invalidated: %v\n", r.failErr)
		return 1
	}
	if te := r.reg.TransportErrorTotal(); te > 0 && r.mode == "uds" {
		fmt.Fprintf(os.Stderr, "run invalidated: %d transport error(s) in uds mode\n", te)
		return 1
	}
	return 0
}

// buildAgents enrolls (agent mode) or synthesizes (uds mode) every agent.
func (r *Runner) buildAgents(ctx context.Context) ([]*agent, error) {
	var agents []*agent
	for _, fleet := range r.scn.Fleets {
		for i := 0; i < fleet.Agents; i++ {
			id := fmt.Sprintf("%d", fleet.FirstID+i)
			// The "bench-" prefix is the contract cleanup_agents.sh relies on to
			// delete only benchmark agents (q=name~bench-), never a real one.
			name := fmt.Sprintf("bench-%s-%04d", fleetPrefix(fleet), fleet.FirstID+i)
			ag := &agent{r: r, fleet: fleet, id: id, name: name}

			if r.mode == "agent" {
				ident, err := wire.Enroll(r.cfg.Manager, r.cfg.RegPort, name, r.cfg.Timeout)
				if err != nil {
					r.failed++
					return nil, fmt.Errorf("enroll %s: %w", name, err)
				}
				ag.id = ident.ID
				ag.client = wire.NewAgentClient(ident, r.cfg.Manager, r.cfg.Port, r.cfg.Timeout, r.cfg.Reuse)
				r.enrolled++
			} else {
				ag.client = wire.NewUDSClient(ag.id, r.cfg.Socket, r.cfg.Timeout)
				r.enrolled++ // synthetic identity: "ready" is the uds-mode equivalent of enrolled
			}
			agents = append(agents, ag)
		}
	}
	return agents, nil
}

func (r *Runner) concurrency(total int) int {
	if c := r.scn.Pacing.ConcurrentAgents; c > 0 && c < total {
		return c
	}
	if total < 1 {
		return 1
	}
	return total
}

func (r *Runner) drainTimeout() time.Duration {
	if d := r.scn.Pacing.DrainTimeout.D(); d > 0 {
		return d
	}
	return 60 * time.Second
}

func (r *Runner) controlEnabled() bool { return r.scn.Defaults.Control.Enabled }

// readinessBudget is how long an agent keeps retrying a 401'd startup while it
// waits for remoted to load its key. It reuses the enroll-settle budget, with a
// floor so the wait is useful even when the settle is switched off.
func (r *Runner) readinessBudget() time.Duration {
	if r.cfg.EnrollSettle > 30*time.Second {
		return r.cfg.EnrollSettle
	}
	return 30 * time.Second
}

// fatalf records the first run-invalidating error and cancels the run.
func (r *Runner) fatalf(format string, args ...any) {
	r.failOnce.Do(func() {
		r.failErr = fmt.Errorf(format, args...)
		if r.cancel != nil {
			r.cancel()
		}
	})
}

// engineLimiter returns (and caches) a per-agent event limiter. The rate is in
// EVENTS per second and is EACH agent's own independent budget -- the knob
// shapes what one agent produces, so N agents running the lane in parallel
// deliver up to N*eps to the manager in aggregate. The burst is raised to the
// largest batch seen so a whole batch can be charged atomically (WaitN).
func (r *Runner) engineLimiter(agentID, lane string, eps float64, batch int) *pacing.Limiter {
	key := fmt.Sprintf("%s|%s|%.3f", agentID, lane, eps)
	r.engineMu.Lock()
	l, ok := r.engineLim[key]
	if !ok {
		l = pacing.New(eps)
		r.engineLim[key] = l
	}
	r.engineMu.Unlock()
	l.EnsureBurst(batch)
	return l
}

// requestStarted/requestFinished bracket every outbound request so the drain
// path knows how many were still awaiting a response when its window closed.
func (r *Runner) requestStarted()  { atomic.AddInt64(&r.inFlight, 1) }
func (r *Runner) requestFinished() { atomic.AddInt64(&r.inFlight, -1) }

// engineLines loads and caches a sample log file's lines, relative to the
// scenario file's directory.
func (r *Runner) engineLines(path string) []string {
	r.engineMu.Lock()
	defer r.engineMu.Unlock()
	if lines, ok := r.engineFiles[path]; ok {
		return lines
	}
	full := path
	if !isAbs(path) {
		full = joinDir(r.cfg.ScenarioPath, path)
	}
	lines := readLines(full)
	r.engineFiles[path] = lines
	return lines
}

// dump loads and caches a captured-session dump, relative to the scenario
// file's directory. On a load error it invalidates the run (fatalf) and returns
// an empty session so the caller sends nothing rather than panicking.
func (r *Runner) dump(path string) *source.DumpSession {
	r.engineMu.Lock()
	defer r.engineMu.Unlock()
	if ds, ok := r.dumps[path]; ok {
		return ds
	}
	full := path
	if !isAbs(path) {
		full = joinDir(r.cfg.ScenarioPath, path)
	}
	ds, err := source.LoadDump(full)
	if err != nil {
		r.fatalf("load dump %s: %v", path, err)
		ds = &source.DumpSession{}
	}
	r.dumps[path] = ds
	return ds
}

// Meta assembles the summary metadata after the run.
func (r *Runner) Meta() metrics.Meta {
	end := time.Now()
	target := r.cfg.Socket
	if r.mode == "agent" {
		target = fmt.Sprintf("%s:%d", r.cfg.Manager, r.cfg.Port)
	}
	requested := 0
	for _, f := range r.scn.Fleets {
		requested += f.Agents
	}
	ki := r.scn.Defaults.Control.KeepaliveInterval.D()
	return metrics.Meta{
		ScenarioName: r.scn.Name, ScenarioPath: r.cfg.ScenarioPath, Mode: r.mode,
		Manager: r.cfg.Manager, Port: r.cfg.Port, RegPort: r.cfg.RegPort, Target: target,
		ClusterName: r.clusterName(), AgentsRequested: requested, AgentsEnrolled: r.enrolled, AgentsFailed: r.failed,
		ConcurrentAgents: r.scn.Pacing.ConcurrentAgents, RPSTarget: r.scn.Pacing.RequestsPerSecond,
		KeepaliveInterval: ki.String(), ControlEnabled: r.controlEnabled(), ConnectionReuse: r.cfg.Reuse, Compression: r.compression(),
		DocumentSeed: r.seed, StartTime: r.start.UTC().Format(time.RFC3339), EndTime: end.UTC().Format(time.RFC3339),
		DurationSec: end.Sub(r.start).Seconds(), SenderVersion: r.cfg.SenderVer, GoVersion: runtime.Version(),
	}
}

// clusterName is the cluster the sessions declare. The server rejects a session
// whose cluster is not its own (403), and that value belongs to the environment
// under test rather than to the scenario, so a CLI override wins over the file.
func (r *Runner) clusterName() string {
	return firstNonEmpty(r.cfg.Cluster, clusterNameFromScenario(r.scn))
}

// vdFeedOffsetOverride is the CLI-level VD feed offset, or 0 for "no override"
// (defer to the step, then to the agent's learned value -- see agent.feedOffsetFor).
func (r *Runner) vdFeedOffsetOverride() uint64 {
	return r.cfg.VDFeedOffset
}

// compression resolves the effective session-body encoding: the CLI override
// wins ("none" is the explicit off), else the scenario's defaults resolved for
// this transport (absent = zstd in agent mode, plain in uds -- what a real
// agent does on each).
func (r *Runner) compression() string {
	switch r.cfg.Compression {
	case "none":
		return ""
	case "":
		return r.scn.Defaults.CompressionFor(r.mode)
	default:
		return r.cfg.Compression
	}
}

// controlEnabled/startup version helpers used by the agent.
func (a *agent) startupVersion() string {
	if v := a.r.scn.Defaults.Control.StartupVersion; v != "" {
		return v
	}
	return "5.0.0"
}

func (r *Runner) fatalIf(err error, format string, args ...any) {
	if err != nil {
		r.fatalf(format+": "+err.Error(), args...)
	}
}

// waitUntilAuthenticated blocks until remoted accepts a signed request from the
// given agent, or the readiness budget runs out.
//
// The probe is a `POST /control` startup, which is exactly what a real agent sends
// first after enrolling, so it exercises the same signature path the run depends on
// and leaves the fleet in the state the manager expects. It is one request per run,
// sent before the measurement clock starts.
func (r *Runner) waitUntilAuthenticated(ctx context.Context, probe *agent) error {
	deadline := time.Now().Add(r.readinessBudget())
	const probeDelay = 2 * time.Second
	attempts := 0
	for {
		attempts++
		res, err := control.Startup(probe.client, probe.startupVersion(), now())
		if err == nil {
			if attempts > 1 {
				fmt.Printf("remoted accepted the fleet's keys after %d probe(s)\n", attempts)
			}
			return nil
		}
		if res.Status != 401 {
			return fmt.Errorf("readiness probe (agent %s) answered %d: %v", probe.id, res.Status, err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("remoted still answers 401 for agent %s after %s: it has not reloaded "+
				"client.keys for this fleet (raise --enroll-settle)", probe.id, r.readinessBudget())
		}
		if err := sleepCtx(ctx, probeDelay); err != nil {
			return err
		}
	}
}
