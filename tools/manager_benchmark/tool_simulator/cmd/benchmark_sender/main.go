// benchmark_sender generates load against the Wazuh manager's ingestion paths
// and reports what it observed. See the design set in ../../docu/.
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/metrics"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/runner"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/scenario"
)

// senderVersion is stamped into the artifacts; overridden at build time with
// -ldflags "-X main.senderVersion=<git describe>".
var senderVersion = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	var (
		scenarioPath = flag.String("scenario", "", "path to the scenario JSON (required)")
		mode         = flag.String("mode", "", "transport: uds | agent (overrides the scenario)")
		socket       = flag.String("socket", "queue/sockets/inventory-sync.sock", "uds mode: module socket path")
		manager      = flag.String("manager", "127.0.0.1", "agent mode: manager host")
		port         = flag.Int("port", 1517, "agent mode: remoted HTTPS port")
		regPort      = flag.Int("reg-port", 1515, "agent mode: authd enrollment port")
		output       = flag.String("output", "bench.csv", "per-second metrics CSV")
		summaryJSON  = flag.String("summary-json", "sender_summary.json", "run summary JSON")
		feedTimeout  = flag.Duration("feed-timeout", 300*time.Second, "budget for feed-not-ready (503+Retry-After) retries")
		drainTimeout = flag.Duration("drain-timeout", 60*time.Second, "bounded shutdown window")
		timeout      = flag.Duration("timeout", 120*time.Second, "per-request timeout")
		noReuse      = flag.Bool("no-reuse", false, "disable HTTP keep-alive (agent mode)")
		seed         = flag.Uint64("seed", 0, "deterministic document seed (0 = random, recorded in meta)")
		validate     = flag.Bool("validate", false, "load and validate the scenario, then exit (no traffic)")
	)
	flag.Parse()

	if *scenarioPath == "" {
		fmt.Fprintln(os.Stderr, "error: --scenario is required")
		flag.Usage()
		return 2
	}

	scn, err := scenario.Load(*scenarioPath, *mode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	// --validate loads and strictly checks the scenario (unknown fields, unknown
	// step kinds, mode/kind constraints) and exits without sending anything.
	// This is what the orchestration and CI use to gate the scenario library.
	if *validate {
		fmt.Printf("ok: %s (mode=%s, fleets=%d, lanes=%d)\n", scn.Name, scn.Mode, len(scn.Fleets), len(scn.Lanes))
		return 0
	}

	usedSeed := *seed
	if usedSeed == 0 {
		usedSeed = uint64(rand.Int63()) | 1
	}

	rn := runner.New(runner.Config{
		Scenario: scn, ScenarioPath: absPath(*scenarioPath), Mode: scn.Mode,
		Manager: *manager, Port: *port, RegPort: *regPort, Socket: *socket,
		FeedTimeout: *feedTimeout, DrainTimeout: *drainTimeout, Timeout: *timeout,
		Reuse: !*noReuse, Seed: usedSeed, SenderVer: senderVersion,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	start := time.Now()
	writer, err := metrics.NewCSVWriter(*output, scn.Mode, rn.Registry(), start, rn.AgentsActive)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	go writer.Run()

	fmt.Printf("=== benchmark_sender (%s) ===\nscenario: %s  mode: %s\n", senderVersion, scn.Name, scn.Mode)
	code := rn.Run(ctx)
	writer.Stop()

	meta := rn.Meta()
	if err := rn.Registry().WriteSummary(*summaryJSON, meta); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write summary: %v\n", err)
	}
	printFinal(rn, meta, code)
	return code
}

func printFinal(rn *runner.Runner, meta metrics.Meta, code int) {
	s := rn.Registry().GlobalSnapshot()
	c := s.C
	fmt.Printf("\n--- run summary ---\n")
	fmt.Printf("mode=%s agents=%d/%d duration=%.1fs\n",
		meta.Mode, meta.AgentsEnrolled, meta.AgentsRequested, meta.DurationSec)
	fmt.Printf("sessions: sent=%d ok=%d noop=%d 400=%d 403=%d 409=%d 413=%d 500=%d 503=%d(retry_after=%d) other=%d\n",
		c.SessionsSent, c.SessionsOK, c.SessionsNoop, c.S400, c.S403, c.S409, c.S413, c.S500, c.S503, c.S503RetryAfter, c.SessOther)
	if c.StatelessSent > 0 {
		fmt.Printf("stateless: sent=%d 202=%d 400=%d 413=%d 503=%d events=%d\n",
			c.StatelessSent, c.St202, c.StBad400, c.StBad413, c.St503, c.EventsSent)
	}
	if c.NotifyOK+c.NotifyErr > 0 {
		fmt.Printf("control: startup=%d/%d notify=%d/%d shutdown=%d/%d\n",
			c.StartupOK, c.StartupOK+c.StartupErr, c.NotifyOK, c.NotifyOK+c.NotifyErr, c.ShutdownOK, c.ShutdownOK+c.ShutdownErr)
	}
	sess := s.Hists["session"]
	fmt.Printf("session latency ms: p50=%.1f p99=%.1f  transport_errors=%d abandoned=%d\n",
		float64(sess.P50)/1000, float64(sess.P99)/1000, c.TransportErrors, c.AbandonedOnDrain)
	valid := "VALID"
	if code != 0 {
		valid = "INVALID (measurement not trustworthy)"
	}
	fmt.Printf("run: %s (exit %d)\n", valid, code)
}

func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}
