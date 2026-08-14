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
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/verdict"
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
		enrollSettle = flag.Duration("enroll-settle", 12*time.Second,
			"agent mode: wait after enrollment for remoted to reload client.keys (remoted.keyupdate_interval, 10s default)")
		cluster     = flag.String("cluster", "", "cluster name the sessions declare (overrides the scenario; the server 403s a foreign cluster)")
		compression = flag.String("compression", "",
			"session-body Content-Encoding: zstd | none (overrides the scenario's defaults.compression; agent mode only)")
		noReuse      = flag.Bool("no-reuse", false, "disable HTTP keep-alive (agent mode)")
		seed         = flag.Uint64("seed", 0, "deterministic document seed (0 = random, recorded in meta)")
		validate     = flag.Bool("validate", false, "load and validate the scenario, then exit (no traffic)")
		vdFeedOffset = flag.Uint64("vd-feed-offset", 0, "VDFirst/VDSync sessions declare this Start.feed_offset "+
			"unless a step overrides it; a mismatch against the target's real current offset answers 409 "+
			"version_mismatch instead of scanning. In uds mode this is the ONLY way to set it correctly (there is "+
			"no /control to learn it from -- query it with 'curl --unix-socket queue/sockets/modulesd "+
			"http://localhost/vulnerability-detector/offset'); in agent mode it defaults to whatever the agent's "+
			"own keepalive loop learns from /control's vd_feed_offset")
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
	// The expected block is validated with the same strictness as the rest of
	// the file: a typo'd counter name must not silently weaken the verdict.
	if err := verdict.Validate(scn.Expected); err != nil {
		fmt.Fprintf(os.Stderr, "error: scenario %s: %v\n", *scenarioPath, err)
		return 2
	}
	// The CLI override is held to the loader's own rules: values and the
	// agent-mode requirement (the UDS ingress has no decoder).
	switch *compression {
	case "", "none":
	case "zstd":
		if scn.Mode != "agent" {
			fmt.Fprintln(os.Stderr, "error: --compression zstd needs agent mode: remoted decompresses "+
				"zstd bodies, but the inventory sync server's UDS ingress has no decoder")
			return 2
		}
	default:
		fmt.Fprintf(os.Stderr, "error: --compression must be \"zstd\" or \"none\", got %q\n", *compression)
		return 2
	}

	// --validate loads and strictly checks the scenario (unknown fields, unknown
	// step kinds, mode/kind constraints, expected block) and exits without
	// sending anything. This is what the orchestration and CI use to gate the
	// scenario library.
	if *validate {
		fmt.Printf("ok: %s (mode=%s, fleets=%d, lanes=%d, expected_checks=%d)\n",
			scn.Name, scn.Mode, len(scn.Fleets), len(scn.Lanes), verdict.Count(scn.Expected))
		return 0
	}

	usedSeed := *seed
	if usedSeed == 0 {
		usedSeed = uint64(rand.Int63()) | 1
	}

	rn := runner.New(runner.Config{
		Scenario: scn, ScenarioPath: absPath(*scenarioPath), Mode: scn.Mode,
		Manager: *manager, Port: *port, RegPort: *regPort, Socket: *socket,
		FeedTimeout: *feedTimeout, DrainTimeout: *drainTimeout, Timeout: *timeout, EnrollSettle: *enrollSettle, Cluster: *cluster,
		Compression: *compression, Reuse: !*noReuse, Seed: usedSeed, SenderVer: senderVersion, VDFeedOffset: *vdFeedOffset,
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

	// The verdict runs only over a VALID measurement: judging counters produced
	// by an unauthenticated fleet or a broken transport would be judging noise.
	var verdictRes *verdict.Result
	if code == 0 {
		verdictRes = verdict.Evaluate(scn.Expected, rn.Registry().GlobalSnapshot().C)
	}

	meta := rn.Meta()
	var extra map[string]any
	if verdictRes != nil {
		extra = map[string]any{"expected": verdictRes}
	}
	if err := rn.Registry().WriteSummary(*summaryJSON, meta, extra); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write summary: %v\n", err)
	}
	if verdictRes != nil && !verdictRes.Passed {
		code = 3
	}
	printFinal(rn, meta, code, verdictRes)
	return code
}

func printFinal(rn *runner.Runner, meta metrics.Meta, code int, verdictRes *verdict.Result) {
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
	if c.ScanSent > 0 {
		// 200 is "queued": remoted admits the re-scan and its worker pool
		// dispatches it later (docu/14-scan-vd.md), so this line says how many
		// requests were ACCEPTED, not how many scans finished.
		scan := s.Hists["scan"]
		fmt.Printf("scan/vd: sent=%d 200(queued)=%d 409=%d 503=%d other=%d  admission ms: p50=%.1f p99=%.1f\n",
			c.ScanSent, c.Scan200, c.Scan409, c.Scan503, c.ScanOther,
			float64(scan.P50)/1000, float64(scan.P99)/1000)
	}
	if c.StartupOK+c.StartupErr+c.NotifyOK+c.NotifyErr+c.ShutdownOK+c.ShutdownErr > 0 {
		fmt.Printf("control: startup=%d/%d notify=%d/%d shutdown=%d/%d\n",
			c.StartupOK, c.StartupOK+c.StartupErr, c.NotifyOK, c.NotifyOK+c.NotifyErr, c.ShutdownOK, c.ShutdownOK+c.ShutdownErr)
	}
	if c.RetriesFeed+c.Retries503+c.RetriesExhausted > 0 {
		fmt.Printf("retries: feed=%d 503=%d exhausted=%d\n", c.RetriesFeed, c.Retries503, c.RetriesExhausted)
	}
	sess := s.Hists["session"]
	fmt.Printf("session latency ms: p50=%.1f p99=%.1f  transport_errors=%d abandoned=%d\n",
		float64(sess.P50)/1000, float64(sess.P99)/1000, c.TransportErrors, c.AbandonedOnDrain)
	if verdictRes != nil {
		if verdictRes.Passed {
			fmt.Printf("expected: PASS (%d check(s))\n", verdictRes.Checked)
		} else {
			fmt.Printf("expected: FAIL (%d of %d check(s))\n", len(verdictRes.Failures), verdictRes.Checked)
			for _, f := range verdictRes.Failures {
				fmt.Printf("  - %s\n", f)
			}
		}
	}
	// Exit-code contract: 0 ok, 1 measurement invalid, 2 setup, 3 expected failed.
	// A 3 is still a VALID measurement -- the numbers are trustworthy; they just
	// broke the scenario's contract.
	valid := "VALID"
	switch {
	case code == 3:
		valid = "VALID, but the scenario's expected block failed"
	case code != 0:
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
