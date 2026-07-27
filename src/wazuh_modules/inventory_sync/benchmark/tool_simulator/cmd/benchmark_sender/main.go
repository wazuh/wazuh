// Command benchmark_sender is the Go reimplementation of
// benchmark_sender.py. See reqmd/ in the parent directory.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/metrics"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/runner"
	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/scenario"
)

const version = "1.0.0"

func main() {
	var (
		scenarioPath = flag.String("scenario", "", "Path to scenario JSON (required)")
		manager      = flag.String("manager", "127.0.0.1", "Manager address")
		port         = flag.Int("port", 1514, "Manager port")
		regPort      = flag.Int("reg-port", 1515, "Registration port")
		output       = flag.String("output", "bench.csv", "Output CSV file")
		summaryJSON  = flag.String("summary-json", "", "If set, write a final summary JSON")
		drainTimeout = flag.Float64("drain-timeout", 60.0, "Seconds to keep sampling after agents finish")
		keyWait      = flag.Int("key-wait", 35, "Seconds to wait after registration for remoted key reload")
		// Session-level timing knobs (start_ack_timeout, end_ack_timeout,
		// end_ack_processing_timeout, post_data_delay) are scenario-only.
		// Set them per-step or via `defaults:` in the scenario JSON.
		keepaliveInterval = flag.Duration("keepalive-interval", 20*time.Second, "How often each agent emits a control-message keepalive (`#!-<JSON>`). Matches the real agent's NOTIFY_TIME default. Pass 0s to disable keepalives entirely (the initial startup + final shutdown frames are still sent).")
		debug             = flag.Bool("debug", false, "Debug logging")
		reportEngine      = flag.Bool("report-engine", true, "Emit engine_* columns in bench.csv")
	)
	// -o alias for --output (matches Python's argparse alias).
	flag.StringVar(output, "o", "bench.csv", "Output CSV file (alias of --output)")
	flag.Parse()

	if *scenarioPath == "" {
		fmt.Fprintln(os.Stderr, "--scenario is required")
		os.Exit(2)
	}
	if *debug {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	}

	// Determine benchmark directory (used to resolve sample_payloads/ + relative
	// dump paths when the scenario-relative resolution misses).
	//
	// The binary lives at .../benchmark/tool_simulator/benchmark_sender, so its
	// parent is .../benchmark/ — where scenarios/ and sample_payloads/ live.
	// Falls back to CWD if Executable() fails (tests, dev builds).
	benchDir, _ := os.Getwd()
	if exe, err := os.Executable(); err == nil {
		if exeDir, derr := filepath.Abs(filepath.Dir(exe)); derr == nil {
			benchDir = filepath.Dir(exeDir)
		}
	}

	scn, err := scenario.Load(*scenarioPath, scenario.LoaderOptions{BenchDir: benchDir})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	// Drain timeout: CLI override applies if scenario didn't set one;
	// scenario setting takes precedence over default but CLI takes
	// precedence over both (matches Python comment).
	dt := time.Duration(*drainTimeout * float64(time.Second))
	if scn.Behavior.HasDrainSet {
		dt = time.Duration(scn.Behavior.DrainTimeout) * time.Second
	}
	// CLI explicit non-default overrides scenario.
	if isFlagSet("drain-timeout") {
		dt = time.Duration(*drainTimeout * float64(time.Second))
	}

	c := metrics.New()
	t0 := time.Now()
	writer, err := metrics.NewWriter(*output, c, *reportEngine, t0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Root context cancelled by SIGINT/SIGTERM.
	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Second-signal force-exit watcher.
	go forceExitOnSecondSignal()

	// CSV writer ticks every 1s; runs until we Close() it.
	writerCtx, writerCancel := context.WithCancel(context.Background())
	defer writerCancel()
	go writer.Run(writerCtx)

	log.Printf("scenario=%s total_agents=%d parallel_agents=%d repeat_until=%ds drain=%ds keepalive=%s engine_cols=%v",
		scn.Name, scn.Behavior.TotalAgents, scn.Behavior.ParallelAgents,
		scn.Behavior.RepeatUntil, int(dt.Seconds()), *keepaliveInterval, *reportEngine)

	registered, err := runner.Run(rootCtx, scn, runner.Config{
		Manager:           *manager,
		Port:              *port,
		RegPort:           *regPort,
		KeyWait:           time.Duration(*keyWait) * time.Second,
		BenchDir:          benchDir,
		KeepaliveInterval: *keepaliveInterval,
	}, c)
	if err != nil {
		log.Printf("runner: %v", err)
	}

	// Drain phase: keep the CSV writer alive for `dt` seconds (or until ctx done).
	log.Printf("agents done; entering drain (%ds)", int(dt.Seconds()))
	drainCtx, drainCancel := context.WithTimeout(context.Background(), dt)
	<-drainCtx.Done()
	drainCancel()

	writer.Close()
	writerCancel()

	if *summaryJSON != "" {
		meta := metrics.SummaryMeta{
			ScenarioName:    scn.Name,
			ScenarioPath:    scn.FilePath,
			Manager:         *manager,
			Port:            *port,
			RegPort:         *regPort,
			TotalAgents:     scn.Behavior.TotalAgents,
			AgentsRegistered: registered,
			ParallelAgents:  scn.Behavior.ParallelAgents,
			RepeatUntil:     scn.Behavior.RepeatUntil,
			DrainTimeout:    int(dt.Seconds()),
			Sender:          "go",
			Version:         version,
		}
		if err := c.WriteSummary(*summaryJSON, meta, t0, time.Now(), *reportEngine); err != nil {
			log.Printf("write summary: %v", err)
		}
	}
}

func isFlagSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func forceExitOnSecondSignal() {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	first := time.Now()
	for {
		<-ch
		if time.Since(first) < 2*time.Second {
			os.Exit(130)
		}
		first = time.Now()
	}
}
