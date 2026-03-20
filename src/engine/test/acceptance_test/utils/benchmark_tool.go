package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	// Unix HTTP socket where wazuh-engine listens
	SocketPath = "/var/wazuh-manager/queue/sockets/queue-http.sock"
	// Inline JSON header sent with every batch
	HeaderJSON = `{"wazuh":{"cluster": {"name": "wazuh", "id": "123"},"agent":{"id":"001","name":"test-agent"}}}`
	// HTTP endpoint for event ingestion
	Endpoint = "/events/enriched"
	// Fixed queue identifier in event format
	EventQueue = "1"
	// After sending ends, stop when no new output for this long
	DrainGrace = 2 * time.Second
)

// ---------------------------------------------------------------------------
// Configuration (CLI flags with defaults)
// ---------------------------------------------------------------------------

// Config holds all benchmark parameters.
type Config struct {
	TestTimeSec int    // Sending-phase duration in seconds
	Rate        int    // Target EPS (0 = unlimited)
	BatchSize   int    // Events per HTTP request
	InputDir    string // Directory with .txt / .log input files
	OutputFile  string // ndjson output file watched for processed events
	Truncate    bool   // Truncate output before the test starts
	CSVFile     string // Optional CSV report output file
}

// ---------------------------------------------------------------------------
// Per-second statistics
// ---------------------------------------------------------------------------

// SecondStat holds counters for a single elapsed second.
type SecondStat struct {
	Sec       int
	Sent      int
	Processed int
}

// Report holds the final benchmark report data.
type Report struct {
	Cfg            Config
	EventsLoaded   int
	InitialLines   int
	StartTime      time.Time
	SendEndTime    time.Time
	EndTime        time.Time
	TotalSent      int
	TotalProcessed int
	History        []SecondStat
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	cfg := parseFlags()
	validateConfig(cfg)

	// Load events from all input files
	events := loadEventsFromDir(cfg.InputDir)
	if len(events) == 0 {
		log.Fatalf("No events loaded from %s", cfg.InputDir)
	}

	// Shuffle events so they are not sent in file-read order
	rand.Shuffle(len(events), func(i, j int) {
		events[i], events[j] = events[j], events[i]
	})
	fmt.Printf("  Events shuffled.\n")

	// Truncate output file if requested
	if cfg.Truncate {
		truncateFile(cfg.OutputFile)
	}

	watcher := NewLineWatcher(cfg.OutputFile)
	initialLines := watcher.Count()
	client := unixHTTPClient(SocketPath)

	printHeader(cfg, len(events), initialLines)

	report := run(cfg, client, events, initialLines, watcher)
	printReport(report)

	if cfg.CSVFile != "" {
		writeCSV(cfg.CSVFile, report)
	}
}

func parseFlags() Config {
	var cfg Config
	flag.IntVar(&cfg.TestTimeSec, "t", 60, "Sending-phase duration in seconds")
	flag.IntVar(&cfg.Rate, "r", 1000, "Target sending rate (EPS). 0 = unlimited")
	flag.IntVar(&cfg.BatchSize, "b", 50, "Events per HTTP request (batch size)")
	flag.StringVar(&cfg.InputDir, "i", "./test_logs", "Directory with .txt / .log input files")
	flag.StringVar(&cfg.OutputFile, "o",
		"/var/wazuh-manager/logs/alerts/alerts.json",
		"Output file to watch for processed events")
	flag.BoolVar(&cfg.Truncate, "T", false, "Truncate output file before the test")
	flag.StringVar(&cfg.CSVFile, "csv", "", "Path to CSV report output file (optional)")
	flag.Parse()
	return cfg
}

func validateConfig(c Config) {
	if c.TestTimeSec <= 0 {
		log.Fatal("-t must be > 0")
	}
	if c.Rate < 0 {
		log.Fatal("-r must be >= 0")
	}
	if c.BatchSize <= 0 {
		log.Fatal("-b must be > 0")
	}
}

// ---------------------------------------------------------------------------
// Benchmark core
// ---------------------------------------------------------------------------

func run(cfg Config, client *http.Client, events []string, initialLines int, watcher *LineWatcher) Report {
	report := Report{
		Cfg:          cfg,
		EventsLoaded: len(events),
		InitialLines: initialLines,
		StartTime:    time.Now(),
	}

	numEvents := len(events)
	var totalSent atomic.Int64
	var sentThisSec atomic.Int64
	var sendDone atomic.Bool

	// -- Sender goroutine ---------------------------------------------------
	go func() {
		defer sendDone.Store(true)

		idx := 0
		deadline := time.Now().Add(time.Duration(cfg.TestTimeSec) * time.Second)

		if cfg.Rate == 0 {
			// Unlimited: fire as fast as possible
			for time.Now().Before(deadline) {
				batch := nextBatch(events, &idx, numEvents, cfg.BatchSize)
				if err := postBatch(client, batch); err != nil {
					log.Printf("send: %v", err)
				}
				n := int64(len(batch))
				totalSent.Add(n)
				sentThisSec.Add(n)
			}
		} else {
			// Rate-limited: space out batches evenly
			batchInterval := time.Duration(
				float64(time.Second) * float64(cfg.BatchSize) / float64(cfg.Rate),
			)
			for time.Now().Before(deadline) {
				start := time.Now()

				batch := nextBatch(events, &idx, numEvents, cfg.BatchSize)
				if err := postBatch(client, batch); err != nil {
					log.Printf("send: %v", err)
				}
				n := int64(len(batch))
				totalSent.Add(n)
				sentThisSec.Add(n)

				if wait := batchInterval - time.Since(start); wait > 0 {
					time.Sleep(wait)
				}
			}
		}
	}()

	// -- Monitor loop (main goroutine) --------------------------------------
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var (
		mu            sync.Mutex
		history       []SecondStat
		second        int
		prevProcessed = initialLines
		lastActivity  = time.Now()
		draining      bool
	)

	for {
		<-ticker.C
		second++

		cur := watcher.Count() // incremental: reads only new bytes
		pSec := cur - prevProcessed
		sSec := int(sentThisSec.Swap(0))
		prevProcessed = cur

		stat := SecondStat{Sec: second, Sent: sSec, Processed: pSec}
		mu.Lock()
		history = append(history, stat)
		mu.Unlock()

		if pSec > 0 {
			lastActivity = time.Now()
		}

		// Detect transition to drain phase
		if sendDone.Load() && !draining {
			draining = true
			report.SendEndTime = time.Now()
			lastActivity = time.Now() // reset grace window
			fmt.Printf("\n--- Sending complete (%d events). Draining... ---\n\n",
				totalSent.Load())
		}

		tag := ""
		if draining {
			tag = "  [drain]"
		}
		fmt.Printf("[%3ds]  Sent: %8d  |  Processed: %8d%s\n",
			second, sSec, pSec, tag)

		if draining && time.Since(lastActivity) >= DrainGrace {
			break
		}
	}

	report.EndTime = time.Now()
	report.TotalSent = int(totalSent.Load())
	report.TotalProcessed = watcher.Count() - initialLines

	mu.Lock()
	report.History = history
	mu.Unlock()

	return report
}

// ---------------------------------------------------------------------------
// Batch helpers
// ---------------------------------------------------------------------------

// nextBatch returns the next batchSize events cycling through the slice.
func nextBatch(events []string, idx *int, n, batchSize int) []string {
	batch := make([]string, batchSize)
	for i := range batch {
		batch[i] = events[*idx%n]
		*idx++
	}
	return batch
}

// buildPayload constructs the HTTP body for a batch.
//
//	H {}
//	E 1:/path/to/file.txt:raw log line
//	E 1:/path/to/file.txt:another line
//	...
func buildPayload(batch []string) string {
	size := 2 + len(HeaderJSON) + 1
	for _, e := range batch {
		size += 2 + len(e) + 1
	}
	var b strings.Builder
	b.Grow(size)
	b.WriteString("H ")
	b.WriteString(HeaderJSON)
	b.WriteByte('\n')
	for _, e := range batch {
		b.WriteString("E ")
		b.WriteString(e)
		b.WriteByte('\n')
	}
	return b.String()
}

// postBatch sends a batch via HTTP POST to /events/enrichment.
func postBatch(client *http.Client, batch []string) error {
	body := buildPayload(batch)
	resp, err := client.Post(
		"http://localhost"+Endpoint,
		"application/x-ndjson",
		strings.NewReader(body),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Event loading
// ---------------------------------------------------------------------------

// loadEventsFromDir reads all .txt and .log files from dir and builds events
// in the format  queue:location:message  (e.g. "1:/path/file.txt:raw log").
func loadEventsFromDir(dir string) []string {
	globs := []string{"*.txt", "*.log"}
	seen := map[string]bool{}
	var files []string
	for _, g := range globs {
		matches, _ := filepath.Glob(filepath.Join(dir, g))
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				files = append(files, m)
			}
		}
	}

	var events []string
	for _, f := range files {
		lines := readLines(f)
		count := 0
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l == "" {
				continue
			}
			events = append(events, fmt.Sprintf("%s:%s:%s", EventQueue, f, l))
			count++
		}
		fmt.Printf("  %s  -> %d lines\n", filepath.Base(f), count)
	}
	return events
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	if err := sc.Err(); err != nil {
		log.Fatalf("read %s: %v", path, err)
	}
	return out
}

// ---------------------------------------------------------------------------
// File utilities
// ---------------------------------------------------------------------------

// LineWatcher tracks the byte offset of a file so that successive calls to
// Count() only read *new* bytes appended since the last call.  This avoids
// re-reading the entire (potentially multi-GB) output file every second,
// which was the root cause of ticker-drop and inflated per-second values.
type LineWatcher struct {
	path   string
	offset int64
	count  int
}

// NewLineWatcher creates a watcher starting from the current end of *path*.
// The initial line count is computed once (full read), and from that point
// on, Count() only reads new data.
func NewLineWatcher(path string) *LineWatcher {
	w := &LineWatcher{path: path}
	w.count = fullLineCount(path)
	if info, err := os.Stat(path); err == nil {
		w.offset = info.Size()
	}
	return w
}

// Count returns the current total line count by reading only bytes appended
// since the previous call.
func (w *LineWatcher) Count() int {
	f, err := os.Open(w.path)
	if err != nil {
		return w.count
	}
	defer f.Close()

	if _, err := f.Seek(w.offset, io.SeekStart); err != nil {
		return w.count
	}

	buf := make([]byte, 64*1024)
	sep := []byte{'\n'}
	for {
		n, err := f.Read(buf)
		w.count += bytes.Count(buf[:n], sep)
		w.offset += int64(n)
		if err == io.EOF {
			return w.count
		}
		if err != nil {
			return w.count
		}
	}
}

// fullLineCount reads the entire file and counts newlines.  Used only once
// at startup to establish the baseline.
func fullLineCount(name string) int {
	if _, err := os.Stat(name); os.IsNotExist(err) {
		return 0
	}
	f, err := os.Open(name)
	if err != nil {
		return 0
	}
	defer f.Close()

	buf := make([]byte, 64*1024)
	sep := []byte{'\n'}
	count := 0
	for {
		n, err := f.Read(buf)
		count += bytes.Count(buf[:n], sep)
		if err == io.EOF {
			return count
		}
		if err != nil {
			return count
		}
	}
}

func truncateFile(path string) {
	if err := os.Truncate(path, 0); err != nil && !os.IsNotExist(err) {
		log.Printf("warning: truncate %s: %v", path, err)
	}
}

// ---------------------------------------------------------------------------
// HTTP client over Unix socket
// ---------------------------------------------------------------------------

func unixHTTPClient(sock string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sock)
			},
		},
		Timeout: 30 * time.Second,
	}
}

// ---------------------------------------------------------------------------
// Printing
// ---------------------------------------------------------------------------

func printHeader(cfg Config, loaded, initial int) {
	fmt.Println()
	fmt.Println("Benchmark configuration")
	fmt.Printf("  Socket:            %s\n", SocketPath)
	fmt.Printf("  Endpoint:          POST %s\n", Endpoint)
	if cfg.Rate == 0 {
		fmt.Println("  Target rate:       unlimited")
	} else {
		fmt.Printf("  Target rate:       %d EPS\n", cfg.Rate)
	}
	fmt.Printf("  Send duration:     %d s\n", cfg.TestTimeSec)
	fmt.Printf("  Batch size:        %d events\n", cfg.BatchSize)
	fmt.Printf("  Input dir:         %s\n", cfg.InputDir)
	fmt.Printf("  Output file:       %s\n", cfg.OutputFile)
	fmt.Printf("  Truncate output:   %v\n", cfg.Truncate)
	fmt.Printf("  Events loaded:     %d\n", loaded)
	fmt.Printf("  Initial out lines: %d\n", initial)
	fmt.Println()
}

func printReport(r Report) {
	sendDur := r.SendEndTime.Sub(r.StartTime).Seconds()
	if sendDur <= 0 {
		sendDur = r.EndTime.Sub(r.StartTime).Seconds()
	}
	totalDur := r.EndTime.Sub(r.StartTime).Seconds()
	drainDur := totalDur - sendDur

	fmt.Println()
	fmt.Println("=========================================================")
	fmt.Println("                   BENCHMARK REPORT")
	fmt.Println("=========================================================")

	fmt.Println()
	fmt.Println("Timing")
	fmt.Printf("  Sending phase:     %10.2f s\n", sendDur)
	fmt.Printf("  Drain phase:       %10.2f s\n", drainDur)
	fmt.Printf("  Total:             %10.2f s\n", totalDur)

	fmt.Println()
	fmt.Println("Throughput")
	fmt.Printf("  Events sent:       %10d\n", r.TotalSent)
	fmt.Printf("  Events processed:  %10d\n", r.TotalProcessed)
	lost := r.TotalSent - r.TotalProcessed
	fmt.Printf("  Events lost:       %10d", lost)
	if r.TotalSent > 0 {
		fmt.Printf("  (%.2f%%)", float64(lost)/float64(r.TotalSent)*100)
	}
	fmt.Println()

	fmt.Println()
	if sendDur > 0 {
		fmt.Printf("  Avg send rate:     %10.2f EPS\n",
			float64(r.TotalSent)/sendDur)
	}
	if totalDur > 0 {
		fmt.Printf("  Avg process rate:  %10.2f EPS (over total time)\n",
			float64(r.TotalProcessed)/totalDur)
	}

	// Per-second table
	if len(r.History) > 0 {
		fmt.Println()
		fmt.Println("Per-second detail")
		fmt.Printf("  %6s  %12s  %12s\n", "Sec", "Sent (EPS)", "Processed")
		fmt.Printf("  %6s  %12s  %12s\n", "------", "----------", "---------")

		maxS, maxP := 0, 0
		sumS, sumP := 0, 0
		for _, h := range r.History {
			fmt.Printf("  %6d  %12d  %12d\n", h.Sec, h.Sent, h.Processed)
			if h.Sent > maxS {
				maxS = h.Sent
			}
			if h.Processed > maxP {
				maxP = h.Processed
			}
			sumS += h.Sent
			sumP += h.Processed
		}

		n := float64(len(r.History))
		fmt.Println()
		fmt.Printf("  Peak sent rate:    %10d EPS\n", maxS)
		fmt.Printf("  Peak process rate: %10d EPS\n", maxP)
		fmt.Printf("  Avg sent (per-s):  %10.2f EPS\n", float64(sumS)/n)
		fmt.Printf("  Avg proc (per-s):  %10.2f EPS\n", float64(sumP)/n)
	}

	fmt.Println()
	fmt.Println("=========================================================")
}

// ---------------------------------------------------------------------------
// CSV output
// ---------------------------------------------------------------------------

// writeCSV writes per-second stats and a summary row to a CSV file.
func writeCSV(path string, r Report) {
	f, err := os.Create(path)
	if err != nil {
		log.Printf("csv: create %s: %v", path, err)
		return
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Header
	w.Write([]string{"timestamp", "sent", "processed"})

	// Per-second rows
	for i, h := range r.History {
		ts := r.StartTime.Add(time.Duration(i+1) * time.Second)
		w.Write([]string{
			ts.Format(time.RFC3339),
			strconv.Itoa(h.Sent),
			strconv.Itoa(h.Processed),
		})
	}

	fmt.Printf("\nCSV report written to %s (%d rows)\n", path, len(r.History))
}
