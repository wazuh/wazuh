package metrics

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// csvHeader is the exact bench.csv header (docu/09). A column not here does not
// exist; adding one means editing this line and the row builder together.
const csvHeader = "timestamp,elapsed_s,mode,agents_active," +
	"sessions_sent,sessions_ok,sessions_noop,sessions_409,sessions_400,sessions_401,sessions_403,sessions_413,sessions_500,sessions_503,sessions_503_retry_after,sessions_other," +
	"stateless_sent,stateless_202,stateless_400,stateless_413,stateless_503,stateless_other,events_sent," +
	"scan_sent,scan_200,scan_409,scan_503,scan_other," +
	"retries_feed,retries_503,retries_exhausted,transport_errors," +
	"bytes_sent,documents_sent," +
	"control_startup_ok,control_startup_err,control_notify_ok,control_notify_err,control_shutdown_ok,control_shutdown_err," +
	"deletes_ok,deletes_err," +
	"session_latency_ms_p50,session_latency_ms_p99,notify_latency_ms_p50,notify_latency_ms_p99,stateless_latency_ms_p50,stateless_latency_ms_p99," +
	"scan_latency_ms_p50,scan_latency_ms_p99"

// CSVWriter appends one bench.csv row per wall-clock second.
type CSVWriter struct {
	reg        *Registry
	mode       string
	start      time.Time
	agentsFunc func() int

	mu   sync.Mutex
	file *os.File
	stop chan struct{}
	done chan struct{}
}

// NewCSVWriter opens path and writes the header.
func NewCSVWriter(path, mode string, reg *Registry, start time.Time, agentsFunc func() int) (*CSVWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintln(f, csvHeader); err != nil {
		f.Close()
		return nil, err
	}
	return &CSVWriter{reg: reg, mode: mode, start: start, agentsFunc: agentsFunc, file: f,
		stop: make(chan struct{}), done: make(chan struct{})}, nil
}

// Run ticks once per second until Stop; it writes a final row on stop so the
// last second is not lost.
func (w *CSVWriter) Run() {
	defer close(w.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			w.writeRow()
		case <-w.stop:
			w.writeRow()
			return
		}
	}
}

// Stop ends the writer and closes the file.
func (w *CSVWriter) Stop() {
	close(w.stop)
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	w.file.Close()
}

func (w *CSVWriter) writeRow() {
	s := w.reg.GlobalSnapshot()
	c := s.C
	ms := func(kind string, pctl func(Snapshot) uint64) float64 {
		return float64(pctl(s.Hists[kind])) / 1000.0
	}
	p50 := func(x Snapshot) uint64 { return x.P50 }
	p99 := func(x Snapshot) uint64 { return x.P99 }

	now := time.Now().UTC()
	fields := []string{
		now.Format(time.RFC3339),
		fmt.Sprintf("%.0f", now.Sub(w.start).Seconds()),
		w.mode,
		fmt.Sprintf("%d", w.agentsFunc()),
		u(c.SessionsSent), u(c.SessionsOK), u(c.SessionsNoop), u(c.S409), u(c.S400), u(c.S401), u(c.S403), u(c.S413), u(c.S500), u(c.S503), u(c.S503RetryAfter), u(c.SessOther),
		u(c.StatelessSent), u(c.St202), u(c.StBad400), u(c.StBad413), u(c.St503), u(c.StOther), u(c.EventsSent),
		u(c.ScanSent), u(c.Scan200), u(c.Scan409), u(c.Scan503), u(c.ScanOther),
		u(c.RetriesFeed), u(c.Retries503), u(c.RetriesExhausted), u(c.TransportErrors),
		u(c.BytesSent), u(c.DocumentsSent),
		u(c.StartupOK), u(c.StartupErr), u(c.NotifyOK), u(c.NotifyErr), u(c.ShutdownOK), u(c.ShutdownErr),
		u(c.DeletesOK), u(c.DeletesErr),
		f1(ms("session", p50)), f1(ms("session", p99)),
		f1(ms("notify", p50)), f1(ms("notify", p99)),
		f1(ms("stateless", p50)), f1(ms("stateless", p99)),
		f1(ms("scan", p50)), f1(ms("scan", p99)),
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	fmt.Fprintln(w.file, strings.Join(fields, ","))
}

func u(v uint64) string   { return fmt.Sprintf("%d", v) }
func f1(v float64) string { return fmt.Sprintf("%.1f", v) }
