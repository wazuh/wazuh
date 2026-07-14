package metrics

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Writer is the per-second stats collector. It opens the CSV file, writes
// the header, and at every 1 Hz tick samples Counters.SwapTick() + flushes
// one row.
type Writer struct {
	csvPath      string
	includeEng   bool
	t0           time.Time
	c            *Counters
	csvFile      *os.File
	csvWriter    *csv.Writer
	closeC       chan struct{}
	stopHumanLog chan struct{}
}

// NewWriter opens the CSV file and writes the header row.
func NewWriter(csvPath string, c *Counters, includeEngine bool, t0 time.Time) (*Writer, error) {
	f, err := os.Create(csvPath)
	if err != nil {
		return nil, fmt.Errorf("metrics: open csv: %w", err)
	}
	w := csv.NewWriter(f)
	header := []string{"timestamp", "elapsed_s"}
	header = append(header, PythonHeader...)
	if includeEngine {
		header = append(header, EngineHeader...)
	}
	if err := w.Write(header); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("metrics: write header: %w", err)
	}
	w.Flush()
	return &Writer{
		csvPath:      csvPath,
		includeEng:   includeEngine,
		t0:           t0,
		c:            c,
		csvFile:      f,
		csvWriter:    w,
		closeC:       make(chan struct{}),
		stopHumanLog: make(chan struct{}),
	}, nil
}

// Run ticks at 1 Hz, writing one row per tick. Returns when ctx is
// canceled OR closeC is closed.
func (w *Writer) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var lastHumanLog time.Time
	for {
		select {
		case <-ctx.Done():
			w.finalFlush()
			return
		case <-w.closeC:
			w.finalFlush()
			return
		case t := <-ticker.C:
			tick := w.c.SwapTick()
			elapsed := int(t.Sub(w.t0).Seconds())
			row := make([]string, 0, 2+int(counterCount))
			row = append(row, t.UTC().Format(time.RFC3339))
			row = append(row, strconv.Itoa(elapsed))
			for i := 0; i < int(counterCount); i++ {
				if !w.includeEng && i >= int(CEngineEventsSent) {
					continue
				}
				row = append(row, strconv.FormatInt(tick[i], 10))
			}
			_ = w.csvWriter.Write(row)
			w.csvWriter.Flush()
			if t.Sub(lastHumanLog) >= 5*time.Second {
				lastHumanLog = t
				w.humanLog(t, tick, elapsed)
			}
		}
	}
}

// Close signals Run to exit cleanly.
func (w *Writer) Close() {
	select {
	case <-w.closeC:
	default:
		close(w.closeC)
	}
}

func (w *Writer) finalFlush() {
	if w.csvWriter != nil {
		w.csvWriter.Flush()
	}
	if w.csvFile != nil {
		_ = w.csvFile.Close()
	}
}

// humanLog mirrors the periodic stdout snapshot the Python sender emits.
func (w *Writer) humanLog(_ time.Time, tick [counterCount]int64, elapsed int) {
	fmt.Printf("[+%02d:%02d] started=%d completed=%d failed=%d msgs=%d engine=%d\n",
		elapsed/60, elapsed%60,
		tick[CSessionsStarted], tick[CSessionsCompleted], tick[CSessionsFailed],
		tick[CMessagesSent], tick[CEngineEventsSent],
	)
}
