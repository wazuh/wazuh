package runner

import (
	"context"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"time"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/engine"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/scenario"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/wire"
)

// The agent's stateless-stream constants this file mirrors
// (src/client-agent/https_client/src/moduleConfig.hpp, backoff.hpp).
const agentBufferCapMultiplier = 4 // buffer cap = batch size x this; beyond it the newest event is dropped

// Backoff bounds of the agent's RetrySender; variables so tests can shorten them.
var (
	agentBackoffBase = time.Second
	agentBackoffCap  = 60 * time.Second
)

// engineStream is the per-(agent, lane) state of an engine step: the start
// jitter that was applied once, and, for "agent" batching, the buffer and
// timers that live across passes the way the agent's accumulator lives across
// its whole run.
type engineStream struct {
	rng      *rand.Rand
	jittered bool

	lines     []string // buffered sample lines, oldest first
	sizes     []int    // framed "E" line bytes of each buffered line
	bytes     int      // sum of sizes
	lastFlush time.Time
	attempt   uint // backoff exponent; reset on a delivered batch
}

// engineStream returns this agent's state for lane, creating it on first use.
// Lanes run on their own goroutines, so the map is guarded; one stream is only
// ever used by its own lane goroutine.
func (a *agent) engineStream(lane string) *engineStream {
	a.streamsMu.Lock()
	defer a.streamsMu.Unlock()
	if a.streams == nil {
		a.streams = map[string]*engineStream{}
	}
	st, ok := a.streams[lane]
	if !ok {
		h := fnv.New64a()
		_, _ = h.Write([]byte(a.id + "|" + lane))
		seed := a.r.seed
		if seed == 0 {
			seed = uint64(time.Now().UnixNano())
		}
		st = &engineStream{rng: rand.New(rand.NewPCG(seed, h.Sum64()))}
		a.streams[lane] = st
	}
	return st
}

// applyStartJitter waits, once per lane, a random time in [0, jitter) so a
// fleet started together does not send in lockstep.
func (a *agent) applyStartJitter(ctx context.Context, st *engineStream, jitter time.Duration) error {
	if st.jittered {
		return nil
	}
	st.jittered = true
	if jitter <= 0 {
		return nil
	}
	return sleepCtx(ctx, time.Duration(st.rng.Int64N(int64(jitter))))
}

// eventLineBytes is the size of line once framed as an "E" line, the unit the
// agent's batch size counts.
func eventLineBytes(location, line string) int {
	return len(fmt.Sprintf("E 1:%s:%s\n", location, line))
}

// runEngineAgent is one pass of an "agent"-batching engine step: it produces
// the sample file's events at events_per_second into the stream's buffer and
// flushes on the agent's policy (src/client-agent/https_client/src/
// statelessStream.cpp): when the buffered "E" bytes reach batch_size_bytes, or
// batch_interval after the previous send ended, sending back to back while the
// buffer stays over the size. A send that cannot be delivered keeps its events
// buffered. The buffer outlives the pass; the last pass of the run flushes what
// is left, as the agent drains on shutdown.
func (a *agent) runEngineAgent(ctx context.Context, lane string, step scenario.Step) {
	lines := a.r.engineLines(step.Engine)
	if len(lines) == 0 || step.EventsPerSecond <= 0 {
		return
	}
	st := a.engineStream(lane)
	if err := a.applyStartJitter(ctx, st, step.ResolvedStartJitter()); err != nil {
		return
	}
	if st.lastFlush.IsZero() {
		st.lastFlush = time.Now()
	}
	size := step.AgentBatchSizeBytes()
	capBytes := size * agentBufferCapMultiplier
	interval := step.AgentBatchInterval()
	eps := step.EventsPerSecond
	eventGap := time.Duration(float64(time.Second) / eps)

	passStart := time.Now()
	produced := 0
	for produced < len(lines) {
		if ctx.Err() != nil {
			return
		}
		due := min(len(lines), int(eps*time.Since(passStart).Seconds()))
		for ; produced < due; produced++ {
			st.add(a, lane, step.Location, lines[produced], capBytes)
		}
		if st.flushDue(size, interval) {
			if !a.flushAgentBatch(ctx, lane, step, st, size) {
				return
			}
			continue
		}
		// Sleep until the interval expires, the buffer would reach the size
		// at the current rate, or the pass has produced everything.
		wake := st.lastFlush.Add(interval)
		if len(st.sizes) > 0 {
			avg := st.bytes / len(st.sizes)
			if fill := passStart.Add(time.Duration(produced+(size-st.bytes)/max(avg, 1)) * eventGap); fill.Before(wake) {
				wake = fill
			}
		}
		if end := passStart.Add(time.Duration(len(lines)) * eventGap); end.Before(wake) {
			wake = end
		}
		if err := sleepCtx(ctx, max(time.Until(wake), eventGap)); err != nil {
			return
		}
	}
	if a.lastPass() {
		// Drain what is left, one batch after another, but stop at the first
		// batch that could not be delivered: like the agent's bounded drain, a
		// manager still refusing it does not hold the run open.
		for len(st.lines) > 0 && ctx.Err() == nil {
			before := len(st.lines)
			if !a.flushAgentBatch(ctx, lane, step, st, size) || len(st.lines) == before {
				return
			}
		}
	}
}

// lastPass reports whether the lane loop will stop after the current pass.
func (a *agent) lastPass() bool {
	repeatUntil := a.r.scn.Pacing.RepeatUntil.D()
	return repeatUntil <= 0 || time.Now().After(a.r.start.Add(repeatUntil))
}

// add buffers line, or drops it (the agent's drop-newest) when the buffer is at its cap.
func (st *engineStream) add(a *agent, lane, location, line string, capBytes int) {
	n := eventLineBytes(location, line)
	if st.bytes+n > capBytes {
		a.r.reg.RecordEventsDropped(a.fleet.Name, lane, 1)
		return
	}
	st.lines = append(st.lines, line)
	st.sizes = append(st.sizes, n)
	st.bytes += n
}

func (st *engineStream) flushDue(size int, interval time.Duration) bool {
	return len(st.lines) > 0 && (st.bytes >= size || time.Since(st.lastFlush) >= interval)
}

// snapshot is how many of the oldest buffered events one request carries:
// as many as fit in size bytes, never fewer than one.
func (st *engineStream) snapshot(size int) int {
	n, total := 0, 0
	for n < len(st.sizes) && (n == 0 || total+st.sizes[n] <= size) {
		total += st.sizes[n]
		n++
	}
	return n
}

func (st *engineStream) consume(n int) {
	for _, s := range st.sizes[:n] {
		st.bytes -= s
	}
	st.lines = append([]string(nil), st.lines[n:]...)
	st.sizes = append([]int(nil), st.sizes[n:]...)
}

// nextBackoff is the agent's full-jitter exponential backoff: uniform in
// [0, min(cap, base * 2^attempt)].
func (st *engineStream) nextBackoff() time.Duration {
	ceiling := min(agentBackoffBase<<min(st.attempt, 16), agentBackoffCap)
	st.attempt++
	return time.Duration(st.rng.Int64N(int64(ceiling) + 1))
}

// flushAgentBatch sends the oldest buffered events as one request, retrying a
// 503, a 5xx or a transport failure up to the step's try budget with the
// agent's backoff (Retry-After wins when longer). A delivered batch, or one the
// manager refused for good, leaves the buffer; an undeliverable one stays for
// the next flush. It reports false when the lane must stop (context done, or a
// run-invalidating answer).
func (a *agent) flushAgentBatch(ctx context.Context, lane string, step scenario.Step, st *engineStream, size int) bool {
	n := st.snapshot(size)
	body := engine.BatchWithHeader(a.engineHeader(step.Header), "1", step.Location, st.lines[:n])
	encoding := ""
	if a.r.mode == "agent" && a.r.compression() == "zstd" {
		body = wire.Compress(body)
		encoding = "zstd"
	}
	defer func() { st.lastFlush = time.Now() }()

	maxAttempts := step.AgentRetryMaxAttempts()
	for attempt := 1; ; attempt++ {
		events := uint64(n)
		if attempt > 1 {
			events = 0 // EventsSent counts each event once, not once per try
		}
		out := a.postEngineBatch(lane, body, encoding, events)
		switch {
		case out.stop:
			return false
		case out.status == 202:
			st.consume(n)
			st.attempt = 0
			return true
		case !out.transportErr && out.status != 503 && out.status < 500:
			// A 4xx other than the run-invalidating 400: retrying the same bytes cannot help.
			st.consume(n)
			return true
		}
		if attempt >= maxAttempts {
			a.r.reg.RecordStatelessRetryExhausted(a.fleet.Name, lane)
			return true
		}
		delay := st.nextBackoff()
		if out.retryAfter > delay {
			delay = out.retryAfter
		}
		if err := sleepCtx(ctx, delay); err != nil {
			return false
		}
		a.r.reg.RecordStatelessRetry(a.fleet.Name, lane)
	}
}
