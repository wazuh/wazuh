package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/engine"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/fbbuild"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/scenario"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/source"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/wire"
)

const octetStream = "application/octet-stream"

// runSession builds one FullSession from a step, sends it (honoring the shared
// rate limiter and the 503 retry contracts), and records the outcome.
//
// Two distinct 503 retry paths, because they mean different things:
//   - 503 WITH Retry-After (FR-11): the CVE feed is still downloading. The
//     header dictates the delay and --feed-timeout bounds the budget.
//   - 503 WITHOUT the header: backpressure (pipeline full, scan lane full,
//     indexer unhealthy). A real agent re-POSTs the same session, so the
//     sender does too: scenario retry interval (default 500ms), bounded by
//     max_attempts (default 10 sends). Shed-counting scenarios disable it.
//
// Every attempt takes a token from the shared limiter and is recorded: a retry
// is real traffic the server answered, so sessions_sent counts attempts, and
// retries_feed/retries_503 tell the logical sessions apart.
func (a *agent) runSession(ctx context.Context, lane string, step scenario.Step) {
	// encode builds the wire body fresh: Start (with whatever feed_offset is
	// current right now) + payload, raw-overridden, then compressed. Documents
	// are deterministic in (seed, docKey, spec) -- calling this more than once
	// for the same step reproduces identical bytes except for feed_offset.
	var docs int
	encoding := ""
	encode := func() []byte {
		var start fbbuild.Start
		var payload fbbuild.Payload
		start, payload, docs, _ = a.buildSession(lane, step)
		b := fbbuild.BuildSession(start, payload)
		if raw := rawOverride(step); raw != nil {
			b = raw
		}
		// `raw` steps are exempt from compression: their deliberately invalid
		// bodies must reach the server byte-exact, or the 400-contract
		// scenarios would be measuring the decoder instead.
		if a.r.compression() == "zstd" && step.Kind != "raw" {
			b = wire.Compress(b)
			encoding = "zstd"
		}
		return b
	}
	body := encode()

	retry := a.r.scn.Defaults.Retry
	feedDeadline := time.Now().Add(a.r.feedTimeout)
	attempts := 0
	for {
		if err := a.r.sessionLimiter.Wait(ctx); err != nil {
			return
		}
		attempts++

		a.r.requestStarted()
		resp, err := a.client.Do("POST", "/stateful", body, octetStream, encoding, now(), a.r.mode == "uds")
		a.r.requestFinished()
		if err != nil {
			a.r.reg.RecordTransportError(a.fleet.Name, lane)
			return
		}
		if resp.Status == 401 {
			// Not data: the fleet's keys are not in remoted's keystore yet (it reloads
			// client.keys on its own cadence). Counting these as ordinary failures
			// would let a whole run of unauthenticated requests read as a result.
			a.r.fatalf("agent %s session answered 401 (remoted has not loaded this fleet's keys): %s",
				a.id, truncate(resp.Body))
		}
		noop := isNoop(resp.Body)
		hasRetry := resp.RetryAfter != ""
		a.r.reg.RecordSession(a.fleet.Name, lane, resp.Status, noop, hasRetry, us(resp.Latency), uint64(len(body)), uint64(docs))

		if resp.Status != 503 {
			return
		}
		if hasRetry {
			if time.Now().After(feedDeadline) {
				a.r.reg.RecordRetryExhausted(a.fleet.Name, lane)
				return
			}
			a.r.reg.RecordFeedRetry(a.fleet.Name, lane)
			if err := sleepCtx(ctx, retryAfterDelay(resp.RetryAfter)); err != nil {
				return
			}
			// Re-encode, not resend: a real agent's control-learned
			// vd_feed_offset can move during a feed-not-ready wait (this loop
			// can span minutes; the keepalive loop ticks every ~10s in agent
			// mode), and a VDFirst/VDSync session built before the feed
			// finished loading would otherwise keep declaring a now-stale
			// offset forever, turning "the feed became ready" into a
			// version_mismatch 409 instead of the 200 this scenario expects.
			// The backpressure branch below intentionally does NOT do this:
			// a real agent resends its already-queued buffer byte-identical
			// on plain backpressure, only a feed-not-ready wait is long
			// enough for its own offset knowledge to have moved on.
			body = encode()
			continue
		}
		if !retry.RetryEnabled() {
			return
		}
		if max := retry.RetryMaxAttempts(); max > 0 && attempts >= max {
			a.r.reg.RecordRetryExhausted(a.fleet.Name, lane)
			return
		}
		a.r.reg.RecordRetry503(a.fleet.Name, lane)
		if err := sleepCtx(ctx, retry.RetryInterval()); err != nil {
			return
		}
	}
}

// buildSession translates a step into a Start + Payload, generating documents
// deterministically. It returns the document count and total document bytes.
func (a *agent) buildSession(lane string, step scenario.Step) (fbbuild.Start, fbbuild.Payload, int, int) {
	start := a.startFor(lane, step)

	// A dump names a captured session; its metadata (module, option, indices)
	// fills whatever the scenario left unset, for BOTH halves of a full_resync —
	// the cleans half needs the module too, or the server rejects a Start with
	// no module (400).
	if step.Dump != "" {
		a.applyDumpMeta(&start, step)
	}

	// A delta step naming a dump replays the real payloads instead of generating
	// documents. (full_resync's delta half arrives here as kind "delta"; its
	// cleans half is kind "cleans" and only needs the patched Start above.)
	if step.Kind == "delta" && step.Dump != "" {
		return a.buildDumpSession(start, step)
	}

	switch step.Kind {
	case "cleans":
		idx := cleanIndices(a.r.scn, step)
		// full_resync's cleans half of a dump replay cleans the dump's own
		// indices, so a first-scan wipes exactly what the delta then upserts.
		if step.Dump != "" {
			if ds := a.r.dump(step.Dump); len(ds.Indices) > 0 {
				idx = ds.Indices
			}
		}
		return start, fbbuild.Payload{Cleans: idx}, 0, 0
	case "checksum":
		start.Mode = fbbuild.ModeModuleCheck
		index := firstIndex(a.r.scn, step)
		return start, fbbuild.Payload{Checksum: &fbbuild.ChecksumModule{
			Index:    index,
			Checksum: a.checksumValue(lane, step, index),
		}}, 0, 0
	case "metadata":
		start.Mode = modeFor(step, fbbuild.ModeMetadataDelta, fbbuild.ModeMetadataCheck)
		return start, fbbuild.Payload{}, 0, 0
	case "groups":
		start.Mode = modeFor(step, fbbuild.ModeGroupDelta, fbbuild.ModeGroupCheck)
		return start, fbbuild.Payload{}, 0, 0
	default: // "delta", "raw" (body overridden later), and full_resync's delta half
		sync := &fbbuild.SyncData{}
		docs, bytes := a.fillDocuments(lane, step, sync)
		return start, fbbuild.Payload{Sync: sync}, docs, bytes
	}
}

// buildDumpSession replays a captured session. Metadata the scenario did not
// pin (module, option, indices) falls back to the dump's own metadata, so a
// dump is self-describing; the fleet's OS/host metadata still comes from the
// Start. Document ids are namespaced per agent (like generated docs) so a fleet
// replaying one dump does not have every agent overwrite the same _id.
// applyDumpMeta fills a Start's module, option and indices from the dump's own
// metadata when the scenario (step or defaults) left them unset.
func (a *agent) applyDumpMeta(start *fbbuild.Start, step scenario.Step) {
	scn := a.r.scn
	ds := a.r.dump(step.Dump)
	if step.Module == "" && scn.Defaults.Module == "" && ds.Module != "" {
		start.Module = ds.Module
	}
	if step.Option == "" && scn.Defaults.Option == "" && ds.Option != "" {
		start.Option = optionEnum(ds.Option)
		// startFor only fills feed_offset when the SCENARIO already says the
		// session is VD, and a dump that declares "VDFirst"/"VDSync" itself
		// (the real_* first-connect captures do) only becomes VD here. Without
		// re-resolving it, such a session declares option VDFirst with
		// feed_offset 0 and the manager answers 409 version_mismatch against
		// any node whose feed offset is not 0 -- the scan lane never runs.
		if start.Option == fbbuild.OptionVDFirst || start.Option == fbbuild.OptionVDSync {
			start.FeedOffset = a.feedOffsetFor(step)
		}
	}
	if len(step.Indices) == 0 && len(ds.Indices) > 0 {
		start.Indices = ds.Indices
	}
}

func (a *agent) buildDumpSession(start fbbuild.Start, step scenario.Step) (fbbuild.Start, fbbuild.Payload, int, int) {
	ds := a.r.dump(step.Dump)
	sync := &fbbuild.SyncData{Values: make([]fbbuild.Value, 0, len(ds.Items))}
	total := 0
	for _, it := range ds.Items {
		sync.Values = append(sync.Values, fbbuild.Value{
			ID:      a.id + "-" + it.ID,
			Index:   it.Index,
			Version: it.Version,
			Data:    it.Data,
			Delete:  it.Operation == "Delete",
		})
		total += len(it.Data)
	}
	return start, fbbuild.Payload{Sync: sync}, len(ds.Items), total
}

func (a *agent) fillDocuments(lane string, step scenario.Step, sync *fbbuild.SyncData) (int, int) {
	spec := step.Documents
	if spec == nil {
		spec = a.r.scn.Defaults.DocSpecDefault()
	}
	if spec == nil {
		sync.Values = []fbbuild.Value{} // an empty (but present) values vector: the D8 rejection path
		return 0, 0
	}
	index := firstIndex(a.r.scn, step)
	docs := source.Documents(a.r.seed, a.docKey(lane, step), source.DocSpec{
		Count: spec.Count, SizeBytes: spec.SizeBytes, Index: index,
	})
	total := 0
	sync.Values = make([]fbbuild.Value, 0, len(docs))
	for _, d := range docs {
		sync.Values = append(sync.Values, fbbuild.Value{ID: d.ID, Index: index, Data: d.Data})
		total += len(d.Data)
	}
	if step.Contexts != nil {
		ctxDocs := source.Documents(a.r.seed, a.docKey(lane, step)+"-ctx", source.DocSpec{
			Count: step.Contexts.Count, SizeBytes: step.Contexts.SizeBytes, Index: index,
		})
		for _, d := range ctxDocs {
			sync.Contexts = append(sync.Contexts, fbbuild.Context{ID: d.ID, Index: index, Data: d.Data})
		}
	}
	return len(docs), total
}

func (a *agent) checksumValue(lane string, step scenario.Step, index string) string {
	switch step.Checksum {
	case "", "correct":
		spec := step.Documents
		if spec == nil {
			spec = a.r.scn.Defaults.DocSpecDefault()
		}
		if spec == nil {
			return source.AggregateChecksum(nil)
		}
		docs := source.Documents(a.r.seed, a.docKey(lane, replaceKind(step, "delta")), source.DocSpec{
			Count: spec.Count, SizeBytes: spec.SizeBytes, Index: index,
		})
		sums := make([]string, 0, len(docs))
		for _, d := range docs {
			sums = append(sums, d.Checksum)
		}
		return source.AggregateChecksum(sums)
	case "mismatch":
		return strings.Repeat("0", 40)
	default:
		return step.Checksum
	}
}

// runEngine ships the step's sample file to /stateless in batches of
// events_per_batch H/E events (0 = the whole file at once). This agent's own
// events_per_second limiter charges each batch its REAL cost in events
// (WaitN), so the configured rate holds no matter how the events are grouped;
// each agent paces itself independently, so the manager-side total scales
// with how many agents run the lane. One call always covers the entire file;
// a 503'd batch is counted and dropped, never retried -- an agent's events
// are lost the same way.
func (a *agent) runEngine(ctx context.Context, lane string, step scenario.Step) {
	lines := a.r.engineLines(step.Engine)
	if len(lines) == 0 {
		return
	}
	batch := step.EventsPerBatch
	if batch <= 0 || batch > len(lines) {
		batch = len(lines)
	}
	limiter := a.r.engineLimiter(a.id, lane, step.EventsPerSecond, batch)

	for off := 0; off < len(lines); off += batch {
		end := off + batch
		if end > len(lines) {
			end = len(lines)
		}
		chunk := lines[off:end]
		if err := limiter.WaitN(ctx, len(chunk)); err != nil {
			return
		}
		body := engine.Batch(a.id, "1", step.Location, chunk)
		a.r.requestStarted()
		resp, err := a.client.Do("POST", "/stateless", body, "", "", now(), false)
		a.r.requestFinished()
		if err != nil {
			a.r.reg.RecordTransportError(a.fleet.Name, lane)
			return
		}
		if resp.Status == 400 {
			a.r.fatalf("agent %s engine batch answered 400: %s", a.id, truncate(resp.Body))
		}
		a.r.reg.RecordStateless(a.fleet.Name, lane, resp.Status, uint64(len(chunk)), us(resp.Latency))
	}
}

func (a *agent) runDelete(ctx context.Context, lane string) {
	if err := a.r.sessionLimiter.Wait(ctx); err != nil {
		return
	}
	a.r.requestStarted()
	defer a.r.requestFinished()
	resp, err := a.client.Do("DELETE", "/agents", nil, "", "", now(), true)
	if err != nil {
		a.r.reg.RecordTransportError(a.fleet.Name, lane)
		return
	}
	a.r.reg.RecordDelete(a.fleet.Name, lane, resp.Status == 200)
}

func isNoop(body []byte) bool {
	var probe struct {
		Noop bool `json:"noop"`
	}
	_ = json.Unmarshal(body, &probe)
	return probe.Noop
}

func retryAfterDelay(header string) time.Duration {
	secs := 1
	if v, err := fmt.Sscanf(header, "%d", &secs); err != nil || v == 0 {
		secs = 1
	}
	if secs < 1 {
		secs = 1
	}
	if secs > 30 {
		secs = 30
	}
	return time.Duration(secs) * time.Second
}
