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
)

const octetStream = "application/octet-stream"

// runSession builds one FullSession from a step, sends it (honoring the shared
// EPS limiter and the feed-retry contract), and records the outcome.
func (a *agent) runSession(ctx context.Context, lane string, step scenario.Step) {
	if err := a.r.sessionLimiter.Wait(ctx); err != nil {
		return
	}

	start, payload, docs, docBytes := a.buildSession(lane, step)
	body := fbbuild.BuildSession(start, payload)
	if raw := rawOverride(step); raw != nil {
		body = raw
	}

	deadline := time.Now().Add(a.r.feedTimeout)
	for {
		resp, err := a.client.Do("POST", "/stateful", body, octetStream, now(), a.r.mode == "uds")
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
		_ = docBytes

		// FR-11: 503 + Retry-After is the feed still downloading; re-send the
		// SAME buffer after the delay, bounded by --feed-timeout.
		if resp.Status == 503 && hasRetry && time.Now().Before(deadline) {
			a.r.reg.RecordFeedRetry(a.fleet.Name, lane)
			if err := sleepCtx(ctx, retryAfterDelay(resp.RetryAfter)); err != nil {
				return
			}
			continue
		}
		return
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
		Count: spec.Count, SizeBytes: spec.SizeBytes, WithChecksum: spec.WithChecksum, Index: index,
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
			Count: spec.Count, SizeBytes: spec.SizeBytes, WithChecksum: true, Index: index,
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

// runEngine ships one H/E batch to /stateless.
func (a *agent) runEngine(ctx context.Context, lane string, step scenario.Step) {
	limiter := a.r.engineLimiter(lane, step.MaxEPS)
	if err := limiter.Wait(ctx); err != nil {
		return
	}
	lines := a.r.engineLines(step.Engine)
	if len(lines) == 0 {
		return
	}
	body := engine.Batch(a.id, "1", step.Location, lines)
	resp, err := a.client.Do("POST", "/stateless", body, "", now(), false)
	if err != nil {
		a.r.reg.RecordTransportError(a.fleet.Name, lane)
		return
	}
	if resp.Status == 400 {
		a.r.fatalf("agent %s engine batch answered 400: %s", a.id, truncate(resp.Body))
	}
	a.r.reg.RecordStateless(a.fleet.Name, lane, resp.Status, uint64(len(lines)), us(resp.Latency))
}

func (a *agent) runDelete(ctx context.Context, lane string) {
	if err := a.r.sessionLimiter.Wait(ctx); err != nil {
		return
	}
	resp, err := a.client.Do("DELETE", "/agents", nil, "", now(), true)
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
