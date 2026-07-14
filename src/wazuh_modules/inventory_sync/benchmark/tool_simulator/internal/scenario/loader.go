package scenario

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// benchDir returns the absolute path of the benchmark/ directory. Used as
// the fallback when a step's `dump`/`engine` path does not resolve relative
// to the scenario file. Mirrors Python's Path(__file__).resolve().parent.
func benchDir() string {
	// At runtime the binary lives under benchmark/cmd/benchmark_sender, but
	// scenarios may use paths relative to benchmark/. Caller passes the
	// expected benchmark dir via LoaderOptions; if unset, default to the
	// current working directory.
	wd, _ := os.Getwd()
	return wd
}

// LoaderOptions configures path resolution.
type LoaderOptions struct {
	// BenchDir is the fallback directory used to resolve relative dump /
	// engine paths when the scenario-relative path does not exist. Defaults
	// to the current working directory.
	BenchDir string
}

// Load parses + validates a scenario JSON file.
func Load(path string, opts LoaderOptions) (*Scenario, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("scenario %s: invalid JSON: %w", abs, err)
	}

	bench := opts.BenchDir
	if bench == "" {
		bench = benchDir()
	}
	scenarioDir := filepath.Dir(abs)

	name := asString(doc["name"])
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(abs), filepath.Ext(abs))
	}
	desc := asString(doc["description"])

	defaultsRaw, _ := doc["defaults"].(map[string]any)

	lanesRaw, ok := doc["lanes"].(map[string]any)
	if !ok || len(lanesRaw) == 0 {
		return nil, fmt.Errorf("scenario %s: lanes must be a non-empty object", abs)
	}

	lanes := make(map[string][]Step, len(lanesRaw))
	for laneName, stepsRaw := range lanesRaw {
		stepsArr, ok := stepsRaw.([]any)
		if !ok || len(stepsArr) == 0 {
			return nil, fmt.Errorf("scenario %s: lanes[%q] must be a non-empty list of steps",
				abs, laneName)
		}
		resolved := make([]Step, 0, len(stepsArr))
		for i, sRaw := range stepsArr {
			sMap, ok := sRaw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("scenario %s: lanes[%q][%d] must be an object", abs, laneName, i)
			}
			// Engine steps don't carry inventory-sync session state, so
			// merging the top-level `defaults` blindly into them would
			// push `session_type`, `use_databatch`, etc. — fields the
			// engine loader explicitly rejects. Strip those before
			// the merge when the step opts into the engine type.
			// Step-local overrides still win because they live in sMap.
			effDefaults := defaultsRaw
			if _, isEngine := sMap["engine"]; isEngine {
				effDefaults = filterDefaultsForEngine(defaultsRaw)
			}
			merged := mergeDefaults(effDefaults, sMap)
			step, err := resolveStep(merged, scenarioDir, bench, laneName, i, abs)
			if err != nil {
				return nil, err
			}
			resolved = append(resolved, step)
		}
		lanes[laneName] = resolved
	}

	fleets, err := resolveFleets(doc, lanes, abs)
	if err != nil {
		return nil, err
	}

	// Cross-fleet validation: every fleet that uses an engine step with
	// `run_while_siblings_active: true` must include at least one lane
	// with at least one non-engine step. Otherwise the engine would
	// never see any sibling and would terminate immediately (or wait
	// forever with no decrementer), neither of which is useful.
	if err := validateEngineSiblings(fleets, lanes, abs); err != nil {
		return nil, err
	}

	total := 0
	for _, f := range fleets {
		total += f.Agents
	}
	beh := Behavior{
		TotalAgents:    total,
		ParallelAgents: asInt(doc["parallel_agents"]),
		RepeatUntil:    asInt(doc["repeat_until"]),
	}
	if beh.ParallelAgents < 0 {
		return nil, fmt.Errorf("scenario %s: parallel_agents must be >= 0", abs)
	}
	if beh.RepeatUntil < 0 {
		return nil, fmt.Errorf("scenario %s: repeat_until must be >= 0", abs)
	}
	if v, ok := doc["drain_timeout"]; ok && v != nil {
		dt := asInt(v)
		if dt < 0 {
			return nil, fmt.Errorf("scenario %s: drain_timeout must be >= 0", abs)
		}
		beh.DrainTimeout = dt
		beh.HasDrainSet = true
	}
	if v, ok := doc["post_run_grace"]; ok && v != nil {
		prg := asInt(v)
		if prg < 0 {
			return nil, fmt.Errorf("scenario %s: post_run_grace must be >= 0", abs)
		}
		beh.PostRunGrace = prg
		beh.HasGraceSet = true
	}

	return &Scenario{
		Name:        name,
		Description: desc,
		Lanes:       lanes,
		Fleets:      fleets,
		Behavior:    beh,
		FilePath:    abs,
	}, nil
}

// laneHasNonEngineStep reports whether the lane contains at least one
// step whose Kind is not SourceKindEngine. Used by the engine-siblings
// validation: an engine step with run_while_siblings_active needs a
// peer that can decrement the siblings counter on completion.
func laneHasNonEngineStep(steps []Step) bool {
	for _, s := range steps {
		if s.Kind != SourceKindEngine {
			return true
		}
	}
	return false
}

// validateEngineSiblings rejects scenarios where a fleet has at least
// one engine step with run_while_siblings_active=true but no lane that
// would ever decrement the siblings counter (all-engine fleet).
func validateEngineSiblings(fleets []Fleet, lanes map[string][]Step, scenarioPath string) error {
	for _, f := range fleets {
		// Does this fleet use any engine step with run_while_siblings_active?
		var siblingDependentSteps []string // "lane[idx]" identifiers for the error message
		hasNonEngineLane := false
		for _, laneName := range f.Lanes {
			steps, ok := lanes[laneName]
			if !ok {
				continue
			}
			if laneHasNonEngineStep(steps) {
				hasNonEngineLane = true
			}
			for _, s := range steps {
				if s.Kind == SourceKindEngine && s.EngineRunWhileSiblings {
					siblingDependentSteps = append(siblingDependentSteps,
						fmt.Sprintf("lanes[%q][%d]", laneName, s.StepIdx))
				}
			}
		}
		if len(siblingDependentSteps) > 0 && !hasNonEngineLane {
			return fmt.Errorf(
				"scenario %s: fleet %q uses engine step(s) %v with run_while_siblings_active=true "+
					"but has no non-engine lane on the same agent — the siblings counter would "+
					"never be decremented",
				scenarioPath, f.Name, siblingDependentSteps)
		}
	}
	return nil
}

// inventoryOnlyDefaultKeys lists scenario `defaults` keys that only make
// sense for inventory_sync steps. When merging defaults into an engine
// step we strip these to avoid: (a) the engine loader's strict reject
// list (e.g. session_type, use_databatch), and (b) silent noise from
// the retry/timeout knobs that the engine doesn't consume anyway.
//
// Keeping the list narrow on purpose: knobs that genuinely apply to
// both (`initial_delay`, `repeat_delay`, `max_eps`) are NOT included.
var inventoryOnlyDefaultKeys = map[string]struct{}{
	"session_type":               {},
	"sync_mode":                  {},
	"data_size":                  {},
	"use_databatch":              {},
	"retransmit":                 {},
	"payload_size":               {},
	"pad_field":                  {},
	"modulecheck_checksum":       {},
	"auto_resync":                {},
	"module":                     {},
	"index":                      {},
	"option":                     {},
	"offline_retry":              {},
	"offline_retry_delay":        {},
	"start_ack_timeout":          {},
	"end_ack_processing_timeout": {},
	"end_ack_timeout":            {},
	"ack_timeout_retry":          {},
	"ack_timeout_retry_delay":    {},
	"post_data_delay":            {},
}

// filterDefaultsForEngine returns a copy of `defaults` with all
// inventory-only keys removed. The original map is left untouched.
func filterDefaultsForEngine(defaults map[string]any) map[string]any {
	if defaults == nil {
		return nil
	}
	out := make(map[string]any, len(defaults))
	for k, v := range defaults {
		if _, drop := inventoryOnlyDefaultKeys[k]; drop {
			continue
		}
		out[k] = v
	}
	return out
}

func mergeDefaults(defaults, step map[string]any) map[string]any {
	out := make(map[string]any, len(defaults)+len(step))
	for k, v := range defaults {
		out[k] = v
	}
	for k, v := range step {
		out[k] = v
	}
	return out
}

func resolveFleets(doc map[string]any, lanes map[string][]Step, scenarioPath string) ([]Fleet, error) {
	if fleetsRaw, ok := doc["fleets"]; ok && fleetsRaw != nil {
		if _, hasTotal := doc["total_agents"]; hasTotal {
			return nil, fmt.Errorf("scenario %s: cannot set both `fleets` and `total_agents`", scenarioPath)
		}
		arr, ok := fleetsRaw.([]any)
		if !ok || len(arr) == 0 {
			return nil, fmt.Errorf("scenario %s: fleets must be a non-empty list of objects", scenarioPath)
		}
		seenNames := make(map[string]bool)
		referencedLanes := make(map[string]bool)
		out := make([]Fleet, 0, len(arr))
		for i, fRaw := range arr {
			fMap, ok := fRaw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("scenario %s: fleets[%d] must be an object", scenarioPath, i)
			}
			name := asString(fMap["name"])
			if name == "" {
				return nil, fmt.Errorf("scenario %s: fleets[%d].name must be a non-empty string", scenarioPath, i)
			}
			if seenNames[name] {
				return nil, fmt.Errorf("scenario %s: duplicate fleet name %q", scenarioPath, name)
			}
			seenNames[name] = true
			agents := asInt(fMap["agents"])
			if agents < 1 {
				return nil, fmt.Errorf("scenario %s: fleets[%d].agents must be >= 1", scenarioPath, i)
			}
			lanesAny, ok := fMap["lanes"].([]any)
			if !ok || len(lanesAny) == 0 {
				return nil, fmt.Errorf("scenario %s: fleets[%d].lanes must be a non-empty list", scenarioPath, i)
			}
			seen := make(map[string]bool)
			refs := make([]string, 0, len(lanesAny))
			for _, l := range lanesAny {
				ls := asString(l)
				if ls == "" {
					return nil, fmt.Errorf("scenario %s: fleets[%d].lanes entries must be non-empty strings", scenarioPath, i)
				}
				if _, ok := lanes[ls]; !ok {
					return nil, fmt.Errorf("scenario %s: fleets[%d] references unknown lane %q", scenarioPath, i, ls)
				}
				if seen[ls] {
					return nil, fmt.Errorf("scenario %s: fleets[%d].lanes lists %q more than once", scenarioPath, i, ls)
				}
				seen[ls] = true
				refs = append(refs, ls)
				referencedLanes[ls] = true
			}
			out = append(out, Fleet{Name: name, Agents: agents, Lanes: refs})
		}
		return out, nil
	}

	// Implicit single fleet.
	total := 1
	if v, ok := doc["total_agents"]; ok && v != nil {
		total = asInt(v)
	}
	if total < 1 {
		return nil, fmt.Errorf("scenario %s: total_agents must be >= 1", scenarioPath)
	}
	laneNames := make([]string, 0, len(lanes))
	for k := range lanes {
		laneNames = append(laneNames, k)
	}
	return []Fleet{{Name: "all", Agents: total, Lanes: laneNames}}, nil
}

func resolveStep(cfg map[string]any, scenarioDir, benchDir, laneName string, idx int, scenarioPath string) (Step, error) {
	ctx := fmt.Sprintf("lanes[%q][%d]", laneName, idx)
	step := Step{Lane: laneName, StepIdx: idx}

	kind := asString(cfg["kind"])
	dumpRef := asString(cfg["dump"])
	engineRef := asString(cfg["engine"])

	// XOR among kind / dump / engine.
	count := 0
	for _, s := range []string{kind, dumpRef, engineRef} {
		if s != "" {
			count++
		}
	}
	if count == 0 {
		return step, fmt.Errorf("scenario %s: %s must set exactly one of `kind`, `dump`, or `engine`",
			scenarioPath, ctx)
	}
	if count > 1 {
		return step, fmt.Errorf("scenario %s: %s cannot set more than one of `kind`, `dump`, `engine`",
			scenarioPath, ctx)
	}

	// Engine branch — completely different shape.
	if engineRef != "" {
		return resolveEngineStep(cfg, engineRef, scenarioDir, benchDir, laneName, idx, scenarioPath)
	}

	// Inventory-sync branch (kind or dump).
	if kind != "" {
		if _, ok := PayloadKinds[PayloadKind(kind)]; !ok {
			return step, fmt.Errorf("scenario %s: %s.kind=%q not in known kinds", scenarioPath, ctx, kind)
		}
		step.Kind = SourceKindStatic
		step.PayloadKind = PayloadKind(kind)
	}
	if dumpRef != "" {
		resolved, err := resolveFilePath(dumpRef, scenarioDir, benchDir)
		if err != nil {
			return step, fmt.Errorf("scenario %s: %s.dump file not found: %s",
				scenarioPath, ctx, dumpRef)
		}
		step.Kind = SourceKindDump
		step.PayloadDumpPath = resolved
	}

	sessionType := SessionType(asStringDefault(cfg["session_type"], string(SessionDelta)))
	switch sessionType {
	case SessionDelta, SessionModuleCheck, SessionDataClean:
	default:
		return step, fmt.Errorf("scenario %s: %s.session_type=%q invalid",
			scenarioPath, ctx, sessionType)
	}
	step.SessionType = sessionType

	// Reject renamed legacy fields with a clear error (parity with Python).
	for old, newName := range map[string]string{
		"repeat": "repeat_count", "delay": "initial_delay", "every": "repeat_delay",
	} {
		if _, ok := cfg[old]; ok {
			return step, fmt.Errorf("scenario %s: %s.%s was renamed to `%s`",
				scenarioPath, ctx, old, newName)
		}
	}

	step.RepeatCount = 1
	if v, ok := cfg["repeat_count"]; ok && v != nil {
		step.RepeatCount = asInt(v)
	}
	if step.RepeatCount < 1 {
		return step, fmt.Errorf("scenario %s: %s.repeat_count must be >= 1", scenarioPath, ctx)
	}
	if v, ok := cfg["initial_delay"]; ok && v != nil {
		step.InitialDelay = asFloat(v)
	}
	if step.InitialDelay < 0 {
		return step, fmt.Errorf("scenario %s: %s.initial_delay must be >= 0", scenarioPath, ctx)
	}
	if v, ok := cfg["repeat_delay"]; ok && v != nil {
		step.RepeatDelay = asFloat(v)
	}
	if step.RepeatDelay < 0 {
		return step, fmt.Errorf("scenario %s: %s.repeat_delay must be >= 0", scenarioPath, ctx)
	}

	step.SyncMode = Mode(asIntDefault(cfg["sync_mode"], 1))
	step.DataSize = asInt(cfg["data_size"])
	step.MaxEPS = asInt(cfg["max_eps"])
	// DataBatch is the only batching policy the real agent uses
	// (MAX_BATCH_PAYLOAD = 60 KB in shared_modules/sync_protocol).
	// Default to true so scenarios match the real wire shape; explicit
	// `"use_databatch": false` in the scenario disables it for the rare
	// test that needs individual DataValues.
	step.UseDatabatch = asBool(cfg["use_databatch"], true)
	step.Retransmit = asBool(cfg["retransmit"], true)
	step.PayloadSize = asInt(cfg["payload_size"])
	step.PadField = asString(cfg["pad_field"])
	step.ModuleCheckChecksum = asString(cfg["modulecheck_checksum"])
	step.AutoResync = asBool(cfg["auto_resync"], false)

	// offline_retry policy (per-step; see scenario.Step.OfflineRetry).
	step.OfflineRetry = asIntDefault(cfg["offline_retry"], -1)
	if step.OfflineRetry < -1 {
		return step, fmt.Errorf("scenario %s: %s.offline_retry must be -1, 0, or a positive integer (got %d)",
			scenarioPath, ctx, step.OfflineRetry)
	}
	step.OfflineRetryDelay = asFloatDefault(cfg["offline_retry_delay"], 1.0)
	if step.OfflineRetryDelay < 0 {
		return step, fmt.Errorf("scenario %s: %s.offline_retry_delay must be >= 0 (got %g)",
			scenarioPath, ctx, step.OfflineRetryDelay)
	}

	// Per-step ack timeout overrides. 0 means "use the inventory package
	// default" (DefaultStartAckTimeout / DefaultEndAckProcessingTimeout /
	// DefaultEndAckTimeout). These are scenario-only knobs — there are no
	// equivalent CLI flags.
	step.StartAckTimeout = asFloatDefault(cfg["start_ack_timeout"], 0)
	if step.StartAckTimeout < 0 {
		return step, fmt.Errorf("scenario %s: %s.start_ack_timeout must be >= 0 (got %g)",
			scenarioPath, ctx, step.StartAckTimeout)
	}
	step.EndAckTimeout = asFloatDefault(cfg["end_ack_timeout"], 0)
	if step.EndAckTimeout < 0 {
		return step, fmt.Errorf("scenario %s: %s.end_ack_timeout must be >= 0 (got %g)",
			scenarioPath, ctx, step.EndAckTimeout)
	}
	step.EndAckProcessingTimeout = asFloatDefault(cfg["end_ack_processing_timeout"], 0)
	if step.EndAckProcessingTimeout < 0 {
		return step, fmt.Errorf("scenario %s: %s.end_ack_processing_timeout must be >= 0 (got %g)",
			scenarioPath, ctx, step.EndAckProcessingTimeout)
	}

	// post_data_delay: pause between the last DataValue and every End
	// frame of the session. Sentinel -1 = use the inventory package
	// default (1 s). 0 disables the pause entirely. >0 is the explicit
	// value in seconds.
	step.PostDataDelay = asFloatDefault(cfg["post_data_delay"], -1)
	if step.PostDataDelay < -1 {
		return step, fmt.Errorf("scenario %s: %s.post_data_delay must be -1, 0, or a positive number (got %g)",
			scenarioPath, ctx, step.PostDataDelay)
	}

	// ack timeout retry policy. Same -1/0/N semantics as offline_retry.
	step.AckTimeoutRetry = asIntDefault(cfg["ack_timeout_retry"], -1)
	if step.AckTimeoutRetry < -1 {
		return step, fmt.Errorf("scenario %s: %s.ack_timeout_retry must be -1, 0, or a positive integer (got %d)",
			scenarioPath, ctx, step.AckTimeoutRetry)
	}
	step.AckTimeoutRetryDelay = asFloatDefault(cfg["ack_timeout_retry_delay"], 1.0)
	if step.AckTimeoutRetryDelay < 0 {
		return step, fmt.Errorf("scenario %s: %s.ack_timeout_retry_delay must be >= 0 (got %g)",
			scenarioPath, ctx, step.AckTimeoutRetryDelay)
	}

	var defaultModule, defaultIndex string
	if step.Kind == SourceKindStatic {
		meta := PayloadKinds[step.PayloadKind]
		defaultModule, defaultIndex = meta.Module, meta.Index
	}
	step.Module = orDefault(asString(cfg["module"]), defaultModule)
	step.Index = orDefault(asString(cfg["index"]), defaultIndex)

	if optStr := asString(cfg["option"]); optStr != "" {
		opt, ok := OptionFromString(optStr)
		if !ok {
			return step, fmt.Errorf("scenario %s: %s.option=%q invalid",
				scenarioPath, ctx, optStr)
		}
		step.StartOption = opt
	} // else: defaults to OptionSync (0)

	return step, nil
}

func resolveEngineStep(cfg map[string]any, engineRef, scenarioDir, benchDir, laneName string, idx int, scenarioPath string) (Step, error) {
	step := Step{Lane: laneName, StepIdx: idx, Kind: SourceKindEngine}
	ctx := fmt.Sprintf("lanes[%q][%d]", laneName, idx)

	// Inventory-only fields MUST NOT appear with `engine`.
	forbidden := []string{
		"session_type", "sync_mode", "data_size", "use_databatch", "retransmit",
		"payload_size", "pad_field", "modulecheck_checksum", "auto_resync",
		"module", "index", "option",
	}
	for _, k := range forbidden {
		if _, ok := cfg[k]; ok {
			return step, fmt.Errorf("scenario %s: %s sets `engine` but also %q (engine streams have no session state)",
				scenarioPath, ctx, k)
		}
	}

	maxEPS := asInt(cfg["max_eps"])
	if maxEPS <= 0 {
		return step, fmt.Errorf("scenario %s: %s.max_eps must be > 0 for engine streams",
			scenarioPath, ctx)
	}
	step.MaxEPS = maxEPS

	resolved, err := resolveFilePath(engineRef, scenarioDir, benchDir)
	if err != nil {
		return step, fmt.Errorf("scenario %s: %s.engine file not found: %s",
			scenarioPath, ctx, engineRef)
	}
	step.EnginePath = resolved

	step.EngineLoop = asBool(cfg["loop"], true)

	step.EngineLocation = asString(cfg["location"])
	if step.EngineLocation == "" {
		base := filepath.Base(resolved)
		step.EngineLocation = strings.TrimSuffix(base, filepath.Ext(base))
	}

	step.RepeatCount = 1
	if v, ok := cfg["repeat_count"]; ok && v != nil {
		step.RepeatCount = asInt(v)
	}
	if step.RepeatCount < 1 {
		return step, fmt.Errorf("scenario %s: %s.repeat_count must be >= 1", scenarioPath, ctx)
	}
	// Engine steps control their own iteration via `loop` + `duration`;
	// repeat_count > 1 wouldn't compose cleanly (per-iteration deadlines,
	// nested loop semantics). Reject upfront for clarity.
	if step.RepeatCount > 1 {
		return step, fmt.Errorf("scenario %s: %s.repeat_count must be 1 for engine steps (use `loop` and `duration` instead)",
			scenarioPath, ctx)
	}
	if v, ok := cfg["initial_delay"]; ok && v != nil {
		step.InitialDelay = asFloat(v)
	}
	if step.InitialDelay < 0 {
		return step, fmt.Errorf("scenario %s: %s.initial_delay must be >= 0", scenarioPath, ctx)
	}
	if v, ok := cfg["repeat_delay"]; ok && v != nil {
		step.RepeatDelay = asFloat(v)
	}
	if step.RepeatDelay < 0 {
		return step, fmt.Errorf("scenario %s: %s.repeat_delay must be >= 0", scenarioPath, ctx)
	}

	// New termination knobs (whichever-first composition).
	step.EngineDuration = asFloatDefault(cfg["duration"], 0)
	if step.EngineDuration < 0 {
		return step, fmt.Errorf("scenario %s: %s.duration must be >= 0 (got %g)",
			scenarioPath, ctx, step.EngineDuration)
	}
	step.EngineRunWhileSiblings = asBool(cfg["run_while_siblings_active"], false)

	return step, nil
}

// resolveFilePath resolves p relative to scenarioDir first, then benchDir.
// Mirrors the Python loader's dump-path resolution.
func resolveFilePath(p, scenarioDir, benchDir string) (string, error) {
	if filepath.IsAbs(p) {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		return "", os.ErrNotExist
	}
	cand := filepath.Join(scenarioDir, p)
	if _, err := os.Stat(cand); err == nil {
		return cand, nil
	}
	alt := filepath.Join(benchDir, p)
	if _, err := os.Stat(alt); err == nil {
		return alt, nil
	}
	return "", os.ErrNotExist
}

// ---------- small JSON helpers ----------

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asStringDefault(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

func asInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case int64:
		return int(t)
	case json.Number:
		i, _ := t.Int64()
		return int(i)
	}
	return 0
}

func asIntDefault(v any, def int) int {
	if v == nil {
		return def
	}
	if i := asInt(v); i != 0 || v == float64(0) || v == 0 {
		return i
	}
	return def
}

func asFloat(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case int64:
		return float64(t)
	}
	return 0
}

// asFloatDefault returns def when v is nil/absent, otherwise the numeric
// value of v. Mirrors asIntDefault for float fields where 0.0 is a valid
// explicit user choice distinct from "field not set".
func asFloatDefault(v any, def float64) float64 {
	if v == nil {
		return def
	}
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case int64:
		return float64(t)
	}
	return def
}

func asBool(v any, def bool) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
}
