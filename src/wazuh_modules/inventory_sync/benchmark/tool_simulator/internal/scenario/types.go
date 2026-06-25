// Package scenario loads, validates and normalises a benchmark scenario
// JSON file. Schema reference: docu/03-scenario-schema.md (+ the engine
// extension documented in docu/12-engine-event-streams.md).
package scenario

// SourceKind enumerates the kinds of payload a step can drive.
type SourceKind int

const (
	SourceKindStatic SourceKind = iota // synthetic from a built-in kind template
	SourceKindDump                     // replay a recorded inventory_sync session
	SourceKindEngine                   // stream lines from a file as engine events
)

func (s SourceKind) String() string {
	switch s {
	case SourceKindStatic:
		return "static"
	case SourceKindDump:
		return "dump"
	case SourceKindEngine:
		return "engine"
	}
	return "unknown"
}

// Mode is the integer value of the FlatBuffer Mode enum.
type Mode int

const (
	ModeModuleFull    Mode = 0
	ModeModuleDelta   Mode = 1
	ModeModuleCheck   Mode = 2
	ModeMetadataDelta Mode = 3
	ModeMetadataCheck Mode = 4
	ModeGroupDelta    Mode = 5
	ModeGroupCheck    Mode = 6
)

// Option is the integer value of the FlatBuffer Option enum.
type Option int

const (
	OptionSync    Option = 0
	OptionVDFirst Option = 1
	OptionVDSync  Option = 2
)

// Operation is the integer value of the FlatBuffer Operation enum.
type Operation int

const (
	OperationUpsert Operation = 0
	OperationDelete Operation = 1
)

// SessionType is the inner state machine kind for inventory_sync steps.
type SessionType string

const (
	SessionDelta       SessionType = "delta"
	SessionModuleCheck SessionType = "modulecheck"
	SessionDataClean   SessionType = "dataclean"
)

// PayloadKind is the static-template kind id. See PayloadKinds map.
type PayloadKind string

// PayloadKindMeta describes a built-in synthetic kind.
type PayloadKindMeta struct {
	File   string
	Module string
	Index  string
}

// PayloadKinds maps each `kind` string to its template file + defaults.
// Mirrors PAYLOAD_KINDS in benchmark_sender.py.
var PayloadKinds = map[PayloadKind]PayloadKindMeta{
	"package":            {"syscollector_package.json", "syscollector", "wazuh-states-inventory-packages"},
	"system":             {"syscollector_system.json", "syscollector", "wazuh-states-inventory-system"},
	"hotfix":             {"syscollector_hotfix.json", "syscollector", "wazuh-states-inventory-hotfixes"},
	"fim_file":           {"fim_file.json", "fim", "wazuh-states-fim-files"},
	"fim_file_windows":   {"fim_file_windows.json", "fim", "wazuh-states-fim-files"},
	"fim_registry_key":   {"fim_registry_key.json", "fim", "wazuh-states-fim-registry-keys"},
	"fim_registry_value": {"fim_registry_value.json", "fim", "wazuh-states-fim-registry-values"},
	"sca_check":          {"sca_check.json", "sca", "wazuh-states-sca"},
}

// PadFieldByKind matches PAD_FIELD_BY_KIND in benchmark_sender.py.
var PadFieldByKind = map[PayloadKind]string{
	"package":            "package.description",
	"system":             "host.os.full",
	"hotfix":             "package.hotfix.name",
	"fim_file":           "file.path",
	"fim_file_windows":   "file.path",
	"fim_registry_key":   "registry.path",
	"fim_registry_value": "registry.path",
	"sca_check":          "check.description",
}

// Step is a fully-resolved unit of work in a lane.
type Step struct {
	Lane    string
	StepIdx int
	Kind    SourceKind

	// Inventory-sync fields (when Kind != SourceKindEngine).
	PayloadKind         PayloadKind // empty for dumps
	PayloadDumpPath     string      // empty for static
	SessionType         SessionType
	SyncMode            Mode
	DataSize            int
	UseDatabatch        bool
	Retransmit          bool
	PayloadSize         int
	PadField            string
	ModuleCheckChecksum string
	AutoResync          bool
	Module              string
	Index               string
	StartOption         Option

	// Engine-stream fields (when Kind == SourceKindEngine).
	EnginePath     string
	EngineLocation string
	EngineLoop     bool

	// EngineDuration is the upper-bound run time for the engine source,
	// in seconds. 0 (default) = no time limit. When >0, engine.Run()
	// returns nil as soon as the deadline elapses, regardless of how
	// much file content is left. Composes with EngineRunWhileSiblings
	// via whichever-fires-first.
	EngineDuration float64

	// EngineRunWhileSiblings, when true, makes the engine source
	// terminate as soon as ALL non-engine lanes on the same agent have
	// completed (their goroutines returned from runLane). The loader
	// rejects scenarios where a fleet using a step with this flag has
	// no non-engine lane — see scenario/loader.go for the validation.
	EngineRunWhileSiblings bool

	// Common pacing/repeat.
	MaxEPS       int
	RepeatCount  int
	InitialDelay float64
	RepeatDelay  float64

	// OfflineRetry controls what the runner does when the manager replies
	// to a Start with Status_Offline (typically: data_value_quota
	// exhausted, or the agent locked by a concurrent Metadata/Group
	// session). Semantics:
	//   -1 → abort the iteration on the first Offline (default; matches
	//        the historical behavior).
	//    0 → retry indefinitely until Status_Ok or ctx.Done.
	//   N>0 → at most N total attempts; fail the iteration if all N return
	//         Offline.
	// Only Status_Offline triggers retries — Status_Error / timeouts use
	// AckTimeoutRetry below. Between attempts the runner sleeps
	// OfflineRetryDelay seconds.
	OfflineRetry      int
	OfflineRetryDelay float64

	// StartAckTimeout / EndAckTimeout override the CLI defaults
	// (--start-ack-timeout, --end-ack-timeout) for this specific step.
	// Expressed in seconds. Zero means "use the CLI/Options value".
	// EndAckTimeout in this two-phase design is the LONG window: time
	// allowed between Status_Processing and the terminal Status_Ok
	// (covers indexer flush latency, can legitimately be 40-120 s).
	StartAckTimeout float64
	EndAckTimeout   float64

	// EndAckProcessingTimeout is the SHORT window between sending End
	// and receiving the first ack (typically Status_Processing). The
	// manager should ack End very quickly — if this elapses, the End
	// frame was almost certainly dropped from the manager's input
	// queue, so retrying it (via ack_timeout_retry) is the correct
	// response. Distinct from EndAckTimeout so the post-Processing
	// indexer-flush window can be long without making lost-End
	// detection slow. Zero = inherit from CLI/Options.
	EndAckProcessingTimeout float64

	// PostDataDelay is the pause inserted between the last DataValue of
	// a session and EVERY End frame (initial + every End that follows a
	// ReqRet round). Lets the manager drain its handleData queue so the
	// End hits the gap-empty branch instead of triggering an extra
	// ReqRet round. Sentinel:
	//   -1 → use the inventory package default (1 s).
	//    0 → no pause (back-to-back DataValue → End).
	//   N>0 → wait N seconds.
	// Scenario-only knob; no CLI equivalent.
	PostDataDelay float64

	// AckTimeoutRetry controls retry behaviour when EITHER the StartAck
	// or the terminal EndAck times out. The manager's input queue is
	// bounded — under sustained pressure a Start or End frame can be
	// dropped silently. Resending the frame gives the manager another
	// chance. Semantics mirror OfflineRetry:
	//   -1 → no retry; the timeout fails the iteration (default,
	//        backward-compatible).
	//    0 → retry indefinitely until ack arrives or ctx cancels.
	//   N>0 → up to N attempts total per ack (Start and End budgets are
	//         independent — a Start timeout exhausting its budget does
	//         not consume the End budget).
	// Between attempts the runner sleeps AckTimeoutRetryDelay seconds.
	// On retry: Start resends the Start frame (manager assigns a new
	// session_id); End resends the End frame for the same session_id
	// (manager handles duplicate End gracefully via m_endEnqueued).
	AckTimeoutRetry      int
	AckTimeoutRetryDelay float64
}

// Fleet is a group of agents that share the same set of lanes.
type Fleet struct {
	Name   string
	Agents int
	Lanes  []string
}

// Behavior captures scenario-wide knobs.
type Behavior struct {
	TotalAgents    int
	ParallelAgents int
	RepeatUntil    int
	DrainTimeout   int // 0 = use CLI default
	PostRunGrace   int // sender ignores this; documented for completeness
	HasDrainSet    bool
	HasGraceSet    bool
}

// Scenario is the fully-resolved, validated scenario.
type Scenario struct {
	Name        string
	Description string
	Lanes       map[string][]Step
	Fleets      []Fleet
	Behavior    Behavior

	// FilePath is the resolved scenario file path; used for relative dump
	// resolution at load time only.
	FilePath string
}

// ModeFromString maps the JSON string to a Mode value.
func ModeFromString(s string) (Mode, bool) {
	switch s {
	case "ModuleFull":
		return ModeModuleFull, true
	case "ModuleDelta":
		return ModeModuleDelta, true
	case "ModuleCheck":
		return ModeModuleCheck, true
	case "MetadataDelta":
		return ModeMetadataDelta, true
	case "MetadataCheck":
		return ModeMetadataCheck, true
	case "GroupDelta":
		return ModeGroupDelta, true
	case "GroupCheck":
		return ModeGroupCheck, true
	}
	return 0, false
}

// OptionFromString maps the JSON string to an Option value.
func OptionFromString(s string) (Option, bool) {
	switch s {
	case "Sync":
		return OptionSync, true
	case "VDFirst":
		return OptionVDFirst, true
	case "VDSync":
		return OptionVDSync, true
	}
	return 0, false
}

// OperationFromString maps the JSON string to an Operation value.
func OperationFromString(s string) (Operation, bool) {
	switch s {
	case "Upsert":
		return OperationUpsert, true
	case "Delete":
		return OperationDelete, true
	}
	return 0, false
}
