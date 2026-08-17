// Package fbbuild turns a plain session spec into the FlatBuffers
// Message{FullSession} bytes an agent POSTs to /stateful. It knows nothing
// about transports (docu/05-flatbuffers-messages.md).
package fbbuild

import (
	fb "github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/fb/Wazuh/SyncSchema"

	flatbuffers "github.com/google/flatbuffers/go"
)

// Mode and Option mirror the schema enums, so callers do not import the
// generated package directly.
type Mode = fb.Mode

const (
	ModeModuleDelta   = fb.ModeModuleDelta
	ModeModuleCheck   = fb.ModeModuleCheck
	ModeMetadataDelta = fb.ModeMetadataDelta
	ModeMetadataCheck = fb.ModeMetadataCheck
	ModeGroupDelta    = fb.ModeGroupDelta
	ModeGroupCheck    = fb.ModeGroupCheck
)

type Option = fb.Option

const (
	OptionSync    = fb.OptionSync
	OptionVDFirst = fb.OptionVDFirst
	OptionVDSync  = fb.OptionVDSync
)

// Start is the who/what/how of a session. Empty string fields are omitted.
type Start struct {
	Module        string
	Mode          Mode
	Option        Option
	Indices       []string
	Architecture  string
	Hostname      string
	OSName        string
	OSPlatform    string
	OSType        string
	OSVersion     string
	AgentVersion  string
	AgentName     string
	AgentID       string
	Groups        []string
	GlobalVersion uint64
	// ClusterName is required by the server (empty -> 400, foreign -> 403). There
	// is deliberately no ClusterNode: the schema still carries the field, but the
	// manager never validated it and is dropping its last consumer, and a real
	// agent only ever echoed back what the manager itself told it during the
	// /control handshake. The sender leaves it unset -- see docu/05.
	ClusterName string
	FeedOffset  uint64
}

// Value is one DataValue: a document upsert or delete.
type Value struct {
	Delete  bool
	ID      string
	Index   string
	Version uint64
	Data    []byte // the document as JSON bytes
}

// Context is one DataContext: vulnerability-detection context, never indexed.
type Context struct {
	ID    string
	Index string
	Data  []byte
}

// Payload is exactly one of the three, matching the SessionPayload union. A nil
// Payload builds a Start-only FullSession (the metadata/group modes).
type Payload struct {
	Sync     *SyncData
	Cleans   []string        // indices to clean
	Checksum *ChecksumModule // integrity verification
}

// SyncData is the ModuleDelta payload.
type SyncData struct {
	Values   []Value
	Contexts []Context
}

// ChecksumModule is the ModuleCheck payload.
type ChecksumModule struct {
	Index    string
	Checksum string
}

// BuildSession serializes one Message{FullSession}. It builds whatever it is
// told, including combinations the server rejects — the validation matrix is
// part of what the benchmark exercises.
func BuildSession(start Start, payload Payload) []byte {
	b := flatbuffers.NewBuilder(1024)

	payloadType := fb.SessionPayloadNONE
	var payloadOffset flatbuffers.UOffsetT
	switch {
	case payload.Sync != nil:
		payloadType = fb.SessionPayloadSyncData
		payloadOffset = buildSyncData(b, payload.Sync)
	case payload.Cleans != nil:
		payloadType = fb.SessionPayloadCleans
		payloadOffset = buildCleans(b, payload.Cleans)
	case payload.Checksum != nil:
		payloadType = fb.SessionPayloadChecksumModule
		payloadOffset = buildChecksum(b, payload.Checksum)
	}

	startOffset := buildStart(b, start)

	fb.FullSessionStart(b)
	fb.FullSessionAddStart(b, startOffset)
	if payloadType != fb.SessionPayloadNONE {
		fb.FullSessionAddPayloadType(b, payloadType)
		fb.FullSessionAddPayload(b, payloadOffset)
	}
	session := fb.FullSessionEnd(b)

	fb.MessageStart(b)
	fb.MessageAddContentType(b, fb.MessageTypeFullSession)
	fb.MessageAddContent(b, session)
	b.Finish(fb.MessageEnd(b))
	return b.FinishedBytes()
}

func buildStart(b *flatbuffers.Builder, s Start) flatbuffers.UOffsetT {
	// Strings and vectors first: nothing referenced by the table may be built
	// after StartStart.
	str := func(v string) flatbuffers.UOffsetT {
		if v == "" {
			return 0
		}
		return b.CreateString(v)
	}
	module := str(s.Module)
	arch := str(s.Architecture)
	hostname := str(s.Hostname)
	osname := str(s.OSName)
	osplatform := str(s.OSPlatform)
	ostype := str(s.OSType)
	osversion := str(s.OSVersion)
	agentversion := str(s.AgentVersion)
	agentname := str(s.AgentName)
	agentid := str(s.AgentID)
	clusterName := str(s.ClusterName)
	indices := buildStringVector(b, s.Indices, fb.StartStartIndexVector)
	groups := buildStringVector(b, s.Groups, fb.StartStartGroupsVector)

	fb.StartStart(b)
	if module != 0 {
		fb.StartAddModule(b, module)
	}
	fb.StartAddMode(b, s.Mode)
	if indices != 0 {
		fb.StartAddIndex(b, indices)
	}
	fb.StartAddOption(b, s.Option)
	addIf := func(add func(*flatbuffers.Builder, flatbuffers.UOffsetT), off flatbuffers.UOffsetT) {
		if off != 0 {
			add(b, off)
		}
	}
	addIf(fb.StartAddArchitecture, arch)
	addIf(fb.StartAddHostname, hostname)
	addIf(fb.StartAddOsname, osname)
	addIf(fb.StartAddOsplatform, osplatform)
	addIf(fb.StartAddOstype, ostype)
	addIf(fb.StartAddOsversion, osversion)
	addIf(fb.StartAddAgentversion, agentversion)
	addIf(fb.StartAddAgentname, agentname)
	addIf(fb.StartAddAgentid, agentid)
	addIf(fb.StartAddGroups, groups)
	if s.GlobalVersion != 0 {
		fb.StartAddGlobalVersion(b, s.GlobalVersion)
	}
	addIf(fb.StartAddClusterName, clusterName)
	if s.FeedOffset != 0 {
		fb.StartAddFeedOffset(b, s.FeedOffset)
	}
	return fb.StartEnd(b)
}

func buildSyncData(b *flatbuffers.Builder, sd *SyncData) flatbuffers.UOffsetT {
	valueOffsets := make([]flatbuffers.UOffsetT, 0, len(sd.Values))
	for i := range sd.Values {
		valueOffsets = append(valueOffsets, buildValue(b, &sd.Values[i]))
	}
	contextOffsets := make([]flatbuffers.UOffsetT, 0, len(sd.Contexts))
	for i := range sd.Contexts {
		contextOffsets = append(contextOffsets, buildContext(b, &sd.Contexts[i]))
	}

	var values, contexts flatbuffers.UOffsetT
	hasValues := sd.Values != nil // distinguish "empty vector" from "no vector" (D8 rejection)
	if hasValues {
		values = buildOffsetVector(b, valueOffsets, fb.SyncDataStartValuesVector)
	}
	if len(contextOffsets) > 0 {
		contexts = buildOffsetVector(b, contextOffsets, fb.SyncDataStartContextsVector)
	}

	fb.SyncDataStart(b)
	if hasValues {
		fb.SyncDataAddValues(b, values)
	}
	if contexts != 0 {
		fb.SyncDataAddContexts(b, contexts)
	}
	return fb.SyncDataEnd(b)
}

func buildValue(b *flatbuffers.Builder, v *Value) flatbuffers.UOffsetT {
	id := b.CreateString(v.ID)
	index := b.CreateString(v.Index)
	data := b.CreateByteVector(v.Data)
	op := fb.OperationUpsert
	if v.Delete {
		op = fb.OperationDelete
	}
	fb.DataValueStart(b)
	fb.DataValueAddOperation(b, op)
	fb.DataValueAddId(b, id)
	fb.DataValueAddIndex(b, index)
	if v.Version != 0 {
		fb.DataValueAddVersion(b, v.Version)
	}
	fb.DataValueAddData(b, data)
	return fb.DataValueEnd(b)
}

func buildContext(b *flatbuffers.Builder, c *Context) flatbuffers.UOffsetT {
	id := b.CreateString(c.ID)
	index := b.CreateString(c.Index)
	data := b.CreateByteVector(c.Data)
	fb.DataContextStart(b)
	fb.DataContextAddId(b, id)
	fb.DataContextAddIndex(b, index)
	fb.DataContextAddData(b, data)
	return fb.DataContextEnd(b)
}

func buildCleans(b *flatbuffers.Builder, indices []string) flatbuffers.UOffsetT {
	itemOffsets := make([]flatbuffers.UOffsetT, 0, len(indices))
	for _, index := range indices {
		idx := b.CreateString(index)
		fb.DataCleanStart(b)
		fb.DataCleanAddIndex(b, idx)
		itemOffsets = append(itemOffsets, fb.DataCleanEnd(b))
	}
	items := buildOffsetVector(b, itemOffsets, fb.CleansStartItemsVector)
	fb.CleansStart(b)
	fb.CleansAddItems(b, items)
	return fb.CleansEnd(b)
}

func buildChecksum(b *flatbuffers.Builder, c *ChecksumModule) flatbuffers.UOffsetT {
	var index, checksum flatbuffers.UOffsetT
	if c.Index != "" {
		index = b.CreateString(c.Index)
	}
	if c.Checksum != "" {
		checksum = b.CreateString(c.Checksum)
	}
	fb.ChecksumModuleStart(b)
	if index != 0 {
		fb.ChecksumModuleAddIndex(b, index)
	}
	if checksum != 0 {
		fb.ChecksumModuleAddChecksum(b, checksum)
	}
	return fb.ChecksumModuleEnd(b)
}

func buildStringVector(b *flatbuffers.Builder, items []string, start func(*flatbuffers.Builder, int) flatbuffers.UOffsetT) flatbuffers.UOffsetT {
	if items == nil {
		return 0
	}
	offsets := make([]flatbuffers.UOffsetT, len(items))
	for i, s := range items {
		offsets[i] = b.CreateString(s)
	}
	return buildOffsetVector(b, offsets, start)
}

func buildOffsetVector(b *flatbuffers.Builder, offsets []flatbuffers.UOffsetT, start func(*flatbuffers.Builder, int) flatbuffers.UOffsetT) flatbuffers.UOffsetT {
	start(b, len(offsets))
	for i := len(offsets) - 1; i >= 0; i-- {
		b.PrependUOffsetT(offsets[i])
	}
	return b.EndVector(len(offsets))
}
