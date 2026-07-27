// Package fbbuild builds and parses the inventory_sync FlatBuffer messages
// the benchmark sender emits and receives. The Python equivalent is
// shared/flatbuffers_manager.py FlatBuffersManager.create_message /
// parse_message.
package fbbuild

import (
	"fmt"

	flatbuffers "github.com/google/flatbuffers/go"
	fb "github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/fb/Wazuh/SyncSchema"
)

// BuildStart wraps a Start table inside a Message union. Field set matches
// the Python builder (module, mode, size, agentid, agentname, agentversion,
// option, index).
func BuildStart(module string, mode fb.Mode, size uint64, option fb.Option,
	agentID, agentName, agentVersion string, indices []string) []byte {

	b := flatbuffers.NewBuilder(256)

	moduleOff := b.CreateString(module)
	agentIDOff := b.CreateString(agentID)
	agentNameOff := b.CreateString(agentName)
	agentVerOff := b.CreateString(agentVersion)

	var indexVecOff flatbuffers.UOffsetT
	if len(indices) > 0 {
		idxOffsets := make([]flatbuffers.UOffsetT, len(indices))
		for i, s := range indices {
			idxOffsets[i] = b.CreateString(s)
		}
		fb.StartStartIndexVector(b, len(idxOffsets))
		for i := len(idxOffsets) - 1; i >= 0; i-- {
			b.PrependUOffsetT(idxOffsets[i])
		}
		indexVecOff = b.EndVector(len(idxOffsets))
	}

	fb.StartStart(b)
	fb.StartAddModule(b, moduleOff)
	fb.StartAddMode(b, mode)
	fb.StartAddSize(b, size)
	fb.StartAddAgentid(b, agentIDOff)
	fb.StartAddAgentname(b, agentNameOff)
	fb.StartAddAgentversion(b, agentVerOff)
	fb.StartAddOption(b, option)
	if indexVecOff != 0 {
		fb.StartAddIndex(b, indexVecOff)
	}
	startOff := fb.StartEnd(b)

	return wrapMessage(b, fb.MessageTypeStart, startOff)
}

// BuildEnd wraps an End in a Message union.
func BuildEnd(session uint64) []byte {
	b := flatbuffers.NewBuilder(64)
	fb.EndStart(b)
	fb.EndAddSession(b, session)
	off := fb.EndEnd(b)
	return wrapMessage(b, fb.MessageTypeEnd, off)
}

// BuildDataValue wraps a single DataValue in a Message union.
func BuildDataValue(session uint64, seq uint64, op fb.Operation,
	docID, index string, data []byte) []byte {

	b := flatbuffers.NewBuilder(256 + len(data))

	idOff := b.CreateString(docID)
	indexOff := b.CreateString(index)
	dataOff := b.CreateByteVector(data)

	fb.DataValueStart(b)
	fb.DataValueAddSeq(b, seq)
	fb.DataValueAddSession(b, session)
	fb.DataValueAddOperation(b, op)
	fb.DataValueAddId(b, idOff)
	fb.DataValueAddIndex(b, indexOff)
	fb.DataValueAddData(b, dataOff)
	off := fb.DataValueEnd(b)

	return wrapMessage(b, fb.MessageTypeDataValue, off)
}

// BatchItem is one item inside a DataBatch.
type BatchItem struct {
	Seq       uint64
	Operation fb.Operation
	DocID     string
	Index     string
	Data      []byte
}

// BuildDataBatch wraps a list of DataValues inside one DataBatch.
func BuildDataBatch(session uint64, items []BatchItem) []byte {
	b := flatbuffers.NewBuilder(1024)

	dvOffsets := make([]flatbuffers.UOffsetT, len(items))
	for i, it := range items {
		idOff := b.CreateString(it.DocID)
		indexOff := b.CreateString(it.Index)
		dataOff := b.CreateByteVector(it.Data)
		fb.DataValueStart(b)
		fb.DataValueAddSeq(b, it.Seq)
		fb.DataValueAddSession(b, session)
		fb.DataValueAddOperation(b, it.Operation)
		fb.DataValueAddId(b, idOff)
		fb.DataValueAddIndex(b, indexOff)
		fb.DataValueAddData(b, dataOff)
		dvOffsets[i] = fb.DataValueEnd(b)
	}

	fb.DataBatchStartValuesVector(b, len(dvOffsets))
	for i := len(dvOffsets) - 1; i >= 0; i-- {
		b.PrependUOffsetT(dvOffsets[i])
	}
	valuesVec := b.EndVector(len(dvOffsets))

	fb.DataBatchStart(b)
	fb.DataBatchAddValues(b, valuesVec)
	off := fb.DataBatchEnd(b)

	return wrapMessage(b, fb.MessageTypeDataBatch, off)
}

// BuildDataClean wraps a DataClean in a Message union.
func BuildDataClean(session uint64, seq uint64, index string) []byte {
	b := flatbuffers.NewBuilder(128)
	indexOff := b.CreateString(index)
	fb.DataCleanStart(b)
	fb.DataCleanAddSeq(b, seq)
	fb.DataCleanAddSession(b, session)
	fb.DataCleanAddIndex(b, indexOff)
	off := fb.DataCleanEnd(b)
	return wrapMessage(b, fb.MessageTypeDataClean, off)
}

// BuildChecksumModule wraps a ChecksumModule in a Message union.
func BuildChecksumModule(session uint64, index, checksum string) []byte {
	b := flatbuffers.NewBuilder(256)
	indexOff := b.CreateString(index)
	checksumOff := b.CreateString(checksum)
	fb.ChecksumModuleStart(b)
	fb.ChecksumModuleAddSession(b, session)
	fb.ChecksumModuleAddIndex(b, indexOff)
	fb.ChecksumModuleAddChecksum(b, checksumOff)
	off := fb.ChecksumModuleEnd(b)
	return wrapMessage(b, fb.MessageTypeChecksumModule, off)
}

// wrapMessage finishes the buffer with a Message{content_type, content}.
func wrapMessage(b *flatbuffers.Builder, ct fb.MessageType, content flatbuffers.UOffsetT) []byte {
	fb.MessageStart(b)
	fb.MessageAddContentType(b, ct)
	fb.MessageAddContent(b, content)
	msg := fb.MessageEnd(b)
	b.Finish(msg)
	return b.FinishedBytes()
}

// ----- Parsing -----

// Inbound is the parsed form of any Message the sender expects to receive.
// Exactly one of the *Set fields is true.
type Inbound struct {
	Type fb.MessageType

	// StartAck / EndAck
	Status  fb.Status
	Session uint64

	// ReqRet
	Ranges []SeqRange
}

// SeqRange is one [Begin, End] inclusive seq range from a ReqRet.
type SeqRange struct {
	Begin uint64
	End   uint64
}

// ParseInbound decodes a Message buffer from the manager. Returns the
// detected MessageType and the relevant fields. Unknown types are returned
// with Type = MessageTypeNONE and no error.
//
// The FlatBuffer library panics on truncated/corrupt input rather than
// returning an error; we recover and translate to a sentinel error so the
// reader goroutine survives garbage from the wire.
func ParseInbound(buf []byte) (out Inbound, err error) {
	if len(buf) < 8 {
		return Inbound{}, fmt.Errorf("inbound: buffer too short (%d)", len(buf))
	}
	defer func() {
		if r := recover(); r != nil {
			out = Inbound{}
			err = fmt.Errorf("inbound: FlatBuffer parse panic: %v", r)
		}
	}()
	msg := fb.GetRootAsMessage(buf, 0)
	if msg == nil {
		return Inbound{}, fmt.Errorf("inbound: parse failed")
	}
	out = Inbound{Type: msg.ContentType()}
	table := new(flatbuffers.Table)
	if !msg.Content(table) {
		return out, nil
	}
	switch out.Type {
	case fb.MessageTypeStartAck:
		x := new(fb.StartAck)
		x.Init(table.Bytes, table.Pos)
		out.Status = x.Status()
		out.Session = x.Session()
	case fb.MessageTypeEndAck:
		x := new(fb.EndAck)
		x.Init(table.Bytes, table.Pos)
		out.Status = x.Status()
		out.Session = x.Session()
	case fb.MessageTypeReqRet:
		x := new(fb.ReqRet)
		x.Init(table.Bytes, table.Pos)
		out.Session = x.Session()
		n := x.SeqLength()
		out.Ranges = make([]SeqRange, 0, n)
		for i := 0; i < n; i++ {
			p := new(fb.Pair)
			if x.Seq(p, i) {
				out.Ranges = append(out.Ranges, SeqRange{Begin: p.Begin(), End: p.End()})
			}
		}
	}
	return out, nil
}
