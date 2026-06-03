package fbbuild

import (
	"testing"

	flatbuffers "github.com/google/flatbuffers/go"
	fb "github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/fb/Wazuh/SyncSchema"
)

func newBuilder() *flatbuffers.Builder { return flatbuffers.NewBuilder(256) }

func TestStartBuildAndParse(t *testing.T) {
	out := BuildStart("syscollector", fb.ModeModuleFull, 42, fb.OptionSync,
		"001", "bench-0001", "4.8.0", []string{"wazuh-states-inventory-packages"})
	if len(out) == 0 {
		t.Fatal("empty buffer")
	}
	msg := fb.GetRootAsMessage(out, 0)
	if msg.ContentType() != fb.MessageTypeStart {
		t.Fatalf("type = %v", msg.ContentType())
	}
}

func TestEndBuildAndParse(t *testing.T) {
	out := BuildEnd(7)
	in, err := ParseInbound(out)
	if err != nil {
		t.Fatalf("ParseInbound: %v", err)
	}
	if in.Type != fb.MessageTypeEnd {
		t.Fatalf("type = %v", in.Type)
	}
}

func TestDataValueBuild(t *testing.T) {
	out := BuildDataValue(7, 0, fb.OperationUpsert, "doc-1", "wazuh-states-fim-files",
		[]byte(`{"file":{"path":"/etc/passwd"}}`))
	msg := fb.GetRootAsMessage(out, 0)
	if msg.ContentType() != fb.MessageTypeDataValue {
		t.Fatalf("type = %v", msg.ContentType())
	}
}

func TestDataBatchBuild(t *testing.T) {
	items := []BatchItem{
		{Seq: 0, DocID: "a", Index: "i", Data: []byte("x")},
		{Seq: 1, DocID: "b", Index: "i", Data: []byte("y")},
	}
	out := BuildDataBatch(99, items)
	msg := fb.GetRootAsMessage(out, 0)
	if msg.ContentType() != fb.MessageTypeDataBatch {
		t.Fatalf("type = %v", msg.ContentType())
	}
}

// Manager-simulated StartAck → confirm we parse status + session correctly.
func TestParseStartAck(t *testing.T) {
	// Build a fake StartAck the way the manager would.
	b := newBuilder()
	fb.StartAckStart(b)
	fb.StartAckAddStatus(b, fb.StatusOk)
	fb.StartAckAddSession(b, 12345)
	off := fb.StartAckEnd(b)
	buf := wrapMessage(b, fb.MessageTypeStartAck, off)

	in, err := ParseInbound(buf)
	if err != nil {
		t.Fatalf("ParseInbound: %v", err)
	}
	if in.Type != fb.MessageTypeStartAck {
		t.Fatalf("type = %v", in.Type)
	}
	if in.Status != fb.StatusOk || in.Session != 12345 {
		t.Fatalf("ack = %+v", in)
	}
}

func TestParseReqRet(t *testing.T) {
	b := newBuilder()
	// Two ranges: [1,3] and [7,9]
	pairOffs := make([]uint32, 0, 2) //nolint:gosimple
	_ = pairOffs
	// Build pairs (struct tables in this schema)
	fb.PairStart(b)
	fb.PairAddBegin(b, 1)
	fb.PairAddEnd(b, 3)
	p1 := fb.PairEnd(b)
	fb.PairStart(b)
	fb.PairAddBegin(b, 7)
	fb.PairAddEnd(b, 9)
	p2 := fb.PairEnd(b)

	fb.ReqRetStartSeqVector(b, 2)
	b.PrependUOffsetT(p2)
	b.PrependUOffsetT(p1)
	vec := b.EndVector(2)

	fb.ReqRetStart(b)
	fb.ReqRetAddSeq(b, vec)
	fb.ReqRetAddSession(b, 55)
	off := fb.ReqRetEnd(b)
	buf := wrapMessage(b, fb.MessageTypeReqRet, off)

	in, err := ParseInbound(buf)
	if err != nil {
		t.Fatalf("ParseInbound: %v", err)
	}
	if in.Type != fb.MessageTypeReqRet {
		t.Fatalf("type = %v", in.Type)
	}
	if in.Session != 55 || len(in.Ranges) != 2 {
		t.Fatalf("got %+v", in)
	}
	if in.Ranges[0].Begin != 1 || in.Ranges[0].End != 3 {
		t.Fatalf("range[0] = %+v", in.Ranges[0])
	}
	if in.Ranges[1].Begin != 7 || in.Ranges[1].End != 9 {
		t.Fatalf("range[1] = %+v", in.Ranges[1])
	}
}
