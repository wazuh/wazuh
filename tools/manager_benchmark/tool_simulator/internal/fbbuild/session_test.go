package fbbuild

import (
	"testing"

	fb "github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/fb/Wazuh/SyncSchema"

	flatbuffers "github.com/google/flatbuffers/go"
)

// A round-trip test: build a session, parse it back with the generated
// bindings, and assert the mode/option/identity/payload survive. Needs no
// manager, so a schema or builder regression is caught at `go test`.
func TestBuildSessionRoundTrip(t *testing.T) {
	start := Start{
		Module:      "syscollector",
		Mode:        ModeModuleDelta,
		Option:      OptionVDSync,
		Indices:     []string{"wazuh-states-inventory-packages"},
		AgentID:     "001",
		AgentName:   "bench-1",
		ClusterName: "cluster01",
		Groups:      []string{"default"},
		FeedOffset:  987654321,
	}
	payload := Payload{Sync: &SyncData{
		Values: []Value{
			{ID: "doc-1", Index: "wazuh-states-inventory-packages", Data: []byte(`{"package":{"name":"zlib"}}`)},
			{Delete: true, ID: "doc-2", Index: "wazuh-states-inventory-packages"},
		},
		Contexts: []Context{
			{ID: "ctx-1", Index: "wazuh-states-inventory-system", Data: []byte(`{"host":{"hostname":"h"}}`)},
		},
	}}

	buf := BuildSession(start, payload)

	msg := fb.GetRootAsMessage(buf, 0)
	if msg.ContentType() != fb.MessageTypeFullSession {
		t.Fatalf("content type = %d, want FullSession", msg.ContentType())
	}

	var contentTab flatbuffers.Table
	if !msg.Content(&contentTab) {
		t.Fatal("Content() did not populate the union table")
	}
	session := new(fb.FullSession)
	session.Init(contentTab.Bytes, contentTab.Pos)

	startTbl := session.Start(nil)
	if startTbl == nil {
		t.Fatal("FullSession has no Start")
	}
	if got := string(startTbl.Agentid()); got != "001" {
		t.Fatalf("agentid = %q, want 001", got)
	}
	if startTbl.Mode() != fb.ModeModuleDelta {
		t.Fatalf("mode = %d, want ModuleDelta", startTbl.Mode())
	}
	if startTbl.Option() != fb.OptionVDSync {
		t.Fatalf("option = %d, want VDSync", startTbl.Option())
	}
	if startTbl.FeedOffset() != 987654321 {
		t.Fatalf("feed_offset = %d, want 987654321", startTbl.FeedOffset())
	}
	if got := string(startTbl.ClusterName()); got != "cluster01" {
		t.Fatalf("cluster_name = %q, want cluster01: an empty one is answered 400", got)
	}
	// cluster_node is a field of the schema the sender must NOT set: the manager
	// never validated it and is dropping its last consumer, so leaving it unset is
	// what makes the manager use its own configured node name (docu/05).
	if got := startTbl.ClusterNode(); got != nil {
		t.Errorf("cluster_node = %q, want absent from the buffer", string(got))
	}

	if session.PayloadType() != fb.SessionPayloadSyncData {
		t.Fatalf("payload type = %d, want SyncData", session.PayloadType())
	}
	var payloadTab flatbuffers.Table
	if !session.Payload(&payloadTab) {
		t.Fatal("Payload() did not populate")
	}
	sync := new(fb.SyncData)
	sync.Init(payloadTab.Bytes, payloadTab.Pos)

	if sync.ValuesLength() != 2 {
		t.Fatalf("values length = %d, want 2", sync.ValuesLength())
	}
	if sync.ContextsLength() != 1 {
		t.Fatalf("contexts length = %d, want 1", sync.ContextsLength())
	}

	var v0, v1 fb.DataValue
	if !sync.Values(&v0, 0) || string(v0.Id()) != "doc-1" || v0.Operation() != fb.OperationUpsert {
		t.Fatalf("value 0 = %q/%d", v0.Id(), v0.Operation())
	}
	if !sync.Values(&v1, 1) || v1.Operation() != fb.OperationDelete {
		t.Fatalf("value 1 operation = %d, want Delete", v1.Operation())
	}
}
