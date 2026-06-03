package fbbuild

import (
	"testing"

	flatbuffers "github.com/google/flatbuffers/go"
	fb "github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/fb/Wazuh/SyncSchema"
)

func TestStartSizeIsEncodedCorrectly(t *testing.T) {
	cases := []uint64{0, 1, 17, 100, 1000, 731, 1447}
	for _, want := range cases {
		buf := BuildStart("syscollector_vd", fb.ModeModuleDelta, want, fb.OptionVDFirst,
			"001", "bench", "4.8.0",
			[]string{"wazuh-states-inventory-packages"})
		msg := fb.GetRootAsMessage(buf, 0)
		if msg.ContentType() != fb.MessageTypeStart {
			t.Fatalf("size=%d: wrong content type %v", want, msg.ContentType())
		}
		tbl := new(flatbuffers.Table)
		if !msg.Content(tbl) {
			t.Fatalf("size=%d: no content", want)
		}
		s := new(fb.Start)
		s.Init(tbl.Bytes, tbl.Pos)
		got := s.Size()
		if got != want {
			t.Errorf("size: got %d, want %d", got, want)
		}
		if string(s.Module()) != "syscollector_vd" {
			t.Errorf("module: got %q", s.Module())
		}
		if s.Mode() != fb.ModeModuleDelta {
			t.Errorf("mode: got %v", s.Mode())
		}
		if s.Option() != fb.OptionVDFirst {
			t.Errorf("option: got %v", s.Option())
		}
	}
}
