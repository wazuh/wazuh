package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

// decodeOrdered parses one JSON object and returns its member names in wire
// order, so a test can pin positions a map would lose.
func decodeOrdered(t *testing.T, raw string) []string {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("not an object: %q (%v)", raw, err)
	}
	var names []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("bad member name in %q: %v", raw, err)
		}
		names = append(names, tok.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatalf("bad member value in %q: %v", raw, err)
		}
	}
	return names
}

func agentObject(t *testing.T, header string) string {
	t.Helper()
	var doc struct {
		Wazuh struct {
			Agent json.RawMessage `json:"agent"`
		} `json:"wazuh"`
	}
	if err := json.Unmarshal([]byte(header), &doc); err != nil {
		t.Fatalf("header is not valid JSON: %q (%v)", header, err)
	}
	return string(doc.Wazuh.Agent)
}

// Every shipped scenario relies on the minimal header staying byte for byte
// what an agent sends.
func TestBatchUnchangedWithoutHeaderSpec(t *testing.T) {
	got := string(Batch("001", "1", "syslog", []string{"line one", "line two"}))
	want := "H {\"wazuh\":{\"agent\":{\"id\":\"001\"}}}\nE 1:syslog:line one\nE 1:syslog:line two\n"
	if got != want {
		t.Fatalf("Batch changed:\n got %q\nwant %q", got, want)
	}
	if HeaderLine("001", nil, 0) != `{"wazuh":{"agent":{"id":"001"}}}` {
		t.Fatalf("nil spec must give the minimal header, got %q", HeaderLine("001", nil, 0))
	}
}

func TestHeaderLinePadsToExactSize(t *testing.T) {
	for _, size := range []int{256, 2048, MaxStatelessHeaderBytes} {
		for _, id := range []string{"001", "4294967295"} {
			got := HeaderLine(id, &HeaderSpec{PadBytes: size, ExtraFields: 2, OffPathFields: 1}, 0)
			if len(got) != size {
				t.Errorf("pad_bytes %d, id %s: header is %d bytes", size, id, len(got))
			}
			if !json.Valid([]byte(got)) {
				t.Errorf("pad_bytes %d: header is not valid JSON", size)
			}
		}
	}
	// Below the unpadded size the header is sent unpadded; the loader refuses
	// such a spec before a run starts.
	spec := &HeaderSpec{PadBytes: 10}
	if got := HeaderLine("001", spec, 0); got != buildHeader("001", spec, 0, -1) {
		t.Fatalf("an unreachable pad_bytes must leave the header unpadded, got %q", got)
	}
	if MinHeaderBytes(&HeaderSpec{PadBytes: 1}) != len(buildHeader("4294967295", &HeaderSpec{PadBytes: 1}, 0, 0)) {
		t.Fatal("MinHeaderBytes must be the widest id's header with an empty filler")
	}
}

func TestHeaderLineIdPositionAndFields(t *testing.T) {
	spec := &HeaderSpec{ExtraFields: 3, OffPathFields: 2, IDPosition: "last"}
	got := HeaderLine("042", spec, 0)

	agent := decodeOrdered(t, agentObject(t, got))
	if len(agent) != 4 || agent[len(agent)-1] != "id" {
		t.Fatalf("wazuh.agent members = %v, want 3 extra fields then id", agent)
	}
	root := decodeOrdered(t, got)
	if len(root) != 2 || root[0] != "wazuh" || root[1] != "bench" {
		t.Fatalf("root members = %v, want [wazuh bench]", root)
	}
	if strings.Count(got, `"id"`) != 1 || strings.Count(got, `"wazuh"`) != 1 || strings.Count(got, `"agent"`) != 1 {
		t.Fatalf("the identity path must appear exactly once: %q", got)
	}
	var doc struct {
		Bench map[string]string `json:"bench"`
	}
	_ = json.Unmarshal([]byte(got), &doc)
	if len(doc.Bench) != 2 {
		t.Fatalf("off-path fields = %d, want 2", len(doc.Bench))
	}

	first := decodeOrdered(t, agentObject(t, HeaderLine("042", &HeaderSpec{ExtraFields: 1}, 0)))
	if first[0] != "id" {
		t.Fatalf("id_position defaults to first, got members %v", first)
	}
}

func TestHeaderLineChangesEveryN(t *testing.T) {
	spec := &HeaderSpec{ChangeEvery: 2, PadBytes: 512}
	// The caller turns its batch counter into seq: batches 0,1 -> 0; 2,3 -> 1.
	h := []string{HeaderLine("001", spec, 0/2), HeaderLine("001", spec, 1/2),
		HeaderLine("001", spec, 2/2), HeaderLine("001", spec, 3/2)}
	if h[0] != h[1] || h[2] != h[3] || h[0] == h[2] {
		t.Fatalf("headers must change once every 2 batches: %q", h)
	}
	for _, line := range h {
		if len(line) != 512 {
			t.Fatalf("a changing header must keep its padded size, got %d", len(line))
		}
	}
	if HeaderLine("001", &HeaderSpec{}, 7) != HeaderLine("001", &HeaderSpec{}, 0) {
		t.Fatal("change_every 0 must never change the header")
	}
}
