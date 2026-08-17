package source

import (
	"encoding/json"
	"testing"
)

// Every generated document carries checksum.hash.sha1, with no way to ask for
// one without it: a real agent has no such mode (syscollector writes
// /checksum/hash/sha1 into every item, SCA computes one per check, FIM keeps it
// as a column), and it is what the ModuleCheck aggregate is computed over. This
// test is the guard for that being unconditional rather than a scenario knob.
func TestDocumentsAlwaysCarryAChecksum(t *testing.T) {
	docs := Documents(4242, "agent-1-fim", DocSpec{Count: 5, SizeBytes: 128, Index: "wazuh-states-fim-files"})
	if len(docs) != 5 {
		t.Fatalf("got %d documents, want 5", len(docs))
	}
	for _, d := range docs {
		if d.Checksum == "" {
			t.Errorf("document %s has no Checksum: the ModuleCheck aggregate would be built over nothing", d.ID)
		}
		var payload struct {
			Checksum struct {
				Hash struct {
					SHA1 string `json:"sha1"`
				} `json:"hash"`
			} `json:"checksum"`
		}
		if err := json.Unmarshal(d.Data, &payload); err != nil {
			t.Fatalf("document %s is not valid JSON: %v", d.ID, err)
		}
		if payload.Checksum.Hash.SHA1 != d.Checksum {
			t.Errorf("document %s: wire checksum.hash.sha1 = %q, GeneratedDoc.Checksum = %q — the server "+
				"reconciles over the wire value, so they must be the same string",
				d.ID, payload.Checksum.Hash.SHA1, d.Checksum)
		}
	}
}

// The whole point of the seed: two runs of one scenario send byte-identical
// payloads, checksums included, or a before/after comparison is not one.
func TestDocumentsAreDeterministic(t *testing.T) {
	spec := DocSpec{Count: 3, SizeBytes: 64, Index: "wazuh-states-inventory-packages"}
	first := Documents(7, "agent-2-syscollector", spec)
	second := Documents(7, "agent-2-syscollector", spec)
	for i := range first {
		if first[i].ID != second[i].ID || first[i].Checksum != second[i].Checksum ||
			string(first[i].Data) != string(second[i].Data) {
			t.Fatalf("document %d differs between two runs of the same seed/key/spec", i)
		}
	}
	// A different seed must move the checksums, or the aggregate would collide
	// across runs that are supposed to be distinguishable.
	if other := Documents(8, "agent-2-syscollector", spec); other[0].Checksum == first[0].Checksum {
		t.Error("the checksum must depend on the seed")
	}
}

// AggregateChecksum is the server's checksum-of-checksums (sessionProcessor.cpp):
// SHA-1 over the per-document checksums in ascending order. Order-independence is
// the property a "correct" checksum step relies on.
func TestAggregateChecksumIsOrderIndependent(t *testing.T) {
	docs := Documents(99, "agent-3-sca", DocSpec{Count: 4, Index: "wazuh-states-sca"})
	ascending := []string{docs[0].Checksum, docs[1].Checksum, docs[2].Checksum, docs[3].Checksum}
	shuffled := []string{docs[2].Checksum, docs[0].Checksum, docs[3].Checksum, docs[1].Checksum}
	if AggregateChecksum(ascending) != AggregateChecksum(shuffled) {
		t.Error("the aggregate must not depend on the order the checksums are passed in")
	}
	if AggregateChecksum(nil) == AggregateChecksum(ascending) {
		t.Error("an empty set must not aggregate to the same value as a non-empty one")
	}
}
