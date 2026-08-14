// Package source generates the payloads a scenario ships: state documents for
// sessions and log lines for engine streams. Generation is DETERMINISTIC from a
// seed, so two runs of one scenario send byte-identical payloads (docu/07,
// docu/11).
package source

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// DocSpec controls document generation for one delta step.
type DocSpec struct {
	Count     int
	SizeBytes int // approximate serialized size of one document
	Index     string
}

// GeneratedDoc is one document plus its stable id and checksum.
type GeneratedDoc struct {
	ID       string
	Data     []byte
	Checksum string // sha1 of (seed, id); always set -- see Documents
}

// Documents builds Count documents for one agent/lane deterministically. The
// key namespaces the ids so two lanes or two agents never collide, and the seed
// makes the whole run reproducible. Each document is padded to about SizeBytes
// with a realistic shape rather than one giant string, since document count and
// document size stress different parts of the pipeline.
//
// EVERY document carries checksum.hash.sha1, unconditionally: a real agent has
// no mode that omits it. syscollector writes /checksum/hash/sha1 into every item
// it emits (syscollectorImp.cpp), SCA computes one per check
// (sca_event_handler.cpp), FIM keeps it as a column of its own, and all 32,000
// documents of the captured corpus in sample_payloads/dumps/ have it. It is also
// what the ModuleCheck aggregate is computed over, so a document without one is
// a document the integrity path could never reconcile.
func Documents(seed uint64, key string, spec DocSpec) []GeneratedDoc {
	docs := make([]GeneratedDoc, 0, spec.Count)
	for i := 0; i < spec.Count; i++ {
		id := fmt.Sprintf("%s-%d", key, i)
		checksum := sha1Hex(fmt.Sprintf("%d:%s", seed, id))

		field, value := domainObject(spec.Index, seed, key, i, spec.SizeBytes)
		doc := map[string]any{
			field:      value,
			"checksum": map[string]any{"hash": map[string]any{"sha1": checksum}},
		}
		data, _ := json.Marshal(doc)

		docs = append(docs, GeneratedDoc{ID: id, Data: data, Checksum: checksum})
	}
	return docs
}

// domainObject returns the one index-specific field every state document
// carries besides checksum, shaped to match that index's mapping. Every
// field here MUST exist in the target index's mapping: the real state
// indices are `dynamic: strict`, so an invented field (a "pad" of our own,
// say) makes the indexer reject the whole bulk with 400 and the session
// answer 500. The size filler therefore rides in a real keyword field
// (`description` or `path`), not a synthetic one.
//
// The object's own key changes per index -- `file` for FIM, `check` for SCA,
// `package` for inventory/VD -- so this switches on spec.Index rather than
// hardcoding one shape for every lane.
func domainObject(index string, seed uint64, key string, i int, sizeBytes int) (string, map[string]any) {
	switch index {
	case "wazuh-states-fim-files":
		return "file", map[string]any{
			"path":  fmt.Sprintf("/opt/%s-%d/%s", key, i, padTo(sizeBytes)),
			"owner": "root",
			"group": "root",
			"size":  int64(i),
			"hash":  map[string]any{"sha1": sha1Hex(fmt.Sprintf("%d:%s:content", seed, key))},
		}
	case "wazuh-states-sca":
		return "check", map[string]any{
			"id":          fmt.Sprintf("check-%s-%d", key, i),
			"name":        fmt.Sprintf("sca-check-%d", i),
			"result":      "passed",
			"description": padTo(sizeBytes),
		}
	default: // wazuh-states-inventory-packages, and any lane sharing it (VD)
		return "package", map[string]any{
			"name":        fmt.Sprintf("pkg-%s-%d", key, i),
			"version":     fmt.Sprintf("%d.%d.%d", seed%10, i%100, i%7),
			"description": padTo(sizeBytes),
		}
	}
}

// AggregateChecksum reproduces the server's ModuleCheck aggregate for a set of
// documents: the SHA-1 of the concatenation of the per-document checksums in
// ascending order (sessionProcessor.cpp calculateChecksumOfChecksums). A
// scenario asking for a "correct" checksum uses this over the docs it sent.
func AggregateChecksum(checksums []string) string {
	sorted := append([]string(nil), checksums...)
	// insertion sort keeps the dependency surface tiny; sets here are small.
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	return sha1Hex(strings.Join(sorted, ""))
}

func sha1Hex(s string) string {
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// padTo returns a filler string of about n bytes; empty when n is not positive.
func padTo(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat("x", n)
}
