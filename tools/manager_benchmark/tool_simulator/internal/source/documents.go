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
	Count        int
	SizeBytes    int  // approximate serialized size of one document
	WithChecksum bool // include checksum.hash.sha1 (needed for ModuleCheck)
	Index        string
}

// GeneratedDoc is one document plus its stable id and checksum (when asked).
type GeneratedDoc struct {
	ID       string
	Data     []byte
	Checksum string // sha1 of the deterministic id when WithChecksum, else ""
}

// Documents builds Count documents for one agent/lane deterministically. The
// key namespaces the ids so two lanes or two agents never collide, and the seed
// makes the whole run reproducible. Each document is padded to about SizeBytes
// with a realistic shape rather than one giant string, since document count and
// document size stress different parts of the pipeline.
func Documents(seed uint64, key string, spec DocSpec) []GeneratedDoc {
	docs := make([]GeneratedDoc, 0, spec.Count)
	for i := 0; i < spec.Count; i++ {
		id := fmt.Sprintf("%s-%d", key, i)
		checksum := sha1Hex(fmt.Sprintf("%d:%s", seed, id))

		// Every field here MUST exist in the target index's mapping: the real
		// state indices are `dynamic: strict`, so an invented field (a "pad" of
		// our own, say) makes the indexer reject the whole bulk with 400 and the
		// session answer 500. The size filler therefore rides in `description`,
		// a real keyword field, instead of a synthetic one.
		doc := map[string]any{
			"package": map[string]any{
				"name":        fmt.Sprintf("pkg-%s-%d", key, i),
				"version":     fmt.Sprintf("%d.%d.%d", seed%10, i%100, i%7),
				"description": padTo(spec.SizeBytes),
			},
		}
		if spec.WithChecksum {
			doc["checksum"] = map[string]any{"hash": map[string]any{"sha1": checksum}}
		}
		data, _ := json.Marshal(doc)

		g := GeneratedDoc{ID: id, Data: data}
		if spec.WithChecksum {
			g.Checksum = checksum
		}
		docs = append(docs, g)
	}
	return docs
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
