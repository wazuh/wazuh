package source

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/wire"
)

// DumpItem is one recorded document from a captured session: a real payload
// shape, kept verbatim in Data. Operation is "Upsert" or "Delete".
type DumpItem struct {
	ID        string
	Index     string
	Operation string
	Version   uint64
	Data      []byte // the raw JSON of the item's "data" object
}

// DumpSession is a captured session: its module metadata plus its items. It is
// what a scenario step replays when it names a `dump` instead of generating
// documents — real payloads, so the wire bytes match production shapes.
type DumpSession struct {
	Module  string
	Mode    string
	Option  string
	Indices []string
	Items   []DumpItem
}

// wire shape of a dump file (the benchmark's captured-session format).
type dumpFile struct {
	Metadata struct {
		Module  string   `json:"module"`
		Mode    string   `json:"mode"`
		Option  string   `json:"option"`
		Indices []string `json:"indices"`
	} `json:"metadata"`
	Items []struct {
		Operation string          `json:"operation"`
		ID        string          `json:"id"`
		Index     string          `json:"index"`
		Version   uint64          `json:"version"`
		Data      json.RawMessage `json:"data"`
	} `json:"items"`
}

// LoadDump reads a captured-session dump and returns its metadata and items.
// A `.zst` path is decompressed transparently: the full-fidelity first-connect
// corpus (27k+ Windows registry documents, ~27 MB of JSON) lives in the repo
// zstd-compressed, and everything downstream of this function never knows.
func LoadDump(path string) (*DumpSession, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(path, ".zst") {
		if raw, err = wire.Decompress(raw); err != nil {
			return nil, fmt.Errorf("dump %s: %w", path, err)
		}
	}
	var df dumpFile
	if err := json.Unmarshal(raw, &df); err != nil {
		return nil, fmt.Errorf("dump %s: %w", path, err)
	}
	ds := &DumpSession{
		Module:  df.Metadata.Module,
		Mode:    df.Metadata.Mode,
		Option:  df.Metadata.Option,
		Indices: df.Metadata.Indices,
		Items:   make([]DumpItem, 0, len(df.Items)),
	}
	for _, it := range df.Items {
		ds.Items = append(ds.Items, DumpItem{
			ID:        it.ID,
			Index:     it.Index,
			Operation: it.Operation,
			Version:   it.Version,
			Data:      append([]byte(nil), it.Data...),
		})
	}
	return ds, nil
}
