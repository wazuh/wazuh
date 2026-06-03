// Package inventory implements the inventory_sync Source: load a dump or
// build a synthetic kind, drive Start → DataValue*/DataBatch → End and
// await StartAck/EndAck. See docu/04-agent-state-machine.md and
// docu/06-flatbuffers-messages.md.
//
// Scope of THIS implementation: the `delta` session_type, the most common
// case (used by 18 of 21 committed scenarios). The `modulecheck` and
// `dataclean` variants share the same Start/End wrapping; their payload
// bodies are stubbed and clearly TODOed for a follow-up.
package inventory

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/wazuh/wazuh-modules/inventory_sync/benchmark/internal/scenario"
)

// Item is one DataValue's worth of input.
type Item struct {
	Seq       uint64
	Operation scenario.Operation
	ID        string
	Index     string
	Data      []byte // JSON-marshalled bytes
}

// PayloadInfo holds the resolved payload metadata + items for one session.
type PayloadInfo struct {
	Kind     string // "static" | "dump"
	Module   string
	Mode     scenario.Mode
	Option   scenario.Option
	Indices  []string
	DataSize int
	Items    []Item // populated for dumps; for static the items are generated at send time
	Template []byte // raw JSON template bytes for static kinds
}

// LoadForStep returns PayloadInfo for the given step. benchDir is used
// to resolve sample_payloads/ relative paths for kind templates.
func LoadForStep(step scenario.Step, benchDir string) (*PayloadInfo, error) {
	switch step.Kind {
	case scenario.SourceKindDump:
		return loadDump(step.PayloadDumpPath)
	case scenario.SourceKindStatic:
		return loadStatic(step, benchDir)
	}
	return nil, fmt.Errorf("inventory: unsupported source kind %v", step.Kind)
}

func loadStatic(step scenario.Step, benchDir string) (*PayloadInfo, error) {
	meta := scenario.PayloadKinds[step.PayloadKind]
	if meta.File == "" {
		return nil, fmt.Errorf("inventory: unknown kind %q", step.PayloadKind)
	}
	samplePath := filepath.Join(benchDir, "sample_payloads", meta.File)
	raw, err := os.ReadFile(samplePath)
	if err != nil {
		return nil, fmt.Errorf("inventory: open %s: %w", samplePath, err)
	}
	// Re-marshal to ensure compact JSON (matches Python's compact separators).
	var tmpl any
	if err := json.Unmarshal(raw, &tmpl); err != nil {
		return nil, fmt.Errorf("inventory: parse template %s: %w", samplePath, err)
	}
	compact, _ := json.Marshal(tmpl)
	return &PayloadInfo{
		Kind:     "static",
		Module:   step.Module,
		Mode:     step.SyncMode,
		Option:   step.StartOption,
		Indices:  []string{step.Index},
		DataSize: step.DataSize,
		Template: compact,
	}, nil
}

func loadDump(path string) (*PayloadInfo, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("inventory: open dump %s: %w", path, err)
	}
	var d struct {
		Metadata struct {
			Module  string   `json:"module"`
			Mode    string   `json:"mode"`
			Option  string   `json:"option"`
			Indices []string `json:"indices"`
			Index   []string `json:"index"`
		} `json:"metadata"`
		Items []struct {
			Seq       uint64          `json:"seq"`
			Operation string          `json:"operation"`
			ID        string          `json:"id"`
			Index     string          `json:"index"`
			Data      json.RawMessage `json:"data"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("inventory: parse dump %s: %w", path, err)
	}
	if d.Metadata.Module == "" {
		return nil, fmt.Errorf("inventory: dump %s: metadata.module required", path)
	}
	if len(d.Items) == 0 {
		return nil, fmt.Errorf("inventory: dump %s: items must be non-empty", path)
	}
	mode, ok := scenario.ModeFromString(emptyTo(d.Metadata.Mode, "ModuleDelta"))
	if !ok {
		return nil, fmt.Errorf("inventory: dump %s: unknown mode %q", path, d.Metadata.Mode)
	}
	opt, ok := scenario.OptionFromString(emptyTo(d.Metadata.Option, "Sync"))
	if !ok {
		return nil, fmt.Errorf("inventory: dump %s: unknown option %q", path, d.Metadata.Option)
	}
	indices := d.Metadata.Indices
	if len(indices) == 0 {
		indices = d.Metadata.Index
	}

	items := make([]Item, len(d.Items))
	for i, raw := range d.Items {
		op := scenario.OperationUpsert
		if raw.Operation != "" {
			v, ok := scenario.OperationFromString(raw.Operation)
			if !ok {
				return nil, fmt.Errorf("inventory: dump %s: items[%d].operation=%q invalid",
					path, i, raw.Operation)
			}
			op = v
		}
		if raw.Index == "" {
			return nil, fmt.Errorf("inventory: dump %s: items[%d].index required", path, i)
		}
		id := raw.ID
		if id == "" {
			id = fmt.Sprintf("%d", i)
		}
		data := []byte(raw.Data)
		if len(data) == 0 {
			data = []byte("{}")
		}
		items[i] = Item{
			Seq:       raw.Seq,
			Operation: op,
			ID:        id,
			Index:     raw.Index,
			Data:      data,
		}
	}
	return &PayloadInfo{
		Kind:     "dump",
		Module:   d.Metadata.Module,
		Mode:     mode,
		Option:   opt,
		Indices:  indices,
		DataSize: len(items),
		Items:    items,
	}, nil
}

func emptyTo(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
