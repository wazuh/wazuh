package source

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/wire"
)

// A captured-session dump parses into metadata + items, keeping each item's raw
// data verbatim and mapping the operation to the delete flag downstream.
func TestLoadDump(t *testing.T) {
	const fixture = `{
	  "metadata": { "module": "syscollector", "mode": "ModuleDelta", "option": "Sync",
	                "indices": ["wazuh-states-inventory-packages", "wazuh-states-inventory-ports"] },
	  "items": [
	    { "seq": 0, "operation": "Upsert", "id": "aaa", "index": "wazuh-states-inventory-packages",
	      "version": 3, "data": { "package": { "name": "vim" } } },
	    { "seq": 1, "operation": "Delete", "id": "bbb", "index": "wazuh-states-inventory-ports",
	      "version": 1, "data": { "port": 22 } }
	  ]
	}`
	dir := t.TempDir()
	path := filepath.Join(dir, "dump.json")
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}

	ds, err := LoadDump(path)
	if err != nil {
		t.Fatalf("LoadDump: %v", err)
	}
	if ds.Module != "syscollector" || ds.Option != "Sync" || len(ds.Indices) != 2 {
		t.Fatalf("metadata wrong: %+v", ds)
	}
	if len(ds.Items) != 2 {
		t.Fatalf("want 2 items, got %d", len(ds.Items))
	}
	if ds.Items[0].ID != "aaa" || ds.Items[0].Index != "wazuh-states-inventory-packages" || ds.Items[0].Version != 3 {
		t.Fatalf("item 0 wrong: %+v", ds.Items[0])
	}
	if ds.Items[0].Operation != "Upsert" || ds.Items[1].Operation != "Delete" {
		t.Fatalf("operations wrong: %q %q", ds.Items[0].Operation, ds.Items[1].Operation)
	}
	// Data is kept as the raw JSON object bytes, not re-encoded.
	if got := string(ds.Items[0].Data); got != `{ "package": { "name": "vim" } }` {
		t.Fatalf("item 0 data not verbatim: %s", got)
	}
}

// A missing dump file is a clean error, not a panic.
func TestLoadDumpMissing(t *testing.T) {
	if _, err := LoadDump(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected an error for a missing dump")
	}
}

// The compressed variant is byte-for-byte the same session after loading: the
// first-connect corpus lives in the repo as .json.zst and nothing downstream
// may be able to tell the difference.
func TestLoadDumpZst(t *testing.T) {
	const fixture = `{
	  "metadata": { "module": "fim", "mode": "ModuleFull", "option": "Sync",
	                "indices": ["wazuh-states-fim-registry-keys"] },
	  "items": [
	    { "seq": 0, "operation": "Upsert", "id": "k1", "index": "wazuh-states-fim-registry-keys",
	      "version": 1, "data": { "registry": { "hive": "HKLM" } } }
	  ]
	}`
	dir := t.TempDir()
	path := filepath.Join(dir, "dump.json.zst")
	if err := os.WriteFile(path, wire.Compress([]byte(fixture)), 0o600); err != nil {
		t.Fatal(err)
	}

	ds, err := LoadDump(path)
	if err != nil {
		t.Fatalf("LoadDump(.zst): %v", err)
	}
	if ds.Module != "fim" || len(ds.Items) != 1 || ds.Items[0].ID != "k1" {
		t.Fatalf("compressed dump did not round-trip: %+v", ds)
	}
	if string(ds.Items[0].Data) != `{ "registry": { "hive": "HKLM" } }` {
		t.Fatalf("item data must stay verbatim, got %s", ds.Items[0].Data)
	}
}

func TestLoadDumpZstRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dump.json.zst")
	if err := os.WriteFile(path, []byte("plain json, wrong extension"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDump(path); err == nil {
		t.Fatal("a .zst that is not a zstd frame must fail loudly, not parse as JSON")
	}
}
