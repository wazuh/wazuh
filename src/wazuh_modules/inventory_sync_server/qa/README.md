# inventory_sync_server — integration QA

End-to-end tests of the real server over its real Unix socket, asserting final
state in a real OpenSearch. No agent emulation and no protocol acks: a session
is ONE `POST /stateful` whose HTTP response IS the result, so the suite builds
FlatBuffers `Message{FullSession}` buffers in Python and reads documents back
from the indexer.

## How it runs

- `conftest.py` regenerates the Python FlatBuffers bindings from the shared
  `inventorySync.fbs` (into `.generated/`, never committed) with `flatc`.
- The server under test is the real module pair booted by
  `inventory_sync_server_testtool --serve --no-vd --config config.json` in a
  temp directory; the suite talks to `queue/sockets/inventory-sync.sock` there.
  `--no-vd` keeps the vulnerability scanner facade down, which makes VD-flagged
  sessions take the scan lane and resolve as D22's *legitimate skip* (index +
  200) — deterministic, no CVE feed required. The scan-gating rows (failed
  scan → 500) are unit-suite territory; the real-scanner path belongs to the
  vulnerability-detection integration workflow.
- OpenSearch: an already-running one at `INDEXER_URL` (default
  `http://127.0.0.1:9200`) is used as-is; otherwise a single-node container
  (`opensearch-test`, security disabled) is started via docker. A minimal
  index template is installed so the fields the server's own queries sort and
  filter on (`checksum.hash.sha1`, `wazuh.agent.id`, ...) are `keyword`.
  Note that the container runs with the security plugin DISABLED, so nothing
  here exercises indexer permissions — a role whose write/delete privileges do
  not cover the `wazuh-agent-config` / `wazuh-agent-stats` patterns would pass
  this suite and fail in production.
- `config.json` sets `flush_interval_seconds: 1` on purpose. It reaches the
  ASYNCHRONOUS connector (the one `POST /config` and `POST /stats` write
  through), whose default 20 s timer would otherwise make every test that reads
  those two indices wait for it.

## Running locally

```bash
# once: build the harness
cmake --build src/build --target inventory_sync_server_testtool -j

cd src/wazuh_modules/inventory_sync_server/qa
pip install -r requirements.txt
python -m pytest
```

Environment overrides: `INVSYNC_TESTTOOL` (harness binary), `FLATC`,
`INDEXER_URL`.

## What is covered

| File | Contract |
|---|---|
| `test_transport_and_validation.py` | Strand-side 400s (missing/invalid identity header, junk body, non-FullSession message, empty values D8, checksum shape) + the `mode`×`payload` matrix + identity/cluster 403 + agent-id padding |
| `test_ingestion.py` | ModuleDelta×SyncData: `_id` shape, the authoritative `wazuh.*` overlay (anti-impersonation), deletes, multi-index sessions, per-document skips (forbidden index, empty id, malformed JSON, vulnerabilities write-protection), no-op 200, idempotent re-POST, contexts not indexed |
| `test_cleans_and_resync.py` | Cleans single/multi-index (agent-scoped, deduplicated), forbidden-index noop, and the composed full resync (D19: Cleans + ModuleDelta) |
| `test_checksum.py` | **ModuleCheck for real** (the legacy suite's hole): match, mismatch→409, agent scoping, `search_after` pagination past 1000 documents, empty-set aggregate |
| `test_metadata_groups.py` | MetadataDelta/GroupDelta across declared indices, the `global_version` stale-writer guard, MetadataCheck repair-if-needed, forbidden-indices noop |
| `test_delete_agent.py` | `DELETE /agents` + POST alias: agent-scoped wipe across the whole deletion scope (`wazuh-states-*` **plus** `wazuh-agent-config` and `wazuh-agent-stats`), 404-as-success retries, 400s, FIFO vs the agent's own sessions. The tests refresh the indices before deleting, because the server does not. Carries two **skipped** tests recording the two known limitations: a document written inside the index refresh interval, and a `/config` or `/stats` report still queued in the asynchronous connector when the deletion runs, both survive it |
| `test_vd_lane.py` | VD-flagged sessions under `--no-vd`: the legitimate-skip row indexes + 200, VD Cleans take the normal pipeline, and `GET /metrics` reflects the lane traffic |

Deliberately NOT here: capacity/budget rejections (413/503) and scan-failure
gating need injected limits/scanners — both are pinned by the unit suite; and
the feed-download 503 + Retry-After path runs in the VD integration workflow.
