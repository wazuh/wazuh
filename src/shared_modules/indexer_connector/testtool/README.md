# Indexer Connector Test Tool

A command-line tool for manually testing all features of the `IndexerConnector` module:
pushing events (sync and async), exporting policy documents, and generating full policy assets
from a running wazuh-indexer instance.

---

## Building

The tool is built with the `indexer_connector` module in the main build tree (it is not installed
with the manager):

```bash
cmake --build src/build --target indexer_connector_tool
# Binary: src/build/bin/indexer_connector_tool
# input/ is copied to src/build/shared_modules/indexer_connector/testtool/input/
```

---

## Subcommands

| Subcommand | Description |
|---|---|
| `push-events` | Push documents to an index (default if no subcommand given) |
| `export-policy` | Dump all raw policy documents for a space from `wazuh-threatintel-policies` |
| `generate-full-policy` | Build a structured full-policy asset (kvdbs, decoders, filters, integrations, policy) across all 5 policy aliases using a consistent PIT snapshot |

---

## Configuration file

Every subcommand requires a **config JSON** passed with `-c`. Fields:

| Field | Required | Description |
|---|---|---|
| `hosts` | ✅ | Array of indexer URLs, e.g. `["https://127.0.0.1:9200"]` |
| `username` | ✅ | Indexer username — seeded into the keystore at startup |
| `password` | ✅ | Indexer password — seeded into the keystore at startup |
| `ssl.certificate_authorities` | For HTTPS | Array with path(s) to the CA root cert |
| `ssl.certificate` | Optional | Path to client TLS certificate (mutual TLS) |
| `ssl.key` | Optional | Path to client TLS private key (mutual TLS) |
| `index` | Optional | Target index for `push-events` (default: `wazuh-test`) |
| `max_bulk_size` | Optional | Sync mode — staged bytes that trigger a flush (default: 10 MB) |
| `max_queue_bytes` | Optional | Async mode — max pending bytes before dropping (default/0 = unlimited) |
| `bulk_max_bytes` | Optional | Async mode — target byte threshold for each bulk request (default: 4 MB) |
| `flush_interval_seconds` | Optional | Flush interval in seconds (default: 20; `0` in sync mode = no background flush) |
| `max_retry_delay_seconds` | Optional | Cap (seconds) for exponential-backoff retries (default: 15) |
| `request_timeout_seconds` | Optional | Per-request timeout (default: 60; 0 = none) |
| `monitoring_interval_seconds` | Optional | Health-check period (default: 10) |

Any other field (`name`, `enabled` in the examples below) is ignored.

### Example: dev e2e environment (HTTPS + TLS)

`input/config.json`:
```json
{
  "name": "wazuh-states-vulnerabilities-cluster",
  "enabled": "yes",
  "hosts": ["https://172.19.0.2:9200"],
  "username": "admin",
  "password": "admin",
  "ssl": {
    "certificate_authorities": [
      "/workspaces/devContainer/wazuh/tools/devContainer/e2e/certs/root-ca.pem"
    ]
  }
}
```

The shipped file is a template: point `hosts` at the indexer (`https://127.0.0.1:9200` for the e2e
stack below), and use a real password (see [Credentials](#credentials) for the e2e stack).

### Example: plain HTTP (local OpenSearch with the security plugin disabled)

```json
{
  "name": "local-opensearch",
  "hosts": ["http://localhost:9200"],
  "username": "admin",
  "password": "admin"
}
```

---

## Credentials & Keystore

The connector reads credentials from a **RocksDB keystore** (`queue/keystore/` relative to the current
working directory). The tool writes `username`/`password` from the config JSON into that keystore
before constructing any connector, so no manual keystore management is needed, and the connector
refuses to start without them.

> **Warning:** never run the tool from `/var/wazuh-manager`: it would overwrite the manager's own
> Indexer credentials in `queue/keystore/`.

---

## Subcommand: `push-events`

Push documents to the `index` of the config file (default `wazuh-test`). Supports sync (bulk HTTP)
and async (in-memory queued) modes. Each element of the events file is indexed **as is**, as the whole
document body, with the ids `doc-0`, `doc-1`, … Sync mode flushes once after staging everything; async
mode waits for the queue to drain.

> **Important:** The async queue is not persistent. Pending events do not survive process
> crashes or restarts and are discarded when the connector shuts down.

### Options

| Flag | Description |
|---|---|
| `-c CONFIG` | Config file (required) |
| `-e EVENTS_FILE` | JSON file: array of documents to index (with `-a true`: the template) |
| `-a true` | Treat the `-e` file as an index-mapping template and index random documents built from it: every `properties` object is walked and each `type` of `keyword`, `long`, `float` or `date` gets a random value |
| `-n COUNT` | Number of random documents to generate (required with `-a true`) |
| `-m async` | Use async mode (default: `sync`) |
| `-w SECONDS` | Wait N seconds before exiting (default `0` = wait for Enter) |
| `-l LOG_FILE` | Also write the logs to this file |
| `-L COUNT` | Call `flush()` N more times after indexing (sync only; ignored in async mode) |
| `-D SECONDS` | Delay between those flush calls (sync only) |
| `-I CONFIG` | Deprecated (async only): one more connector per extra config file, each fed the same events |
| `-t FILE` | Deprecated and ignored |

### Examples

```bash
# Index a file of events (sync)
./indexer_connector_tool push-events \
  -c input/config.json \
  -e input/example.json \
  -w 5

# Index a file of events (async)
./indexer_connector_tool push-events \
  -c input/config.json \
  -e input/example.json \
  -m async -w 5

# Auto-generate 1000 random documents from a mapping template
./indexer_connector_tool push-events \
  -c input/config.json \
  -e <mapping-template>.json \
  -a true -n 1000 -w 5

# Push events and run 10 flush cycles spaced 2s apart (sync, stress test)
./indexer_connector_tool push-events \
  -c input/config.json \
  -e input/example.json \
  -L 10 -D 2

# Legacy (no subcommand) — same as push-events
./indexer_connector_tool \
  -c input/config.json \
  -e input/example.json
```

### Example events file (`input/example.json`)

The `id`, `operation` and `data` keys of the shipped example are not interpreted: they become fields of
the indexed document.

```json
[
  {
    "id": "000_pkghash_CVE-2022-1234",
    "operation": "INSERT",
    "data": {
      "wazuh": {
        "agent": { "id": "000", "name": "agent-01", "version": "5.0.0" }
      },
      "package": {
        "name": "openssl",
        "version": "1.1.1k",
        "architecture": "x86_64"
      }
    }
  }
]
```

---

## Subcommand: `export-policy`

Fetches all raw documents for a given space from the `wazuh-threatintel-policies` index
and writes them to a JSON file. Useful for inspecting what is currently stored.

### Options

| Flag | Description |
|---|---|
| `-c CONFIG` | Config file (required) |
| `-s SPACE` | Policy space name (required) |
| `-l OUTPUT_FILE` | Output file path (default: `exported_policy.json`) |

### Example

```bash
./indexer_connector_tool export-policy \
  -c input/config.json \
  -s standard \
  -l /tmp/standard_policy_raw.json
```

### Output format

An array of raw `_source` documents (pretty-printed, 4-space indent):
```json,fragment
[
  {
    "space": { "name": "standard", "hash": { "sha256": "abc123..." } },
    "document": { ... }
  }
]
```

---

## Subcommand: `generate-full-policy`

Retrieves all resources for a space across **all 5 policy aliases** using a
Point-In-Time (PIT) snapshot for consistency, then writes a structured JSON asset. Only the
`document` of each hit is kept; a hit without one is skipped.

Aliases queried:
- `wazuh-threatintel-kvdbs`
- `wazuh-threatintel-decoders`
- `wazuh-threatintel-filters`
- `wazuh-threatintel-integrations`
- `wazuh-threatintel-policies`

### Options

| Flag | Description |
|---|---|
| `-c CONFIG` | Config file (required) |
| `-s SPACE` | Policy space name (required) |
| `-l OUTPUT_FILE` | Output file path (default: `full_policy_asset.json`) |

### Example

```bash
./indexer_connector_tool generate-full-policy \
  -c input/config.json \
  -s standard \
  -l /tmp/standard_full_policy.json
```

### Output format

```json,fragment
{
  "space": "standard",
  "kvdbs": [ { ... }, { ... } ],
  "decoders": [ { ... }, { ... } ],
  "filters": [ { ... } ],
  "integration": [ { ... } ],
  "policy": { ... }
}
```

---

## Using the dev e2e stack

The dev e2e stack is in `tools/devContainer/e2e/` (see its `README.md`).

### Start the indexer

```bash
cd tools/devContainer/e2e
./init.sh            # certificates into certs/ and the passwords into .credentials.env
docker compose up -d
```

The indexer container publishes port 9200 on the host, and its node certificate (`certs/node-1.pem`)
carries `IP:127.0.0.1` and `DNS:wazuh-indexer` in its SAN (from
`tools/devContainer/scripts/wazuh-certs-tool.yml`). Use `"hosts": ["https://127.0.0.1:9200"]` and
`tools/devContainer/e2e/certs/root-ca.pem` as the CA.

### Credentials

The indexer passwords are generated into `tools/devContainer/e2e/.credentials.env` (mode 0600):
`WAZUH_INDEXER_ADMIN_PASSWORD` for `admin`, `WAZUH_INDEXER_MANAGER_PASSWORD` for `wazuh-manager`.
Copy one pair into the config file's `username`/`password`.

### TLS certificate note

To reach the indexer through another address, add it to the `indexer` node in
`tools/devContainer/scripts/wazuh-certs-tool.yml` and regenerate the certificates with
`./init.sh --certs-only --regen-certs`, then recreate the stack (`docker compose down -v && docker
compose up -d`).

---

## Local plain-HTTP OpenSearch (alternative)

The `docker-compose.yml` in this directory starts a plain HTTP two-node OpenSearch
cluster with security disabled — no TLS, no credentials needed.

```bash
# Start
docker compose -f testtool/docker-compose.yml up -d

# Use this config
cat > /tmp/config-local.json << 'EOF'
{
  "name": "local-test",
  "hosts": ["http://localhost:9200"],
  "username": "admin",
  "password": "admin"
}
EOF

./indexer_connector_tool push-events \
  -c /tmp/config-local.json \
  -e input/example.json \
  -w 3
```

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `No indexer credentials found in the keystore. ...` | `username`/`password` missing from config JSON | Add them to the config file |
| `SSL peer certificate or SSH remote key was not OK` | Cert SAN doesn't include the target IP/hostname | Regenerate cert with correct SAN (see above) |
| `No available server. Unavailable nodes: ...` | Wrong address or port, or indexer not running | Check `docker ps` and `hosts` |
| `Health check failed for '<host>' - Unauthorized - Check indexer credentials` | Wrong user or password | Check `.credentials.env` |
| `Space name is required: use -s <space>` | Missing `-s` flag on policy subcommands | Add `-s <space_name>` |
| `[export-policy] Warning: no policy documents found for space '<space>'` | Space name doesn't exist in the indexer | Verify with `curl` directly against the index |
