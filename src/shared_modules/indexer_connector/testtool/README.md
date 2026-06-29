# Indexer Connector Test Tool

A command-line tool for manually testing all features of the `IndexerConnector` module:
pushing events (sync and async), exporting policy documents, and generating full policy assets
from a running wazuh-indexer instance.

---

## Building

```bash
cd /workspaces/devContainer/wazuh/src/build
make indexer_connector_tool -j$(nproc)
# Binary is placed at: src/build/bin/indexer_connector_tool
```

---

## Subcommands

| Subcommand | Description |
|---|---|
| `push-events` | Push documents to an index/data-stream (default if no subcommand given) |
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
| `name` | Optional | Connector instance name (informational) |
| `index` | Optional | Default index name for `push-events` |
| `max_queue_bytes` | Optional | Async mode — max pending bytes before dropping (0 = unlimited) |
| `flush_interval_seconds` | Optional | Async mode — flush interval in seconds |

### Example: dev e2e environment (HTTPS + TLS)

`input/config.json`:
```json
{
  "name": "wazuh-states-vulnerabilities-cluster",
  "enabled": "yes",
  "hosts": ["https://127.0.0.1:9200"],
  "username": "admin",
  "password": "admin",
  "ssl": {
    "certificate_authorities": [
      "/workspaces/devContainer/wazuh/src/engine/tools/devContainer/e2e/certs/root-ca.pem"
    ]
  }
}
```

### Example: plain HTTP (no TLS, no auth — local dev OpenSearch)

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

The connector reads credentials from a **RocksDB keystore** (`queue/keystore/` relative to CWD).
The tool automatically seeds `username`/`password` from the config JSON into the keystore before
constructing any connector, so no manual keystore management is needed.

---

## Subcommand: `push-events`

Push documents to an index. Supports sync (bulk HTTP) and async (RocksDB-queued) modes.

### Options

| Flag | Description |
|---|---|
| `-c CONFIG` | Config file (required) |
| `-e EVENTS_FILE` | JSON file: array of documents to index |
| `-a true` | Auto-generate random events from a template instead of indexing the file as-is |
| `-n COUNT` | Number of random events to generate (requires `-a true`) |
| `-m async` | Use async mode (default: `sync`) |
| `-w SECONDS` | Wait N seconds before exiting (0 = wait for Enter) |
| `-l LOG_FILE` | Write logs to file |
| `-L COUNT` | Run N flush cycles after indexing (sync only) |
| `-D SECONDS` | Delay between flush cycles (sync only) |
| `-I CONFIG2` | Add a second async instance (repeatable) |

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

# Auto-generate 1000 random events from a template
./indexer_connector_tool push-events \
  -c input/config.json \
  -e input/example.json \
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

An array of raw `_source` documents:
```json
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
Point-In-Time (PIT) snapshot for consistency, then writes a structured JSON asset.

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

```json
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

## Using engine's dev environment setup (e2e)

The dev e2e stack is in `src/engine/tools/devContainer/e2e/`.

### Start the indexer

```bash
docker compose \
  -f src/engine/tools/devContainer/e2e/docker-compose.yml \
  -p dev-env-engine up -d
```

### Get the container IP

```bash
docker inspect wazuh-indexer \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
```

Update `hosts` in `input/config.json` with this IP.

### Credentials

The `admin` password after a fresh `indexer-security-init.sh` run is `admin`.
Check `src/engine/tools/devContainer/e2e/certs/wazuh-passwords.txt` if it differs.

### TLS certificate note

The e2e node cert (`certs/node-1.pem`) has been updated to include the container IP
in its SAN (`IP:127.0.0.1, IP:127.0.0.1`). If the container IP changes, regenerate
the cert:

```bash
CERTS=src/engine/tools/devContainer/e2e/certs

# Generate new CSR (reuse existing key)
openssl req -new -key $CERTS/node-1-key.pem \
  -out /tmp/node-1.csr \
  -subj "/C=US/L=California/O=Wazuh/OU=Wazuh/CN=node-1"

# Sign with SAN including the new IP (replace 127.0.0.X)
printf "[v3_req]\nsubjectAltName=IP:127.0.0.1,IP:127.0.0.X\n" > /tmp/san.cnf
openssl x509 -req -in /tmp/node-1.csr \
  -CA $CERTS/root-ca.pem -CAkey $CERTS/root-ca.key -CAcreateserial \
  -out $CERTS/node-1.pem -days 3650 \
  -extensions v3_req -extfile /tmp/san.cnf

# Deploy to running container
docker exec wazuh-indexer cp /certs/node-1.pem /etc/wazuh-indexer/certs/indexer.pem
docker exec wazuh-indexer chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs/indexer.pem
docker exec wazuh-indexer chmod 640 /etc/wazuh-indexer/certs/indexer.pem
docker exec wazuh-indexer service wazuh-indexer restart
docker exec wazuh-indexer /usr/share/wazuh-indexer/bin/indexer-security-init.sh
```

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
| `No username and password found in the keystore` | `username`/`password` missing from config JSON | Add them to the config file |
| `SSL peer certificate or SSH remote key was not OK` | Cert SAN doesn't include the target IP/hostname | Regenerate cert with correct SAN (see above) |
| `No available server` | Wrong IP, wrong port, or indexer not running | Check `docker ps` and container IP |
| `Health check failed … status: 401` | Wrong password | Check `wazuh-passwords.txt` or use `admin:admin` after fresh init |
| `Space name is required` | Missing `-s` flag on policy subcommands | Add `-s <space_name>` |
| Output file is empty / 0 documents | Space name doesn't exist in the indexer | Verify with `curl` directly against the index |
