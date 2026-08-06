# Inventory Sync Server Test Tools

Two tools live with the module's sources, one per layer: a raw HTTP sender for the transport and
routes, and a full integration driver that exercises the pipeline together with the real
vulnerability scanner.

## `tools/send_sync.py` — UDS smoke sender

A standard-library-only Python script (it runs on the manager's embedded interpreter without
installing anything) that speaks the same bytes remoted puts on the wire: HTTP/1.1 over an
`AF_UNIX` stream, `Content-Length` delimited, `Connection: close`. Useful to probe a live module
and to reproduce every transport-level rejection by hand.

Run it from the manager's home directory so the default relative socket path resolves, or pass
`--socket` with an absolute path.

```bash
# Liveness probe (expects 200)
./send_sync.py --health

# Junk payload to POST /stateful (expects 400: not a valid FullSession)
./send_sync.py --size 1024

# Missing identity header (expects 400)
./send_sync.py --agent-id ""

# Unknown route (404) and wrong verb (405 + Allow header)
./send_sync.py --bad-route
./send_sync.py --method PUT

# A session declaring more than the total in-flight budget (expects 413)
./send_sync.py --size 335544320

# 100 requests in sequence, to watch the throttled log lines aggregate
./send_sync.py --size 4096 --repeat 100 --quiet
```

Options: `--socket`, `--path` (default `/stateful`), `--method`, `--size`, `--repeat`,
`--content-type`, `--timeout`, `--agent-id` (the `X-Wazuh-Agent-Id` header remoted would set;
empty string omits it), `--health`, `--bad-route`, `--quiet`. The exit code is `0` only when every
response was a 2xx, so it can anchor a shell check.

Sending a VALID session requires a FlatBuffers `FullSession` body, which this script deliberately
does not build — that is the integration driver's job below.

## `inventory_sync_server_testtool` — integration driver

The C++ driver behind the vulnerability-detection integration workflow
(`wazuh_modules/vulnerability_scanner/qa/test_efficacy_log.py`). It boots the REAL module pair —
the vulnerability scanner and this server, in one process — converts a JSON description into one
FlatBuffers `Message{FullSession}` per input file, and POSTs it to the server's real UDS socket
with the `X-Wazuh-Agent-Id` header, exactly as remoted would. Because a VD `200` guarantees
scan-then-ingest, the driver needs no scan-completion polling: the HTTP status IS the outcome.

Built as the `inventory_sync_server_testtool` CMake target (into `build/bin/`); sources in the
module's `testtool/` directory.

```text
inventory_sync_server_testtool <input.json>|<directory>
                               [--config <file>]        # module config: clusterName + <indexer> block
                               [--logFile <file>]       # scanner log lines, "function():message" format
                               [--wait <seconds>]       # settle time after the last session (default 3)
                               [--feed-timeout <secs>]  # how long to retry 503 feed-not-ready (default 300)
                               [--verbose]
```

Behavior worth knowing:

- A `503` with `Retry-After` (the CVE feed still downloading) is retried, honoring the header,
  until `--feed-timeout` expires — so a test run can start before the feed finished seeding.
- A directory input processes every `*.json` in it, sorted, as one session each.
- The exit code is non-zero if any session did not answer `200`.

### Input format

```json
{
  "Start": {
    "agentid": "001",
    "option": "VDFirst | VDSync | Sync",      // default VDSync
    "mode": "delta",                           // default delta
    "agentname": "test-agent-001",             // every Start metadata field is optional,
    "agentversion": "5.0.0",                   // with sensible defaults
    "architecture": "x86_64",
    "hostname": "test-host",
    "osname": "Ubuntu", "osplatform": "ubuntu", "ostype": "linux", "osversion": "22.04",
    "groups": ["default"],
    "indices": ["wazuh-states-inventory-packages"]   // optional; inferred from the data if omitted
  },
  "data_values": [
    {
      "operation": "upsert | delete",
      "index": "wazuh-states-inventory-packages",    // optional; inferred from the payload shape
      "id": "document-id-1",
      "payload": { "package": { "...": "..." }, "checksum": { "...": "..." } }
    }
  ],
  "data_context": [
    { "index": "wazuh-states-inventory-system", "id": "os-1", "payload": { "host": { "...": "..." } } }
  ]
}
```

Index inference when `index` is omitted: a payload with `package.hotfix` maps to
`wazuh-states-inventory-hotfixes`, any other `package` to `wazuh-states-inventory-packages`, and a
`host` to `wazuh-states-inventory-system`.

The `--config` file is the same JSON the QA suite uses (`qa/test_data/config.json`): a
`clusterName` (which the driver stamps into every session's `Start.cluster_name`, since the server
answers `403` on a cluster mismatch) and the `<indexer>` block with the hosts the module and the
scanner should reach.

## See Also

- [API Reference](api-reference.md)
- [Schemas](flatbuffers.md)
- [Architecture](architecture.md)
