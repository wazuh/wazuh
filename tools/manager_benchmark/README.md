# manager_benchmark

Load generation and reporting for the Wazuh manager's agent-facing ingestion paths. Its first (and
current) target is the **inventory synchronization** path — remoted's `POST /stateful` and the
`inventory_sync_server` behind it — together with the control and engine-event traffic a real fleet
produces alongside it. It lives under `tools/` rather than inside the module because it drives the
manager as a whole (authd enrollment, remoted, the engine ingress), not one module in isolation.

## Status

| Piece | State |
|---|---|
| `tool_simulator/docu/` — design documentation of the sender | **written** (subplan F9c-1) |
| `tool_simulator/` — the Go sender | pending (subplan F9c-2) |
| `scenarios/` + orchestration scripts | pending (subplan F9c-3) |
| `LOAD_REPORT.md` — the baseline report | pending (subplan F9c-4) |

The design is documented before the code on purpose: the sender has to reproduce the manager's
authentication and wire contracts byte for byte, and those are worth pinning down in prose (and
cross-checking against the manager's sources) before they are implemented.

## What it will measure

The same scenarios over two transports, so the difference isolates the relay:

- **`--mode uds`** — straight to the module's Unix socket (`POST /stateful`), measuring the
  ingestion pipeline alone: validation, sharded workers, group commit, the vulnerability-detection
  scan lane.
- **`--mode agent`** — like a real fleet: enroll against authd, then HTTPS to remoted with AES-CMAC
  signatures, sending `POST /control` (`startup`, a `notify` keepalive every 20 s, `shutdown`) and
  the `POST /stateful` sessions.

Per run it produces `bench.csv` (per-second cumulative counters and latency percentiles),
`sender_summary.json` (metadata, totals, per-kind histograms, verdict) and a scrape of the server's
own `GET /metrics`, so client-observed behavior can be correlated with shard depths, bulk flushes and
scan-lane timings.

## Start here

[`tool_simulator/docu/00-index.md`](tool_simulator/docu/00-index.md) — index, glossary and reading
order. The two documents worth reading first are `01-overview.md` (what this measures and what it
deliberately does not do) and `03-control-protocol.md` (the `POST /control` contract, which was not
documented for a synthetic client until now).

## Related

- System under test: [`docs/ref/modules/inventory-sync-server/`](../../docs/ref/modules/inventory-sync-server/README.md)
- Correctness (not performance): the integration QA in [`inventory_sync_server/qa/`](../../src/wazuh_modules/inventory_sync_server/qa/README.md)
- Runtime statistics the monitor scrapes: `GET /metrics`, documented in the API reference
