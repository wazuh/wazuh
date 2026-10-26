# Builder

Builds the policy assets (decoders, outputs, filters) into executable operation graphs. This file documents only the
output stage that talks to `wazuh-indexer`; the helper validation system is in
[`src/builders/README.md`](src/builders/README.md).

## `wazuh-indexer` output stage

Source: `src/builders/stage/indexerOutput.cpp`. The stage takes an `index` name template (placeholders such as
`${wazuh.integration.category}` are replaced from the event) and posts the event to `wiconnector::IWIndexerConnector`.

Per event:

1. Every placeholder field must exist in the event and the resulting name must be at most 255 characters; otherwise the
   stage fails for that event.
2. Outside test mode, `index(std::move(finalIndexName), event->str())` hands the name and the serialized event over by
   value; the connector posts them to the `events` bucket of the indexer client without a shared lock. The call never
   blocks and never throws: a full or closed bucket drops the event, counted in `indexer.events.dropped`.
3. In test mode (`/router/test`, `isTestMode`), step 1 runs as usual but the event is **not** indexed; see
   [Indexer connector](../../../../docs/ref/modules/engine/README.md#indexer-connector) for the operator contract.
   Building the stage in test mode does not require a connector (outside test mode an empty weak pointer throws
   `Indexer connector is not available`).

## Stage benchmark (`benchmark/`)

`builder_stage_bench` measures what one event costs the router worker that runs the real `wazuh-indexer` stage, with
the v1 write path (side `v1`: a frozen copy of the earlier `IndexerConnectorAsync` wrapper,
`benchmark/src/frozenV1Connector.*`) against `wiconnector::WIndexerConnector` on the engine's indexer client runtime
(side `v2`), both against the in-process fake of the `indexer_client` benches. `--mode stage` times the stage's
operation; `--mode index` times `IWIndexerConnector::index()` alone. One side per process.

- **Build**: the target exists only with `ENGINE_BUILD_BENCHMARK=ON` (`make ... ENGINE_TEST=y`), and the numbers
  are only meaningful in a Release (or RelWithDebInfo) tree; `cmake --build <tree> --target builder_stage_bench`.
- **Run**: `benchmark/run.sh --bench <path to builder_stage_bench> --out <prefix>` runs P = 1 and P = 8, five v1/v2
  pairs each (alternating which side goes first), and writes `<prefix>.csv`, `<prefix>.log` and
  `<prefix>-summary.txt` with the median v2/v1 ratio per mode. It never builds; `--selfcheck` is a short smoke run.
- **Regime**: P producers run bursts of 1000 events; between bursts the backlog must fall below a 4 MiB watermark.
  The backlog is payload bytes on both sides, so both run the same regime: the v1 queue size, and on v2 the sum of
  the buckets' `retainedBytes` (not their charge, which adds the 2048-byte result reserve of every queued event).
- **Why 4 MiB** (it was 16 MiB): v2 charges each event its payload plus the 2048-byte reserve, so with the ~360-byte
  corpus event its 64 MiB `events` quota fills with 10-11 MiB of payload. A 16 MiB watermark would not be reached on
  v2 (by arithmetic; the bench never ran with it on v2): the bucket would drop first and the regime would not be the
  v1's. With 4 MiB, the backlog under the watermark plus a whole P = 8 burst stays near 47 MiB of charge (127 MiB
  with 16 MiB); a `static_assert` in `stageBench.cpp` keeps it under the quota. Larger `--event-file` events or more
  than 8 producers are not covered: a drop shows as `lost > 0` and the row is invalid. Numbers taken with the 16 MiB
  watermark are not comparable with these.
- The stage ratio is a diagnostic: the RNF-2 gate of plan 18 is the engine's end-to-end A/B (I208).
