# Test Tools

Inventory Sync currently has three practical test surfaces in the source tree:

- **unit tests** for core session and dispatcher logic,
- **protocol integration tests** under `qa/`,
- **the Inventory Sync test tool** for end-to-end manager-side session simulation.

## Unit tests

Unit tests live under:

- `src/wazuh_modules/inventory_sync/tests/unit/`

They cover components such as:

- `AgentSession`
- `GapSet`
- `ResponseDispatcher`
- `DataBatch` handling behavior

These tests validate session lifecycle, chunk tracking, checksum handling, retransmission behavior, and response dispatch without requiring a full manager deployment.

## Protocol integration tests

Protocol-oriented integration tests live under:

- `src/wazuh_modules/inventory_sync/qa/`

This suite uses the real FlatBuffer protocol to simulate agent-manager exchanges and validate the Inventory Sync behavior end to end.

Current test coverage includes flows such as:

- basic start/data/end synchronization,
- sessions with no data,
- `ReqRet` retransmission handling,
- `DataClean` processing,
- `DataContext`-only sessions,
- checksum match and mismatch flows,
- metadata delta updates,
- group delta updates.

Representative test assets:

- `qa/test_data/basic_flow.json`
- `qa/test_data/module_check_match_flow.json`
- `qa/test_data/module_check_mismatch_flow.json`
- `qa/test_data/metadata_delta_flow.json`
- `qa/test_data/groups_delta_flow.json`

## Inventory Sync test tool

The end-to-end test tool lives under:

- `src/wazuh_modules/inventory_sync/testtool/`

The executable is `inventory_sync_testtool`.

Its purpose is to simulate a full Inventory Sync session against a manager-side environment using a single JSON input file that describes:

- the `Start` message,
- `DataValue` entries,
- `DataContext` entries,
- vulnerability-scanner-related session options such as `VDFirst` and `VDSync`.

This tool is especially useful for validating the integration between:

- Inventory Sync,
- the Wazuh Indexer,
- and the Vulnerability Scanner.

## When to use each tool

- Use **unit tests** when changing session logic, queueing behavior, or protocol parsing.
- Use the **QA integration suite** when changing protocol semantics, acknowledgments, retransmission, metadata or group reconciliation, or checksum logic.
- Use **`inventory_sync_testtool`** when validating realistic manager-side indexing or vulnerability-scanner-triggered sessions.

## Notes

- The FlatBuffer schema used by the tests is the live schema in `src/shared_modules/utils/flatbuffers/schemas/inventorySync.fbs`.
- If you update the protocol, update the schema consumers in `qa/` and `testtool/` together.
