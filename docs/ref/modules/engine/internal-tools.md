# Internal Development Tools

The repository contains Python tools for developing and testing the Wazuh engine. They are **not part of the
`wazuh-manager` package**. Most of them are bundled in the separate `wazuh-internal-tools` package (built from
`src/engine/internal_packages/`), which installs them into a virtual environment under `/opt/wazuh-internal-tools`
with command wrappers in `/usr/bin`. They are intended **exclusively for internal use** during the development and
testing of the engine and may change without notice.

Every tool that talks to a running engine uses its API socket, by default
`/var/wazuh-manager/queue/sockets/engine-api-http.sock` (see [API access](configuration.md#api-access)).

## Api-communication

A Python client library for the engine API over its Unix socket, shared by the other tools.

Details: `src/engine/tools/api-communication/README.md`.

---

## Engine Suite

The `engine-suite` Python package provides the command-line clients of the engine API:

- **engine-public**: commands on the public API — `cm` (policy and resource validation), `logtest` (cleanup),
  `ioc` (state, update) and `status` (engine readiness). Example: `engine-public status get`.
- **engine-private**: commands on the internal API — namespace management, content-manager CRUD, GeoIP databases
  and the raw-event indexer status.
- **engine-router**: route management (`add`, `delete`, `get`, `list`, `reload`, `update`) and event ingestion
  (`ingest`).
- **engine-event-dumper**: the event-dumper routes.
- **engine-test**: test sessions against a policy.

`engine-public`, `engine-private`, `engine-router` and `engine-event-dumper` accept `--api-socket` to target
another socket; `engine-test` commands take it as their own `--api-socket` option.

Details: `src/engine/tools/engine-suite/README.md`.

---

## Engine Test Utils

A Python library containing utility functions and helpers for testing scripts that interact with the Wazuh engine.

Details: `src/engine/test/engine-test-utils/README.md`.

---

## Engine Helper Test

`engine-helper-test` generates test cases from YAML descriptions of the helper functions, runs them end to end
against an engine, and generates the [helper functions reference](ref-helper-functions.md).

Details: `src/engine/test/helper_tests/README.md`.

---

## Engine Integration Test

`engine-it` runs the engine's behaviour-driven (behave) integration tests — content CRUD, namespaces, router,
tester, GeoIP, status — against a sandboxed engine.

Details: `src/engine/test/integration_tests/README.md`.

---

## Engine Metrics

`engine-metrics` is a real-time metrics dashboard and CLI for the engine. It polls the engine's metrics API over
its Unix socket and renders live, auto-refreshing charts for global and per-space metrics in a browser.

Details: `src/engine/tools/engine-metrics/README.md`.

---

## Engine Schema

`engine-schema` generates the engine's schema and the associated decoder and enrichment configuration files from
the Wazuh Common Schema (WCS) definitions. The manager installer runs it from the source tree; the generated files
are installed into the engine store.

Details: `src/engine/tools/engine-schema/README.md`.

---

## Engine Bench

`engine-bench` runs the engine executable under `perf` and produces flame graphs to visualize performance
bottlenecks and hotspots. It is not part of `wazuh-internal-tools`.

Details: `src/engine/tools/engine-bench/README.md`.

---

## evtx2xml

A Python tool that converts Windows Event Log (EVTX) files to XML, used when preparing Windows event samples for
engine testing and decoder development. It is not part of `wazuh-internal-tools`.

Details: `src/engine/tools/evtx2xml/README.md`.
