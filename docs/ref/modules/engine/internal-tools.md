# Internal Development Tools

The repository contains Python modules that are not distributed with the Wazuh engine.
These modules are intended **exclusively for internal use** during the development and testing of the Wazuh engine.
Their use outside of development is not recommended, as they may change without notice.

## Api-communication

This library provides a client interface for local communication with the Wazuh engine. It is designed to facilitate seamless interaction between components during development and testing.

For more details, refer to the README on src/engine/tools/api-communication/README.md

---

## Engine Suite

The `engine-suite` Python package offers a comprehensive set of tools to manage and interact with the Wazuh engine.
These tools simplify the management of assets, policies, integrations, and other elements within the Wazuh environment,
providing a centralized and efficient workflow.

### Key Tools in `engine-suite`:
- **engine-private**: Hosts internal-only operations for namespace management, content-manager CRUD, geo, and raw-event tooling.
- **engine-public**: Hosts public-facing validation, IOC, and logtest cleanup commands.
- **engine-router**: Provides internal route management and event ingestion tooling.
- **engine-event-dumper**: Manages the internal event-dumper endpoints.
- **engine-test**: Provides utilities for testing engine functionality.

For more details, refer to the README on src/engine/tools/engine-suite/README.md

---

## Engine Test Utils

A Python library containing utility functions and helpers for testing scripts that interact with the Wazuh engine.
These utilities streamline the creation and execution of test cases.

For more details, refer to the README on src/engine/test/engine-test-utils/README.md

---

## Engine Helper Test

This tool automates the generation of test cases to verify the correct end-to-end operation of helper functions used
in asset. It uses YAML files to define the parameters of helper functions and generates corresponding test cases
automatically. The tool also generates documentation for helper functions.

**Features:**
- YAML-based test case generation.
- Simplifies testing of helper functions.
- Generate documentation for helper functions.

For more details, refer to the README on src/engine/test/helper-test/README.md

---

## Engine Integration Test

The `engine-integration-test` tool is designed to test the integration of the Wazuh engine with external systems.
It verifies the correct operation of integrations and ensures that data is correctly processed and forwarded to the
engine.

For more details, refer to the README on src/engine/test/integration_tests/README.md.

---

## Engine Metrics

A real-time metrics dashboard and CLI for the Wazuh engine. It polls the engine's metrics API over its Unix domain
socket and renders live, auto-refreshing charts for global and per-space metrics in a browser.

For more details, refer to the README on src/engine/tools/engine-metrics/README.md

---

## Engine Schema

A standalone tool that generates the engine's schema and associated decoder/field configuration files from the
Wazuh Common Schema (WCS) YAML definitions.

For more details, refer to the README on src/engine/tools/engine-schema/README.md

---

## Engine Bench

A benchmarking tool that runs the Wazuh engine executable under `perf` and produces flame graphs to visualize
performance bottlenecks and hotspots.

For more details, refer to the README on src/engine/tools/engine-bench/README.md

---

## evtx2xml

A Python tool that converts Windows Event Log (EVTX) files to XML, used when preparing Windows event samples for
engine testing and decoder development.

For more details, refer to the README on src/engine/tools/evtx2xml/README.md
