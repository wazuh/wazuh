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
- **engine-clear**: Clears specific configurations or data from the engine.
- **engine-decoder**: Manages and tests decoders used by the engine.
- **engine-diff**: Compares configurations or data for differences.
- **engine-integration**: Handles integrations with external systems.
- **engine-policy**: Manages policies within the Wazuh engine.
- **engine-router**: Configures and tests routing within the engine.
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

## Engine Health Test

The `engine-health-test` tool performs comprehensive health checks on the Wazuh ruleset.
It runs a series of automated tests against the Wazuh engine to ensure the ruleset operates as expected.
This tool is essential for validating the integrity and functionality of the ruleset.

For more details, refer to the README on src/engine/test/health_test/README.md

**Location:** `src/engine/test/health_test/engine-health-test`

---

## Engine Integration Test

The `engine-integration-test` tool is designed to test the integration of the Wazuh engine with external systems.
It verifies the correct operation of integrations and ensures that data is correctly processed and forwarded to the
engine.

For more details, refer to the README on src/engine/test/integration_test/README.md.
