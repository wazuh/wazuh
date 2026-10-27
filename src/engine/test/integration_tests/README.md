# Integration Tests for Wazuh Engine

## Overview

This directory contains the integration tests for the Wazuh Engine. These tests are essential for validating the interactions between different components of the Wazuh Engine and ensuring that they function together as expected.

The tests are [behave](https://behave.readthedocs.io/) suites, one per directory (`crud_cm`, `crud_ns`,
`geo`, `router`, `status`, `tester`), each with a `features/` and a `steps/` directory and an `environment.py`
that starts and stops the engine with `engine-test-utils`. They run with the `engine-it` tool
([engine-it/README.md](engine-it/README.md)), in the `api_tests` job of
[5_testintegration_engine.yml](../../../../.github/workflows/5_testintegration_engine.yml).

## Prerequisites

- **The sandbox requirements** ([described here](../README.md#prerequisites)), including the manager tree
  built (`src/build/engine/wazuh-engine` and `src/build/bin/wazuh-manager-keystore`).
- **engine-it**, which installs **behave** as a dependency. From `src/engine/`:
  ```bash
  pip3 install tools/api-communication
  pip3 install tools/engine-suite
  pip3 install test/engine-test-utils
  pip3 install test/integration_tests/engine-it
  ```

## Running the Tests

The commands below run from `src/engine/`.

### Setting Up the Test Environment

First, set up an isolated environment to run the tests. This ensures that the tests do not interfere with any existing installations or configurations:

```bash
./test/setupEnvironment.py -e /tmp/engine-integration-test
```

### Initializing the Test Environment

Load all necessary configurations for the test:

```bash
engine-it -e /tmp/engine-integration-test -t ./test/integration_tests init
```

`init` copies `configuration_files/config.env` into the environment, seeds the enrichment, geo and default
output (`ruleset/outputs/*.yml`) stores, then starts the engine binary `<environment>/wazuh-engine` and creates
the `testing` namespace with the test decoders and integrations the suites expect.

### Executing All Integration Tests

Run all integration tests by executing:

```bash
engine-it -e /tmp/engine-integration-test -t ./test/integration_tests run
```

### Running a Specific Feature

To run a specific feature, point to the feature file:

```bash
engine-it -e /tmp/engine-integration-test -t ./test/integration_tests run -f test/integration_tests/router/features/api.feature
```

Scenarios tagged `@exclude` are skipped.

### Command Line Help

For additional options and help, use the `-h` flag:

```bash
engine-it -e /tmp/engine-integration-test -t ./test/integration_tests run -h
```

This will display usage information and describe the command-line options available.
