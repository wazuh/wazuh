# Integration Tests for Wazuh Engine

## Overview

This directory contains the integration tests for the Wazuh Engine. These tests are essential for validating the interactions between different components of the Wazuh Engine and ensuring that they function together as expected.

## Prerequisites

Before running the integration tests, ensure that the following prerequisites are installed:

- **Basic requirements for sandbox environment  ([described here](../README.md#prerequisites))**
- **IT-Utils**: A set of utilities for integration tests. Install it using pip:
  ```bash
  pip3 install test/integration_tests/it-utils
  ```
- **Behave**: A behavior-driven development (BDD) Python framework. Install it using pip:
  ```bash
  pip3 install behave
  ```

## Running the Tests



### Setting Up the Test Environment

First, set up an isolated environment to run the tests. This ensures that the tests do not interfere with any existing installations or configurations:

```bash
./test/setupEnvironment.py -e /tmp/engine-integration-test
```

### Initializing the Test Environment

Load all necessary configurations for the test:

```bash
./test/integration_tests/initialState.py -e /tmp/engine-integration-test
```

### Executing All Integration Tests

Run all integration tests by executing:

```bash
./test/integration_tests/run.py -e /tmp/engine-integration-test
```

### Running a Specific Module

To run tests for a specific module, specify the test directory of the module:

```bash
./test/integration_tests/run.py -e /tmp/engine-integration-test -f test/integration_tests/catalog
```

### Running a Specific Feature

To run a specific feature, point to the feature file:

```bash
./test/integration_tests/run.py -e /tmp/engine-integration-test -f test/integration_tests/catalog/features/api.feature
```

### Command Line Help

For additional options and help, use the `-h` flag:

```bash
./test/integration_tests/run.py -h
```

This will display usage information and describe the command-line options available.
