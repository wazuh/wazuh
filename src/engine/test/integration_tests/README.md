# Integration Tests for Wazuh Engine

## Overview

This directory contains the integration tests for the Wazuh Engine. These tests are essential for validating the interactions between different components of the Wazuh Engine and ensuring that they function together as expected.

## Prerequisites

Before running the integration tests, ensure that the following prerequisites are installed:

- **Basic requirements for sandbox environment  ([described here](../README.md#prerequisites))**
- **engine-test-utils**: A set of utilities for integration tests. Install it using pip:
  ```bash
  pip3 install test/engine-test-utils
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
engine-it -e /tmp/engine-integration-test -t ./test/integration_tests init -b ./build/main
```

### Executing All Integration Tests

Run all integration tests by executing:

```bash
engine-it -e /tmp/engine-integration-test -t ./test/integration_tests run
```

### Running a Specific Feature

To run a specific feature, point to the feature file:

```bash
engine-it -e /tmp/engine-integration-test -t ./test/integration_tests run -f test/integration_tests/catalog/api.feature
```

### Command Line Help

For additional options and help, use the `-h` flag:

```bash
engine-it run -h
```

This will display usage information and describe the command-line options available.
