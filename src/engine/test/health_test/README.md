# Health Tests for Wazuh-Engine Integrations

## Overview

This directory contains the necessary tools and scripts to run health tests for various integrations within the Wazuh-Engine ruleset. These tests are crucial for verifying the correctness and efficacy of each integration by comparing actual outputs against expected outcomes.

## Directory Structure

- **Integration Tests**: Each integration test is located within the `./ruleset/integrations/{integration-name}/test` directory.
- **Test Configuration**: The `engine-test.conf` within each integration's test directory configures the parameters for running the tests.


## Prerequisites

Before running the health tests, ensure that the following requirements are met:

- **Basic requirements for sandbox environment  ([described here](../README.md#prerequisites))**


## Configuration Files

The `engine-test.conf` file specifies the settings necessary to run `engine-test`. It includes configurations like log collection parameters for the events under test.

## Input and Expected Output Files

- **Input Files (`${test_name}_input.txt`)**: Contains lines where each line represents an event to be tested.
- **Expected Output Files (`${test_name}_expected.json`)**: Includes an array of JSON objects, each corresponding to the expected outcome for the respective input event.

## Running Health Tests

### Setup the Environment

First, set up an isolated environment to run the tests using the `setupEnvironment.py` script:

```bash
./test/setupEnvironment.py -e /tmp/engine-test
```

### Initialize Test Environment

Load all necessary configurations and integration from ruleset tests:

```bash
./test/health_test/initialState.py -e /tmp/engine-test
```

### Execute Tests

Run all tests for a specific integration or execute health tests across all integrations:

```bash
./test/health_test/run.py -e /tmp/engine-test
# To run a specific test
./test/health_test/run.py -e /tmp/engine-test -i ruleset/integrations/{integration-name}/test/{test_name}_input.txt
```

## Error Handling and Reports

After the test execution, a report is generated. If any test fails, the exit code will be non-zero, and details will be printed to stdout. This helps in identifying and resolving issues effectively.

## Contribution Guidelines

TODO

## Note

It is important to remember that while this `README.md` is located in the `./test/health_test` directory, the actual tests are hosted within each integration's directory under `./ruleset/integrations/`. This structure helps in maintaining clear separation and organization of tests according to their specific integrations.
