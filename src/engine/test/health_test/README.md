# Health Tests for Wazuh-Engine Integrations

## Overview

This directory contains the necessary tools and scripts to run health tests for various integrations within the Wazuh-Engine ruleset. These tests are crucial for verifying the correctness and efficacy of each integration by comparing actual outputs against expected outcomes.

## Directory Structure

- **Integration Tests**: Each integration test is located within the `ruleset/engine/integrations/{integration-name}/test` directory.
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
./test/setupEnvironment.py -e health_test/environment
```

### Install health test
```bash
pip install ./engine-health-test
```

### Initialize Test Environment

Load all necessary configurations and integration from ruleset tests:

```bash
engine-health-test -e health_test/environment init -b build/main -r engine/ruleset -t test/health_test/
```

All parameters available:
```bash
$ engine-health-test init -h
usage: engine-health-test init [-h] -b BINARY -r RULESET -t TEST_DIR

options:
  -h, --help            show this help message and exit
  -b BINARY, --binary BINARY
                        Specify the path to the engine binary
  -r RULESET, --ruleset RULESET
                        Specify the path to the ruleset directory
  -t TEST_DIR, --test-dir TEST_DIR
                        Specify the path to the test directory
```

### Execute Tests

Run all tests for a specific integration or execute health tests across all integrations:

```bash
engine-health-test -e health_test/environment run
# To run a specific test
engine-health-test -e health_test/environment run -i windows
# To skip specific tests
engine-health-test -e health_test/environment run --skip windows,syslog
```

All parameters available:
```bash
$ engine-health-test -e ____test/integration/ run -h
usage: engine-health-test run [-h] [-i INTEGRATION] [--skip SKIP]

options:
  -h, --help            show this help message and exit
  -i INTEGRATION, --integration INTEGRATION
                        Specify the name of the integration to test, if not specified all integrations will be tested
  --skip SKIP           Skip the tests with the specified name
```

## Error Handling and Reports

After the test execution, a report is generated. If any test fails, the exit code will be non-zero, and details will be printed to stdout. This helps in identifying and resolving issues effectively.

## Contribution Guidelines

TODO

## Note

It is important to remember that while this `README.md` is located in the `./test/health_test` directory, the actual tests are hosted within each integration's directory under `./ruleset/engine/integrations/`. This structure helps in maintaining clear separation and organization of tests according to their specific integrations.
