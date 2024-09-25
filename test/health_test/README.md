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

### Install health test
```bash
pip install ./engine-health-test
```

## Running Static tests
These tests do not require the engine to be running as they evaluate the expected values ​​of each test performed in each of the integrations. From this, conclusions can be drawn about custom fields used in the assets, mandatory fields that should be mapped and finally the verification that the metadata of each asset is correctly added.

### Metadata validate
This tool validates that the metadata field contains all the required information:
- Module to which the decoder belongs.
- Title of the product that generates the logs to decode.
- Description of the decoder source.
- Compatibility, versions Versions for which the logs have been tested and supported.
- Author: name and email address
- References from a URL, a site, or any documentation where those logs are defined and established.
```bash
usage: engine-health-test metadata_validate [-h] -r RULESET [--integration INTEGRATION] [--asset ASSET]

options:
  -h, --help            show this help message and exit
  -r RULESET, --ruleset RULESET
                        Specify the path to the ruleset directory
  --integration INTEGRATION
                        Specify integration name
  --asset ASSET         Specify asset name
```

#### Use
To evaluate the metadata in a particular integration
```bash
engine-health-test metadata_validate -r ruleset_dir --integration windows
```
To evaluate the metadata in a particular asset
```bash
engine-health-test metadata_validate -r ruleset_dir --integration windows --asset rule/execution-python-script-in-cmdline/0
```
To evaluate the metadata in all integrations
```bash
engine-health-test metadata_validate -r ruleset_dir
```

### Schema validate
This tool validates that the fields present in the output event exist in the wazuh schema. If not, they should be defined in the custom_fields.yml file within the test folder of each integration. Otherwise the test will fail.

```bash
usage: engine-health-test schema_validate [-h] -r RULESET [--integration INTEGRATION]

options:
  -h, --help            show this help message and exit
  -r RULESET, --ruleset RULESET
                        Specify the path to the ruleset directory
  --integration INTEGRATION
                        Specify integration name
```

#### Use
To evaluate the schema in a particular integration
```bash
engine-health-test schema_validate -r ruleset_dir --integration windows
```
To evaluate the schema in all integrations
```bash
engine-health-test schema_validate -r ruleset_dir
```

### Mapping validate
This tool validates that certain fields that are required are mapped in the output event.
Such as 'wazuh.decoders'. This list can be expanded and is located within base-rules

```bash
usage: engine-health-test mapping_validate [-h] -r RULESET [--integration INTEGRATION]

options:
  -h, --help            show this help message and exit
  -r RULESET, --ruleset RULESET
                        Specify the path to the ruleset directory
  --integration INTEGRATION
                        Specify integration name
```

#### Use
To evaluate the mapping in a particular integration
```bash
engine-health-test mapping_validate -r ruleset_dir --integration windows
```
To evaluate the mapping in all integrations
```bash
engine-health-test mapping_validate -r ruleset_dir
```

### Event processing
This tool validates that each asset in the ruleset has processed at least one event

```bash
usage: engine-health-test event_processing_validate [-h] -r RULESET

options:
  -h, --help            show this help message and exit
  -r RULESET, --ruleset RULESET
                        Specify the path to the ruleset directory
```

#### Use
```bash
engine-health-test event_processing_validate -r ruleset_dir
```

## Running Dynamic Tests

These tests need the engine to communicate with the API. Therefore each dynamic test starts its instance of the engine, performs the tests and then stops the engine.

### Setup the Environment

First, set up an isolated environment to run the tests using the `setupEnvironment.py` script:

```bash
./test/setupEnvironment.py -e health_test/environment
```

### Initialize Test Environment

Load all necessary configurations and geo-as databases.

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

### Integration validate
This tool validates an entire integration or a particular asset using the catalog API

```bash
usage: engine-health-test integration_validate [-h] [--integration INTEGRATION] [--asset ASSET]

options:
  -h, --help            show this help message and exit
  --integration INTEGRATION
                        Specify integration name
  --asset ASSET         Specify asset name
```

#### Use
To validate a particular integration
```bash
engine-health-test -e health_test/environment integration_validate --integration windows
```
To validate a particular asset
```bash
engine-health-test -e health_test/environment integration_validate --integration windows --asset rule/execution-python-script-in-cmdline/0
```
To validate all integrations
```bash
engine-health-test -e health_test/environment integration_validate
```

### Load ruleset
This tool create the filters, load the integrations and add the assets to the policy

```bash
usage: engine-health-test load_ruleset [-h]

options:
  -h, --help  show this help message and exit
```

#### Use
To validate a particular integration
```bash
engine-health-test -e health_test/environment load_ruleset
```

### Run
This tool ingests events and verifies in the trace that the assets that resulted successful are added to wazuh.decoders or wazuh.rules
```bash
usage: engine-health-test dynamic_mapping_validate [-h] [-i INTEGRATION] [--skip SKIP]

options:
  -h, --help            show this help message and exit
  -i INTEGRATION, --integration INTEGRATION
                        Specify the name of the integration to test, if not specified all integrations will be
                        tested
  --skip SKIP           Skip the tests with the specified name
```
#### Usage
```bash
engine-health-test -e health_test/environment dynamic_mapping_validate
# To run a specific test
engine-health-test -e health_test/environment dynamic_mapping_validate -i windows
```


### Run
This tool injects events into the engine and evaluates the output events with an expected event
```bash
$ engine-health-test -e ____test/integration/ run -h
usage: engine-health-test run [-h] [-i INTEGRATION] [--skip SKIP]

options:
  -h, --help            show this help message and exit
  -i INTEGRATION, --integration INTEGRATION
                        Specify the name of the integration to test, if not specified all integrations will be tested
  --skip SKIP           Skip the tests with the specified name
```

#### Usage
```bash
engine-health-test -e health_test/environment run
# To run a specific test
engine-health-test -e health_test/environment run -i windows
# To skip specific tests
engine-health-test -e health_test/environment run --skip windows,syslog
```

## Error Handling and Reports

After the test execution, a report is generated. If any test fails, the exit code will be non-zero, and details will be printed to stdout. This helps in identifying and resolving issues effectively.

## Note

It is important to remember that while this `README.md` is located in the `./test/health_test` directory, the actual tests are hosted within each integration's directory under `./ruleset/engine/integrations/`. This structure helps in maintaining clear separation and organization of tests according to their specific integrations.
