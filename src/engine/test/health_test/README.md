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
usage: engine-health-test static metadata_validate [-h] [--integration INTEGRATION] [--decoder DECODER] [--rule_folder RULE_FOLDER]

options:
  -h, --help            show this help message and exit
  --integration INTEGRATION
                        Specify integration name
  --decoder DECODER     Specify decoder name
  --rule_folder RULE_FOLDER
                        Specify rule folder name
```

#### Use
To evaluate the metadata in a particular integration
```bash
engine-health-test static -r ruleset_dir metadata_validate --integration windows
```
To evaluate the metadata in a particular decoder
```bash
engine-health-test static -r ruleset_dir metadata_validate --decoder rule/execution-python-script-in-cmdline/0
```
To evaluate the metadata in a particular rule folder
```bash
engine-health-test static -r ruleset_dir metadata_validate --rule_folder windows
```
To evaluate the metadata in all rules and decoders
```bash
engine-health-test static -r ruleset_dir metadata_validate
```

### Schema validate
This tool validates that the fields present in the output event exist in the wazuh schema. If not, they should be defined in the custom_fields.yml file within the test folder of each integration. Otherwise the test will fail.

```bash
usage: engine-health-test schema_validate [-h] -r RULESET [--integration INTEGRATION] [--rule_folder rule_folder]

options:
  -h, --help            show this help message and exit
  --integration INTEGRATION
                        Specify integration name
  --rule_folder rule_folder
                        Specify rule folder name
```

#### Use
To evaluate the schema in a particular integration
```bash
engine-health-test static -r ruleset_dir schema_validate --integration windows
```
To evaluate the schema in a particular rule folder
```bash
engine-health-test static -r ruleset_dir schema_validate --rule_folder windows
```
To evaluate the schema in all decoders and rules
```bash
engine-health-test static -r ruleset_dir schema_validate
```

### Mandatory mapping validate
This tool validates that certain fields that are required are mapped in the output event.
Such as 'wazuh.decoders'. This list can be expanded and is located within base-rules

```bash
usage: engine-health-test mandatory_mapping_validate [-h] -r RULESET [--integration INTEGRATION] [--rule_folder rule_folder]

options:
  -h, --help            show this help message and exit
  --integration INTEGRATION
                        Specify integration name
  --rule_folder rule_folder
                        Specify rule folder name
```

#### Use
To evaluate the mapping in a particular integration
```bash
engine-health-test static -r ruleset_dir mapping_validate --integration windows
```
To evaluate the mapping in a particular rule folder
```bash
engine-health-test static -r ruleset_dir mapping_validate --rule_folder windows
```
To evaluate the mapping in all decoders and rules
```bash
engine-health-test static -r ruleset_dir mapping_validate
```

### Event processing
This tool validates that each asset in the ruleset has processed at least one event

```bash
usage: engine-health-test event_processing_validate [-h] -r RULESET

options:
  -h, --help            show this help message and exit
```

#### Use
```bash
engine-health-test static -r ruleset_dir event_processing_validate
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
engine-health-test dynamic -e health_test/environment init -b build/main -r engine/ruleset -t test/health_test/
```

All parameters available:
```bash
usage: engine-health-test dynamic -e health_test/environment init [-h] -b BINARY -r RULESET -t TEST_DIR

options:
  -h, --help            show this help message and exit
  -b BINARY, --binary BINARY
                        Specify the path to the engine binary
  -r RULESET, --ruleset RULESET
                        Specify the path to the ruleset directory
  -t TEST_DIR, --test-dir TEST_DIR
                        Specify the path to the test directory
```

### Assets validate
This tool validates an entire integration, particular asset or rule folder using the catalog API

```bash
usage: engine-health-test dynamic -e health_test/environment assets_validate [-h] [--integration INTEGRATION] [--decoder DECODER] [--rule_folder rule_folder]

options:
  -h, --help            show this help message and exit
  --integration INTEGRATION
                        Specify integration name
  --decoder DECODER         Specify decoder name
  --rule_folder rule_folder
                        Specify the name of the rule folder to test
```

#### Use
To validate a particular integration
```bash
engine-health-test dynamic -e health_test/environment assets_validate --integration windows
```
To validate a particular decoder
```bash
engine-health-test dynamic -e health_test/environment assets_validate --decoder decoder/windows-security/0
```
To validate a particular rule folder
```bash
engine-health-test dynamic -e health_test/environment assets_validate --rule_folder windows
```
To validate all decoders and rules
```bash
engine-health-test dynamic -e health_test/environment assets_validate
```

### Load decoders
This tool create the filters, load the integrations and add the decoders to the policy.
It is necessary to run this tool to correctly perform the tests with decoders, otherwise they will fail.

```bash
usage: engine-health-test dynamic -e health_test/environment load_ruleset [-h]

options:
  -h, --help  show this help message and exit
```

#### Use
```bash
engine-health-test dynamic -e health_test/environment load_decoders
```

### Validate decoder mapping
Verifies that only certain fields are mapped in the decoders.
```bash
usage: engine-health-test dynamic validate_decoder_mapping [-h] [--integration INTEGRATION] [--skip SKIP]

options:
  -h, --help            show this help message and exit
  --integration INTEGRATION
                        Specify the name of the integration to test, if not specified all integration will be tested
  --skip SKIP           Skip the tests with the specified name
```

#### Use
```bash
# Validate specific integration
engine-health-test dynamic -e health_test/environment validate_decoder_mapping --integration suricata
# Validate all decoders
engine-health-test dynamic -e health_test/environment validate_decoder_mapping
```

### Load rules
This tool load and add the rules to the policy.
It is necessary to run this tool to correctly perform the tests with rules, otherwise they will fail.
Never run this until you are done running tests with the decoders as it will affect the expected traces and mappings.

```bash
usage: engine-health-test dynamic -e health_test/environment load_rules [-h]

options:
  -h, --help  show this help message and exit
```

#### Use
```bash
engine-health-test dynamic -e health_test/environment load_rules
```

### Validate successful assets
Verifies in the trace that the decoders that were successful are added to wazuh.decoders and that the successful rules are added to wazuh.rules.
```bash
usage: engine-health-test dynamic -e health_test/environment validate_successful_assets [-h] [-i INTEGRATION] [--rule_folder rule_folder] --target TARGET [--skip SKIP]

options:
  -h, --help            show this help message and exit
  -i INTEGRATION, --integration INTEGRATION
                        Specify the name of the integration to test
  --rule_folder rule_folder
                        Specify the name of the rule folder to test
  --target TARGET       Specify the asset type (decoder or rule). If it is a decoder, the tests are carried out for all decoders. The same for the rules.
  --skip SKIP           Skip the tests with the specified name
```
#### Usage
```bash
# Validate specific integration
engine-health-test dynamic -e health_test/environment validate_successful_assets --integration windows
# Validate specific rule folder
engine-health-test dynamic -e health_test/environment validate_successful_assets --rule_folder windows
# Validate all rules
engine-health-test dynamic -e health_test/environment validate_successful_assets --target rule
# Validate all decoders
engine-health-test dynamic -e health_test/environment validate_successful_assets --target decoder
```

### Validate rule mapping
Verifies that only certain fields are meped in the rules.
```bash
usage: engine-health-test dynamic -e health_test/environment validate_rule_mapping [-h] [--rule_folder rule_folder] [--skip SKIP]

options:
  -h, --help            show this help message and exit
  --rule_folder rule_folder
                        Specify the name of the rule folder to test, if not specified all rules folder will be tested
  --skip SKIP           Skip the tests with the specified name
```
#### Usage
```bash
# Validate specific rule folder
engine-health-test dynamic -e health_test/environment validate_rule_mapping --rule_folder windows
# Validate all rules
engine-health-test dynamic -e health_test/environment validate_rule_mapping
```

### Validate event indexing
Creates an opensearch instance along with an index. Ingests different events to the engine and compares the output with the document searched by hash in the index an expected one.
```bash
usage: engine-health-test dynamic validate_event_indexing [-h] [--integration INTEGRATION] [--rule_folder RULE_FOLDER] [--skip SKIP]
                                                          [--target TARGET]

options:
  -h, --help            show this help message and exit
  --integration INTEGRATION
                        Specify the name of the integration to test.
  --rule_folder RULE_FOLDER
                        Specify the name of the rule folder to test
  --skip SKIP           Skip the tests with the specified name
  --target TARGET       Specify the asset type (decoder or rule). If it is a decoder, the tests are carried out for all decoders. The same for the
                        rules.
```

#### Usage
```bash
# To run a specific integration
engine-health-test dynamic -e health_test/environment validate_event_indexing --integration windows
# To run a specific rule folder
engine-health-test dynamic -e health_test/environment validate_event_indexing --rule_folder windows
# To run all tests in decoders
engine-health-test dynamic -e health_test/environment validate_event_indexing --target decoder
# To run all tests in rules
engine-health-test dynamic -e health_test/environment validate_event_indexing --target rules
# To skip specific tests in decoders
engine-health-test dynamic -e health_test/environment validate_event_indexing --target decoder --skip windows,wazuh-core
```

### Validate custom field indexing
Creates an opensearch instance along with an index. It ingests different events to the engine and extracts all the custom fields.
It then verifies that each of the custom fields are present in the opensearch index.
If you do not specify a specific argument, an error will be raised.
However, if you specify the argument, only one is accepted.

```bash
usage: engine-health-test dynamic validate_custom_field_indexing [-h] [--integration INTEGRATION] [--rule_folder RULE_FOLDER] [--skip SKIP]
                                                          [--target TARGET]

options:
  -h, --help            show this help message and exit
  --integration INTEGRATION
                        Specify the name of the integration to test.
  --rule_folder RULE_FOLDER
                        Specify the name of the rule folder to test
  --skip SKIP           Skip the tests with the specified name
  --target TARGET       Specify the asset type (decoder or rule). If it is a decoder, the tests are carried out for all decoders. The same for the
                        rules.
```

#### Usage
```bash
# To run a specific integration
engine-health-test dynamic -e health_test/environment validate_custom_field_indexing --integration windows
# To run a specific rule folder
engine-health-test dynamic -e health_test/environment validate_custom_field_indexing --rule_folder windows
# To run all tests in decoders
engine-health-test dynamic -e health_test/environment validate_custom_field_indexing --target decoder
# To run all tests in rules
engine-health-test dynamic -e health_test/environment vvalidate_custom_field_indexing --target rules
# To skip specific tests in decoders
engine-health-test dynamic -e health_test/environment validate_custom_field_indexing --target decoder --skip windows,wazuh-core
```

### Run
This tool injects events into the engine and evaluates the output events with an expected event
```bash
usage: engine-health-test dynamic -e health_test/environment run [-h] [-i INTEGRATION] [--rule_folder rule_folder] [--skip SKIP] --target TARGET

options:
  -h, --help            show this help message and exit
  -i INTEGRATION, --integration INTEGRATION
                        Specify the name of the integration to test
  --rule_folder rule_folder
                        Specify the name of the rule folder to test
  --skip SKIP           Skip the tests with the specified name
  --target TARGET       Specify the asset type (decoder or rule). If it is a decoder, the tests are carried out for all decoders. The same for the rules.
```

#### Usage
```bash
# To run a specific integration
engine-health-test dynamic -e health_test/environment run --integration windows
# To run a specific rule folder
engine-health-test dynamic -e health_test/environment run --rule_folder windows
# To run all tests in decoders
engine-health-test dynamic -e health_test/environment run --target decoder
# To run all tests in rules
engine-health-test dynamic -e health_test/environment run --target rules
# To skip specific tests in decoders
engine-health-test dynamic -e health_test/environment run --target decoder --skip windows,wazuh-core
```

## Error Handling and Reports

After the test execution, a report is generated. If any test fails, the exit code will be non-zero, and details will be printed to stdout. This helps in identifying and resolving issues effectively.

## Note

It is important to remember that while this `README.md` is located in the `./test/health_test` directory, the actual tests are hosted within each integration's directory under `./ruleset/engine/integrations/`. This structure helps in maintaining clear separation and organization of tests according to their specific integrations.
