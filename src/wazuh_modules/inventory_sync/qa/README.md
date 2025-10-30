# Inventory Sync Integration Tests

This directory contains integration tests for the Wazuh `inventory_sync` module. The tests use the Wazuh agent protocol with FlatBuffers to simulate real agent-manager communication.

## Overview

The integration test framework provides:

- **Automated testing** of the inventory_sync module using real Wazuh protocol
- **JSON-based test data** for easy test case creation and maintenance
- **Sequential message execution** to test the ordered nature of the sync algorithm
- **Expected result validation** against actual responses

## Prerequisites

### System Requirements

- Python 3.8 or higher
- Wazuh manager running and accessible
- Docker (for OpenSearch testing)

### Python Dependencies

Install the required dependencies:

```bash
pip install -r requirements.txt
```

### FlatBuffers Setup

The test framework uses FlatBuffers for protocol communication. The required Python classes are generated automatically when needed, but you can also generate them manually:

```bash
python3 generate_flatbuffers.py
```

This requires the `flatc` compiler to be installed on your system.

## Usage

### Basic Usage

Run all tests against a local manager:

```bash
python run_tests.py --manager 127.0.0.1
```

### Run Specific Test

```bash
python run_tests.py --manager 127.0.0.1 --test basic_flow
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--manager` | Wazuh manager IP address | `127.0.0.1` |
| `--port` | Manager communication port | `1514` |
| `--test` | Run specific test (without .json extension) | All tests |
| `--verbose` | Enable verbose output | False |
| `--list-tests` | List available tests and exit | False |

## Test Cases

### 1. Basic Flow Test (`basic_flow`)

Tests the fundamental inventory sync flow:
- Start synchronization session
- Send data message
- End synchronization session

### 2. Multiple Data Messages (`nodata_flow`)

Tests handling when no data is sent during sync.

### 3. Request-Return Flow (`reqret_end_flow`)

Tests the request-return mechanism for missing data.

### 4. Simple Request-Return (`simple_reqret_test`)

Tests basic request-return functionality.

### 5. Metadata Delta Flow (`metadata_delta_flow`)

Tests the metadata delta synchronization mode (Mode 4):
- Start synchronization with MetadataDelta mode
- No data messages are sent
- Manager updates agent metadata across all specified indices
- Updates: agent.id, agent.name, agent.version, agent.host.*, state.document_version, state.modified_at
- End synchronization with Status_Ok response

This mode is used when agent metadata changes (hostname, OS, architecture, etc.) and all existing documents need to be updated.

### 6. Groups Delta Flow (`groups_delta_flow`)

Tests the groups delta synchronization mode (Mode 6):
- Start synchronization with GroupDelta mode
- No data messages are sent
- Manager updates agent groups across all specified indices
- Updates: agent.groups, state.document_version, state.modified_at
- End synchronization with Status_Ok response

This mode is used when agent group membership changes and all existing documents need to reflect the new groups.

## Test Data Format

Test files in `test_data/` and expected results in `expected_data/` use JSON format to define test scenarios and expected outcomes.

## Creating New Tests

1. Create test data in `test_data/` directory
2. Create expected results in `expected_data/` directory  
3. Run the new test with `--test <test_name>`

## Troubleshooting

### Common Issues

1. **Connection Refused**: Verify Wazuh manager is running
2. **Agent Registration Failed**: Check manager registration port (1515)
3. **Import Errors**: Install required dependencies with `pip install -r requirements.txt`

## License

This test framework is part of the Wazuh project and follows the same licensing terms.
