# Inventory Sync Test Tool

This tool allows you to perform E2E testing of the inventory sync module, similar to the inventory harvester test tool.

## Usage

```bash
./inventory_sync_tool <option(s)>

Options:
  -h                    Show this help message
  -i <file1,file2,...>  Specify the input files
  -c <file>             Specify the configuration file
  -l <file>             Specify the log file (optional)
```

## Examples

### 1. Basic usage with configuration file only (uses default test data)
```bash
./inventory_sync_tool -c examples/config.json
```

### 2. Process specific input files
```bash
./inventory_sync_tool -c examples/config.json -i examples/start_message.json,examples/data_message_001.json,examples/end_message.json
```

### 3. Process input files with logging
```bash
./inventory_sync_tool -c examples/config.json -i examples/ -l output.log
```

### 4. Process an entire directory of files
```bash
./inventory_sync_tool -c examples/config.json -i examples/
```

## Input File Formats

### Inventory Sync Messages

The tool supports inventory sync message files with the following format:

#### Start Message
```json
{
    "message_type": "start",
    "content": {
        "agent_id": 1,
        "module": "syscollector",
        "size": 3
    }
}
```

#### Data Message
```json
{
    "message_type": "data",
    "content": {
        "seq": 0,
        "operation": "upsert",
        "index": "syscollector_packages",
        "id": "package_001",
        "data": "{\"name\":\"vim\",\"version\":\"8.2\",\"architecture\":\"x86_64\"}"
    }
}
```

#### End Message
```json
{
    "message_type": "end",
    "content": {}
}
```

### Raw JSON Messages

The tool also supports raw JSON messages that will be sent directly:

```json
{
    "action": "test",
    "data": {
        "message": "This is a raw JSON message for testing"
    }
}
```

## Features

- **Configuration file support**: Load settings from JSON configuration file
- **Multiple input formats**: Support for inventory sync messages and raw JSON
- **Batch processing**: Process multiple files at once
- **Directory processing**: Process all files in a directory
- **Logging**: Optional log file output with timestamps
- **E2E testing**: Complete start -> data -> end message sequences
- **Default test data**: Generates test data when no input files provided

## Configuration File

The configuration file should be a JSON file with the necessary settings for the inventory sync module. Example:

```json
{
    "enabled": true,
    "interval": 30,
    "timeout": 10,
    "retry_attempts": 3,
    "log_level": "info"
}
```

## Testing Workflows

### Complete E2E Test Sequence
1. Create start message with agent ID and module information
2. Send multiple data messages with different operations (upsert/delete)
3. Send end message to close the session
4. Monitor logs for proper processing

### Raw JSON Testing
Send arbitrary JSON messages to test the module's handling of different data formats.

## Building

The tool should be built as part of the main Wazuh build process. Make sure to build the inventory sync module dependencies first.
