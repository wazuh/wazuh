# Events format

The Inventory Sync module processes flatbuffer-encoded synchronization messages from Wazuh agents. These messages follow a specific protocol for maintaining inventory state consistency between agents and the Wazuh Indexer.

## Synchronization Protocol

The Inventory Sync module implements a session-based synchronization protocol with three message types:

### 1. Start Message

Initiates a new synchronization session. The agent sends this message to begin inventory state synchronization.

```cpp
// Flatbuffer schema structure
message Start {
  mode: Mode;           // Full or Delta sync mode
  size: uint64;        // Amount messages to sent
}
```

**Synchronization Modes:**

- **Full Mode**: Complete inventory replacement - triggers delete-by-query before indexing new data
- **Delta Mode**: Incremental updates - only processes changes without clearing existing data

### 2. Data Message

Contains the actual inventory data to be synchronized. Multiple data messages can be sent within a single session.

```cpp
// Flatbuffer schema structure
message Data {
  session: uint64;      // Session identifier
  operation: Operation; // Upsert or Delete operation
  index: string;        // Target index name
  id: string;          // Document identifier
  data: [byte];        // JSON document payload
}
```

**Operations:**

- **Upsert**: Insert or update document in the index
- **Delete**: Remove document from the index

### 3. End Message

Signals the completion of data transmission and triggers the indexing process.

```cpp
// Flatbuffer schema structure
message End {
  session: uint64;      // Session identifier
}
```

## Message Flow Example

A complete synchronization session follows this sequence:

1. **Agent** → **Manager**: Start message (creates session)
2. **Agent** → **Manager**: Data message(s) (stored in local RocksDB)
3. **Agent** → **Manager**: End message (triggers indexing)
4. **Manager** → **Agent**: ACK response (confirms completion)

## Sample Inventory Data

The actual inventory data carried in Data messages is JSON-formatted and follows the Wazuh Common Schema (WCS).

```console
2025/09/16 19:18:48 logger-helper[275809] inventorySyncFacade.hpp:331 at operator()(): DEBUG: InventorySyncFacade::start: Upserting data...
{"agent":{"id":"002","name":"Agent5", "version":"v5.0.0"},"wazuh":{"cluster":{"name":"cluster"}},"checksum":{"hash":{"sha1":"864d1e848ea2fc1f31a01c119812e08d523ded09"}},"package":{"architecture":"amd64","category":"libs","description":"X11 Session Management library","installed":null,"multiarch":"same","name":"libsm6","path":null,"priority":"optional","size":56320,"source":"libsm","type":"deb","vendor":"Ubuntu Developers","version":"2:1.2.3-1build2"},"state":{"modified_at":"2025-09-16T19:13:26.068Z"}}
```

## Response Messages

The module sends response messages back to agents through the Router system:

### Success Response

```cpp
message EndAck {
  status: Status_Ok;
  session: uint64;
}
```

### Error Response

```cpp
message EndAck {
  status: Status_Error;
  session: uint64;
}
```

## Error Handling

The module implements comprehensive error handling for various scenarios:

- **Invalid Message Buffer**: Flatbuffer verification failures
- **Session Not Found**: References to non-existent sessions
- **Session Already Exists**: Duplicate session creation attempts
- **Invalid Operations**: Unsupported operation types
- **Indexer Failures**: Connection or indexing errors
- **Timeout Conditions**: Sessions that exceed timeout limits

## Message Validation

All incoming messages undergo validation:

1. **Flatbuffer Verification**: Binary format validation
2. **Session Consistency**: Session ID validation and state checking
3. **Data Integrity**: JSON payload validation for Data messages
4. **Operation Validity**: Supported operation type verification

Invalid messages trigger error responses and session cleanup to maintain system stability.
