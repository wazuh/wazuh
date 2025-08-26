# Flatbuffers

The Inventory Sync module uses Google FlatBuffers for efficient serialization and deserialization of synchronization messages between Wazuh agents and the manager. FlatBuffers provide zero-copy deserialization and compact binary representation ideal for high-throughput inventory synchronization.

## Schema Definition

The inventory synchronization protocol is defined in flatbuffer schema files that specify the message structure and types.

### Core Message Structure

```flatbuffers
// Main message wrapper
table Message {
    content: MessageContent;
}

union MessageContent {
    Start,
    Data, 
    End
}
```

### Start Message

Initiates a synchronization session with mode and agent information:

```flatbuffers
table Start {
    mode: Mode;
    agent_id: uint64;
    module_name: string;
}

enum Mode : byte {
    Full = 0,
    Delta = 1
}
```

**Fields:**
- `mode`: Synchronization type (Full replaces all data, Delta applies changes)
- `agent_id`: Unique identifier for the Wazuh agent
- `module_name`: Source module generating the inventory data (e.g., "syscollector", "fim")

### Data Message

Contains inventory payload for indexing:

```flatbuffers
table Data {
    session: uint64;
    operation: Operation;
    index: string;
    id: string;
    data: [byte];
}

enum Operation : byte {
    Upsert = 0,
    Delete = 1
}
```

**Fields:**
- `session`: Session identifier linking messages to a synchronization session
- `operation`: Type of operation (Upsert for insert/update, Delete for removal)
- `index`: Target Elasticsearch/OpenSearch index name
- `id`: Unique document identifier within the index
- `data`: JSON document payload as byte array

### End Message

Signals completion of data transmission:

```flatbuffers
table End {
    session: uint64;
}
```

**Fields:**
- `session`: Session identifier to complete

### Response Messages

The module sends acknowledgment responses back to agents:

```flatbuffers
table EndAck {
    status: Status;
    session: uint64;
}

enum Status : byte {
    Ok = 0,
    Error = 1
}
```

## Message Validation

The Inventory Sync module performs comprehensive validation of all flatbuffer messages:

### Buffer Verification

```cpp
flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(dataRaw.data()), dataRaw.size());
if (Wazuh::SyncSchema::VerifyMessageBuffer(verifier)) {
    // Process valid message
    auto message = Wazuh::SyncSchema::GetMessage(dataRaw.data());
} else {
    throw InventorySyncException("Invalid message buffer");
}
```

### Content Type Validation

```cpp
if (message->content_type() == Wazuh::SyncSchema::MessageType_Data) {
    const auto data = message->content_as<Wazuh::SyncSchema::Data>();
    if (!data) {
        throw InventorySyncException("Invalid data message");
    }
    // Process data message
}
```

## Performance Characteristics

FlatBuffers provide several performance advantages for inventory synchronization:

### Memory Efficiency
- **Zero-copy deserialization**: Direct access to binary data without intermediate objects
- **Compact representation**: Binary format more efficient than JSON or XML
- **Minimal allocations**: Reduced garbage collection pressure

### Processing Speed
- **Fast access**: Direct field access without parsing overhead
- **Schema evolution**: Backward/forward compatibility for protocol updates
- **Vectorization**: Efficient processing of arrays and nested structures

## Usage Examples

### Creating Start Message

```cpp
flatbuffers::FlatBufferBuilder builder;

auto module_name = builder.CreateString("syscollector");
auto start = Wazuh::SyncSchema::CreateStart(builder, 
    Wazuh::SyncSchema::Mode_Full, 
    agent_id, 
    module_name);

auto message = Wazuh::SyncSchema::CreateMessage(builder, 
    Wazuh::SyncSchema::MessageType_Start, 
    start.Union());

builder.Finish(message);
```

### Processing Data Message

```cpp
auto message = Wazuh::SyncSchema::GetMessage(buffer.data());
if (message->content_type() == Wazuh::SyncSchema::MessageType_Data) {
    const auto data = message->content_as_Data();
    
    uint64_t session = data->session();
    auto operation = data->operation();
    auto index = data->index()->string_view();
    auto id = data->id()->string_view();
    auto payload = data->data();
    
    // Process inventory data
}
```

### Creating Response Message

```cpp
flatbuffers::FlatBufferBuilder builder;

auto response = Wazuh::SyncSchema::CreateEndAck(builder,
    Wazuh::SyncSchema::Status_Ok,
    session_id);

auto message = Wazuh::SyncSchema::CreateMessage(builder,
    Wazuh::SyncSchema::MessageType_EndAck,
    response.Union());

builder.Finish(message);
```

## Error Handling

The module implements robust error handling for flatbuffer operations:

### Buffer Corruption
- Verification failure detection
- Graceful error response to agents
- Session cleanup on invalid messages

### Schema Mismatches
- Version compatibility checking
- Fallback handling for unsupported fields
- Progressive schema evolution support

### Memory Safety
- Bounds checking on all field access
- Safe string and array iteration
- Protection against malformed buffers

## Integration with Router

The flatbuffer messages integrate seamlessly with the Wazuh Router system:

```cpp
m_inventorySubscription = std::make_unique<TRouterSubscriber>(
    INVENTORY_SYNC_TOPIC, 
    INVENTORY_SYNC_SUBSCRIBER_ID);

m_inventorySubscription->subscribe(
    [queue = m_workersQueue.get()](const std::vector<char>& message) {
        auto copy = message;
        queue->push(std::move(copy));
    });
```

This integration allows for efficient message routing and processing across the Wazuh infrastructure while maintaining type safety and performance through FlatBuffers.
