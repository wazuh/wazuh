# Flatbuffers

The Inventory Sync module uses Google FlatBuffers for efficient serialization and deserialization of synchronization messages between Wazuh agents and the manager. FlatBuffers provide zero-copy deserialization and compact binary representation ideal for high-throughput inventory synchronization.

## Schema Definition

The inventory synchronization protocol is defined in flatbuffer schema files that specify the message structure and types.

### Core Message Structure

```flatbuffers
// Main message wrapper
table Message {
    content: MessageType;
}

union MessageType {
    Data,
    Start,
    StartAck,
    End,
    EndAck,
    ReqRet
}

table Data {
    seq: ulong;
    session: ulong;
    operation: Operation;
    id: string;
    index: string;
    data: [byte];
}

table Start {
    mode: Mode;
    size: ulong;
}

table StartAck {
    status: Status;
    session: ulong;
}

table End {
    session: ulong;
}

table EndAck {
    status: Status;
    session: ulong;
}

table Pair {
    begin: ulong;
    end: ulong;
}

table ReqRet {
    seq: [Pair];
    session: ulong;
}
```

### Start Message

Initiates a synchronization session with mode and agent information:

```flatbuffers
table Start {
    mode: Mode;
    size: ulong;
}

enum Mode: byte {
    Full,
    Delta
}
```

**Fields:**

- `mode`: Synchronization type (Full replaces all data, Delta applies changes)
- `size`: The size of the inventory data being synchronized

### Data Message

Contains inventory payload for indexing:

```flatbuffers
table Data {
    seq: ulong;
    session: ulong;
    operation: Operation;
    id: string;
    index: string;
    data: [byte];
}

enum Operation : byte {
    Upsert = 0,
    Delete = 1
}
```

**Fields:**

- `seq`: Sequence number for the message
- `session`: Session identifier linking messages to a synchronization session
- `operation`: Type of operation (Upsert for insert/update, Delete for removal)
- `id`: Unique document identifier within the index
- `index`: Target Elasticsearch/OpenSearch index name
- `data`: JSON document payload as byte array

### End Message

Signals completion of data transmission:

```flatbuffers
table End {
    session: ulong;
}
```

**Fields:**

- `session`: Session identifier to complete

### Response Messages

The module sends acknowledgment responses back to agents:

```flatbuffers
table EndAck {
    status: Status;
    session: ulong;
}

enum Status: byte {
    Ok,
    PartialOk,
    Error,
    Offline
}
```

## Message Validation

The Inventory Sync module performs comprehensive validation of all flatbuffer messages, that follows this schema:

```flatbuffers
table AgentInfo {
    id: string;
    name: string;
    ip: string;
    version: string;
    module: string;
    data: [ubyte];
}

root_type AgentInfo;
```

### Buffer Verification

```cpp
auto message = Wazuh::Sync::GetAgentInfo(dataRaw.data());

if (message->id() == nullptr || message->module_() == nullptr)
{
    throw InventorySyncException("Invalid message buffer");
}

auto agentId = message->id()->string_view();
auto moduleName = message->module_()->string_view();

auto agentName = message->name() ? message->name()->string_view() : std::string_view();
auto agentIp = message->ip() ? message->ip()->string_view() : std::string_view();
auto agentVersion = message->version() ? message->version()->string_view() : std::string_view();

flatbuffers::Verifier verifier(message->data()->data(), message->data()->size());
```

### Content Type Validation

```cpp
if (Wazuh::SyncSchema::VerifyMessageBuffer(verifier))
{
    auto syncMessage = Wazuh::SyncSchema::GetMessage(message->data()->data());
    if (syncMessage->content_type() == Wazuh::SyncSchema::MessageType_Data)
    {
        // Process data message
    }
    else if (syncMessage->content_type() == Wazuh::SyncSchema::MessageType_Start)
    {
        // Process start message
    }
    else if (syncMessage->content_type() == Wazuh::SyncSchema::MessageType_End)
    {
        // Process end message
    }
    else
    {
        throw InventorySyncException("Unknown message contentype");
    }
}
else
{
    throw InventorySyncException("Invalid message buffer");
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
auto fbBuilder = std::make_shared<flatbuffers::FlatBufferBuilder>();
auto startAckOffset =
    Wazuh::SyncSchema::CreateStartAckDirect(*fbBuilder, status, ctx->sessionId, ctx->moduleName.c_str());
auto messageOffset = Wazuh::SyncSchema::CreateMessage(
    *fbBuilder, Wazuh::SyncSchema::MessageType_StartAck, startAckOffset.Union());
fbBuilder->Finish(messageOffset);
```

### Processing Data Message

```cpp
auto message = Wazuh::SyncSchema::GetMessage(buffer.data());
if (message->content_type() == Wazuh::SyncSchema::MessageType_Data) {
    const auto seq = message->seq();
    const auto session = message->session();

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
