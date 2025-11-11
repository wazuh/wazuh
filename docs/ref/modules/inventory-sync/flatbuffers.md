# Flatbuffers

The Inventory Sync module uses Google FlatBuffers for efficient serialization and deserialization of synchronization messages between Wazuh agents and the manager. FlatBuffers provide zero-copy deserialization and compact binary representation ideal for high-throughput inventory synchronization.

## Schema Definition

The inventory synchronization protocol is defined in flatbuffer schema files that specify the message structure and types.

### Core Message Structure

```flatbuffers
table Message {
    content: MessageType;
}

union MessageType {
    DataValue,
    DataClean,
    ChecksumModule,
    Start,
    StartAck,
    End,
    EndAck,
    ReqRet,
    DataContext
}

root_type Message;
```

All synchronization messages are wrapped in the `Message` table with the specific message type in the `content` union field.

### Start Message

Initiates a synchronization session with mode and agent information:

```flatbuffers
table Start {
    module: string;
    mode: Mode;
    size: ulong;
    index: [string];
    option: Option;
    architecture: string;
    hostname: string;
    osname: string;
    osplatform: string;
    ostype: string;
    osversion: string;
    agentversion: string;
    agentname: string;
    agentid: string;
    groups: [string];
    global_version: ulong;
}

enum Mode: byte {
    ModuleFull,
    ModuleDelta,
    ModuleCheck,
    MetadataDelta,
    MetadataCheck,
    GroupDelta,
    GroupCheck
}

enum Option: byte {
    Sync,
    VDFirst,
    VDSync,
    VDClean
}
```

**Fields:**

- `module`: Module name (syscollector, fim, sca)
- `mode`: Synchronization type (see modes below)
- `size`: Number of messages to be sent in this session
- `index`: Target index names for the synchronization
- `option`: Synchronization option (used by Vulnerability Scanner integration)
- `architecture`, `hostname`, `osname`, `osplatform`, `ostype`, `osversion`: Agent OS information
- `agentversion`, `agentname`, `agentid`: Agent identification information
- `groups`: Agent group memberships
- `global_version`: Version counter for agent context updates

**Synchronization Modes:**

**Module Synchronization** (syscollector, FIM, SCA):
- `ModuleFull`: Complete inventory replacement - triggers delete-by-query before indexing
- `ModuleDelta`: Incremental updates - only processes changes
- `ModuleCheck`: Integrity verification using checksums

**Agent Context Synchronization** (agent-info module):
- `MetadataDelta`: Updates agent metadata (name, version, IP, OS) on existing documents
- `MetadataCheck`: Disaster recovery - scans all indices and fixes metadata inconsistencies
- `GroupDelta`: Updates agent group membership on existing documents
- `GroupCheck`: Disaster recovery - scans all indices and fixes group inconsistencies

### Data Messages

The protocol supports multiple data message types:

#### DataValue

Standard inventory data message with versioning:

```flatbuffers
table DataValue {
    seq: ulong;
    session: ulong;
    operation: Operation;
    id: string;
    index: string;
    version: ulong;
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
- `version`: Module-specific version number for integrity checks
- `data`: JSON document payload as byte array

**Usage:** Used by syscollector, FIM, and SCA modules for inventory synchronization.

#### DataContext

Lightweight message for vulnerability scanning context:

```flatbuffers
table DataContext {
    seq: ulong;
    session: ulong;
    id: string;
    data: [byte];
}
```

**Fields:**

- `seq`: Sequence number
- `session`: Session identifier
- `id`: Document identifier
- `data`: Context payload

**Usage:** Reserved for future Vulnerability Scanner integration.

#### DataClean

Delete-by-query message for bulk data removal:

```flatbuffers
table DataClean {
    seq: ulong;
    session: ulong;
    index: string;
}
```

**Fields:**

- `seq`: Sequence number
- `session`: Session identifier
- `index`: Target index to clean

**Usage:** Used to remove outdated data.

#### ChecksumModule

Checksum verification for integrity checks:

```flatbuffers
table ChecksumModule {
    session: ulong;
    index: string;
    checksum: string;
}
```

**Fields:**

- `session`: Session identifier
- `index`: Target index name
- `checksum`: Calculated checksum for integrity verification

**Usage:** Used in ModuleCheck mode to determine if full sync is needed.

### End Message

Signals completion of data transmission:

```flatbuffers
table End {
    session: ulong;
}
```

**Fields:**

- `session`: Session identifier to complete

Sent by the agent after all data messages have been transmitted. This triggers the manager to process and index all session data.

---

## Response Messages

The manager sends acknowledgment responses back to agents:

### StartAck Message

Acknowledgment for session creation:

```flatbuffers
table StartAck {
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

**Fields:**

- `status`: Result of session creation
  - `Ok`: Session created successfully
  - `Error`: Session creation failed
  - `PartialOk`, `Offline`: Reserved for future use
- `session`: Unique session identifier assigned by the manager

Sent by the manager in response to a Start message. The agent uses this session ID for all subsequent data messages.

---

### EndAck Message

Acknowledgment for completed synchronization:

```flatbuffers
table EndAck {
    status: Status;
    session: ulong;
}
```

**Fields:**

- `status`: Final synchronization result
  - `Ok`: All data successfully indexed
  - `PartialOk`: Some data indexed, some failed
  - `Error`: Synchronization failed
  - `Offline`: Indexer unavailable
- `session`: Session identifier

Sent by the manager after processing all session data and completing indexing operations.

---

### ReqRet Message

Request for message retransmission:

```flatbuffers
table ReqRet {
    seq: [Pair];
    session: ulong;
}

table Pair {
    begin: ulong;
    end: ulong;
}
```

**Fields:**

- `seq`: Array of sequence number ranges to retransmit (each Pair represents a range from `begin` to `end`)
- `session`: Session identifier

Sent by the manager when sequence gaps are detected in received data messages. The agent retransmits the requested messages to ensure data completeness.

---

## Message Validation

The Inventory Sync module validates all incoming FlatBuffer messages:

### Message Verification

```cpp
// Verify the flatbuffer structure
flatbuffers::Verifier verifier(buffer.data(), buffer.size());
if (!Wazuh::SyncSchema::VerifyMessageBuffer(verifier))
{
    throw InventorySyncException("Invalid message buffer");
}

// Parse the message
auto syncMessage = Wazuh::SyncSchema::GetMessage(buffer.data());

// Validate content type
switch (syncMessage->content_type())
{
    case Wazuh::SyncSchema::MessageType_Start:
        // Validate Start message fields
        if (syncMessage->content_as_Start()->module() == nullptr)
        {
            throw InventorySyncException("Missing module name");
        }
        break;

    case Wazuh::SyncSchema::MessageType_DataValue:
        // Validate DataValue message fields
        auto dataValue = syncMessage->content_as_DataValue();
        if (dataValue->id() == nullptr || dataValue->index() == nullptr)
        {
            throw InventorySyncException("Missing required fields");
        }
        break;

    // ... other message types
}
```

**Validation checks:**
- FlatBuffer structure integrity
- Required fields presence
- Session ID validity
- Sequence number ordering
- Operation type validity

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

### Creating StartAck Response

```cpp
auto fbBuilder = std::make_shared<flatbuffers::FlatBufferBuilder>();
auto startAckOffset = Wazuh::SyncSchema::CreateStartAck(
    *fbBuilder,
    Wazuh::SyncSchema::Status_Ok,
    sessionId);
auto messageOffset = Wazuh::SyncSchema::CreateMessage(
    *fbBuilder,
    Wazuh::SyncSchema::MessageType_StartAck,
    startAckOffset.Union());
fbBuilder->Finish(messageOffset);
```

### Processing DataValue Message

```cpp
auto message = Wazuh::SyncSchema::GetMessage(buffer.data());
if (message->content_type() == Wazuh::SyncSchema::MessageType_DataValue)
{
    auto dataValue = static_cast<const Wazuh::SyncSchema::DataValue*>(message->content());
    const auto seq = dataValue->seq();
    const auto session = dataValue->session();
    const auto version = dataValue->version();
    const auto operation = dataValue->operation();

    // Access JSON payload
    auto data = dataValue->data();
    std::string_view jsonPayload(reinterpret_cast<const char*>(data->data()), data->size());

    // Process inventory data
}
```

### Creating EndAck Response

```cpp
flatbuffers::FlatBufferBuilder builder;

auto endAck = Wazuh::SyncSchema::CreateEndAck(
    builder,
    Wazuh::SyncSchema::Status_Ok,
    sessionId);

auto message = Wazuh::SyncSchema::CreateMessage(
    builder,
    Wazuh::SyncSchema::MessageType_EndAck,
    endAck.Union());

builder.Finish(message);
```

### Creating ReqRet (Retransmission Request)

```cpp
flatbuffers::FlatBufferBuilder builder;

// Create pairs of sequence ranges to retransmit
std::vector<flatbuffers::Offset<Wazuh::SyncSchema::Pair>> pairs;
pairs.push_back(Wazuh::SyncSchema::CreatePair(builder, 10, 15));  // Request seq 10-15
pairs.push_back(Wazuh::SyncSchema::CreatePair(builder, 20, 25));  // Request seq 20-25

auto reqRet = Wazuh::SyncSchema::CreateReqRet(
    builder,
    builder.CreateVector(pairs),
    sessionId);

auto message = Wazuh::SyncSchema::CreateMessage(
    builder,
    Wazuh::SyncSchema::MessageType_ReqRet,
    reqRet.Union());

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
