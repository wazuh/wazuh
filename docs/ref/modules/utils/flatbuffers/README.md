# Flatbuffers

FlatBuffers is a high-performance serialization library used throughout Wazuh for efficient data exchange between components. It enables zero-copy deserialization and provides direct access to data without unpacking or parsing overhead.

## Usage in Wazuh

### Inventory Sync Server Module

The Inventory Sync Server module uses FlatBuffers as its primary communication protocol for synchronizing inventory data between agents and the manager. The protocol supports multiple synchronization modes:

**Module Synchronization** (agent-side inventory modules):
- `ModuleDelta`: Incremental updates for inventory changes. A full-replace resync (e.g. after a
  checksum mismatch) is a `DataClean` followed by an ordinary `ModuleDelta` sync of the fresh
  snapshot — there is no separate full-replacement mode.
- `ModuleCheck`: Integrity verification using checksums

**Agent Context Synchronization** (agent-info module):
- `MetadataDelta`: Agent metadata updates (name, version, IP, OS details)
- `MetadataCheck`: Disaster recovery for metadata across all indices
- `GroupDelta`: Agent group membership updates
- `GroupCheck`: Disaster recovery for groups across all indices

A whole synchronization session travels as ONE FlatBuffers `Message{FullSession}` (Start metadata plus the session's data items — there are no acks, no `End` and no per-item sequence numbers; the HTTP response is the session result), providing:

- **Zero-copy access**: Direct field access without intermediate object creation
- **Compact binary format**: Significantly smaller than JSON for large inventory datasets
- **Schema evolution**: Backward and forward compatibility for protocol updates
- **Type safety**: Compile-time validation of message structures

See the [Inventory Sync Server schema documentation](../../inventory-sync-server/flatbuffers.md) for detailed schema information.

### Vulnerability Scanner Module

The Vulnerability Scanner uses FlatBuffers for processing vulnerability feeds, particularly CVE5 schema data. This avoids deserialization overhead during scanning operations where performance is critical.

### Agent Info Module

The Agent Info module uses FlatBuffers to communicate metadata and group information updates to the manager's Inventory Sync Server, ensuring efficient propagation of agent context changes.

## Performance Characteristics

FlatBuffers provides significant performance advantages over traditional serialization formats:

- **Memory efficiency**: No intermediate allocations during deserialization
- **Processing speed**: Direct field access without parsing overhead
- **Scalability**: Handles high-volume message throughput efficiently
- **Low latency**: Minimal CPU overhead for serialization/deserialization

## Schema Files

FlatBuffer schemas are defined in `.fbs` files located in `src/shared_modules/utils/flatbuffers/schemas/`:

- `inventorySync.fbs`: Inventory synchronization protocol messages
- Additional schemas for other modules as needed

These schemas are compiled into C++ headers during the build process.

### `inventorySync.fbs` — Session outcome

There is no status enum and no acknowledgment message in the wire protocol: the HTTP response to
`POST /stateful` carries the session's outcome (`200` applied and flushed, `409` checksum mismatch
triggering a full resync, `4xx`/`5xx`/`503` per the
[response contract](../../inventory-sync-server/api-reference.md)).
