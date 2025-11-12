# Flatbuffers

FlatBuffers is a high-performance serialization library used throughout Wazuh for efficient data exchange between components. It enables zero-copy deserialization and provides direct access to data without unpacking or parsing overhead.

## Usage in Wazuh

### Inventory Sync Module

The Inventory Sync module uses FlatBuffers as its primary communication protocol for synchronizing inventory data between agents and the manager. The protocol supports multiple synchronization modes:

**Module Synchronization** (agent-side inventory modules):
- `ModuleFull`: Complete inventory replacement for a module (syscollector, FIM, SCA)
- `ModuleDelta`: Incremental updates for inventory changes
- `ModuleCheck`: Integrity verification using checksums

**Agent Context Synchronization** (agent-info module):
- `MetadataDelta`: Agent metadata updates (name, version, IP, OS details)
- `MetadataCheck`: Disaster recovery for metadata across all indices
- `GroupDelta`: Agent group membership updates
- `GroupCheck`: Disaster recovery for groups across all indices

All synchronization messages (Start, Data, End, Acknowledgments) are encoded as FlatBuffers, providing:

- **Zero-copy access**: Direct field access without intermediate object creation
- **Compact binary format**: Significantly smaller than JSON for large inventory datasets
- **Schema evolution**: Backward and forward compatibility for protocol updates
- **Type safety**: Compile-time validation of message structures

See [Inventory Sync FlatBuffers documentation](../inventory-sync/flatbuffers.md) for detailed schema information.

### Vulnerability Scanner Module

The Vulnerability Scanner uses FlatBuffers for processing vulnerability feeds, particularly CVE5 schema data. This avoids deserialization overhead during scanning operations where performance is critical.

### Agent Info Module

The Agent Info module uses FlatBuffers to communicate metadata and group information updates to the Inventory Sync module, ensuring efficient propagation of agent context changes.

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
