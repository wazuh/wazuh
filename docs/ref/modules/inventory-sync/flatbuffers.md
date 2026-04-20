# Flatbuffers

Inventory Sync uses the FlatBuffer schema in `src/shared_modules/utils/flatbuffers/schemas/inventorySync.fbs` as its on-the-wire protocol between agents and the manager.

## Root message

All protocol messages are wrapped in a `Message` table.

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
    DataContext,
    DataBatch
}

root_type Message;
```

## Enums

### `Mode`

```flatbuffers
enum Mode: byte {
    ModuleFull,
    ModuleDelta,
    ModuleCheck,
    MetadataDelta,
    MetadataCheck,
    GroupDelta,
    GroupCheck
}
```

### `Operation`

```flatbuffers
enum Operation: byte {
    Upsert,
    Delete
}
```

### `Status`

```flatbuffers
enum Status: byte {
    Ok,
    Error,
    Offline,
    ChecksumMismatch,
    Processing
}
```

### `Option`

```flatbuffers
enum Option: byte {
    Sync,
    VDFirst,
    VDSync
}
```

## Start message

The Start message opens a session and carries the manager-side context used for indexing and downstream processing.

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
    cluster_name: string;
    cluster_node: string;
}
```

Important fields:

- `module`: currently `syscollector`, `fim`, or `sca` for indexed module flows.
- `mode`: full, delta, integrity-check, metadata, or group mode.
- `size`: number of expected sequence-tracked messages.
- `index`: target indices for the current session.
- `option`: vulnerability-scanner integration behavior.
- `global_version`: version used by metadata and group update flows.
- `cluster_name` and `cluster_node`: cluster metadata propagated by the manager-side session context.

## Data messages

### `DataValue`

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
```

This is the main indexable payload type.

- `seq`: sequence number used by `GapSet`.
- `session`: session identifier assigned in `StartAck`.
- `operation`: `Upsert` or `Delete`.
- `id`: logical document id fragment.
- `index`: target state index.
- `version`: optional document version propagated to the indexer.
- `data`: JSON payload bytes.

### `DataBatch`

```flatbuffers
table DataBatch {
    values: [DataValue];
}
```

`DataBatch` allows multiple `DataValue` items to be sent inside one message. Inventory Sync expands the batch internally and stores each contained item as an individual session record.

### `DataContext`

```flatbuffers
table DataContext {
    seq: ulong;
    session: ulong;
    id: string;
    index: string;
    data: [byte];
}
```

Current behavior:

- stored in RocksDB with a `_context` suffix,
- tracked for retransmission and end-of-session completeness,
- not indexed directly by Inventory Sync,
- available to downstream processing that reads the session store.

### `DataClean`

```flatbuffers
table DataClean {
    seq: ulong;
    session: ulong;
    index: string;
}
```

`DataClean` requests a `deleteByQuery` for the given agent and index during session finalization.

### `ChecksumModule`

```flatbuffers
table ChecksumModule {
    session: ulong;
    index: string;
    checksum: string;
}
```

Used by `ModuleCheck` to compare the agent-side checksum with the manager-side checksum computed from indexed documents.

## Session close message

```flatbuffers
table End {
    session: ulong;
}
```

`End` closes the upload side of the session. The manager completes the session only after `End` is received and all expected sequence-tracked messages have been accounted for.

## Acknowledgments

### `StartAck`

```flatbuffers
table StartAck {
    status: Status;
    session: ulong;
}
```

The manager returns the assigned session id here when the Start request succeeds.

### `EndAck`

```flatbuffers
table EndAck {
    status: Status;
    session: ulong;
}
```

The manager returns the final outcome of the session in `EndAck`.

## Retransmission support

```flatbuffers
table Pair {
    begin: ulong;
    end: ulong;
}

table ReqRet {
    seq: [Pair];
    session: ulong;
}
```

`ReqRet` is used to request retransmission of missing sequence ranges detected by the manager.

## Practical notes

- `size` in `Start` can be zero for `MetadataDelta`, `MetadataCheck`, `GroupDelta`, `GroupCheck`, and `ModuleCheck` sessions.
- `DataContext` is part of the live protocol even though it is not replayed into the indexer.
- `DataBatch` is part of the live protocol and should be supported by tools that generate or validate Inventory Sync traffic.
