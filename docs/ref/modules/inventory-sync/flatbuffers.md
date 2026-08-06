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
    End,
    EndAck,
    DataContext,
    FullSession
}

root_type Message;
```

## Enums

### `Mode`

```flatbuffers
enum Mode: byte {
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
- `mode`: delta, integrity-check, metadata, or group mode. There is no full/replace mode: a full resync is a `DataClean` followed by a delta sync of the fresh snapshot (see [architecture.md](architecture.md)).
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
    operation: Operation;
    id: string;
    index: string;
    version: ulong;
    data: [byte];
}
```

This is the main indexable payload type.

- `operation`: `Upsert` or `Delete`.
- `id`: logical document id fragment.
- `index`: target state index.
- `version`: optional document version propagated to the indexer.
- `data`: JSON payload bytes.

### `DataContext`

```flatbuffers
table DataContext {
    id: string;
    index: string;
    data: [byte];
}
```

Current behavior:

- stored in RocksDB with a `_context` suffix,
- tracked for end-of-session completeness,
- not indexed directly by Inventory Sync,
- available to downstream processing that reads the session store.

### `DataClean`

```flatbuffers
table DataClean {
    index: string;
}
```

`DataClean` requests a `deleteByQuery` for the given agent and index during session finalization.

### `ChecksumModule`

```flatbuffers
table ChecksumModule {
    index: string;
    checksum: string;
}
```

Used by `ModuleCheck` to compare the agent-side checksum with the manager-side checksum computed from indexed documents.

## Session close message

```flatbuffers
table End {
}
```

`End` closes the upload side of the session. The manager completes the session only after `End` is received and all expected sequence-tracked messages have been accounted for.

## Acknowledgments

### `EndAck`

```flatbuffers
table EndAck {
    status: Status;
}
```

The manager returns the final outcome of the session in `EndAck`.

## `FullSession` (one message per session)

None of the tables above carry a `session` field anymore. The session id is chosen by the **agent**, not handed back by a `StartAck`, and it is not part of any FlatBuffer table at all — it travels as a parameter of the transport call that sends the session (e.g. as an HTTP header, when the transport is the HTTPS client), so a retried session keeps the same id and the manager can dedupe on it independently of the message body.

```flatbuffers
table SyncData {
    values: [DataValue];
    contexts: [DataContext];
}

table Cleans {
    items: [DataClean];
}

union SessionPayload {
    SyncData,
    Cleans,
    ChecksumModule
}

table FullSession {
    start: Start;
    payload: SessionPayload;
    end: End;
}
```

The chunked `Start` → `StartAck` → `DataBatch`/`DataClean`/`ChecksumModule`[…] → `End` → `EndAck` exchange documented above exists because the module→agentd transport used to be a DGRAM socket bounded by `OS_MAXSTR` (65536), which forced sessions to be split into ~60 KB messages. Over the STREAM sync socket that bound is gone, so the agent now sends the whole session as **one** `FullSession` message and the manager answers it with a single `EndAck` — no `StartAck`, no per-item messages, no `ReqRet` round trip.

- `payload` carries exactly one of `SyncData`, `Cleans`, or `ChecksumModule` — a session is either a data sync, a clean notification, or an integrity check, never a combination. The union makes that mutual exclusion structural instead of relying on sender discipline. `ChecksumModule` is referenced directly (no wrapper array table) because an integrity check always covers a single index/module; `Cleans` stays an array because a session can clean several indices at once.
- `SyncData.values` and `SyncData.contexts` *can* both be non-empty in the same session: regular module deltas (`DataValue`) and vulnerability-detection context items (`DataContext`) are pulled from the same producer queue and travel together.
- `payload` can be entirely absent (a session with just `start`/`end`, no `SessionPayload` set at all) for metadata/group syncs that carry no data items.

## Practical notes

- `size` in `Start` can be zero for `MetadataDelta`, `MetadataCheck`, `GroupDelta`, `GroupCheck`, and `ModuleCheck` sessions.
- `DataContext` is part of the live protocol even though it is not replayed into the indexer.
- The agent-side `sync_protocol` module (`src/shared_modules/sync_protocol`) only ever sends `FullSession` messages; the chunked, per-message protocol documented above is what Inventory Sync's manager-side receiver currently implements. Tools that need to interoperate with the agent as it actually behaves today should target `FullSession`.
