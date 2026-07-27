# 06 — FlatBuffers messages

The inventory-sync wire payload (the `flatbuffer_bytes` of
[05-wire-protocol.md](./05-wire-protocol.md)) is a FlatBuffer `Message`
union. Schema:
[`shared_modules/utils/flatbuffers/schemas/inventorySync.fbs`](../../../../../shared_modules/utils/flatbuffers/schemas/inventorySync.fbs).

This document is the per-message reference for the sender.

## Schema summary

### Enums

```
enum Mode : ubyte {
  ModuleFull   = 0,
  ModuleDelta  = 1,
  ModuleCheck  = 2,
  MetadataDelta= 3,
  MetadataCheck= 4,
  GroupDelta   = 5,
  GroupCheck   = 6
}

enum Operation : ubyte {
  Upsert = 0,
  Delete = 1
}

enum Status : ubyte {
  Ok               = 0,
  Error            = 1,
  Offline          = 2,
  ChecksumMismatch = 3,
  Processing       = 4
}

enum Option : ubyte {
  Sync    = 0,
  VDFirst = 1,
  VDSync  = 2
}

// Union discriminator
enum MessageType : ubyte {
  NONE            = 0,
  Start           = 1,
  StartAck        = 2,
  End             = 3,
  EndAck          = 4,
  DataValue       = 5,
  DataBatch       = 6,
  DataClean       = 7,
  ChecksumModule  = 8,
  DataContext     = 9,
  ReqRet          = 10
}
```

Numeric values are stable: do not reorder, do not insert.

### Top-level union

```
table Message {
  content : MessageContent;   // FlatBuffer union — gives a (type, value)
}

union MessageContent {
  Start, StartAck, End, EndAck,
  DataValue, DataBatch, DataClean,
  ChecksumModule, DataContext, ReqRet
}
```

When parsing inbound buffers, branch on `Message.content_type()` (a
`MessageType` value).

### Tables (fields in schema order)

```
table Start {
  agent       : string;
  module      : string;
  mode        : Mode;
  size        : uint64;        // total number of DataValue items the sender will emit
  option      : Option;
  indices     : [string];      // list of OpenSearch indices that this session may touch
}

table StartAck {
  session : uint64;            // assigned session id (or UINT64_MAX on Offline rejection)
  status  : Status;
}

table End {
  session : uint64;
}

table EndAck {
  session : uint64;
  status  : Status;
}

table DataValue {
  session   : uint64;
  seq       : uint64;          // monotonically increasing within the session
  operation : Operation;
  id        : string;          // document id in OpenSearch
  index     : string;          // target index (must be in Start.indices)
  data      : string;          // arbitrary JSON payload, as a UTF-8 string
}

table DataBatch {
  session : uint64;
  items   : [DataValue];       // 1..N values; serialised size MUST stay <= ~60 KB
}

table DataClean {
  session : uint64;
  indices : [string];          // indices to clear of agent-owned docs
}

table ChecksumModule {
  session  : uint64;
  module   : string;
  checksum : string;           // 40-char hex (sha1)
}

table Pair {
  key   : string;
  value : string;
}

table DataContext {
  session : uint64;
  entries : [Pair];
}

table ReqRet {
  session : uint64;
  ranges  : [Range];           // missing seq ranges; inclusive
}

table Range {
  first : uint64;
  last  : uint64;
}
```

The exact field order matters for parsers that rely on schema order. Do not
add fields, do not reorder.

## Builder reference per message type

The sender uses the generated Go stubs from:

```
flatc --go inventorySync.fbs
```

then `import "github.com/wazuh/.../inventorySync/InventorySync"` (or whatever
package path the generator produces under the engine tree).

Builder order (FlatBuffers requires strings/vectors to be serialised before
the table that references them):

### `Start`

| Field      | From scenario / state                          | Default                              |
| ---------- | ---------------------------------------------- | ------------------------------------ |
| `agent`    | agent_id from enrolment                        | (always set)                         |
| `module`   | step's `module` (from dump metadata or kind)   | n/a                                  |
| `mode`     | step's `sync_mode` as `Mode`                   | `ModuleDelta` if not set             |
| `size`     | `len(items)` for dumps; `data_size` for kinds  | (always set)                         |
| `option`   | step's `option` as `Option`                    | `Sync`                               |
| `indices`  | dump metadata `indices` or `[step.index]`      | (always set)                         |

Build order: serialise all strings (`agent`, `module`, each entry in
`indices`) → serialise the `indices` vector → start the `Start` table →
fill scalars and offsets → end the table → wrap in a `Message` union.

### `End`

| Field     | Source                                |
| --------- | ------------------------------------- |
| `session` | id from the matching `StartAck`       |

### `DataValue` (single message form)

| Field       | Source                                                       |
| ----------- | ------------------------------------------------------------ |
| `session`   | id from StartAck                                             |
| `seq`       | runner-local counter, starts at 0, increments per item       |
| `operation` | `Upsert` for synthetic; from dump's `operation` string field |
| `id`        | from dump item or generated (`fmt.Sprintf("doc-%d", seq)`)   |
| `index`     | per-item index; respects multi-index dumps                   |
| `data`      | `json.Marshal(item.data)` serialised to a UTF-8 string       |

The `data` field is a string, NOT bytes — it carries JSON text.

### `DataBatch` (batched form, when `use_databatch=true`)

| Field   | Source                                                     |
| ------- | ---------------------------------------------------------- |
| `session` | id from StartAck                                         |
| `items` | vector of `DataValue` tables, each as above                |

Batching rule: pack items into the current batch until the next item would
push the serialised batch size over **60 KB**, then close the batch and
start a new one. Single-item batches are allowed. Empty batches are never
sent.

A practical implementation:

```
const BatchTargetBytes = 60 * 1024
// after appending an item, compute the *current* builder size; if it
// exceeds the target, finalise this batch and start a new one before the
// next item.
```

### `DataClean`

| Field     | Source                                                 |
| --------- | ------------------------------------------------------ |
| `session` | id from StartAck                                       |
| `indices` | from the dump's metadata `indices` or step's `index`   |

### `ChecksumModule`

| Field      | Source                                          |
| ---------- | ----------------------------------------------- |
| `session`  | id from StartAck                                |
| `module`   | step's `module`                                 |
| `checksum` | step's `modulecheck_checksum` (40 hex chars)    |

### `DataContext`

| Field     | Source                                                                              |
| --------- | ----------------------------------------------------------------------------------- |
| `session` | id from StartAck                                                                    |
| `entries` | vector of `Pair{key,value}` from the dump's `metadata.context` (if present), else `[]` |

The current Python implementation emits `DataContext` only when the dump
explicitly provides a context block. The sender should do the same.

## Parser reference (inbound)

Inbound `Message` types the sender MUST handle:

| `MessageType`  | Fields read                                  | Routing                                                       |
| -------------- | -------------------------------------------- | ------------------------------------------------------------- |
| `StartAck`     | `session`, `status`                          | Match to the oldest unresolved Start in the per-agent FIFO    |
| `EndAck`       | `session`, `status`                          | Route to runner by `session` id                               |
| `ReqRet`       | `session`, `ranges[].first/last`             | Route to runner by `session` id; expand to a set of seq ids   |

All other types (`Start`, `End`, `DataValue`, ...) MUST NOT arrive from the
manager. If one does, log + drop.

### StartAck FIFO ordering (FR-20)

The manager assigns `session` ids in the order it received `Start` messages.
The reader cannot rely on `session` from the StartAck alone to find the
runner — at the moment a StartAck arrives, the original runner does not yet
know its session id. Therefore the reader MUST:

```
per-agent FIFO queue of pending Start runners.
on StartAck arrival:
   pop the FRONT of the queue
   resolve its Start future with (session=ack.session, status=ack.status)
on EndAck/ReqRet:
   look up the runner by session id (it now knows its id)
```

If the FIFO is empty when a StartAck arrives: log warning, drop.

## Builder pitfalls

- **String length**: `data` strings are UTF-8 — never encode raw binary as a
  Go `string` directly; use `flatbuffers.Builder.CreateByteString` only if
  the source is already valid UTF-8.
- **Vector ordering**: FlatBuffers requires vectors be built with
  `StartVector(elem_size, count, alignment)` and elements pushed in
  **reverse** order. Use the generated `*Start<Field>Vector` helpers; do not
  hand-roll.
- **Table termination**: each `*End` returns an offset; the union wrap requires
  `MessageStart` → `MessageAddContent` + `MessageAddContentType` → `MessageEnd`.
  Forgetting to set the type means the receiver sees `MessageType_NONE` and
  drops the frame.
- **Builder reuse**: call `builder.Clear()` (Python) / `builder.Reset()` (Go)
  before reusing a builder for the next message in the same goroutine.

## Verifying parity

Round-trip test: build the same message in Python and in Go using identical
inputs, dump `builder.Output()` bytes — they MUST be byte-identical. Any
diff means a field ordering or alignment bug.
