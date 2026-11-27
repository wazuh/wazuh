# Output Reference

The `outputs` stage sends events to their destinations. It is the stage of the output assets (`output/<name>/<version>`)
and holds a non-empty list of outputs. Each item is an object with exactly one key, the output type, whose value is
that output's configuration. Every output of the list receives the event, whatever the result of the others.

The output types are `file`, `wazuh-indexer` and `first_of`, which chooses among outputs.

## First of

To choose between the different output methods the `first_of` stage can be used.
This acts as an if-else block: the `check` blocks are evaluated in order, and the first one that succeeds sends the event
to the outputs of its `then` block; the remaining items are not evaluated. If no `check` succeeds, the event is not
sent anywhere by this stage. A `then` block can only contain `file` and `wazuh-indexer` outputs.

### Signature

```yaml
outputs:
  - first_of:
    - check: <condition-a>
      then:
        - wazuh-indexer:
            index: "wazuh-events-v5-a"

    - check: <condition-b>
      then:
        - wazuh-indexer:
            index: "wazuh-events-v5-b"
        - file: "c"
```

### Parameters

A non-empty array of items. Each item has exactly two keys, in this order:

| Name | type | required | Description |
|------|------|----------|-------------|
| check | string or array | yes | A condition with the syntax of the `check` stage. A condition that is always true, such as a check on a field every event has, makes the item a fallback; place it last. |
| then | array | yes | A non-empty list of `file` and `wazuh-indexer` outputs. All of them receive the event. |

### Asset example

The indexer output asset shipped with the engine:

```yaml
name: output/indexer/0
enabled: true

metadata:
  module: wazuh
  title: Indexer data stream outputs
  description: Output integrations events to wazuh-indexer

outputs:
  - first_of:
    - check: index_unclassified_events($wazuh.integration.category)
      then:
        - wazuh-indexer:
            index: "wazuh-events-v5-unclassified"

    - check: string_ne($wazuh.integration.category, "unclassified")
      then:
        - wazuh-indexer:
            index: "wazuh-events-v5-${wazuh.integration.category}"
```


## File

The `file` output appends each event, as one JSON document per line, to a file managed by the engine's stream logger, which
rotates and compresses it. Each policy's origin space is prepended to the channel name so that different spaces write to
isolated channels (e.g., `standard-wazuh-events-v5`).

### Signature

```yaml
file: "wazuh-events-v5"
```

### Parameters

The parameter is a non-empty base channel name. The effective channel is `{originSpace}-{channelName}`, where
`originSpace` comes from the policy definition. The effective channel may only contain letters, digits, `_` and `-`,
and at most 255 characters; otherwise the asset fails to build.

A policy that routes events creates the channel when it is built. A tester session (`POST /content/validate/policy`)
only checks the name: the channel is created by the first event run against the session, so a policy that is only
validated (`load_in_tester: false`) creates no channel.

### Files

With the default settings, the events of a channel are written to:

```text
/var/wazuh-manager/logs/<channel>/<YYYY>/<MMM>/wazuh-<channel>-<DD>.json
```

for example `/var/wazuh-manager/logs/standard-wazuh-events-v5/2026/Oct/wazuh-standard-wazuh-events-v5-22.json`, and
`/var/wazuh-manager/logs/<channel>/<channel>.json` is a hard link to the file being written. The file rotates when the
local date changes; a rotated file is compressed to `.gz`, and old files are deleted beyond 90 files or 20 GiB per channel.

These settings are the `analysisd.streamlog_*` internal options ([Stream log](configuration.md#stream-log)): base directory
`analysisd.streamlog_base_path`, path pattern `analysisd.streamlog_events_pattern`, size-based rotation
`analysisd.streamlog_events_max_size` (0, disabled, by default), compression `analysisd.streamlog_compress` and
`analysisd.streamlog_compression_level`, and retention `analysisd.streamlog_max_files` and
`analysisd.streamlog_max_accumulated_size`.

### Asset example

The file output asset shipped with the engine, disabled by default:

```yaml
name: output/file-output-integrations/0
enabled: false

metadata:
  module: wazuh
  title: file output event
  description: Output integrations events to a file
  compatibility: >
    This decoder has been tested on Wazuh version 5.x
  versions:
    - 5.x
  author:
    name: Wazuh, Inc.
    date: 2022/11/08
  references:
    - ""

outputs:
  - file: "wazuh-events-v5"
```

## Indexer

The `wazuh-indexer` output sends events to `wazuh-indexer` for indexing.

### Signature

```yaml
wazuh-indexer:
    index: "wazuh-events-v5-<name>"
```

### Parameters

| Name | type | required | Description |
|------|------|----------|-------------|
| index | string | yes | Data stream where the events are indexed. Must follow the index name rules below. It is the only key accepted. |

#### Index name rules

- The name must start with `wazuh-events-v5-`.
- After the prefix it may only contain lowercase letters, digits, `.`, `-` and `${field}` placeholders, for example
  `wazuh-events-v5-${wazuh.integration.category}-custom`. A name that breaks these rules makes the asset fail to build.
  A name outside the default data streams must also be prepared on the indexer, or every event sent to it is dropped:
  see [Data streams the manager can write to](#data-streams-the-manager-can-write-to).
- Each `${field}` placeholder is replaced, for every event, with the value of that event field. The field must exist and
  hold a string; otherwise the event is not indexed and the operation fails (trace:
  `write.output(wazuh-indexer/<index>) -> Couldn't get field ${field} from event`).
- The replacement is not sanitized: a referenced field value must already contain only lowercase letters, digits,
  `.`, `-` and `_`. A value holding anything else is not indexed and the operation fails (trace:
  `write.output(wazuh-indexer/<index>) -> Field ${field} holds characters not allowed in an index name`).
- After the replacement the name must be at most 255 characters; a longer name is not indexed and the operation fails
  (trace: `write.output(wazuh-indexer/<index>) -> Index name '<name>' exceeds 255 characters limit`).
- The traces appear in test sessions (logtest). On live traffic the same cause is logged as a `WARNING` without the
  event, at most once per minute for each output operation:
  `[builder] Event not indexed by 'write.output(wazuh-indexer/<index>)': <cause>`, followed by
  `(<n> more events not indexed by this output since the previous report)` when events were skipped since the last line.
  The line never carries event content: for a name that is too long the cause is
  `Index name exceeds 255 characters limit (<length> characters)`, without the name. Events skipped after the last
  line are reported when the output next indexes an event, once that minute is over:
  `[builder] <n> more events not indexed by 'write.output(wazuh-indexer/<index>)' since the previous report`.
- There is no date placeholder: apart from the `${field}` replacement, the name is used as written.

#### Data streams the manager can write to

The rules above are what the engine accepts; whether the indexer stores the event depends on the indexer.
The manager authenticates as the `wazuh-manager` indexer user, whose default role (`wazuh_manager`, defined by the
Wazuh indexer) may read and index documents in `wazuh-events-v5-*` but may **not create** an index or a data stream.
Out of the box, the only event data streams that exist are the ones the Wazuh indexer creates at startup, one per
integration category:

| Data stream |
|---|
| `wazuh-events-v5-access-management` |
| `wazuh-events-v5-applications` |
| `wazuh-events-v5-cloud-services` |
| `wazuh-events-v5-network-activity` |
| `wazuh-events-v5-other` |
| `wazuh-events-v5-security` |
| `wazuh-events-v5-system-activity` |
| `wazuh-events-v5-unclassified` |

These are the names the shipped output writes (`wazuh-events-v5-${wazuh.integration.category}`, where the category
is always one of the above). An output that resolves to any other name, such as
`wazuh-events-v5-${wazuh.integration.category}-custom`, builds and runs, but the indexer refuses every event sent
to it until that data stream exists: the events are dropped and the manager logs, for each one, a `WARNING` that
names the index and never quotes the event:

```text
Error indexing document (type security_exception - reason: 'no permissions for [indices:admin/create] and User [name=wazuh-manager, …]') - index: 'wazuh-events-v5-security-custom', id: '…', document size: … bytes
```

Before routing events to another name, prepare it on the indexer as an administrator, once for every name the output
can resolve to (with a `${field}` placeholder, every value the field can hold):

1. Make the name match a composable index template that declares a data stream (`"data_stream": {}`) and carries the
   mappings the events need — for example a template of your own whose `index_patterns` lists the name.
2. Create the data stream: `PUT _data_stream/<name>`.

The `wazuh_manager` role already indexes into any existing `wazuh-events-v5-*` data stream, so nothing else is
needed. Alternatively, mapping the `wazuh-manager` user to a role of your own that grants `indices:admin/create` on
`wazuh-events-v5-*` lets the first event create the stream from whichever template matches its name (the default
role is reserved and cannot be edited).

### Asset example

An output that writes to a data stream of its own; `wazuh-events-v5-${wazuh.integration.category}-custom` must be
prepared on the indexer for every category first (see [Data streams the manager can write to](#data-streams-the-manager-can-write-to)):

```yaml
name: output/custom-indexer/0

metadata:
  module: wazuh
  title: Indexer output event
  description: Output integrations events to wazuh-indexer

outputs:
  - wazuh-indexer:
      index: "wazuh-events-v5-${wazuh.integration.category}-custom"
```
