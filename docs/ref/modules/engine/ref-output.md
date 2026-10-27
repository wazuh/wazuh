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

    - check: string_not_equal($wazuh.integration.category, "unclassified")
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
- Each `${field}` placeholder is replaced, for every event, with the value of that event field. The field must exist and
  hold a string; otherwise the event is not indexed (trace: `Couldn't get field ${field} from event`).
- The replacement is not sanitized: referenced field values must already contain only valid index-name characters.
- After the replacement the name must be at most 255 characters; a longer name is not indexed (trace:
  `Index name '<name>' exceeds 255 characters limit`).
- There is no date placeholder: apart from the `${field}` replacement, the name is used as written.

### Asset example

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
