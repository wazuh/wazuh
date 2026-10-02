# Output Reference

The output stage is responsible for sending alerts to different destinations. This stage is only supported by
`outputs assets` and can have multiple outputs. Each output can have its own configuration.


## First of

To choose between the different output methods the `first_of` stage can be used.
This acts as an if else block. The first `check` that returns true will execute what's inside the `then` block, this block can be filled with `File` or `Indexer` blocks.

### Signature

```yaml
outputs:
  - first_of:
    - check: A
      then:
        - wazuh-indexer:
            index: "wazuh-events-v5-a"

    - check: B
      then:
        - wazuh-indexer:
            index: "wazuh-events-v5-b"

    - check: true
      then:
        - file: "c"
```

### Parameters

Accepts any array of `check` `then` blocks in each item the order is mandatory and will be respected as an order of execution. Ideally the last option should act as a fallback case.

### Asset example

```yaml
name: output/indexer/0

metadata:
  module: wazuh
  title: Indexer data stream outputs
  description: Output integrations events to wazuh-indexer

outputs:
  - first_of:
    - check: >-
        $wazuh.integration.category != "cloud-services" OR
        (NOT starts_with($wazuh.integration.name, "aws")
        AND NOT starts_with($wazuh.integration.name, "azure")
        AND NOT starts_with($wazuh.integration.name, "gcp"))

      then:
        - wazuh-indexer:
            index: "wazuh-events-v5-${wazuh.integration.category}"

    - check: starts_with($wazuh.integration.name, "gcp")
      then:
        - wazuh-indexer:
            index: "wazuh-events-v5-${wazuh.integration.category}-gcp"

    - check: starts_with($wazuh.integration.name, "azure")
      then:
        - wazuh-indexer:
            index: "wazuh-events-v5-${wazuh.integration.category}-azure"

    - check: starts_with($wazuh.integration.name, "aws")
      then:
        - wazuh-indexer:
            index: "wazuh-events-v5-${wazuh.integration.category}-aws"

```


## File

The `file` output sends events to a file. This output supports compression and rotation.
Each policy's `originSpace` is prepended to the channel name so that different spaces
write to isolated streamlog channels (e.g., `standard-wazuh-events-v5`).

### Signature

```yaml
file: "wazuh-events-v5"
```

### Parameters

The parameter is a base channel name. The effective streamlog channel is derived as
`{originSpace}-{channelName}`, where `originSpace` comes from the policy definition.

### Asset example

```yaml
name: output/file-output-integrations/0

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

The `indexer` output sends alerts to `wazuh-indexer` for indexing.

### Signature

```yaml
wazuh-indexer:
    index: ${INDEX}
```

### Parameters

| Name | type | required | Description |
|------|------|----------|-------------|
| index | string | yes | Data stream where the events are indexed. Must follow the index name rules below. |

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
name: output/indexer/0

metadata:
  module: wazuh
  title: Indexer output event
  description: Output integrations events to wazuh-indexer
  compatibility: >
    This decoder has been tested on Wazuh version 5.0
  versions:
    - ""
  author:
    name: Wazuh, Inc.
    date: 2025/12/01
  references:
    - ""

outputs:
  - wazuh-indexer:
      index: "wazuh-events-v5-${wazuh.integration.category}"
```
