# Output Reference

The output stage is responsible for sending alerts to different destinations. This stage is only supported by
`outputs assets` and can have multiple outputs. Each output can have its own configuration.


## File

The `file` output sends alerts to a file. This output supports compression and rotation.

### Signature

```yaml
file: "alerts"
```

### Parameters

Only support "alerts" as a parameter, this writes alerts to `alerts.json` file.

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
  - file: "alerts"
```

## Indexer

The `indexer` output sends alerts to `wazuh-index` for indexing.

### Signature

```yaml
wazuh-indexer:
    index: ${INDEX}
```

### Parameters

| Name | type | required | Description |
|------|------|----------|-------------|
| index | string | yes | Index name where the alerts will be indexed. Should be a valid Elasticsearch index name and start with `wazuh-`. |

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
    date: 2024/12/01
  references:
    - ""

outputs:
  - wazuh-indexer:
      index: wazuh-alerts-$(DATE)
```

> [!TIP]
> The `$(DATE)` macro is replaced by the current date in the format `YYYY.MM.DD` when the alert is indexed.
