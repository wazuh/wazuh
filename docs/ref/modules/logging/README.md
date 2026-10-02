# Logging Module

## Overview

The `logging` section selects the format of the Wazuh daemons' own log: human-readable plain text,
one JSON object per line, or both at once. It is not a daemon: the shared logging code in
`src/shared/src/debug_op.c` (part of `libwazuhshared`) reads the setting the first time a process
logs, and every C/C++ daemon writes its log lines through that code.

| | Manager | Agent |
|---|---|---|
| Configuration | `<logging>` in `/var/wazuh-manager/etc/wazuh-manager.conf` (root `<wazuh_config>`) | `<logging>` in `/var/ossec/etc/ossec.conf` (root `<ossec_config>`) |
| Plain log | `/var/wazuh-manager/logs/wazuh-manager.log` | `/var/ossec/logs/ossec.log` |
| JSON log | `/var/wazuh-manager/logs/wazuh-manager.json` | `/var/ossec/logs/ossec.json` |
| Default | `plain` | `plain` |

On the manager the setting covers every C/C++ daemon, the engine (`wazuh-manager-analysisd`)
included. The two Python daemons keep their own logs and are not affected by it:
`wazuh-manager-apid` writes `logs/api.log` (its format is set in `api.yaml`) and
`wazuh-manager-clusterd` writes `logs/cluster.log`.

## Quick example

Both default configuration files already contain a `<logging>` block; change its `<log_format>`
rather than adding a second block.

```xml,fragment
<wazuh_config>
  <logging>
    <log_format>plain,json</log_format>
  </logging>
  <!-- cluster, indexer and the other sections -->
</wazuh_config>
```

## Documentation

- [Configuration Reference](configuration.md) - The `log_format` option, line formats and examples

## See Also

- [Recurring manager tasks](../task_manager/schedules.md) - Daily and size-based rotation of `wazuh-manager.log` and `wazuh-manager.json`
- [Manager Configuration](../../configuration/manager/README.md) - Manager configuration overview
- [Agent Configuration](../../configuration/agent/README.md) - Agent configuration overview
