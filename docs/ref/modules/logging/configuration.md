# Logging Configuration Reference

Configuration reference for the `logging` section, which selects the format of the daemons' own log
on the manager and on agents. For what it covers, see the [Logging module](README.md).

---

## Configuration

**Configuration file:**
- Manager: `/var/wazuh-manager/etc/wazuh-manager.conf`, section `<logging>` under `<wazuh_config>`
- Agent: `/var/ossec/etc/ossec.conf`, section `<logging>` under `<ossec_config>`

**Internal Options:** None

### log_format

Format of the daemon log.

| | Manager | Agent |
|---|---|---|
| Values | `plain`, `json`, or both | `plain`, `json`, or both |
| Default | `plain` | `plain` (also when the element is missing or empty) |
| How to give both | `plain,json` (comma-separated, tokens trimmed), or one `<log_format>` element per format | `plain,json` only: an agent reads the first `<log_format>` element and ignores any other |
| Invalid value | The configuration is rejected: `(1244): Invalid configuration at '/logging/log_format/<n>': …` (keyword `enum`), and `wazuh-manager-control start` refuses to start anything | `(1235): Invalid value for element 'log_format': <value>.` and the daemon exits |

On the manager the option is a list (schema: `minItems` 1, `maxItems` 2, unique items), so an empty
element or a repeated format (`plain,plain`) is rejected as well. Its generated entry is in the
[manager configuration reference](../../configuration/manager/reference.md#logging).

| Value | Writes |
|---|---|
| `plain` | `logs/wazuh-manager.log` (manager), `logs/ossec.log` (agent) |
| `json` | `logs/wazuh-manager.json` (manager), `logs/ossec.json` (agent) |
| `plain,json` | both files, each line to both |

Both default configuration files already contain a `<logging>` block with `plain`; change its
`<log_format>` rather than adding another block. The manager refuses a second `<logging>` element
(`duplicate element <logging>`); an agent reads only the first.

---

## Configuration Examples

The examples use the manager root; on an agent the same block goes inside `<ossec_config>`. They are
fragments: a manager configuration also needs its `cluster` and `indexer` sections.

### Plain text (default)

```xml,fragment
<wazuh_config>
  <logging>
    <log_format>plain</log_format>
  </logging>
</wazuh_config>
```

### JSON only

```xml,fragment
<wazuh_config>
  <logging>
    <log_format>json</log_format>
  </logging>
</wazuh_config>
```

### Both formats

```xml,fragment
<wazuh_config>
  <logging>
    <log_format>plain,json</log_format>
  </logging>
</wazuh_config>
```

---

## Line formats

Every line carries the local time as `YYYY/MM/DD HH:MM:SS`, the tag of the daemon that wrote it, and
the level. Manager tags are the manager daemon names (`wazuh-manager-db`, `wazuh-manager-remoted`,
…); a module inside modulesd logs as `wazuh-manager-modulesd:<module>`. Agent tags are the agent's
daemon names (`wazuh-agentd`, `wazuh-modulesd:<module>`, …).

### Plain

```text
2026/07/06 12:34:56 wazuh-manager-db: INFO: Started (pid: 12345).
2026/07/06 12:34:56 wazuh-manager-modulesd:control: INFO: Starting control thread.
2026/07/06 12:34:57 wazuh-manager-remoted: INFO: Started (pid: 12350). Listening on port 1514/TCP (secure).
```

Levels are `DEBUG`, `INFO`, `WARNING`, `ERROR` and `CRITICAL`. A daemon running in debug mode (`-d`,
for example after `wazuh-manager-control enable debug` and a restart) adds
`[<pid>] <file>:<line> at <function>():` after the tag.

### JSON

```json
{"timestamp":"2026/07/06 12:34:56","tag":"wazuh-manager-db","level":"info","description":"Started (pid: 12345)."}
```

One object per line, with the keys `timestamp`, `tag`, `level` (`debug`, `info`, `warning`,
`error`, `critical`) and `description`. In debug mode each object also carries `pid`, `file`, `line`
and `routine`.

---

## Rotation

On the manager, `wazuh-manager.log` and `wazuh-manager.json` are rotated daily, and when they exceed a
size threshold, into `logs/wazuh/<YYYY>/<Mon>/wazuh-<DD>.log` and `.json` (with a `-<NNN>` counter
for further rotations of the same day). The schedule and its internal options are described in
[Recurring manager tasks](../task_manager/schedules.md).

---

## Implementation Notes

- **Reader:** `os_logging_config()` in `src/shared/src/debug_op.c`. On the manager it reads the
  `logging` section of the effective configuration through the hook `libconfig` registers (the engine
  registers the same hook, so it follows the setting too); with no configuration available it falls
  back to `plain`. On an agent it reads `ossec.conf` directly.
- **Default file:** the installer writes the block from `etc/templates/config/generic/logging.template`
  (`plain`).

---

## See Also

- [Recurring manager tasks](../task_manager/schedules.md) - Daily and size-based log rotation on the manager
- [Manager Configuration](../../configuration/manager/README.md) - Manager-side configuration overview
- [Agent Configuration](../../configuration/agent/README.md) - Agent-side configuration overview
