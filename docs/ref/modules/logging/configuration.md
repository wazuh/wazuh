# Logging Configuration Reference

Configuration reference for the `logging` section, which selects the format of the daemons' own log
on the manager and on agents. For what it covers, see the [Logging module](README.md).

---

## Configuration

**Configuration file:**
- Manager: `/etc/wazuh-manager/wazuh-manager.conf`, section `<logging>` under `<wazuh_config>`
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
the level. A manager tag has the shape `<daemon>[:<component>[:<sub>]][(<library>)]`: it starts with the
manager daemon name (`wazuh-manager-db`, `wazuh-manager-remoted`, …), a module inside modulesd adds
`:<module>`, a component can add its own `:<part>` levels, and a shared library (the indexer connector, its
health monitor, the HTTP server) appends its name in parentheses to the tag of whoever called it. Examples:

| Tag | Written by |
|---|---|
| `wazuh-manager-modulesd:control` | a modulesd module |
| `wazuh-manager-remoted:client-keys` | a component of remoted's agent-facing module |
| `wazuh-manager-remoted:endpoints(cacerts)` | an endpoint of remoted's agent-facing listener |
| `wazuh-manager-modulesd:vulnerability-scanner:server` | a part of a modulesd module |
| `wazuh-manager-modulesd:inventory-sync-server:async(indexer-connector)` | the indexer connector, called by a part of a module |
| `wazuh-manager-analysisd(monitoring)` | the indexer connector's node health monitor, inside the engine |

Two manager programs that are not
daemons write to the same file under their own name: `wazuh-manager-control` (a refused start, restart, reload or
check, and the credential resolver's lines it relays) and `bin/verify-agent-conf` (`verify-agent-conf`, when it
checks a shared `agent.conf`; the SCA block's lines are reported as `verify-agent-conf:sca`, and some lines of
the AWS and Google Cloud blocks as `verify-agent-conf:aws-s3`, `verify-agent-conf:gcp-pubsub` and
`verify-agent-conf:gcp-bucket` — their value errors, such as `Invalid content for tag '<tag>' at module
'<module>'.`, keep the plain `verify-agent-conf` tag). Agent tags are the agent's daemon names (`wazuh-agentd`,
`wazuh-modulesd:<module>`, …).

### Plain

```text
2026/07/06 12:34:56 wazuh-manager-db: INFO: Started (pid: 12345).
2026/07/06 12:34:56 wazuh-manager-modulesd:control: INFO: Starting control thread.
2026/07/06 12:34:57 wazuh-manager-remoted: INFO: Started (pid: 12350). Legacy listener disabled (remote.legacy.enabled is false).
```

Levels are `DEBUG`, `INFO`, `WARNING`, `ERROR` and `CRITICAL`; the engine
(`wazuh-manager-analysisd`) writes its critical messages as `ERROR`. A daemon running in debug mode (`-d`,
for example after `wazuh-manager-control enable debug` and a restart) adds
`[<pid>] <file>:<line> at <function>():` to the tag, before the level:

```text
2026/07/06 12:34:58 wazuh-manager-modulesd[23059] main.c:179 at main(): DEBUG: Created new thread for the 'control' module.
```

### JSON

```json
{"timestamp":"2026/07/06 12:34:56","tag":"wazuh-manager-db","level":"info","description":"Started (pid: 12345)."}
```

One object per line, with the keys `timestamp`, `tag`, `level` (`debug`, `info`, `warning`,
`error`, `critical`; never `critical` from the engine) and `description`. In debug mode each object also carries `pid`, `file`, `line`
and `routine`.

---

## Rotation

On the manager, `wazuh-manager.log` and `wazuh-manager.json` are rotated daily, and when they exceed a
size threshold, into `logs/wazuh/<YYYY>/<Mon>/wazuh-<DD>.log.gz` and `.json.gz` (with a `-<NNN>` counter
for further rotations of the same day). The rotated files are gzip-compressed by default; with the internal
option `wazuh_modules.manager_task_log_compress=0` they stay plain `.log` and `.json`. The schedule and its internal options are described in
[Recurring manager tasks](../task_manager/schedules.md).

---

## Implementation Notes

- **Reader:** `os_logging_config()` in `src/shared/src/debug_op.c`. On a manager C daemon it reads the
  `logging` section of the effective configuration through the hook `libconfig` registers; with no
  configuration available it falls back to `plain`. The engine has no such hook: it reads the same
  setting through `base::managerConfig::logFormat()` at start-up and writes with its own sink
  (`src/engine/source/base/src/managerLogSink.cpp`). On an agent it reads `ossec.conf` directly.
- **Default file:** the installer writes the block from `etc/templates/config/generic/logging.template`
  (`plain`).

---

## See Also

- [Recurring manager tasks](../task_manager/schedules.md) - Daily and size-based log rotation on the manager
- [Manager Configuration](../../configuration/manager/README.md) - Manager-side configuration overview
- [Agent Configuration](../../configuration/agent/README.md) - Agent-side configuration overview
