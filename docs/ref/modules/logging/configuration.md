# Logging Configuration Reference

Complete configuration reference for the Logging module.

The logging module controls the format and output of Wazuh daemon logs. It applies to both manager and agent, allowing logs to be written in plain text or JSON format.

For general logging concepts, see the Wazuh documentation on log management.

---

## Configuration

**Configuration file:**
- Manager: `/var/wazuh-manager/etc/wazuh-manager.conf`
- Agent: `/var/ossec/etc/ossec.conf`

**XML Section:** `<logging>`

**Module:** Both manager and agent

**Internal Options:** None

The logging configuration is a top-level XML block that controls log output format for all Wazuh daemons.

### log_format

Log output format for Wazuh daemon logs.

- **Default value:** `plain`
- **Allowed values:** `plain`, `json`, `plain,json`
- **Note:**
  - `plain` - Human-readable text format (default)
  - `json` - Structured JSON format for log aggregation tools
  - `plain,json` - Output both formats simultaneously (comma-separated)
  - Invalid values cause startup failure with error message
- **File locations:**
  - Manager: `/var/wazuh-manager/logs/wazuh-manager.log`
  - Agent: `/var/ossec/logs/ossec.log`
  - JSON logs (when enabled): same location with `.json` extension

---

## Configuration Examples

The examples use the manager root, `<wazuh_config>`; on an agent the block lives inside `<ossec_config>`. Both default configuration files already contain a `<logging>` block, so change its `<log_format>` rather than adding a second block: the manager refuses to load a duplicate `<logging>` block or root element, and an agent reads only the first `<logging><log_format>`.

### Default Configuration (Plain Text)

Standard plain text logging for human readability:

```xml
<wazuh_config>
  <logging>
    <log_format>plain</log_format>
  </logging>
</wazuh_config>
```

### JSON Logging Only

Structured JSON output for integration with log aggregation systems (Elasticsearch, Splunk, etc.):

```xml
<wazuh_config>
  <logging>
    <log_format>json</log_format>
  </logging>
</wazuh_config>
```

### Dual Output (Plain and JSON)

Output both plain text and JSON logs simultaneously:

```xml
<wazuh_config>
  <logging>
    <log_format>plain,json</log_format>
  </logging>
</wazuh_config>
```

**Use case:** Maintain human-readable logs for troubleshooting while also feeding structured JSON to SIEM/log aggregation tools.

Use a single comma-separated value as shown. The manager also accepts one `<log_format>` element per format, but an agent reads only the first one.

---

## Output Examples

### Plain Format Example

```
2026/07/06 12:34:56 wazuh-manager-remoted: INFO: (1409): Reading authentication keys file.
2026/07/06 12:34:56 wazuh-manager-analysisd: INFO: Started (pid: 12345).
2026/07/06 12:34:57 wazuh-manager-remoted: INFO: Listening on port 1514 (TCP).
```

### JSON Format Example

```json
{"timestamp":"2026-07-06T12:34:56+0000","tag":"wazuh-manager-remoted","level":"info","description":"Reading authentication keys file."}
{"timestamp":"2026-07-06T12:34:56+0000","tag":"wazuh-manager-analysisd","level":"info","description":"Started (pid: 12345)."}
{"timestamp":"2026-07-06T12:34:57+0000","tag":"wazuh-manager-remoted","level":"info","description":"Listening on port 1514 (TCP)."}
```

---

## Implementation Notes

- **Parser location:** The logging configuration parser is implemented in `src/shared/src/debug_op.c` (`os_logging_config()` function)
- **Validation:** Invalid `log_format` values trigger `mlerror_exit` and prevent daemon startup
- **Default file:** The manager default configuration at `/var/wazuh-manager/etc/wazuh-manager.conf` includes this block with `plain` format
- **Scope:** Applies globally to all Wazuh daemons (remoted, analysisd, logcollector, etc.)

---

## See Also

- [Recurring manager tasks](../task_manager/schedules.md) - Daily and size-based log rotation on the manager
- [Manager Configuration](../../configuration/manager/index.md) - Manager-side configuration overview
- [Agent Configuration](../../configuration/agent/index.md) - Agent-side configuration overview
