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

### Default Configuration (Plain Text)

Standard plain text logging for human readability:

```xml
<ossec_config>
  <logging>
    <log_format>plain</log_format>
  </logging>
</ossec_config>
```

### JSON Logging Only

Structured JSON output for integration with log aggregation systems (Elasticsearch, Splunk, etc.):

```xml
<ossec_config>
  <logging>
    <log_format>json</log_format>
  </logging>
</ossec_config>
```

### Dual Output (Plain and JSON)

Output both plain text and JSON logs simultaneously:

```xml
<ossec_config>
  <logging>
    <log_format>plain,json</log_format>
  </logging>
</ossec_config>
```

**Use case:** Maintain human-readable logs for troubleshooting while also feeding structured JSON to SIEM/log aggregation tools.

---

## Output Examples

### Plain Format Example

```
2026/07/06 12:34:56 wazuh-remoted: INFO: (1409): Reading authentication keys file.
2026/07/06 12:34:56 wazuh-analysisd: INFO: Started (pid: 12345).
2026/07/06 12:34:57 wazuh-remoted: INFO: Listening on port 1514 (TCP).
```

### JSON Format Example

```json
{"timestamp":"2026-07-06T12:34:56+0000","tag":"wazuh-remoted","level":"info","description":"Reading authentication keys file."}
{"timestamp":"2026-07-06T12:34:56+0000","tag":"wazuh-analysisd","level":"info","description":"Started (pid: 12345)."}
{"timestamp":"2026-07-06T12:34:57+0000","tag":"wazuh-remoted","level":"info","description":"Listening on port 1514 (TCP)."}
```

---

## Implementation Notes

- **Parser location:** The logging configuration parser is implemented in `src/shared/src/debug_op.c` (`os_logging_config()` function)
- **Validation:** Invalid `log_format` values trigger `mlerror_exit` and prevent daemon startup
- **Default file:** The manager default configuration at `/var/wazuh-manager/etc/wazuh-manager.conf` includes this block with `plain` format
- **Scope:** Applies globally to all Wazuh daemons (remoted, analysisd, logcollector, etc.)

---

## See Also

- [Monitord Configuration](../monitord/configuration.md) - Daemon monitoring and log rotation
- [Manager Configuration](../../configuration/manager/index.md) - Manager-side configuration overview
- [Agent Configuration](../../configuration/agent/index.md) - Agent-side configuration overview
