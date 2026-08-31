# Logging Module

## Overview

The Logging module controls the format and output of Wazuh daemon logs for both manager and agent components. It provides flexible log formatting options to support human-readable plain text output, structured JSON for integration with log aggregation tools, or both simultaneously.

## Key Features

- **Plain text format** - Human-readable logs for troubleshooting and manual review
- **JSON format** - Structured logs for SIEM integration (Elasticsearch, Splunk, etc.)
- **Dual output** - Produce both formats simultaneously for maximum flexibility
- **Global scope** - Applies to all Wazuh daemons (remoted, analysisd, logcollector, etc.)

## Configuration

The logging module is configured via the `logging` section of the manager configuration (`etc/wazuh-manager.yml`) — on agents, the `<logging>` XML block of `ossec.conf`:

- **Manager:** `/var/wazuh-manager/etc/wazuh-manager.yml`
- **Agent:** `/var/ossec/etc/ossec.conf`

### Quick Example

```yaml
logging:
  log_format:
  - plain
```

## Log Files

Wazuh daemon logs are written to:

- **Manager:** `/var/wazuh-manager/logs/wazuh-manager.log` (plain) or `.json` (JSON format)
- **Agent:** `/var/ossec/logs/ossec.log` (plain) or `.json` (JSON format)

## Use Cases

- **Plain text logs** - Default format for human readability and troubleshooting
- **JSON logs** - Enable structured logging for centralized log management systems
- **Dual output** - Maintain both formats when you need human-readable logs for support while feeding JSON to your SIEM

## Documentation

- [Configuration Reference](configuration.md) - Complete configuration options and examples

## Implementation

The logging configuration parser is implemented in `src/shared/src/debug_op.c` and is loaded during daemon initialization. Invalid `log_format` values will prevent daemon startup.

## See Also

- [Monitord Module](../monitord/configuration.md) - Daemon monitoring and log rotation
- [Manager Configuration](../../configuration/manager/README.md) - Manager configuration overview
- [Agent Configuration](../../configuration/agent/README.md) - Agent configuration overview
