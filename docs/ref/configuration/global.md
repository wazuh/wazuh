# Global Configuration

The `<global>` section sets manager-wide timing parameters for agent disconnection detection and alerting.

Configuration file: `/var/wazuh-manager/etc/wazuh-manager.conf`

Parser: `src/config/src/global-config.c`

## Configuration Options

### agents_disconnection_time

Time without communication after which an agent is marked as disconnected.

- **Default value**: `15m` (900 s)
- **Allowed values**: Positive integer with optional time unit suffix — `s` (seconds), `m` (minutes), `h` (hours), `d` (days). Minimum: 1 second.

### agents_disconnection_alert_time

Time after an agent disconnects before a disconnection alert is generated. Set to `0` to disable disconnection alerts.

- **Default value**: `0`
- **Allowed values**: Non-negative integer with optional time unit suffix — `s`, `m`, `h`, `d`. `0` disables the alert.

## Configuration Example

```xml
<global>
  <agents_disconnection_time>15m</agents_disconnection_time>
  <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
</global>
```
