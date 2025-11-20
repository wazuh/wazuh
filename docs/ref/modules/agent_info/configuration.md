# Configuration

The `agent_info` module is configured in the `ossec.conf` file. It defines the scan intervals, synchronization parameters, and module behavior.

---

## Example Configuration

```xml
<agent_info>
  <interval>60</interval>
  <integrity_interval>86400</integrity_interval>
  <synchronization>
    <enabled>yes</enabled>
    <sync_end_delay>1s</sync_end_delay>
    <response_timeout>30s</response_timeout>
    <retries>5</retries>
    <max_eps>10</max_eps>
  </synchronization>
</agent_info>
```

---

## Configuration Options

### Core Settings

| Option               | Type    | Default | Description                                                                                                 |
| -------------------- | ------- | ------- | ----------------------------------------------------------------------------------------------------------- |
| `interval`           | integer | `60`    | Time between periodic scans to collect agent metadata in seconds.                                           |
| `integrity_interval` | integer | `86400` | Time between integrity checks to verify that the agent's state is synchronized with the manager in seconds. |

### Synchronization Settings

The `<synchronization>` block configures the coordination protocol used when agent metadata or group memberships change.

| Option             | Type    | Default | Description                                                                                       |
| ------------------ | ------- | ------- | ------------------------------------------------------------------------------------------------- |
| `enabled`          | boolean | `yes`   | Enables or disables the module coordination and synchronization features.                         |
| `sync_end_delay`   |  time   | `1s`    | Delay in seconds before sending the synchronization end message.                                  |
| `response_timeout` |  time   | `30s`   | Timeout in seconds to wait for a response from other modules during coordination.                 |
| `retries`          | integer | `5`     | Number of retry attempts when a coordination command fails.                                       |
| `max_eps`          | integer | `10`    | Maximum events per second to send during synchronization.                                         |

---

## Time Interval Format

The `sync_end_delay` and `response_timeout` options support various time formats:

| Format  | Example | Description              |
| ------- | ------- | ------------------------ |
| Seconds | `300s`  | 300 seconds              |
| Minutes | `30m`   | 30 minutes               |
| Hours   | `2h`    | 2 hours                  |
| Days    | `1d`    | 1 day                    |

---

## Configuration Validation

The module performs the following validation at startup:
- **Boolean Values**: Ensures boolean values are either `yes` or `no`.
- **Time Values**: Ensures time values are in valid formats and within acceptable ranges.
- **Integer Values**: Ensures integer values are in valid ranges.

If the configuration is invalid, the module will log a warning and use default values or, in case of critical errors, fail to start.
