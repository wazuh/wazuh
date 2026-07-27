# Wodle: Docker Listener Configuration

The `<wodle name="docker-listener">` section monitors Docker events and container metadata on a schedule. It is available on both agents and the manager.

Configuration file: `/var/wazuh-manager/etc/wazuh-manager.conf`

Parser: `src/config/src/wmodules-docker.c`

## Configuration Options

### disabled

Disables the Docker listener.

- **Default value**: `no`
- **Allowed values**: `yes`, `no`

### attempts

Maximum number of connection attempts to the Docker daemon before giving up.

- **Default value**: `5`
- **Allowed values**: Positive integer (> 0); the parser rejects 0 and negative values

### run_on_start

Poll Docker immediately when the module starts, before waiting for the first scheduled time.

- **Default value**: `no`
- **Allowed values**: `yes`, `no`

### interval

Time between polling cycles.

- **Default value**: `60s`
- **Allowed values**: Positive number followed by a suffix: `s` (seconds), `m` (minutes), `h` (hours), `d` (days), `w` (weeks), `M` (months)

### day

Day of the month for scheduled polling. If the configured interval is not a month-based value, the scheduler normalizes it to `1M` with a warning. Cannot be combined with `wday`.

- **Default value**: none
- **Allowed values**: Integer from `1` to `31`

### wday

Day of the week for scheduled polling. If the configured interval is not a weekly multiple, the scheduler normalizes it to `1w` with a warning. Cannot be combined with `day`.

- **Default value**: none
- **Allowed values**: `sunday`, `monday`, `tuesday`, `wednesday`, `thursday`, `friday`, `saturday`

### time

Time of day for scheduled polling, in `HH:MM` format.

- **Default value**: none
- **Allowed values**: `HH:MM`

## Configuration Example

```xml
<wodle name="docker-listener">
  <disabled>no</disabled>
  <attempts>5</attempts>
  <run_on_start>no</run_on_start>
  <interval>60s</interval>
</wodle>
```

Scheduled daily at midnight:

```xml
<wodle name="docker-listener">
  <disabled>no</disabled>
  <attempts>3</attempts>
  <run_on_start>no</run_on_start>
  <interval>1d</interval>
  <time>00:00</time>
</wodle>
```
