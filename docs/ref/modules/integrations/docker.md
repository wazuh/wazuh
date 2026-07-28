# Docker Listener

The Docker listener wodle monitors Docker events on the host where it runs. It connects to the Docker daemon and collects container lifecycle events and metadata on a configurable schedule.

Source: `src/config/src/wmodules-docker.c`

## How it works

1. `wazuh-modulesd` (manager) or `wazuh-agentd` (agent) loads the `<wodle name="docker-listener">` block.
2. On the first scheduled run (or immediately if `run_on_start` is set to `yes`), the module connects to the local Docker daemon socket.
3. If the connection fails, it retries up to `attempts` times (default 5) before giving up for that cycle.
4. Docker events are collected and forwarded to the analysis engine as structured events.

## Configuration example

```xml
<wodle name="docker-listener">
  <disabled>no</disabled>
  <attempts>5</attempts>
  <run_on_start>no</run_on_start>
  <interval>60s</interval>
</wodle>
```

## Configuration options

| Option | Default | Description |
|--------|---------|-------------|
| `disabled` | `no` | Enable or disable the Docker listener |
| `attempts` | `5` | Number of retry attempts to connect to Docker daemon |
| `run_on_start` | `no` | Run immediately on module start |
| `interval` | `60s` | Time between collection cycles. Accepts time suffixes: `s`, `m`, `h`, `d` |
