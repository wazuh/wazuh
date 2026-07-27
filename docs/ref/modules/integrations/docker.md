# Docker Listener

The Docker listener wodle monitors Docker events on the host where it runs. It connects to the Docker daemon and collects container lifecycle events and metadata on a configurable schedule.

Source: `src/config/src/wmodules-docker.c`

For the full per-option reference see [Wodle: Docker Listener Configuration](../../configuration/wodle-docker.md).

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

For all options see [Wodle: Docker Listener Configuration](../../configuration/wodle-docker.md).
