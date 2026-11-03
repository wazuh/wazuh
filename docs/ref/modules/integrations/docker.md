# Docker Listener

The Docker listener module forwards the events reported by the Docker daemon on the host where the
agent runs. It is an agent
module, configured in the agent's `ossec.conf`, and is not available on Windows agents (see
[Integrations](README.md)).

## Prerequisites

- Docker running on the agent host, reachable with the Docker SDK's default client settings
  (`docker.from_env()`).
- The `docker` Python package installed for the host's `python3` (`pip3 install docker`). Without it
  the listener exits with `'docker' module needs to be installed.`

## How it works

1. The agent's `wazuh-modulesd` reads the `<wodle name="docker-listener">` block and logs
   `Module docker-listener started.`
2. On the first scheduled run (immediately if `run_on_start` is `yes`, otherwise after `interval`) it
   launches the listener script `wodles/docker/DockerListener`, which stays running and streams
   every Docker event to the manager.
3. While the Docker daemon is not reachable, the listener logs `Docker service is not running.` and
   retries every 5 seconds; when the daemon stops it reconnects the same way. This does not end the
   listener.
4. If the listener process exits, the module logs `Docker-listener finished unexpectedly (code <n>).
   Retrying to run in next scheduled time...` and launches it again at the next scheduled run. After
   `attempts` such exits in total the module logs `Maximum attempts reached to run the listener.
   Exiting...` and stops until the agent restarts. If the script cannot be executed at all (exit code
   127) the module stops at once.

Each event is sent with `integration` set to `docker` and the Docker event under `docker`.

## Configuration example

```xml
<wodle name="docker-listener">
  <disabled>no</disabled>
  <attempts>5</attempts>
  <run_on_start>yes</run_on_start>
  <interval>10m</interval>
</wodle>
```

## Configuration options

| Option | Default | Description |
|--------|---------|-------------|
| `disabled` | `no` | `yes` disables the module (`Module disabled. Exiting...`). |
| `attempts` | `5` | Number of listener exits after which the module stops. Must be a positive integer. |
| `run_on_start` | `no` | `yes` launches the listener as soon as the module starts. |
| `interval` | `60` (seconds) | Wait before the first launch (when `run_on_start` is `no`) and before relaunching an exited listener. Units and the `day`/`wday`/`time` alternatives are described in [Scheduling](README.md#scheduling). |

Any other element makes the configuration fail to load.

## Verify the integration

Restart the agent and look for the module's lines:

```bash
systemctl restart wazuh-agent
grep "docker-listener" /var/ossec/logs/ossec.log
```

`Docker service was started.` confirms the listener is connected to the daemon.
