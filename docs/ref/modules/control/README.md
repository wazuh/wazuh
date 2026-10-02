# Control Module (wm_control)

The **Control Module** restarts or reloads the Wazuh manager, or a Unix agent, on request. It listens
on a local Unix domain socket and accepts exactly two commands, `restart` and `reload`. It is
implemented in a single source file (`src/wazuh_modules/src/wm_control.c`) that compiles differently
depending on the build target:

- **Manager** (`TARGET=manager`): runs inside `wazuh-manager-modulesd` and hands every accepted
  command to the setuid helper [`wazuh-manager-service-control`](#wazuh-manager-service-control),
  because modulesd itself runs unprivileged as `wazuh-manager`.
- **Unix agent** (`CLIENT` defined): runs inside the agent's `wazuh-modulesd` and runs
  `systemctl <action> wazuh-agent` or `bin/wazuh-control <action>` itself (on macOS it asks the
  launcher to do it, see [Architecture](architecture.md#agent-side-unix)).

On **Windows agents** the equivalent logic is `control_dispatch()` in `src/client-agent/src/control.c`,
called in-process by `wazuh-agentd`; there is no socket.

The module has no configuration section: it is always added on Linux, macOS and the BSDs
(`wm_config()` in `src/wazuh_modules/src/wmodules.c`) and logs under the tag
`wazuh-manager-modulesd:control` on the manager (`wazuh-modulesd:control` on an agent).

## Socket interface

| Component | Socket path | Framing |
|-----------|-------------|---------|
| Manager | `/var/wazuh-manager/queue/sockets/control.sock` | Raw bytes: one command per connection, no length header |
| Agent (Unix) | `/var/ossec/queue/sockets/control` | Wazuh secure framing (4-byte length header) |

Both are `SOCK_STREAM` sockets created with mode `0660`, owned by the daemon's user and the Wazuh
group. The paths are `CONTROL_SOCK` in `src/shared/include/defs.h`; the framework uses
`common.CONTROL_SOCKET` for the manager one.

### Manager commands

| Request | Response | Meaning |
|---------|----------|---------|
| `restart` | `ok accepted` | `wazuh-manager-service-control` validated the request and is about to restart the manager |
| `reload` | `ok accepted` | Same, for a reload |
| `restart` / `reload` | `err Service control rejected action` | The helper refused the request, or did not confirm it within 5 seconds |
| `restart` / `reload` | `err Cannot create service control pipe`, `err Cannot fork` | modulesd could not start the helper |
| `<command> <args>` | `err Unexpected arguments` | Any argument after the command is rejected |
| anything else | `Err` | Unknown command (logged as `Unknown command: '<command>'`) |

The manager also checks the peer's credentials (`SO_PEERCRED`): a connection from any user other than
`root` or `wazuh-manager` is closed without an answer and logged as
`Rejected unauthorized control socket peer.`

`ok accepted` means the action was **accepted**, not that it finished: the restart or reload runs
afterwards, in a process modulesd does not wait for.

### Agent commands

| Request | Response (Unix) | Response (Windows) |
|---------|-----------------|--------------------|
| `restart` | `ok ` | `ok ` |
| `reload` | `ok ` | `ok ` |
| anything else | `Err` | `err Unrecognized command` |

On the agent, anything after the first space is ignored rather than rejected. On Windows, `reload` is a
full stop and start of the service, as `restart` is.

## Manager restart and reload

The Server API is the usual client: `PUT /cluster/restart` and `PUT /cluster/reload` call
`manager_restart()` / `manager_reload()` in `framework/wazuh/core/cluster/utils.py`, which send the
command to `control.sock` and require an answer starting with `ok`.

| Error | When |
|-------|------|
| `1901` *Control socket has not been created* | `control.sock` does not exist (modulesd is not running) |
| `1902` *Connection to control socket failed* | The socket exists but the connection failed |
| `1014` *Error communicating with socket* | The answer did not start with `ok` (for example `err Service control rejected action`), or the exchange failed |

Both routes require the `cluster:read` and `cluster:restart` RBAC actions.

### wazuh-manager-service-control

`/var/wazuh-manager/bin/wazuh-manager-service-control` (source `src/util/manager_service_control/main.c`)
is the only path from `wm_control` to the manager service. It is installed `root:wazuh-manager`, mode
`4750` (set-user-ID root).

```text
Usage: wazuh-manager-service-control {restart|reload}
       wazuh-manager-service-control -h
```

It accepts exactly one argument. It runs only when the **real** user is `root` or `wazuh-manager`
(the effective user being `root` through the setuid bit), and only if its own file, the install
directory, `bin/`, `bin/wazuh-manager-control` and, when present, `bin/.process_list` are owned by
`root` and not group- or world-writable — and its own file still carries the setuid bit. It then
clears the environment (`PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LANG=C`), reports acceptance to
modulesd and becomes `root` before running:

| Action | systemd is PID 1 | No systemd |
|--------|------------------|------------|
| `restart` | `/usr/bin/systemctl restart wazuh-manager.service` | `bin/wazuh-manager-control restart` |
| `reload` | polls `systemctl is-active wazuh-manager.service` once a second, up to 60 times: `active` → `systemctl reload wazuh-manager.service`; `inactive` or `failed` → `bin/wazuh-manager-control reload`; any other state → wait | `bin/wazuh-manager-control reload` |

The unit's `ExecReload` is `wazuh-manager-control reload`, which restarts every daemon except
`wazuh-manager-remoted`, so agent connections stay up.

On any refusal it prints `wazuh-manager-service-control: <reason>` on standard error and exits `1`;
`-h` prints the usage and exits `0`. When modulesd runs it, standard error is not the manager log, so
the only trace there is modulesd's `Privileged service control rejected or could not execute '<action>'`.
A failure after acceptance (for example `cannot determine a safe manager service state` when the unit
never settles during the 60 seconds) leaves no trace in `logs/wazuh-manager.log` at all; check
`systemctl status wazuh-manager` or `wazuh-manager-control status`.

Run by hand (as `root`), it does exactly what an API restart does:

```bash
/var/wazuh-manager/bin/wazuh-manager-service-control restart
```

## Agent restart and reload

The API never connects to an agent's control socket. For agents on **v5.0.0 or later**,
`PUT /agents/restart`, `PUT /agents/{agent_id}/restart`, `PUT /agents/group/{group_id}/restart` and the
matching `reload` routes create one `agent_restart` or `agent_reload` task per agent in the Task
Manager (`POST /v1/tasks/bulk` on `queue/sockets/task-http.sock`, up to 500 agents per request, empty
payload). The agent fetches the task on its next `POST /control` poll to `wazuh-manager-remoted`, and
`wazuh-agentd` hands it to the control socket (Unix) or to `control_dispatch()` (Windows). The Task
Manager marks the task delivered when it hands it out; **no result comes back to the manager**. The
full flow is in [Architecture](architecture.md#remote-agent-restartreload-request-flow).

The routes require `agent:restart` or `agent:reload`. Framework code:
`framework/wazuh/agent.py` (`restart_agents()`, `reload_agents()` and their `_by_group` variants) and
`framework/wazuh/core/agent_tasks.py` (`core_restart_agents()`, `core_reload_agents()`).

### Agent version requirement and error codes

The target agent must run **v5.0.0 or later**; an older agent is answered with error `1761`.

A manager only knows the version of the agents that have connected to **it**, and it answers error `1774` ("the agent has never connected to this node, which holds no information about it") for any agent it has no version for, rather than `1761`, which would blame a version it has never seen. This applies to a single manager as much as to a cluster: **an agent that is registered but has never connected is answered with `1774`, on every deployment.**

**`1774` does not mean the command was dropped.** The task is created either way, and the agent runs it on its first poll within `task-manager.task_ttl` (1 h by default), after which the unfetched copy expires and is logged at debug level. The response message ("Restart command was not sent to some agents", or "Reload …") is the generic one for a result with failed items — **do not send the request again on account of a `1774`**: task ids are derived from the request's timestamp, so a second request creates a second task and the agent runs both. `1727` is the answer when the task could *not* be created.

In a cluster this is what makes the per-node breakdown readable. The request is broadcast to every node — 5.x agents connect over stateless, load-balanced HTTPS and have no fixed owning node, so the task is created everywhere and the agent, which discards a task id it has already run, runs it once wherever it polls. `1774` is then a per-node answer, so read it in the `nodes` field: a merge drops it as soon as any node reports that agent as affected, and it reaches the top level only when no node has ever seen the agent.

### Verifying the result

Nothing reports completion. A restarted agent reconnects; check its status and `lastKeepAlive` with
`GET /agents?agents_list=<id>`, or the agent's own log (`/var/ossec/logs/ossec.log`), where
`wazuh-agentd` logs `https_client: task <id> (agent_restart) dispatched.` or `... failed to dispatch.`

## Example: the manager socket

```python
import socket

def send_control_command(command):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect('/var/wazuh-manager/queue/sockets/control.sock')
    sock.send(command.encode())
    response = sock.recv(1024).decode().strip()
    sock.close()
    return response

result = send_control_command('restart')  # "ok accepted"
```

Run it as `root` or `wazuh-manager`; any other user is disconnected without an answer.

## Related modules

- **wazuh-manager-modulesd / wazuh-modulesd**: host daemon for `wm_control` (manager and Unix agent)
- **wazuh-manager-remoted**: serves the agent's `POST /control` poll that delivers restart and reload tasks
- **wazuh-agentd**: receives the task and forwards it to the control socket (Unix) or calls `control_dispatch()` (Windows)
- **wazuh-manager-apid**: calls the control socket for `PUT /cluster/restart` and `PUT /cluster/reload`
- [Task Manager](../task_manager/README.md): stores the `agent_restart` / `agent_reload` tasks

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Components, data flows, privilege model and the 4.x migration |

## See Also

- [Server API Reference](../server-api/api-reference.md) - API endpoints that use the control channel
- [RBAC](../rbac/README.md) - `agent:reload`, `agent:restart` and `cluster:restart` RBAC actions
