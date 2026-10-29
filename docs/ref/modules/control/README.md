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
| `<command> <args>` | `err Unexpected arguments` | Any argument after the command is rejected (logged as a warning, `Unexpected arguments for command: '<command>'`) |
| anything else | `Err` | Unknown command (logged as `Unknown command: '<command>'`) |

A `<command>` is logged as the client sent it, made safe for a one-line log: `\n`, `\r`, `\t` and `\\` stand
for a newline, carriage return, tab and backslash, any other control or non-ASCII byte is written `\xHH`, and only
the first 128 bytes are kept — a longer command ends in `...[truncated]`.

Every manager reply ends in a NUL byte (`ok accepted\0`, `Err\0`): strip it, not only whitespace, before
comparing (`.rstrip('\x00')` in Python).

The manager also checks the peer's credentials (`SO_PEERCRED`): a connection from any user other than
`root` or `wazuh-manager` is closed without an answer and logged as
`Rejected unauthorized control socket peer.`

The manager socket serves **one client at a time**: the next connection waits in the listen backlog until
the current one is answered and closed. A client that connects and sends nothing within **3 seconds** is
disconnected without an answer and logged as a warning,
`A local client sent no command within 3 seconds; connection closed.`, so one idle client cannot hold the
socket for longer than that. The limit is **per client**, though, and clients are served one after another:
idle clients waiting in the backlog add up, 3 seconds each, so four of them delay the next command by about
12 seconds — longer than the API's default `request_timeout` of 10 seconds. While modulesd itself is stopped or busy, a connection is accepted by the
kernel but not served: the API's `PUT /cluster/restart` or `PUT /cluster/reload` can then time out (it does
not fall back to the helper, which it runs only when the socket is missing or refuses the connection), and
the queued command **is still carried out** once modulesd reads it. Check `wazuh-manager-control status`
before retrying a restart that timed out.

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
command to `control.sock` and require an answer starting with `ok`. When `control.sock` does not exist or
refuses the connection (modulesd is not running), the API runs
[`wazuh-manager-service-control`](#wazuh-manager-service-control) itself, as `wm_control` would, and logs
`Control socket has not been created. Using wazuh-manager-service-control` (or the connection error) as a
warning in `logs/api.log`, followed by `Manager restart accepted by wazuh-manager-service-control` (or `run
by`) at info level; on a worker restarted through the master these lines go to the worker's
`logs/cluster.log`. A manager whose modulesd died can still be restarted remotely.

| Error | When |
|-------|------|
| `1903` *The manager service-control helper could not be run* | The socket is unavailable and the helper could not be started (missing, wrong owner or mode) |
| `1904` *The manager service-control helper refused the restart request* (or *reload*) | The socket is unavailable and the helper refused the request, did not accept it within 5 seconds, or its check refused the restart within 4 seconds of accepting it; the message carries the helper's exit code and output |
| `1014` *Error communicating with socket* | The answer did not start with `ok` (for example `err Service control rejected action`), or the exchange failed |

Both routes require the `cluster:read` and `cluster:restart` RBAC actions.

### wazuh-manager-service-control

`/var/wazuh-manager/bin/wazuh-manager-service-control` (source `src/util/manager_service_control/main.c`)
is the only path from `wm_control` to the manager service. It is installed `root:wazuh-manager`, mode
`4750` (set-user-ID root).

```text
Usage: wazuh-manager-service-control {restart|reload}
       wazuh-manager-service-control -h

Commands:
  restart  Restart the Wazuh manager service
  reload   Reload the Wazuh manager while keeping agent connections active

Options:
  -h       Show this help
```

It accepts exactly one argument. It runs only when the **real** user is `root` or `wazuh-manager`
(the effective user being `root` through the setuid bit), and only if its own file, the install
directory, `bin/`, `bin/wazuh-manager-control` and, when present, `bin/.process_list` are owned by
`root` and not group- or world-writable — and its own file still carries the setuid bit. It then
clears the environment (`PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LANG=C`), reports acceptance to
modulesd and becomes `root` before running:

| Action | systemd is PID 1 | No systemd |
|--------|------------------|------------|
| `restart` | `bin/wazuh-manager-control check`, then `/usr/bin/systemctl restart wazuh-manager.service` | `bin/wazuh-manager-control restart` (it runs the same checks before stopping anything) |
| `reload` | polls `systemctl is-active wazuh-manager.service` once a second, up to 60 times: `active` → `bin/wazuh-manager-control check`, then `systemctl reload wazuh-manager.service`; `inactive` or `failed` → `bin/wazuh-manager-control reload`; any other state, or a failed query → wait | `bin/wazuh-manager-control reload` (it runs the same checks before stopping anything) |

The unit's `ExecStop` stops every daemon before its `ExecStart` checks anything, so before handing a
restart or reload to systemd the helper runs [`wazuh-manager-control check`](../../architecture.md#wazuh-manager-control)
— the configuration, the credentials and every daemon's `-t`, without stopping or starting anything — as
`root`, with the cleared environment. When the check fails the helper calls no `systemctl`, prints
`wazuh-manager-service-control: the manager configuration or credentials check failed; the manager was not restarted`
on standard error and exits `1`: the manager keeps running on its previous configuration, and the check's own
`wazuh-manager-control: ERROR: …` lines are in `logs/wazuh-manager.log`. Without systemd,
`wazuh-manager-control restart|reload` runs the same checks before it stops anything.

The unit's `ExecReload` is `wazuh-manager-control reload`, which restarts every daemon except
`wazuh-manager-remoted`, so agent connections stay up. On a systemd host this helper and the unit keep the
daemons inside the unit; `wazuh-manager-control` run by hand acts on the daemons itself and does not (see
[`wazuh-manager-control`](../../architecture.md#wazuh-manager-control)).

On any refusal it prints `wazuh-manager-service-control: <reason>` on standard error and exits `1`;
`-h` prints the usage and exits `0`. When modulesd runs it, standard error is not the manager log, so
the only trace there is modulesd's `Privileged service control rejected or could not execute '<action>'`.
The check runs **after** acceptance. Through `wm_control` the API has already answered `202` (`Restart request
sent`, or `Reload request sent`) when a check refuses the restart, and the reason is only in `logs/wazuh-manager.log` (the check's lines). When the API runs
the helper itself (modulesd is down), it waits up to 4 seconds after acceptance: a refusal in that time comes
back as error `1904`; a later one is logged in `logs/api.log` (`The manager restart run by
wazuh-manager-service-control failed (exit code 1): …`). Any
other failure after acceptance (for example `cannot determine a safe manager service state` when the unit
never settles during the 60 seconds) leaves no trace in `logs/wazuh-manager.log`; check
`systemctl status wazuh-manager` or `wazuh-manager-control status`. A daemon that passes the check but then
does not start (an engine that dies on an out-of-range internal option, for example) fails the start, and the
start stops every daemon it had already launched: a failed restart leaves the manager stopped, a failed reload
leaves only `wazuh-manager-remoted` running, never a partial set inside a failed unit.

Run by hand (as `root`), it does exactly what an API restart does:

```bash
/var/wazuh-manager/bin/wazuh-manager-service-control restart
```

### A daemon that dies is not restarted

Restart and reload are the only recovery the manager has: nothing supervises the daemons. The unit
(`Type=forking`, `RemainAfterExit=yes`, no `Restart=`) stays `active` when one of them crashes;
`wazuh-manager-control status` reports it as `not running...` and exits `1`. Recover with
`wazuh-manager-control check && systemctl restart wazuh-manager`, or remotely with `PUT /cluster/restart`.
A plain `systemctl restart` runs no check before its `ExecStop`: when the start that follows refuses the
configuration or a credential, the manager stays **down** until it is fixed and started. Check first (the
API's helper does), or use `wazuh-manager-control restart`, which refuses before it stops anything but
relaunches the daemons outside the unit (see
[`wazuh-manager-control`](../../architecture.md#wazuh-manager-control)). While one of the core daemons
(`wazuh-manager-modulesd`, `-remoted`, `-analysisd`, `-db`) is down, the Server API still answers login, the
status queries and the restart and reload endpoints, and every other call with error `1017`. `wm_control`
lives in `wazuh-manager-modulesd`; with modulesd down the API runs `wazuh-manager-service-control` itself
(see [Manager restart and reload](#manager-restart-and-reload)), so `PUT /cluster/restart` still works as long
as `wazuh-manager-apid` runs. From a shell, `wazuh-manager-control start` relaunches only the dead daemon,
outside the unit.

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

**`1774` does not mean the command was dropped.** The task is created either way, and the agent runs it on its first poll within `task-manager.task_ttl` (1 h by default), after which the unfetched copy expires and is logged at debug level. The response message ("Restart command was not sent to some agents", or "Reload …") is the generic one for a result with failed items — **do not send the request again on account of a `1774`**: task ids are derived from the request's timestamp, so a second request creates a second task and the agent runs both. `1775` ("The task could not be created") is the answer when the task could *not* be created: nothing was queued, so that request can be sent again.

In a cluster this is what makes the per-node breakdown readable. The request is broadcast to every node — 5.x agents connect over stateless, load-balanced HTTPS and have no fixed owning node, so the task is created everywhere and the agent, which discards a task id it has already run, runs it once wherever it polls. `1774` is then a per-node answer, so read it in the `nodes` field: a merge drops it as soon as any node reports that agent as affected, and it reaches the top level only when no node has ever seen the agent.

An id named in `agents_list` that is not registered is answered with `1701` ("Agent does not exist"), and one the caller may not act on with `4000`, exactly as for a single agent — broadcasting does not make them disappear. A node whose replicated `client.keys` has not caught up yet may answer `1701` for an agent another node knows; the merge drops that answer in favour of the other node's, so `1701` reaches the top level only when no node knows the agent. Omitting `agents_list` (all agents) reports neither.

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
    response = sock.recv(1024).decode().rstrip('\x00')
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
