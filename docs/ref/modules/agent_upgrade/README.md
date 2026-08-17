# Agent Upgrade

The agent upgrade module handles remote agent upgrades using WPK (Wazuh Package Kit) files. It has two roles depending on where it runs:

- **Manager side** — validates upgrade requests coming from the Server API, resolves the target WPK for each agent, and creates a `remote_upgrade` task in the [Task Manager](../task_manager/README.md) with the metadata the agent will need to fetch and install the package.
- **Agent side** — listens on the agent's local `queue/sockets/upgrade` socket and executes the `upgrade` command issued by the agent daemon once the WPK has been downloaded. After the agent restarts, it reports the outcome as a stateless event and erases its local `upgrade_result` file.

Source: [src/wazuh_modules/src/agent_upgrade/](../../../../src/wazuh_modules/src/agent_upgrade/)

For configuration options see [Agent Upgrade Configuration](configuration.md).

---

## What is a WPK file

A WPK is a signed, compressed archive containing the Wazuh agent binaries and an installer script (`upgrade.sh` on Linux/macOS, `upgrade.bat` on Windows) for a specific platform and version. Each WPK is distributed together with a SHA-1 checksum used to validate the file end-to-end.

The default repository URL is auto-derived from the manager version as `packages.wazuh.com/<major>.x/wpk/`. A custom URL can be set with the `wpk_repository` option in the manager configuration.

---

## Manager-side flow

```
API / agent_upgrade CLI  ──►  queue/tasks/upgrade  (agent_upgrade manager)
                                     │
                                     ▼
                       Validate agent, platform and version
                                     │
                                     ▼
             Resolve WPK, download and SHA-1-verify it locally
                                     │
                                     ▼
                       queue/tasks/task  (Task Manager)
                       ┌──────────────────────────────────┐
                       │ action:      create_task         │
                       │ task_type:   remote_upgrade      │
                       │ agent_id:    <id>                │
                       │ create_time: <request timestamp> │
                       │ payload:                         │
                       │   wpk_file:  <WPK filename>      │
                       │   wpk_sha1:  <hex digest>        │
                       │   installer: upgrade.sh|.bat     │
                       └──────────────────────────────────┘
```

The manager-side module does **not** send WPK data to the agent directly. Once the task has been stored in the Task Manager, the module is done with that request. Task delivery depends on the target agent's version:

**5.x agents** pull the task from the manager's HTTPS control endpoint on their next poll, download the WPK through the same HTTPS interface, and hand the file off to their local upgrade module for installation.

A **4.x agent** installs the WPK with its own 4.x upgrade module, which is why a 5.0.0 WPK still has to be consumable by 4.x code: the WPK's `upgrade.sh` / `upgrade.bat` and `pkg_installer.sh` run under the agent being replaced, not under 5.x. Getting a task's WPK to a 4.x agent is not handled by this module.

Because task IDs are derived deterministically from `agent_id`, `task_type`, `create_time`, and the request timestamp forwarded from the API, the same upgrade request routed to different manager nodes produces the same `task_id` and does not double-schedule the upgrade.

**Custom WPK files in cluster environments:** When using the `/agents/upgrade_custom` API endpoint
with a local WPK file (via the `file_path` parameter), you must ensure the specified file exists at
the same absolute path on **all manager nodes** in the cluster. The manager that receives the API
request validates and creates the task, but the agent may connect to a different cluster node to
download the WPK. If the file is missing on that node, the upgrade will fail.

### Version constraints

| Condition                                                       | Behavior                                                                                   |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Agent below `v3.0.0`                                            | Rejected — minimum supported version                                                       |
| Upgrade target ≥ `v5.0.0` and current agent version < `v4.14.0` | Rejected with `Direct upgrade to v5.0.0 is not supported. Please upgrade to v4.14.x first` |
| Target version ≤ current agent version                          | Rejected unless `force_upgrade` is set                                                     |
| Target version > manager version                                | Rejected unless `force_upgrade` is set                                                     |
| Upgrade target ≥ `v5.0.0` and `remoted`'s `<remote><https><verification_mode>` is not `none` | Rejected (repo-based path: unless `force_upgrade` is set, with a logged warning; custom-WPK path: unconditionally, no `force` bypass exists there) |

### Manager-side sockets

| Socket                | Direction | Purpose                                                            |
| --------------------- | --------- | ------------------------------------------------------------------ |
| `queue/tasks/upgrade` | Inbound   | Receives `upgrade` / `upgrade_custom` commands from the Server API |
| `queue/tasks/task`    | Outbound  | Sends `create_task` requests to the Task Manager                   |

The manager-side module no longer connects directly to Remoted or drives a WPK transfer thread pool from the API request path. For 5.x agents, WPK bytes are meant to flow from the manager to the agent through the HTTPS server on the manager, driven by the agent's poll: the agent fetches the file with `POST /download` once `/control` hands it a `remote_upgrade` task.

---

## Agent-side flow

On the agent, the upgrade module runs a listener on the local Unix domain socket `queue/sockets/upgrade` (`AGENT_UPGRADE_SOCK`). A 5.x agent downloads the WPK itself over HTTPS, so the listener accepts one JSON command, issued by the agent daemon once the file is on disk:

| Command   | Parameters          | Purpose                                                                                            |
| --------- | ------------------- | -------------------------------------------------------------------------------------------------- |
| `upgrade` | `file`, `installer` | Verify the WPK signature, uncompress, unmerge into the upgrade directory and execute the installer |

The command is gated by the `allow_upgrades` flag, which reflects the agent's `<agent-upgrade><enabled>` setting. When disabled, it is answered with `Upgrade module is disabled or not ready yet` (error code `ERROR_UPGRADES_NOT_ALLOWED`).

The `upgrade` command:
1. Verifies the WPK signature against the CA store (see `ca_verification` / `ca_store`).
2. Uncompresses the archive and unmerges its contents into the upgrade directory.
3. Applies executable permissions to the installer (`chmod 0750` on POSIX).
4. Executes the installer with the request timeout defined by `execd.request_timeout`.

### Agent-side sockets

| Socket                  | Direction | Purpose                                                             |
| ----------------------- | --------- | ------------------------------------------------------------------- |
| `queue/sockets/upgrade` | Inbound   | Receives upgrade commands from the agent daemon (Linux/Unix agents) |

Windows agents accept the same JSON commands but through the agentd IPC layer instead of a Unix domain socket.

---

## Key source files

| File                                  | Purpose                                                                   |
| ------------------------------------- | ------------------------------------------------------------------------- |
| `wm_agent_upgrade.c` / `.h`           | Module entry point and dump/destroy hooks (manager and agent)             |
| `manager/wm_agent_upgrade_manager.c`  | Manager listener on `queue/tasks/upgrade`; sends requests to Task Manager |
| `manager/wm_agent_upgrade_commands.c` | Per-agent validation, WPK resolution and Task Manager task creation       |
| `manager/wm_agent_upgrade_parsing.c`  | Parses API messages and formats responses                                 |
| `manager/wm_agent_upgrade_validate.c` | Version / platform / WPK integrity checks                                 |
| `agent/wm_agent_upgrade_agent.c`      | Agent-side listener on `queue/sockets/upgrade` (POSIX)                    |
| `agent/wm_agent_upgrade_com.c`        | Implementation of the `upgrade` command                                   |
