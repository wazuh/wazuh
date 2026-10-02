# Agent Upgrade

The agent-side half of remote agent upgrades. It receives a WPK the agent has already downloaded,
verifies its signature, and runs the installer that replaces the agent.

**Daemon:** Part of `wazuh-modulesd` (Linux, Unix, macOS); in-process in the agent on Windows

**Platform:** Agent only (Linux, Unix, macOS, Windows)

**Configuration file:** `/var/ossec/etc/ossec.conf`

**XML Section:** `<agent-upgrade>`

**Source:** `src/wazuh_modules/src/agent_upgrade/`

> **The manager side is not this module.** Validating an upgrade request, resolving and downloading
> the WPK, and creating the `remote_upgrade` task all belong to the
> [Task Manager](../task_manager/agent-upgrades.md). Nothing of this module is built into a manager.

---

## What is a WPK file

A WPK (Wazuh Package Kit) is a signed, compressed archive containing the Wazuh agent binaries and an
installer script — `upgrade.sh` on Linux/macOS, `upgrade.bat` on Windows — for a specific platform
and version. Each WPK is distributed together with a SHA-1 checksum used to validate the file end to
end.

An agent on v5.0.0 or newer downloads its own WPK over HTTPS from the manager, having been handed a
`remote_upgrade` task on its regular `POST /control` poll. An agent below v5.0.0 has the file pushed
to it by `wazuh-manager-remoted` instead, and installs it with its own 4.x upgrade module. Either way,
this module only ever sees a file already on disk.

---

## Requesting an upgrade

Upgrades are requested on the manager, through the Server API or the `agent_upgrade` CLI; both create
`remote_upgrade` tasks in the Task Manager and return. **No outcome comes back to the manager.**

| Request | RBAC action |
|---------|-------------|
| `PUT /agents/upgrade?agents_list=<ID>,<ID>` (optional `upgrade_version`, `wpk_repo`, `use_http`, `force`, `package_type`) | `agent:upgrade` |
| `PUT /agents/upgrade_custom?agents_list=<ID>&file_path=<WPK>` (optional `installer`) | `agent:upgrade` |
| `GET /agents/outdated` | `agent:read` |

### agent_upgrade

`/var/wazuh-manager/bin/agent_upgrade` (source `framework/scripts/agent_upgrade.py`) calls the same
framework function as the API, broadcast to every cluster node.

```bash
/var/wazuh-manager/bin/agent_upgrade -a 001 002          # upgrade from the repository
/var/wazuh-manager/bin/agent_upgrade -a 001 -f my.wpk    # custom WPK from var/upgrade/
/var/wazuh-manager/bin/agent_upgrade -l                  # list outdated agents
```

| Flag | Meaning |
|------|---------|
| `-a`, `--agents <ID> [<ID> …]` | Agents to upgrade. Without `-a` (and without `-l`) the help is printed |
| `-l`, `--list_outdated` | List the agents older than the manager and exit |
| `-v`, `--version <version>` | Target version. Default: the manager's own version |
| `-r`, `--repository <host/path>` | WPK repository. Default: `task-manager.wpk_repository`, else `packages.wazuh.com/<major>.x/wpk/` for the target version |
| `-F`, `--force` | Skip the overridable version checks |
| `--http` | Fetch the repository over HTTP instead of HTTPS |
| `--package_type <rpm\|deb>` | Package family for a Linux agent whose distribution does not imply one |
| `-f`, `--file <WPK>` | Custom WPK: a bare file name, or a path inside `/var/wazuh-manager/var/upgrade/`. The file must already be there (on every cluster node); the CLI exits with an error otherwise |
| `-x`, `--execute <installer>` | Installer inside a custom WPK. Default: `upgrade.bat` for Windows agents, `upgrade.sh` otherwise |
| `-s`, `--silent` | Print nothing on success or per-agent failure |
| `-d`, `--debug` | Re-raise errors with a traceback |

`-f` or `-x` selects the custom path, on which `-v`, `-r`, `-F`, `--http` and `--package_type` are
ignored. Output:

```text
Upgrade tasks created for 1 agent(s).
Note: Agents will execute upgrades autonomously. Use agent logs to track progress.
```

Agents that cannot be upgraded are listed first, as `Agent <ID> upgrade failed. Status: <error>`. The
version rules and per-agent errors are in [Agent upgrades](../task_manager/agent-upgrades.md#version-constraints);
building and signing a custom WPK is described in `tools/agent-upgrade/README.md`.

To verify the result, check the agent's version (`GET /agents?agents_list=<ID>&select=version`) once
it reconnects, or the agent's log.

---

## Flow

```text
wazuh-agentd (WPK already on disk)
    │  Unix only: "lock_restart -1" to wazuh-execd
    │  {"command": "upgrade", "parameters": {"file": "...", "installer": "upgrade.sh"}}
    ▼
queue/sockets/upgrade  (Windows: in-process call)
    ├─► verify the WPK signature against the CA store
    ├─► uncompress, and unmerge into var/upgrade/
    ├─► chmod 0750 the installer (Unix)
    └─► execute it, bounded by execd.request_timeout
            │
            ▼
    agent restarts as the new version
            └─► reads var/upgrade/upgrade_result, emits it as a stateless
                    event, and erases the file
```

The listener accepts exactly one command:

| Command   | Parameters          | Purpose                                                                                            |
| --------- | ------------------- | -------------------------------------------------------------------------------------------------- |
| `upgrade` | `file`, `installer` | Verify the WPK signature, uncompress, unmerge into the upgrade directory and execute the installer |

It is gated by the agent's `<agent-upgrade><enabled>` setting. When disabled, every command is
answered `Upgrade module is disabled or not ready yet` (`ERROR_UPGRADES_NOT_ALLOWED`).

**The outcome is reported as a stateless event, not back to the manager.** The manager stored the
task and handed it out; it never learns what came of it. The installer writes the code to
`upgrade_result`, and the event carries it as `data.error` with `data.message`: `0` *Upgrade was
successful* (`status` `Done`), `1` *Upgrade failed: intermediate version required*, `2` *Upgrade
failed* (`status` `Failed`); any other value is reported as *Upgrade failed*.

### Sockets

| Socket                  | Direction | Purpose                                                             |
| ----------------------- | --------- | ------------------------------------------------------------------- |
| `queue/sockets/upgrade` | Inbound   | Receives upgrade commands from the agent daemon (Linux/Unix agents) |

Windows agents call the same command handler in-process instead of using a Unix domain socket.

---

## Key source files

| File                             | Purpose                                                                    |
| -------------------------------- | -------------------------------------------------------------------------- |
| `wm_agent_upgrade.c` / `.h`      | Module entry point: starts the listener                                    |
| `agent/wm_agent_upgrade_agent.c` | The listener on `queue/sockets/upgrade`, and the `upgrade_result` reporting |
| `agent/wm_agent_upgrade_com.c`   | Implementation of the `upgrade` command                                     |

The `<agent-upgrade>` parser is `src/config/src/wmodules-agent-upgrade.c`.

---

## See Also

- [Agent Upgrade Configuration](configuration.md) — this module's options
- [Agent upgrades on the manager](../task_manager/agent-upgrades.md) — request validation, WPK resolution and task creation
- [Agent Configuration Reference](../../configuration/agent/README.md)
