# Agent Upgrade

The agent-side half of remote agent upgrades. It receives a WPK the agent has already downloaded,
verifies its signature, and runs the installer that replaces the agent.

**Daemon:** Part of `wazuh-agent-modulesd`

**Platform:** Agent only (Linux, Unix, macOS, Windows)

**Configuration file:** `/var/ossec/etc/ossec.conf`

**XML Section:** `<agent-upgrade>`

Source: [src/wazuh_modules/src/agent_upgrade/](../../../../src/wazuh_modules/src/agent_upgrade/)

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
to it by `remoted` instead. Either way, this module only ever sees a file already on disk.

---

## Flow

```
agent daemon (WPK already on disk)
    │  {"command": "upgrade", "parameters": {"file": "...", "installer": "upgrade.sh"}}
    ▼
queue/sockets/upgrade
    ├─► verify the WPK signature against the CA store
    ├─► uncompress, and unmerge into the upgrade directory
    ├─► chmod 0750 the installer
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
task and handed it out; it never learns what came of it.

### Sockets

| Socket                  | Direction | Purpose                                                             |
| ----------------------- | --------- | ------------------------------------------------------------------- |
| `queue/sockets/upgrade` | Inbound   | Receives upgrade commands from the agent daemon (Linux/Unix agents) |

Windows agents accept the same JSON command through the agentd IPC layer instead of a Unix domain
socket.

---

## Key source files

| File                             | Purpose                                                                    |
| -------------------------------- | -------------------------------------------------------------------------- |
| `wm_agent_upgrade.c` / `.h`      | Module entry point: parses `<agent-upgrade>`, starts the listener          |
| `agent/wm_agent_upgrade_agent.c` | The listener on `queue/sockets/upgrade`, and the `upgrade_result` reporting |
| `agent/wm_agent_upgrade_com.c`   | Implementation of the `upgrade` command                                     |

---

## See Also

- [Agent Upgrade Configuration](configuration.md) — this module's options
- [Agent upgrades on the manager](../task_manager/agent-upgrades.md) — request validation, WPK resolution and task creation
- [Agent Configuration Reference](../../configuration/agent/README.md)
