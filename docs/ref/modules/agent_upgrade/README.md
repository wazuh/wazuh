# Agent Upgrade

The agent upgrade module orchestrates remote agent upgrades from the manager. It distributes WPK (Wazuh Package Kit) files to agents over the existing agent connection, validates checksums, executes the installer, and tracks the result through the task manager.

Source: `src/wazuh_modules/src/agent_upgrade/`

For configuration options see [Agent Upgrade Configuration](../../configuration/agent-upgrade.md).

## What is a WPK file

A WPK is a gzip-compressed tar archive containing the Wazuh agent binaries and an installer script (`pkg_install.sh`) for a specific platform and version. WPK files are identified by a SHA-1 checksum distributed alongside them from the WPK repository.

Default repository: `packages.wazuh.com/<major>.x/wpk/` (auto-derived from the manager version). A custom URL can be set with `wpk_repository` in the configuration.

## Upgrade flow

```
API request  →  Agent Upgrade module
                 ↓
            Validate agent (active, version ≥ v3.0.0, no upgrade in progress)
                 ↓
            Create task in Task Manager (status: Pending)
                 ↓
            Download WPK + verify SHA-1
                 ↓
            ┌─── Thread pool (max_threads concurrent upgrades) ─────────────┐
            │  1. lock_restart          — freeze agent restart               │
            │  2. open <wpk_file> wb    — create file on agent               │
            │  3. write <chunk>×N       — transfer WPK in 32 KB chunks       │
            │  4. close                 — finalize file                      │
            │  5. sha1                  — agent verifies checksum            │
            │  6. upgrade               — agent runs pkg_install.sh          │
            └───────────────────────────────────────────────────────────────┘
                 ↓
            Agent reboots and reports result via Router topic upgrade_notifications
                 ↓
            Task Manager updated (status: Done / Failed / Timeout)
```

### Version constraints

| Condition | Behaviour |
|-----------|-----------|
| Agent < v3.0.0 | Rejected — minimum supported version |
| Upgrade to v5.0.0 from < v4.14.0 | Intermediate upgrade to v4.14.0 required first |
| Agent version ≥ manager version | Rejected unless `force_upgrade` is set |

## Task states

| Status | Meaning |
|--------|---------|
| `Pending` | Task created, waiting for dispatch |
| `In progress` | WPK transfer and installation running |
| `Done` | Agent reported success |
| `Failed` | Agent reported error |
| `Timeout` | No result received within `task_timeout` (default 15 m) |
| `Cancelled` | Task cancelled before completion |

## Sockets

| Socket | Direction | Purpose |
|--------|-----------|---------|
| `queue/tasks/upgrade` | Inbound | Receives upgrade requests from the server API |
| `queue/tasks/task` | Outbound | Sends task create/update commands to Task Manager |
| `queue/sockets/ar` | Outbound | Sends WPK commands to agents via Remoted |
| Router topic `upgrade_notifications` | Inbound | Receives agent upgrade results via Router |

## Key source files

| File | Purpose |
|------|---------|
| `manager/wm_agent_upgrade_manager.c` | Listener on `queue/tasks/upgrade`, Router subscriber |
| `manager/wm_agent_upgrade_upgrades.c` | Thread pool, WPK transfer loop |
| `manager/wm_agent_upgrade_tasks.c` | In-memory task tracking, Task Manager IPC |
| `manager/wm_agent_upgrade_validate.c` | Version and eligibility checks |
| `agent/wm_agent_upgrade_com.c` | Agent-side: open/write/close/sha1/upgrade commands |
| `agent/wm_agent_upgrade_agent.c` | Agent-side: listener and post-reboot result reporter |
