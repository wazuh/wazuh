# Agent Upgrade and Task Manager Configuration

This page covers two closely related `<wodle>` sections that together handle remote agent upgrades on the manager side:

- `<wodle name="agent-upgrade">` — WPK distribution and upgrade orchestration (manager-side options only)
- `<wodle name="task-manager">` — Upgrade task lifecycle and database cleanup

Configuration file: `/var/wazuh-manager/etc/wazuh-manager.conf`

Parsers:
- `src/config/src/wmodules-agent-upgrade.c` (manager build — `#ifndef CLIENT`)
- `src/config/src/wmodules-task-manager.c`

> **Note:** The `wm_agent_upgrade` module is compiled differently for managers and agents. Options documented here are the manager-side options only (`#ifndef CLIENT`). Agent-side options (`notification_wait_start`, `notification_wait_max`, `notification_wait_factor`, `ca_verification`) are configured in the agent's own `wazuh-agent.conf` and are not recognized by the manager parser.

## agent-upgrade Options

### enabled

Enable or disable the agent upgrade module.

- **Default value**: `yes`
- **Allowed values**: `yes`, `no`

### wpk_repository

Base URL from which WPK upgrade packages are downloaded. A trailing `/` is added automatically at runtime if absent. If not set, the manager constructs the URL as `packages.wazuh.com/<major>.x/wpk/` using the manager's own major version.

- **Default value**: none (auto-derived from manager version)
- **Allowed values**: Any valid URL

### chunk_size

Size in bytes of each chunk sent to the agent during WPK transfer.

- **Default value**: `32768`
- **Allowed values**: Integer from `64` to `60000`

### max_threads

Maximum number of simultaneous upgrade operations. Set to `0` to use the number of available CPU cores.

- **Default value**: `8`
- **Allowed values**: `0` (CPU count) or integer from `1` to `256`

## agent-upgrade Configuration Example

```xml
<wodle name="agent-upgrade">
  <enabled>yes</enabled>
  <chunk_size>32768</chunk_size>
  <max_threads>8</max_threads>
</wodle>
```

---

## task-manager Options

### cleanup_time

How long completed, failed, or timed-out task records are retained before being deleted from the task database. Must be greater than or equal to `task_timeout`.

- **Default value**: `7d` (604800 seconds)
- **Allowed values**: Positive time value with optional suffix — `s`, `m`, `h`, `d`

### task_timeout

Maximum time a task is allowed to stay in `In progress` state before it is marked `Timeout`.

- **Default value**: `15m` (900 seconds)
- **Allowed values**: Positive time value with optional suffix — `s`, `m`, `h`, `d`

## task-manager Configuration Example

```xml
<wodle name="task-manager">
  <cleanup_time>7d</cleanup_time>
  <task_timeout>15m</task_timeout>
</wodle>
```
