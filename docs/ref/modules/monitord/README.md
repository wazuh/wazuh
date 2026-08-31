# Monitord

> **This daemon no longer does any of the work described below, and is scheduled for removal.**
> The agent disconnection sweep, the disconnection log line, the retention deletion of
> long-disconnected agents and both kinds of log rotation now run as recurring tasks inside
> `wazuh-modulesd`'s Task Manager — see [Recurring manager tasks](../task_manager/schedules.md) for
> what each one does now and for the three behaviours that changed. `wazuh-manager-monitord` still
> starts and still answers `getconfig` on `queue/sockets/monitor`, so the `component='monitor'`
> configuration endpoint keeps working until the daemon is removed; its main loop is otherwise idle.
>
> Every option keeps its current name, location and meaning. The `monitord.` prefix on the internal
> options is part of the key rather than a label, so those keys stay where they are.
>
> The rest of this page describes the historical implementation.

`wazuh-manager-monitord` was the housekeeping daemon. It monitored agent connection health, generated disconnection alerts, and rotated manager log files.

Source: `src/monitord/`

## What it did

The main loop ran every second and checked four timers:

| Check | Trigger | Action |
|-------|---------|--------|
| Disconnection check | Once per `agents_disconnection_time` interval (default 900 s / 15m) | Query Wazuh DB for agents with `last_keepalive` older than `agents_disconnection_time`; add them to the alert hash table |
| Alert check | After `agents_disconnection_alert_time` (default 0 s) | Generate a disconnection alert for each agent in the hash table |
| Deletion check | Configurable | Delete agents that remain disconnected beyond the retention threshold |
| Log rotation | Daily or size threshold | Rotate and compress `/var/wazuh-manager/logs/wazuh-manager.log` |

`agents_disconnection_time` and `agents_disconnection_alert_time` are set in the `<global>` section of `wazuh-manager.conf` — see [Global Configuration](configuration.md).

## Log rotation

Monitord rotates the following files daily (or when size limits are exceeded):

- `/var/wazuh-manager/logs/wazuh-manager.log`
- `/var/wazuh-manager/logs/wazuh-manager.json`

Rotated files are gzip-compressed and stored under `/var/wazuh-manager/logs/` with a date-stamped suffix.

## Key source files

| File | Purpose |
|------|---------|
| `src/main.c` | Daemon entry point, configuration loading |
| `src/monitord.c` | Main loop, timer checks, log rotation triggers |
| `src/monitor_actions.c` | Agent disconnection detection, alert generation, deletion |
| `src/moncom.c` | Inter-process communication with `wazuh-manager` |
