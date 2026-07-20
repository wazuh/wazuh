# Monitord

`wazuh-manager-monitord` is the housekeeping daemon. It monitors agent connection health, generates disconnection alerts, and rotates manager log files.

Source: `src/monitord/`

## What it does

The main loop runs every second and checks four timers:

| Check | Trigger | Action |
|-------|---------|--------|
| Disconnection check | Every cycle | Query Wazuh DB for agents with `last_keepalive` older than `agents_disconnection_time` (default 900 s / 15m); add them to the alert hash table |
| Alert check | After `agents_disconnection_alert_time` (default 0 s) | Generate a disconnection alert for each agent in the hash table |
| Deletion check | Configurable | Delete agents that remain disconnected beyond the retention threshold |
| Log rotation | Daily or size threshold | Rotate and compress `/var/wazuh-manager/logs/wazuh-manager.log` |

`agents_disconnection_time` and `agents_disconnection_alert_time` are set in the `<global>` section of `wazuh-manager.conf` — see [Global Configuration](../../configuration/global.md).

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
