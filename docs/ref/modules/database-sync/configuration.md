# Database Sync Configuration Reference

Configuration reference for the `database` module of `wazuh-manager-modulesd`, which keeps the agent
and group tables of `global.db` in step with `etc/client.keys` and `etc/shared/`. What the module does
is described in [Database Sync](README.md).

- **Component:** Manager-only
- **Daemon:** `wazuh-manager-modulesd`
- **Configuration method:** Internal options only

---

## Configuration

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`

**XML Section:** None

**Internal Options:** `wazuh_database.*`

The file ships with comments only, so every key below takes its default until set. Each value must be
a plain non-negative integer inside its range: anything else makes `wazuh-manager-modulesd` exit at
start with `(2302): Invalid definition for wazuh_database.<key>: '<value>'.` The options are read once,
at start: restart the manager after a change.

---

## Internal Options Reference

### wazuh_database.sync_agents

Whether the module runs at all.

```ini
wazuh_database.sync_agents=1
```

- **Default value:** `1` (enabled)
- **Allowed values:** `0` (disabled), `1` (enabled)

With `0` the module is not created: no reconciliation of agents or groups happens, not even at start.

### wazuh_database.real_time

How changes to `client.keys` and `etc/shared/` are noticed.

```ini
wazuh_database.real_time=1
```

- **Default value:** `1` (enabled)
- **Allowed values:** `0` (disabled), `1` (enabled)

With `1`, inotify watches report each change as it happens and `wazuh_database.interval` is not used.
With `0`, the module polls every `wazuh_database.interval` seconds.

### wazuh_database.interval

Seconds between two polls in interval mode.

```ini
wazuh_database.interval=60
```

- **Default value:** `60`
- **Allowed values:** `0`-`86400`
- **Note:** Only applies when `wazuh_database.real_time=0`. The first poll happens one interval after
  start. With `0` the polls run back to back with no pause. A poll that takes longer than the interval
  logs `Time interval exceeded by <n> seconds.`

### wazuh_database.max_queued_events

Capacity of the module's internal queue of pending paths in real-time mode.

```ini
wazuh_database.max_queued_events=0
```

- **Default value:** `0` (use the internal default of `16384` entries)
- **Allowed values:** `0` or a positive integer
- **Note:** Only applies when `wazuh_database.real_time=1`.

The module never changes the kernel's `fs.inotify.max_queued_events`. When the configured value is
above the kernel's, the module logs `The system inotify queued events limit is '<kernel>', below the
configured value '<configured>'. Update '/proc/sys/fs/inotify/max_queued_events' through the operating
system.`, and the administrator raises the kernel limit separately. When the internal queue is full, a
change is dropped with `Internal queue is full (<size>).`; when the kernel's queue overflows, the module
logs `Inotify event queue overflowed.`

---

## Configuration Examples

### Default Configuration

Equivalent to setting nothing:

```ini
wazuh_database.sync_agents=1
wazuh_database.real_time=1
wazuh_database.interval=60
wazuh_database.max_queued_events=0
```

### Interval Mode

Poll every 5 minutes instead of reacting to each change:

```ini
wazuh_database.real_time=0
wazuh_database.interval=300
```

### Disabled

```ini
wazuh_database.sync_agents=0
```

**Warning:** With the module disabled, groups created or removed under `etc/shared/` and, on a
worker, agents added or removed in `client.keys` are not reflected in `global.db`.

---

## Monitoring

### Agents in the database

List the agents `global.db` holds, to compare with `client.keys`:

```bash
curl -s --unix-socket /var/wazuh-manager/queue/sockets/wdb-http.sock http://localhost/v1/agents/all
```

See [`GET /v1/agents/all`](../wazuh_db/api-reference.md#get-v1agentsall).

### Logs

The module logs under the tag `wazuh-manager-modulesd:database`:

```bash
grep "wazuh-manager-modulesd:database" /var/wazuh-manager/logs/wazuh-manager.log
```

Set `wazuh_modules.debug=1` (or `2`) and restart to see each synchronization (`Synchronizing
agents.`, `Agents synchronization completed.`, and with `2` every file event).

---

## Troubleshooting

### A group created under `etc/shared/` is missing from the database

1. Verify `wazuh_database.sync_agents=1` (or that it is unset).
2. In real-time mode, look for `Internal queue is full`, `Inotify event queue overflowed` or
   `Couldn't watch the shared groups directory` in the log; the next restart reconciles all groups.
3. In interval mode, wait one `wazuh_database.interval`.

### A worker's database does not match `client.keys`

1. Verify `wazuh_database.sync_agents=1`.
2. Look for `Couldn't synchronize the keystore with the DB.` or `Couldn't watch client.keys file` in the
   log; the former means `wazuh-manager-db` did not answer (check it with
   [`GET /v1/status`](../wazuh_db/api-reference.md#get-v1status)).

On the master, agents are reconciled only at start; after that `wazuh-manager-authd` keeps `global.db`
up to date.

---

## See Also

- [Database Sync](README.md) - What the module does
- [Wazuh DB Configuration](../wazuh_db/configuration.md) - The database daemon's own options
- [Agent Management](../agent-management/README.md) - Agent lifecycle management
- [Manager Configuration Reference](../../configuration/manager/README.md) - All manager configuration options
