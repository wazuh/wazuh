# Wazuh DB Configuration Reference

Configuration reference for `wazuh-manager-db`, the daemon that stores the agent registry and group
assignments (`global.db`) and the MITRE ATT&CK reference data (`mitre.db`).

For the daemon overview, socket protocol and database tables, see [Wazuh DB](README.md).

---

## Manager Configuration

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<wdb>`

**Internal Options:** `wazuh_db.*`

The `<wdb>` section configures the periodic backups of `global.db`. The installer writes no `<wdb>`
section, so the defaults below apply until you add one.

### backup

Backup block. The `database` attribute names the database it configures, and `global` is the only
value the schema accepts (any other is rejected when the configuration is validated). In the effective
configuration the block is `wdb.backup.global`.

- **Sub-options:** `enabled`, `interval`, `max_files`

#### enabled

Enable periodic backups of the global database.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** When `no`, the backup thread is not started. On-demand backups (`global backup create` on
  `wdb.sock`, see [the socket protocol](README.md#socket-protocol)) still work.

#### interval

Time between two backups.

- **Default value:** `1d` (86400 seconds)
- **Allowed values:** a number of seconds, or a number with a suffix `s`, `m`, `h`, `d` or `w`
  (seconds, minutes, hours, days, weeks). Minimum 1 second: `0` (in any unit, such as `0s` or `0d`)
  is rejected by `wazuh-manager-conf validate` and by the pre-start check of `wazuh-manager-control`
  with `(1244): Invalid configuration at '/wdb/backup/global/interval': ...`, so no daemon starts.

#### max_files

Number of backup files kept. After each backup, the oldest files are deleted until this many remain.

- **Default value:** `3`
- **Allowed values:** integer ≥ 1 (no upper bound)
- **Note:** Every file whose name starts with `global.db-backup` counts, including `-pre_restore`
  backups.

To see the effective values:

```bash
/var/wazuh-manager/bin/wazuh-manager-conf get wdb.backup.global
```

---

## Internal Options

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`

The file ships with comments only; these keys take their defaults until set. Each value must be a plain
non-negative integer inside its range: anything else makes `wazuh-manager-db` exit at start with
`(2302): Invalid definition for wazuh_db.<key>: '<value>'.` Restart the manager after a change.

```ini
# Debug level (0-2, default: 0)
wazuh_db.debug=0

# Worker thread pool size (1-32, default: 8)
wazuh_db.worker_pool_size=8

# Commit an open transaction once this many seconds pass without a query (1-3600, default: 10)
wazuh_db.commit_time_min=10

# Commit an open transaction once it is this many seconds old (1-3600, default: 60)
wazuh_db.commit_time_max=60

# Databases kept open before idle ones are closed; global.db is never closed (1-4096, default: 64)
wazuh_db.open_db_limit=64

# Soft file descriptor limit, capped by the hard limit the daemon inherits (1024-1048576, default: 65536)
wazuh_db.rlimit_nofile=65536

# Fragmentation percentage above which a vacuum is considered (0-100, default: 75)
wazuh_db.fragmentation_threshold=75

# Growth in fragmentation since the last vacuum needed to vacuum again (0-100, default: 5)
wazuh_db.fragmentation_delta=5

# Minimum free-pages percentage required before any vacuum (0-99, default: 0)
wazuh_db.free_pages_percentage=0

# Fragmentation percentage that forces a vacuum (0-100, default: 90)
wazuh_db.max_fragmentation=90

# Seconds between fragmentation checks (1-30758400, default: 7200 = 2 hours)
wazuh_db.check_fragmentation_interval=7200
```

A database is vacuumed when its free-pages percentage is at least `free_pages_percentage` and either
its fragmentation exceeds `max_fragmentation`, or it exceeds `fragmentation_threshold` and it has never
been vacuumed or has grown more than `fragmentation_delta` points since the last vacuum.

---

## Manager Configuration Examples

### Default Configuration

The effective configuration when no `<wdb>` section is present:

```xml
<wazuh_config>
  <wdb>
    <backup database="global">
      <enabled>yes</enabled>
      <interval>1d</interval>
      <max_files>3</max_files>
    </backup>
  </wdb>
</wazuh_config>
```

### Frequent Backups

```xml
<wazuh_config>
  <wdb>
    <backup database="global">
      <interval>6h</interval>
      <max_files>8</max_files>
    </backup>
  </wdb>
</wazuh_config>
```

### Extended Retention

```xml
<wazuh_config>
  <wdb>
    <backup database="global">
      <interval>1d</interval>
      <max_files>30</max_files>
    </backup>
  </wdb>
</wazuh_config>
```

### Disable Backups

```xml
<wazuh_config>
  <wdb>
    <backup database="global">
      <enabled>no</enabled>
    </backup>
  </wdb>
</wazuh_config>
```

These examples show only the `<wdb>` section; a real `wazuh-manager.conf` also carries the required
`cluster` and `indexer` sections.

---

## Database Location

| File | Path |
|---|---|
| Global database | `/var/wazuh-manager/queue/db/global.db` (`wazuh-manager`, mode `0640`) |
| MITRE database | `/var/wazuh-manager/var/db/mitre.db` |
| Backups | `/var/wazuh-manager/backup/db/` |

---

## Backup Management

### Backup files

Each backup is written with SQLite's `VACUUM INTO` after committing the open transaction, then
gzip-compressed, as `backup/db/global.db-backup-<YYYY-MM-DD-hh:mm:ss>.gz`. A backup taken before a
restore has the suffix `-pre_restore` before `.gz`.

The first periodic backup is due `interval` seconds after the newest file already in `backup/db/`
(or about one second after start when there is none). A successful backup is logged at debug level as
`Created Global database backup "<path>"`, each deletion as `Deleted Global database backup: "<path>"`,
and a failure as `Creating Global DB snapshot by interval failed: <reason>`.

### View Backup Files

```bash
ls -lh /var/wazuh-manager/backup/db/
```

### Manual Backup

With the manager stopped, a plain copy is consistent:

```bash
systemctl stop wazuh-manager
cp /var/wazuh-manager/queue/db/global.db /root/global-$(date +%Y%m%d-%H%M%S).db
systemctl start wazuh-manager
```

### Restore from Backup

```bash
systemctl stop wazuh-manager

# Replace <TIMESTAMP> with the timestamp of the backup file to restore
gunzip -c /var/wazuh-manager/backup/db/global.db-backup-<TIMESTAMP>.gz \
  > /var/wazuh-manager/queue/db/global.db

chown wazuh-manager:wazuh-manager /var/wazuh-manager/queue/db/global.db
chmod 640 /var/wazuh-manager/queue/db/global.db

systemctl start wazuh-manager
```

A running daemon can also restore in place with `global backup restore` on `wdb.sock` (see
[the socket protocol](README.md#socket-protocol)).

### Storage Requirements

Each backup is a full, compressed copy of `global.db`. Monitor disk usage:

```bash
du -sh /var/wazuh-manager/backup/db/ /var/wazuh-manager/queue/db/
```

---

## Troubleshooting

### Check wazuh-manager-db Status

```bash
# Check if wazuh-manager-db is running
/var/wazuh-manager/bin/wazuh-manager-control status | grep wazuh-manager-db

# Check the sockets
ls -l /var/wazuh-manager/queue/sockets/wdb.sock /var/wazuh-manager/queue/sockets/wdb-http.sock

# Test that the global database can serve queries
curl -s --unix-socket /var/wazuh-manager/queue/sockets/wdb-http.sock http://localhost/v1/status
```

A healthy daemon answers `{"status":"ok","module":"wazuh-db","global":{"available":true}}`. A `503`
means the daemon is running but cannot query `global.db`, and a refused connection means it is not
running; see [`GET /v1/status`](api-reference.md#get-v1status). The `wazuh-manager-db` binary does not
read queries from standard input: `wdb.sock` speaks a length-prefixed protocol, so a plain `echo`
into the binary or the socket does not reach the database.

### View wazuh-manager-db Logs

```bash
grep wazuh-manager-db /var/wazuh-manager/logs/wazuh-manager.log
```

For more detail set `wazuh_db.debug=1` (or `2`) and restart the manager.

### Common Issues

**Issue:** Backup files not being created
**Solution:** Check that `wazuh-manager-conf get wdb.backup.global.enabled` prints `true`, check free
space in `backup/db/`, and look for `Creating Global DB snapshot by interval failed` in the log.

**Issue:** The daemon exits at start with `Invalid configuration block for Wazuh-DB.`
**Solution:** Run `wazuh-manager-conf validate` and fix the option it names; it rejects every value
of the `wdb` section the daemon would refuse, a zero `wdb.backup.global.interval` included.

**Issue:** The daemon exits at start with `(2302): Invalid definition for wazuh_db.…`
**Solution:** Fix that key in `wazuh-manager-internal-options.conf` to an integer inside its range.

---

## See Also

- [Wazuh DB](README.md) - Daemon overview, socket protocol, database tables
- [Wazuh DB API Reference](api-reference.md) - Routes on `wdb-http.sock`
- [Database Sync](../database-sync/README.md) - The modulesd module that keeps `global.db` in step with `client.keys` and `etc/shared/`
- [Manager Configuration Reference](../../configuration/manager/README.md) - All manager configuration options
