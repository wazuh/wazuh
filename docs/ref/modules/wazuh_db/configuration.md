# Wazuh DB Configuration Reference

Complete configuration reference for Wazuh DB (wazuh-db).

Wazuh DB is the central database service that stores agent information, vulnerability data, file integrity monitoring data, and other module state. It provides a unified query interface and automatic backup capabilities.

For module overview, architecture, and database schemas, see [Wazuh DB Module](index.html).

---

## Manager Configuration

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<wdb>`

**Internal Options:** `wazuh_database.*`

The Wazuh DB configuration controls automatic database backups and retention policies.


### backup

Database backup configuration block. Use the `database` attribute to specify which database to configure.

- **Attribute:** `database` - Which database to back up (currently only `global` is supported)
- **Sub-options:** `enabled`, `interval`, `max_files`

#### enabled

Enable automatic backups of the selected database.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** When disabled, no automatic backups are created. Manual backups are still possible

#### interval

How often a backup is created.

- **Default value:** `1d` (86400 seconds)
- **Allowed values:** Positive time value with optional suffix: `s` (seconds), `m` (minutes), `h` (hours), `d` (days)
- **Note:** More frequent backups provide better recovery points but consume more disk space

#### max_files

Maximum number of backup files to keep. Older backups are removed when this limit is exceeded.

- **Default value:** `3`
- **Allowed values:** Positive integer (1-999)
- **Note:** Adjust based on available disk space and backup frequency. Total space = database size × max_files

---

## Internal Options

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`

Additional wazuh-db settings can be configured in the internal options file:

```ini
# Wazuh DB debug level (0-2)
wazuh_db.debug=0

# Worker thread pool size (1-32, default: 8)
wazuh_db.worker_pool_size=8

# Minimum commit interval for transactions (seconds, 1-3600, default: 10)
wazuh_db.commit_time_min=10

# Maximum commit interval for transactions (seconds, 1-3600, default: 60)
wazuh_db.commit_time_max=60

# Maximum number of open database connections (1-4096, default: 64)
wazuh_db.open_db_limit=64

# Maximum file descriptors (1024-1048576, default: 458752)
wazuh_db.rlimit_nofile=458752

# Database fragmentation threshold percentage (0-100, default: 75)
wazuh_db.fragmentation_threshold=75

# Fragmentation delta for triggering vacuum (0-100, default: 5)
wazuh_db.fragmentation_delta=5

# Free pages percentage to maintain (0-99, default: 0)
wazuh_db.free_pages_percentage=0

# Maximum allowed fragmentation percentage (0-100, default: 90)
wazuh_db.max_fragmentation=90

# Interval to check database fragmentation in seconds (1-30758400, default: 7200 = 2 hours)
wazuh_db.check_fragmentation_interval=7200
```

**Note:** Use `wazuh-manager-internal-options.conf` instead of modifying the default `internal_options.conf` to preserve settings across upgrades.

---

## Manager Configuration Examples

### Default Configuration

Standard backup settings:

```xml
<wdb>
  <backup database="global">
    <enabled>yes</enabled>
    <interval>1d</interval>
    <max_files>3</max_files>
  </backup>
</wdb>
```

Backup files are written to `/var/wazuh-manager/backup/db/`.

### Frequent Backups

For critical environments requiring more frequent backups:

```xml
<wdb>
  <backup database="global">
    <enabled>yes</enabled>
    <interval>6h</interval>
    <max_files>8</max_files>
  </backup>
</wdb>
```

### Extended Retention

Keep more backup history:

```xml
<wdb>
  <backup database="global">
    <enabled>yes</enabled>
    <interval>1d</interval>
    <max_files>30</max_files>
  </backup>
</wdb>
```

### Disable Backups

For testing or storage-constrained environments:

```xml
<wdb>
  <backup database="global">
    <enabled>no</enabled>
  </backup>
</wdb>
```

---

## Database Location

Wazuh DB stores its databases in:

**Global database:** `/var/wazuh-manager/queue/db/global.db`

**Agent databases:** `/var/wazuh-manager/queue/db/agents/<agent-id>.db`

**Backup location:** `/var/wazuh-manager/backup/db/`

---

## Backup Management

### Manual Backup

Create a manual backup of the global database:

```bash
# Stop wazuh-db to ensure consistency
systemctl stop wazuh-manager

# Create backup directory if it doesn't exist
mkdir -p /var/wazuh-manager/backup/db/manual

# Copy global database
cp /var/wazuh-manager/queue/db/global.db \
   /var/wazuh-manager/backup/db/manual/global-$(date +%Y%m%d-%H%M%S).db

# Restart wazuh-manager
systemctl start wazuh-manager
```

### Restore from Backup

To restore from a backup:

```bash
# Stop wazuh-manager
systemctl stop wazuh-manager

# Restore backup (replace TIMESTAMP with actual backup filename)
cp /var/wazuh-manager/backup/db/global-TIMESTAMP.db \
   /var/wazuh-manager/queue/db/global.db

# Restore ownership and permissions
chown wazuh:wazuh /var/wazuh-manager/queue/db/global.db
chmod 660 /var/wazuh-manager/queue/db/global.db

# Start wazuh-manager
systemctl start wazuh-manager
```

### View Backup Files

```bash
ls -lh /var/wazuh-manager/backup/db/
```

---

## Performance Considerations

### Backup Impact

- Backups create a snapshot of the database using SQLite's backup API
- Minimal performance impact during backup operation
- Brief lock on database during snapshot creation

### Storage Requirements

Each backup is a full copy of the database. Monitor disk usage:

```bash
du -sh /var/wazuh-manager/backup/db/
du -sh /var/wazuh-manager/queue/db/
```

Typical sizes:
- Small deployments (<100 agents): ~50-200 MB
- Medium deployments (100-1000 agents): ~200 MB - 2 GB
- Large deployments (1000+ agents): 2+ GB

### Tuning for Large Deployments

For deployments with large databases:

```xml
<wdb>
  <backup database="global">
    <enabled>yes</enabled>
    <interval>12h</interval>     <!-- Less frequent -->
    <max_files>5</max_files>     <!-- Fewer retained backups -->
  </backup>
</wdb>
```

---

## Troubleshooting

### Check wazuh-db Status

```bash
# Check if wazuh-db is running
systemctl status wazuh-manager | grep wazuh-db

# Check wazuh-db socket
ls -l /var/wazuh-manager/queue/db/wdb

# Test database connection
echo 'agent 000 sql SELECT name FROM sqlite_master' | \
  /var/wazuh-manager/bin/wazuh-db
```

### View wazuh-db Logs

```bash
tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep wazuh-db
```

### Database Integrity Check

Check global database integrity:

```bash
sqlite3 /var/wazuh-manager/queue/db/global.db "PRAGMA integrity_check;"
```

Expected output: `ok`

### Common Issues

**Issue:** Backup files not being created
**Solution:** Check disk space, verify `<enabled>yes</enabled>`, check logs for errors

**Issue:** wazuh-db high CPU usage
**Solution:** Reduce query frequency from other modules, increase `worker_pool_size` in internal options

**Issue:** Database locked errors
**Solution:** Check for long-running queries, increase `commit_time` in internal options

---

## See Also

- [Wazuh DB Module](index.html) - Module overview, architecture, and database schemas
- [Manager Configuration Reference](../../configuration/manager/README.md) - All manager configuration options
- [Vulnerability Scanner Configuration](../vulnerability-scanner/configuration.md) - Uses wazuh-db for vulnerability data
- [Task Manager Configuration](../task_manager/configuration.md) - Uses wazuh-db for task storage
