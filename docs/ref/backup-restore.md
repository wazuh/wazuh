# Back Up and Restore

This guide provides instructions for backing up and restoring Wazuh manager and agent data. Regular backups are essential for disaster recovery and should be performed before major operations such as upgrades or configuration changes.

---

## Manager Backup and Restore

### What to Back Up

The following components should be included in your Wazuh manager backup strategy:

#### Essential Data

- **Configuration files**: `/var/wazuh-manager/etc/`
  - `wazuh-manager.conf` - Main configuration file
  - `wazuh-manager-internal-options.conf` - Internal configuration overrides

- **Agent keys**: `/var/wazuh-manager/etc/client.keys`
  - Contains encryption keys for registered agents
  - Critical for agent communication

- **SSL/TLS certificates**: `/var/wazuh-manager/etc/certs/`
  - Manager certificates and keys
  - Root CA certificates

- **Global database**: `/var/wazuh-manager/queue/db/global.db`
  - Agent information (registration, metadata)
  - Agent group assignments
  - Group membership data

  **Note**: `/var/wazuh-manager/var/db/` is not the global database. It holds only `mitre.db`, which is generated at installation time and does not need to be backed up. The manager also keeps its own periodic snapshots of the global database under `/var/wazuh-manager/backup/db/` (`wdb.backup.global`: enabled by default, daily, three files kept). Those snapshots are a useful fallback, but they cover this one database and nothing else.

- **Agent groups**: `/var/wazuh-manager/etc/shared/`
  - Group-specific configurations and files
  - Shared files distributed to agents in each group

- **API configuration and users**: `/var/wazuh-manager/api/configuration/`
  - `api.yaml` - API configuration
  - `security/rbac.db` - API users, roles, policies and their mappings

- **Indexer credential store**: `/var/wazuh-manager/queue/keystore/`
  - Encrypted store holding the indexer credentials
  - Without it the restored manager cannot authenticate to the indexer

- **Task history**: `/var/wazuh-manager/queue/tasks/tasks.db`
  - Agent upgrade and recurring manager task history

- **Pending agent deletions**: `/var/wazuh-manager/queue/authd/`
  - `pending-purges` - agent deletions not yet relayed to the indexer
  - Losing it leaves the corresponding indexer documents orphaned

- **Detection content**: `/var/wazuh-manager/data/`
  - `store/` - engine content store (schemas, enrichment definitions)
  - `ruleset/` - ruleset content written by the Content Manager
  - `kvdb-ioc/` - IOC key-value store
  - `mmdb/`, `tzdb/` - GeoIP and timezone databases, reinstalled with the package

#### Optional Data

- **Logs**: `/var/wazuh-manager/logs/`
  - Historical logs for audit and troubleshooting
  - Can be large; consider retention policies

### Manager Backup Procedures

#### Pre-Backup Checklist

Before creating a backup, verify:

1. Sufficient disk space for backup files
2. Backup destination is accessible
3. You have appropriate permissions
4. Consider stopping the manager for consistent backups (optional)

#### Creating a Full Manager Backup

**Option 1: Backup while manager is running** (recommended for production)

This method allows the manager to continue operating during the backup:

```bash
# Create backup directory with timestamp
BACKUP_DIR="/backup/wazuh-manager-$(date +%Y%m%d-%H%M%S)"
sudo mkdir -p $BACKUP_DIR

# Backup configuration files
sudo tar -czf $BACKUP_DIR/wazuh-etc.tar.gz -C /var/wazuh-manager etc/

# Backup API configuration, credential store, pending agent deletions and detection content.
# The databases are excluded here: they are copied below with the SQLite backup API.
sudo tar -czf $BACKUP_DIR/wazuh-state.tar.gz -C /var/wazuh-manager \
    --exclude='api/configuration/security/rbac.db' \
    api/configuration/ \
    queue/keystore/ \
    queue/authd/ \
    data/

# Backup the databases. Each source is tested first -- with `sudo test`, since
# these directories are not readable unprivileged -- because sqlite3 creates a
# database when handed a path that does not exist.
sudo mkdir -p $BACKUP_DIR/db
for DB in queue/db/global.db queue/tasks/tasks.db api/configuration/security/rbac.db; do
    SRC="/var/wazuh-manager/$DB"
    if sudo test -f "$SRC"; then
        sudo sqlite3 "$SRC" ".backup '$BACKUP_DIR/db/$(basename "$DB")'"
    else
        echo "MISSING: $SRC was not backed up"
    fi
done

# Set proper permissions. These archives carry agent keys, API password hashes and
# the indexer credential store, so close them to other local users first.
sudo chmod -R go-rwx $BACKUP_DIR
sudo chown -R $(whoami):$(whoami) $BACKUP_DIR
```

**Note**: `queue/keystore/` and `data/kvdb-ioc/` are key-value stores that the manager may be writing while the archive is created. Use Option 2 when their consistency matters.

**Option 2: Backup with manager stopped** (recommended for critical operations)

This method ensures complete data consistency:

```bash
# Create backup directory with timestamp
BACKUP_DIR="/backup/wazuh-manager-$(date +%Y%m%d-%H%M%S)"
sudo mkdir -p $BACKUP_DIR

# Stop the Wazuh manager
sudo systemctl stop wazuh-manager

# Backup essential directories. Whole directories rather than the database files
# alone, so that any journal or write-ahead log left beside them is included.
sudo tar -czf $BACKUP_DIR/wazuh-manager-backup.tar.gz \
    -C /var/wazuh-manager \
    etc/ \
    api/configuration/ \
    queue/db/ \
    queue/tasks/ \
    queue/keystore/ \
    queue/authd/ \
    data/

# Start the Wazuh manager
sudo systemctl start wazuh-manager

# Verify manager is running
sudo systemctl status wazuh-manager

# Set proper permissions. These archives carry agent keys, API password hashes and
# the indexer credential store, so close them to other local users first.
sudo chmod -R go-rwx $BACKUP_DIR
sudo chown -R $(whoami):$(whoami) $BACKUP_DIR
```

#### Creating Selective Manager Backups

**Configuration only:**

```bash
sudo tar -czf wazuh-manager-config-$(date +%Y%m%d).tar.gz -C /var/wazuh-manager etc/
```

**Agent keys only:**

```bash
sudo cp /var/wazuh-manager/etc/client.keys wazuh-client-keys-$(date +%Y%m%d).backup
```

**Global database only:**

```bash
sudo test -f /var/wazuh-manager/queue/db/global.db \
  && sudo sqlite3 /var/wazuh-manager/queue/db/global.db ".backup 'wazuh-global-db-$(date +%Y%m%d).db'" \
  || echo "MISSING: /var/wazuh-manager/queue/db/global.db - nothing was backed up"
```

#### Backup Verification

The three procedures produce three different layouts, so use the check that matches the backup you took. In all of them `sqlite3` must not be run against a path that may not exist: it creates an empty database there, and `PRAGMA integrity_check` then reports `ok` on it.

**Option 1** — two archives plus a `db/` directory:

```bash
tar -tzf $BACKUP_DIR/wazuh-etc.tar.gz > /dev/null && echo "Configuration backup verified" || echo "Backup verification failed"
tar -tzf $BACKUP_DIR/wazuh-state.tar.gz > /dev/null && echo "State backup verified" || echo "Backup verification failed"

if [ -f "$BACKUP_DIR/db/global.db" ]; then
    sudo sqlite3 "$BACKUP_DIR/db/global.db" "PRAGMA integrity_check" && echo "Database backup verified" || echo "Database verification failed"
    # The row count is what proves the copy carries the registry
    sudo sqlite3 "$BACKUP_DIR/db/global.db" "SELECT count(*) FROM agent" && echo "Agent registry present" || echo "Backup contains no agent registry"
else
    echo "MISSING: no global.db in this backup - do NOT restore from it"
fi

du -sh $BACKUP_DIR
tar -tzf $BACKUP_DIR/wazuh-etc.tar.gz | head -20
```

**Option 2** — one archive holding whole directories, so the databases are inside it:

```bash
tar -tzf $BACKUP_DIR/wazuh-manager-backup.tar.gz > /dev/null && echo "Archive verified" || echo "Backup verification failed"
tar -tzf $BACKUP_DIR/wazuh-manager-backup.tar.gz | grep -q '^queue/db/global.db$' \
  && echo "Agent registry present in the archive" || echo "MISSING: no queue/db/global.db in this archive"
du -sh $BACKUP_DIR
```

**Container backup** — a directory tree copied out of the container, with the databases at their installed paths:

```bash
for DB in queue/db/global.db queue/tasks/tasks.db api/configuration/security/rbac.db; do
    [ -f "$BACKUP_DIR/$DB" ] || { echo "MISSING: $DB"; continue; }
    sqlite3 "$BACKUP_DIR/$DB" "PRAGMA integrity_check" > /dev/null && echo "$DB verified" || echo "$DB verification failed"
done
[ -f "$BACKUP_DIR/queue/db/global.db" ] && sqlite3 "$BACKUP_DIR/queue/db/global.db" "SELECT count(*) FROM agent"
du -sh $BACKUP_DIR
```

**Note**: `PRAGMA integrity_check` reports `ok` on a well-formed database with no tables in it, so it cannot on its own tell a good backup from a copy of a source that was not there. Always check that the expected tables carry rows, as the agent count above does.

#### Automated Manager Backup Script

Create a script for regular automated backups:

```bash
#!/bin/bash
# /usr/local/bin/wazuh-manager-backup.sh

BACKUP_BASE="/backup/wazuh-manager"
RETENTION_DAYS=30
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="$BACKUP_BASE/backup-$TIMESTAMP"
LOG_FILE="/var/log/wazuh-backup.log"
GLOBAL_DB="/var/wazuh-manager/queue/db/global.db"

# Create backup directory
mkdir -p $BACKUP_DIR/db

# Refuse to run if the global database is not where it is expected: sqlite3 would
# create the missing source and back up an empty database, which the verification
# below cannot distinguish from a healthy one.
if [ ! -f "$GLOBAL_DB" ]; then
    echo "$(date): Manager backup FAILED - $GLOBAL_DB does not exist" >> $LOG_FILE
    exit 1
fi

# Perform backup
tar -czf $BACKUP_DIR/wazuh-etc.tar.gz -C /var/wazuh-manager etc/
tar -czf $BACKUP_DIR/wazuh-state.tar.gz -C /var/wazuh-manager \
    --exclude='api/configuration/security/rbac.db' \
    api/configuration/ queue/keystore/ queue/authd/ data/
sqlite3 "$GLOBAL_DB" ".backup '$BACKUP_DIR/db/global.db'"

# The task history and the API users are only created once the task manager and
# the API have written them, so a missing file is not an error here.
for DB in queue/tasks/tasks.db api/configuration/security/rbac.db; do
    SRC="/var/wazuh-manager/$DB"
    if [ -f "$SRC" ]; then
        sqlite3 "$SRC" ".backup '$BACKUP_DIR/db/$(basename "$DB")'"
    else
        echo "$(date): skipped $SRC (does not exist)" >> $LOG_FILE
    fi
done

# Close the backup to other local users before verifying it: it carries agent
# keys, API password hashes and the indexer credential store.
chmod -R go-rwx $BACKUP_DIR

# Verify backup. The agent count proves the copy carries the registry; an
# integrity check alone passes on an empty database.
if tar -tzf $BACKUP_DIR/wazuh-etc.tar.gz > /dev/null 2>&1 && \
   tar -tzf $BACKUP_DIR/wazuh-state.tar.gz > /dev/null 2>&1 && \
   sqlite3 $BACKUP_DIR/db/global.db "PRAGMA integrity_check" > /dev/null 2>&1 && \
   sqlite3 $BACKUP_DIR/db/global.db "SELECT count(*) FROM agent" > /dev/null 2>&1; then
    echo "$(date): Manager backup completed successfully to $BACKUP_DIR" >> $LOG_FILE

    # Remove old backups
    find $BACKUP_BASE -type d -name "backup-*" -mtime +$RETENTION_DAYS -exec rm -rf {} \;
else
    echo "$(date): Manager backup FAILED - verification error" >> $LOG_FILE
    exit 1
fi
```

Schedule with cron:

```bash
# Daily backup at 2 AM
0 2 * * * /usr/local/bin/wazuh-manager-backup.sh
```

### Manager Restore Procedures

#### Pre-Restore Checklist

Before restoring from a backup:

1. Verify backup file integrity
2. Ensure compatible Wazuh version
3. Check available disk space
4. Plan for service downtime
5. Notify relevant stakeholders

#### Full Manager Restore

**Step 1: Stop the Wazuh manager**

```bash
sudo systemctl stop wazuh-manager
```

**Step 2: Backup current data (optional but recommended)**

Verify the backup before this step, with the commands in [Backup Verification](#backup-verification). This step moves the live configuration aside, so a restore that then fails in Step 3 leaves the manager with no configuration to start from.

```bash
SUFFIX=$(date +%Y%m%d-%H%M%S)
sudo mv /var/wazuh-manager/etc /var/wazuh-manager/etc.old.$SUFFIX
sudo mv /var/wazuh-manager/queue/db/global.db /var/wazuh-manager/queue/db/global.db.old.$SUFFIX

# Everything else Step 3 overwrites, so a failure there still has a fallback
sudo cp -a /var/wazuh-manager/api/configuration /var/wazuh-manager/api/configuration.old.$SUFFIX
sudo cp -a /var/wazuh-manager/queue/tasks /var/wazuh-manager/queue/tasks.old.$SUFFIX
sudo cp -a /var/wazuh-manager/queue/keystore /var/wazuh-manager/queue/keystore.old.$SUFFIX
sudo cp -a /var/wazuh-manager/queue/authd /var/wazuh-manager/queue/authd.old.$SUFFIX
sudo cp -a /var/wazuh-manager/data /var/wazuh-manager/data.old.$SUFFIX
```

**Step 3: Restore from backup**

If the backup was taken with Option 2, its single archive already holds every path below; extract it with `sudo tar -xzf $BACKUP_DIR/wazuh-manager-backup.tar.gz -C /var/wazuh-manager` and go to Step 4. For a backup taken with Option 1:

```bash
# Restore configuration
sudo tar -xzf $BACKUP_DIR/wazuh-etc.tar.gz -C /var/wazuh-manager

# Restore API configuration, credential store, pending agent deletions and detection content
sudo tar -xzf $BACKUP_DIR/wazuh-state.tar.gz -C /var/wazuh-manager

# Restore the databases. The agent registry is mandatory; the other two are only
# in the backup if the task manager and the API had written them by then, so a
# missing copy there is a skip rather than a failure.
if [ -f "$BACKUP_DIR/db/global.db" ]; then
    sudo cp $BACKUP_DIR/db/global.db /var/wazuh-manager/queue/db/global.db
else
    echo "MISSING: $BACKUP_DIR/db/global.db - the agent registry was NOT restored"
fi
[ -f "$BACKUP_DIR/db/tasks.db" ] && sudo cp $BACKUP_DIR/db/tasks.db /var/wazuh-manager/queue/tasks/tasks.db \
  || echo "skipped tasks.db (not in this backup)"
[ -f "$BACKUP_DIR/db/rbac.db" ] && sudo cp $BACKUP_DIR/db/rbac.db /var/wazuh-manager/api/configuration/security/rbac.db \
  || echo "skipped rbac.db (not in this backup)"
```

**Step 4: Set proper permissions**

```bash
# Configuration and shared files
sudo chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/etc

# The files and directories the installer keeps root-owned, which the recursive
# chown above takes: the WPK signing anchor, the internal options, the schema that
# validates the configuration, the configuration itself, and the shared tree.
sudo chown root:wazuh-manager /var/wazuh-manager/etc \
    /var/wazuh-manager/etc/shared \
    /var/wazuh-manager/etc/indexer-plugins \
    /var/wazuh-manager/etc/wazuh-manager.conf \
    /var/wazuh-manager/etc/wazuh-manager-internal-options.conf \
    /var/wazuh-manager/etc/wazuh-manager.schema.json \
    /var/wazuh-manager/etc/wpk_root.pem \
    /var/wazuh-manager/etc/localtime

# client.keys stays with the service account: authd appends to it after dropping
# privileges, so root ownership would stop enrollment.
sudo chown wazuh-manager:wazuh-manager /var/wazuh-manager/etc/client.keys
sudo chmod 660 /var/wazuh-manager/etc/client.keys

# Certificates, in the modes the installer applies: root-owned and sticky so a
# daemon can regenerate its own certificate but not replace the indexer material.
# Do not make the directory read-only, or regeneration stops working. The glob and
# the test run inside the root shell -- unprivileged they expand to nothing.

sudo sh -c 'cd /var/wazuh-manager/etc/certs || exit 1
    chown root:wazuh-manager . && chmod 1770 .
    chmod 640 * 2>/dev/null
    for CERT in root-ca.pem indexer-connector.pem indexer-connector-key.pem; do
        [ -f "$CERT" ] && chown root:wazuh-manager "$CERT"
    done'

# Databases, credential store, pending agent deletions and detection content
sudo chown -R wazuh-manager:wazuh-manager \
    /var/wazuh-manager/queue/db \
    /var/wazuh-manager/queue/tasks \
    /var/wazuh-manager/queue/keystore \
    /var/wazuh-manager/queue/authd \
    /var/wazuh-manager/data
sudo chmod 660 /var/wazuh-manager/queue/db/global.db
sudo chmod 640 /var/wazuh-manager/queue/tasks/tasks.db

# API configuration: root-owned directories, database owned by the manager user
sudo chown root:wazuh-manager /var/wazuh-manager/api/configuration /var/wazuh-manager/api/configuration/security
sudo chmod 770 /var/wazuh-manager/api/configuration /var/wazuh-manager/api/configuration/security
sudo chown wazuh-manager:wazuh-manager /var/wazuh-manager/api/configuration/security/rbac.db
sudo chmod 640 /var/wazuh-manager/api/configuration/security/rbac.db
```

**Step 5: Start the Wazuh manager**

```bash
sudo systemctl start wazuh-manager
```

**Step 6: Verify the restore**

```bash
# Check manager status
sudo systemctl status wazuh-manager

# Check the restored databases, guarded on the file existing: an unguarded
# sqlite3 would create the very database it is checking. An integrity check also
# passes on an empty one, so the row counts below are what prove the restore.
sudo sh -c 'for DB in queue/db/global.db api/configuration/security/rbac.db; do
    SRC="/var/wazuh-manager/$DB"
    if [ -f "$SRC" ]; then
        sqlite3 "$SRC" "PRAGMA integrity_check"
    else
        echo "MISSING: $SRC was not restored"
    fi
done'
sudo sh -c '[ -f /var/wazuh-manager/queue/db/global.db ] && sqlite3 /var/wazuh-manager/queue/db/global.db "SELECT count(*) FROM agent"'
sudo sh -c '[ -f /var/wazuh-manager/api/configuration/security/rbac.db ] && sqlite3 /var/wazuh-manager/api/configuration/security/rbac.db "SELECT count(*) FROM users"'

# Check logs for errors
sudo tail -f /var/wazuh-manager/logs/wazuh-manager.log
```

#### Selective Manager Restore

**Restore configuration only:**

```bash
sudo systemctl stop wazuh-manager
sudo tar -xzf wazuh-manager-config-YYYYMMDD.tar.gz -C /var/wazuh-manager
sudo chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/etc
sudo systemctl start wazuh-manager
```

**Restore agent keys only:**

```bash
sudo systemctl stop wazuh-manager
sudo cp wazuh-client-keys-YYYYMMDD.backup /var/wazuh-manager/etc/client.keys
sudo chown wazuh-manager:wazuh-manager /var/wazuh-manager/etc/client.keys
sudo chmod 660 /var/wazuh-manager/etc/client.keys
sudo systemctl start wazuh-manager
```

**Restore global database only:**

```bash
sudo systemctl stop wazuh-manager
sudo cp wazuh-global-db-YYYYMMDD.db /var/wazuh-manager/queue/db/global.db
sudo chown wazuh-manager:wazuh-manager /var/wazuh-manager/queue/db/global.db
sudo chmod 660 /var/wazuh-manager/queue/db/global.db
sudo systemctl start wazuh-manager
```

### Cluster-Specific Manager Backup

In a cluster deployment, backup procedures differ slightly:

**Master node:**
- Backup all data as described above
- The master node contains authoritative agent registration and group assignment data

**Worker nodes:**
- Configuration, certificates and the indexer credential store
- The global database is synchronized from master
- Shared files are synchronized from master

**Recommended approach:**

1. Always backup the master node completely
2. Backup worker node configurations
3. Store backups separately for each node
4. Document cluster topology and node roles

#### Master Node Backup

```bash
BACKUP_DIR="/backup/wazuh-master-$(date +%Y%m%d-%H%M%S)"
sudo mkdir -p $BACKUP_DIR/db

# Full backup of master node
# Same archive names the full restore procedure expects in Step 3; the directory
# name already says which node this is.
sudo tar -czf $BACKUP_DIR/wazuh-etc.tar.gz -C /var/wazuh-manager etc/
sudo tar -czf $BACKUP_DIR/wazuh-state.tar.gz -C /var/wazuh-manager \
    --exclude='api/configuration/security/rbac.db' \
    api/configuration/ \
    queue/keystore/ \
    queue/authd/ \
    data/
for DB in queue/db/global.db queue/tasks/tasks.db api/configuration/security/rbac.db; do
    SRC="/var/wazuh-manager/$DB"
    if sudo test -f "$SRC"; then
        sudo sqlite3 "$SRC" ".backup '$BACKUP_DIR/db/$(basename "$DB")'"
    else
        echo "MISSING: $SRC was not backed up"
    fi
done

# Same exposure as the single-node backups: agent keys, API password hashes and
# the indexer credential store.
sudo chmod -R go-rwx $BACKUP_DIR
```

The API users, roles and policies live on the master, so `rbac.db` is part of the master backup only.

#### Worker Node Backup

```bash
BACKUP_DIR="/backup/wazuh-worker-$(hostname)-$(date +%Y%m%d-%H%M%S)"
sudo mkdir -p $BACKUP_DIR

# Configuration, certificates and indexer credentials. The global database and the
# shared files are synchronized from the master, but the credential store is not:
# a worker restored without it cannot authenticate to the indexer.
sudo tar -czf $BACKUP_DIR/wazuh-worker-config.tar.gz -C /var/wazuh-manager \
    etc/wazuh-manager.conf \
    etc/wazuh-manager-internal-options.conf \
    etc/certs/ \
    queue/keystore/

# Carries the certificates and the indexer credential store
sudo chmod -R go-rwx $BACKUP_DIR
```

### Cluster Restore Procedures

#### Restore Master Node

1. Follow the [full manager restore procedure](#full-manager-restore) with `BACKUP_DIR` set to the master backup directory. It produces the same `wazuh-etc.tar.gz`, `wazuh-state.tar.gz` and `db/` layout Step 3 expects.
2. Verify the cluster configuration survived the `etc/` restore: `sudo grep -A10 "<cluster>" /var/wazuh-manager/etc/wazuh-manager.conf`
3. Start the manager and verify cluster status: `sudo /var/wazuh-manager/bin/cluster_control -l`

#### Restore Worker Node

A worker's global database and shared files come from the master, but its credential store does not: restore `queue/keystore/` or the node cannot authenticate to the indexer.

```bash
BACKUP_DIR="/backup/wazuh-worker-$(hostname)-YYYYMMDD-HHMMSS"

sudo systemctl stop wazuh-manager
sudo tar -xzf $BACKUP_DIR/wazuh-worker-config.tar.gz -C /var/wazuh-manager

sudo chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/etc /var/wazuh-manager/queue/keystore

# The files and directories the installer keeps root-owned, which the recursive
# chown above takes: the WPK signing anchor, the internal options, the schema that
# validates the configuration, the configuration itself, and the shared tree.
sudo chown root:wazuh-manager /var/wazuh-manager/etc \
    /var/wazuh-manager/etc/shared \
    /var/wazuh-manager/etc/indexer-plugins \
    /var/wazuh-manager/etc/wazuh-manager.conf \
    /var/wazuh-manager/etc/wazuh-manager-internal-options.conf \
    /var/wazuh-manager/etc/wazuh-manager.schema.json \
    /var/wazuh-manager/etc/wpk_root.pem \
    /var/wazuh-manager/etc/localtime

sudo sh -c 'cd /var/wazuh-manager/etc/certs || exit 1
    chown root:wazuh-manager . && chmod 1770 .
    chmod 640 * 2>/dev/null
    for CERT in root-ca.pem indexer-connector.pem indexer-connector-key.pem; do
        [ -f "$CERT" ] && chown root:wazuh-manager "$CERT"
    done'

sudo /var/wazuh-manager/bin/wazuh-manager-conf validate
sudo systemctl start wazuh-manager
```

Then confirm the node rejoined and allow a synchronisation cycle for the registry to arrive from the master:

```bash
sudo /var/wazuh-manager/bin/cluster_control -l
sudo tail -f /var/wazuh-manager/logs/cluster.log
```

#### Cluster Restore Verification

```bash
# Check cluster status
sudo /var/wazuh-manager/bin/cluster_control -l

# Verify cluster health
sudo /var/wazuh-manager/bin/cluster_control -i

# Check synchronization status
sudo tail -f /var/wazuh-manager/logs/cluster.log
```

### Container Deployments

The procedures above assume a package or source installation. They cannot be run as written in a container deployment: the manager image ships neither `tar` nor `sqlite3` nor `gzip`, and the service is not controlled with `systemctl`.

```bash
docker compose exec wazuh.manager sh -c 'command -v tar sqlite3 gzip' # prints nothing
```

The installation path inside the container is the same `/var/wazuh-manager`, so the set of paths to back up does not change. Drive the copy from the host instead, and stop the manager first so the databases are copied in a consistent state.

#### Container Backup

```bash
BACKUP_DIR="./wazuh-manager-backup-$(date +%Y%m%d-%H%M%S)"
PATHS="etc api/configuration queue/db queue/tasks queue/keystore queue/authd data"

# Stop the manager: without sqlite3 in the image there is no way to take a
# consistent copy of a database that is being written
docker compose stop wazuh.manager

for P in $PATHS; do
    mkdir -p "$BACKUP_DIR/$(dirname $P)"
    docker compose cp -a "wazuh.manager:/var/wazuh-manager/$P" "$BACKUP_DIR/$P"
done

docker compose start wazuh.manager
```

Verify the result with the commands in [Backup Verification](#backup-verification), run on the host against `$BACKUP_DIR`.

**Note**: `docker compose cp` copies the container filesystem, so it captures these paths whether or not the compose file mounts them as volumes. A `docker run --volumes-from` sidecar only reaches the paths that are volumes, which is why it is not used here.

#### Container Restore

```bash
BACKUP_DIR="./wazuh-manager-backup-YYYYMMDD-HHMMSS"
PATHS="etc api/configuration queue/db queue/tasks queue/keystore queue/authd data"

docker compose stop wazuh.manager

# Note the trailing "/." : it copies the directory's *contents*. Without it,
# docker cp puts the source directory inside the destination, producing
# /var/wazuh-manager/etc/etc and leaving the real paths untouched.
for P in $PATHS; do
    docker compose cp -a "$BACKUP_DIR/$P/." "wazuh.manager:/var/wazuh-manager/$P"
done

docker compose start wazuh.manager

# Copying in does not restore ownership: the files arrive owned by the host user
# that took the backup, and the image's init only remaps ids from older versions.
# Re-apply the ownership and modes, then restart so every daemon sees them.
docker compose exec -u root wazuh.manager sh -c '
    chown -R wazuh-manager:wazuh-manager \
        /var/wazuh-manager/etc \
        /var/wazuh-manager/queue/db \
        /var/wazuh-manager/queue/tasks \
        /var/wazuh-manager/queue/keystore \
        /var/wazuh-manager/queue/authd \
        /var/wazuh-manager/data
    chmod 660 /var/wazuh-manager/etc/client.keys
    chmod 660 /var/wazuh-manager/queue/db/global.db
    chown root:wazuh-manager /var/wazuh-manager/etc/certs
    chmod 1770 /var/wazuh-manager/etc/certs
    for CERT in root-ca.pem indexer-connector.pem indexer-connector-key.pem; do
        [ -f "/var/wazuh-manager/etc/certs/$CERT" ] && chown root:wazuh-manager "/var/wazuh-manager/etc/certs/$CERT"
    done
    chown -R root:wazuh-manager /var/wazuh-manager/api/configuration
    chown wazuh-manager:wazuh-manager /var/wazuh-manager/api/configuration/security/rbac.db
'

docker compose restart wazuh.manager
```

**Note**: with a plain `docker run` deployment the same commands apply, addressing the container by name (`docker cp`, `docker exec`) instead of by compose service.

---

## Agent Backup and Restore

### What to Back Up

The following components should be included in your Wazuh agent backup strategy:

#### Essential Data

- **Configuration files**: `/var/ossec/etc/`
  - `ossec.conf` - Agent configuration file
  - `local_internal_options.conf` - Internal configuration overrides

- **Agent key**: `/var/ossec/etc/client.keys`
  - Contains the agent's encryption key for manager communication
  - Critical for maintaining agent identity

#### Optional Data

- **Local databases**: `/var/ossec/queue/`
  - `fim/db/fim.db` - File Integrity Monitoring database
  - `syscollector/db/local.db` - System inventory database
  - `sca/db/sca.db` - Security Configuration Assessment database

  **Note**: These databases contain local state and scan results. They can be recreated by the agent modules after a restore, but backing them up preserves historical state information.

- **Logs**: `/var/ossec/logs/`
  - Historical logs for troubleshooting
  - Can be large; consider retention policies

### Agent Backup Procedures

#### Creating a Full Agent Backup

**Linux/Unix agents:**

```bash
# Create backup directory with timestamp
BACKUP_DIR="/backup/wazuh-agent-$(date +%Y%m%d-%H%M%S)"
sudo mkdir -p $BACKUP_DIR

# Backup configuration and agent key
sudo tar -czf $BACKUP_DIR/wazuh-agent-etc.tar.gz -C /var/ossec etc/

# Optional: Backup local databases
sudo tar -czf $BACKUP_DIR/wazuh-agent-db.tar.gz -C /var/ossec queue/fim/db/ queue/syscollector/db/ queue/sca/ 2>/dev/null || true

# Set proper permissions. These archives carry agent keys, API password hashes and
# the indexer credential store, so close them to other local users first.
sudo chmod -R go-rwx $BACKUP_DIR
sudo chown -R $(whoami):$(whoami) $BACKUP_DIR
```

**Windows agents:**

```powershell
# Create backup directory with timestamp
$BackupDir = "C:\backup\wazuh-agent-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Path $BackupDir -Force

# Backup configuration
Copy-Item -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Destination "$BackupDir\ossec.conf"
Copy-Item -Path "C:\Program Files (x86)\ossec-agent\client.keys" -Destination "$BackupDir\client.keys"
Copy-Item -Path "C:\Program Files (x86)\ossec-agent\local_internal_options.conf" -Destination "$BackupDir\local_internal_options.conf" -ErrorAction SilentlyContinue
```

**macOS agents:**

```bash
# Create backup directory with timestamp
BACKUP_DIR="/backup/wazuh-agent-$(date +%Y%m%d-%H%M%S)"
sudo mkdir -p $BACKUP_DIR

# Backup configuration and agent key
sudo tar -czf $BACKUP_DIR/wazuh-agent-etc.tar.gz -C /Library/Ossec etc/

# Optional: Backup local databases
sudo tar -czf $BACKUP_DIR/wazuh-agent-db.tar.gz -C /Library/Ossec queue/fim/db/ queue/syscollector/db/ queue/sca/ 2>/dev/null || true
```

#### Creating Selective Agent Backups

**Configuration and key only (Linux/macOS):**

```bash
sudo tar -czf wazuh-agent-config-$(date +%Y%m%d).tar.gz -C /var/ossec etc/ossec.conf etc/client.keys etc/local_internal_options.conf
```

**Agent key only (Linux):**

```bash
sudo cp /var/ossec/etc/client.keys wazuh-agent-key-$(date +%Y%m%d).backup
```

### Agent Restore Procedures

#### Pre-Restore Checklist

Before restoring an agent from backup:

1. Verify backup file integrity
2. Ensure compatible Wazuh version
3. Stop the agent service
4. Backup current configuration (optional)

#### Full Agent Restore

**Linux/Unix agents:**

```bash
# Stop the agent
sudo systemctl stop wazuh-agent

# Backup current configuration (optional)
sudo mv /var/ossec/etc /var/ossec/etc.old.$(date +%Y%m%d)

# Restore from backup
sudo tar -xzf $BACKUP_DIR/wazuh-agent-etc.tar.gz -C /var/ossec

# Optional: Restore databases
sudo tar -xzf $BACKUP_DIR/wazuh-agent-db.tar.gz -C /var/ossec 2>/dev/null || true

# Set proper permissions
sudo chown -R root:wazuh /var/ossec/etc
sudo chmod 640 /var/ossec/etc/client.keys
sudo chmod 640 /var/ossec/etc/ossec.conf

# Start the agent
sudo systemctl start wazuh-agent

# Verify agent status
sudo systemctl status wazuh-agent
```

**Windows agents:**

```powershell
# Stop the agent service
Stop-Service -Name wazuh

# Restore configuration files
Copy-Item -Path "$BackupDir\ossec.conf" -Destination "C:\Program Files (x86)\ossec-agent\ossec.conf" -Force
Copy-Item -Path "$BackupDir\client.keys" -Destination "C:\Program Files (x86)\ossec-agent\client.keys" -Force
Copy-Item -Path "$BackupDir\local_internal_options.conf" -Destination "C:\Program Files (x86)\ossec-agent\local_internal_options.conf" -Force -ErrorAction SilentlyContinue

# Start the agent service
Start-Service -Name wazuh

# Verify agent status
Get-Service -Name wazuh
```

**macOS agents:**

```bash
# Stop the agent
sudo /Library/Ossec/bin/wazuh-control stop

# Restore from backup
sudo tar -xzf $BACKUP_DIR/wazuh-agent-etc.tar.gz -C /Library/Ossec

# Optional: Restore databases
sudo tar -xzf $BACKUP_DIR/wazuh-agent-db.tar.gz -C /Library/Ossec 2>/dev/null || true

# Set proper permissions
sudo chown -R root:wazuh /Library/Ossec/etc
sudo chmod 640 /Library/Ossec/etc/client.keys

# Start the agent
sudo /Library/Ossec/bin/wazuh-control start

# Verify agent status
sudo /Library/Ossec/bin/wazuh-control status
```

---

## Best Practices

1. **Schedule regular backups**: Automate daily backups with retention policies
2. **Test restores regularly**: Verify backups can be restored successfully in a test environment
3. **Store backups off-site**: Use remote storage or cloud backup solutions
4. **Document procedures**: Maintain up-to-date restore procedures and runbooks
5. **Version compatibility**: Test backups after upgrades to ensure compatibility
6. **Monitor backup jobs**: Set up alerts for backup failures
7. **Encrypt sensitive data**: Protect backups containing certificates and keys
8. **Backup before changes**: Always backup before upgrades or major configuration changes
9. **Label backups clearly**: Include hostname, date, and backup type in filenames
10. **Verify integrity**: Always verify backup integrity after creation

---

## Troubleshooting

### Manager Issues

**Issue: Manager won't start after restore**

```bash
# Re-apply the ownership and modes from Step 4 of the restore procedure. Do not
# chown the whole installation: bin/ is root-owned and etc/certs holds root-owned
# indexer trust material.
sudo chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/etc

# The files and directories the installer keeps root-owned, which the recursive
# chown above takes: the WPK signing anchor, the internal options, the schema that
# validates the configuration, the configuration itself, and the shared tree.
sudo chown root:wazuh-manager /var/wazuh-manager/etc \
    /var/wazuh-manager/etc/shared \
    /var/wazuh-manager/etc/indexer-plugins \
    /var/wazuh-manager/etc/wazuh-manager.conf \
    /var/wazuh-manager/etc/wazuh-manager-internal-options.conf \
    /var/wazuh-manager/etc/wazuh-manager.schema.json \
    /var/wazuh-manager/etc/wpk_root.pem \
    /var/wazuh-manager/etc/localtime

# client.keys stays with the service account: authd appends to it after dropping
# privileges, so root ownership would stop enrollment.
sudo chown wazuh-manager:wazuh-manager /var/wazuh-manager/etc/client.keys
sudo chmod 660 /var/wazuh-manager/etc/client.keys

sudo sh -c 'cd /var/wazuh-manager/etc/certs || exit 1
    chown root:wazuh-manager . && chmod 1770 .
    chmod 640 * 2>/dev/null
    for CERT in root-ca.pem indexer-connector.pem indexer-connector-key.pem; do
        [ -f "$CERT" ] && chown root:wazuh-manager "$CERT"
    done'

# Check logs
sudo tail -100 /var/wazuh-manager/logs/wazuh-manager.log
```

**Issue: Agents not connecting after restore**

```bash
# Verify client.keys was restored
sudo ls -l /var/wazuh-manager/etc/client.keys

# Check global database
sudo sqlite3 /var/wazuh-manager/queue/db/global.db "SELECT id, name FROM agent"

# Restart manager
sudo systemctl restart wazuh-manager

# Check remoted logs
sudo tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep remoted
```

**Issue: Database corruption after restore**

```bash
# Check database integrity
sudo sqlite3 /var/wazuh-manager/queue/db/global.db "PRAGMA integrity_check"

# If corrupted, restore from backup again. Copy over the live database rather than
# removing it first, and only once the replacement is known to be there: an unset
# $BACKUP_DIR would otherwise leave the manager with no database at all.
sudo systemctl stop wazuh-manager
if [ -f "$BACKUP_DIR/db/global.db" ]; then
    sudo cp $BACKUP_DIR/db/global.db /var/wazuh-manager/queue/db/global.db
    sudo chown wazuh-manager:wazuh-manager /var/wazuh-manager/queue/db/global.db
    sudo chmod 660 /var/wazuh-manager/queue/db/global.db
    sudo systemctl start wazuh-manager
else
    echo "No backup at '$BACKUP_DIR/db/global.db' - leaving the live database alone"
fi
```

With no usable backup at hand, the manager's own periodic snapshots under `/var/wazuh-manager/backup/db/` are the next thing to try. They are gzipped copies of this same database:

```bash
sudo ls -l /var/wazuh-manager/backup/db/
sudo systemctl stop wazuh-manager
sudo gunzip -c /var/wazuh-manager/backup/db/global.db-backup-YYYY-MM-DD-HH:MM:SS.gz > /tmp/global.db
sudo cp /tmp/global.db /var/wazuh-manager/queue/db/global.db
sudo chown wazuh-manager:wazuh-manager /var/wazuh-manager/queue/db/global.db
sudo chmod 660 /var/wazuh-manager/queue/db/global.db
sudo systemctl start wazuh-manager
```

**Issue: Cluster not synchronizing after restore**

```bash
# Verify cluster configuration
sudo grep -A10 "<cluster>" /var/wazuh-manager/etc/wazuh-manager.conf

# Restart cluster daemon
sudo systemctl restart wazuh-manager

# Check cluster logs
sudo tail -f /var/wazuh-manager/logs/cluster.log

# Verify cluster connectivity
sudo /var/wazuh-manager/bin/cluster_control -l
```

### Agent Issues

**Issue: Agent won't start after restore**

```bash
# Check permissions (Linux)
sudo chown -R root:wazuh /var/ossec/etc
sudo chmod 640 /var/ossec/etc/client.keys

# Check logs
sudo tail -50 /var/ossec/logs/ossec.log
```

**Issue: Agent not connecting to manager after restore**

```bash
# Verify client.keys exists and has correct permissions
sudo ls -l /var/ossec/etc/client.keys

# Check manager IP configuration
sudo grep "<address>" /var/ossec/etc/ossec.conf

# Restart agent
sudo systemctl restart wazuh-agent

# Check connection logs
sudo tail -f /var/ossec/logs/ossec.log | grep "Connected to"
```

**Issue: Agent databases not accessible after restore**

```bash
# Check database file permissions
sudo ls -l /var/ossec/queue/fim/db/
sudo ls -l /var/ossec/queue/syscollector/db/
sudo ls -l /var/ossec/queue/sca/db/

# Set proper permissions
sudo chown -R root:wazuh /var/ossec/queue

# If databases are corrupted, remove them to allow recreation
sudo rm /var/ossec/queue/fim/db/*.db
sudo rm /var/ossec/queue/syscollector/db/*.db
sudo rm /var/ossec/queue/sca/db/*.db

# Restart agent to recreate databases
sudo systemctl restart wazuh-agent
```

---

## Additional Resources

- [Installation Guide](getting-started/installation.md)
- [Upgrade Guide](upgrade.md)
- [Configuration Reference](configuration/README.md)
- [Cluster Documentation](modules/cluster/README.md)
- [FIM Module](modules/fim/README.md)
- [SCA Module](modules/sca/README.md)
- [Syscollector Module](modules/syscollector/README.md)
