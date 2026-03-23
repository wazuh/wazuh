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

- **Global database**: `/var/wazuh-manager/var/db/global.db`
  - Agent information (registration, metadata)
  - Agent group assignments
  - Group membership data

- **Agent groups**: `/var/wazuh-manager/etc/shared/`
  - Group-specific configurations and files
  - Shared files distributed to agents in each group

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

# Backup global database (use SQLite backup for consistency)
sudo mkdir -p $BACKUP_DIR/db
sudo sqlite3 /var/wazuh-manager/var/db/global.db ".backup '$BACKUP_DIR/db/global.db'"

# Set proper permissions
sudo chown -R $(whoami):$(whoami) $BACKUP_DIR
```

**Option 2: Backup with manager stopped** (recommended for critical operations)

This method ensures complete data consistency:

```bash
# Create backup directory with timestamp
BACKUP_DIR="/backup/wazuh-manager-$(date +%Y%m%d-%H%M%S)"
sudo mkdir -p $BACKUP_DIR

# Stop the Wazuh manager
sudo systemctl stop wazuh-manager

# Backup essential directories
sudo tar -czf $BACKUP_DIR/wazuh-manager-backup.tar.gz \
    -C /var/wazuh-manager \
    etc/ \
    var/db/global.db

# Start the Wazuh manager
sudo systemctl start wazuh-manager

# Verify manager is running
sudo systemctl status wazuh-manager

# Set proper permissions
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
sudo sqlite3 /var/wazuh-manager/var/db/global.db ".backup 'wazuh-global-db-$(date +%Y%m%d).db'"
```

#### Backup Verification

After creating a backup, verify its integrity:

```bash
# Verify tar archive integrity
tar -tzf $BACKUP_DIR/wazuh-etc.tar.gz > /dev/null && echo "Configuration backup verified" || echo "Backup verification failed"

# Check database integrity
sudo sqlite3 $BACKUP_DIR/db/global.db "PRAGMA integrity_check" && echo "Database backup verified" || echo "Database verification failed"

# Check backup size
du -sh $BACKUP_DIR

# List backup contents
tar -tzf $BACKUP_DIR/wazuh-etc.tar.gz | head -20
```

#### Automated Manager Backup Script

Create a script for regular automated backups:

```bash
#!/bin/bash
# /usr/local/bin/wazuh-manager-backup.sh

BACKUP_BASE="/backup/wazuh-manager"
RETENTION_DAYS=30
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="$BACKUP_BASE/backup-$TIMESTAMP"

# Create backup directory
mkdir -p $BACKUP_DIR/db

# Perform backup
tar -czf $BACKUP_DIR/wazuh-etc.tar.gz -C /var/wazuh-manager etc/
sqlite3 /var/wazuh-manager/var/db/global.db ".backup '$BACKUP_DIR/db/global.db'"

# Verify backup
if tar -tzf $BACKUP_DIR/wazuh-etc.tar.gz > /dev/null 2>&1 && \
   sqlite3 $BACKUP_DIR/db/global.db "PRAGMA integrity_check" > /dev/null 2>&1; then
    echo "$(date): Manager backup completed successfully to $BACKUP_DIR" >> /var/log/wazuh-backup.log

    # Remove old backups
    find $BACKUP_BASE -type d -name "backup-*" -mtime +$RETENTION_DAYS -exec rm -rf {} \;
else
    echo "$(date): Manager backup FAILED - verification error" >> /var/log/wazuh-backup.log
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

```bash
sudo mv /var/wazuh-manager/etc /var/wazuh-manager/etc.old.$(date +%Y%m%d)
sudo mv /var/wazuh-manager/var/db/global.db /var/wazuh-manager/var/db/global.db.old.$(date +%Y%m%d)
```

**Step 3: Restore from backup**

```bash
# Restore configuration
sudo tar -xzf $BACKUP_DIR/wazuh-etc.tar.gz -C /var/wazuh-manager

# Restore global database
sudo cp $BACKUP_DIR/db/global.db /var/wazuh-manager/var/db/global.db
```

**Step 4: Set proper permissions**

```bash
sudo chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/etc
sudo chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/var/db
sudo chmod 640 /var/wazuh-manager/etc/client.keys
sudo chmod 500 /var/wazuh-manager/etc/certs
sudo chmod 400 /var/wazuh-manager/etc/certs/*
```

**Step 5: Start the Wazuh manager**

```bash
sudo systemctl start wazuh-manager
```

**Step 6: Verify the restore**

```bash
# Check manager status
sudo systemctl status wazuh-manager

# Check database integrity
sudo sqlite3 /var/wazuh-manager/var/db/global.db "PRAGMA integrity_check"

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
sudo chmod 640 /var/wazuh-manager/etc/client.keys
sudo systemctl start wazuh-manager
```

**Restore global database only:**

```bash
sudo systemctl stop wazuh-manager
sudo cp wazuh-global-db-YYYYMMDD.db /var/wazuh-manager/var/db/global.db
sudo chown wazuh-manager:wazuh-manager /var/wazuh-manager/var/db/global.db
sudo chmod 640 /var/wazuh-manager/var/db/global.db
sudo systemctl start wazuh-manager
```

### Cluster-Specific Manager Backup

In a cluster deployment, backup procedures differ slightly:

**Master node:**
- Backup all data as described above
- The master node contains authoritative agent registration and group assignment data

**Worker nodes:**
- Configuration backup is sufficient
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
sudo tar -czf $BACKUP_DIR/wazuh-master-etc.tar.gz -C /var/wazuh-manager etc/
sudo sqlite3 /var/wazuh-manager/var/db/global.db ".backup '$BACKUP_DIR/db/global.db'"
```

#### Worker Node Backup

```bash
BACKUP_DIR="/backup/wazuh-worker-$(hostname)-$(date +%Y%m%d-%H%M%S)"
sudo mkdir -p $BACKUP_DIR

# Configuration only for worker nodes
sudo tar -czf $BACKUP_DIR/wazuh-worker-config.tar.gz -C /var/wazuh-manager/etc wazuh-manager.conf wazuh-manager-internal-options.conf
```

### Cluster Restore Procedures

#### Restore Master Node

1. Follow the full manager restore procedure
2. Verify cluster configuration in `/var/wazuh-manager/etc/wazuh-manager.conf`
3. Start the manager service
4. Verify cluster status: `sudo /var/wazuh-manager/bin/cluster_control -l`

#### Restore Worker Node

1. Restore configuration files
2. Ensure cluster settings point to correct master
3. Start the manager service
4. Verify connection to master node
5. Allow time for synchronization from master

#### Cluster Restore Verification

```bash
# Check cluster status
sudo /var/wazuh-manager/bin/cluster_control -l

# Verify cluster health
sudo /var/wazuh-manager/bin/cluster_control -i

# Check synchronization status
sudo tail -f /var/wazuh-manager/logs/cluster.log
```

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
  - `sca/sca.db` - Security Configuration Assessment database

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

# Set proper permissions
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
# Check permissions
sudo chown -R wazuh-manager:wazuh-manager /var/wazuh-manager
sudo chmod 640 /var/wazuh-manager/etc/client.keys

# Check logs
sudo tail -100 /var/wazuh-manager/logs/wazuh-manager.log
```

**Issue: Agents not connecting after restore**

```bash
# Verify client.keys was restored
sudo ls -l /var/wazuh-manager/etc/client.keys

# Check global database
sudo sqlite3 /var/wazuh-manager/var/db/global.db "SELECT id, name FROM agent"

# Restart manager
sudo systemctl restart wazuh-manager

# Check remoted logs
sudo tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep remoted
```

**Issue: Database corruption after restore**

```bash
# Check database integrity
sudo sqlite3 /var/wazuh-manager/var/db/global.db "PRAGMA integrity_check"

# If corrupted, restore from backup again
sudo systemctl stop wazuh-manager
sudo rm /var/wazuh-manager/var/db/global.db
sudo cp $BACKUP_DIR/db/global.db /var/wazuh-manager/var/db/global.db
sudo chown wazuh-manager:wazuh-manager /var/wazuh-manager/var/db/global.db
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

# Set proper permissions
sudo chown -R root:wazuh /var/ossec/queue

# If databases are corrupted, remove them to allow recreation
sudo rm /var/ossec/queue/fim/db/*.db
sudo rm /var/ossec/queue/syscollector/db/*.db
sudo rm /var/ossec/queue/sca/*.db

# Restart agent to recreate databases
sudo systemctl restart wazuh-agent
```

---

## Additional Resources

- [Installation Guide](getting-started/installation.md)
- [Upgrade Guide](upgrade.md)
- [Configuration Reference](configuration.md)
- [Cluster Documentation](modules/cluster/README.md)
- [FIM Module](modules/fim/README.md)
- [SCA Module](modules/sca/README.md)
- [Syscollector Module](modules/syscollector/README.md)
