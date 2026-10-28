# Upgrade

This guide provides instructions for upgrading the Wazuh manager from an earlier 5.x version, and Wazuh agents to 5.x. The upgrade installs the new version's files and then restores the whole previous `/etc/wazuh-manager` and every `data/*` entry except `data/tzdb` over them (see [File preservation](#file-preservation)). A **package** upgrade (DEB or RPM) restarts a manager that was running when it started and leaves a stopped one stopped: the packages never enable or start the service on their own. An **`install.sh`** update always starts the manager at its end, whether or not it was running before.

**Important**: Upgrading the Wazuh **manager** from version 4.x to 5.x is **not supported**: the 5.x package (and `install.sh`) refuses to install over a 4.x manager, or beside one, with `ERROR: Upgrade from Wazuh manager versions prior to 5.x is not supported.` A 5.x manager is always a fresh installation; [Manager migration from 4.x to 5.0](../guide/migration/manager-4x-to-5x.md) describes how to carry agent keys, registry, groups and API users into it. Wazuh **agents** upgrade to 5.x from 4.14.0 or later, and a 4.x agent can connect to a 5.x manager through the legacy listener (see [Compatibility](compatibility.md)).

---

## Server

This section covers single-node and multi-node server upgrades.

### Pre-Upgrade Requirements

Before upgrading, ensure you:

1. Review release notes for breaking changes and new features
2. Verify system meets requirements for the new version
3. Create a backup following the [backup procedures](#backup)
4. Plan maintenance window for the upgrade
5. Notify relevant stakeholders

### Backup

Take a full backup before upgrading, as described in [Creating a Full Manager Backup](backup-restore.md#creating-a-full-manager-backup). A [rollback](#rollback) restores from it, and it has to carry more than the configuration: removing the package deletes the databases, the keystore and the API users.

### Download package

Download the Wazuh manager package for your platform and version. See the [Package Download](getting-started/packages.md#package-download) section for available repositories and download instructions.

### Upgrade

Install the downloaded Wazuh manager package for your platform:

**Debian-based platforms:**

```bash
sudo dpkg -i wazuh-manager_*.deb
```

**Red Hat-based platforms:**

```bash
sudo rpm -Uvh wazuh-manager-*.rpm
```

The package manager will automatically:
- Stop the current service
- Preserve your configuration and runtime data (see [File preservation](#file-preservation))
- Install the new binaries
- Resolve credentials with `bin/wazuh-manager-resolve-credentials --upgrade`, which fills in a missing password or keystore entry, imports the indexer's CA and client pair when they changed, and validates the manager's CA and server pairs without ever minting or issuing one (see [The resolver and its modes](getting-started/credentials.md#the-resolver-and-its-modes))
- Restart the service, only if it was running before the upgrade

### File preservation

During a 5.x to 5.x upgrade, the package and source upgrade scripts apply a **preserve / restore** mechanism that guarantees the following behavior:

| Path | Result after upgrade |
|---|---|
| `/etc/wazuh-manager` | Preserved from the previous installation: the whole directory is copied back over the newly installed files. |
| `data/*` (except `data/tzdb`) | Preserved from the previous installation: copied back over the newly installed files. |
| `data/tzdb` | Not preserved by the upgrade backup/restore flow; updated from the new package or source timezone database. |
| `bin/`, libraries, assets | Replaced by the new package. |

This applies to `.deb`, `.rpm`, and source-based upgrades.

File contents are preserved for the paths listed above. Ownership and modes depend on the stack:

- **DEB and RPM** copy the preserved files back with `cp -a`, so their ownership and modes come back as they were. Both then re-own `data/ruleset/` and `data/kvdb-ioc/` to `wazuh-manager:wazuh-manager`, and the DEB `postinst` additionally re-applies the package's own ownership and modes to every path the package ships, with one script for the installation directory (`restore-permissions.sh`) and one for the configuration directory (`restore-permissions-conf.sh`). Below a directory `wazuh-manager` can write (such as `/etc/wazuh-manager`, `logs/` or `queue/`), a path that is, or passes through, a symbolic link is left untouched, and so is a file with a second hard link.
- **Source** (`install.sh`) copies them back with `cp -R`, so the ownership and modes are the ones the installer assigns, not the ones the files had.

**Seeing new defaults.** Because `/etc/wazuh-manager` and `data/*` are restored after the new files are installed, a file the new version ships under them that the previous installation also had — the configuration with its new default values, the `wazuh-manager.schema.json` copy, the engine outputs under `outputs/default/`, the metrics templates under `indexer-plugins/`, the engine store documents under `data/store/` — comes back with its previous content, so a change to it reaches fresh installations only. On DEB manager upgrades a `wazuh-manager.conf.new` side-file is written alongside the live config so you can compare changes manually. On RPM no equivalent side-file is generated for the preserved paths; compare against the package defaults manually if needed.

The `WAZUH_REMOTE_*` installation variables described in [Installation](getting-started/installation.md) also shape that `wazuh-manager.conf.new`, so an upgrade run with them exported produces a side-file that already carries those values. If one of them holds an invalid value the side-file is not written and the upgrade reports a warning and continues: the live configuration is preserved either way.

Note also the indexer connector's trust anchor: a fresh installation names `/etc/wazuh-manager/certs/indexer-ca.pem` in `<indexer><ssl><certificate_authorities>`, while a configuration preserved from an earlier 5.0 build still names `certs/root-ca.pem`, which is now the agents' CA bundle only. Change that `<ca>` to `/etc/wazuh-manager/certs/indexer-ca.pem` in the live configuration (see [Indexer trust](getting-started/credentials.md#indexer-trust)).

Note in particular `remote.https.global_prefix`: its schema default, `/wazuh-manager/`, is applied to every configuration the manager loads, preserved or not. A preserved `wazuh-manager.conf` with no `<global_prefix>` element therefore serves routes under `/wazuh-manager/`, exactly like a fresh install. Agents use the same prefix by default; only an agent whose `<manager><endpoint>` ends in a bare `/` expects unprefixed routes (see [Client configuration](modules/client/configuration.md#endpoint)). To keep such agents working, add `<global_prefix>/</global_prefix>` to the live configuration (and, on DEB, to `wazuh-manager.conf.new` before adopting it), then move them to the prefixed path as a coordinated agent-side change.

**If the upgrade fails.** Source-based upgrades attempt to restore preserved files automatically when the upgrade fails or is interrupted after the preserve step. If automatic restore fails, or if a package-based upgrade fails before restoration completes, the preserve directory is left in place for manual recovery:

| Stack | Preserve directory |
|---|---|
| DEB | `/var/wazuh-manager/packages_files/manager_upgrade_preserve` |
| RPM | `/var/wazuh-manager/tmp/manager_upgrade_preserve` |
| Source | `${TMPDIR:-/tmp}/wazuh-manager-upgrade-preserve.*` |

Once you have recovered the data, remove the preserve directory before retrying. DEB and RPM upgrades abort if they find an existing preserve backup. Source upgrades create a new temporary preserve directory for each attempt, so an older source preserve directory does not block a retry, but it should still be removed after manual recovery.

### Verify upgrade

Verify the server is running:

```bash
# Check service status
sudo systemctl status wazuh-manager

# Check logs for errors
sudo tail -50 /var/wazuh-manager/logs/wazuh-manager.log

# Check database integrity. Guarded: an unguarded sqlite3 would create the very
# database it is checking, and an integrity check passes on an empty one.
sudo sh -c '[ -f /var/wazuh-manager/queue/db/global.db ] \
  && sqlite3 /var/wazuh-manager/queue/db/global.db "PRAGMA integrity_check" \
  || echo "MISSING: /var/wazuh-manager/queue/db/global.db"'
```

### Cluster upgrade

For cluster deployments, upgrade nodes in this order:

1. Worker nodes (one at a time)
2. Master node (last)

The master accepts a worker only when both run exactly the same Wazuh version: it refuses any other with error `3031` (`Worker and master versions are not the same`), and the worker keeps retrying every 10 seconds (see [Wazuh server cluster](modules/cluster/README.md#how-it-works)). So from the first node upgraded until the last, nodes on different versions are **not connected to each other**: each upgraded worker stays out of the cluster until the master is upgraded too, and only then do the workers rejoin and synchronize. Keep that window short, and expect the per-worker checks below to show the worker disconnected until the master upgrade.

#### Backup all nodes

Back up the master with [Master Node Backup](backup-restore.md#master-node-backup) and each worker with [Worker Node Backup](backup-restore.md#worker-node-backup). A worker's backup must carry its certificates, its CA and its keystore, which the cluster does not synchronize.

#### Upgrade worker nodes

Upgrade worker nodes one at a time to maintain service availability.

**On each worker node:**

1. Check cluster status before upgrading:

```bash
sudo /var/wazuh-manager/bin/cluster_control -l
```

2. Download the package (see [Package Download](getting-started/packages.md#package-download) section).

3. Upgrade the package:

**Debian-based platforms:**

```bash
sudo dpkg -i wazuh-manager_*.deb
```

**Red Hat-based platforms:**

```bash
sudo rpm -Uvh wazuh-manager-*.rpm
```

4. Verify the upgrade:

```bash
# Check service status
sudo systemctl status wazuh-manager

# The master refuses this worker until it runs the same version (3031)
sudo tail -50 /var/wazuh-manager/logs/cluster.log
```

**Repeat for each remaining worker node.**

#### Upgrade master node

Upgrade the master node last to ensure worker nodes can continue operating during their individual upgrades.

**On the master node:**

1. Verify all workers are upgraded and their services are running (`sudo systemctl status wazuh-manager` on each). They are not connected to the master yet.

2. Download the package (see [Package Download](getting-started/packages.md#package-download) section).

3. Upgrade the package:

**Debian-based platforms:**

```bash
sudo dpkg -i wazuh-manager_*.deb
```

**Red Hat-based platforms:**

```bash
sudo rpm -Uvh wazuh-manager-*.rpm
```

4. Verify the upgrade:

```bash
# Check service status
sudo systemctl status wazuh-manager

# Check cluster status
sudo /var/wazuh-manager/bin/cluster_control -l

# Verify cluster health
sudo /var/wazuh-manager/bin/cluster_control -i

# Check logs
sudo tail -50 /var/wazuh-manager/logs/wazuh-manager.log
sudo tail -50 /var/wazuh-manager/logs/cluster.log
```

5. Verify that every worker rejoined, now that the versions match:

```bash
# Every node should be listed, with the new version
sudo /var/wazuh-manager/bin/cluster_control -l

# Monitor cluster logs on master
sudo tail -f /var/wazuh-manager/logs/cluster.log
```

#### Verify cluster upgrade

After upgrading all nodes, perform comprehensive verification:

**On the master node:**

```bash
# Check cluster status
sudo /var/wazuh-manager/bin/cluster_control -l

# Check cluster health
sudo /var/wazuh-manager/bin/cluster_control -i

# Check database integrity. Guarded: an unguarded sqlite3 would create the very
# database it is checking, and an integrity check passes on an empty one.
sudo sh -c '[ -f /var/wazuh-manager/queue/db/global.db ] \
  && sqlite3 /var/wazuh-manager/queue/db/global.db "PRAGMA integrity_check" \
  || echo "MISSING: /var/wazuh-manager/queue/db/global.db"'

# Monitor logs for errors
sudo tail -100 /var/wazuh-manager/logs/wazuh-manager.log | grep -i error
sudo tail -100 /var/wazuh-manager/logs/cluster.log | grep -i error
```

**On each worker node:**

```bash
# Check cluster connectivity
sudo /var/wazuh-manager/bin/cluster_control -l

# Monitor logs
sudo tail -50 /var/wazuh-manager/logs/cluster.log
```

---

## Agent

This section covers agent upgrades across all supported platforms.

### Pre-Upgrade Recommendations

Before upgrading agents:

1. Back up agent configuration as a precaution (`ossec.conf` and `client.keys` are preserved automatically, but an external backup is still recommended)
2. Plan upgrades in batches to avoid upgrading all agents simultaneously
3. Test on non-production agents first
4. Verify manager compatibility with the new agent version

**Note:** Wazuh agents upgrade to 5.x only from version 4.14.0 or later. The agent packages and `install.sh` refuse an older one with `Upgrade to Wazuh 5.0.0 is only supported from version 4.14.0 or later.`; upgrade it to 4.14 first.

### File preservation

During a 5.x to 5.x agent upgrade the package scripts apply a **preserve / restore** mechanism for agent configuration files:

| Path | Result after upgrade |
|---|---|
| `etc/` (`ossec.conf`, `client.keys`, `local_internal_options.conf`, `localtime`, ...) | Preserved from the previous installation. |
| `bin/`, libraries | Replaced by the new package. |


On DEB upgrades a `ossec.conf.new` side-file is written with the new default config for comparison.

File contents, permissions, and ownership are preserved for the paths listed above. The upgrade does not normalize or reset any permissions or ownership set by the administrator.

Preserve directory locations for recovery:

| Stack | Preserve directory |
|---|---|
| DEB | `/var/ossec/packages_files/agent_config_files` |
| RPM | None. RPM itself keeps `client.keys` and `local_internal_options.conf` (`%config(noreplace)`) and `ossec.conf` (`%ghost`, generated only on first install) in place under `/var/ossec/etc/` |
| Source | `${TMPDIR:-/tmp}/wazuh-agent-upgrade-preserve.*` |

### Download package

Download the Wazuh agent package for your platform and version. See the [Package Download](getting-started/packages.md#package-download) section for available repositories and download instructions.

### Linux

#### Debian-based platforms

Upgrade the package:

```bash
sudo dpkg -i wazuh-agent_*.deb
```

Verify the agent is running:

```bash
sudo systemctl status wazuh-agent
```

The package restarts the agent only if it was running before the upgrade. If the agent does not start again, the upgrade still completes. It prints the errors the agent logged to `/var/ossec/logs/ossec.log` while starting, such as the manager refusing the enrollment, followed by a notice starting with `wazuh-agent: the agent did not start after the upgrade`. The agent stays stopped until the cause is fixed.

#### Red Hat-based platforms

Upgrade the package:

```bash
sudo rpm -Uvh wazuh-agent-*.rpm
```

Verify the agent is running:

```bash
sudo systemctl status wazuh-agent
```

The package behaves as on Debian-based platforms when the agent does not start again after the upgrade.

#### SUSE-based platforms

Upgrade the package:

```bash
sudo rpm -Uvh wazuh-agent-*.rpm
```

Verify the agent is running:

```bash
sudo systemctl status wazuh-agent
```

The package behaves as on Debian-based platforms when the agent does not start again after the upgrade.

### macOS

Upgrade the package:

```bash
sudo installer -pkg wazuh-agent-*.pkg -target /
```

Verify the agent is running:

```bash
sudo /Library/Ossec/bin/wazuh-control status
```

### Windows

Upgrade the package, replacing `<MSI_PATH>` with the full path of the new MSI. `Start-Process -Wait` returns only when the installer finishes, and the command prints the msiexec exit code: `0` or `3010` (restart pending) mean success, and any other value is a [Windows Installer error code](https://learn.microsoft.com/en-us/windows/win32/msi/error-codes).

```powershell
(Start-Process msiexec.exe -ArgumentList '/i "<MSI_PATH>" /q' -Wait -PassThru).ExitCode
```

Verify the agent is running:

```powershell
Get-Service -Name WazuhSvc
```

---

## Rollback

If the upgrade fails or causes issues, you can roll back to the previous version.

Removing the package is not a neutral step. `dpkg -r` and `rpm -e` delete `queue/` (every wazuh-db database, the Task Manager's `tasks.db`, the keystore and authd's pending deletions), `var/`, `logs/`, `data/` and the API directory (including `rbac.db`), and leave `/etc/wazuh-manager` only as `*.save` copies (see [Uninstall](uninstall.md#server)); `rpm -e` also deletes the `wazuh-manager` user and group. The installation of the previous version then starts from scratch, minting a new CA and new passwords, and the restore puts the backed-up state over it. Roll back only with a full backup taken as described in [Backup](#backup).

### Server rollback

**Step 1: Stop the service**

```bash
sudo systemctl stop wazuh-manager
```

**Step 2: Remove the new package**

**Debian-based platforms:**

```bash
sudo dpkg -r wazuh-manager
```

**Red Hat-based platforms:**

```bash
sudo rpm -e wazuh-manager
```

**Step 3: Install the previous version**

Install the previous version's package. A fresh package installation does not start the service.

**Step 4: Restore from backup**

Follow [Full Manager Restore](backup-restore.md#full-manager-restore) from its Step 2 on, with `BACKUP_DIR` set to the backup taken before the upgrade. Its last steps start the manager and verify the restore.

### Cluster rollback

If the cluster upgrade fails, roll back **every** node to the same previous version: the master refuses a worker on any other version (`3031`), so a node left on the new version stays out of the cluster.

On each node, run Steps 1 to 3 of the [server rollback](#server-rollback), then restore:

- **Master node**: [Restore Master Node](backup-restore.md#restore-master-node).
- **Worker nodes**: [Restore Worker Node](backup-restore.md#restore-worker-node).

Then verify that every node is listed, on the previous version:

```bash
sudo /var/wazuh-manager/bin/cluster_control -l
```

---

## Troubleshooting

### Server issues

**Issue: Manager fails to start after upgrade**

```bash
# Check logs for specific errors
sudo tail -100 /var/wazuh-manager/logs/wazuh-manager.log

# Verify permissions against what the package installs: never chown the whole tree,
# bin/ is root-owned and /etc/wazuh-manager/certs holds root-owned files
sudo ls -l /etc/wazuh-manager /etc/wazuh-manager/certs

# Check database integrity. Guarded: an unguarded sqlite3 would create the very
# database it is checking, and an integrity check passes on an empty one.
sudo sh -c '[ -f /var/wazuh-manager/queue/db/global.db ] \
  && sqlite3 /var/wazuh-manager/queue/db/global.db "PRAGMA integrity_check" \
  || echo "MISSING: /var/wazuh-manager/queue/db/global.db"'
```

**Issue: Agents not reconnecting after manager upgrade**

```bash
# Verify the manager is listening: 1517 (agents), 1514 (legacy agents, only when
# enabled), 1515 (enrollment), 1516 (cluster), 55000 (Server API, master only)
sudo ss -ltunp '( sport = :1514 or sport = :1515 or sport = :1516 or sport = :1517 or sport = :55000 )'

# Check that every daemon is running (remoted included)
sudo /var/wazuh-manager/bin/wazuh-manager-control status

# Review remoted logs
sudo tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep remoted

# Verify client.keys integrity
sudo ls -l /etc/wazuh-manager/client.keys
```

**Issue: Cluster node not synchronizing after upgrade**

```bash
# Check cluster configuration
sudo grep -A10 "<cluster>" /etc/wazuh-manager/wazuh-manager.conf

# Verify network connectivity
ping <master_node_ip>
telnet <master_node_ip> 1516

# Check the cluster daemon (a Python process, listed by status)
sudo /var/wazuh-manager/bin/wazuh-manager-control status

# Review cluster logs
sudo tail -100 /var/wazuh-manager/logs/cluster.log

# Restart cluster service
sudo systemctl restart wazuh-manager
```

**Issue: Global database refused after an upgrade or a rollback**

`wazuh-manager-db` refuses a `global.db` whose schema version it does not know, which is what a rollback over a database written by a newer release shows: `DB(global) Unsupported schema version <n> (expected: 1..<m>). Disabling database.` A schema upgrade that fails is rolled back to the snapshot it takes first (`backup/db/global.db-backup-<timestamp>-pre_upgrade.gz`) and logs `Failed to update global.db to version <n>. The global.db was restored to the original state.`

```bash
# Check database file permissions
sudo ls -l /var/wazuh-manager/queue/db/

# Review wazuh-manager.log for schema messages
sudo grep -E "schema version|Failed to update global.db" /var/wazuh-manager/logs/wazuh-manager.log

# If migration fails, restore from backup (the db/ copy of a backup taken with Option 1)
sudo systemctl stop wazuh-manager
sudo cp $BACKUP_DIR/db/global.db /var/wazuh-manager/queue/db/global.db
sudo chown wazuh-manager:wazuh-manager /var/wazuh-manager/queue/db/global.db
sudo chmod 640 /var/wazuh-manager/queue/db/global.db
sudo systemctl start wazuh-manager
```

### Upgrade aborted: existing preserve directory

If a previous package-based upgrade was interrupted, a preserve directory may still be present. DEB and RPM upgrades abort with `ERROR: Existing manager upgrade preserve backup found at <directory>.` Source upgrades use a new temporary preserve directory for each attempt, so older source preserve directories do not block retries. To recover:

1. Inspect the preserve directory contents.
2. Copy any needed files back: for the manager, its `etc/` to `/etc/wazuh-manager` and its `data/` to `/var/wazuh-manager/data`; for the agent, to `/var/ossec/etc`.
3. Remove the preserve directory, then retry the upgrade.

```bash
# Example for manager DEB
ls /var/wazuh-manager/packages_files/manager_upgrade_preserve/
# Recover if needed, then:
sudo rm -rf /var/wazuh-manager/packages_files/manager_upgrade_preserve
```

### Agent issues

**Issue: Agent fails to start after upgrade**

```bash
# Check logs
sudo tail -50 /var/ossec/logs/ossec.log

# Verify client.keys exists
sudo ls -l /var/ossec/etc/client.keys

# Check permissions
sudo chown -R root:wazuh /var/ossec/etc
```

**Issue: Agent not connecting after upgrade**

```bash
# Verify the manager endpoint. An upgrade never rewrites ossec.conf, so a carried-over
# 4.x file still spells this as <address>, which is deprecated but still read.
sudo grep -E "<endpoint>|<address>" /var/ossec/etc/ossec.conf

# Check network connectivity to the manager. The agent channel is 1517; 1514 is the
# legacy listener and an upgraded agent no longer uses it.
nc -vz <manager_ip> 1517

# Has the agent a trust anchor? A remote upgrade delivers one; a local package
# upgrade does not. Without it the agent connects but verifies nothing, until
# sudo /var/ossec/bin/wazuh-agent-auth --token-file <path> --certs-only installs one.
# A CA left in var/incoming means one was delivered but never installed, usually
# because the openssl command was missing during the upgrade (logged as (4126)).
sudo ls -l /var/ossec/etc/certs/root-ca.pem /var/ossec/var/incoming/root-ca.pem

# What does the agent say about TLS and enrollment? Every failure here names itself.
sudo grep -E "TLS verification|cacerts|pin_mismatch|\(41[0-9]{2}\)" /var/ossec/logs/ossec.log | tail -20

# Restart agent
sudo systemctl restart wazuh-agent
```

The message table in [Agent Not Connecting](modules/client/README.md#agent-not-connecting) maps each of those lines to its cause. An agent that still holds an identity keeps working on the key it has; one that has to register again needs an enrollment token, since the endpoint no longer holds a password.

**Issue: Windows agent upgrade fails**

```powershell
# Check the remote (WPK) upgrade log
Get-Content "C:\Program Files (x86)\ossec-agent\upgrade\upgrade.log"

# Check the agent log
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 50

# Verify service status
Get-Service -Name WazuhSvc

# Restart service
Restart-Service -Name WazuhSvc
```

---

## Best Practices

1. **Always backup before upgrading**: Follow the [backup procedures](backup-restore.md) before any upgrade
2. **Read release notes**: Review breaking changes and new features
3. **Test in non-production**: Validate upgrades in a test environment first
4. **Upgrade during maintenance windows**: Schedule upgrades during low-activity periods
5. **Upgrade incrementally**: For large deployments, upgrade in batches
6. **Monitor during upgrades**: Watch logs and metrics during the upgrade process
7. **Keep rollback ready**: Maintain previous version packages and backups
8. **Document changes**: Record configuration changes and issues encountered
9. **Upgrade workers before master**: In cluster deployments, upgrade workers first
10. **Verify compatibility**: Ensure manager and agent versions are compatible

---

## Additional Resources

- [Back Up and Restore Guide](backup-restore.md)
- [Installation Guide](getting-started/installation.md)
- [Configuration Reference](configuration/README.md)
- [Cluster Documentation](modules/cluster/README.md)
