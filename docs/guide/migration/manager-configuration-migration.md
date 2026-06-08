# Migrating Manager Configuration to Wazuh 5.0

Wazuh 5.0 introduces breaking changes to the manager configuration that require manual migration. **There is no in-place upgrade path from a 4.x manager to 5.0.** You must uninstall the 4.x manager, perform a fresh Wazuh 5.0 installation, and then restore your customizations from a pre-migration backup.

This guide covers the four configuration files that changed between versions:

- [`ossec.conf`](#osseconf--wazuh-managerconf) → `wazuh-manager.conf`
- [`internal_options.conf`](#internal_optionsconf--wazuh-manager-internal-optionsconf) → `wazuh-manager-internal-options.conf`
- [`api.yaml`](#apiyaml)
- [`cluster.json`](#clusterjson)

## Migration overview

| Area | 4.x | 5.0 |
|------|-----|-----|
| Installation path | `/var/ossec/` | `/var/wazuh-manager/` |
| Main configuration file | `etc/ossec.conf` | `etc/wazuh-manager.conf` |
| Root XML element | `<ossec_config>` | `<wazuh_config>` |
| Internal options file | `etc/internal_options.conf` + `etc/local_internal_options.conf` | `etc/wazuh-manager-internal-options.conf` |
| System user / group | `wazuh` | `wazuh-manager` |
| Manager log file | `logs/ossec.log` | `logs/wazuh-manager.log` |
| Manager JSON log file | `logs/ossec.json` | `logs/wazuh-manager.json` |

## Migration procedure

### 1. Back up the 4.x configuration

On the running **4.x manager**, export the configuration files you will need to adapt:

```bash
mkdir -p /tmp/wazuh-4x-backup
cp /var/ossec/etc/ossec.conf                    /tmp/wazuh-4x-backup/
cp /var/ossec/etc/internal_options.conf         /tmp/wazuh-4x-backup/
cp /var/ossec/etc/local_internal_options.conf   /tmp/wazuh-4x-backup/
cp /var/ossec/api/configuration/api.yaml        /tmp/wazuh-4x-backup/
```

Also back up any custom rules, decoders, and lists:

```bash
tar -czf /tmp/wazuh-4x-backup/custom-ruleset.tar.gz \
    /var/ossec/etc/rules/ \
    /var/ossec/etc/decoders/ \
    /var/ossec/etc/lists/
```

Keep these files somewhere that survives the reinstall (external storage or a remote location).

### 2. Uninstall the 4.x manager

Follow the official Wazuh documentation to uninstall the 4.x manager package for your distribution. This removes the 4.x binaries and the `/var/ossec/` directory.

### 3. Install the 5.0 manager

Follow the official Wazuh 5.0 installation documentation for your distribution. The manager installs to `/var/wazuh-manager/` and generates a fresh `wazuh-manager.conf` with default settings.

### 4. Apply configuration changes

Do not copy the 4.x configuration files directly into the 5.0 installation. Instead, use your backed-up files as a reference and apply your customizations to the new default files, following the per-file guidance in the sections below.

---

## `ossec.conf` → `wazuh-manager.conf`

The main configuration file is renamed and its XML root element changed. Several sections that were manager-side in 4.x have been removed; their functionality either moved to the agent, was replaced by a new subsystem, or was deprecated.

### Root element

Replace `<ossec_config>` with `<wazuh_config>` throughout the file.

**4.x:**
```xml
<ossec_config>
  ...
</ossec_config>
```

**5.0:**
```xml
<wazuh_config>
  ...
</wazuh_config>
```

### `<global>` section

In 5.0 the `<global>` parser only accepts `<agents_disconnection_time>` and `<agents_disconnection_alert_time>`. **Every other element causes a startup error.** Remove all email, logging, and alert options before starting the manager.

**4.x options that must be removed (cause startup error in 5.0):**

| Option | Notes |
|--------|-------|
| `<jsonout_output>` | Removed |
| `<alerts_log>` | Removed |
| `<logall>` | Removed |
| `<logall_json>` | Removed |
| `<email_notification>` | Email functionality removed — see [Mail forwarding and reporting migration](mail-forwarding-reporting.md) |
| `<smtp_server>` | Email functionality removed |
| `<email_from>` | Email functionality removed |
| `<email_to>` | Email functionality removed |
| `<email_maxperhour>` | Email functionality removed |
| `<email_log_source>` | Email functionality removed |

**4.x:**
```xml
<global>
  <jsonout_output>yes</jsonout_output>
  <alerts_log>yes</alerts_log>
  <logall>no</logall>
  <logall_json>no</logall_json>
  <email_notification>no</email_notification>
  <smtp_server>smtp.example.wazuh.com</smtp_server>
  <email_from>wazuh@example.wazuh.com</email_from>
  <email_to>recipient@example.wazuh.com</email_to>
  <email_maxperhour>12</email_maxperhour>
  <email_log_source>alerts.log</email_log_source>
  <agents_disconnection_time>15m</agents_disconnection_time>
  <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
</global>

<alerts>
  <log_alert_level>3</log_alert_level>
  <email_alert_level>12</email_alert_level>
</alerts>
```

**5.0:**
```xml
<global>
  <agents_disconnection_time>15m</agents_disconnection_time>
  <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
</global>
```

> [!NOTE]
> The second `<global>` block used for active-response whitelisting (`<white_list>`) is silently ignored in 5.0. It can be removed.

### `<remote>` section

The `<connection>` element has been removed. Leaving it in the configuration **causes a startup error** in 5.0. All agent-manager communication uses the secure protocol by default.

**4.x:**
```xml
<remote>
  <connection>secure</connection>
  <port>1514</port>
  <protocol>tcp</protocol>
</remote>
```

**5.0:**
```xml
<remote>
  <port>1514</port>
  <protocol>tcp</protocol>
</remote>
```

### `<auth>` section

The section is preserved. Update the certificate paths to reflect the new installation directory.

**4.x:**
```xml
<auth>
  ...
  <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
  <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
  ...
</auth>
```

**5.0:**
```xml
<auth>
  ...
  <ssl_manager_cert>/var/wazuh-manager/etc/sslmanager.cert</ssl_manager_cert>
  <ssl_manager_key>/var/wazuh-manager/etc/sslmanager.key</ssl_manager_key>
  ...
</auth>
```

### Sections to remove from `wazuh-manager.conf`

The following sections from 4.x must be removed. The table indicates the consequence of leaving each one in place.

| Section | Consequence if left in 5.0 | Notes |
|---------|---------------------------|-------|
| `<alerts>` | **Startup error** | Removed; no replacement |
| `<command>` blocks | **Startup error** | Removed from manager config; active-response commands are defined differently in 5.0 |
| `<ruleset>` | **Startup error** | Ruleset management moved to the engine; `etc/rules/`, `etc/decoders/`, `etc/lists/` do not exist in 5.0 |
| `<rootcheck>` | Silently accepted by parser | Functionality is fully agent-side in 5.0; remove to avoid confusion |
| `<syscheck>` | Silently accepted by parser | File integrity monitoring is fully agent-side in 5.0; remove to avoid confusion |
| `<wodle name="syscollector">` | Silently accepted by parser | Moved to agent configuration |
| `<localfile>` blocks | Silently accepted by parser | Log collection is an agent-side function; remove all entries |
| `<wodle name="open-scap">` | Silently accepted by parser | Replaced by SCA — see [CIS-CAT/OpenSCAP to SCA migration](ciscat-openscap-to-sca.md) |

> [!IMPORTANT]
> Custom rules and decoders from 4.x **cannot** be migrated by copying XML files to the manager. Content is managed through the engine's content management system. Refer to the Wazuh 5.0 engine documentation for the procedure to create and publish custom rules and decoders.


### `<vulnerability-detection>` section

The `<vulnerability-detection>` section is preserved in 5.0 but the `<index-status>` option has been removed.

**4.x:**
```xml
<vulnerability-detection>
  <enabled>yes</enabled>
  <index-status>yes</index-status>
  <feed-update-interval>60m</feed-update-interval>
</vulnerability-detection>
```

**5.0:**
```xml
<vulnerability-detection>
  <enabled>yes</enabled>
  <feed-update-interval>60m</feed-update-interval>
</vulnerability-detection>
```

Remove the `<index-status>` element from your configuration. All other options carry over unchanged.

### `<indexer>` section

The `<indexer>` section exists in both 4.x and 5.0 but has two changes.

**`<enabled>` removed**

In 4.x the section had an `<enabled>` flag. In 5.0 the indexer connection is always active and the flag has been removed.

**Certificate paths changed**

In 4.x the certificates pointed to Filebeat's certificate directory. In 5.0, Filebeat is no longer used, the manager connects to the indexer directly, so the paths must point to the manager's own certificates.

**4.x:**
```xml
<indexer>
  <enabled>yes</enabled>
  <hosts>
    <host>https://127.0.0.1:9200</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>/etc/filebeat/certs/root-ca.pem</ca>
    </certificate_authorities>
    <certificate>/etc/filebeat/certs/wazuh-server.pem</certificate>
    <key>/etc/filebeat/certs/wazuh-server-key.pem</key>
  </ssl>
</indexer>
```

**5.0:**
```xml
<indexer>
  <hosts>
    <host>https://127.0.0.1:9200</host>
  </hosts>
  <ssl>
    <certificate_authorities>
      <ca>/var/wazuh-manager/etc/certs/root-ca.pem</ca>
    </certificate_authorities>
    <certificate>/var/wazuh-manager/etc/certs/wazuh-manager.pem</certificate>
    <key>/var/wazuh-manager/etc/certs/wazuh-manager-key.pem</key>
  </ssl>
</indexer>
```

> [!NOTE]
> The 5.0 installer generates the `<indexer>` section with the correct certificate paths for your environment. If you are applying the configuration manually, update the paths to match your actual certificate locations under `/var/wazuh-manager/etc/certs/`.

---

## `internal_options.conf` → `wazuh-manager-internal-options.conf`

In 4.x, internal options were split across two files with a priority system:

1. `local_internal_options.conf` — user-editable overrides, read first (highest priority). This file survived upgrades.
2. `internal_options.conf` — system defaults shipped with the package, read as fallback. This file was overwritten on every upgrade and was not meant to be edited.

When a daemon needed an internal option value, it checked `local_internal_options.conf` first; if the key was absent, it fell back to `internal_options.conf`.

**In 5.0, this two-file system is gone.** There is now a single file: `wazuh-manager-internal-options.conf`. It inherits the role of the old `local_internal_options.conf` — it is the user-editable file where overrides are placed — while the system defaults are hardcoded directly in the engine. There is no longer a system-level file to fall back to.

Migrate your customizations from `local_internal_options.conf` (or from `internal_options.conf` if you edited it directly) to `wazuh-manager-internal-options.conf`, keeping only the options that remain valid in 5.0. Many options have been removed as part of the engine rewrite; carrying them forward will cause startup errors.

### Removed options

The following options were present in 4.x and have been removed in 5.0. Do not carry them forward.

**analysisd (entire section removed)**

The analysis daemon has been replaced by the Wazuh engine. All `analysisd.*` options are no longer valid:

```
analysisd.default_timeframe
analysisd.stats_maxdiff
analysisd.stats_mindiff
analysisd.stats_percent_diff
analysisd.fts_list_size
analysisd.fts_min_size_for_str
analysisd.log_fw
analysisd.decoder_order_size
analysisd.geoip_jsonout
analysisd.label_cache_maxage
analysisd.show_hidden_labels
analysisd.rlimit_nofile
analysisd.min_rotate_interval
analysisd.event_threads
analysisd.syscheck_threads
analysisd.syscollector_threads
analysisd.rootcheck_threads
analysisd.sca_threads
analysisd.hostinfo_threads
analysisd.winevt_threads
analysisd.rule_matching_threads
analysisd.dbsync_threads
analysisd.decode_event_queue_size
analysisd.decode_syscheck_queue_size
analysisd.decode_syscollector_queue_size
analysisd.decode_rootcheck_queue_size
analysisd.decode_sca_queue_size
analysisd.decode_hostinfo_queue_size
analysisd.decode_winevt_queue_size
analysisd.decode_output_queue_size
analysisd.archives_queue_size
analysisd.statistical_queue_size
analysisd.alerts_queue_size
analysisd.firewall_queue_size
analysisd.fts_queue_size
analysisd.dbsync_queue_size
analysisd.upgrade_queue_size
analysisd.state_interval
analysisd.debug
```

**remoted (most options removed)**

The remoted daemon has been simplified. The following 4.x options are no longer valid:

```
remoted.recv_counter_flush
remoted.comp_average_printout
remoted.verify_msg_id
remoted.pass_empty_keyfile
remoted.sender_pool
remoted.request_pool
remoted.request_timeout
remoted.response_timeout
remoted.request_rto_sec
remoted.request_rto_msec
remoted.max_attempts
remoted.shared_reload
remoted.rlimit_nofile
remoted.recv_timeout
remoted.merge_shared
remoted.disk_storage
remoted.keyupdate_interval
remoted.worker_pool
remoted.state_interval
remoted.guess_agent_group
remoted.receive_chunk
remoted.send_chunk
remoted.send_buffer_size
remoted.send_timeout_to_retry
remoted.buffer_relax
remoted.tcp_keepidle
remoted.tcp_keepintvl
remoted.tcp_keepcnt
remoted.control_msg_queue_size
remoted.router_forwarding_disabled
remoted.debug
```

> [!NOTE]
> `remoted.guess_agent_group` has been explicitly removed. The checksum-based group guessing mechanism no longer exists in Wazuh 5.0 — see [Agent groups migration](agent-groups-migration.md) for the replacement workflow.

**Other removed options:**

```
maild.strict_checking
maild.grouping
maild.full_subject
maild.geoip
monitord.sign
monitord.monitor_agents
monitord.delete_old_agents
wazuh_database.sync_agents
wazuh_database.real_time
wazuh_database.interval
wazuh_database.max_queued_events
wazuh_download.enabled
wazuh_db.worker_pool_size
wazuh_db.commit_time_min
wazuh_db.commit_time_max
wazuh_db.open_db_limit
wazuh_db.rlimit_nofile
wazuh_db.max_fragmentation
wazuh_db.fragmentation_threshold
wazuh_db.fragmentation_delta
wazuh_db.free_pages_percentage
wazuh_db.check_fragmentation_interval
wazuh_db.debug
dbd.reconnect_attempts
vulnerability-detection.translation_lru_size
vulnerability-detection.osdata_lru_size
vulnerability-detection.remediation_lru_size
vulnerability-detection.disable_scan_manager
vulnerability-detection.report_queue_size
authd.debug
integrator.debug
wazuh_clusterd.debug
```

### Retained options

The following options are valid in `wazuh-manager-internal-options.conf` and carry over from 4.x without change:

```
logcollector.*
monitord.day_wait
monitord.compress
monitord.rotate_log
monitord.keep_log_days
monitord.size_rotate
monitord.daily_rotations
execd.request_timeout
execd.max_restart_lock
execd.debug
syscheck.rt_delay
syscheck.max_fd_win_rt
syscheck.max_audit_entries
syscheck.default_max_depth
syscheck.symlink_scan_interval
syscheck.file_max_size
syscheck.debug
rootcheck.sleep
agent.tolerance
agent.warn_level
agent.normal_level
agent.min_eps
agent.state_interval
agent.recv_timeout
agent.remote_conf
agent.request_pool
agent.request_rto_sec
agent.request_rto_msec
agent.max_attempts
agent.debug
wazuh_modules.task_nice
wazuh_modules.max_eps
wazuh_modules.kill_timeout
wazuh_modules.rlimit_nofile
wazuh_modules.debug
wazuh_command.remote_commands
wazuh.thread_stack_size
sca.request_db_interval
sca.remote_commands
sca.commands_timeout
windows.debug
logcollector.debug
```

---

## `api.yaml`

The REST API configuration file is located at the same relative path (`api/configuration/api.yaml`) but the 5.0 default file removes several options.

Apply your 4.x customizations to the 5.0 default file using the changes described below.

### SSL certificate names

The default certificate file names have changed to reflect the renamed system user.

| Option | 4.x default | 5.0 default |
|--------|------------|------------|
| `https.key` | `server.key` | `manager.key` |
| `https.cert` | `server.crt` | `manager.crt` |

If you use custom certificate file names, no change is needed. If you rely on the defaults, rename your certificate files or update the configuration.

**4.x:**
```yaml
# https:
#  enabled: yes
#  key: "server.key"
#  cert: "server.crt"
#  use_ca: False
#  ca: "ca.crt"
#  ssl_protocol: "auto"
#  ssl_ciphers: ""
```

**5.0:**
```yaml
# https:
#  enabled: yes
#  key: "manager.key"
#  cert: "manager.crt"
#  use_ca: False
#  ca: "ca.crt"
#  ssl_ciphers: ""
```

### Removed options

| Option | Reason |
|--------|--------|
| `https.ssl_protocol` | Removed; the manager negotiates the best available protocol automatically |
| `experimental_features` | Experimental features toggle removed |

### Simplified `upload_configuration`

The `upload_configuration` section has been reduced. The following subsections are no longer valid in 5.0 and must be removed if present:

```yaml
# Removed in 5.0:
upload_configuration:
  remote_commands:
    localfile:
      allow: yes
      exceptions: []
    wodle_command:
      allow: yes
      exceptions: []
  limits:
    eps:
      allow: yes
  integrations:
    virustotal:
      public_key:
        allow: yes
        minimum_quota: 240
```

The options that remain valid are:

```yaml
upload_configuration:
  agents:
    allow_higher_versions:
      allow: yes
  indexer:
    allow: yes
```

---

## `cluster.json`

`cluster.json` is an internal file that controls cluster behavior. It is not intended for direct user editing, but if you applied customizations to the 4.x version you should be aware of the changes.

> [!WARNING]
> The `cluster.json` file located at `framework/wazuh/core/cluster/cluster.json` is replaced during installation. Do not copy the 4.x file into the 5.0 installation — use the 5.0 default as the base and reapply only the interval values you changed.

### Files synchronized in the cluster

The list of paths synchronized from master to worker nodes has changed.

**Removed from sync (4.x only):**

- `etc/rules/` — Custom rules are no longer propagated through the cluster file sync mechanism
- `etc/decoders/` — Same as above
- `etc/lists/` — Same as above

**`excluded_files` list updated:**

| 4.x | 5.0 |
|-----|-----|
| `ar.conf`, `ossec.conf` | `wazuh-manager.conf` |

### New master intervals

The following interval settings are new in 5.0 and appear in the `intervals.master` block:

| Setting | Default | Description |
|---------|---------|-------------|
| `sync_disconnected_agent_groups` | `300` | Seconds between syncs of disconnected agent group data |
| `sync_disconnected_agent_groups_batch_size` | `100` | Agents processed per batch during disconnected-agent group sync |
| `sync_disconnected_agent_groups_min_offline` | `600` | Minimum offline time (seconds) before an agent's groups are synced |
| `sync_disconnected_agent_cluster_name_delay` | `300` | Delay (seconds) before syncing cluster name for disconnected agents |
| `metrics_frequency` | `600` | Interval (seconds) for cluster metrics collection |
| `metrics_bulk_size` | `100` | Number of metric events per bulk write |

### New `common` section

A new `intervals.common` block is introduced:

```json
"common": {
    "active_response_polling": 30
}
```

This controls the polling interval (in seconds) for active-response status checks, shared across master and worker nodes.

---

## Checklist

Use this checklist to confirm the migration is complete before starting the 5.0 manager.

- [ ] `wazuh-manager.conf` root element is `<wazuh_config>`, not `<ossec_config>`
- [ ] `<global>` section contains only `<agents_disconnection_time>` and `<agents_disconnection_alert_time>` (plus any retained custom options)
- [ ] `<remote>` section does not contain `<connection>`
- [ ] `<auth>` certificate paths point to `/var/wazuh-manager/etc/`
- [ ] `<rootcheck>`, `<syscheck>`, `<wodle name="open-scap">`, `<wodle name="syscollector">`, `<alerts>`, `<command>`, `<localfile>`, and `<ruleset>` blocks have been removed
- [ ] `<vulnerability-detection>` section does not contain `<index-status>`
- [ ] `<indexer>` section does not contain `<enabled>` and certificate paths point to `/var/wazuh-manager/etc/certs/` (not Filebeat paths)
- [ ] Custom rules and decoders have been migrated through the engine's content management system (files cannot be copied to disk — refer to the Wazuh 5.0 engine documentation)
- [ ] `wazuh-manager-internal-options.conf` does not contain any `analysisd.*`, `remoted.*`, `maild.*`, `wazuh_db.*`, or `vulnerability-detection.*` options
- [ ] `api.yaml` SSL certificate names updated if using defaults (`server.key`/`server.crt` → `manager.key`/`manager.crt`)
- [ ] `api.yaml` does not reference `ssl_protocol`, `experimental_features`, `remote_commands`, `limits.eps`, or `integrations.virustotal`
- [ ] Agent groups restored — see [Agent groups migration](agent-groups-migration.md)
