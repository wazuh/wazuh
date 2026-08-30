# Migrating Manager Configuration to Wazuh 5.0

Wazuh 5.0 introduces breaking changes to the manager configuration that require manual migration. **There is no in-place upgrade path from a 4.x manager to 5.0.** You must uninstall the 4.x manager, perform a fresh Wazuh 5.0 installation, and then restore your customizations from a pre-migration backup.

This guide covers the four configuration files that changed between versions:

- [`ossec.conf`](#osseconf-xml--wazuh-manageryml-yaml) → `wazuh-manager.yml` (YAML)
- [`internal_options.conf`](#internal_optionsconf--wazuh-manager-internal-optionsconf) → `wazuh-manager-internal-options.conf`
- [`api.yaml`](#apiyaml)
- [`cluster.json`](#clusterjson)

## Migration overview

| Area | 4.x | 5.0 |
|------|-----|-----|
| Installation path | `/var/ossec/` | `/var/wazuh-manager/` |
| Main configuration file | `etc/ossec.conf` (XML) | `etc/wazuh-manager.yml` (YAML, validated against `etc/wazuh-manager.schema.json`) |
| Root XML element | `<ossec_config>` | none: a YAML mapping with one key per section |
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

Follow the official Wazuh 5.0 installation documentation for your distribution. The manager installs to `/var/wazuh-manager/` and generates a fresh `wazuh-manager.yml` with default settings.

### 4. Apply configuration changes

Do not copy the 4.x configuration files directly into the 5.0 installation. Instead, use your backed-up files as a reference and apply your customizations to the new default files, following the per-file guidance in the sections below.

---

## `ossec.conf` (XML) → `wazuh-manager.yml` (YAML)

The manager configuration is a YAML file in 5.0: `/var/wazuh-manager/etc/wazuh-manager.yml`, a
mapping with one key per section and no root element. It is validated against a JSON schema
(`/var/wazuh-manager/etc/wazuh-manager.schema.json`) before any daemon starts, so unknown options and
out-of-range values are refused up front instead of being ignored or reported by one daemon. The agent
keeps its XML `ossec.conf` (and `agent.conf` is still XML on the manager).

There is no automatic conversion: install 5.0, let the installer generate `wazuh-manager.yml` with
its defaults, and carry over the 4.x values you had customized using the tables below. Booleans are
`true`/`false` (not `yes`/`no`), repeated elements become lists, and 4.x sections that no longer exist
must simply not be added. Every option, with its type, default and constraints, is listed in the
[Manager Configuration Reference](../../ref/configuration/manager/reference.md).

**4.x:**
```xml
<ossec_config>
  <global>...</global>
  <remote>...</remote>
</ossec_config>
```

**5.0:**
```yaml
global:
  agents_disconnection_time: 15m
remote:
  legacy:
    port: 1514
```

### `<global>` → `global`

Only two options survive; **every other 4.x element of `<global>` has no YAML counterpart**.

| 4.x element | 5.0 option | Type, default |
|---|---|---|
| `<agents_disconnection_time>` | `global.agents_disconnection_time` | duration, `15m` |
| `<agents_disconnection_alert_time>` | `global.agents_disconnection_alert_time` | duration, `0` |
| `<jsonout_output>`, `<alerts_log>`, `<logall>`, `<logall_json>` | — | Removed (alert output belongs to the engine) |
| `<email_notification>`, `<smtp_server>`, `<email_from>`, `<email_to>`, `<email_maxperhour>`, `<email_log_source>` | — | Email functionality removed — see [Mail forwarding and reporting migration](mail-forwarding-reporting.md) |
| `<update_check>` | — | Removed |
| second `<global>` with `<white_list>` | — | Removed (active response is agent-side) |

```yaml
global:
  agents_disconnection_time: 15m
  agents_disconnection_alert_time: 0
```

### `<remote>` → `remote`

The classic TCP/UDP listener options move under `remote.legacy`; the HTTPS agent server has its own
`remote.https` mapping (see [Remoted Configuration](../../ref/modules/remoted/configuration.md)); the
version policy is `remote.agents`. `<connection>`, `<allowed-ips>` and `<denied-ips>` have no
counterpart, and an unknown option under `remote` is refused with `(1244): Invalid configuration at
'/remote/<name>'`.

| 4.x element | 5.0 option | Type, default |
|---|---|---|
| `<connection>` | — | Removed: all agent-manager communication uses the secure protocol |
| `<port>` | `remote.legacy.port` | integer 1-65535, `1514` |
| `<protocol>` (`tcp,udp`) | `remote.legacy.protocol` | list of `tcp`/`udp`, `[tcp]` — an unknown protocol is refused, it no longer falls back to TCP |
| `<ipv6>` | `remote.legacy.ipv6` | boolean, `false` |
| `<local_ip>` | `remote.legacy.local_ip` | IP, `127.0.0.1` (see the breaking change below) |
| `<queue_size>` | `remote.legacy.queue_size` | integer >= 1, `131072` |
| `<rids_closing_time>` | `remote.legacy.rids_closing_time` | duration, `5m` |
| `<connection_overtake_time>` | `remote.legacy.connection_overtake_time` | integer 0-3600, `60` |
| `<allowed-ips>`, `<denied-ips>` | — | Removed |
| — | `remote.legacy.enabled` | boolean, `true` — set to `false` to run the HTTPS listener only |
| — | `remote.https.*` | new in 5.0: `port` (`1517`), `bind_addr`, `global_prefix`, `certificate`, `key`, `ca`, `verification_mode`, `ciphers`, `max_body_size`, `dual_stack` |
| `<agents><allow_higher_versions>` | `remote.agents.allow_higher_versions` | boolean, `false` |

> **Breaking change:** `local_ip`'s default also changed. In 4.x, leaving `local_ip` unset meant
> "accept agent connections from any interface." In 5.0 an absent `remote.legacy.local_ip` defaults to
> `127.0.0.1` (loopback-only) and `remote.https.bind_addr` also defaults to `127.0.0.1`. **If your 4.x
> configuration did not set `<local_ip>`, set `remote.legacy.local_ip: 0.0.0.0` (and
> `remote.https.bind_addr: 0.0.0.0` for the HTTPS listener) to keep accepting agents from other hosts.**

**4.x:**
```xml
<remote>
  <connection>secure</connection>
  <port>1514</port>
  <protocol>tcp</protocol>
</remote>
```

**5.0:**
```yaml
remote:
  legacy:
    port: 1514
    protocol: [tcp]
    local_ip: 0.0.0.0
  https:
    port: 1517
    bind_addr: 0.0.0.0
```

### `<auth>` → `auth`

The options keep their names. `wazuh-manager-authd` enforces TLS 1.3 as the minimum protocol version,
`ciphers` must be a colon-separated list of TLS 1.3 ciphersuite names (`TLS_AES_128_GCM_SHA256`,
`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_CCM_SHA256`,
`TLS_AES_128_CCM_8_SHA256`), and `ssl_manager_cert`/`ssl_manager_key` point at the same certificate the
HTTPS agent server presents (authd no longer owns a certificate of its own).

| 4.x element | 5.0 option | Type, default |
|---|---|---|
| `<disabled>` | `auth.disabled` | boolean, `false` |
| `<port>` | `auth.port` | integer 1-65535, `1515` |
| `<use_source_ip>` | `auth.use_source_ip` | boolean, `false` |
| `<force><enabled>` | `auth.force.enabled` | boolean, `true` |
| `<force><key_mismatch>` | `auth.force.key_mismatch` | boolean, `true` |
| `<force><disconnected_time enabled="yes">1h</disconnected_time>` | `auth.force.disconnected_time.enabled` / `.value` | boolean `true` / duration `1h` (the XML attribute becomes a key) |
| `<force><after_registration_time>` | `auth.force.after_registration_time` | duration, `1h` |
| `<purge>` | `auth.purge` | boolean, `false` |
| `<use_password>` | `auth.use_password` | boolean, `false` (the installer generates the file with `true`) |
| `<ciphers>` | `auth.ciphers` | TLS 1.3 suites, `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256` |
| `<ssl_agent_ca>` | `auth.ssl_agent_ca` | path, unset |
| `<ssl_verify_host>` | `auth.ssl_verify_host` | boolean, `false` |
| `<ssl_manager_cert>` | `auth.ssl_manager_cert` | path, `etc/certs/remoted.pem` |
| `<ssl_manager_key>` | `auth.ssl_manager_key` | path, `etc/certs/remoted-key.pem` |
| `<ssl_auto_negotiate>` | — | Removed: an unknown option is refused (`/auth/ssl_auto_negotiate`) |
| `<remote_enrollment>` | `auth.remote_enrollment` | boolean, `true` |
| — | `auth.legacy_enrollment` | boolean, `true` — port 1515 enrollment; `false` leaves only the HTTPS `/enroll` endpoint |
| `<agents><allow_higher_versions>` | `auth.agents.allow_higher_versions` | boolean, `false` |

```yaml
auth:
  disabled: false
  port: 1515
  use_password: true
  ciphers: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
  ssl_manager_cert: etc/certs/remoted.pem
  ssl_manager_key: etc/certs/remoted-key.pem
  force:
    enabled: true
    disconnected_time:
      enabled: true
      value: 1h
```

### Sections with no YAML counterpart

The manager configuration only has the sections of the reference (`global`, `logging`, `remote`,
`auth`, `wdb`, `vulnerability-detection`, `indexer`, `agent-upgrade`, `task-manager`, `cluster`). Any
other key at the top level is refused at start-up (`(1244): Invalid configuration at '/<name>': unknown
option`), so the 4.x sections below must not be carried over:

| 4.x section | Notes |
|---------|-------|
| `<alerts>` | Removed; no replacement |
| `<command>` blocks | Active-response commands are not defined in the manager configuration in 5.0 |
| `<ruleset>` | Ruleset management moved to the engine; `etc/rules/`, `etc/decoders/`, `etc/lists/` do not exist in 5.0 |
| `<rootcheck>`, `<syscheck>`, `<wodle name="syscollector">`, `<localfile>` | Agent-side functionality: configure it in the agents (`ossec.conf`) or centrally in `etc/shared/<group>/agent.conf`, which stays XML |
| `<wodle name="open-scap">` | Replaced by SCA — see [CIS-CAT/OpenSCAP to SCA migration](ciscat-openscap-to-sca.md) |
| `<active-response>`, `<labels>`, `<client_buffer>`, `<integration>`, `<syslog_output>`, `<database_output>`, `<email_alerts>`, `<reports>`, `<agentless>`, `<fluent-forward>`, `<agent-key-polling>` | Removed in 5.0 (agent-side, or the daemon was removed) |

> [!IMPORTANT]
> Custom rules and decoders from 4.x **cannot** be migrated by copying XML files to the manager. Content is managed through the engine's content management system. Refer to the Wazuh 5.0 engine documentation for details.

### `<vulnerability-detection>` → `vulnerability-detection`

| 4.x element | 5.0 option | Type, default |
|---|---|---|
| `<enabled>` | `vulnerability-detection.enabled` | boolean, `true` |
| `<index-status>` | — | Removed |
| `<feed-update-interval>` | `vulnerability-detection.feed-update-interval` | duration, `60m` |

```yaml
vulnerability-detection:
  enabled: true
  feed-update-interval: 60m
```

### `<indexer>` → `indexer`

The connection is always active (the 4.x `<enabled>` flag is gone) and the certificate paths point at
the manager's own certificates instead of Filebeat's. The installer generates this section with the
right paths; when writing it by hand, keep the lists as YAML sequences.

| 4.x element | 5.0 option | Type, default |
|---|---|---|
| `<enabled>` | — | Removed |
| `<hosts><host>` | `indexer.hosts` | list of URLs (`https://host:9200`), `[]` — an empty list means "no indexer" |
| `<ssl><certificate_authorities><ca>` | `indexer.ssl.certificate_authorities` | list of paths |
| `<ssl><certificate>` | `indexer.ssl.certificate` | path |
| `<ssl><key>` | `indexer.ssl.key` | path |

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
```yaml
indexer:
  hosts:
    - https://127.0.0.1:9200
  ssl:
    certificate_authorities:
      - etc/certs/root-ca.pem
    certificate: etc/certs/indexer-connector.pem
    key: etc/certs/indexer-connector-key.pem
```

### Validation

Check the file before starting the manager:

```bash
sudo /var/wazuh-manager/bin/wazuh-manager-conf validate          # silent when the file is valid
sudo /var/wazuh-manager/bin/wazuh-manager-conf get remote.legacy.port
sudo /var/wazuh-manager/bin/wazuh-manager-conf dump               # the effective document, defaults applied
```

An invalid file is refused by `wazuh-manager-control start` before any daemon runs, with the JSON
pointer of the offending option, for example
`(1244): Invalid configuration at '/remote/legacy/protocol/0': does not satisfy 'enum'`. This is
stricter than 4.x: values a daemon used to warn about and replace with a default (an unknown
protocol, a port above 65535, a malformed duration such as `4S`, a negative `after_registration_time`,
an empty `max_files`) now stop the manager until the file is fixed. The daemons report the same
error in `logs/wazuh-manager.log` as `ERROR: (1244): Invalid configuration at '<file>': <pointer>: ...`
followed by `CRITICAL: (1202): Configuration error at '<file>'.`.

### API

`GET /cluster/{node_id}/configuration` returns the effective sections as JSON (native booleans and
integers; durations as written), `raw=true` returns the YAML text, and `PUT /cluster/{node_id}/configuration`
replaces the file with a YAML document (`Content-Type: application/yaml` or
`application/octet-stream`); an XML body is rejected with 415 and an invalid document with error 1130
and its JSON pointer. Tooling that uploaded XML through the API must send YAML.

---

## `internal_options.conf` → `wazuh-manager-internal-options.conf`

In 4.x, internal options were split across two files with a priority system:

1. `local_internal_options.conf` — user-editable overrides, read first (highest priority). This file survived upgrades.
2. `internal_options.conf` — system defaults shipped with the package, read as fallback. This file was overwritten on every upgrade and was not meant to be edited.

When a daemon needed an internal option value, it checked `local_internal_options.conf` first; if the key was absent, it fell back to `internal_options.conf`.

**In 5.0, this two-file system is gone for the manager.** There is now a single file: `wazuh-manager-internal-options.conf`. It inherits the role of the old `local_internal_options.conf` — it is the user-editable file where overrides are placed — while the system defaults are hardcoded directly in the engine. There is no longer a system-level file to fall back to. Agents continue to use the 4.x two-file system (`internal_options.conf` + `local_internal_options.conf`).

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

**remoted**

Only one option has been removed from remoted:

```
remoted.guess_agent_group
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
wazuh_download.enabled
dbd.reconnect_attempts
integrator.debug
wazuh_clusterd.debug
```

---

## `api.yaml`

The REST API configuration file is located at the same relative path (`api/configuration/api.yaml`) but the 5.0 default file removes several options.

Apply your 4.x customizations to the 5.0 default file using the changes described below.

### SSL certificate names

The API certificates moved to the unified `etc/certs` directory and were renamed after the daemon (`apid`). The default file names are resolved relative to `etc/certs`.

| Option | 4.x default | 5.0 default |
|--------|------------|------------|
| `https.key` | `server.key` | `apid-key.pem` |
| `https.cert` | `server.crt` | `apid.pem` |
| `https.ca` | `ca.crt` | `root-ca.pem` |

The 5.0 defaults resolve to `etc/certs/apid.pem`, `etc/certs/apid-key.pem` and `etc/certs/root-ca.pem`. If you use custom certificate file names, no change is needed. If you rely on the defaults, move and rename your certificate files or update the configuration.

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
#  key: "apid-key.pem"
#  cert: "apid.pem"
#  use_ca: False
#  ca: "root-ca.pem"
#  ssl_ciphers: ""
```

### Removed options

| Option | Reason |
|--------|--------|
| `https.ssl_protocol` | Removed; the manager negotiates the best available protocol automatically |
| `experimental_features` | Experimental features toggle removed |

### Simplified `upload_configuration`

The `upload_configuration.integrations.virustotal` subsection is no longer valid in 5.0 and must be removed if present:

```yaml
# Removed in 5.0:
upload_configuration:
  integrations:
    virustotal:
      public_key:
        allow: yes
        minimum_quota: 240
```

`remote_commands.{localfile,wodle_command}` and `limits.eps` are still valid in 5.0. The options that remain valid are:

```yaml
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
| `ar.conf`, `ossec.conf` | `wazuh-manager.yml` |

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
