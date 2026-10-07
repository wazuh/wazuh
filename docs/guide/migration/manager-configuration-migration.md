# Migrating Manager Configuration to Wazuh 5.0

Wazuh 5.0 introduces breaking changes to the manager configuration that require manual migration. **There is no in-place upgrade path from a 4.x manager to 5.0.** You must uninstall the 4.x manager, perform a fresh Wazuh 5.0 installation, and then restore your customizations from a pre-migration backup.

This guide covers the four configuration files that changed between versions:

- [`ossec.conf`](#ossecconf--wazuh-managerconf) → `wazuh-manager.conf`
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

### Strict XML

5.0 parses `wazuh-manager.conf` as **well-formed XML** validated against a JSON Schema
(`etc/wazuh-manager.schema.json`; `bin/wazuh-manager-conf validate` reports the same verdict the
daemons apply). Constructs the 4.x parser tolerated are now rejected at startup, each reported as
`(1244): Invalid configuration at '<pointer or file>': <detail>`:

- **A single root.** Multiple sibling `<wazuh_config>` blocks are no longer merged — keep one root.
- **No raw `&` or `<` in values.** Escape them as `&amp;` and `&lt;`. XML entities are now **decoded**:
  a value written `&amp;` reaches the daemons as `&` (4.x delivered the literal `&amp;`).
- **`<!-- -->` comments only.** The legacy `<! ... !>` comment form is a syntax error, and `--` inside
  a comment is rejected.
- **No `<var>` definitions** (they had no effect on the manager's own configuration in 4.x).
- **Unknown options are fatal**, reported with their JSON pointer
  (`/remote/connection: unknown option`), as are duplicated elements the schema declares unique.
- **Booleans are `yes`/`no`**, checked strictly; numbers must be digits; every option is typed by the
  schema (see the [generated reference](../../ref/configuration/manager/reference.md)).
- **`<cluster>` and `<indexer>` are required sections**, and `<cluster><key>` and `<indexer><hosts>`
  cannot be omitted within them: every manager runs as a cluster node and needs at least one indexer
  host to start `wazuh-manager-analysisd` (the installer always generates both).
- The **minimal valid document** is
  `<wazuh_config><cluster><key>...32 alphanumeric...</key></cluster><indexer><hosts><host>scheme://host:port</host></hosts></indexer></wazuh_config>`:
  every other option then takes its schema default (`bin/wazuh-manager-conf dump` prints the resulting
  effective document). A genuinely empty (zero-byte) file is NOT valid — it is rejected as malformed
  XML at startup.

### `<global>` section

In 5.0 the `<global>` parser accepts exactly one element: `<agents_disconnection_time>`. **Every other element causes a startup error.** Remove all email, logging, and alert options before starting the manager.

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
| `<update_check>` | Removed |
| `<agents_disconnection_alert_time>` | Removed; no replacement. In 4.x it delayed the agent-disconnection *alert*; 5.0 raises no such alert. Agents are still marked `disconnected` after `<agents_disconnection_time>` |

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
</global>
```

> [!IMPORTANT]
> Remove the second `<global>` block that 4.x configurations used for active-response whitelisting
> (`<white_list>`). 5.0 rejects it at startup: a repeated section is reported as
> `(1244): Invalid configuration at '/global': duplicate element <global>`, and `<white_list>` is not
> a 5.0 option either.

### `<remote>` section

The `<connection>`, `<allowed-ips>`, and `<denied-ips>` elements have been removed. Leaving any of
them in the configuration **causes a startup error** in 5.0. All agent-manager communication uses
the secure protocol by default.

In addition, `<remote>`'s options are now grouped under nested blocks: the classic TCP/UDP listener
options (`port`, `protocol`, `queue_size`, `ipv6`, `local_ip`, `rids_closing_time`,
`connection_overtake_time`) move under a new `<legacy>` block, and a new `<https>` block configures
the RESTinio-based HTTPS listener (see
[Remoted Configuration Reference](../../ref/modules/remoted/configuration.md#https-configuration)).
`<agents>` is unchanged. Options placed directly under `<remote>` (the pre-5.0 flat layout) are
rejected and the manager will not start; there is no automatic migration.

> `local_ip` keeps its 4.x effective default: an absent `<local_ip>` means `0.0.0.0` (accept agent
> connections from any IPv4 interface; with `<ipv6>yes</ipv6>` remoted listens on every IPv6
> interface instead). If your 4.x configuration set `<local_ip>`, move that value under `<legacy>`
> as shown below. See
> [`legacy.local_ip`](../../ref/modules/remoted/configuration.md#legacylocal_ip) for details.

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
  <legacy>
    <port>1514</port>
    <protocol>tcp</protocol>
    <local_ip>0.0.0.0</local_ip>
  </legacy>
</remote>
```

### `<auth>` section

The section is preserved, but `wazuh-manager-authd` now enforces TLS 1.3 as the minimum protocol version for agent enrollment. Besides updating the certificate paths to reflect the new installation directory, this requires two additional changes:

- `<ciphers>` must be a colon-separated list of TLS 1.3 ciphersuite names (`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_CCM_SHA256`, `TLS_AES_128_CCM_8_SHA256`). A 4.x-style OpenSSL cipher-list string does not match the schema's pattern, so the configuration is rejected (`(1244): Invalid configuration at '/auth/ciphers': does not satisfy 'pattern' [...]`) and the manager does not start. A `TLS_`-prefixed name that is not one of these suites passes the schema but is refused by `wazuh-manager-authd` itself (`Invalid TLS 1.3 cipher suite '<token>' in 'ciphers' option`).
- `<ssl_auto_negotiate>` was removed entirely. Leaving it in place is now an unknown option (`ERROR: (1244): Invalid configuration at '/auth/ssl_auto_negotiate': unknown option (does not satisfy 'additionalProperties') [...]`) and blocks the manager from starting.

**4.x:**
```xml
<auth>
  ...
  <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
  <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
  <ssl_auto_negotiate>no</ssl_auto_negotiate>
  <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
  ...
</auth>
```

**5.0:**
```xml
<auth>
  ...
  <ssl_manager_cert>/var/wazuh-manager/etc/certs/remoted.pem</ssl_manager_cert>
  <ssl_manager_key>/var/wazuh-manager/etc/certs/remoted-key.pem</ssl_manager_key>
  <ciphers>TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256</ciphers>
  ...
</auth>
```

`ssl_manager_cert`/`ssl_manager_key` now point at the same certificate the HTTPS agent listener of
`wazuh-manager-remoted` presents (schema defaults `etc/certs/remoted.pem` and
`etc/certs/remoted-key.pem`), not a separate pair of its own. The package issues that pair at
installation (see
[Credentials and certificates](../../ref/getting-started/installation.md#credentials-and-certificates)),
or you supply it from your own PKI (see
[Using certificates issued elsewhere](../../ref/getting-started/installation.md#using-certificates-issued-elsewhere)
and `ssl_manager_cert` in [authd/configuration.md](../../ref/modules/authd/configuration.md#ssl_manager_cert)).
If you do not override these two options, omit them and the defaults apply.

### Sections to remove from `wazuh-manager.conf`

The following 4.x sections must be removed. The 5.0 schema admits only the sections `global`,
`logging`, `remote`, `auth`, `wdb`, `vulnerability-detection`, `indexer`, `task-manager` and
`cluster`, so leaving any of these in place is a **startup error**:
`(1244): Invalid configuration at '/<section>': unknown option (does not satisfy 'additionalProperties') [...]`
(or `duplicate element <section>` when the block is repeated, as `<localfile>` and `<wodle>` usually
are), and `wazuh-manager-control start` starts nothing.

| Section | Notes |
|---------|-------|
| `<alerts>` | Removed; no replacement |
| `<command>` blocks | Removed from the manager configuration; active-response commands are defined differently in 5.0 — see [Active Response](active-response.md) |
| `<ruleset>` | Ruleset management moved to the engine; `etc/rules/`, `etc/decoders/`, `etc/lists/` do not exist in 5.0 |
| `<rootcheck>` | Agent-side only in 5.0 |
| `<syscheck>` | File integrity monitoring is agent-side only in 5.0 |
| `<wodle name="syscollector">` | Agent-side only; configure it in the agent's `ossec.conf` |
| `<localfile>` blocks | Log collection is an agent-side function |
| `<wodle name="open-scap">` | Replaced by SCA — see [CIS-CAT/OpenSCAP to SCA migration](ciscat-openscap-to-sca.md) |
| `<agent-upgrade>` | Its manager options moved into `<task-manager>` — see [Remote Agent Upgrade Migration](remote-agent-upgrade.md#configuration-changes) |

> [!IMPORTANT]
> Custom rules and decoders from 4.x **cannot** be migrated by copying XML files to the manager. Content is managed through the engine's content management system. See [Migrating rules from 4.x to 5.x](rules-4x-to-5x.md), [Migrating decoders from XML to YAML](xml-decoders-migration.md) and [Migrating CDB lists to KVDB lists](cdb-to-kvdb-migration.md).


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

Remove the `<index-status>` element from your configuration: left in place it is an unknown option and
the manager does not start. `<enabled>` and `<feed-update-interval>` carry over unchanged.

### `<indexer>` section

The `<indexer>` section exists in both 4.x and 5.0 but has two changes.

**`<enabled>` removed**

In 4.x the section had an `<enabled>` flag. In 5.0 the indexer connection is always active and the flag has been removed; left in place it is an unknown option and the manager does not start. The installer still needs an `apid.pem`/`apid-key.pem` pair under the default names to
complete: when the manager's CA has no private key (an anchor-only deployment), stage one signed by that
CA even if the API is then pointed at other files.

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
    <certificate>/var/wazuh-manager/etc/certs/indexer-connector.pem</certificate>
    <key>/var/wazuh-manager/etc/certs/indexer-connector-key.pem</key>
  </ssl>
</indexer>
```

> [!NOTE]
> The 5.0 installer generates the `<indexer>` section with these certificates as paths relative to
> `/var/wazuh-manager` (`etc/certs/root-ca.pem`, …); relative and absolute paths are equivalent. See
> [Configure the indexer address](../../ref/getting-started/installation.md#configure-the-indexer-address).

---

## `internal_options.conf` → `wazuh-manager-internal-options.conf`

In 4.x, internal options were split across two files with a priority system:

1. `local_internal_options.conf` — user-editable overrides, read first (highest priority). This file survived upgrades.
2. `internal_options.conf` — system defaults shipped with the package, read as fallback. This file was overwritten on every upgrade and was not meant to be edited.

When a daemon needed an internal option value, it checked `local_internal_options.conf` first; if the key was absent, it fell back to `internal_options.conf`.

**In 5.0, this two-file system is gone for the manager.** There is now a single file: `wazuh-manager-internal-options.conf`. It inherits the role of the old `local_internal_options.conf` — it is the user-editable file where overrides are placed — while the defaults are compiled into the manager binaries (the shipped file contains comments only). There is no longer a system-level file to fall back to. Agents continue to use the 4.x two-file system (`internal_options.conf` + `local_internal_options.conf`).

Migrate your customizations from `local_internal_options.conf` (or from `internal_options.conf` if you edited it directly) to `wazuh-manager-internal-options.conf`, keeping only the options that remain valid in 5.0. A key that 5.0 no longer reads does not cause an error: nothing looks it up, so it is **silently ignored** and has no effect. Do not carry the options below forward expecting them to do anything. A key that 5.0 still reads, given a value of the wrong type or out of its range, does stop the daemon that reads it.

### Removed options

The following options were present in 4.x and are not read by 5.0.

**analysisd**

The 4.x analysis daemon has been replaced by the Wazuh engine, which runs as `wazuh-manager-analysisd`. The engine reads its own set of `analysisd.*` keys from `wazuh-manager-internal-options.conf` (the complete list is the units registered in `src/engine/source/conf/src/conf.cpp`). Of the 4.x keys, only `analysisd.debug` survives, still as the log verbosity (`0` info, `1` debug, `2` trace). These 4.x keys are not read:

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
```

**remoted**

The other `remoted.*` keys of the 4.x file are still read. These are not:

```
remoted.guess_agent_group
remoted.state_interval
remoted.router_forwarding_disabled
```

> [!NOTE]
> The checksum-based group guessing behind `remoted.guess_agent_group` no longer exists in Wazuh 5.0 — see [Agent groups migration](agent-groups-migration.md) for the replacement workflow.

**Other removed options:**

```
maild.strict_checking
maild.grouping
maild.full_subject
maild.geoip
monitord.sign
monitord.debug
wazuh_download.enabled
dbd.reconnect_attempts
integrator.debug
```

The 4.x file also carried `logcollector.*`, `execd.*` and `agent.*` keys. They belong to agent-side
daemons that a 5.0 manager does not run; do not carry them into
`wazuh-manager-internal-options.conf`.

`wazuh_clusterd.debug` is still read in 5.0 (by `wazuh-manager-clusterd`, range `0`–`2`), so it can be
carried forward.

**Renamed options:**

`wazuh-manager-monitord` was removed in 5.0 and its work — agent disconnection detection, deletion of
long-disconnected agents, and log rotation — moved into the Task Manager inside
`wazuh-manager-modulesd`. The options survive with the same meanings under the `wazuh_modules`
namespace; their 5.0 ranges and defaults are in
[Where their settings come from](../../ref/modules/task_manager/configuration.md#where-their-settings-come-from):

| 4.x key | 5.0 key |
|---|---|
| `monitord.delete_old_agents` | `wazuh_modules.manager_task_delete_old_agents` |
| `monitord.monitor_agents` | `wazuh_modules.manager_task_monitor_agents` |
| `monitord.rotate_log` | `wazuh_modules.manager_task_log_rotate` |
| `monitord.compress` | `wazuh_modules.manager_task_log_compress` |
| `monitord.keep_log_days` | `wazuh_modules.manager_task_log_keep_days` |
| `monitord.day_wait` | `wazuh_modules.manager_task_log_day_wait` |
| `monitord.size_rotate` | `wazuh_modules.manager_task_log_size_rotate` |
| `monitord.daily_rotations` | `wazuh_modules.manager_task_log_daily_rotations` |

> [!IMPORTANT]
> An override left under the old name is **silently ignored** rather than rejected: the lookup
> compares the part before the first `.` as well as the part after it, so `monitord.rotate_log` on a
> 5.0 manager matches nothing and the compiled default applies. Rename any of these you had set.

> [!NOTE]
> This applies to the **manager** only. Agents keep `monitord.*` for their own log rotation, and
> their `local_internal_options.conf` needs no change — see
> [Upgrade 4.x to 5.x](upgrade-4x-to-5x.md).

`<global><agents_disconnection_time>` is unchanged and stays in `wazuh-manager.conf`: it is read by
both `remoted` and the disconnection sweep.

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

The 5.0 defaults resolve to `/var/wazuh-manager/etc/certs/apid.pem`, `apid-key.pem` and
`root-ca.pem`. The three values are **file names only** (letters, digits, `_`, `-`, `.`; a directory
is rejected with error `2000`) and are always looked up in `etc/certs/`. To keep your 4.x API
certificates, copy them into `/var/wazuh-manager/etc/certs/` under other file names, readable by `wazuh-manager`,
and set `https.key`/`https.cert`/`https.ca` to those names. The names `apid.pem` and `apid-key.pem` are
those of the pair the installer issues, or that you provide signed by the manager's CA, which the
installer validates (chain to the CA, `serverAuth`, `CA:FALSE`, not expired, with a SAN extension, key, owner and mode). `wazuh-manager-apid`
generates no certificate: if `https.enabled` is on and the configured pair is missing, not readable by
`wazuh-manager`, or its key does not match, it logs error `2003` naming the files in `logs/api.log` and
does not start.

**4.x (`ssl_protocol` is rejected in 5.0):**
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

5.0 validates `api.yaml` against a closed schema: a key it does not know makes `wazuh-manager-apid`
refuse the file with error `2000` (`Some parameters are not expected in the configuration file`) and
the API does not start. Remove these 4.x options:

| Option | Notes |
|--------|-------|
| `https.ssl_protocol` | No longer configurable |
| `experimental_features` | Experimental features toggle removed |
| `upload_configuration.integrations` (`virustotal.public_key`) | VirusTotal is no longer configured in the manager — see [VirusTotal migration](virustotal-migration.md) |

```yaml
# 4.x only — rejected by 5.0:
upload_configuration:
  integrations:
    virustotal:
      public_key:
        allow: yes
        minimum_quota: 240
```

### `upload_configuration`

`upload_configuration` decides which parts of `wazuh-manager.conf` the API may change through
`PUT /cluster/{node_id}/configuration`. In 5.0 two switches are enforced, both `yes` by default; a
change to a section whose switch is `no` is refused with error `1127` (indexer) or `1129`
(`allow_higher_versions`):

```yaml
upload_configuration:
  agents:
    allow_higher_versions:
      allow: yes   # changes to <auth>/<remote> <agents><allow_higher_versions>
  indexer:
    allow: yes     # changes to the <indexer> section
```

`remote_commands.{localfile,wodle_command}` and `limits.eps` are still accepted by the schema, so a
4.x file carrying them still loads, but no 5.0 code reads them: they have no effect and can be
removed.

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

**Synchronized in 5.0:** `etc/client.keys`, `etc/authd.pass`, `etc/enrollment_tokens.json`, everything
under `etc/shared/`, and `var/multigroups/merged.mg` files.

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
| `sync_disconnected_agent_cluster_name_delay` | `300` | Seconds the master waits before its one-time sync of the cluster name of disconnected agents (once per `wazuh-manager-clusterd` start) |
| `metrics_frequency` | `600` | Seconds between metrics snapshots written to the indexer; `0` disables them, and a value below `600` is raised to `600` |
| `metrics_bulk_size` | `100` | Documents per bulk request when a metrics snapshot is written |

### New `common` section

A new `intervals.common` block is introduced:

```json,fragment
"common": {
    "active_response_polling": 30,
    "active_response_page_size": 1000,
    "active_response_event_grace": 120
}
```

`active_response_polling` is how often, in seconds, every node reads new documents from `wazuh-active-responses*` to turn them into agent tasks; `active_response_page_size` is how many it reads at once, and `active_response_event_grace` how long a response may wait for its event to become visible. See [Active Response → Settings](../../ref/modules/active-response/architecture.md#settings).

---
