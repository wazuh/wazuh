# Migrating a Wazuh manager from 4.x to 5.0

A 4.x manager cannot be upgraded in place. The 5.0 manager is a fresh installation in a new path
(`/var/wazuh-manager/`), run by a new system user (`wazuh-manager`), with a new configuration
format and a new agent protocol. What survives the move is what you carry across yourself.

This guide is the procedure, in the order you execute it. Each step links to the detailed guide
for that area. It was written against a 4.14.x manager with enrolled Linux and Windows 4.14.x
agents, custom groups, agents assigned to groups from the manager side, API users and a populated
indexer.

## What is kept and what is not

| Data | Outcome | How |
|---|---|---|
| Agent identities: ids, names, keys (`client.keys`) | Kept. Agents reconnect without re-enrolling. | Step 3 |
| Agent registry: registration date, last known version and OS, group membership (`global.db`) | Kept, including assignments made from the manager or the API that never reached the agent's `ossec.conf`. | Step 3 |
| Group folders (`etc/shared/<group>/`) | Kept. `agent.conf` files must be valid for 5.0. | Step 3 |
| Enrollment password (`authd.pass`) | Kept, so 4.x agents (and new ones) enroll with the password they already have. | Step 3 |
| API users, roles and policies (`rbac.db`) | Kept, including passwords. | Step 3 |
| Manager configuration | Rewritten by hand into `wazuh-manager.conf`. | Step 4 |
| TLS material | Not carried. 5.0 needs its own CA and agent-listener certificate, issued before the first start, and every agent ends up verifying the manager against that CA. | Step 2, [Step 7](#7-upgrade-the-agents-to-50) |
| Alerts, inventory, vulnerability and SCA history in the indexer | Not read by 5.0. The 4.x indices stay in the indexer for consultation; inventory, FIM, SCA and vulnerability state is rebuilt by each agent once it runs 5.0. | Section [Historical data](#historical-data) |
| Agent labels | Removed in 5.0 on both sides. Not migrated. | |
| Custom rules, decoders and CDB lists | Not migrated. The engine uses a different model; see the ruleset guides. | [Rules](rules-4x-to-5x.md), [decoders](xml-decoders-migration.md), [CDB lists](cdb-to-kvdb-migration.md) |
| Modules removed in 5.0 (email, agentless, VirusTotal, syslog output, ...) | Replaced. | The per-feature guides in this section |

## Before you start

- **Manager address.** Every 4.x agent connects to the address in its `<client><server><address>`.
  Give the 5.0 manager the same IP or resolvable name, or plan to edit that value on every agent.
- **Operating system.** The 5.0 manager supports fewer distributions than 4.x (see
  [Requirements](../../ref/getting-started/requirements.md); the installation assistant checks the
  host and warns). A same-host migration may require an OS upgrade first.
- **Agent versions.** 4.x agents keep working against a 5.0 manager over the legacy channel, with
  the limitations listed in [Step 6](#6-reconnect-the-4x-agents). Upgrading an agent to 5.0
  requires it to be on 4.14.0 or later first.
- **Ports.** Agents need `1514/tcp` and `1515/tcp` (legacy channel and enrollment) while any 4.x
  agent remains, and `1517/tcp` (HTTPS) for every agent that has been upgraded to 5.0.
- **Certificates.** The 5.0 manager does not generate any, and refuses to start without the agent
  listener pair. Issue them with the installation assistant's `wazuh-certs-tool` before you install,
  and make sure the certificate's subjectAltName carries every address agents dial, which for a
  migration is the address the 4.x fleet already uses. See [Step 2](#2-install-the-50-manager).
- **Tools.** The `sqlite3` command-line tool on the 5.0 host for [Step 3](#3-restore-the-identity-data).
  It is not part of the manager packages and is often absent on a minimal server; the Python the
  manager bundles (`/var/wazuh-manager/framework/python/bin/python3`, module `sqlite3`) runs the same
  statements when you would rather not install it.

## 1. Back up the 4.x manager

Stop the 4.x manager so the files are consistent, then copy everything below off the host. The
paths are the 4.x ones; the table says where each item lands on 5.0.

```bash
systemctl stop wazuh-manager
mkdir -p /root/wazuh-4x-backup && cd /var/ossec
cp etc/client.keys etc/authd.pass queue/db/global.db api/configuration/security/rbac.db /root/wazuh-4x-backup/
cp etc/ossec.conf etc/local_internal_options.conf api/configuration/api.yaml /root/wazuh-4x-backup/
tar -czf /root/wazuh-4x-backup/groups.tar.gz -C /var/ossec/etc --exclude='shared/default' --exclude='*/merged.mg' shared/*/
tar -czf /root/wazuh-4x-backup/ruleset.tar.gz -C /var/ossec/etc rules decoders lists
```

| 4.x file | Content | 5.0 destination |
|---|---|---|
| `etc/client.keys` | Agent ids, names, allowed addresses and keys | `/var/wazuh-manager/etc/client.keys` |
| `queue/db/global.db` | Agent registry and group membership | Rows copied into `/var/wazuh-manager/queue/db/global.db` |
| `etc/shared/<group>/` (custom groups only) | Group configuration and files | `/var/wazuh-manager/etc/shared/<group>/` |
| `etc/authd.pass` | Enrollment password | `/var/wazuh-manager/etc/authd.pass` |
| `api/configuration/security/rbac.db` | API users, roles, policies | `/var/wazuh-manager/api/configuration/security/rbac.db` |
| `etc/ossec.conf`, `etc/local_internal_options.conf`, `api/configuration/api.yaml` | Configuration to translate by hand | See [Step 4](#4-migrate-the-configuration) |
| `etc/rules/`, `etc/decoders/`, `etc/lists/` | Your content, to translate by hand | See the ruleset guides |

The `default` group is excluded on purpose: the 5.0 package ships its own `default` folder and
`shared/*/` would otherwise overwrite it with the 4.x files. If you customized
`shared/default/agent.conf`, copy that single file and merge it into the 5.0 one by hand.

`global.db` is under `queue/db/`, not `var/db/`. Copying a path that does not exist produces a
valid, empty database and no error.

This backup is for the migration. For backing up the 5.0 manager afterwards, whose layout and file
set are different, see [Back up and restore](../../ref/backup-restore.md).

## 2. Install the 5.0 manager

Uninstall 4.x and install 5.0 following the installation documentation.

Unlike 4.x, the 5.0 manager generates no TLS material. Issue it with the installation assistant's
`wazuh-certs-tool` and deploy it under `etc/certs/` before the first start, as
[Deploy certificates](../../ref/getting-started/installation.md#deploy-certificates) describes: the
indexer material (`root-ca.pem`, `indexer-connector.pem`, `indexer-connector-key.pem`) and the agent
listener pair `remoted.pem`/`remoted-key.pem`, a leaf of that same `root-ca.pem`, owned
`wazuh-manager:wazuh-manager 640`. Two requirements come from the fleet rather than from the
installer:

- **The subjectAltName must carry every address agents dial.** For a migration that is the address
  the 4.x agents already have in their `ossec.conf`, plus the cluster VIP and any NAT address. The
  manager cannot check this and warns only when the certificate carries no usable SAN at all.
- **Keep `root-ca.pem` and its key.** It is what every 5.0 agent verifies the manager against and
  what enrollment tokens pin, so reissuing it later invalidates both. Certificates are not
  synchronized between cluster nodes: every node's listener certificate must be issued by this CA.

Without the pair the manager does not start, and says so before any daemon runs:

```console
(1244): Invalid configuration at '/remote/https/certificate': file not found: /var/wazuh-manager/etc/certs/remoted.pem (the manager does not generate certificates; provision the file, e.g. with wazuh-certs-tool).
```

A pair that exists but is unreadable by the service user passes that check and stops
`wazuh-manager-remoted` instead, with `Cannot start the HTTPS agent listener: ...`.

Once the installation finishes, stop the manager before touching any of its files:

```bash
systemctl stop wazuh-manager
```

Do not connect any agent yet.

## 3. Restore the identity data

Run everything in this step as root on the 5.0 host with the manager stopped. Ownership matters:
in 4.x the daemons ran as root and read files owned by `root:wazuh`; in 5.0 they run as
`wazuh-manager`, and `wazuh-manager-authd` rewrites `client.keys` itself. A `client.keys` owned by
root stops authd with `ERROR: Unable to open etc/client.keys (key file)`.

### Agent keys

```bash
install -m 640 -o wazuh-manager -g wazuh-manager /root/wazuh-4x-backup/client.keys /var/wazuh-manager/etc/client.keys
```

The file format is unchanged and the 4.x key is exactly the key the 5.0 protocol uses, so no agent
has to re-enroll (see [Agent-manager protocol](agent-manager-protocol.md#authentication)).

### Agent registry

The 4.x `global.db` cannot be copied over: 5.0 tracks the schema with `PRAGMA user_version` and
refuses a 4.x file (`Unsupported schema version 0 ... Disabling database`), and the `agent` table
changed columns. Copy the rows into the database the 5.0 installation created instead:

```bash
sqlite3 /var/wazuh-manager/queue/db/global.db <<'SQL'
ATTACH '/root/wazuh-4x-backup/global.db' AS old;
INSERT OR REPLACE INTO agent
  (id, name, ip, register_ip, internal_key, os_name, os_version, os_major, os_minor, os_type, os_platform, os_arch,
   version, date_add, last_keepalive, `group`, group_hash, group_sync_status, sync_status, connection_status,
   disconnection_time, status_code)
SELECT id, name, ip, register_ip, internal_key, os_name, os_version, os_major, os_minor,
       CASE WHEN lower(os_platform) = 'windows' THEN 'windows'
            WHEN lower(os_platform) = 'darwin' THEN 'macos'
            WHEN os_platform IS NULL THEN NULL ELSE 'linux' END,
       os_platform, os_arch, version, date_add, last_keepalive, `group`, group_hash, group_sync_status, sync_status,
       'disconnected', 0, status_code
FROM old.agent WHERE id > 0;
INSERT OR IGNORE INTO `group` (name) SELECT name FROM old.`group`;
INSERT OR REPLACE INTO belongs (id_agent, id_group, priority)
SELECT b.id_agent, g5.id, b.priority
FROM old.belongs b JOIN old.`group` g4 ON g4.id = b.id_group JOIN `group` g5 ON g5.name = g4.name
WHERE b.id_agent > 0;
SQL
chown wazuh-manager:wazuh-manager /var/wazuh-manager/queue/db/global.db
```

Row `0` is the manager itself and is skipped. Agents are inserted as `disconnected`; the first
keepalive marks them `active` and refreshes version and OS. The 4.x `labels` and `info` tables
have no counterpart in 5.0 (agent labels were removed). Columns dropped in 5.0 (`os_codename`,
`os_build`, `os_uname`, `config_sum`, `merged_sum`, `manager_host`, `node_name`,
`group_config_status`) are not needed.

### Groups

```bash
tar -xzf /root/wazuh-4x-backup/groups.tar.gz -C /var/wazuh-manager/etc/
chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/etc/shared/
```

Group membership came with `global.db`: an agent assigned to a group from the dashboard, the API
or `agent_groups` in 4.x is in the same group on 5.0, even though its `ossec.conf` never mentioned
it. Review every `agent.conf` against the 5.0 agent configuration reference before starting: a
deprecated option makes the group's configuration fail to compile. With the manager stopped there
is no window in which `wazuh-manager-modulesd` sees a half-extracted folder and drops the group.

### Enrollment password

```bash
install -m 640 -o root -g wazuh-manager /root/wazuh-4x-backup/authd.pass /var/wazuh-manager/etc/authd.pass
```

The installer writes `<auth><use_password>yes</use_password>` (see
[authd](../../ref/modules/authd/configuration.md#use_password)), so keeping the 4.x password means
the `authd.pass` already present on every agent keeps working. Skip this and `wazuh-manager-authd`
generates a new random password on its first start, which every agent that enrolls with the old one
is then rejected with. In a cluster the file belongs to the master and is distributed to the workers.

Migrated agents never enroll again, so this only matters for agents that re-enroll and for new 4.x
agents. New 5.0 agents use enrollment tokens instead, covered in
[After the migration](#after-the-migration-enrolling-new-agents).

### API users, roles and policies

```bash
install -m 640 -o wazuh-manager -g wazuh-manager /root/wazuh-4x-backup/rbac.db /var/wazuh-manager/api/configuration/security/rbac.db
sqlite3 /var/wazuh-manager/api/configuration/security/rbac.db 'PRAGMA user_version = 0'
```

The 4.x database has the same tables as the 5.0 one and the API accepts it as-is, but only the
`PRAGMA user_version` decides whether it is *upgraded*. Both 4.x and 5.0 stamp version `1`, so a
copied database is taken for a current one and keeps its 4.x **default** roles and policies: the
ones 5.0 added for endpoints that did not exist in 4.x — minting enrollment tokens among them — are
never created, and no role, `administrator` included, can use them through the API. Setting the
version back to `0` is what asks for the supported upgrade, which the API performs on its next
start: it builds a database with the 5.0 defaults and migrates your own resources into it.

```console
INFO: RBAC database migration required. Current version is 0 but it should be 1. Upgrading RBAC database to version 1
INFO: /var/wazuh-manager/api/configuration/security/rbac.db database upgraded successfully
```

What survives that upgrade: the `wazuh` and `wazuh-wui` users with their 4.x passwords, and every
user, role, policy, rule and relationship you created yourself (ids from 100 up). What it drops:
the 4.x default policies, including those naming endpoints removed in 5.0 (`syscollector:read`,
`active-response:command`, `rootcheck:*`, `ciscat:*`, ...), replaced by the 5.0 set.

Verify after [Step 5](#5-start-the-manager-and-verify-the-registry) that your own users authenticate
and their roles still apply. Minting enrollment tokens never depends on this: the
`wazuh-manager-authd` command line does not go through the API.

## 4. Migrate the configuration

Follow [Manager configuration migration](manager-configuration-migration.md) to carry your
`ossec.conf`, internal options and `api.yaml` customizations into `wazuh-manager.conf`,
`wazuh-manager-internal-options.conf` and `api.yaml`. Do not copy the 4.x files over the 5.0
ones.

While any 4.x agent remains, the manager needs the legacy channel and legacy enrollment
listening. The installer writes `<remote><legacy><enabled>yes</enabled>` and
`<auth><disabled>no</disabled>`, and `<auth><legacy_enrollment>` defaults to `yes`, so a default
installation already accepts 4.x agents:

```xml
<remote>
  <legacy>
    <enabled>yes</enabled>
    <port>1514</port>
    <protocol>tcp</protocol>
  </legacy>
  ...
</remote>
<auth>
  <use_password>yes</use_password>
  <legacy_enrollment>yes</legacy_enrollment>
  ...
</auth>
```

Validate before starting:

```bash
/var/wazuh-manager/bin/wazuh-manager-conf validate
```

## 5. Start the manager and verify the registry

```bash
systemctl start wazuh-manager
/var/wazuh-manager/bin/wazuh-manager-control status
grep -E "keystore|authd" /var/wazuh-manager/logs/wazuh-manager.log | tail
```

Expected: every daemon running, `wazuh-manager-remoted:keystore: INFO: Loaded N agent key(s)
from 'etc/client.keys'` with your agent count, and authd `Accepting connections on port 1515`.
Then confirm the registry with your 4.x API credentials:

```bash
TOKEN=$(curl -sk -u <user>:<password> -X POST "https://localhost:55000/security/user/authenticate?raw=true")
curl -sk "https://localhost:55000/agents?select=id,name,version,status,group,dateAdd" -H "Authorization: Bearer $TOKEN"
curl -sk "https://localhost:55000/groups" -H "Authorization: Bearer $TOKEN"
```

Every agent appears with its 4.x id, name, version, groups and registration date, as
`disconnected` until it reconnects.

## 6. Reconnect the 4.x agents

If the manager kept its address, there is nothing to do: each agent reconnects on its next
retry, authenticates with its existing key and is marked `active`. Otherwise edit
`<client><server><address>` in each agent's `ossec.conf` and restart it. Do not remove
`client.keys` on the agents.

A 4.x agent on the legacy channel keeps:

- events (they appear in the 5.0 `wazuh-events-*` and `wazuh-findings-*` indices, attributed to
  its original agent id);
- keepalives, so version, OS and status stay current in the agent list;
- centralized configuration (`agent.conf` of its groups);
- remote upgrade through the manager.

It does not get active response, inventory or FIM state synchronization, or vulnerability
detection: the `wazuh-states-*` indices stay empty for it until it runs 5.0. See
[Agent-manager protocol](agent-manager-protocol.md#what-the-legacy-channel-still-carries).
The API endpoints that served that data in 4.x (`/syscollector/{agent_id}/*`, `PUT /active-response`)
no longer exist in 5.0.

## 7. Upgrade the agents to 5.0

Follow [Upgrade 4.x to 5.x](upgrade-4x-to-5x.md) for an in-place package upgrade and
[Remote agent upgrade](remote-agent-upgrade.md) for the WPK path. Points that matter for a
migrated fleet:

- **Trust.** A 5.0 agent verifies the manager's certificate, a 4.x agent never did. An agent that
  reaches 5.0 by upgrade holds no trust anchor, and it never enrolls again, so it cannot receive one
  the way a fresh agent does. Which path you use decides who closes that gap:
  - **Remote upgrade (WPK).** The manager pushes `root-ca.pem` to the agent's `var/incoming/` over
    the upgrade channel, immediately before the `upgrade` command, and the agent's installer picks
    it up. On by default (`<remote><legacy><ca_delivery>`). It never fails an upgrade: if the CA
    cannot be sent the upgrade proceeds and the manager logs that step alone, which is worth
    checking before declaring the migration done. See
    [Trust anchor delivery](remote-agent-upgrade.md#trust-anchor-delivery-to-legacy-agents).
  - **Package upgrade on the host.** Nothing is delivered. Place the manager's
    `/var/wazuh-manager/etc/certs/root-ca.pem` at `/var/ossec/etc/certs/root-ca.pem` on Linux and
    macOS, or `<installdir>\certs\root-ca.pem` on Windows, before upgrading.

  An agent that holds the anchor verifies the manager against it, whatever
  `<agent><ssl><verification_mode>` says; an agent upgraded without one starts but does not
  connect.
- **Identity.** The upgraded agent keeps `client.keys` and `ossec.conf`, reads the manager address
  from the legacy `<client>` block and connects over HTTPS on `1517` with the same id and key. No
  enrollment happens.
- **Unattended package upgrades.** On Debian-based hosts `dpkg -i` asks about the modified
  conffile `/etc/init.d/wazuh-agent` and blocks without a terminal; pass `--force-confold`. Do not
  restart the agent while the package is half installed: until the postinst runs, the
  configuration and keys on disk are the package placeholders.
- **State rebuild.** Within minutes of connecting over HTTPS the agent's inventory, FIM, SCA and
  vulnerability state appears in the `wazuh-states-*` indices. The 4.x history is not carried.

## 8. Retire the legacy channel

Once no 4.x agent remains, disable `<remote><legacy>` and `<auth><legacy_enrollment>` and close
`1514` and `1515`, as described in
[Retiring the legacy channel](agent-manager-protocol.md#retiring-the-legacy-channel).

## After the migration: enrolling new agents

Migrated agents keep their 4.x identity and never enroll again. An agent installed from scratch
against the 5.0 manager does, and 5.0 enrolls it with an **enrollment token**: one value carrying
the manager address, a pin of `root-ca.pem` and the enrollment credential, so the agent verifies the
manager on its first connection instead of trusting it. Mint one on the master, with an address
covered by the listener certificate's SAN:

```bash
sudo /var/wazuh-manager/bin/wazuh-manager-authd --create-enrollment-token --address mgr.example.com --ttl 30d
```

Pass it to the installer as `WAZUH_ENROLLMENT_TOKEN`. `--list-enrollment-tokens` and
`--revoke-enrollment-token` manage them. The shared password path you carried over in
[Step 3](#enrollment-password) keeps working alongside it, for 4.x agents and for automation written
before tokens existed. See [Agent enrollment lifecycle](../../ref/modules/authd/enrollment-lifecycle.md).

## Historical data

- **Alerts.** 5.0 writes events and findings to `wazuh-events-*` and `wazuh-findings-*`. The 4.x
  `wazuh-alerts-4.x-*` indices are not read or migrated; keep them in the indexer for as long as
  you need to consult them, and expect dashboards built on them to need new index patterns.
- **Inventory, FIM, SCA, vulnerabilities.** 5.0 keeps this state in its own `wazuh-states-*`
  indices, rebuilt from each agent after it is upgraded. The 4.x `wazuh-states-*` indices are not
  updated by 5.0.
- **Agent ids.** Because ids are preserved, historical documents in the 4.x indices and new
  documents in the 5.0 ones refer to the same agent by the same id. Re-enrolling agents instead
  of carrying `client.keys` breaks that: ids are reassigned in enrollment order.

## If you re-enroll instead

If you cannot carry `client.keys` and `global.db`, agents get new ids and only the groups they
declare in `<enrollment><groups>` on their own `ossec.conf`; every assignment made from the
manager side is lost and has to be redone. [Agent groups migration](agent-groups-migration.md)
covers that path.
