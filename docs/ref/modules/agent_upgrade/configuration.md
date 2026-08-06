# Agent Upgrade Configuration Reference

Complete configuration reference for the Agent Upgrade module.

The Agent Upgrade module handles remote agent upgrades using WPK files. Configuration differs between manager and agent:

- **Manager:** Enables the module and optionally overrides the WPK repository URL. The manager no longer configures per-transfer parameters (chunk size, worker threads) — the manager only creates a `remote_upgrade` task in the [Task Manager](../task_manager/README.md); the WPK is served over the manager's HTTPS interface when the agent requests it. For agents older than v5.0.0, `remoted`'s own legacy task delivery poller (see [`remoted.legacy_task_polling_interval`](../remoted/configuration.md)) pushes the task instead, over the agent's existing 1514 session — that path does reintroduce WPK chunking, but as a fixed internal 32768-byte constant, not a user-facing option, so no new per-transfer knob is exposed either way.
- **Agent:** Enables the module and controls WPK signature verification.

For module overview and architecture, see [Agent Upgrade Module](README.md).

---

## Manager Configuration

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<agent-upgrade>`

**Internal Options:** None

### enabled

Enable or disable the agent upgrade module on the manager.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** When disabled, the module exits at startup and the manager will not accept upgrade requests.

### wpk_repository

Base URL from which WPK upgrade packages are fetched. Only applies to the manager.

- **Default value:** none — the module falls back to `packages.wazuh.com/<major>.x/wpk/`, derived from the manager version.
- **Allowed values:** any valid URL. A trailing `/` is added automatically if absent.

---

## Manager Configuration Examples

### Default Configuration

Standard configuration for most deployments:

```xml
<agent-upgrade>
  <enabled>yes</enabled>
</agent-upgrade>
```

### Custom WPK Repository

Use an internal or mirrored WPK repository instead of the official Wazuh one:

```xml
<agent-upgrade>
  <enabled>yes</enabled>
  <wpk_repository>https://packages.internal.company.com/wazuh/wpk/</wpk_repository>
</agent-upgrade>
```

### Disable Remote Upgrades on the Manager

```xml
<agent-upgrade>
  <enabled>no</enabled>
</agent-upgrade>
```

---

## Agent Configuration

**Configuration file:** `/var/ossec/etc/ossec.conf` (Linux/Unix) or `C:\Program Files (x86)\ossec-agent\ossec.conf` (Windows)

**XML Section:** `<agent-upgrade>`

**Internal Options:** None

The agent-side configuration controls whether the agent accepts remote upgrades and how the incoming WPK is validated.

### enabled

Allow or prevent this agent from being upgraded remotely.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** When disabled, the agent-side upgrade listener replies with the error `Upgrade module is disabled or not ready yet` to every incoming command.

### ca_verification

Container element for WPK signature verification settings.

**Sub-options:**

#### enabled (inside `<ca_verification>`)

Verify the WPK package digital signature before running the installer.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Disabling signature verification is strongly discouraged. When disabled, the CA store is cleared and the agent will execute any WPK it receives without cryptographic validation.

#### ca_store

Path to a CA certificate file used to verify the WPK signature. The tag can be repeated to accept multiple CAs.

- **Default value:** the packaged Wazuh CA certificate.
- **Allowed values:** valid absolute paths.
- **Note:** Only effective when `ca_verification` is enabled.

Complete `ca_verification` block:

```xml
<ca_verification>
  <enabled>yes</enabled>
  <ca_store>/etc/ssl/certs/wazuh_ca.pem</ca_store>
  <ca_store>/etc/ssl/certs/internal_ca.pem</ca_store>
</ca_verification>
```

### Deprecated options

The following tags are still accepted for backwards compatibility with 4.x configuration files but are ignored by the current implementation. Each occurrence produces a deprecation warning at startup:

- `notification_wait_start`
- `notification_wait_max`
- `notification_wait_factor`

They can be safely removed from the configuration.

---

## Agent Configuration Examples

### Default Configuration

```xml
<agent-upgrade>
  <enabled>yes</enabled>
  <ca_verification>
    <enabled>yes</enabled>
  </ca_verification>
</agent-upgrade>
```

### Disable Remote Upgrades on Agent

Prevent this specific agent from being upgraded remotely:

```xml
<agent-upgrade>
  <enabled>no</enabled>
</agent-upgrade>
```

### Custom CA Store

Use one or more custom CAs to sign WPK packages:

```xml
<agent-upgrade>
  <enabled>yes</enabled>
  <ca_verification>
    <enabled>yes</enabled>
    <ca_store>/etc/ssl/certs/wazuh_internal_ca.pem</ca_store>
  </ca_verification>
</agent-upgrade>
```

---

## Monitoring

### Check module status on the manager

```bash
tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep agent-upgrade
```

Successful upgrade requests produce log lines from the `agent-upgrade` and `task-manager` module tags: `agent-upgrade` validates the request and creates a task, `task-manager` only stores/tracks it — it never delivers anything itself. For upgrades to an agent below v5.0.0, `remoted`'s own task-polling thread also logs under its own tag, since it — not `agent-upgrade` or `task-manager` — is what actually delivers the WPK to that agent.

### Inspect pending upgrade tasks

Since upgrade requests end up as `remote_upgrade` rows in `tasks.db`, task state can be inspected the same way as any other task type. See the [Task Manager configuration reference](../task_manager/configuration.md) for the query examples.

### View agent-side upgrade logs

```bash
# Linux/Unix
tail -f /var/ossec/logs/ossec.log | grep agent-upgrade
```

```powershell
# Windows
Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Wait | Select-String agent-upgrade
```

---

## Troubleshooting

### Upgrade requests are rejected on the manager

Verify the module is enabled:

```bash
grep -A 3 "<agent-upgrade>" /var/wazuh-manager/etc/wazuh-manager.conf
```

Verify the target version is compatible (see [Version constraints](README.md#version-constraints)).

### WPK download failures on the manager

Confirm the manager has outbound HTTPS access to the WPK repository configured in `wpk_repository`, or place the WPK manually under `/var/wazuh-manager/var/upgrade/` and use the custom-upgrade API endpoint.

### Upgrades never complete

The manager only records that a task was created. Whether the agent picked it up, downloaded the WPK, and executed the installer is visible in the agent-side log and in the `delivery_time` column of the `tasks.db` row. If a task remains in the `pending` state past `task_ttl` (default 1 h), it will be marked `expired` by the Task Manager cleanup thread.

---

## See Also

- [Agent Upgrade Module](README.md) — Module overview and architecture
- [Task Manager Configuration](../task_manager/configuration.md) — Backing store for upgrade tasks
- [Manager Configuration Reference](../../configuration/manager/README.md)
- [Agent Configuration Reference](../../configuration/agent/README.md)
