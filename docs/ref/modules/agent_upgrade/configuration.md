# Agent Upgrade Configuration Reference

Complete configuration reference for the Agent Upgrade module.

This is the **agent-side** configuration: whether the agent accepts remote upgrades, and how it
validates the WPK it is given.

**Manager-side upgrade options live in
[`<task-manager>`](../task_manager/configuration.md#agent-upgrades)** — the manager serves upgrades
from the Task Manager, and this module is not part of a manager at all.

For module overview and architecture, see [Agent Upgrade Module](README.md).

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

### View agent-side upgrade logs

```bash
# Linux/Unix
tail -f /var/ossec/logs/ossec.log | grep agent-upgrade
```

```powershell
# Windows
Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Wait | Select-String agent-upgrade
```

After the upgrade the agent restarts and reports the outcome as a stateless event; the manager is
never told directly.

---

## Troubleshooting

### The agent refuses an upgrade command

The agent answers `Upgrade module is disabled or not ready yet` when `<enabled>` is `no`, or before
the module has finished starting.

### The agent rejects the WPK signature

`Could not verify signature` means the WPK was not signed by any CA in `<ca_store>`. Confirm the
package came from a repository whose signing CA the agent trusts, and see
[`ca_verification`](#ca_verification).

**Manager-side troubleshooting** — a rejected request, a failed WPK download, a request refused
under load — is in the
[Task Manager configuration reference](../task_manager/configuration.md#troubleshooting-agent-upgrades),
since that is the module doing the work.

---

## See Also

- [Agent Upgrade Module](README.md) — Module overview and architecture
- [Task Manager Configuration](../task_manager/configuration.md#agent-upgrades) — the manager side: options, monitoring and troubleshooting
- [Agent Configuration Reference](../../configuration/agent/README.md)
