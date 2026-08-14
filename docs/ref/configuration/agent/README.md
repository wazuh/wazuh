# Agent Configuration

Configuration reference for Wazuh agent components.

## Configuration Files

| File | Location (Linux/Unix) | Location (Windows) | Description |
|------|----------------------|-------------------|-------------|
| `ossec.conf` | `/var/ossec/etc/` | `C:\Program Files (x86)\ossec-agent\` | Main XML configuration |
| `internal_options.conf` | `/var/ossec/etc/` | `C:\Program Files (x86)\ossec-agent\` | Internal tuning parameters |
| `local_internal_options.conf` | `/var/ossec/etc/` | `C:\Program Files (x86)\ossec-agent\` | User overrides |

## Configuration Sections

| Module | XML Section | Internal Options |
|--------|-------------|------------------|
| [Active Response](../../modules/active-response/configuration.md) | `<active-response>` | `execd.*` |
| [Agent Info](../../modules/agent_info/configuration.md) | `<agent-info>` | - |
| [Agent Upgrade](../../modules/agent_upgrade/configuration.md) | `<agent-upgrade>` | - |
| [Client](../../modules/client/configuration.md) | `<agent>`, `<anti_tampering>` | `agent.*`, `windows.*` (Windows only) |
| [Command](../../modules/command/configuration.md) | `<wodle name="command">` | `wazuh_command.*` |
| [Logcollector](../../modules/logcollector/configuration.md) | `<localfile>`, `<socket>` | `logcollector.*` |
| [Logging](../../modules/logging/configuration.md) | `<logging>` | - |
| [Rootcheck](../../modules/rootcheck/configuration.md) | `<rootcheck>` | `rootcheck.*` |
| [SCA](../../modules/sca/configuration.md) | `<sca>` | `sca.*` |
| [Syscollector](../../modules/syscollector/configuration.md) | `<wodle name="syscollector">` | - |
| [FIM](../../modules/fim/configuration.md) | `<syscheck>` | `syscheck.*` |

**Note:** All wodle-based modules (Command, Syscollector, AWS, Azure, Docker) also use common `wazuh_modules.*` options documented in [Common Internal Options](#common-internal-options).

### Cloud & Integration Modules

| Module | XML Section | Internal Options |
|--------|-------------|------------------|
| [AWS](../../modules/integrations/index.html) | `<wodle name="aws-s3">` | - |
| [Azure](../../modules/integrations/index.html) | `<wodle name="azure-logs">` | - |
| [Docker](../../modules/integrations/index.html) | `<wodle name="docker-listener">` | - |
| [GCP](../../modules/integrations/index.html) | `<gcp-pubsub>`, `<gcp-bucket>` | - |
| [GitHub](../../modules/integrations/index.html) | `<github>` | - |
| [MS Graph](../../modules/integrations/index.html) | `<ms-graph>` | - |
| [Office 365](../../modules/integrations/index.html) | `<office365>` | - |

---

## Common Internal Options

These internal options apply to all Wazuh modules (wodles) on the agent. Configure them in `/var/ossec/etc/local_internal_options.conf`:

```ini
# Debug level for all wazuh modules (0-2, default: 0)
wazuh_modules.debug=0

# Maximum events per second for all modules (default: 100)
wazuh_modules.max_eps=100

# Process priority/nice value for module threads (-20 to 19, default: 10)
wazuh_modules.task_nice=10

# Timeout in seconds for killing unresponsive modules (default: 10)
wazuh_modules.kill_timeout=10

# Maximum file descriptors for module processes (default: 8192)
wazuh_modules.rlimit_nofile=8192
```

**Used by modules:** Command, Syscollector, and other wodle-based modules on the agent.

---

For comprehensive module documentation including architecture and implementation details, see [Modules Reference](../../modules/index.html).
