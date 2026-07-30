# Configuration Reference

This section documents all Wazuh configuration files and settings.

## Configuration Files

### Manager Configuration Files

**Location:** `/var/wazuh-manager/etc/`

| File | Description |
|------|-------------|
| `wazuh-manager.conf` | Main XML configuration file for the manager |
| `wazuh-manager-internal-options.conf` | Internal tuning parameters for manager components |
| `api.yaml` | REST API configuration (located in `api/configuration/`) |
| `agent.conf` | Centralized agent configuration distributed to agents (in `shared/<group>/`) |

See [Manager Configuration](manager/index.html) for detailed module references.

### Agent Configuration Files

**Location:** `/var/ossec/etc/` (Linux/Unix) or `C:\Program Files (x86)\ossec-agent\` (Windows)

| File | Description |
|------|-------------|
| `ossec.conf` | Main XML configuration file for the agent |
| `internal_options.conf` | Internal tuning parameters for agent components |
| `local_internal_options.conf` | User overrides for internal options (takes precedence) |

See [Agent Configuration](agent/index.html) for detailed module references.

### Centralized Configuration

The manager can distribute configuration to agents using group-based `agent.conf` files.

See [Agent Management - Centralized Configuration](../modules/agent-management/centralized-configuration.md) for detailed documentation.

---

## Quick Navigation

- [Manager Configuration](manager/index.html) - Configuration for manager components
- [Agent Configuration](agent/index.html) - Configuration for agent components
- [Centralized Configuration](../modules/agent-management/centralized-configuration.md) - Group-based agent configuration distribution

---

## Configuration by Module

For comprehensive module documentation including architecture, events, and database schemas, see [Modules Reference](../modules/index.html).
