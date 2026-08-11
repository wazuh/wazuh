# Manager Configuration

Configuration reference for Wazuh manager components.

## Configuration Files

| File | Location | Description |
|------|----------|-------------|
| `wazuh-manager.conf` | `/var/wazuh-manager/etc/` | Main XML configuration |
| `wazuh-manager-internal-options.conf` | `/var/wazuh-manager/etc/` | Internal tuning parameters |
| `api.yaml` | `/var/wazuh-manager/api/configuration/` | REST API configuration |

## Configuration Sections

| Module | XML Section | YAML Section | Internal Options |
|--------|-------------|--------------|------------------|
| [Agent Upgrade](../../modules/agent_upgrade/configuration.md) | `<agent-upgrade>` | - | - |
| [Server API](../../modules/server-api/configuration.md) | - | `api.yaml` | - |
| [Authentication](../../modules/authd/configuration.md) | `<auth>` | - | `authd.*` |
| [Cluster](../../modules/cluster/configuration.md) | `<cluster>` | - | `wazuh_clusterd.*` |
| [Database Sync](../../modules/database-sync/configuration.md) | - | - | `wazuh_database.*` |
| [Engine](../../modules/engine/configuration.md) | - | - | `analysisd.*` |
| [Indexer Connector](../../modules/indexer_connector/configuration.md) | `<indexer>` | - | - |
| [Inventory Sync Server](../../modules/inventory-sync-server/configuration.md) | - | - | `wazuh_modules.inventory_sync_server_*` |
| [Logging](../../modules/logging/configuration.md) | `<logging>` | - | - |
| [Monitord](../../modules/monitord/configuration.md) | `<global>` | - | `monitord.*` |
| [Remoted](../../modules/remoted/configuration.md) | `<remote>` | - | `remoted.*` |
| [Task Manager](../../modules/task_manager/configuration.md) | `<task-manager>` | - | - |
| [Vulnerability Scanner](../../modules/vulnerability-scanner/configuration.md) | `<vulnerability-detection>` | - | `vulnerability-detection.*` |
| [Wazuh DB](../../modules/wazuh_db/configuration.md) | `<wdb>` | - | `wazuh_db.*` |

**Note:** All wodle-based modules (Task Manager, Inventory Sync Server, Vulnerability Scanner) also use common `wazuh_modules.*` options documented in [Common Internal Options](#common-internal-options).

---

## Common Internal Options

These internal options apply to all Wazuh modules (wodles) on the manager. Configure them in `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`:

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

**Used by modules:** Task Manager, Inventory Sync Server, Vulnerability Scanner, and other wodle-based modules.

---

For comprehensive module documentation including architecture and implementation details, see [Modules Reference](../../modules/index.html).
