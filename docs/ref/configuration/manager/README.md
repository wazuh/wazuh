# Manager Configuration

Configuration reference for Wazuh manager components. The manager configuration is a **strict XML**
file validated against a JSON schema (the agent keeps its own XML `ossec.conf`, read by the legacy
parser).

## Configuration Files

| File | Location | Mode | Description |
|------|----------|------|-------------|
| `wazuh-manager.conf` | `/var/wazuh-manager/etc/` | 660 `root:wazuh-manager` | Main configuration: a single `<wazuh_config>` root with one element per section (see [the generated reference](reference.md)) |
| `wazuh-manager.schema.json` | `/var/wazuh-manager/etc/` | 640 `root:wazuh-manager` | JSON Schema (draft-04) the file is validated against; installed copy of `src/shared_modules/manager_config/schema/wazuh-manager.schema.json` (product, not configuration) |
| `wazuh-manager-internal-options.conf` | `/var/wazuh-manager/etc/` | 640 `root:wazuh-manager` | Internal tuning parameters (`key=value`) |
| `api.yaml` | `/var/wazuh-manager/api/configuration/` | 640 | REST API configuration |

`wazuh-manager.conf` is **generated, not shipped**: the installer and the packages write it once
(`src/init/gen_wazuh.sh conf manager <dist> <version>` prints the same document) from the templates in
`etc/templates/config/`, validate it with `wazuh-manager-conf` and install it. Upgrades preserve it;
DEB upgrades leave the regenerated defaults next to it as `wazuh-manager.conf.new`.

The file is parsed as **well-formed XML**: a single `<wazuh_config>` root, no unescaped `&` or `<`,
`<!-- -->` comments only, and XML entities (`&amp;`, `&lt;`…) are decoded into the values. Values are
typed by the schema: booleans are written `yes`/`no`, numbers as digits, lists as repeated elements
(`<hosts><host>…</host></hosts>`) or comma-separated values where the 4.x syntax did so.

## Validation and tools

- `bin/wazuh-manager-conf validate [-f <file>] [--skip-file-checks]` — XML syntax, schema (types,
  ranges, enums, unknown options), cross-field rules (port clashes) and, unless `--skip-file-checks`,
  the existence of the files the configuration names. Silent on success; on failure it prints the JSON
  pointer of the offending option: `(1244): Invalid configuration at '/remote/legacy/port': does not
  satisfy 'maximum' [...]` (syntax problems name the file and embed the line instead).
- `bin/wazuh-manager-conf get <key.path>` — one option of the **effective** document (defaults
  applied): scalars as plain text, objects and lists as JSON. `bin/wazuh-manager-conf dump` prints the
  whole effective document.
- `bin/wazuh-manager-control start|restart` validates the file first and refuses to start any daemon
  when it is invalid (the CLI's `(1244)` verdict, then `wazuh-manager.conf: Configuration error.`);
  a daemon started against an invalid file reports the same ERROR `(1244)` and CRITICAL `(1202)` in
  `logs/wazuh-manager.log`. Each daemon's `-t` validates the whole file, including the files it names.
- The API serves the effective sections as JSON (`GET /cluster/{node_id}/configuration`, optional
  `section`/`field`, `raw=true` for the XML text) and replaces the file with an XML document
  (`PUT /cluster/{node_id}/configuration`, `application/xml` or `application/octet-stream`); a
  malformed document is refused with error 1131 and an invalid one with error 1130 and the same JSON
  pointer. After a `PUT` the file is owned by `wazuh-manager:wazuh-manager` (the API runs as that user).

## Configuration Sections

| Module | Section | Internal Options |
|--------|---------|------------------|
| [Server API](../../modules/server-api/configuration.md) | - (`api.yaml`) | - |
| [Authentication](../../modules/authd/configuration.md) | `auth` | `authd.*` |
| [Cluster](../../modules/cluster/configuration.md) | `cluster` | `wazuh_clusterd.*` |
| [Database Sync](../../modules/database-sync/configuration.md) | - | `wazuh_database.*` |
| [Engine](../../modules/engine/configuration.md) | `cluster`, `logging`, `indexer` (read-only consumer) | `analysisd.*` |
| [Indexer Connector](../../modules/indexer_connector/configuration.md) | `indexer` | - |
| [Inventory Sync Server](../../modules/inventory-sync-server/configuration.md) | `indexer` (read-only consumer) | `wazuh_modules.inventory_sync_server_*` |
| [Logging](../../modules/logging/configuration.md) | `logging` | - |
| [Remoted](../../modules/remoted/configuration.md) | `remote` (`legacy`, `https`, `agents`) | `remoted.*` |
| [Task Manager](../../modules/task_manager/configuration.md) (incl. [agent upgrades](../../modules/task_manager/agent-upgrades.md)) | `task-manager`, `global` (disconnection settings only), `remote` (delivery gates, read-only consumer) | `wazuh_modules.manager_task_*`, `wazuh_modules.upgrade_*` |
| [Vulnerability Scanner](../../modules/vulnerability-scanner/configuration.md) | `vulnerability-detection` | `vulnerability-detection.*` |
| [Wazuh DB](../../modules/wazuh_db/configuration.md) | `wdb` | `wazuh_db.*` |

Every option, with its type, default, constraints and description, is listed in the
[Manager Configuration Reference](reference.md), generated from the schema. The `global` section only
holds `agents_disconnection_time`; it is read by both remoted and the Task Manager's disconnection
sweep, so it is shared configuration rather than one module's; the Task Manager reads `remote` the
same way, for the gates that decide whether an upgrade could be delivered at all. There is no
`agent-upgrade` section: that module is agent-only, and the manager configures the upgrades it serves
under `task-manager`. The manager's log-rotation and
agent-retention tunables (`wazuh_modules.manager_task_log_*`,
`wazuh_modules.manager_task_delete_old_agents`) are internal options unrelated to `global` — see
[Recurring manager tasks](../../modules/task_manager/schedules.md).

**Note:** All wodle-based modules (Task Manager, Inventory Sync Server, Vulnerability Scanner) also use common `wazuh_modules.*` options documented in [Common Internal Options](#common-internal-options).

## When a change takes effect

| Section | Applied |
|---|---|
| `cluster` | `wazuh-manager-control restart` or `reload` (clusterd re-reads the file on both) |
| `indexer` | Python consumers re-read the file when its modification time changes; the C daemons (modulesd, engine) read it at start |
| every other section | at daemon start (`restart`); note that `reload` does **not** restart `wazuh-manager-remoted`, so a change in `remote` needs `restart` |

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
