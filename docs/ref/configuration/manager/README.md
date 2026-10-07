# Manager Configuration

Configuration reference for Wazuh manager components. The manager configuration is a **strict XML**
file validated against a JSON schema (the agent keeps its own XML `ossec.conf`, read by the legacy
parser).

## Configuration Files

| File | Location | Mode | Description |
|------|----------|------|-------------|
| `wazuh-manager.conf` | `/var/wazuh-manager/etc/` | 660 `root:wazuh-manager` | Main configuration: a single `<wazuh_config>` root with one element per section (see [the generated reference](reference.md)) |
| `wazuh-manager.schema.json` | `/var/wazuh-manager/etc/` | 640 `root:wazuh-manager` | JSON Schema (draft-04) the file is validated against; installed copy of `src/shared_modules/manager_config/schema/wazuh-manager.schema.json`, replaced on every install and upgrade (product, not configuration) |
| `wazuh-manager-internal-options.conf` | `/var/wazuh-manager/etc/` | 640 `root:wazuh-manager` | Internal tuning parameters (`key=value`); ships with comments only, the defaults are compiled in, and an existing file is kept |
| `api.yaml` | `/var/wazuh-manager/api/configuration/` | 660 `root:wazuh-manager` | REST API configuration (see [Server API configuration](../../modules/server-api/configuration.md)) |

`wazuh-manager.conf` is **generated, not shipped**: the installer and the packages write it once
(`src/init/gen_wazuh.sh conf manager <dist> <version>` prints the same document) from the templates in
`etc/templates/config/`, validate it with `wazuh-manager-conf --skip-file-checks validate` and install it.
Upgrades preserve it; DEB upgrades leave the regenerated defaults next to it as `wazuh-manager.conf.new`.

The file is parsed as **well-formed XML**: a single `<wazuh_config>` root without attributes, no
unescaped `&` or `<`, `<!-- -->` comments only (with no `--` inside), at most 1 MiB and 16 levels of
nesting. XML entities (`&amp;`, `&lt;`…) are decoded into the values. Values are typed by the schema:
booleans are written `yes`/`no` (any case; `true`/`false` are rejected), numbers as digits, enumerated
values in any case, and lists in any of three forms: one child per item
(`<hosts><host>…</host></hosts>`), a comma-separated value (`<protocol>tcp,udp</protocol>`), or the
element repeated (`<log_format>plain</log_format><log_format>json</log_format>`). Any other repeated
element is rejected as a duplicate.

## Validation and tools

- `bin/wazuh-manager-conf [-f <file>] [-H <home>] [--skip-file-checks] <command>` reads
  `<home>/etc/wazuh-manager.conf` unless `-f` names another file; `-H` defaults to
  `$WAZUH_MANAGER_HOME`, else the parent of the `bin/` directory holding the program. `-V` prints the
  version. Exit status: `0` success, `1` invalid configuration, missing file or usage error, `2` key not
  set (`get`).
  - `validate` checks the XML syntax, the schema (types, ranges, enums, unknown options), the cross-field
    rules (a certificate and its key set together, no `.`/`..` segment in `remote.https.global_prefix`,
    distinct listener ports — `remote.legacy.port` counts only when the legacy listener is enabled and
    `auth.port` only when authd is not disabled) and, unless `--skip-file-checks`, the existence of the
    certificate files the configuration names (`remote.https.certificate`, `key`, `ca`,
    `ca_certificate`, `auth.ssl_agent_ca`, `ssl_manager_cert`, `ssl_manager_key`; `indexer.ssl.*` is not
    checked). Silent on success; on failure it prints the JSON pointer of the offending option:
    `(1244): Invalid configuration at '/remote/legacy/port': does not satisfy 'maximum' [...]`
    (`'/'` for syntax problems, which name the line instead). A missing file is
    `(1239): Configuration file not found: '<file>'.`
  - `get <key.path>` prints one option of the **effective** document (defaults applied): scalars as
    plain text, objects and lists as JSON. `dump` prints the whole effective document.
- `bin/wazuh-manager-control start|restart|reload` validates the file first and refuses to start any
  daemon when it is invalid: the CLI's verdict on stderr and as
  `wazuh-manager-control: ERROR: (1244): …` in `logs/wazuh-manager.log`, then
  `wazuh-manager.conf: Configuration error. Exiting` (`{"error":20,…}` with `-j`). It then runs each
  daemon's `-t`; for the C daemons and the engine, `-t` validates the whole file, including the files it
  names. A daemon started against an invalid file logs `(1244): Invalid configuration at
  '<file>': <pointer>: <reason>.` and the CRITICAL `(1202): Configuration error at '<file>'.` in
  `logs/wazuh-manager.log`.
- The API serves the effective sections as JSON (`GET /cluster/{node_id}/configuration`, optional
  `section`/`field`, `raw=true` for the XML text) and replaces the file with an XML document
  (`PUT /cluster/{node_id}/configuration`, `application/xml` or `application/octet-stream`); a
  malformed document is refused with error 1131 and an invalid one with error 1130 and the same JSON
  pointer. A new `<cluster><key>`, or any change to `<indexer>`, needs `cluster:read_secrets` over the
  node (error 1132 otherwise); the masked `*****` the `GET` returns keeps the current key. After a `PUT` the file keeps its mode and
  is owned by `wazuh-manager:wazuh-manager` (the API runs as that user).
  `GET /cluster/{node_id}/configuration/{component}/{configuration}` returns what a running daemon
  reports instead (for example `request/internal` for remoted's `remoted.*` internal options).

## Configuration Sections

| Module | Section | Internal Options |
|--------|---------|------------------|
| [Server API](../../modules/server-api/configuration.md) | - (`api.yaml`) | - |
| [Authentication](../../modules/authd/configuration.md) | `auth` | `authd.*`, `auth.timeout_seconds`, `auth.timeout_microseconds` |
| [Cluster](../../modules/cluster/configuration.md) | `cluster` | `wazuh_clusterd.debug` |
| [Database Sync](../../modules/database-sync/configuration.md) | - | `wazuh_database.*` |
| [Engine](../../modules/engine/configuration.md) | `cluster`, `logging`, `indexer` (read-only consumer) | `analysisd.*` |
| [Indexer Connector](../../modules/indexer_connector/configuration.md) | `indexer` | - |
| [Inventory Sync Server](../../modules/inventory-sync-server/configuration.md) | `indexer` (read-only consumer) | `wazuh_modules.inventory_sync_server_*` |
| [Logging](../../modules/logging/configuration.md) | `logging` | - |
| [Remoted](../../modules/remoted/configuration.md) | `remote` (`legacy`, `https`, `agents`), `global` | `remoted.*`, `fim.*_limit`, `sca.checks_limit`, `syscollector.*_limit` |
| [Task Manager](../../modules/task_manager/configuration.md) (incl. [agent upgrades](../../modules/task_manager/agent-upgrades.md)) | `task-manager`, `global` (disconnection settings only), `remote` (delivery gates, read-only consumer) | `wazuh_modules.manager_task_*`, `wazuh_modules.upgrade_*` |
| [Vulnerability Scanner](../../modules/vulnerability-scanner/configuration.md) | `vulnerability-detection` | `vulnerability-detection.*`, `wazuh_modules.indexer_*` |
| [Wazuh DB](../../modules/wazuh_db/configuration.md) | `wdb` | `wazuh_db.*` |

Every option, with its type, default, constraints and description, is listed in the
[Manager Configuration Reference](reference.md), generated from the schema. The `global` section only
holds [`agents_disconnection_time`](../../modules/task_manager/configuration.md#agents_disconnection_time);
it is read by both remoted and the Task Manager's disconnection sweep, so it is shared configuration
rather than one module's; the Task Manager reads `remote` the same way, for the gates that decide
whether an upgrade could be delivered at all. There is no `agent-upgrade` section: that module is
agent-only, the element is rejected as an unknown option, and the manager configures the upgrades it
serves under `task-manager`. The manager's log-rotation and agent-retention tunables
(`wazuh_modules.manager_task_log_*`, `wazuh_modules.manager_task_delete_old_agents`) are internal
options unrelated to `global` — see [Recurring manager tasks](../../modules/task_manager/schedules.md).

**Note:** the `wazuh-manager-modulesd` modules (Task Manager, Inventory Sync Server, Vulnerability
Scanner) also read the process-wide `wazuh_modules.*` options documented in
[Common Internal Options](#common-internal-options).

## When a change takes effect

| Section | Applied |
|---|---|
| `cluster` | `wazuh-manager-control restart` or `reload` (clusterd re-reads the file on both) |
| `indexer` | Python consumers re-read the file when its modification time changes; the C daemons (modulesd, engine) read it at start |
| every other section | at daemon start (`restart`); note that `reload` does **not** restart `wazuh-manager-remoted`, so a change in `remote` needs `restart` |

---

## Common Internal Options

These internal options apply to every module of `wazuh-manager-modulesd`, or to every C daemon. Set
them in `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`; an absent key takes the default
below, and a value outside the range stops the daemon at start with
`(2302): Invalid definition for <name>: '<value>'.`

| Option | Default | Range | Effect on the manager |
|---|---|---|---|
| `wazuh_modules.debug` | `0` | `0`-`2` | Debug level of `wazuh-manager-modulesd` (the `-d` flag overrides it) |
| `wazuh_modules.rlimit_nofile` | `65536` | `8192`-`1048576` | Soft file descriptor limit of `wazuh-manager-modulesd`, see [File descriptor limits](#file-descriptor-limits) |
| `wazuh_modules.max_eps` | `100` | `1`-`1000` | Events per second of the agent-side modules; read and range-checked, but no manager module paces on it |
| `wazuh_modules.task_nice` | `10` | `-20`-`19` | Nice value of the external programs a module launches; no manager module launches one |
| `wazuh_modules.kill_timeout` | `10` | `0`-`3600` | Seconds a module's child process gets to exit at shutdown before it is killed; no manager module starts one |
| `wazuh.thread_stack_size` | `8192` | `2048`-`65536` | Stack size, in KiB, of the threads `wazuh-manager-remoted` and `wazuh-manager-modulesd` start; read at each thread creation |

---

## File descriptor limits

Two limits apply to every daemon, and they have different owners:

1. **The hard limit** is set by whatever starts the manager: `LimitNOFILE=65536` in
   `wazuh-manager.service`, the shell that runs the SysV init script, or `ulimits.nofile` in a
   container. The daemons never change it. Raising it needs `CAP_SYS_RESOURCE`, which containers drop
   by default, so it is set where the process is started, not from inside. The SysV init scripts only
   raise the soft limit to `65536` (to the hard limit when that is lower, with a warning on stderr).
2. **The soft limit** is the one the kernel enforces (`EMFILE`, "too many open files"). At start,
   each daemon raises its own soft limit to the value of its internal option, never above the hard
   limit it inherited and never below what it already had:

| Option | Default | Range |
|---|---|---|
| `remoted.rlimit_nofile` | `65536` | `1024`-`1048576` |
| `wazuh_db.rlimit_nofile` | `65536` | `1024`-`1048576` |
| `wazuh_modules.rlimit_nofile` | `65536` | `8192`-`1048576` |

`wazuh-manager-analysisd` (the engine) has no option: at start it raises its own soft limit to a
fixed `8192`, never above the hard limit it inherited and never below what it already had, and logs
`File descriptor limit is <n>, below the 8192 requested by the engine. …` when the hard limit is lower.
Its HTTP servers hold one descriptor per client connection, and its IoC store is a RocksDB database
opened with RocksDB's default `max_open_files` (`-1`, every file kept open), so its usage grows with the
size of the IoC data. `authd`, `apid` and `clusterd` keep the limits they inherit.

When the hard limit is below the option, the daemon runs with the hard limit and logs a warning
naming both values, for example
`File descriptor limit is 8192, below the 65536 requested by 'remoted.rlimit_nofile'. Raise the limit the process is started with (LimitNOFILE, ulimit -n, container ulimits) to go higher.`
`wazuh-manager-modulesd` logs it twice per start, because it raises its limit before the `-t` check
`wazuh-manager-control` runs first. To go higher, raise the limit the process is started with: a
drop-in with `LimitNOFILE=` for the service unit, `ulimit -n` before the init script, or
`ulimits.nofile` in the container definition. An option above the hard limit never fails and never
logs an error. `GET /cluster/{node_id}/configuration/request/internal` reports the effective value
for remoted (`internal.remoted.rlimit_nofile`, after the cap); no other daemon reports it.

`wazuh_modules.rlimit_nofile` cannot go below `8192`: a lower value is rejected at start with
`Invalid definition` and `wazuh-manager-modulesd` does not run.

---

For comprehensive module documentation including architecture and implementation details, see [Modules Reference](../../modules/README.md).
