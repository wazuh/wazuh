# Manager Configuration

Configuration reference for Wazuh manager components. The manager configuration is a **strict XML**
file validated against a JSON schema (the agent keeps its own XML `ossec.conf`, read by the legacy
parser).

## Configuration Files

| File | Location | Mode | Description |
|------|----------|------|-------------|
| `wazuh-manager.conf` | `/etc/wazuh-manager` | 660 `root:wazuh-manager` | Main configuration: a single `<wazuh_config>` root with one element per section (see [the generated reference](reference.md)) |
| `wazuh-manager.schema.json` | `/etc/wazuh-manager` | 640 `root:wazuh-manager` | JSON Schema (draft-04) the file is validated against; installed copy of `src/shared_modules/manager_config/schema/wazuh-manager.schema.json`, replaced on every install and upgrade (product, not configuration) |
| `wazuh-manager-internal-options.conf` | `/etc/wazuh-manager` | 640 `root:wazuh-manager` | Internal tuning parameters (`key=value`); ships with comments only, the defaults are compiled in, and an existing file is kept |
| `api.yaml` | `/var/wazuh-manager/api/configuration/` | 660 `root:wazuh-manager` | REST API configuration (see [Server API configuration](../../modules/server-api/configuration.md)) |

`wazuh-manager.conf` is **generated, not shipped**: the installer and the packages write it once
(`src/init/gen_wazuh.sh conf manager <dist> <version>` prints the same document) from the templates in
`etc/templates/config/`, validate it with `wazuh-manager-conf --skip-file-checks validate` and install it.
Upgrades preserve it; DEB upgrades leave the regenerated defaults next to it as `wazuh-manager.conf.new`.

The file is parsed as **well-formed XML**: a single `<wazuh_config>` root without attributes, no
unescaped `&` or `<`, `<!-- -->` comments only (with no `--` inside), at most 1 MiB and 16 levels of
nesting. An XML declaration (`<?xml …?>`), a processing instruction or a `<!DOCTYPE …>` is accepted and
ignored without a message; nothing declared in a DOCTYPE is applied, and a reference to an entity it declares
is refused as a raw `&`. The predefined XML entities (`&amp;`, `&lt;`…) and character references are decoded
into the values. Values are typed by the schema:
booleans are written `yes`/`no` (any case; `true`/`false` are rejected), numbers as digits, enumerated
values in any case, and lists in any of three forms: one child per item
(`<hosts><host>…</host></hosts>`), a comma-separated value (`<protocol>tcp,udp</protocol>`), or the
element repeated (`<log_format>plain</log_format><log_format>json</log_format>`). Any other repeated
element is rejected as a duplicate.

## Validation and tools

- `bin/wazuh-manager-conf [-f <file>] [-H <home>] [--skip-file-checks] <command>` reads
  `/etc/wazuh-manager/wazuh-manager.conf` unless `-f` names another file (`-H` never moves it: it sets the
  home that relative paths inside the file resolve against); `-H` defaults to
  `$WAZUH_MANAGER_HOME`, else the parent of the `bin/` directory holding the program. `-V` prints the
  version. Exit status: `0` success, `1` invalid configuration, missing file or usage error, `2` key not
  set (`get`).
  - `validate` checks the XML syntax, the schema (types, ranges, enums, unknown options, the address
    syntax of `remote.legacy.local_ip` and `remote.https.bind_addr`, the lengths the daemons cap), the
    cross-field rules (a certificate and its key set together — `remote.https.certificate`/`key` and
    `auth.ssl_manager_cert`/`ssl_manager_key` only; the `indexer.ssl` pair is not paired here — no `.`/`..` segment in
    `remote.https.global_prefix`, distinct listener ports — `remote.legacy.port` counts only when the legacy
    listener is enabled and `auth.port` only while authd's port-1515 listener starts; the Server API port,
    55000 by default, lives in `api.yaml` and is **not** compared with them) and, unless `--skip-file-checks`, the existence of the
    certificate files the configuration names (`remote.https.certificate`, `key`, `ca`,
    `ca_certificate`, `auth.ssl_agent_ca`, `ssl_manager_cert`, `ssl_manager_key`; `indexer.ssl.*` is not
    checked). Silent on success; on failure it prints the JSON pointer of the offending option:
    `(1244): Invalid configuration at '/remote/legacy/port': does not satisfy 'maximum' [...]`
    (`'/'` for syntax problems, which name the line instead). A missing file is
    `(1239): Configuration file not found: '<file>'.`; a file that exists but cannot be read is
    `(1244): Invalid configuration at '/': configuration file cannot be read: <file>: <reason>.`
  - Durations and sizes are judged to the limits the daemons read them with: a size is at least one byte
    in any unit (`0K` is refused), and a duration or size has at most as many digits as its unit allows
    without overflowing a reader (a duration at most 999999999 seconds; the limits per unit are in
    [the reference](reference.md)). `cluster.bind_addr` must be a host name or an IP address, and every
    `indexer.hosts` entry an `http://` or `https://` URL that names a host.
  - What `validate` does not judge, and the start does: the `indexer.ssl` certificate and key (one set
    without the other passes `validate` and the API's `PUT`; the other half keeps its default file, and the
    credential check refuses the resulting pair at the next start with error 22), where the TLS files lie and what they hold (the
    credential check refuses a path outside `/etc/wazuh-manager/certs`, an expired or mismatched pair —
    [Credentials](../../getting-started/credentials.md)), the internal options (read only by each daemon at
    start), and what only a running system shows (an address this host does not have, a port another
    program holds). The API's `PUT` runs the same `validate`, so it has the same limits.
    `wazuh-manager-control check` runs the whole pre-start sequence below — validation, credentials and
    every daemon's `-t` — without stopping or starting anything. Through those `-t` runs it also judges
    what the TLS files hold: `wazuh-manager-remoted -t` loads `remote.https.certificate` and `key` (and
    `remote.https.ca` when `verification_mode` needs it), and `wazuh-manager-authd -t` loads the
    `auth.ssl_*` files when authd's legacy enrollment listener (1515) will start — authd enabled, with
    `remote_enrollment` and `legacy_enrollment` on; enrollment through the HTTPS listener uses remoted's pair
    and never reads them — so a file that is not a usable PEM certificate, key or CA is
    refused before anything stops.
  - What even `wazuh-manager-control check` does not judge, so that a value passes it and still stops a
    daemon at start:
    - the engine's `analysisd.*` internal options: its `-t` returns before it reads the internal-options
      file, so an out-of-range value stops `wazuh-manager-analysisd` before it writes its pid file
      (`Failed to obtain PID for wazuh-manager-analysisd`);
    - `wazuh.thread_stack_size`: read only when a thread is created, which no `-t` does, so an
      out-of-range value stops `wazuh-manager-remoted` or `wazuh-manager-modulesd` at start with `(2302)`;
    - memory: `remote.legacy.queue_size` is judged by type and range (at most 134217728, which asks for
      1 GiB of queue slots at start), not against what the host can allocate — see the option in
      [the reference](reference.md);
    - what the cluster protocol can carry: a `cluster.name` or `cluster.node_name` outside
      `[A-Za-z0-9_-]` passes every check, and a worker so named never joins its master (see
      [Cluster configuration](../../modules/cluster/configuration.md)).
  - `get <key.path>` prints one option of the **effective** document (defaults applied): scalars as
    plain text, objects and lists as JSON. A key the effective document does not hold exits `2` with
    `wazuh-manager-conf: '<key.path>' is not set` — an option with no default left out of the file, and
    equally a key the schema does not know (a misspelling is not reported as such). `dump` prints the whole
    effective document.
- `bin/wazuh-manager-control start|restart|reload|check` validates the file first (with
  `--skip-file-checks`) and refuses to start any daemon when it is invalid: the CLI's verdict on stderr
  and as `wazuh-manager-control: ERROR: (1244): …` in `logs/wazuh-manager.log`, then
  `wazuh-manager.conf: Configuration error. Exiting` (`{"error":20,…}` with `-j`). After the credential
  check it validates the file again with the file checks on, then runs each daemon's `-t`; for the C
  daemons and the engine, `-t` validates the whole file, including the files it names. A C daemon
  started against an invalid file logs `(1244): Invalid configuration at '<file>': <pointer>: <reason>.`
  in `logs/wazuh-manager.log` and exits; `wazuh-manager-remoted` and `wazuh-manager-authd` add the
  CRITICAL `(1202): Configuration error at '<file>'.`, `wazuh-manager-db` the CRITICAL
  `Invalid configuration block for Wazuh-DB.`. The engine prints
  `Error loading configuration: <pointer>: <reason>` on stderr instead.
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
| [Remoted](../../modules/remoted/configuration.md) | `remote` (`legacy`, `https`, `agents`), `global` (read-only consumer) | `remoted.*`, `fim.*_limit`, `sca.checks_limit`, `syscollector.*_limit` |
| [Task Manager](../../modules/task_manager/configuration.md) (incl. [agent upgrades](../../modules/task_manager/agent-upgrades.md)) | `task-manager`, `global` ([`agents_disconnection_time`](../../modules/task_manager/configuration.md#agents_disconnection_time) is documented here), `remote` (delivery gates, read-only consumer) | `wazuh_modules.manager_task_*`, `wazuh_modules.upgrade_*` |
| [Vulnerability Scanner](../../modules/vulnerability-scanner/configuration.md) | `vulnerability-detection` | `vulnerability-detection.*`, `wazuh_modules.indexer_*` |
| [Wazuh DB](../../modules/wazuh_db/configuration.md) | `wdb` | `wazuh_db.*` |

Every option, with its type, default, constraints and description, is listed in the
[Manager Configuration Reference](reference.md), generated from the schema. The `global` section only
holds [`agents_disconnection_time`](../../modules/task_manager/configuration.md#agents_disconnection_time),
documented with the Task Manager; it is read by both remoted (which stops pushing to an agent silent
for longer, and checks `remoted.control_keepalive_throttle` against it) and the Task Manager's
disconnection sweep, so it is shared configuration rather than one module's; the Task Manager reads `remote` the same way, for the gates that decide
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
| `indexer` | Python consumers re-read the file when its modification time changes; `wazuh-manager-modulesd` and the engine read it at start |
| every other section | at daemon start (`restart`); note that `reload` does **not** restart `wazuh-manager-remoted`, so a change in `remote` needs `restart` (`reload` still runs `wazuh-manager-remoted -t`, so it refuses a `remote` change that the next `restart` would) |

---

## Common Internal Options

These internal options apply to every module of `wazuh-manager-modulesd`, or to every C daemon. Set
them in `/etc/wazuh-manager/wazuh-manager-internal-options.conf`; an absent key takes the default
below, and a value outside the range stops the daemon at start with
`(2302): Invalid definition for <name>: '<value>'.`

| Option | Default | Range | Effect on the manager |
|---|---|---|---|
| `wazuh_modules.debug` | `0` | `0`-`2` | Debug level of `wazuh-manager-modulesd` (the `-d` flag overrides it) |
| `wazuh_modules.rlimit_nofile` | `65536` | `8192`-`1048576` | Soft file descriptor limit of `wazuh-manager-modulesd`, see [File descriptor limits](#file-descriptor-limits) |
| `wazuh_modules.max_eps` | `100` | `1`-`1000` | Events per second of the agent-side modules; read and range-checked, but no manager module paces on it |
| `wazuh_modules.task_nice` | `10` | `-20`-`19` | Nice value of the external programs a module launches; no manager module launches one |
| `wazuh_modules.kill_timeout` | `10` | `0`-`3600` | Seconds a module's child process gets to exit at shutdown before it is killed; no manager module starts one |
| `wazuh_modules.socket_timeout` | `1` | `1`-`60` | Longest time, in seconds, a local client of the `wazuh-manager-modulesd` request socket can go without sending the next part of its request, or without reading the reply, before the connection is dropped. It bounds each wait, not the whole request |
| `wazuh_modules.unmask_credentials` | `0` | `0`-`1` | Reports module credentials in clear instead of as `*****`; read and range-checked, but the modules that hold credentials run only on agents |
| `wazuh.thread_stack_size` | `8192` | `2048`-`65536` | Stack size, in KiB, of the threads `wazuh-manager-remoted` and `wazuh-manager-modulesd` start; read at each thread creation, so no daemon's `-t` reads it and `wazuh-manager-control check` passes an out-of-range value that then stops the daemon at start |

### `wazuh-manager-modulesd` command line

`wazuh-manager-control` runs `bin/wazuh-manager-modulesd -t` before every start and then starts it
with no flags, or with `-d` after `wazuh-manager-control enable debug`. Usage:
`wazuh-manager-modulesd -[V|d|f|h|t] [-u <user>] [-c <config>]`.

| Flag | Effect |
|---|---|
| `-V` | Print the version and license and exit with status `0` |
| `-d` | Raise the debug level by one; repeat it (`-dd`) for level 2. When given, `wazuh_modules.debug` is ignored |
| `-f` | Run in the foreground instead of as a daemon |
| `-t` | Test the configuration and exit: load `wazuh-manager.conf` and the internal options, read every section the modules use, then validate the whole file, including the certificate files it names. Exit `0` when valid, `1` otherwise — also when a module's reader refuses a section it borrows (the task manager reads `global` and `remote`) and logs an `ERROR`, which a running daemon only warns about and replaces with its defaults. Implies `-f` |
| `-c <config>` | Manager configuration file to read (default `/etc/wazuh-manager/wazuh-manager.conf`). A relative path is resolved against the directory the command runs from |
| `-u <user>` | User the daemon switches to at start, after raising its file descriptor limit (default `wazuh-manager`); the group is always `wazuh-manager` |
| `-h` | Print the usage and exit with status `1` |

Any other flag prints the usage and exits with status `1`.

The exit status of `-h` is not the same for every daemon: the C daemons (`wazuh-manager-remoted`,
`wazuh-manager-authd`, `wazuh-manager-db`, `wazuh-manager-modulesd`) print the usage and exit `1`, as
for an unknown flag, while `wazuh-manager-analysisd` (the engine) and `wazuh-manager-conf` exit `0`.
`-V` exits `0` wherever it exists. Scripts should not read success from `-h`.

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
