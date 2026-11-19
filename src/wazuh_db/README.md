# wazuh_db (wazuh-manager-db)

The manager's SQLite daemon. It owns `queue/db/global.db` — the agent registry, the groups and their
assignments, each agent's connection state and credentials — and answers read-only queries on the
MITRE ATT&CK database `var/db/mitre.db`. Every other manager component that needs one of those rows
asks this process, over one of two Unix sockets: the framed query protocol on `queue/sockets/wdb.sock`
and the HTTP routes on `queue/sockets/wdb-http.sock`.

Three documentation layers cover wazuh-db, each with its own job:

- **This README** — the developer's map: the [requirements catalog](#requirements) and
  [design decisions](#design-decisions-d1d15), the [layout](#layout), how the
  [threads and the one lock per database](#threads-and-locking) divide the work, the
  [transaction model](#transactions-and-durability), the [invariants](#invariants) a change must keep,
  and the [test map](#tests).
- **[`docs/ref/modules/wazuh_db/`](../../docs/ref/modules/wazuh_db/README.md)** — the operator
  contract: the command line, the socket protocol and every command's syntax, the databases and their
  tables ([overview](../../docs/ref/modules/wazuh_db/README.md)), the `wdb` section and the
  `wazuh_db.*` internal options ([configuration](../../docs/ref/modules/wazuh_db/configuration.md)), and
  the HTTP routes with their bodies and status codes
  ([API reference](../../docs/ref/modules/wazuh_db/api-reference.md)). Nothing here restates them.
- **[`uds_http_server`](../shared_modules/uds_http_server/README.md)** — the library that serves
  `wdb-http.sock`: its routing, shedding classes and the handler contract this daemon deliberately
  bends (D5).

## Requirements

What the daemon has to do, and where each requirement is answered.

### Functional (RF)

| # | Requirement | Where it is answered |
|---|---|---|
| RF-1 | Own `global.db`: create it from the embedded schema on first open (mode `0640`), and close the handle when a failed query finds the file gone, so that the next open recreates it | `wdb_open_global()`, `wdb_create_file()` (`src/wdb.c`); the `w_is_file()` check at the end of the `global` branch of `wdb_parse()` (`src/wdb_parser.c`) |
| RF-2 | Serve the framed query protocol on `wdb.sock`: `<database> <command> [<arguments>]`, answered `ok`, `err` or `due`, one message per frame of at most `OS_MAXSTR` (65536) bytes; a longer frame closes that peer | `run_dealer()`, `run_worker()` (`src/main.c`), `wdb_parse()` |
| RF-3 | Answer what cannot fit in one frame in pages (`due` + the caller asks again from the last id) or, for `get-all-agents context`, as a stream of one `due` frame per row ended by `ok []` | the `*_get` parsers in `src/wdb_parser.c`; `wdb_exec_stmt_send()` (`src/wdb.c`) |
| RF-4 | Answer `mitre sql` on `mitre.db` without ever modifying it | `wdb_open_mitre()` opens it `SQLITE_OPEN_READONLY` — D4 |
| RF-5 | Answer the JSON commands `getstats` and `getconfig` (`wdb`, `internal`) on the same socket | `wdbcom_dispatch()` (`src/wdb_com.c`), chosen by a leading `{` in `run_worker()` |
| RF-6 | Serve the agent sync, summary and group routes on `wdb-http.sock` for clusterd and the framework; a failure to start them is logged and does not stop the daemon | `wdb_http_start()` (`src/http/wdb_http.cpp`), one header per route under `src/http/` |
| RF-7 | Report, on `GET /v1/status`, whether `global.db` can be queried — not whether the process is up | `registerStatusRoute()`, `endpointGetV1Status.hpp` — D6 |
| RF-8 | Commit writes on the daemon's own clock: a write joins the open deferred transaction, which the garbage collector commits once `commit_time_min` passes without a query or `commit_time_max` after it began | `wdb_begin2()` before each write (`src/wdb_global.c`), `wdb_commit_old()` (`src/wdb.c`) |
| RF-9 | Let a caller end that transaction now (`global commit`) | the `commit` branch of `wdb_parse()` — D2 |
| RF-10 | Back up `global.db` periodically and on demand (`VACUUM INTO` + gzip, keeping `max_files`), list the backups, and restore a named or the most recent one, optionally after a `-pre_restore` backup | `run_backup()` (`src/main.c`); `wdb_global_create_backup()`, `wdb_global_remove_old_backups()`, `wdb_global_restore_backup()` (`src/wdb_global.c`) — D14 |
| RF-11 | Keep the files compact and the handle count bounded: `VACUUM` a fragmented database (never `mitre.db`), close idle handles above `open_db_limit` (never `global.db`) | `run_gc()`; `wdb_check_fragmentation()`, `wdb_close_old()` (`src/wdb.c`) |
| RF-12 | Refuse to serve a `global.db` whose `user_version` this build does not support: the handle is disabled and every `global` query answers `err DB global disabled.` | `wdb_upgrade_global()` (`src/wdb_upgrade.c`, no upgrade steps), `wdb_user_version_get()` (`src/wdb_metadata.c`) |
| RF-13 | Never write an agent's key or re-enrollment secret to the log | the entry log of the `global` branch of `wdb_parse()` — D3 |
| RF-14 | Count queries and their time per database and command, HTTP requests included, for `getstats` | `src/wdb_state.c`; `wdb_global_pre()` counts each HTTP request under `global` |

### Non-functional (RNF)

| # | Requirement | Where it is answered |
|---|---|---|
| RNF-1 | One SQLite handle and one mutex per database: every access to `global.db`, from a socket worker, an HTTP handler, the garbage collector or the backup thread, is serialized on it | `wdb_pool_get_or_create()` returns the handle **locked** (`src/wdb_pool.c`); [threads and locking](#threads-and-locking) |
| RNF-2 | No C++ exception crosses the `extern "C"` boundary into `main.c` | the `try`/`catch` in `wdb_http_start()` and around every handler in `registerRoute()` |
| RNF-3 | Run unprivileged, with the installation directory as working directory and every path relative to it, SQLite's temporary files included | `main()`: `chdir()`, `Privsep_SetGroup()`/`Privsep_SetUser()`, `SQLITE_TMPDIR=tmp` — D8, D9 |
| RNF-4 | Bounded waits: a streamed row waits at most `WDB_BLOCK_SEND_TIMEOUT_S` (1 s) for the peer; `SQLITE_BUSY` is retried at most `MAX_ATTEMPTS` (1000) times, `BUSY_SLEEP` (1 ms) apart, so a database another connection keeps locked is given up on after about one second — with the handle's mutex held throughout | `wdb_exec_stmt_send()`, `wdb_prepare()`, `wdb_step()` (`src/wdb.c`) |
| RNF-5 | Unit-testable without a running daemon | `wdb_lib` excludes `main.c` and, under `UNIT_TEST`, defines `WAZUH_UNIT_TESTING` so the `STATIC` helpers link; the HTTP endpoints are templates over the database connection and statement types ([`CMakeLists.txt`](CMakeLists.txt), [tests](#tests)) |

<a id="design-decisions-d1d15"></a>

## Design decisions (D1–D15)

| # | Decision | Why |
|---|---|---|
| D1 | **`global.db` runs with `PRAGMA synchronous=1` (NORMAL)** on SQLite's default rollback journal, not WAL (`wdb_open_global()`, `wdb_set_synchronous_normal()`) | The comment in `include/wdb.h` gives the trade: FULL's `fsync` was the dominant write cost, and the contents are taken to be reconstructible because agents re-report their state on reconnect. That premise does not cover every column — see invariant 7 |
| D2 | **`global commit` ends the deferred transaction immediately** | `wazuh-manager-authd` may forget a journaled identity transition only once the write is durable, and the `ok` of `insert-agent` or `set-agent-credentials` comes from inside a transaction that commits later (commit "never hand out a credential the database may never see"; the comment on the branch). authd is its only caller |
| D3 | **`insert-agent` and `set-agent-credentials` log only their verb**; every other `global` command still logs whole at debug level 2 | Their arguments carry `internal_key` and `reenroll_secret`, and the manager log is served by `GET /cluster/{node_id}/logs` under ordinary read permission. The other commands carry no credentials and their text is worth having when something fails |
| D4 | **`mitre.db` is opened read-only, and the fragmentation check skips it** (`wdb_open_mitre()`, `wdb_check_fragmentation()`) | The installer builds it and nothing writes it afterwards; `mitre sql` takes any SQL, so read-only turns a write into `attempt to write a readonly database` instead of a change, and a read-only file can never be vacuumed |
| D5 | **HTTP handlers run their SQLite query inline on the `uds_http_server` I/O thread** (`registerRoute()`) — an accepted exception to that library's non-blocking handler rule, and the example not to copy | The comment in `src/http/wdb_http.cpp`: every endpoint is a synchronous SQLite query, and `wdb-http.sock` is low-traffic (clusterd and the Server API, never agents), so the trade was accepted rather than adding a worker dispatch layer. The cost: a handler waits on the `global.db` mutex (RNF-1), including behind a `VACUUM`, a backup or a long socket stream |
| D6 | **`GET /v1/status` has its own wrapper, answers `503` (never `500`) when the database cannot answer, is registered `RouteClass::Liveness`, and reads only `sqlite_master`** | A caller asking "can you serve?" needs `503` to route elsewhere; `500` reads as a broken endpoint. Liveness keeps data-plane back-pressure from shedding the probe exactly when the daemon struggles. The route is polled by load balancers, so it must stay cheap: it checks that `agent`, `belongs` and `group` exist instead of reading rows (comments in `wdb_http.cpp` and `endpointGetV1Status.hpp`) |
| D7 | **A malformed `POST /v1/agents/sync` body is a `400` with a throttled warning that never quotes the body** | That endpoint parses the caller's body unguarded, so a JSON or `invalid_argument` exception there is a client error, not a daemon fault; elsewhere a JSON exception comes from the daemon's own data and stays a `500` (comment in `registerRoute()`) |
| D8 | **No chroot**: the daemon changes to the installation directory, drops to `wazuh-manager`, and opens every path relative to it (the constants in `src/shared/include/defs.h`) | The chroot only moved the root to where the working directory already was; dropping it is the prerequisite for confining the daemons with the systemd unit instead (commit "Run wazuh-manager-remoted and wazuh-manager-db without chroot") |
| D9 | **`SQLITE_TMPDIR` is set to `tmp` before any SQLite call** | Without the chroot SQLite's large sorts and `VACUUM` temporaries went to the host's `/var/tmp` or `/tmp`, or the unit's private one; SQLite reads the variable once, at its first initialization, and the control script empties `tmp/` at every start (comment in `main()`, commit "Keep wazuh-db's SQLite temporary files in the installation directory") |
| D10 | **A relative `-c` is resolved before the `chdir()`** | It names a file under the directory the command runs from; after the `chdir()` the same relative path would name another file (comment in `main()`) |
| D11 | **`-h` and an unknown option exit `1`** (`wdb_help()`) | Like remoted and modulesd: the same function runs for an unknown option, which must not read as success to a script (comment in `wdb_help()`) |
| D12 | **Only the soft descriptor limit is raised** (`w_raise_nofile_limit()` with `wazuh_db.rlimit_nofile`) | The hard limit belongs to whoever started the manager (comment in `main()`) |
| D13 | **A frame longer than `OS_MAXSTR` closes that peer; the worker keeps serving** | Leaving the connection open and unanswered would leave the client waiting forever for an answer that never comes (commit "Close peer socket on oversized message instead of exiting worker"; `test_wazuh_db_oversized_message.py`) |
| D14 | **A restore accepts only a name a backup could have** — the `global.db-backup` prefix, `.gz`, the characters a generated name carries, no `..` — **and checks it before taking the pre-restore backup** (`wdb_global_is_valid_backup_name()`) | The name is joined to `backup/db`, so it must be a bare file name; checking first means a refused name leaves nothing behind (comments in `wdb_global_restore_backup()`) |
| D15 | **`global sql` clears the global group-hash cache after every statement that is not a plain `SELECT`, whether or not it succeeded** (`wdb_global_sql_is_select()` in `src/wdb_parser.c`) | The hash is computed from `agent.group_hash`, which a statement changes by updating that column or by inserting, replacing or deleting agents, under any quoting, alias or `WITH` clause, so telling the touched tables from the text would be fragile; a needless clear costs one recalculation. A failed statement is not proof of no change (`UPDATE OR FAIL` keeps the rows it changed before the error). The framework's frequent `SELECT`s keep the cache (comment on the branch) |

## Layout

| Path | Contents |
|---|---|
| `src/main.c` | `main()`: options, internal options, the `wdb` section through `w_mconf_load()`/`w_mconf_section()` and `Read_WazuhDB_JSON()` (`src/config/src/wazuh_db-config.c`), privilege drop, and the thread bodies (`run_dealer`, `run_worker`, `run_gc`, `run_backup`) |
| `src/wdb_parser.c` | `wdb_parse()`, the dispatcher of the framed protocol, one `wdb_parse_global_*()` per command; `wdb_global_pre()`/`wdb_global_post()`, the HTTP routes' way into the same handle |
| `src/wdb_global.c` | the `global` commands' SQL work, the group-hash calculations, backup create/list/restore |
| `src/wdb.c` | handle lifecycle (`wdb_open_global()`, `wdb_open_mitre()`, `wdb_close()`), the prepared-statement table `SQL_STMT[]` and its per-handle cache, transactions, the row-to-JSON executors (sized, paged, streamed), the garbage collector's commit, vacuum and close passes, `getconfig` |
| `src/wdb_pool.c`, `include/wdb_pool.h` | the pool of open handles: a red-black tree keyed by database name under one pool mutex, each node with its own mutex and refcount |
| `src/wdb_upgrade.c`, `src/wdb_metadata.c` | the `user_version` gate on opening an existing `global.db` (no upgrade steps) |
| `src/wdb_com.c` | the JSON commands `getstats` and `getconfig` |
| `src/wdb_state.c`, `src/wdb_state.h` | the counters and timings behind `getstats`, one `w_inc_*()` pair per command |
| `src/http/wdb_http.cpp`, `src/http/wdb_http.h` | the `extern "C"` start/stop of the HTTP server and the route table |
| `src/http/endpoint*.hpp` | one header-only endpoint per route, templated on `DBConnection`/`DBStatement` (default `SQLite3Wrapper`) |
| `include/wdb.h` | everything the units share: `wdb_t`, the `wdb_stmt` enum that indexes `SQL_STMT[]`, the configuration struct, every prototype |
| `schemas/schema_global.sql` | the DDL of `global.db`, `user_version = 1` |
| `embed_sql.cmake` | turns each `schemas/*.sql` into a C string `<name>_sql` at build time (invariant 4) |

The binary `wazuh-manager-db` is `main.c` linked against `wdb_lib`, the static library holding every other
source; the unit tests link `wdb_lib` the same way ([`CMakeLists.txt`](CMakeLists.txt)). The `UNIT_TEST`
tree defines no executable. `wdb_lib` links `wazuh_modulesd_lib` and `config` publicly and
`wazuh_uds_http_server` privately.

## Threads and locking

| Thread | Role |
|---|---|
| Dealer | binds `wdb.sock`, accepts peers and registers each one in a `wnotify` queue |
| Workers (`wazuh_db.worker_pool_size`) | one at a time waits on the queue under `queue_mutex`; the winner takes a ready peer out of it, reads one frame, answers it, and puts the peer back |
| HTTP I/O threads | owned by `uds_http_server` (`ioThreads` left at `0`: one per CPU); each request runs its handler inline (D5) |
| Garbage collector | once a second: `wdb_commit_old()`, every `check_fragmentation_interval` seconds `wdb_check_fragmentation()`, then `wdb_close_old()` |
| Backup | only when `wdb.backup.global.enabled`: once a second, a backup when `interval` has elapsed since the newest file in `backup/db` |

**The lock that matters is the handle's.** `wdb_pool_get_or_create()` and `wdb_pool_get()` return the
`wdb_t` with its mutex held, and `wdb_pool_leave()` releases it. Because there is one handle per
database, every `global.db` operation in the process runs one at a time, whichever thread issues it:
the worker pool parallelizes socket I/O and the `mitre` handle, never two `global` queries. The same
mutex is held across a whole `VACUUM`, a whole backup, and a whole `get-all-agents context` stream, so
those stall every other `global` caller — socket and HTTP alike — for their duration.

The streaming and paging helpers exist because of the frame limit: a worker's answer buffer is
`OS_MAXSTR + 1` bytes, so any answer that can grow with the number of agents must page or stream.

## Transactions and durability

- Writers open a transaction when none is open (`if (!wdb->transaction && wdb_begin2(wdb) < 0)` at the
  top of each `wdb_global_*()` writer), and so do the HTTP routes, read-only ones included, through
  `wdb_global_pre()`. `wdb_begin2()`/`wdb_commit2()` keep `wdb->transaction` and its start time in step
  with SQLite.
- Nothing commits after a write. `wdb_commit_old()` commits once the handle has been idle for more than
  `commit_time_min` seconds or the transaction is older than `commit_time_max`; `global commit` (D2),
  `wdb_close()`, a backup and a vacuum commit first. An `ok` is therefore not a durability
  acknowledgement — the operator page says so too.
- `global sql` executes through `wdb_exec()` without opening a transaction: inside one if a writer left it
  open, autocommitted otherwise.
- With `synchronous=NORMAL` (D1), even a committed transaction can be lost to a power cut.

## Invariants

1. **Every lock is paired with a leave.** A path that obtains a handle (`wdb_open_global()`,
   `wdb_open_mitre()`, `wdb_pool_get*()`, `wdb_global_pre()`) and returns without
   `wdb_pool_leave()`/`wdb_global_post()` leaves that database's mutex held, and every later query on it
   blocks forever.
2. **An answer fits in `OS_MAXSTR`.** A new command whose answer grows with the fleet pages it (`due`) or
   streams it (`wdb_exec_stmt_send()`); `wdb_exec_stmt_sized()` stops at a byte budget.
3. **Prepared statements belong to a handle.** A new statement is a `wdb_stmt` enum value in
   `include/wdb.h` and an entry at that index of `SQL_STMT[]` in `src/wdb.c`, obtained through
   `wdb_init_stmt_in_cache()`/`wdb_stmt_cache()`. `wdb_finalize_all_statements()` drops them before a
   `VACUUM`, a backup and a close, so never hold one across those.
4. **A schema file has no `--` comments.** `embed_sql.cmake` deletes every newline, so a `--` line
   comment would swallow the rest of the file; use `/* */` like `schemas/schema_global.sql`. Every
   `schemas/*.sql` is picked up by a `file(GLOB)`, so re-run the configure step after adding one.
5. **The global group-hash cache is cleared by every write that changes groups.** The hash lives in a
   static in `wdb_global_group_hash_cache()` (`src/wdb.c`); `insert-agent`, `delete-agent`, the
   `wdb_global_recalculate_*()` functions, a restore that replaces `global.db`
   (`wdb_global_restore_backup()`) and any `global sql` statement but a plain `SELECT` (D15) clear it.
6. **A new command or route is counted.** Add its `w_inc_*()` pair in `src/wdb_state.{c,h}`, call it from
   the dispatcher, and add the `--wrap` flags to the test's list in
   [`unit_tests/wazuh_db/CMakeLists.txt`](../unit_tests/wazuh_db/CMakeLists.txt) — the parser tests wrap
   every counter.
7. **Not everything in `global.db` is re-reported by agents.** The `reenroll_secret` column is stored
   nowhere else (the operator page's table of `global.db`), so D1's premise does not hold for it;
   weigh that before relying on `synchronous=NORMAL` for new state.
8. **The socket paths are spelled in several places.** `wdb.sock`: `WDB_LOCAL_SOCK` in
   `src/shared/include/defs.h`, `WDB_SOCKET` in `framework/wazuh/core/common.py`, and `kWdbSocket` in
   `src/remoted/remoted_module/src/common/installPaths.hpp`. `wdb-http.sock`: the literal passed to
   `wdb_http_start()` in `src/main.c` and `WDB_HTTP_SOCKET` in `common.py` — there is no C constant.

## Clients

| Client | Socket | Code |
|---|---|---|
| C daemons (authd, remoted, modulesd's database and task-manager modules) | `wdb.sock` | `src/shared/src/wazuhdb_op.c` (framing, `wdbc_query_ex()`), `src/shared/src/wazuhdb_queries_op.c` (one helper per command) |
| The framework and the Server API | `wdb.sock` | `framework/wazuh/core/wdb.py` (`WazuhDBConnection`) |
| clusterd and the framework | `wdb-http.sock` | `framework/wazuh/core/wdb_http.py`; the readiness client is named in the [API reference](../../docs/ref/modules/wazuh_db/api-reference.md) |

A change to a command's syntax or answer moves the daemon's parser, the C helper in
`wazuhdb_queries_op.c` or the framework client, their tests, and the
[operator page](../../docs/ref/modules/wazuh_db/README.md); a route change moves its endpoint header,
`registerRoute()`'s table and the [API reference](../../docs/ref/modules/wazuh_db/api-reference.md).

## Tests

| Suite | Covers |
|---|---|
| `unit_tests/wazuh_db/test_wdb_parser.c` | `wdb_parse()`'s `backup` syntax and `create`, and that the removed `sleep` verb is refused |
| `unit_tests/wazuh_db/test_wdb_global_parser.c` | every `global` command's parser with its `wdb_global_*()` and counters wrapped, `commit`, `backup` |
| `unit_tests/wazuh_db/test_wdb_global.c` | the SQL side of the `global` commands, group hashes, backup create/list/restore and the snapshot-name check |
| `unit_tests/wazuh_db/test_wdb.c` | handle open/close, the `SQLITE_BUSY` retry of `wdb_prepare()`/`wdb_step()` (`w_time_delay` wrapped), transactions, statement cache, the executors, commit/vacuum/close passes |
| `unit_tests/wazuh_db/test_wdb_pool.c` | the pool: get, create, leave, keys, clean, size |
| `unit_tests/wazuh_db/test_wdb_upgrade.c` | the `user_version` gate: unreadable, current, `0` and a future version |
| `unit_tests/wazuh_db/test_wdb_com.c`, `test_wazuh_db_state.c`, `test_wazuh_db-config.c` | the JSON commands, the statistics document, the `wdb` section reader |
| `unit_tests/wazuh_db/test_wdb_http_endpoints.cpp` | the endpoint classes (groups, all, summary, both sync routes, status) driven by a hand-fed mock statement — no SQLite, no `wdb_lib`, no socket; gtest, because the malformed-body case needs real exceptions. `registerRoute()`'s wrapper (500/400/503 mapping) is not in it |
| `tests/integration/test_wazuh_db/` | on an installed manager: `test_backup`, `test_configuration` (`getconfig`), `test_databases` (queries, oversized frame, timeout), `test_groups` |

The unit suites are the legacy cmocka project: they run in the manager leg of
[5_testunit_linux-win.yml](../../.github/workflows/5_testunit_linux-win.yml), always built with ASAN and
UBSAN. Every log line the code under test emits must be expected, because the `debug_op` wrappers check
each one. The integration suite runs only from
[5_builderpackage_manager-multiples.yml](../../.github/workflows/5_builderpackage_manager-multiples.yml)
through [5_testintegration_manager.yml](../../.github/workflows/5_testintegration_manager.yml), against
the `.deb` built in the run, when a path listed for `wazuh_db` in
[test_modules_manager.json](../../.github/test_modules_manager.json) changes. What no suite exercises:
`main.c` (it is not in `wdb_lib`) — the thread bodies and the lock discipline between them — and the
real `uds_http_server` wiring of the routes, which only the integration suite reaches.
