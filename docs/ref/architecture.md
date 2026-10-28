# Architecture

## Server

The Wazuh Manager is a multi-daemon system where each component runs as a separate process. Components communicate through **Unix domain sockets** located under `queue/sockets/`. The major architectural change in 5.0 is the **Engine** (replacing the legacy `analysisd`) as the core event processing pipeline.

### High-Level Architecture

```mermaid
---
config:
  title: "Wazuh Manager Architecture"
  flowchart:
    nodeSpacing: 20
    rankSpacing: 50
---
flowchart LR

classDef ext fill:#f0f0f0,stroke:#999,stroke-width:2px,stroke-dasharray:6px,rx:10
classDef d fill:#e8f4fd,stroke:#2980b9,stroke-width:2px,rx:10
classDef e fill:#eaf7ea,stroke:#27ae60,stroke-width:2px,rx:10
classDef m fill:#fef9e7,stroke:#f39c12,stroke-width:2px,rx:10
classDef a fill:#fdecea,stroke:#e74c3c,stroke-width:2px,rx:10

agents(["Wazuh Agents"]):::ext
clients(["Dashboard / API Clients"]):::ext

subgraph manager[" "]
  direction LR

  subgraph gw["Gateway"]
    direction TB
    authd["Auth<br/>(UDS bridge, legacy TLS :1515)"]:::d
    remoted["Remoted<br/>(HTTPS :1517, legacy TCP/UDP :1514)"]:::d
  end

  subgraph core["Core"]
    direction TB
    engine["Engine<br/>(analysisd)"]:::e
    wdb["Wazuh DB"]:::d
  end

  subgraph modulesd["Modulesd"]
    direction TB
    vs["Vuln Scanner"]:::m
    cm["Content Manager"]:::m
    is["Inventory Sync Server"]:::m
    tm["Task Manager"]:::m
    ctrl["Control"]:::m
    ks["Keystore Server"]:::m
    dbm["Database"]:::m
  end

  subgraph mgmt["Management"]
    direction TB
    api["API"]:::a
    clusterd["Clusterd"]:::a
  end
end

indexer[("Wazuh Indexer")]:::ext
wpk(["WPK Repository<br/>(packages.wazuh.com)"]):::ext

%% External → Gateway
agents <-->|1| authd
agents <-->|1,2,3,4,5,9| remoted

%% Gateway → Gateway (POST /enroll bridges to authd's local socket: the 5.x registration path)
remoted -->|1| authd

%% Gateway → Core
remoted -->|2| engine
remoted -->|9| wdb
authd -->|1,10| wdb

%% Modulesd → Core
vs -->|3| engine
tm -->|9| wdb

%% The database module keeps global.db's agents and groups in step with client.keys and /etc/wazuh-manager/shared/
dbm --> wdb

%% Modulesd internal (in-process VD scan lane)
is -->|3| vs
vs -->|3| tm

%% Task Manager dispatches its manager tasks to Inventory Sync Server's internal routes
tm -->|3,10| is

%% The WPK download for an upgrade request: modulesd's only connection outside the deployment
tm -->|5| wpk

%% CVE feed downloads: VD registers a provider, Content Manager pages the feed back to it
vs <-->|3| cm

%% Modulesd ↔ Gateway (UDS relay: POST /stateful → queue/sockets/inventory-sync-http.sock)
remoted <-->|3| is

%% An agent's on-demand rescan request is relayed to the scanner's own socket (queue/sockets/vd-http.sock)
remoted -->|3| vs

%% Remoted asks for an agent's pending tasks and hands them back in the POST /control response
remoted -->|4,5| tm

%% Auth records the indexer purge as a task rather than calling Inventory Sync itself
authd -->|10| tm

%% Core / Modulesd → Indexer
engine <-->|2,3,4| indexer
vs <-->|3| indexer
cm <-->|3| indexer
is <-->|3,10| indexer
clusterd <-->|4,8| indexer
clusterd -->|8| wdb

%% Active response: clusterd turns each finding into an agent task; remoted hands it to the agent
clusterd -->|4| tm

%% Clusterd reads the Indexer credentials from the keystore before any Indexer access
clusterd -->|4,8| ks

%% Management → Internal
api -->|5,6| tm
api -->|6| engine & wdb & remoted
api -->|3,6| vs
api -->|1,6,10| authd
api -->|7| ctrl
api -->|8| clusterd

%% External → Management
clients -->|1,5,6,7,8,10| api
```

### Daemons

| Daemon         | Binary                    | Purpose | Command line |
| -------------- | ------------------------- | ------- | ------------ |
| **Engine**     | `wazuh-manager-analysisd` | Event processing, event generation (replaces legacy analysisd) | [Engine command line](modules/engine/configuration.md#command-line-options) |
| **Remoted**    | `wazuh-manager-remoted`   | Agent communication gateway — HTTPS agent API on port 1517 (enrollment, events, state sync, control, downloads); legacy AES TCP/UDP on 1514 for 4.x agents, controlled by `<remote><legacy><enabled>`: off when the `<legacy>` block is absent, but the configuration the installer generates writes it with `yes`, so an installed manager listens on 1514 | [Command line](modules/remoted/README.md#command-line) |
| **Wazuh DB**   | `wazuh-manager-db`        | SQLite-based database daemon for agent and global state | [Running the daemon](modules/wazuh_db/README.md#running-the-daemon) |
| **Auth**       | `wazuh-manager-authd`     | Owns all agent registration logic. Reached by Remoted's `POST /enroll` over its local socket for 5.x agents; its own TLS listener on port 1515 serves 4.x agents, gated by `<auth><legacy_enrollment>`, which follows `<remote><legacy><enabled>` when it is not set. Not started when `<auth><disabled>` is `yes` | [Command-line options](modules/authd/README.md#command-line-options) |
| **Server API** | `wazuh-manager-apid`      | REST API (Python/Starlette, HTTPS) with JWT auth and RBAC. Started only on the master node | [`wazuh-manager-apid` options](modules/server-api/configuration.md#wazuh-manager-apid-options) |
| **Modules**    | `wazuh-manager-modulesd`  | Hosts manager-side modules: vulnerability scanner, inventory sync server, keystore server, content manager, task manager (which also serves agent upgrades), database (keeps `global.db` in step with `client.keys` and `/etc/wazuh-manager/shared/`), and control (restart/reload) | [`wazuh-manager-modulesd` command line](configuration/manager/README.md#wazuh-manager-modulesd-command-line) |
| **Cluster**    | `wazuh-manager-clusterd`  | Multi-node master-worker synchronization (Python, asyncio) | [The daemon](modules/cluster/README.md#the-daemon) |

> **Note:** The manager also ships CLI tools (`wazuh-manager-control`, `wazuh-manager-conf`, `wazuh-manager-keystore`, etc.) listed in the [CLI Tools](#cli-tools) section below.

### Modulesd Module Composition

A manager-side module hosted by `wazuh-manager-modulesd` is three pieces, not one. The split is what lets a C daemon host C++ modules, and it is why the same name can appear in two directories.

| Layer                  | Location                        | Build output                            | Role                                                                                                                                                                                                                                     |
| ---------------------- | ------------------------------- | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Shim**               | `src/wazuh_modules/src/wm_<name>.c` | compiled into `wazuh-manager-modulesd`  | Declares the module's `wm_context` (`start`, `stop`, `destroy`, `dump`, `query`), registers it in `wmodules.c`, then `dlopen`s the implementation and calls its `extern "C"` entry points. The C↔C++ ABI boundary; ~100 lines, no logic of its own. |
| **Implementation**     | `src/wazuh_modules/<name>/`         | `lib<name>.so`, loaded by the shim      | The module proper. The shim resolves only its flat `<name>_start()` / `<name>_stop()` pair (the `dlopen` contract); the library keeps default symbol visibility, and modules may link each other directly — `libinventory_sync_server.so` links `libvulnerability_scanner.so` for `runScannerFromViews` and the `vd_sync` coordination registry. |
| **Shared library**     | `src/shared_modules/<name>/`        | `.so` or `.a`, linked by its consumers  | Reusable code with more than one consumer. Not a module: no `wm_context`, no registration.                                                                                                                                               |

| Module                    | Implementation                         | Shim                            |
| ------------------------- | -------------------------------------- | ------------------------------- |
| **Vulnerability Scanner** | `src/wazuh_modules/vulnerability_scanner/` | `wm_vulnerability_scanner.c`    |
| **Inventory Sync Server** | `src/wazuh_modules/inventory_sync_server/` | `wm_inventory_sync_server.c`    |
| **Task Manager**          | `src/wazuh_modules/task_manager/`          | `wm_task_manager.c`             |
| **Keystore Server**       | `src/wazuh_modules/keystore_server/`       | `wm_keystore_server.c`          |
| **Content Manager**       | `src/shared_modules/content_manager/`      | `wm_content_manager.c`          |
| **Database**              | —                                      | `wm_database.c`                 |
| **Control**               | —                                      | `wm_control.c`                  |

`Database` and `Control` are plain C compiled straight into modulesd, so they have no `.so` and no ABI boundary to cross — the two entries above with no implementation directory. `Database` is created only while the internal option `wazuh_database.sync_agents` is `1` (its default); see [Database Sync](modules/database-sync/README.md).

`src/wazuh_modules/` is a shared tree: it also holds the agent's modules. Their implementations (`agent_info`, `agent_upgrade`, `sca`, `syscollector`) are built only for the agent, but the manager build compiles every shim in `src/wazuh_modules/src/` into `wazuh-manager-modulesd`, the agent-only ones included (`wm_agent_info.c`, `wm_command.c`, `wm_sca.c`, `wm_syscollector.c`, and `wm_aws.c`, `wm_azure.c`, `wm_docker.c`, `wm_gcp.c`, `wm_github.c`, `wm_ms_graph.c`, `wm_office365.c`). `wm_config()` registers none of them in a manager build, so the table above is the manager's complete module set.

### Shared Libraries

| Library               | Source                             | Consumers                                                                              | Purpose                                                                                                                                                                    |
| --------------------- | ---------------------------------- | -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Indexer Connector** | `src/shared_modules/indexer_connector` | Engine, Vulnerability Scanner, Inventory Sync Server, Content Manager                    | Client library for reading from and pushing to the Wazuh Indexer. Per-instance classes with RAII lifetimes; reads Indexer credentials through the Keystore library.        |
| **Content Manager**   | `src/shared_modules/content_manager`   | Vulnerability Scanner (links it), Modulesd (registers it as a module)                    | Fetches CVE feed documents from the Indexer with Point-In-Time pagination and delivers them page-by-page to a registered callback. Also a modulesd module — see above.      |
| **Keystore**          | `src/shared_modules/keystore`          | Indexer Connector, Keystore Server, `wazuh-manager-keystore` CLI                         | AES-256 encrypted credential store (RocksDB). Static library, in-process only; socket access is the Keystore Server module's job.                                          |
| **UDS HTTP Server**   | `src/shared_modules/uds_http_server`   | Wazuh DB, Inventory Sync Server, Task Manager, Vulnerability Scanner, Remoted             | Asio-based HTTP/1.1 server over a Unix socket. The shared transport behind every HTTP socket listed below except the Engine's two, which the Engine serves itself.          |
| **Metrics**           | `src/shared_modules/metrics`           | Remoted, Vulnerability Scanner, Inventory Sync Server, Task Manager                       | Counters, gauges, histograms, pull metrics and a sliding-window rate behind a thread-safe registry, with a deterministic JSON dump. Static library, STL-only public headers, and deliberately **not** a singleton: each daemon owns a `Manager` and injects it. Kept under its own target and namespace rather than sharing the Engine's `fastmetrics`, which lives in the same build tree — one `Manager` under both names would be a silent ODR trap. |
| **Manager Config**    | `src/shared_modules/manager_config`    | Remoted, Authd, Wazuh DB, Modulesd (through libconfig's `w_mconf_*()`), Engine, `wazuh-manager-conf`, `wazuh-manager-certs` | Loader of `/etc/wazuh-manager/wazuh-manager.conf`: strict XML to canonical JSON, validated against the embedded schema, defaults filled, cross-field semantics checked. The single implementation of the manager configuration. |
| **CA Bundle**         | `src/shared_modules/ca_bundle`         | Remoted, `wazuh-manager-certs`                                                           | Pure functions over the CA bundle (`/etc/wazuh-manager/certs/root-ca.pem`): its certificates, content hash, publication stamp, and whether the served leaf chains to it. No file reads, logging or configuration, so remoted and the tool judge a bundle with the same code. |

### CLI Tools

Every tool is installed in `/var/wazuh-manager/bin/`.

| Binary                              | Purpose                                                                                                   | Reference |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------- | --------- |
| `wazuh-manager-control`             | Start, stop, restart, reload and query the daemons                                                        | [below](#wazuh-manager-control) |
| `wazuh-manager-conf`                | Validate, query (`get <key>`) and dump the effective manager configuration                                | [Validation and tools](configuration/manager/README.md#validation-and-tools) |
| `wazuh-manager-certs`               | Inspect, check and rotate the CA bundle remoted publishes (`inspect`, `check`, `add`, `remove`, `prune-expired`, `stamp`, `--from-master`) | [CA Bundle Rotation Runbook](modules/remoted/ca-rotation.md) |
| `wazuh-manager-resolve-credentials` | Set up and check the manager's passwords, keystore entry, CA, server pairs and indexer trust: `--install`, `--upgrade`, `--prestart` (default), read-only `--check`, and `--clear` | [The resolver and its modes](getting-started/credentials.md#the-resolver-and-its-modes) |
| `wazuh-manager-service-control`     | setuid-root (`4750`, `root:wazuh-manager`) helper that runs `restart` or `reload` of the manager service; `wm_control`'s only path to the service | [wazuh-manager-service-control](modules/control/README.md#wazuh-manager-service-control) |
| `wazuh-manager-keystore`            | Manage secrets in the encrypted keystore (AES-256, RocksDB)                                               | [Keystore](modules/keystore/README.md) |
| `verify-agent-conf`                 | Validate `agent.conf` syntax for shared group configurations                                              | [Centralized configuration](modules/agent-management/centralized-configuration.md) |
| `agent_groups`                      | Manage agent group assignments                                                                            | [Agent groups](modules/agent-management/agent-groups.md) |
| `agent_upgrade`                     | Request agent WPK upgrades (through the Task Manager)                                                     | [agent_upgrade](modules/agent_upgrade/README.md#agent_upgrade) |
| `cluster_control`                   | Query cluster nodes, agents and health                                                                    | [Inspecting the cluster](modules/cluster/README.md#inspecting-the-cluster-cluster_control) |
| `rbac_control`                      | Seed the RBAC database, change the API default users' passwords, or reset it (`seed`, `change-password`, `factory-reset`) | [Server API authentication](modules/server-api/authentication.md) |

#### wazuh-manager-control

```text
wazuh-manager-control [-j] {start|stop|restart|reload|check|status|enable|disable|info [-v -r -t]}
```

`-j` switches the output to one JSON document on standard output (diagnostics such as a daemon's own `-t`
output go to standard error) and is recognised only as the **first** argument. Every answer is that one document,
refusals and usage errors included (`{"error":1,"message":"Invalid action: <action>."}`, the `help` usage, a
missing or unknown `enable`/`disable` option), with the arguments it repeats escaped as JSON strings. The
daemons it manages are, in order, `wazuh-manager-clusterd`, `-modulesd`, `-remoted`, `-analysisd`,
`-db`, `-authd` and `-apid`; `start` launches them in the reverse order. Two are skipped by `start` and
`status` (`stop` stops whatever is running): `wazuh-manager-apid` unless `bin/wazuh-manager-conf --skip-file-checks get
cluster.node_type` is `master`, and `wazuh-manager-authd` when `auth.disabled` is `true` (both read without
checking the files the configuration names, so a missing certificate does not hide a running apid from `status`).

| Action | Behaviour |
| ------ | --------- |
| `start` | Runs the four pre-start checks below, empties `tmp/`, then starts each daemon that is not already running. `wazuh-manager-analysisd` counts as started once its API answers on `queue/sockets/engine-api-http.sock`; the script waits for its pid file for up to 10 seconds (`Failed to obtain PID for wazuh-manager-analysisd` when it never appears) and then probes the API up to 120 times — each probe gives the engine 5 seconds to answer, then the script waits a second — before giving up with `wazuh-manager-analysisd did not respond correctly after 120 attempts.` (an engine that exits meanwhile ends the wait at once with `wazuh-manager-analysisd died during the readiness check.`). A daemon that fails to start stops the sequence with `<daemon> did not start correctly.` and exit status `1`. |
| `stop` | Stops every daemon: `SIGTERM`, then up to 30 seconds for each before `SIGKILL` (`Process <daemon> couldn't be terminated. It will be killed.`). |
| `restart` | Runs the first three pre-start checks **while the manager is still running** (a refusal leaves it up), stops every daemon, resolves credentials, and starts them again. |
| `reload` | `restart` for every daemon except `wazuh-manager-remoted`, which keeps running, so agent connections stay up. Its checks still include `wazuh-manager-remoted -t`: remoted reads the configuration at its next restart, so a `remote` change it would refuse is refused now, while the manager is up. |
| `check` | Runs the first three pre-start checks and nothing else: no daemon is stopped or started, no lock is taken, and the `var/run/<daemon>.failed` verdicts of the last start are left alone. Exits `0` when a start would pass them (`Configuration and credentials checks passed.`, or `{"error":0,"data":[]}` with `-j`) and `1` otherwise, with the same message, `-j` error code (`20`, `21` or `22`) and log lines the start would print. Run it as `root`, like `start`: the credential check refuses any other user. Step 4 is not part of it — it opens the keystore, which must not happen while the manager is up — so what only step 4 refuses (an indexer password in neither the keystore nor any source, the resolver's lock held for over 60 seconds) passes the check and still refuses the start that follows. |
| `status` | Prints `<daemon> is running...` or `<daemon> not running...` per daemon (`refused its configuration...` or `failed to start...` when the last `start` left that verdict in `var/run/<daemon>.failed`), and exits `1` when any daemon is down. |
| `enable debug` / `disable debug` | Make every later start pass `-d` to the daemons (or stop doing so), recorded in `bin/.process_list`. `debug` is the only accepted option: a missing or other option prints the usage (one `{"error":1,…}` document with `-j`) and exits `1` before the start lock is taken; success prints nothing, or `{"error":0,"data":[]}` with `-j`. The exception is `wazuh-manager-analysisd`: only its `-t` gets `-d`, and it is started with no flags, so the engine's level is set by the internal option `analysisd.debug` ([Engine configuration](modules/engine/configuration.md)). |
| `info` | Prints `WAZUH_VERSION`, `WAZUH_REVISION` and `WAZUH_TYPE` (`manager`); `-v`, `-r` and `-t` print one of them alone. With `-j`, `{"error":0,"data":[…]}` holds the three, or the one asked for; an unknown flag is `{"error":1,…}`. |

Before `start`, `restart` and `reload` touch any daemon, four checks run, and the first one that fails
refuses the command:

1. `bin/wazuh-manager-conf validate --skip-file-checks`: the configuration file alone.
2. `bin/wazuh-manager-resolve-credentials --check`: every credential file and certificate, read-only.
3. `bin/wazuh-manager-conf validate`, now with the checks that the files the configuration names exist,
   then each daemon's own `-t`.
4. `bin/wazuh-manager-resolve-credentials --prestart`, which completes what it can and refuses what it
   cannot. On `restart` and `reload` it runs after the stop; it is skipped while
   `wazuh-manager-modulesd` is running.

Every refusal prints one line ending in `Exiting` (for example `wazuh-manager.conf: Configuration error.
Exiting` or `Unresolved credentials. Exiting`), records the reason in `logs/wazuh-manager.log` (except
when the engine's own `-t` refuses, which prints its reason on stderr only), and exits
`1`. The error codes (`20` for the configuration, `21` for an unresolved credential, `22` for an unsafe or
invalid one or a check that could not run, `1` for anything else — another invocation holding the lock, a
daemon that did not start) appear only in the `-j` output, as
`{"error":<code>,"message":"<reason>."}`. The messages, codes and log
lines of each step are in [When the manager does not start](getting-started/credentials.md#when-the-manager-does-not-start).
When `bin/wazuh-manager-resolve-credentials` is missing or not executable, steps 2 and 4 are skipped. A
configuration so broken that `cluster.node_type` cannot be read surfaces as `Invalid cluster
configuration, check the /etc/wazuh-manager/wazuh-manager.conf file.`

An unknown action prints the usage and exits `1`; with `-j` it prints only `{"error":1,"message":"Invalid action: <action>."}` (or `Missing action.`).
Anything after `start`, `stop`, `restart`, `reload`, `check` or `status` is ignored, not refused:
`wazuh-manager-control check extra` is `check`. The daemons inherit the command's standard output,
so redirect `start` to a file rather than piping it: a pipe never sees end-of-file and the command
appears to hang. On a systemd host the `wazuh-manager` unit drives the same script (`ExecStart`, `ExecStop`, `ExecReload`); its
`TimeoutStartSec=180` bounds `start` and also `reload` (systemd times `ExecReload` with the start timeout), which
covers the engine wait in both; `stop` is bounded by `TimeoutSec=45`.

**`wazuh-manager-control` always acts on the daemons itself**, whoever runs it: `start` launches every daemon
that is not running (and reports `already running` for the rest), even while the unit is `active`, and the
caller's environment and standard error reach the checks. Typed in a shell on a systemd host, it therefore starts
the daemons outside the unit — outside its control group, its sandbox (`ProtectSystem`, `PrivateTmp`, …) and its
accounting, and systemd does not know they exist.

The shell `wazuh-manager-control restart` and `systemctl restart wazuh-manager` are therefore **not
equivalent**. The script checks first and stops nothing when a check fails, but it relaunches the daemons outside
the unit. `systemctl restart` keeps them inside the unit, but its `ExecStop` stops every daemon before its
`ExecStart` runs any check, so a configuration the start refuses leaves the manager **down**. On a systemd host,
check first and then restart through the unit:

```bash
/var/wazuh-manager/bin/wazuh-manager-control check && systemctl restart wazuh-manager
```

The Server API's `PUT /cluster/restart` and `PUT /cluster/reload` do exactly that: `wazuh-manager-service-control`
runs `wazuh-manager-control check` before it calls `systemctl`, and a failed check leaves the manager running
([Control](modules/control/README.md#wazuh-manager-service-control)). Use the script directly to relaunch a single
daemon that died, or on hosts without systemd.

#### Daemons are not supervised

Nothing restarts a daemon that dies. The unit is `Type=forking` with `RemainAfterExit=yes` and no
`Restart=`, so it stays `active` after a crash; `wazuh-manager-control status` shows the daemon as `not
running...` (or `failed to start...`) and exits `1`, and `GET /cluster/{node_id}/status` reports it. Recover with
`wazuh-manager-control check && systemctl restart wazuh-manager` (a plain `systemctl restart` stops the manager
before any check, so a refused start leaves it down; see above), or relaunch only the dead daemon with `wazuh-manager-control start` (it
runs outside the unit then; see above). While one of
the core daemons the Server API depends on is down, the API keeps answering login, its status queries and the
restart endpoints, so the manager can still be inspected and restarted remotely; every other call answers
error `1017` (*Some Wazuh daemons are not ready yet*) until the daemon is back. The core daemons are
`wazuh-manager-modulesd`, `-remoted`, `-analysisd` and `-db`. The restart endpoints work with
`wazuh-manager-modulesd` down too: when its control socket is gone, the API runs `wazuh-manager-service-control`
itself ([Control](modules/control/README.md#manager-restart-and-reload)); only `wazuh-manager-apid` has to be
running.

### Data Flow

1. **Agent Registration** — A 5.x agent POSTs its registration request to **Remoted**'s HTTPS route `POST /enroll` (port 1517, the same connection and TLS configuration it uses for everything afterward), which bridges it to **Auth** over Auth's local socket (`queue/sockets/auth.sock`). A 4.x agent instead connects directly to **Auth** over TLS on port 1515, which remains available via `<auth><legacy_enrollment>`; a client may also register via **API** → **Auth**. Auth owns all enrollment logic in every case: it generates and returns an agent key, then persists the agent record in **Wazuh DB** (`queue/sockets/wdb.sock`).
2. **Event Processing** — Agent sends stateless events (logs, SCA, etc.) to **Remoted**'s authenticated HTTPS route `POST /stateless` (port 1517, authenticated with the agent's `wazuh-agent+jwt` bearer token, the transport a 5.x agent uses). 4.x agents send events over the classic AES-encrypted TCP/UDP channel (port 1514), which remains available via `<remote><legacy>`. The two paths differ in what Remoted does with the batch: on the HTTPS route it verifies the signature, cross-checks the batch's `wazuh.agent.id` against the authenticated agent, and forwards the body **verbatim** — the agent supplies its own metadata in the batch's `H` line, so there is nothing to enrich; on the legacy channel it decrypts the message and enriches it from its in-memory agent-metadata cache, which is what the keep-alives on that channel are for. Either way the batch reaches the **Engine** via HTTP POST (`engine-ingest-http.sock`). The Engine routes events through policies and pushes resulting events to the **Wazuh Indexer** via Indexer Connector. The Engine also pulls content (policies, decoders, integrations, KVDBs) from the Indexer via its internal **cmsync** module, and its IOC databases via **iocsync**.
3. **Inventory & Vulnerability Scan** — Agent POSTs a whole synchronization session (one FlatBuffers `FullSession`) to **Remoted**'s authenticated HTTPS route `POST /stateful`, and Remoted relays it over UDS (`queue/sockets/inventory-sync-http.sock`) to **Inventory Sync Server** in modulesd. The server validates the session, applies it to the **Indexer** (via Indexer Connector) and answers; the HTTP response relayed back to the agent IS the session result. Vulnerability-detection sessions run through a dedicated scan lane that executes the **Vulnerability Scanner** synchronously BEFORE indexing, so a `200` guarantees both the scan and the ingest. The scanner queries CVE feeds from the Indexer (via Content Manager → Indexer Connector), matches against the agent's packages, and sends vulnerability events to the **Engine** (via `engine-ingest-http.sock`) and vulnerability state to the **Indexer** (via Indexer Connector). Feed-update scans and session scans coordinate through a per-agent registry, so they never race. An **on-demand** rescan is the one path that is not inline: remoted (or the API) posts to the scanner's own socket, and the scanner records a `vd_scan` manager task with **Task Manager** rather than scanning on the caller's thread, so the answer is an admission and the scan itself survives a restart. Task Manager later runs it against `POST /_internal/vd/scan` on **Inventory Sync Server**.
4. **Active Response** — The **Engine** produces events and sends them to the **Wazuh Indexer** (via Indexer Connector). The Indexer's internal processes evaluate these events against its own rules and generate active response findings, indexing them into `wazuh-active-responses*`. **Clusterd** polls this index periodically (`active_response_polling`, 30s by default) and dispatches an `active_response` task per agent to **Task Manager** (`queue/sockets/task-http.sock`), the same path used for `remote_upgrade`. There is deliberately **no filtering by status or by connected node**: stateless HTTPS means no node owns an agent, so the agent-to-worker assignment that such filtering relied on no longer exists. Tasks simply wait in the database until the agent polls for them. The bookmark that drives that polling is a **high-water mark of what was read**, not of what was delivered: it is written once per page and clears every document the page returned, whatever happened to each one, and the read itself is bounded at the present instant. That is what keeps one document from either skipping the rest of the stream (a future `@timestamp` used to move the cursor past every response created before it) or freezing it (a document discarded before dispatch used to leave the cursor on its page, re-read every cycle). The exception is a response whose referenced event is not visible in its own index yet: that one is still deliverable, so the page is held short of it and read again on the next cycle, for up to two minutes. Past that the reference is taken as broken, because holding for an event that never appears would stop delivery fleet-wide. A response that cannot be delivered is lost, and every path that loses one says so at `WARNING` or above: delivery guarantees are the Task Manager's job, not the cursor's. For an agent on v5.0.0+, the task is handed back in a `POST /control` response and forwarded to the agent's `execd` daemon, which executes the corresponding active response script. Active response has no delivery path for agents below v5.0.0 (removed with the legacy TCP/UDP protocol); a task targeting one is dropped. The document contract, the read, the cursor and the messages the poller logs are detailed in [Active Response → Manager-side ingestion](modules/active-response/architecture.md#manager-side-ingestion).
5. **Agent Upgrade** — Client sends an upgrade request via **API** → **Task Manager** (`queue/sockets/task-http.sock`, `POST /v1/agents/upgrade`, or `/v1/agents/upgrade-custom` for a WPK already staged on the node). Task Manager validates each agent, downloads the WPK from the **WPK repository** over HTTPS and checks its SHA-1 against the repository's own index — once per distinct package, not once per agent — then writes a `remote_upgrade` task per agent into its own database (`queue/tasks/tasks.db`) in a single transaction. That download is the only connection modulesd makes outside the deployment, and peer verification on it can never be turned off: the expected SHA-1 arrives over the same channel as the file, so an unverified channel would leave the integrity check confirming whatever a man in the middle supplied. Delivery then depends on the agent's version, and the manager never pushes to a 5.x agent:
    - **v5.0.0+** — the task is handed back in the response to the agent's next `POST /control` `notify`, and the agent **pulls** the WPK itself via `POST /download`.
    - **Below v5.0.0** — a polling thread in **Remoted** (gated on the legacy channel) walks the connected agents, asks Task Manager for each one's pending task, and pushes the WPK down its existing session using the legacy six-step WPK push. This path exists only so 4.x agents remain upgradable; it deliberately skips agents at v5.0.0 or above.

    Task delivery is fire-and-forget from the manager's perspective either way: the manager never learns what came of an upgrade. See [Agent upgrades](modules/task_manager/agent-upgrades.md) for the version gates and the WPK rules.
6. **API Query** — Client sends an HTTPS request to the **Server API**. The API connects directly to **Engine** (`queue/sockets/engine-api-http.sock`), **Wazuh DB** (`queue/sockets/wdb.sock` and `queue/sockets/wdb-http.sock`), **Remoted** (`queue/sockets/remote.sock` and `queue/sockets/remote-admin-http.sock`), **Auth** (`queue/sockets/auth.sock`), **Vulnerability Scanner** (`queue/sockets/vd-http.sock`), or **Task Manager** (`queue/sockets/task-http.sock`) depending on the endpoint. Agent restart and reload are the Task Manager cases: the API creates one `agent_restart` or `agent_reload` task per agent, in bulk requests of up to 500, and answers as soon as they are recorded — the agent picks the task up on its next `POST /control`. The **DAPI** layer transparently routes requests across cluster nodes.
7. **Manager Restart/Reload** — Client sends a restart or reload request via **API** → **wm_control** module (`queue/sockets/control.sock`), which runs `bin/wazuh-manager-service-control restart|reload` (the API runs the helper itself when `control.sock` is gone). When systemd is PID 1 the helper runs `bin/wazuh-manager-control check` and then, only if it passes, `systemctl restart|reload wazuh-manager.service`; otherwise it runs `bin/wazuh-manager-control restart|reload`, which checks before it stops anything. Any other command is answered `Err` and logged as `Unknown command: '<command>'`, escaped (`\n`, `\r`, `\t`, `\\`, `\xHH` for other control or non-ASCII bytes) and cut to 128 bytes with `...[truncated]`. See [Control](modules/control/README.md#manager-restart-and-reload).
8. **Cluster Sync** — **Clusterd** synchronizes agent registration and shared configuration between master and worker nodes using Fernet-encrypted connections. It reads/writes agent state via **Wazuh DB** (`queue/sockets/wdb-http.sock`) and connects to the **Wazuh Indexer** (via Python opensearchpy) for active response dispatch, agent sync, and metrics — reading the Indexer credentials from the **Keystore Server** (`queue/sockets/keystore.sock`) first, since they are never held in the cluster configuration. Its Indexer-dependent jobs are supervised: availability is re-checked every 300s and the jobs are cancelled and restarted with exponential backoff (capped at 3600s) whenever the Indexer becomes unreachable; an unusable Indexer configuration is reported once and re-checked every 300s instead, and any wait ends early when `wazuh-manager.conf` changes. The API forwards cluster queries to Clusterd (`queue/sockets/cluster-internal.sock`).
9. **Agent Monitoring** — **Remoted** refreshes each agent's keep-alive in **Wazuh DB** (`queue/sockets/wdb.sock`). Marking silent agents disconnected, deleting long-disconnected ones and rotating the manager's logs are recurring **Task Manager** jobs inside **Modulesd**. These are the only Task Manager work that still reaches **Wazuh DB**, and it does so through modulesd's host callbacks rather than for its own storage — the agent queries live there, the task rows do not — see [Recurring manager tasks](modules/task_manager/schedules.md).
10. **Agent Deletion** — Client sends a delete request via **API** → **Auth** (`queue/sockets/auth.sock`). Auth removes the agent from **Wazuh DB** (`queue/sockets/wdb.sock`), journals the deletion, and records an `agent_delete_indexer` manager task with **Task Manager** (`queue/sockets/task-http.sock`) — a durable intent, keyed by a deterministic id so a retry of the same journal line collapses onto the same row rather than deleting twice. Task Manager then executes it against **Inventory Sync Server**'s delete endpoint (`queue/sockets/inventory-sync-http.sock`) to remove every document of that agent from the **Indexer** — its state documents (`wazuh-states-*`) plus its reported configuration and statistics (`wazuh-agent-config`, `wazuh-agent-stats`). This task type never gives up: attempts and deferrals are unbounded and a 4xx requeues, because an agent whose documents outlive it is a data-retention problem rather than a transient one.

### Who uses the Task Manager

The Task Manager is the manager's only durable work queue, and it holds two kinds of work that behave differently. An **agent task** is stored and handed out — the manager records what the agent should do and never learns what came of it. A **manager task** is claimed, executed by the module itself and retired with an outcome, retrying on its own schedule until it reaches one.

It owns `queue/tasks/tasks.db` outright and is the only process that opens it. Nothing about task storage goes through Wazuh DB.

| Task type | Kind | Created by | Executed by |
| --------- | ---- | ---------- | ----------- |
| `active_response` | Agent | Clusterd, from the `wazuh-active-responses*` index (flow 4) | The agent, on its next `POST /control` |
| `remote_upgrade` | Agent | Task Manager's own upgrade routes (flow 5) | The agent pulls the WPK; Remoted's legacy poller pushes it for 4.x |
| `agent_restart`, `agent_reload` | Agent | Server API, in bulk per 500 agents | The agent, on its next `POST /control` |
| `agent_delete_indexer` | Manager | Auth, after journaling a deletion (flow 10) | `POST /_internal/agents/delete` on Inventory Sync Server |
| `vd_scan` | Manager | Vulnerability Scanner, on an on-demand rescan (flow 3) | `POST /_internal/vd/scan` on Inventory Sync Server |
| `agent_disconnect_sweep`, `agent_delete_old`, `log_rotate_daily` | Manager | The module's own schedules (flow 9) | In-process, against Wazuh DB and the filesystem |

Two properties are worth knowing at this level, because they are what the rest of the manager relies on:

- **Task IDs are deterministic**, derived by SHA-256 from the request's own identity. The same logical request produced twice — retried by its creator, or raised independently on two cluster nodes — collapses onto one row instead of doing the work twice. This is what lets Auth keep a deletion journal and replay it freely.
- **Creation is answered at admission**, not at completion. A `200` means the work is recorded durably, not that it has happened. A producer that needs the outcome asks for the row later.

See [Task Manager](modules/task_manager/README.md) for the HTTP surface and [Manager tasks](modules/task_manager/manager-tasks.md) for the retry, deferral and ownership rules.

### IPC (Unix Domain Sockets)

All inter-process communication uses Unix domain sockets, and every one of them lives in `queue/sockets/`. The subsystem directories `queue/db/`, `queue/tasks/` and `queue/cluster/` hold only their data: databases, backups, the active-response bookmark and the per-worker directories.

Naming rules, which apply to any socket added later:

- Every socket file ends in `.sock`.
- The name states what the socket does or which component owns it, in kebab-case. A socket that speaks HTTP carries `-http` before the extension, so the wire protocol is readable from the name and a new HTTP socket is distinguishable from the framed one it replaces.
- When a component owns more than one socket of the same protocol, a qualifier names the plane: `api` for a control or query interface, `ingest` for a data-path intake, `admin` for an operator-facing endpoint.
- Every socket lives in `queue/sockets/`, endpoints kept apart from data. Bind, then `chmod` to 0660: `bind()` applies the umask.

Below, `HTTP` is HTTP/1.1 over the socket, reachable with `curl --unix-socket`. `Framed` is the legacy protocol: a 4-byte little-endian length header followed by a text or JSON payload. `Raw` is the bare payload with no length header.

| Socket                                   | Owner                 | Protocol | Purpose                                                            |
| ---------------------------------------- | --------------------- | -------- | ------------------------------------------------------------------ |
| `queue/sockets/auth.sock`                | wazuh-manager-authd   | Framed   | Local agent registration and deletion                              |
| `queue/sockets/remote.sock`              | wazuh-manager-remoted | Framed   | Stats and runtime configuration queries                            |
| `queue/sockets/remote-admin-http.sock`   | wazuh-manager-remoted | HTTP     | Operator-facing admin and metrics endpoint                         |
| `queue/sockets/engine-api-http.sock`     | wazuh-manager-analysisd | HTTP     | Engine API: content (`_internal/content/*`, `content/validate/*`), IOC (`content/ioc/*`), router, tester and `logtest`, GeoIP databases, metrics, `status`, event dumper, raw event indexer status; see [Engine API reference](modules/engine/api-reference.md) |
| `queue/sockets/engine-ingest-http.sock`  | wazuh-manager-analysisd | HTTP     | Event ingestion                                                    |
| `queue/sockets/inventory-sync-http.sock` | modulesd (Inventory Sync Server) | HTTP     | Stateful sync (`POST /stateful`), agent-reported stats and config (`POST /stats`, `POST /config`), the two manager-task routes the Task Manager drives (`POST /_internal/agents/delete`, `POST /_internal/vd/scan`), `GET /metrics` and the `GET /` liveness probe; see [Inventory Sync Server API reference](modules/inventory-sync-server/api-reference.md) |
| `queue/sockets/vd-http.sock`             | modulesd (Vulnerability Scanner) | HTTP     | On-demand scans and feed operations, called by remoted and the API |
| `queue/sockets/keystore.sock`            | modulesd (Keystore Server) | Framed   | Indexer credential retrieval, called by clusterd (the framework's `KeystoreClient`, from its Indexer tasks) |
| `queue/sockets/control.sock`             | modulesd (Control)    | Raw      | Daemon restart and reload: one unframed command per connection, a NUL-terminated reply, then the manager closes it ([Control](modules/control/README.md)) |
| `queue/sockets/wmodules.sock`            | wazuh-manager-modulesd | Framed   | Active configuration (`getconfig wmodules`, `getconfig internal_options`, `getallconfig`), read by the Server API for the `wmodules` component of `GET /cluster/{node_id}/configuration/{component}/{configuration}`. Its generic `query <module>` verb has no taker on the manager: no manager module implements it |
| `queue/sockets/wdb.sock`                 | wazuh-manager-db      | Framed   | Legacy wdb query protocol                                          |
| `queue/sockets/wdb-http.sock`            | wazuh-manager-db      | HTTP     | Agent sync and summary REST API, used by clusterd and the API; also `GET /v1/status`, the daemon's readiness answer |
| `queue/sockets/task-http.sock`           | modulesd (Task Manager) | HTTP     | Agent and manager task creation, lookup, pending-task delivery, and agent upgrade requests |
| `queue/sockets/cluster-internal.sock`    | wazuh-manager-clusterd | Cluster  | Cluster and DAPI queries                                           |

Keeping every endpoint in one directory means `ls queue/sockets/` is the complete IPC surface of the manager, and it keeps cleanup code from having to special-case a live socket sitting among the files it deletes.
