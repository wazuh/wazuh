## [v5.0.0]

### Manager

#### Added

| Issue | Comment |
|-------|---------|
| [#38260](https://github.com/wazuh/wazuh/issues/38260) | Added HTTPS communication between Wazuh agents and the manager: a new HTTPS transport, protocol, and control plane (connection, configuration, statistics, task dispatch, remote upgrade, and event ingestion) replacing the legacy MQ/DGRAM-based agent-manager protocol end to end. |
| [#31295](https://github.com/wazuh/wazuh/issues/31295) | Added cluster-by-default deployment model: all Wazuh Server installations now run as a cluster node, removing the distinction between clustered and non-clustered deployments. The `cluster.disabled` configuration option has been removed. |
| [#33269](https://github.com/wazuh/wazuh/issues/33269) | Added stateless metadata enrichment in `remoted`, centralizing event metadata handling for stateless messages and removing the dependency on `wazuh-db` for that ingestion path. |
| [#33493](https://github.com/wazuh/wazuh/issues/33493) | Added Engine enrichment support: IOC matching, GeoIP lookup, and event filters. |
| [#34477](https://github.com/wazuh/wazuh/issues/34477) | Added Engine adaptation tier 2: raw archives handling, uncategorized event routing, input-level throttling, and internal metrics exposure. |
| [#35623](https://github.com/wazuh/wazuh/issues/35623) | Added CVSS v4.0 support to the Vulnerability Scanner. |
| [#35771](https://github.com/wazuh/wazuh/issues/35771) | Added Engine metrics collection, normalization, and indexing pipeline. |
| [#36000](https://github.com/wazuh/wazuh/issues/36000) | Added new CVE 5.0 schema fields to the Vulnerability Detector content model. |
| [#35579](https://github.com/wazuh/wazuh/issues/35579) | Added manager watermarks. |
| [#37052](https://github.com/wazuh/wazuh/issues/37052) | Added byte-based capacity limits to wazuh-manager-remoted. |
| [#37706](https://github.com/wazuh/wazuh/issues/37706) | Added default API role mappings for the indexer users wazuh-admin, wazuh-readonly and wazuh-demo. |
| [#38023](https://github.com/wazuh/wazuh/issues/38023) | Added the `POST /config` HTTPS endpoint, which receives an agent's reported configuration and indexes it into `wazuh-agent-config`. |
| [#38024](https://github.com/wazuh/wazuh/issues/38024) | Added the `POST /stats` HTTPS endpoint, which persists the statistics an agent reports as one document per agent in the `wazuh-agent-stats` index, replacing the previous report on every push. |
| [#38007](https://github.com/wazuh/wazuh/issues/38007) | Added legacy `remote_upgrade` task delivery in `remoted`: a polling thread pushes pending Task Manager tasks to connected agents older than v5.0.0 over their existing session using the legacy six-step WPK push, gated on `remoted`'s HTTPS `verification_mode`. |
| [#38157](https://github.com/wazuh/wazuh/issues/38157) | Added installation-time variables to customize the default `<remote>` configuration on source, DEB, and RPM manager installations. |
| [#38553](https://github.com/wazuh/wazuh/issues/38553) | Added the `PUT /agents/scan/vulnerability` endpoint to trigger an on-demand vulnerability scan for one agent, a list of agents, or all agents. |
| [#38589](https://github.com/wazuh/wazuh/issues/38589) | Added recurring manager tasks to the Task Manager: the agent disconnection sweep, the deletion of long-disconnected agents, and manager log rotation now run as durable, retried tasks inside `wazuh-manager-modulesd`. Their resolved settings are reported by `GET /manager/configuration/wmodules/wmodules`. |

#### Changed

| Issue | Comment |
|-------|---------|
| [#38816](https://github.com/wazuh/wazuh/issues/38816) | Replaced the manager's pseudo-XML configuration parser with a schema-validated strict-XML loader (`shared_modules/manager_config`): every consumer — the C daemons, the engine, the control script, the Python framework and the API — reads the same effective document; any daemon's `-t` and the new `bin/wazuh-manager-conf validate\|get\|dump` CLI validate the whole file (including the installed schema copy `etc/wazuh-manager.schema.json`) with JSON-pointer diagnostics (error 1244); `GET /cluster/{node_id}/configuration` serves the canonical schema shape with native types, and `cluster.key` becomes mandatory. Constructs the old parser tolerated (multiple roots, raw `&`, legacy comments, unknown options) are now rejected at startup — see the migration guide. |
| [#33377](https://github.com/wazuh/wazuh/issues/33377) [#33570](https://github.com/wazuh/wazuh/issues/33570) | Upgraded embedded Python interpreter from 3.10 to 3.12. |
| [#30535](https://github.com/wazuh/wazuh/issues/30535) | Adapted Vulnerability Detector input pipeline to the new Wazuh 5.0 synchronization algorithm, covering first-scan, inventory-change, and feed-update scenarios. |
| [#34608](https://github.com/wazuh/wazuh/issues/34608) | Removed legacy configuration surfaces, database schemas, build targets, and compatibility layers in the second server cleanup phase. |
| [#35881](https://github.com/wazuh/wazuh/issues/35881) | Reduced `wazuh-manager` Debian package dependencies, removed `adduser`, `lsb-release`, `debconf`, and `libc6`. |
| [#29734](https://github.com/wazuh/wazuh/issues/29734) | Upgraded external dependencies: `curl`, `sqlite`, `xz`, and `libarchive`. |
| [#34479](https://github.com/wazuh/wazuh/issues/34479) | Implemented cooperative-cancellation graceful termination for `wmodules`. |
| [#35358](https://github.com/wazuh/wazuh/pull/35358) | Included source IP in `wazuh-manager-remoted` log messages. |
| [#35478](https://github.com/wazuh/wazuh/issues/35478) | Preserved manager configuration files during package upgrades. |
| [#35479](https://github.com/wazuh/wazuh/issues/35479) | Improved Wazuh server directory layout. |
| [#35525](https://github.com/wazuh/wazuh/issues/35525) | Updated manager index names to align with the new sync model. |
| [#35905](https://github.com/wazuh/wazuh/issues/35905) | Added caller module context to indexer-connector logs. |
| [#36805](https://github.com/wazuh/wazuh/issues/36805) | Randomized the cluster key generated during manager installation instead of using a hardcoded default. |
| [#36311](https://github.com/wazuh/wazuh/issues/36311) | Changed the default Indexer user used by the Manager from `admin` to the restricted `wazuh-server` user, aligning with the Indexer RBAC least-privilege model. |
| [#36705](https://github.com/wazuh/wazuh/issues/36705) | Enabled shared-password agent enrollment by default, persisting the auto-generated `authd.pass` and synchronizing it to worker nodes, with fail-closed password validation. |
| [#38091](https://github.com/wazuh/wazuh/issues/38091) | Raised the minimum TLS protocol version accepted by `wazuh-manager-authd` (agent enrollment) to TLS 1.3, removed the `ssl_auto_negotiate` fallback and its `-a` CLI flag, and changed `<auth><ciphers>` to a TLS 1.3 ciphersuite list. |
| [#32698](https://github.com/wazuh/wazuh/issues/32698) | Adapted API integration tests. |
| [#36453](https://github.com/wazuh/wazuh/issues/36453) | Increased the minimum API user password length from 8 to 12 characters to align with PCI DSS. |
| [#38589](https://github.com/wazuh/wazuh/issues/38589) | Renamed the manager's log rotation and agent monitoring internal options from `monitord.*` to `wazuh_modules.manager_task_*`. An override left under an old name is silently ignored. Agents keep `monitord.*` for their own log rotation. |
| [#38436](https://github.com/wazuh/wazuh/issues/38436) | Standardized the manager's Unix socket names and layout: every socket ends in `.sock`, carries an `-http` marker when it speaks HTTP, and lives in `queue/sockets/`. The sockets that were under `queue/db/`, `queue/tasks/` and `queue/cluster/` moved there, leaving those directories holding only their data. An upgraded installation keeps the old socket files as dead entries until a clean install. |

#### Removed

| Issue | Comment |
|-------|---------|
| [#33124](https://github.com/wazuh/wazuh/pull/33124) | Removed Filebeat as the log-shipping component; event forwarding now uses native Wazuh server connectivity to the Wazuh Indexer via `indexer-connector`. |
| [#30922](https://github.com/wazuh/wazuh/issues/30922) | Removed deprecated manager daemons: `ossec-authd`, `wazuh-agentlessd`, `wazuh-maild`, `wazuh-dbd`. |
| [#30924](https://github.com/wazuh/wazuh/issues/30924) | Removed deprecated C CLI tools: `manage_agents`, `agent-auth`. |
| [#31028](https://github.com/wazuh/wazuh/issues/31028) | Removed OpenSCAP server-side module. |
| [#31299](https://github.com/wazuh/wazuh/issues/31299) | Removed inventory-related API endpoints. |
| [#28425](https://github.com/wazuh/wazuh/issues/28425) | Removed legacy API security configuration endpoints. |
| [#35908](https://github.com/wazuh/wazuh/issues/35908) | Removed SELinux integration from the manager. |
| [#38024](https://github.com/wazuh/wazuh/issues/38024) | Removed the `GET /agents/{agent_id}/stats/{component}` API endpoint. Agent statistics are read from the `wazuh-agent-stats` index. |
| [#38589](https://github.com/wazuh/wazuh/issues/38589) | Removed the `wazuh-manager-monitord` daemon, along with the `monitor` component of the active configuration endpoints, which its socket served. |
| [#38589](https://github.com/wazuh/wazuh/issues/38589) | Removed the `<global><agents_disconnection_alert_time>` option. A configuration that still includes it fails to start. |

#### Fixed

| Issue | Comment |
|-------|---------|
| [#31746](https://github.com/wazuh/wazuh/issues/31746) | Fixed Vulnerability Detector version matcher logic for improved detection accuracy. |
| [#33108](https://github.com/wazuh/wazuh/issues/33108) | Fixed Cloudtrail log ingestion parsing errors. |
| [#34082](https://github.com/wazuh/wazuh/issues/34082) | Fixed `wazuh-manager-db` error assigning groups by avoiding the keyentries counter as index. |
| [#35043](https://github.com/wazuh/wazuh/issues/35043) | Fixed token validation race condition after revoke. |
| [#35638](https://github.com/wazuh/wazuh/issues/35638) | Handled the stop signal during vulnerability feed download. |
| [#37521](https://github.com/wazuh/wazuh/issues/37521) | Fixed `GET /cluster/{node_id}/daemons/stats` always returning error 1014 for `wazuh-manager-analysisd` due to a protocol mismatch between `WazuhSocketJSON` and the engine's HTTP API socket. |
| [#35909](https://github.com/wazuh/wazuh/issues/35909) | Fixed `make deps` branch detection in GitHub Actions.
| [#38511](https://github.com/wazuh/wazuh/issues/38511) | Fixed world-writable permissions on bundled Python files after DEB installation, caused by the permission restoration script following symlinks. |
| [#38589](https://github.com/wazuh/wazuh/issues/38589) | Fixed the agent disconnection sweep running on cluster workers, and fixed manager log files never rotating daily on a manager that was restarted every day. |
| [#38547](https://github.com/wazuh/wazuh/issues/38547) | Fixed the API serving its OpenAPI specification and exact version at `/openapi.json` and `/openapi.yaml` without authentication. |
| [#38565](https://github.com/wazuh/wazuh/issues/38565) | Bounded the `search` query parameter to 1024 characters across every endpoint that accepts it, fixed the API's `wazuh-db` socket client raising an unhandled error instead of a clean `500` when `wazuh-db` closes the connection on an oversized request, and stopped the API from returning `wazuh-db`'s raw backend error text (including SQL fragments) to the caller. |
| [#38592](https://github.com/wazuh/wazuh/issues/38592) | Fixed the legacy `remote_upgrade` task delivery in `remoted` silently losing an agent's upgrade task when the push failed after the Task Manager had already marked it delivered, and fixed the agent's own reported upgrade failures being logged at `INFO`, where severity-filtered monitoring never saw them, instead of `WARNING`. `remoted` now owns a task's delivery retries end to end once it has read it: a rejection (the agent answered, just not with success) is retried up to 5 times in-memory within the same poll cycle (logging each failed attempt at `debug` except the last, which logs a `warning`), while a true no-response is deferred to a small in-memory retry list a later poll cycle picks back up, instead of blocking that cycle's sweep of every other agent. A task that exhausts every retry avenue is simply logged and dropped, never reported back to the Task Manager. |
| [#38626](https://github.com/wazuh/wazuh/issues/38626) | Fixed `POST /agents/insert` accepting an `id` outside the signed 32-bit range the manager stores it in, and `authd`'s auto-assigned id counter wrapping to a negative id once it reached `INT_MAX`, both of which produced an agent record that could not be queried or deleted. A caller-supplied `id` is now rejected when it is out of range or equal to `0`, and the id counter refuses to wrap, failing the enrollment instead. |
| [#38695](https://github.com/wazuh/wazuh/issues/38695) | Fixed `wazuh-manager-apid` and `wazuh-manager-clusterd` killing their own freshly started process during an unclean-stop recovery, when the kernel reused a PID recorded in a stale `.pid` file for the new instance. `clean_pid_files()` now only terminates a process whose creation time predates the stale file, and never the caller's own PID. Also fixed `delete_child_pids()` matching a child's pidfile by PID substring, which let a child with PID 16 remove the pidfile of PID 161. |
| [#38749](https://github.com/wazuh/wazuh/issues/38749) | Fixed `install.sh` silently repointing the host's `wazuh-manager`/`wazuh-agent` service to the directory being installed: an install into an alternative `USER_DIR` (a sandbox tree, or a package build root) now leaves an existing service definition that names a different directory untouched and warns, unless `USER_TAKEOVER_SERVICE="y"` is set. `USER_REGISTER_SERVICE="n"` skips the boot integration altogether. |
| [#38810](https://github.com/wazuh/wazuh/pull/38810) | Fixed `POST /security/user/authenticate/run_as` returning a token with the service account's static administrator role when the authorization context was empty. An empty context is now resolved against the authorization rules like any other context instead of falling back to those static roles, so it yields a token with no roles under the default ruleset; a user without `allow_run_as` posting an empty context now gets the documented 403/6004 instead of a token; the API access log no longer raises on a body that is not an object, which turned the validator's 400 for a `null`, numeric or boolean body into an unhandled 500 on every endpoint; and the API specification now declares the `text/plain` response this endpoint returns with `raw=true`. |

### Agent

#### Added

| Issue | Comment |
|-------|---------|
| [#29533](https://github.com/wazuh/wazuh/issues/29533) [#31838](https://github.com/wazuh/wazuh/issues/31838) | Added local state persistence for agent modules (FIM, System Inventory, SCA), removing the dependency on `rsync` with the Wazuh Server and reducing network traffic and server-side processing overhead. |
| [#37828](https://github.com/wazuh/wazuh/issues/37828) [#37830](https://github.com/wazuh/wazuh/issues/37830) [#37832](https://github.com/wazuh/wazuh/issues/37832) [#37833](https://github.com/wazuh/wazuh/issues/37833) [#37834](https://github.com/wazuh/wazuh/issues/37834) [#37835](https://github.com/wazuh/wazuh/issues/37835) [#37836](https://github.com/wazuh/wazuh/issues/37836) | Added an agent HTTPS client covering the `/control` lifecycle, the `/stateless` and `/stateful` data planes, `/download` for centralized configuration and WPK packages, task dispatch with durable deduplication, and remote upgrade, with AES-CMAC request signing and fail-closed TLS validation. |
| [#37843](https://github.com/wazuh/wazuh/issues/37843) | Added periodic `/stats` and `/config` push, reporting every module's statistics and configuration in a single aggregated document per endpoint, behind two `ossec.conf` toggles that are off by default. |

#### Changed

| Issue | Comment |
|-------|---------|
| [#37831](https://github.com/wazuh/wazuh/issues/37831) | Changed the agent transport to HTTPS for all server communication, removing the legacy TCP data path and its internal-option fallback. |
| [#38465](https://github.com/wazuh/wazuh/issues/38465) | Changed agent enrollment to consume the manager's HTTPS `POST /enroll` endpoint instead of the legacy `A:`/`K:` protocol over TCP/1515, reusing the same `<agent><ssl>`/`<agent><server>` transport as the rest of the agent's HTTPS traffic. |
| [#38624](https://github.com/wazuh/wazuh/issues/38624) | Changed the `WAZUH_MANAGER_ENDPOINT` installation variable to carry the whole connection target — `host[:port][/prefix]`, with only the address mandatory — which the DEB/RPM, source and MSI installers write verbatim into the agent's single `<endpoint>` setting. It supersedes `WAZUH_MANAGER` and `WAZUH_MANAGER_PORT` when set, and those keep working unchanged when it is not. A trailing slash (`host/`) opts out of the reverse-proxy prefix. Replaces the variable's previous prefix-only meaning. |
| [#33378](https://github.com/wazuh/wazuh/issues/33378) | Changed the Wazuh Manager installation path to `/var/wazuh-manager` (replacing `/var/ossec`) and removed agent ID `000`, fully decoupling agent and manager processes on shared hosts. |
| [#34849](https://github.com/wazuh/wazuh/issues/34849) | Changed Vulnerability Detection to use the Wazuh Indexer as the sole authoritative CVE data source, removing direct CTI network access from the agent-side Vulnerability Detector. |
| [#33199](https://github.com/wazuh/wazuh/issues/33199) | Adjusted agent-side Vulnerability Detector inventory emission and synchronization (OS, packages, hotfixes) to align with the updated VD behavior in Wazuh 5.0. |
| [#31478](https://github.com/wazuh/wazuh/issues/31478) | Simplified rootcheck: removed the server-side database, sync path, and API surface; findings are now indexed through the standard alert pipeline. |
| [#38589](https://github.com/wazuh/wazuh/issues/38589) | Changed the shared log-rotation helper so a rotation whose target directory cannot be created is reported and skipped instead of terminating the daemon. This also applies to the agent's own log rotation, which previously exited on that error and was restarted by the service manager. |
| [#33382](https://github.com/wazuh/wazuh/issues/33382) | Updated logcollector file-tailing initial read strategy for more consistent behavior across log rotation scenarios. |
| [#34462](https://github.com/wazuh/wazuh/issues/34462) | Updated Windows Event Channel log collection to emit native XML from `EvtRender()` without an XML declaration header. |
| [#35330](https://github.com/wazuh/wazuh/issues/35330) | Increased default limits for agent event throughput and inventory message sizes. |
| [#35880](https://github.com/wazuh/wazuh/issues/35880) | Reduced `wazuh-agent` Debian package dependencies, removed `adduser`, `lsb-release`, and `debconf`. |
| [#35471](https://github.com/wazuh/wazuh/issues/35471) | Standardized agent-start and buffer-status events to a WCS-aligned JSON format. |

#### Removed

| Issue | Comment |
|-------|---------|
| [#30435](https://github.com/wazuh/wazuh/issues/30435) | Removed deprecated agent binaries and legacy modules as part of the Wazuh 5.0 agent cleanup. |
| [#31582](https://github.com/wazuh/wazuh/issues/31582) | Removed NSIS-based Windows agent installer; Windows agent now ships exclusively as an MSI package. |
| [#38091](https://github.com/wazuh/wazuh/issues/38091) | Removed the `<enrollment><auto_method>` option; enrollment now always requires TLS 1.3, so there is nothing left for it to negotiate down to. The `ssl_cipher` option now expects a TLS 1.3 ciphersuite list instead of an OpenSSL cipher-list string. |
| [#38465](https://github.com/wazuh/wazuh/issues/38465) | Removed the `<enrollment>` `manager_address`, `port`, `interface_index`, `ssl_cipher`, `server_certificate_path`, `agent_certificate_path`, and `agent_key_path` options; enrollment now always targets the same manager and TLS configuration as the rest of the agent's HTTPS traffic. A 4.x `ossec.conf` carrying them still parses without error after an in-place upgrade. |

#### Fixed

| Issue | Comment |
|-------|---------|
| [#29668](https://github.com/wazuh/wazuh/issues/29668) | Fixed FIM checksum calculation that was incorrectly ignoring some file fields. |
| [#30513](https://github.com/wazuh/wazuh/issues/30513) | Fixed syscollector reporting duplicate and bogus packages on macOS arm64. |
| [#32915](https://github.com/wazuh/wazuh/issues/32915) | Fixed `agent_control` not displaying agent status information. |
| [#35071](https://github.com/wazuh/wazuh/issues/35071) | Fixed SCA handling of invalid operators and missing values in regex patterns. |
| [#35156](https://github.com/wazuh/wazuh/issues/35156) | Fixed agent modules initializing before agent metadata was fully ready. |
| [#35162](https://github.com/wazuh/wazuh/issues/35162) | Fixed FIM inventory reporting file modification time as 1970-01-01. |
| [#35169](https://github.com/wazuh/wazuh/issues/35169) | Fixed agent automatic reload failing after receiving centralized configuration. |
| [#35248](https://github.com/wazuh/wazuh/issues/35248) | Fixed syscollector false positive package detection on macOS. |
| [#35329](https://github.com/wazuh/wazuh/issues/35329) | Fixed agent uninstall on Windows after a WPK upgrade. |
| [#35474](https://github.com/wazuh/wazuh/issues/35474) | Fixed agent 5.x sending a trailing null byte in messages. |
| [#35636](https://github.com/wazuh/wazuh/issues/35636) | Fixed WUA hotfix collection regression in Windows agent v5.0.0. |
| [#35955](https://github.com/wazuh/wazuh/issues/35955) | Fixed wodle command argument construction for Windows paths. |
| [#35960](https://github.com/wazuh/wazuh/issues/35960) | Prevented Windows agent restart abort when the service is already stopping. |
| [#35978](https://github.com/wazuh/wazuh/issues/35978) | Fixed timeout message displayed after a 4.13-to-5.0 upgrade on Windows. |
| [#35979](https://github.com/wazuh/wazuh/issues/35979) | Fixed agent disconnection on direct 4.13-to-5.0 custom WPK upgrade. |
| [#35988](https://github.com/wazuh/wazuh/issues/35988) | Excluded `/bin` and `/sbin` from FIM monitored directories on usrmerge distributions. |
| [#36002](https://github.com/wazuh/wazuh/issues/36002) | Expanded Windows environment variables in SCA rule inputs. |
| [#36061](https://github.com/wazuh/wazuh/issues/36061) | Made `sync_end_delay` interruptible to remove stale `modulesd.pid` after agent stop. |
| [#36092](https://github.com/wazuh/wazuh/issues/36092) | Honored the shutdown signal in `agent-upgrade` `StartMQ` to avoid timeout warning on agent stop. |
| [#36126](https://github.com/wazuh/wazuh/issues/36126) | Adjusted DockerListener messages as log entries to fix event categorization. |
| [#36134](https://github.com/wazuh/wazuh/issues/36134) | Dropped orphan paths before promoting on agent startup to fix FIM. |
| [#37653](https://github.com/wazuh/wazuh/issues/37653) | Lowered the `wazuh-agentd` connection socket error log to debug level to avoid duplicating the "Lost connection with manager" error on transient disconnections. |
| [#37626](https://github.com/wazuh/wazuh/issues/37626) | Fixed a race condition when saving the Logcollector file status on shutdown. |
| [#37656](https://github.com/wazuh/wazuh/issues/37656) | Fixed an unbounded memory leak in `wazuh-modulesd` caused by a missing RPM macro context cleanup on every package scan cycle. |
| [#37543](https://github.com/wazuh/wazuh/issues/37543) | Fixed agent-info module caching cluster_name, cluster_node, and agent_groups from a one-time handshake at startup, causing stale values in `agent_metadata` until the agent process restarted. |
| [#37993](https://github.com/wazuh/wazuh/issues/37993) | Fixed `wazuh-syscheckd` failing the `file_entry.checksum` NOT NULL constraint when the deferred sync-flag update ran for an entry deleted during the scan. |
| [#37993](https://github.com/wazuh/wazuh/issues/37993) | Fixed `wazuh-syscheckd` failure on shutdown, which logged "Invalid handle value", crashed the process and left a stale PID file. |
| [#38163](https://github.com/wazuh/wazuh/issues/38163) | Fixed `wazuh-agentd` crashing on start when the agent metadata segment could only be opened read-only, which happens whenever a root process creates it before the daemon drops privileges. |
| [#38065](https://github.com/wazuh/wazuh/issues/38065) | Fixed SCA and Syscollector sync threads not blocking `SIGTERM`, which could cause the shutdown handler to run on a module thread instead of the main thread and time out joining it. |
| [#38212](https://github.com/wazuh/wazuh/issues/38212) | Fixed the Windows agent leaving the FIM synchronization database open when the service stopped, which left the `queue\` directory behind after an uninstall without purge. |
| [#38646](https://github.com/wazuh/wazuh/pull/38646) | Fixed SCA HIPAA compliance mappings across policy checks. |
| [#38736](https://github.com/wazuh/wazuh/pull/38736) | Fixed two CIS Amazon Linux 2023 SCA checks (`gpgcheck`, `vsftpd`) reporting false-positives on compliant systems. |
| [#38600](https://github.com/wazuh/wazuh/issues/38600) | Removed the default `netstat` and `last` command monitoring entries, which depend on binaries not present on every supported platform (e.g. minimal container images), causing repeated failed executions every `frequency` cycle. |
| [#38766](https://github.com/wazuh/wazuh/issues/38766) | Fixed `wazuh-agentd` crashing with `SIGSEGV` on every service stop, which also cut the shutdown drain short before the `/control` shutdown notification was sent. |
| [#38850](https://github.com/wazuh/wazuh/issues/38850) | Fixed missing `<manager>` block on Debian 10 unattended DEB installs. |
