## [v5.0.0]

### Manager

#### Added

- Added cluster-by-default deployment model: all Wazuh Server installations now run as a cluster node, removing the distinction between clustered and non-clustered deployments. The `cluster.disabled` configuration option has been removed. ([#31295](https://github.com/wazuh/wazuh/issues/31295))
- Added stateless metadata enrichment in `remoted`, centralizing event metadata handling for stateless messages and removing the dependency on `wazuh-db` for that ingestion path. ([#33269](https://github.com/wazuh/wazuh/issues/33269))
- Added Engine enrichment support: IOC matching, GeoIP lookup, and event filters. ([#33493](https://github.com/wazuh/wazuh/issues/33493))
- Added Engine adaptation tier 2: raw archives handling, uncategorized event routing, input-level throttling, and internal metrics exposure. ([#34477](https://github.com/wazuh/wazuh/issues/34477))
- Added CVSS v4.0 support to the Vulnerability Scanner. ([#35623](https://github.com/wazuh/wazuh/issues/35623))
- Added Engine metrics collection, normalization, and indexing pipeline. ([#35771](https://github.com/wazuh/wazuh/issues/35771))
- Added new CVE 5.0 schema fields to the Vulnerability Detector content model. ([#36000](https://github.com/wazuh/wazuh/issues/36000))
- Added manager watermarks. ([#35579](https://github.com/wazuh/wazuh/issues/35579))
- Added byte-based capacity limits to wazuh-manager-remoted. ([#37052](https://github.com/wazuh/wazuh/issues/37052))
- Added default API role mappings for the indexer users wazuh-admin, wazuh-readonly and wazuh-demo. ([#37706](https://github.com/wazuh/wazuh/issues/37706))

#### Changed

- Upgraded embedded Python interpreter from 3.10 to 3.12. ([#33377](https://github.com/wazuh/wazuh/issues/33377)) ([#33570](https://github.com/wazuh/wazuh/issues/33570))
- Adapted Vulnerability Detector input pipeline to the new Wazuh 5.0 synchronization algorithm, covering first-scan, inventory-change, and feed-update scenarios. ([#30535](https://github.com/wazuh/wazuh/issues/30535))
- Removed legacy configuration surfaces, database schemas, build targets, and compatibility layers in the second server cleanup phase. ([#34608](https://github.com/wazuh/wazuh/issues/34608))
- Reduced `wazuh-manager` Debian package dependencies, removed `adduser`, `lsb-release`, `debconf`, and `libc6`. ([#35881](https://github.com/wazuh/wazuh/issues/35881))
- Upgraded external dependencies: `curl`, `sqlite`, `xz`, and `libarchive`. ([#29734](https://github.com/wazuh/wazuh/issues/29734))
- Implemented cooperative-cancellation graceful termination for `wmodules`. ([#34479](https://github.com/wazuh/wazuh/issues/34479))
- Included source IP in `wazuh-remoted` log messages. ([#35358](https://github.com/wazuh/wazuh/pull/35358))
- Preserved manager configuration files during package upgrades. ([#35478](https://github.com/wazuh/wazuh/issues/35478))
- Improved Wazuh server directory layout. ([#35479](https://github.com/wazuh/wazuh/issues/35479))
- Updated manager index names to align with the new sync model. ([#35525](https://github.com/wazuh/wazuh/issues/35525))
- Added caller module context to indexer-connector logs. ([#35905](https://github.com/wazuh/wazuh/issues/35905))
- Randomized the cluster key generated during manager installation instead of using a hardcoded default. ([#36805](https://github.com/wazuh/wazuh/issues/36805))
- Changed the default Indexer user used by the Manager from `admin` to the restricted `wazuh-server` user, aligning with the Indexer RBAC least-privilege model. ([#36311](https://github.com/wazuh/wazuh/issues/36311))
- Enabled shared-password agent enrollment by default, persisting the auto-generated `authd.pass` and synchronizing it to worker nodes, with fail-closed password validation. ([#36705](https://github.com/wazuh/wazuh/issues/36705))
- Adapted API integration tests. ([#32698](https://github.com/wazuh/wazuh/issues/32698))

#### Removed

- Removed Filebeat as the log-shipping component; event forwarding now uses native Wazuh server connectivity to the Wazuh Indexer via `indexer-connector`. ([#33124](https://github.com/wazuh/wazuh/pull/33124))
- Removed deprecated manager daemons: `ossec-authd`, `wazuh-agentlessd`, `wazuh-maild`, `wazuh-dbd`. ([#30922](https://github.com/wazuh/wazuh/issues/30922))
- Removed deprecated C CLI tools: `manage_agents`, `agent-auth`. ([#30924](https://github.com/wazuh/wazuh/issues/30924))
- Removed OpenSCAP server-side module. ([#31028](https://github.com/wazuh/wazuh/issues/31028))
- Removed inventory-related API endpoints. ([#31299](https://github.com/wazuh/wazuh/issues/31299))
- Removed legacy API security configuration endpoints. ([#28425](https://github.com/wazuh/wazuh/issues/28425))
- Removed SELinux integration from the manager. ([#35908](https://github.com/wazuh/wazuh/issues/35908))

#### Fixed

- Fixed Vulnerability Detector version matcher logic for improved detection accuracy. ([#31746](https://github.com/wazuh/wazuh/issues/31746))
- Fixed Cloudtrail log ingestion parsing errors. ([#33108](https://github.com/wazuh/wazuh/issues/33108))
- Fixed `wazuh-db` error assigning groups by avoiding the keyentries counter as index. ([#34082](https://github.com/wazuh/wazuh/issues/34082))
- Fixed token validation race condition after revoke. ([#35043](https://github.com/wazuh/wazuh/issues/35043))
- Handled the stop signal during vulnerability feed download. ([#35638](https://github.com/wazuh/wazuh/issues/35638))
- Fixed `GET /cluster/{node_id}/daemons/stats` always returning error 1014 for `wazuh-manager-analysisd` due to a protocol mismatch between `WazuhSocketJSON` and the engine's HTTP API socket. ([#37521](https://github.com/wazuh/wazuh/issues/37521))

### Agent

#### Added

- Added local state persistence for agent modules (FIM, System Inventory, SCA), removing the dependency on `rsync` with the Wazuh Server and reducing network traffic and server-side processing overhead. ([#29533](https://github.com/wazuh/wazuh/issues/29533)) ([#31838](https://github.com/wazuh/wazuh/issues/31838))

#### Changed

- Changed the Wazuh Manager installation path to `/var/wazuh-manager` (replacing `/var/ossec`) and removed agent ID `000`, fully decoupling agent and manager processes on shared hosts. ([#33378](https://github.com/wazuh/wazuh/issues/33378))
- Changed Vulnerability Detection to use the Wazuh Indexer as the sole authoritative CVE data source, removing direct CTI network access from the agent-side Vulnerability Detector. ([#34849](https://github.com/wazuh/wazuh/issues/34849))
- Adjusted agent-side Vulnerability Detector inventory emission and synchronization (OS, packages, hotfixes) to align with the updated VD behavior in Wazuh 5.0. ([#33199](https://github.com/wazuh/wazuh/issues/33199))
- Simplified rootcheck: removed the server-side database, sync path, and API surface; findings are now indexed through the standard alert pipeline. ([#31478](https://github.com/wazuh/wazuh/issues/31478))
- Updated logcollector file-tailing initial read strategy for more consistent behavior across log rotation scenarios. ([#33382](https://github.com/wazuh/wazuh/issues/33382))
- Updated Windows Event Channel log collection to emit native XML from `EvtRender()` without an XML declaration header. ([#34462](https://github.com/wazuh/wazuh/issues/34462))
- Increased default limits for agent event throughput and inventory message sizes. ([#35330](https://github.com/wazuh/wazuh/issues/35330))
- Reduced `wazuh-agent` Debian package dependencies, removed `adduser`, `lsb-release`, and `debconf`. ([#35880](https://github.com/wazuh/wazuh/issues/35880))
- Standardized agent-start and buffer-status events to a WCS-aligned JSON format. ([#35471](https://github.com/wazuh/wazuh/issues/35471))

#### Removed

- Removed deprecated agent binaries and legacy modules as part of the Wazuh 5.0 agent cleanup. ([#30435](https://github.com/wazuh/wazuh/issues/30435))
- Removed NSIS-based Windows agent installer; Windows agent now ships exclusively as an MSI package. ([#31582](https://github.com/wazuh/wazuh/issues/31582))

#### Fixed

- Fixed FIM checksum calculation that was incorrectly ignoring some file fields. ([#29668](https://github.com/wazuh/wazuh/issues/29668))
- Fixed syscollector reporting duplicate and bogus packages on macOS arm64. ([#30513](https://github.com/wazuh/wazuh/issues/30513))
- Fixed `agent_control` not displaying agent status information. ([#32915](https://github.com/wazuh/wazuh/issues/32915))
- Fixed SCA handling of invalid operators and missing values in regex patterns. ([#35071](https://github.com/wazuh/wazuh/issues/35071))
- Fixed agent modules initializing before agent metadata was fully ready. ([#35156](https://github.com/wazuh/wazuh/issues/35156))
- Fixed FIM inventory reporting file modification time as 1970-01-01. ([#35162](https://github.com/wazuh/wazuh/issues/35162))
- Fixed agent automatic reload failing after receiving centralized configuration. ([#35169](https://github.com/wazuh/wazuh/issues/35169))
- Fixed syscollector false positive package detection on macOS. ([#35248](https://github.com/wazuh/wazuh/issues/35248))
- Fixed agent uninstall on Windows after a WPK upgrade. ([#35329](https://github.com/wazuh/wazuh/issues/35329))
- Fixed agent 5.x sending a trailing null byte in messages. ([#35474](https://github.com/wazuh/wazuh/issues/35474))
- Fixed WUA hotfix collection regression in Windows agent v5.0.0. ([#35636](https://github.com/wazuh/wazuh/issues/35636))
- Fixed wodle command argument construction for Windows paths. ([#35955](https://github.com/wazuh/wazuh/issues/35955))
- Prevented Windows agent restart abort when the service is already stopping. ([#35960](https://github.com/wazuh/wazuh/issues/35960))
- Fixed timeout message displayed after a 4.13-to-5.0 upgrade on Windows. ([#35978](https://github.com/wazuh/wazuh/issues/35978))
- Fixed agent disconnection on direct 4.13-to-5.0 custom WPK upgrade. ([#35979](https://github.com/wazuh/wazuh/issues/35979))
- Excluded `/bin` and `/sbin` from FIM monitored directories on usrmerge distributions. ([#35988](https://github.com/wazuh/wazuh/issues/35988))
- Expanded Windows environment variables in SCA rule inputs. ([#36002](https://github.com/wazuh/wazuh/issues/36002))
- Made `sync_end_delay` interruptible to remove stale `modulesd.pid` after agent stop. ([#36061](https://github.com/wazuh/wazuh/issues/36061))
- Honored the shutdown signal in `agent-upgrade` `StartMQ` to avoid timeout warning on agent stop. ([#36092](https://github.com/wazuh/wazuh/issues/36092))
- Adjusted DockerListener messages as log entries to fix event categorization. ([#36126](https://github.com/wazuh/wazuh/issues/36126))
- Dropped orphan paths before promoting on agent startup to fix FIM. ([#36134](https://github.com/wazuh/wazuh/issues/36134))
- Lowered the `wazuh-agentd` connection socket error log to debug level to avoid duplicating the "Lost connection with manager" error on transient disconnections. ([#37653](https://github.com/wazuh/wazuh/issues/37653))
- Fixed a race condition when saving the Logcollector file status on shutdown. ([#37626](https://github.com/wazuh/wazuh/issues/37626))
- Fixed an unbounded memory leak in `wazuh-modulesd` caused by a missing RPM macro context cleanup on every package scan cycle. ([#37656](https://github.com/wazuh/wazuh/issues/37656))
- Fixed agent-info module caching cluster_name, cluster_node, and agent_groups from a one-time handshake at startup, causing stale values in `agent_metadata` until the agent process restarted. ([#37543](https://github.com/wazuh/wazuh/issues/37543))
- Fixed `wazuh-syscheckd` failing the `file_entry.checksum` NOT NULL constraint when the deferred sync-flag update ran for an entry deleted during the scan. ([#37993](https://github.com/wazuh/wazuh/issues/37993))

