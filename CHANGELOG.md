## [v5.1.0]

### Manager

#### Added

| Issue | Comment |
|-------|---------|

#### Changed

| Issue | Comment |
|-------|---------|
| [#35897](https://github.com/wazuh/wazuh/issues/35897) | Unified the Content Manager across the manager: the Engine's ruleset and IoC sync and the Vulnerability Scanner's feed now share one library that validates the CTI consumer inside the download snapshot; the `content_manager` modulesd module is removed |

#### Removed

| Issue | Comment |
|-------|---------|

#### Fixed

| Issue | Comment |
|-------|---------|

### Agent

#### Added

| Issue | Comment |
|-------|---------|

#### Changed

| Issue | Comment |
|-------|---------|
| [#39304](https://github.com/wazuh/wazuh/issues/39304) | Unified byte-to-hex conversion into a single shared implementation. |
| [#39306](https://github.com/wazuh/wazuh/issues/39306) | Replaced the duplicated `expandAbsolutePath` helper with `FileSystemUtils`. |
| [#39307](https://github.com/wazuh/wazuh/issues/39307) | Removed duplicated join code in the agent data provider. |
| [#38171](https://github.com/wazuh/wazuh/issues/38171) | Compiled syscollector normalizer and data_provider parser regex once instead of on every call. |
| [#37532](https://github.com/wazuh/wazuh/issues/37532) | Moved every container runtime security setting into a single `container_security` configuration block. |
| [#37532](https://github.com/wazuh/wazuh/issues/37532) | Stopped scanning container monitored directories on the host filesystem as well. |
| [#37532](https://github.com/wazuh/wazuh/issues/37532) | Made container file monitoring and container inventory opt-in and independently switchable. |
| [#37396](https://github.com/wazuh/wazuh/issues/37396) | Stopped resolving process working directories for container file events, which never used them. |
| [#37396](https://github.com/wazuh/wazuh/issues/37396) | Stopped delivering file events from outside any container to container file monitoring. |

#### Removed

| Issue | Comment |
|-------|---------|
| [#38857](https://github.com/wazuh/wazuh/issues/38857) | Removed manager-probing dead code from the agent's execd. |
| [#37532](https://github.com/wazuh/wazuh/issues/37532) | Removed the container options from the syscollector module configuration. |
| [#37532](https://github.com/wazuh/wazuh/issues/37532) | Removed the container directory tag that scoped file monitoring to containers. |

#### Fixed

| Issue | Comment |
|-------|---------|
| [#39179](https://github.com/wazuh/wazuh/issues/39179) | Reported a network interface type on macOS for tunnel and virtual interfaces (gif, stf, utun, VLAN, bridge, cellular) instead of leaving them blank. |
| [#39169](https://github.com/wazuh/wazuh/issues/39169) | Reported per-process CPU time (`utime`, `stime`) and process state on macOS instead of leaving them empty or `unknown`. |
| [#39182](https://github.com/wazuh/wazuh/issues/39182) | Reported launchd `ProgramArguments`, `WatchPaths` and `QueueDirectories` on macOS as one array element per plist entry instead of a single space-joined string. |
| [#39866](https://github.com/wazuh/wazuh/issues/39866) | Removed trivial compiler warnings from the agent build. |
| [#40012](https://github.com/wazuh/wazuh/issues/40012) | Reported the CPU name on arm64 and POWER Linux agents, whose `/proc/cpuinfo` has no `model name`, instead of leaving it empty. |
| [#37396](https://github.com/wazuh/wazuh/issues/37396) | Corrected the user and group reported by the container file monitoring engine, which were interchanged. |

## Prior versions

- [v5.0.1](https://github.com/wazuh/wazuh/blob/v5.0.1/CHANGELOG.md)
- [v5.0.0](https://github.com/wazuh/wazuh/blob/v5.0.0/CHANGELOG.md)
