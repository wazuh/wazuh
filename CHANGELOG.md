## [v5.1.0]

### Manager

#### Added

| Issue | Comment |
|-------|---------|

#### Changed

| Issue | Comment |
|-------|---------|

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
| [#38171](https://github.com/wazuh/wazuh/issues/38171) | Compiled syscollector normalizer and data_provider parser regex once instead of on every call. |

#### Removed

| Issue | Comment |
|-------|---------|
| [#38857](https://github.com/wazuh/wazuh/issues/38857) | Removed manager-probing dead code from the agent's execd. |

#### Fixed

| Issue | Comment |
|-------|---------|
| [#39179](https://github.com/wazuh/wazuh/issues/39179) | Reported a network interface type on macOS for tunnel and virtual interfaces (gif, stf, utun, VLAN, bridge, cellular) instead of leaving them blank. |
| [#39169](https://github.com/wazuh/wazuh/issues/39169) | Reported per-process CPU time (`utime`, `stime`) and process state on macOS instead of leaving them empty or `unknown`. |
| [#39182](https://github.com/wazuh/wazuh/issues/39182) | Reported launchd `ProgramArguments`, `WatchPaths` and `QueueDirectories` on macOS as one array element per plist entry instead of a single space-joined string. |
| [#39866](https://github.com/wazuh/wazuh/issues/39866) | Removed trivial compiler warnings from the agent build. |
| [#40012](https://github.com/wazuh/wazuh/issues/40012) | Reported the CPU name on arm64 and POWER Linux agents, whose `/proc/cpuinfo` has no `model name`, instead of leaving it empty. |

## Prior versions

- [v5.0.1](https://github.com/wazuh/wazuh/blob/v5.0.1/CHANGELOG.md)
- [v5.0.0](https://github.com/wazuh/wazuh/blob/v5.0.0/CHANGELOG.md)
