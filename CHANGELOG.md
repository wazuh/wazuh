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
| [#38171](https://github.com/wazuh/wazuh/issues/38171) | Compiled syscollector normalizer and data_provider parser regex once instead of on every call. |
| [#37532](https://github.com/wazuh/wazuh/issues/37532) | Moved every container runtime security setting into a single `container_security` configuration block. |
| [#37532](https://github.com/wazuh/wazuh/issues/37532) | Stopped scanning container monitored directories on the host filesystem as well. |
| [#37532](https://github.com/wazuh/wazuh/issues/37532) | Made container file monitoring and container inventory opt-in and independently switchable. |
| [#37396](https://github.com/wazuh/wazuh/issues/37396) | Stopped resolving process working directories for container file events, which never used them. |
| [#37396](https://github.com/wazuh/wazuh/issues/37396) | Stopped delivering file events from outside any container to container file monitoring. |
| [#37532](https://github.com/wazuh/wazuh/issues/37532) | Detected new containers as soon as the container runtime reports them instead of waiting for the next scheduled check. |
| [#37532](https://github.com/wazuh/wazuh/issues/37532) | Refreshed container inventory when a container appears or is removed rather than only on its scan interval. |

#### Removed

| Issue | Comment |
|-------|---------|
| [#37532](https://github.com/wazuh/wazuh/issues/37532) | Removed the container options from the syscollector module configuration. |
| [#37532](https://github.com/wazuh/wazuh/issues/37532) | Removed the container directory tag that scoped file monitoring to containers. |

#### Fixed

| Issue | Comment |
|-------|---------|
| [#37396](https://github.com/wazuh/wazuh/issues/37396) | Corrected the user and group reported by the container file monitoring engine, which were interchanged. |
| [#37532](https://github.com/wazuh/wazuh/issues/37532) | Started monitoring containers that were created moments apart on an otherwise idle host, which were previously never detected. |
| [#37532](https://github.com/wazuh/wazuh/issues/37532) | Kept the file and inventory data of a stopped container instead of discarding it as if the container had been deleted. |

## Prior versions

- [v5.0.1](https://github.com/wazuh/wazuh/blob/v5.0.1/CHANGELOG.md)
- [v5.0.0](https://github.com/wazuh/wazuh/blob/v5.0.0/CHANGELOG.md)
