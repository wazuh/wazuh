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

#### Removed

| Issue | Comment |
|-------|---------|
| [#37532](https://github.com/wazuh/wazuh/issues/37532) | Removed the container options from the syscollector module configuration. |
| [#37532](https://github.com/wazuh/wazuh/issues/37532) | Removed the container directory tag that scoped file monitoring to containers. |

#### Fixed

| Issue | Comment |
|-------|---------|

## Prior versions

- [v5.0.1](https://github.com/wazuh/wazuh/blob/v5.0.1/CHANGELOG.md)
- [v5.0.0](https://github.com/wazuh/wazuh/blob/v5.0.0/CHANGELOG.md)
