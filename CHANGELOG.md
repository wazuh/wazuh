## [v5.0.1]

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
| [#40574](https://github.com/wazuh/wazuh/issues/40574) | Fixed the engine API so that concurrent requests that replace or delete the tester session of the same space (`POST /content/validate/policy` with `load_in_tester`, `DELETE /logtest`) no longer fail with "environment already exists" or "Namespace does not exist" and no longer leave orphan `logtest_*` namespaces. |

### Agent

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

## Prior versions

- [v5.0.0](https://github.com/wazuh/wazuh/blob/v5.0.0/CHANGELOG.md)
