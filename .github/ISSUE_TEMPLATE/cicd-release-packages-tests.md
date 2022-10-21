---
name: Release Candidate - Packages tests
about: Report the results after running Jenkins tests for the specified release.
title: 'Release [WAZUH VERSION] - Release candidate [RC NUMBER] - Packages tests'
labels: 'team/cicd, type/release tracking'
assignees: ''

---

### Packages tests information
|||
| -- | -- |
| **Main release candidate issue** | --- |
| **Version** | 4.X.X |
| **Release candidate** | RCX |
| **Tag** | https://github.com/wazuh/wazuh/tree/v4.X.X-rcX |
| **Previous packages metrics** | ---  |

---

| Status | Test | Issue |
| :--: | :--: | :--: | 
| ⚫ | Installation      | --- |
| ⚫ | Upgrade           | --- |
| ⚫ | SELinux           | --- |
| ⚫ | Register          | --- |
| ⚫ | Service           | --- |
| ⚫ | Specific systems  | --- |
| ⚫ | Indexer/Dashboard | --- |

Status legend:
⚫ - Pending/In progress
⚪ - Skipped
🔴 - Rejected
🟢 - Approved

## Auditors validation

In order to close and proceed with release or the next candidate version, the following auditors must give the green light to this RC.

- [ ] @alberpilot 
- [ ] @okynos 
