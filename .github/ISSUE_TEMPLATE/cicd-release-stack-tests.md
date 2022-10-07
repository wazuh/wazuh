---
name: Release Candidate - Indexer/Dashboard packages
about: Report the results after running Jenkins tests for the specified release.
title: 'Release [WAZUH VERSION] - Release candidate [RC NUMBER] - Indexer/Dashboard packages'
labels: 'team/cicd, type/release tracking'
assignees: ''

---

### Packages tests metrics information
|||
| --- | --- |
| **Main release candidate issue** | --- |
| **Main packages metrics issue** | --- |
| **Version** | 4.X.X |
| **Release candidate** | RCX |
| **Tag** | https://github.com/wazuh/wazuh/tree/v4.X.X-rcX |

---

## Checks

System | Install | Upgrade | Remove | Purge | Service | Systemd | Working (Curl) | Dashboard/Indexer VERSION file
:-- | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: |
CentOS 7       | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
CentOS 8       | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
RedHat 7       | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
RedHat 8       | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
RedHat 9       | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
Amazon Linux 2 | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
Ubuntu 16.04   | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
Ubuntu 18.04   | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
Ubuntu 20.04   | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
Ubuntu 22.04   | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |

- [ ] Include traces of each test in plain text

Status legend:
⚫ - Pending/In progress
⚪ - Skipped
🔴 - Rejected
🟢 - Approved

---

## Auditors validation

In order to close and proceed with release or the next candidate version, the following auditors must give the green light to this RC.

- [ ] @alberpilot
- [ ] @okynos
