---
name: Release Candidate - Specific systems 
about: Report the results after running Jenkins tests for the specified release.
title: 'Release [WAZUH VERSION] - Release candidate [RC NUMBER] - Specific systems'
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

## Build packages

| System | Status | Build |
| :-- | :--: | -- |
| AIX       | ⚫ | --- |
| HPUX      | ⚫ | --- |
| S10 SPARC | ⚫ | --- |
| S11 SPARC | ⚫ | --- |
| OVA       | ⚫ | --- |
| AMI       | ⚫ | --- |

---

### Test packages

| System | Build | Install | Deployment install | Upgrade | Remove | TCP | UDP | Errors found | Warnings found | Alerts found | Check users |
| :-- | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: |
| AIX       | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| HPUX      | ⚫ | ⚫ | --- | --- |  ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| S10 SPARC | ⚫ | ⚫ | --- | ⚫ |  ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| S11 SPARC | ⚫ | ⚫ | --- | ⚫ |  ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| OVA       | ⚫ | ⚫ | --- | --- | --- | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| AMI       | ⚫ | ⚫ | --- | --- | --- | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |

---

##### PPC64EL packages #####

| System | Build | Install | Deployment install | Upgrade | Uninstall | Alerts | TCP | UDP | Errors | Warnings | System users |
| :-- | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: |
| Centos         | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| Debian Stretch | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |

---

##### OVA/AMI specific tests

| System | Filebeat test | Cluster green/yellow | Production repositories | UI Access | No SSH root access | SSH user access | Wazuh dashboard/APP version | Dashboard/Indexer VERSION file |
| :-- | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: |
| OVA | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |
| AMI | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ | ⚫ |


Status legend:
⚫ - Pending/In progress
⚪ - Skipped
🔴 - Rejected
🟢 - Approved
