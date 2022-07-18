---
name: [Release Candidate] Footprint metrics 
about: Report the results after obtaining footprint metrics.
title: 'Release [WAZUH VERSION] - Release Candidate [RC VERSION] - Footprint metrics'
labels: 'cicd'
assignees: ''

---


### Footprint metrics information
|                                  |                                            |
|---------------------------------|--------------------------------------------|
| **Main release candidate issue** |  ----- |
| **Version** | X.Y.Z                                    |
| **Release candidate #** | RCX                                        |
| **Tag** | https://github.com/wazuh/wazuh/tree/vX.Y.Z-rcx                                       |
| **Previous footprint meetrics** | -- |

## Checks
Status | Result | Modules | X.Y.Z Issue (12h) | X.Y.Z Issue (2.5d)  |
|-- | -- | -- | -- | -- | 
| ⚫ | 🕐 | All | ----- | -- |   
| ⚫ | 🕐 | Vulnerability-detector | -----  | -- |  
| ⚫ | 🕐 | All | ----  |  ---- |
| ⚫ | 🕐 | Logcollector |   ----  |  ---- |
| ⚫ | 🕐 | Syscheck |  ----  |  ---- |
| ⚫ | 🕐 | Rootcheck | ----  |  ---- |
| ⚫ | 🕐 | SCA | ----  |  ---- |
| ⚫ | 🕐 | Active Response |  ----  |  ---- |
| ⚫ | 🕐 | Syscollector | ----  |  ---- |
| ⚫ | 🕐 | Docker,Ciscat,Osquery,Azure,Openscap | ---- |  ---- |
| ⚫ | 🕐 | All-except-Logcollector | ---- |  ---- |
| ⚫ | 🕐 | All-except-Syscheck | ---- |  ---- |
| ⚫ | 🕐 | All-except-Rootcheck | ---- |  ---- |
| ⚫ | 🕐 | All-except-SCA | ---- |  ---- |
| ⚫ | 🕐 | All-except-Active Response | ---- |  ---- |
| ⚫ | 🕐 | All-except-Syscollector |  ----  |  ---- |
| ⚫ | 🕐 | All-except-Docker,Ciscat,Osquery,Azure,Openscap | ---- |  ---- |
| ⚫ | 🕐 | Logcollector-Syscollector | ---- |  ---- |
| ⚫ | 🕐 | Logcollector-SCA |  ---- |  ---- |
| ⚫ | 🕐 | Logcollector-Syscheck | ---- |  ---- |
| ⚫ | 🕐 | macOS-All | ---- |  ---- |




Result legend:
⚫ - Not launched
🕐 - Pending/In progress
✔️ - Results Ready
⚠️ - Review required

Status legend:
⚫ - None
🔴 - Rejected
🟢 - Approved

## Auditors validation

In order to close and proceed with release or the next candidate version, the following auditors must give the green light to this RC.

- [ ] @santiago-bassett 
- [ ] @alberpilot 
- [ ] @okynos 
- [ ] @rauldpm 
