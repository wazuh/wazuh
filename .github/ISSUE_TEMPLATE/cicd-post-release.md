---
name: Release - Post release
about: Perform analysis and tests after the publish release procedure.
title: 'Release [WAZUH VERSION] - Post release'
labels: 'team/cicd, type/release tracking'
assignees: ''

---

The following issue aims to perform required post-release checks to ensure a well-published release procedure.

## Main information
|||
| :-- | :-- |
| **Version** | X.Y.Z |
| **Tag** | https://github.com/wazuh/wazuh/tree/vX.Y.Z |
| **Release issue** | --- |
| **Previous post release issue** | --- |



## Checks

### Release notes
- [ ] wazuh/wazuh release notes (tag)
- [ ] wazuh/wazuh-feed release notes (tag)
- [ ] wazuh/wazuh-packages release notes (tag)
- [ ] wazuh/wazuh-kibana-app release notes (tag)
- [ ] wazuh/wazuh-splunk release notes (tag)
- [ ] wazuh/wazuh-qa release notes (tag)
- [ ] wazuh/wazuh-ansible release notes (tag)
- [ ] wazuh/wazuh-docker release notes (tag)
- [ ] wazuh/wazuh-kubernetes release notes (tag)
- [ ] wazuh/wazuh-puppet release notes (tag)

### Repository
- [ ] Live installation test
- [ ] Live upgrade test
- [ ] WPK versions check
- [ ] WPK upgrade test
- [ ] Post-release check (files)
- [ ] AMI published
- [ ] Cache invalidated
- [ ] Build release containers
- [ ] Build and push Docker Hub images
- [ ] Build and release debug packages

### Documentation
- [ ] Documentation updated
- [ ] Documentation published
- [ ] Cache invalidated

Status legend:
⚫ - None
🔴 - Rejected
🟢 - Approved

## Validation

The following auditors must give the green light to this release.

- [ ] @alberpilot
- [ ] @okynos
