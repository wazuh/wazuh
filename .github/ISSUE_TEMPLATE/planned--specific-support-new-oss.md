---
name: 'Planned: Specific support new OSs'
about: Test compatibility with new OS.
title: Support new OSs - <OS name & version> - <Specific test name>
labels: level/task, request/operational, type/maintenance
assignees: ''
---

# Description

| Related issue | Epic issue |
|---|---|
| Issue number | Issue number|

| Agent tier | Central components support | OS type | Architectures |
|-|-|-|-|
| 1/2/3 | Yes/No | New family/Major/Minor | AMD64/ARM64 |

# Plan

<!-- Uncomment for MANAGEMENT issue (for major/new family versions)
**Management**
- [ ] Decide if the new OS family or version will be supported for the Wazuh agent and/or Wazuh central components.
- [ ] Update the Google Sheets compatibility file if applicable.
-->

<!-- Uncomment for PRELIMINARY SUPPORT issue (when OS has public Beta available)
**Preliminary Support**

**Agent**
- [ ] Smoke test that the package works, including installation, upgrade.
- [ ] Check agent connectivity to the manager and basic log collection capabilities.
- [ ] Check that the agent correctly reports the OS name and version.

**ThreatIntel**
- [ ] Define a plan to support the new OS, particularly with regard to SCA policies. If there's no official CIS policy for that OS version, we either use an existing draft or adapt a previous version.
- [ ] **Note**: The PR will not be merged until we know the version where full support will be included.
-->

<!-- Uncomment for FULL SUPPORT issue (when OS is released)
**Full Support**

**Important**: All tests performed by all teams involved must use the same testing environment. The Agent team will request the environment from the DevOps team and share access to it with the rest of the teams. The full support release version will be defined by the new OS support in the allocator.
-->

<!-- Uncomment for DEVOPS minor issue
**DevOps (Minor version)**
- [ ] Update the allocator images.
- [ ] Update AMI, OVA, or Docker images if needed.
-->

<!-- Uncomment for DEVOPS full support issue
**DevOps (Full Support)**
- [ ] **Central components**: Manually allocate two different accessible machines with the new OS. This is the first step for everything else.
- [ ] **No central components**: Deploy an All In One (in our featured OS, probably Amazon Linux) and allocate an accessible machine with the new OS to test the agent. This is the first step for everything else.
- [ ] **Central components**: Review/test the installation assistant using the new OS.
- [ ] Update AMI, OVA, or Docker images if needed.
- [ ] Adapt Puppet.
- [ ] Adapt Ansible.
- [ ] Add support for it in the allocator.
- [ ] Announce in the internal thread the release version where we will support the OS in the allocator.
-->

<!-- Uncomment for AGENT full support issue
**Agent (Full Support)**
- [ ] Smoke test that the package works, including installation, upgrade, and its related tier functionality.
- [ ] Check the default settings of previous versions, and adapt them to the new OS version if necessary.
- [ ] Add support for the new OS to the GitHub Actions package builder.

Requested testing code:
:white_circle: Requested.
:black_circle: Not requested.

Result code:
:green_circle: Completed: Test finished with success.
:red_circle: Completed with failures.
:yellow_circle: Completed with known issues.

- **Requested checks by tier:**

|| Tier 1 | Tier 2 | Tier 3 | Result |
|-|-|-|-|-|
| **Log collection - System events** | :white_circle: | :white_circle: | :white_circle: | |
| **Log collection - Log files** | :white_circle: | :white_circle: | :white_circle: | |
| **Log collection -Command execution** | :white_circle: | :white_circle: | :white_circle: | |
| **FIM - Scheduled** | :white_circle: | :white_circle: | :white_circle: | |
| **FIM - Realtime** | :white_circle: | :black_circle: | :black_circle: | |
| **FIM - Whodata** | :white_circle: | :black_circle: | :black_circle: | |
| **SCA** | :white_circle: | :white_circle: | :black_circle: | |
| **Inventory** | :white_circle: | :white_circle: | :white_circle: | |
| **Active response** | :white_circle: | :white_circle: | :black_circle: | |
| **Remote upgrade** | :white_circle: | :black_circle: | :black_circle: | |
| **Command monitoring** | :white_circle: | :white_circle: | :black_circle: | |
| **Wodles** | :white_circle: | :black_circle: | :black_circle: | |
-->

<!-- Uncomment for CPPSERVER full support issue
**CppServer (Full Support)**
- [ ] **Central components**: Smoke test that the package works, including installation, upgrade, and its related functionality.
- [ ] **Central components**: Add support for the new OS to the GitHub Actions package builder.
- [ ] **Tier 1 agent**: Make sure that VD works properly according to the OS tier.
-->

<!-- Uncomment for INDEXER full support issue
**Indexer (Full Support)**
- [ ] **Central components**: Smoke test that the package works, including installation and upgrade.
- [ ] **Central components**: Add support for the new OS to the GitHub Actions package builder.
-->

<!-- Uncomment for DASHBOARD full support issue
**Dashboard (Full Support)**
- [ ] **Central components**: Smoke test that the package works, including installation and upgrade.
- [ ] **Central components**: Add support for the new OS to the GitHub Actions package builder.
-->

<!-- Uncomment for THREATINTEL full support issue
**ThreatIntel (Full Support)**
- [ ] Define a plan to support the new OS, particularly with regard to SCA policies. If there's no official CIS policy for that OS version, we either use an existing draft or adapt a previous version.
-->

<!-- Uncomment for QA full support issue
**QA (Full Support)**

## Considerations

- Testing environment: Deploy the new OS taking into account the following notes:
  - If the Wazuh central components are supported: 1 VM for each architecture supported.
  - If the Wazuh agent is supported: 1 VM for each architecture supported.
  - If the Wazuh central components or the Wazuh agent is not supported, deploy a Debian 12 VM for the non-supported component.
- All testing tasks must be completed for each OS architecture supported.
- The following tasks should be completed in order.

## Tasks

- [ ] Test the Wazuh dashboard one-liner deployment.
  - [ ] Deploy a Wazuh agent using the Wazuh dashboard one-liner feature provided in the Wazuh user interface with the following cases.
    - [ ] Only IP address.
    - [ ] Only FQDN.
    - [ ] IP address, agent name, and group.
- [ ] Add/Update/Check CI
  - [ ] Test the JobFlow testing tool for that specific system.
  - [ ] Add the OS and each architecture to the JobFlow testing tool.
  - [ ] Add the OS and each architecture to the GitHub Deployability and Upgrade release templates.
- [ ] Add the OS and its supported architectures to the E2E UX Tests spreadsheet (OS sheet).
-->

<!-- Uncomment for DISCLOSURE issue (when full support is finished)
**Disclosure**
- [ ] Create an [issue](https://github.com/wazuh/internal-documentation-requests/issues/new/choose) using the "Support new OSs request" template, requesting the content team to add support for the new OS version in the full support release version. **Note**: This request issue doesn't block any of the development team tasks.
-->
