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

| Agent tier | Central components support | OS type |
|-|-|-|
| 1/2/3 | Yes/No | New family/Major/Minor |

# Plan

<!-- Uncomment for QA issue
**QA**
- [ ] **Major/New family**: Add new tests according to the OS's tier.
- [ ] **Major/New family**: Add proper documentation.
- [ ] **Agent**: Test functionality for all stateful modules according to the OS's tier.
-->

<!-- Uncomment for CPPSERVER issue
**CppServer**
- [ ] **Major/New family**: Make sure that VD works properly according to the OS tier.
- [ ] **Central components**: Add support for the new OS to the GitHub Actions package builder.
- [ ] **Central components**: Smoke test that the package works, including installation, upgrade, and its related functionality.
-->

<!-- Uncomment for INDEXER issue
**Indexer**
- [ ] **Central components**: Add support for the new OS to the GitHub Actions package builder.
- [ ] **Central components**: Smoke test that the package works, including installation and upgrade.
-->

<!-- Uncomment for DEVOPS issue
**DevOps**
- [ ] **Major/New family**: Manually allocate two different accessible machines with the new OS. This is the first step for everything else.
- [ ] **Minor**: Deploy an All In One (in our featured OS, probably Amazon Linux) and allocate an accessible machine with the new OS to test the agent. This is the first step for everything else.
- [ ] **Major/New family**: Add support in the allocator.
- [ ] **Major/New family**: Adapt Puppet.
- [ ] **Major/New family**: Adapt Ansible.
- [ ] **Minor**: Update the allocator images.
- [ ] **Central components**: Review/test the installation assistant using the new OS.
- [ ] Update AMI, OVA, or Docker images if needed.
-->

<!-- Uncomment for DASHBOARD issue
**Dashboard**
- [ ] **Central components**: Add support for the new OS to the GitHub Actions package builder.
- [ ] **Central components**: Smoke test that the package works, including installation and upgrade.
- [ ] **Agent**: Make sure that the agent-related information in the agent list is correct.
- [ ] **Agent**: Test the deployment one-liner for the new OS.
-->

<!-- Uncomment for THREATINTEL issue
**ThreatIntel**
- [ ] **Agent**: Make sure that basic OS ruleset and SCA policies are available for the new OS.
-->

<!-- Uncomment for AGENT issue
**Agent**
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