---
name: 'Planned: Support new OSs'
about: Add support for a new OS
title: Support new OSs - OS name & version
labels: level/epic, type/enhancement
assignees: ''

---

# Description 

This issue aims to add support for Support name & version.

| Agent support | Agent tier | Central components support | OS type |
|-|-|-|-|
|Yes/No | # | Yes/No| Major/Minor/New family |

# Plan

- **DevOps**
If the new OS's version is a major/new family, we need to add support for it in the allocator.
If the new OS's version is a minor, we need to update the allocator images for it.
If the new OS's version relates to the base OS used in the AMI, OVA, or Docker images, we need to update it.
If we need to add support for the central components, we need to review/test the installation assistant using the new OS.
- **Agent**
Add support for the new OS to the GitHub Actions package builder.
Smoke test that the package works, including installation, upgrade, and its related tier functionality.
Modify the evidence issue template to include the new OS.
- **CppServer** 
If we need to add support for the central components, add support for the new OS to the GitHub Actions package builder.
If we need to add support for the central components, smoke test that the package works, including installation and upgrade.
**Indexer**
If we need to add support for the central components, add support for the new OS to the GitHub Actions package builder.
If we need to add support for the central components, smoke test that the package works, including installation and upgrade.
- **Dashboard**
If we need to add support for the central components, add support for the new OS to the GitHub Actions package builder.
If we need to add support for the central components, smoke test that the package works, including installation and upgrade.
If we need to add support for the agent, we need to test functionality for all stateful modules according to the OS's tier.
If we need to add support for the agent, we need to make sure that the agent-related information in the agent list is correct.
If we need to add support for the agent, we need to test the deployment one-liner for the new OS.
- **ThreatIntel**
If we need to add support for the agent, we need to make sure that basic OS ruleset and SCA policies are available for the new OS.
- **QA**
If the new OS's version is a major/new family, we need to add new tests according to the OS's tier.
If the new OS's version is a major/new family,  we need to add proper documentation.
