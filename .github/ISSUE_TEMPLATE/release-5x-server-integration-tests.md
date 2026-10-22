---
name: Release - 5.x - Server integration tests
about: Report the results after running server integration tests for a release stage.
title: 'Release {{VERSION}} - {{STAGE}} - Server integration tests'
labels: 'level/task, type/test'
assignees: ''
---

The following issue aims to run all `server integration tests` for the current release candidate, report the results, and open new issues for any encountered errors.

## Server integration tests information
|  |  |
|--|--|
| **Main release stage issue** | {{STAGE_ISSUE}} |
| **Version** | {{VERSION}} |
| **Stage** | {{STAGE}} |
| **Tag** | [{{TAG}}](https://github.com/wazuh/wazuh/tree/{{TAG}}) |
| **Wazuh QA: Tag** | [{{TAG}}](https://github.com/wazuh/qa-integration-framework/tree/{{TAG}}) |
| **Previous server integration tests issue** | {{PREVIOUS_ISSUE}} |

## Workflows
```yaml
workflows:
  - name: "Engine integration tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_engine.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "Inventory sync server integration tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_inventory-sync-server.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "Task manager integration tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_taskmanager.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "Vulnerability scanner integration tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_vulnerability-scanner.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "Manager integration tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testintegration_manager.yml"
    ref: "{{TAG}}"
    inputs:
      modules: "authd-tier-0-1,remoted-tier-0-1,remoted-tier-2,wazuh_db,manager_control"
      base_branch: "{{TAG}}"
```

## Test report procedure
All workflow results must have one of the following statuses:

|Color| Details |
|:--:|:--|
| :green_circle: | The **pipeline** has been executed successfully |
| :red_circle: | The **pipeline** has failed or it has errors |

## Conclusion
List every new or known issue that appeared while testing this task, with its link, before closing this issue.

| Status | Test | Failure type | New or known issues (with link) | Notes |
|---|---|---|---|---|
|  | Engine - Integration tests |  |  |  |
|  | Inventory Sync - Integration Tests |  |  |  |
|  | Vulnerability Scanner - Integration tests |  |  |  |
|  | Task Manager - Integration tests |  |  |  |
|  | Authd - Integration tests |  |  |  |
|  | Remoted - Integration tests |  |  |  |
|  | WazuhDB - Integration tests |  |  |  |
|  | Manager control - Integration tests |  |  |  |

## Auditors' validation
- [ ] @wazuh/devel-xdrsiem-server-div1
- [ ] @wazuh/devel-xdrsiem-qa-release
