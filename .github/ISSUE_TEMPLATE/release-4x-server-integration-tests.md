---
name: Release - 4.x - Server integration tests
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
  - name: "Analysisd integration tests tier 0-1"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_analysisd-tier-0-1.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Analysisd integration tests tier 2"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_analysisd-tier-2.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Authd integration tests tier 0-1"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_authd-tier-0-1.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Integratord integration tests tier 0-1"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_integratord-tier-0-1.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Logtest integration tests tier 0-1"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_logtest-tier-0-1.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Remoted integration tests tier 0-1"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_remoted-tier-0-1.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Remoted integration tests tier 2"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_remoted-tier-2.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Wazuh DB integration tests tier 0-1"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_wazuh_db-tier-0-1.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Vulnerability scanner component tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testcomponent_vulnerability-scanner.yml"
    ref: "{{TAG}}"
    inputs: {}
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
|  | 4_testintegration_analysisd-tier-0-1 |  |  |  |
|  | 4_testintegration_analysisd-tier-2 |  |  |  |
|  | 4_testintegration_authd-tier-0-1 |  |  |  |
|  | 4_testintegration_integratord-tier-0-1 |  |  |  |
|  | 4_testintegration_logtest-tier-0-1 |  |  |  |
|  | 4_testintegration_remoted-tier-0-1 |  |  |  |
|  | 4_testintegration_remoted-tier-2 |  |  |  |
|  | 4_testintegration_wazuh_db-tier-0-1 |  |  |  |
|  | 4_testcomponent_vulnerability-scanner |  |  |  |

## Auditors' validation
- [ ] @wazuh/devel-xdrsiem-server
- [ ] @wazuh/devel-xdrsiem-qa-release
