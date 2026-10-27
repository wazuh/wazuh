---
name: Release - 4.x - Agent integration tests
about: Report the results after running the agent integration tests for a release stage.
title: 'Release {{VERSION}} - {{STAGE}} - Agent integration tests'
labels: 'level/task, type/test'
assignees: ''
---

The tests will be performed on GitHub workflows. Linux, Windows, and macOS will be used as required.

## Agent integration tests information
|  |  |
|--|--|
| **Main release stage issue** | {{STAGE_ISSUE}} |
| **Version** | {{VERSION}} |
| **Stage** | {{STAGE}} |
| **Tag** | [{{TAG}}](https://github.com/wazuh/wazuh/tree/{{TAG}}) |
| **Wazuh QA: Tag** | [{{TAG}}](https://github.com/wazuh/qa-integration-framework/tree/{{TAG}}) |
| **Previous agent integration tests issue** | {{PREVIOUS_ISSUE}} |

## Workflows
```yaml
workflows:
  - name: "Agent integration tests agentd-tier-0-1-lin"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_agentd-tier-0-1-lin.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests agentd-tier-0-1-win"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_agentd-tier-0-1-win.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests aws-tier-0-1"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_aws-tier-0-1.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
      base_qa_it_fw_branch: "{{TAG}}"
  - name: "Agent integration tests enrollment-tier-0-1-lin"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_enrollment-tier-0-1-lin.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests enrollment-tier-0-1-win"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_enrollment-tier-0-1-win.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests execd-tier-0-1-lin"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_execd-tier-0-1-lin.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests execd-tier-0-1-win"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_execd-tier-0-1-win.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests fim-tier-0-1-lin"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_fim-tier-0-1-lin.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests fim-tier-0-1-macos"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_fim-tier-0-1-macos.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests fim-tier-0-1-win"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_fim-tier-0-1-win.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests github-tier-0-1-lin"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_github-tier-0-1-lin.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests github-tier-0-1-win"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_github-tier-0-1-win.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests logcollector-tier-0-1-lin"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_logcollector-tier-0-1-lin.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests logcollector-tier-0-1-macos"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_logcollector-tier-0-1-macos.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests logcollector-tier-0-1-win"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_logcollector-tier-0-1-win.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests msgraph-tier-0-1-lin"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_msgraph-tier-0-1-lin.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests office365-tier-0-1-lin"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_office365-tier-0-1-lin.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests office365-tier-0-1-win"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_office365-tier-0-1-win.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests sca-tier-0-1-lin"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_sca-tier-0-1-lin.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests sca-tier-0-1-win"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_sca-tier-0-1-win.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests syscollector-tier-0-1-lin"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_syscollector-tier-0-1-lin.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests syscollector-tier-0-1-win"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_syscollector-tier-0-1-win.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests fim-tier-2-lin"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_fim-tier-2-lin.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "Agent integration tests fim-tier-2-win"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_fim-tier-2-win.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
```

### Legend

🟢 The pipeline has been executed successfully.
🟡 The pipeline is still in progress.
🔴 The pipeline has failed.

## Conclusion
List every new or known issue that appeared while testing this task, with its link, before closing this issue.

| Status | Test | Failure type | New or known issues (with link) | Notes |
|---|---|---|---|---|
|  | Agent integration tests agentd-tier-0-1-lin |  |  |  |
|  | Agent integration tests agentd-tier-0-1-win |  |  |  |
|  | Agent integration tests aws-tier-0-1 |  |  |  |
|  | Agent integration tests enrollment-tier-0-1-lin |  |  |  |
|  | Agent integration tests enrollment-tier-0-1-win |  |  |  |
|  | Agent integration tests execd-tier-0-1-lin |  |  |  |
|  | Agent integration tests execd-tier-0-1-win |  |  |  |
|  | Agent integration tests fim-tier-0-1-lin |  |  |  |
|  | Agent integration tests fim-tier-0-1-macos |  |  |  |
|  | Agent integration tests fim-tier-0-1-win |  |  |  |
|  | Agent integration tests github-tier-0-1-lin |  |  |  |
|  | Agent integration tests github-tier-0-1-win |  |  |  |
|  | Agent integration tests logcollector-tier-0-1-lin |  |  |  |
|  | Agent integration tests logcollector-tier-0-1-macos |  |  |  |
|  | Agent integration tests logcollector-tier-0-1-win |  |  |  |
|  | Agent integration tests msgraph-tier-0-1-lin |  |  |  |
|  | Agent integration tests office365-tier-0-1-lin |  |  |  |
|  | Agent integration tests office365-tier-0-1-win |  |  |  |
|  | Agent integration tests sca-tier-0-1-lin |  |  |  |
|  | Agent integration tests sca-tier-0-1-win |  |  |  |
|  | Agent integration tests syscollector-tier-0-1-lin |  |  |  |
|  | Agent integration tests syscollector-tier-0-1-win |  |  |  |
|  | Agent integration tests fim-tier-2-lin |  |  |  |
|  | Agent integration tests fim-tier-2-win |  |  |  |

## Auditors' validation
In order to close and proceed with the release or the next candidate version, the following auditors must give the green light to this stage.

- [ ] @wazuh/devel-xdrsiem-agent
- [ ] @wazuh/devel-xdrsiem-qa-release
