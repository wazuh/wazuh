---
name: Release - 5.x - C unit tests and RTR - Agent
about: Report the results after running the agent C unit tests and RTR checks for a release stage.
title: 'Release {{VERSION}} - {{STAGE}} - C unit tests and RTR - Agent'
labels: 'level/task, type/test'
assignees: ''
---

This issue aims to run all C unit tests and RTR checks for the current stage, through the workflows listed below, and report the results. Any failing test should be properly addressed with a new issue, detailing the error and the possible cause. Then, it will be determined if that failure is to be fixed immediately or marked as expected if there is enough support and approval. In case a test is marked as expected-fail, the issue detailing the error should always be used as a reference in the test.

## C unit tests and RTR information
|  |  |
|--|--|
| **Main release stage issue** | {{STAGE_ISSUE}} |
| **Version** | {{VERSION}} |
| **Stage** | {{STAGE}} |
| **Tag** | [{{TAG}}](https://github.com/wazuh/wazuh/tree/{{TAG}}) |
| **Previous C unit tests and RTR issue** | {{PREVIOUS_ISSUE}} |

## Workflows
```yaml
workflows:
  - name: "Linux and Windows C unit tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testunit_linux-win.yml"
    ref: "{{TAG}}"
    inputs:
      base_branch: "{{TAG}}"
  - name: "macOS C unit tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testunit_macos.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "agent_info RTR"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testcomponent_agent_info-rtr.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "agent_metadata RTR"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testcomponent_agent_metadata-rtr.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "sca RTR"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testcomponent_sca-rtr.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "schema_validator RTR"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testcomponent_schema_validator-rtr.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "shared_modules_file_helper RTR"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testcomponent_shared_modules_file_helper-rtr.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "sync_protocol RTR"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testcomponent_sync_protocol-rtr.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "syscheck RTR"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testcomponent_syscheck-rtr.yml"
    ref: "{{TAG}}"
    inputs: {}
  - name: "syscollector RTR"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testcomponent_syscollector-rtr.yml"
    ref: "{{TAG}}"
    inputs: {}
```

## Conclusion
List every new or known issue that appeared while testing this task, with its link, before closing this issue.

| Status | Test | Failure type | New or known issues (with link) | Notes |
|---|---|---|---|---|
|  | 5_testunit_linux-win |  |  |  |
|  | 5_testunit_macos |  |  |  |
|  | 5_testcomponent_agent_info-rtr |  |  |  |
|  | 5_testcomponent_agent_metadata-rtr |  |  |  |
|  | 5_testcomponent_sca-rtr |  |  |  |
|  | 5_testcomponent_schema_validator-rtr |  |  |  |
|  | 5_testcomponent_shared_modules_file_helper-rtr |  |  |  |
|  | 5_testcomponent_sync_protocol-rtr |  |  |  |
|  | 5_testcomponent_syscheck-rtr |  |  |  |
|  | 5_testcomponent_syscollector-rtr |  |  |  |

## Auditors' validation
In order to close and proceed with the release or the next candidate version, the following auditors must give the green light to this stage.

- [ ] @wazuh/devel-xdrsiem-agent
- [ ] @wazuh/devel-xdrsiem-qa-release
