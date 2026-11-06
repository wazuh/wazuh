---
name: Release - 4.x - Coverity scan
about: Report the results of the Coverity scan for a release stage.
title: 'Release {{VERSION}} - {{STAGE}} - Coverity scan'
labels: 'level/task, type/test'
assignees: ''
---

This issue will show the results of the Coverity scan for the current stage.
- [Coverity dashboard](https://scan.coverity.com/projects/wazuh-wazuh)

## Coverity scan information
|  |  |
|--|--|
| **Main release stage issue** | {{STAGE_ISSUE}} |
| **Version** | {{VERSION}} |
| **Stage** | {{STAGE}} |
| **Tag** | [{{TAG}}](https://github.com/wazuh/wazuh/tree/{{TAG}}) |
| **Previous Coverity scan issue** | {{PREVIOUS_ISSUE}} |

## Workflows
```yaml
workflows:
  - name: "Coverity scan"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_codeanalysis_coverity.yml"
    ref: "{{TAG}}"
    inputs:
      project: "wazuh"
      threads: "0"
```

## Conclusion
List every new or known issue that appeared while testing this task, with its link, before closing this issue.

| Status | Test | Failure type | New or known issues (with link) | Notes |
|---|---|---|---|---|
|  | Coverity scan |  |  |  |

## Auditors' validation
In order to close and proceed with the release or the next candidate version, the following auditors must give the green light to this stage.

- [ ] @wazuh/devel-xdrsiem-agent
- [ ] @wazuh/devel-xdrsiem-qa-release
