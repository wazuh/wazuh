---
name: Release - 5.x - Python unit tests
about: Report the results after running Python unit tests for a release stage.
title: 'Release {{VERSION}} - {{STAGE}} - Python unit tests'
labels: 'level/task, type/test'
assignees: ''
---

The following issue aims to run all `python unit tests` for the current release candidate, report the results, and open new issues for any encountered errors.

## Python unit tests information
|  |  |
|--|--|
| **Main release stage issue** | {{STAGE_ISSUE}} |
| **Version** | {{VERSION}} |
| **Stage** | {{STAGE}} |
| **Tag** | [{{TAG}}](https://github.com/wazuh/wazuh/tree/{{TAG}}) |
| **Previous python unit tests issue** | {{PREVIOUS_ISSUE}} |

## Workflows
```yaml
workflows:
  - name: "API unit tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testunit_api.yml"
    ref: "{{TAG}}"
    inputs:
      generate_report: "true"
      qa_branch: "{{TAG}}"
  - name: "Framework unit tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testunit_framework.yml"
    ref: "{{TAG}}"
    inputs:
      generate_report: "true"
      qa_branch: "{{TAG}}"
  - name: "Wodles unit tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "5_testunit_wodles.yml"
    ref: "{{TAG}}"
    inputs:
      generate_report: "true"
      qa_branch: "{{TAG}}"
```

## Test report procedure
All individual test checks must be marked as:
|                                  |                                            |
|---------------------------------|--------------------------------------------|
| Pass | The test ran successfully. |
| Xfail | The test was expected to fail and it failed. It must be properly justified and reported in an issue.  |
| Skip | The test was not run. It must be properly justified and reported in an issue.  |
| Fail | The test failed. A new issue must be opened to evaluate and address the problem. |

All test results must have one the following statuses: 
|                                  |                                            |
|---------------------------------|--------------------------------------------|
| :green_circle:  | All checks passed. |
| :red_circle:  | There is at least one failed check. |
| :yellow_circle:  | There is at least one expected fail or skipped test and no failures. |

Any failing test must be properly addressed with a new issue, detailing the error and the possible cause. It must be included in the `Fixes` section of the current release candidate main issue.

Any expected fail or skipped test must have an issue justifying the reason. All auditors must validate the justification for an expected fail or skipped test.

An extended report of the test results must be attached as a zip or txt. This report can be used by the auditors to dig deeper into any possible failures and details.

## Conclusion
List every new or known issue that appeared while testing this task, with its link, before closing this issue.

| Status | Test | Failure type | New or known issues (with link) | Notes |
|---|---|---|---|---|
|  | API |  |  |  |
|  | Wodles |  |  |  |
|  | Framework |  |  |  |

## Auditors' validation
The definition of done for this one is the validation of the conclusions and the test results from all auditors.

All checks from below must be accepted in order to close this issue.

- [ ] @wazuh/devel-xdrsiem-server-div1
- [ ] @wazuh/devel-xdrsiem-qa-release
