---
name: Release - 4.x - C unit tests and RTR
about: Report the results after running the C unit tests and RTR checks for a release stage.
title: 'Release {{VERSION}} - {{STAGE}} - C unit tests and RTR'
labels: 'level/task, type/test'
assignees: ''
---

This issue aims to run all C unit tests and RTR checks for the current stage and report the results. Any failing test should be properly addressed with a new issue, detailing the error and the possible cause. Then, it will be determined if that failure is to be fixed immediately or marked as expected if there is enough support and approval. In case a test is marked as expected-fail, the issue detailing the error should always be used as a reference in the test.

> [!NOTE]
> These tests are run locally.

## C unit tests and RTR information
|  |  |
|--|--|
| **Main release stage issue** | {{STAGE_ISSUE}} |
| **Version** | {{VERSION}} |
| **Stage** | {{STAGE}} |
| **Tag** | [{{TAG}}](https://github.com/wazuh/wazuh/tree/{{TAG}}) |
| **Previous C unit tests and RTR issue** | {{PREVIOUS_ISSUE}} |

## Conclusion
List every new or known issue that appeared while testing this task, with its link, before closing this issue.

| Status | Test | Failure type | New or known issues (with link) | Notes |
|---|---|---|---|---|
|  | C unit tests |  |  |  |
|  | RTR |  |  |  |

## Auditors' validation
In order to close and proceed with the release or the next candidate version, the following auditors must give the green light to this stage.

- [ ] @wazuh/devel-xdrsiem-agent
- [ ] @wazuh/devel-xdrsiem-qa-release
