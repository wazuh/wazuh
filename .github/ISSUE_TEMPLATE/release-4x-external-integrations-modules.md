---
name: Release - 4.x - External integrations modules
about: Report the results after testing the external integrations modules for a release stage.
title: 'Release {{VERSION}} - {{STAGE}} - External integrations modules'
labels: 'level/task, type/test'
assignees: ''
---

The following issue aims to perform all the required testing for the current release candidate to ensure the modules (AWS, Azure, GCP, Docker Listener, Shuffle, Slack, Virustotal, Pagerduty, and Maltiverse) work as expected, report the results, and open new issues for any encountered errors.

## Modules test information
|  |  |
|--|--|
| **Main release stage issue** | {{STAGE_ISSUE}} |
| **Version** | {{VERSION}} |
| **Stage** | {{STAGE}} |
| **Tag** | [{{TAG}}](https://github.com/wazuh/wazuh/tree/{{TAG}}) |
| **Previous external integrations modules issue** | {{PREVIOUS_ISSUE}} |

## Manual tests
- [ ] AWS (manual tests only; the Agent team runs the AWS integration tests, `4_testintegration_aws-tier-0-1.yml`)
  - [ ] Security Lake as a subscriber
- [ ] Azure
- [ ] GCP
- [ ] Docker Listener
- [ ] Shuffle
- [ ] Slack
- [ ] Virustotal
- [ ] Pagerduty
- [ ] Maltiverse

## Test report procedure

All test results must have one of the following statuses:
|                 |                                                                         |
|-----------------|-------------------------------------------------------------------------|
| :green_circle:  | The test passed successfully.                                           |
| :yellow_circle: | The test passed, but some enhancements must be applied to the module.   |
| :red_circle:    | The test failed.                                                        |
| :white_circle:  | The test does not apply.                                                |

Any failing test must be adequately addressed with a new issue detailing the error and the possible cause. It must be included in the Fixes section of the current release candidate's central issue.

The resulting logs for the tests must be included in the status report so the auditors can use them to dig deeper into any possible failures and details.

## Conclusion
List every new or known issue that appeared while testing this task, with its link, before closing this issue.

| Module | Status | New or known issues (with link) |
|---|---|---|
| AWS |  |  |
| Azure |  |  |
| GCP |  |  |
| Docker Listener |  |  |
| Shuffle |  |  |
| Slack |  |  |
| Virustotal |  |  |
| Pagerduty |  |  |
| Maltiverse |  |  |

## Auditors' validation
The definition of done for this one is the validation of the conclusions and the test results from all auditors.

All checks from below must be accepted in order to close this issue.

- [ ] @wazuh/devel-xdrsiem-server
- [ ] @wazuh/devel-xdrsiem-qa-release
