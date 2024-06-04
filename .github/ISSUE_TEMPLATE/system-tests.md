---
name: Release Candidate - System tests
about: Report the results after running system tests.
title: Release [WAZUH VERSION] - [STAGE] - System tests
labels: level/task, type/test
assignees: ''

---

The following issue aims to run all `system tests` for the current release candidate, report the results, and open new issues for any encountered errors.

## System tests information
|                                      |                                            |
|--------------------------------------|--------------------------------------------|
| **Main release candidate issue**     |                                            |
| **Version**                          |                                            |
| **Release candidate #**              |                                            |
| **Tag**                              |                                            |
| **Previous system tests issue**      |                                            |

## Instructions
To run tests in an AWS EC2 virtual environment, the following requirements will need to be met:

| Environment                  | EC2                                       |
|------------------------------|-------------------------------------------|
|Basic_cluster                 |Ubuntu 22.04.2 LTS C5.XLarge 15GB SSD      |
|Big_cluster_40_agents         |Ubuntu 22.04.2 LTS T3.Large 60GB SSD       |
|Agentless_cluster             |Ubuntu 22.04.2 LTS C5a.XLarge 30GB SSD     |
|Four_manager_disconnected_node|Ubuntu 22.04.2 LTS T3.Large 30GB SSD       |
|One_manager_agent             |Ubuntu 22.04.2 LTS T3.Large 30GB SSD       |
|Manager_agent                 |Ubuntu 22.04.2 LTS T3.Large 30GB SSD       |
|Enrollment_cluster            |Ubuntu 22.04.2 LTS T3.Large 30GB SSD       |
|Basic_environment             |Ubuntu 22.04.2 LTS T3.Large 30GB SSD       |


These requirements should be requested to the @wazuh/devel-devops team via https://github.com/wazuh/internal-devel-requests.

For further information, check https://github.com/wazuh/wazuh-qa/tree/master/tests/system/README.md

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

## Conclusions

<!--
All tests have been executed and the results can be found [here]().

|                |             |                     |                |
|----------------|-------------|---------------------|----------------|
| **Status**     | **Test**    | **Failure type**    | **Notes**      |
|                |             |                     |                |

All tests have passed and the fails have been reported or justified. I therefore conclude that this issue is finished and OK for this release candidate.
-->

## Auditors validation
The definition of done for this one is the validation of the conclusions and the test results from all auditors.

All checks from below must be accepted in order to close this issue.

- [ ] @wazuh/devel-qa-release
