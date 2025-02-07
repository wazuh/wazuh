---
name: Release Candidate - API integration tests
about: Report the results after running API integration tests.
title: Release [WAZUH VERSION] - Release Candidate [RC VERSION] - API integration
  tests
labels: ''
assignees: ''

---

The following issue aims to run all [API integration tests](https://github.com/wazuh/wazuh/tree/main/api/test/integration) for the current release candidate, report the results, and open new issues for any encountered errors.

## API integration tests information
|                                          |                                            |
|------------------------------------------|--------------------------------------------|
| **Main release candidate issue**         |                                            |
| **Version**                              |                                            |
| **Release candidate #**                  |                                            |
| **Tag**                                  |                                            |
| **Previous API integration tests issue** |                                            |


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

- [ ]
