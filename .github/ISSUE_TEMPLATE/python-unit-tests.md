---
name: Release Candidate - Python unit tests
about: Report the results after running Python unit tests.
title: Release [WAZUH VERSION] - Release Candidate [RC VERSION] - Python unit tests
labels: ''
assignees: ''

---

The following issue aims to run all `python unit tests` for the current release candidate, report the results, and open new issues for any encountered errors.

## Python unit tests information
|                                      |                                            |
|--------------------------------------|--------------------------------------------|
| **Main release candidate issue**     |                                            |
| **Version**                          |                                            |
| **Release candidate #**              |                                            |
| **Tag**                              |                                            |
| **Previous python unit tests issue** |                                            |

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

As for the coverage results, they must be added split by modules. Test files must not be included in the coverage report.

All test coverage results must have one of the following statuses: 
|                 |        |
|-----------------|--------|
| :green_square:  | >= 75% |
| :yellow_square: | >= 50% |
| :orange_square: | >= 25% |
| :red_square:    | < 25%  |


## Conclusions

<!--
All tests have been executed and the results can be found [here]().

|                |             |                     |                |
|----------------|-------------|---------------------|----------------|
| **Status**     | **Test**    | **Failure type**    | **Notes**      |
|                |             |                     |                |

All tests have passed and the fails have been reported or justified. I therefore conclude that this issue is finished and OK for this release candidate.

|                                        |              |            |
|----------------------------------------|--------------|------------|
|                                        | **Coverage** | **Status** |
| **Overall python unit tests coverage** |              |            |
-->

## Auditors validation
The definition of done for this one is the validation of the conclusions and the test results from all auditors.

All checks from below must be accepted in order to close this issue.

- [ ]
