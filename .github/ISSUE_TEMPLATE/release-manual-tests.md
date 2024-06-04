---
name: Release Candidate - Manual tests
about: Report the results after running manual tests for the specified release.
title: Release [WAZUH VERSION] - Manual tests - [TEST NAME]
labels: release/4.3.0
assignees: ''

---

The following issue aims to run the specified test for the current release candidate, report the results, and open new issues for any encountered errors.

## Test information
|                         |                                            |
|-------------------------|--------------------------------------------|
| **Test name**           |                                            |
| **Category**            |                                            |
| **Deployment option**   |                                            |
| **Main release issue**  |                                            |
| **Release candidate #** |                                            |

## Test description
ADD TEST DESCRIPTION HERE

## Test report procedure

All test results must have one of the following statuses: 
|                                  |                                            |
|---------------------------------|--------------------------------------------|
| :green_circle:  | All checks passed. |
| :red_circle:  | There is at least one failed result. |
| :yellow_circle:  | There is at least one expected failure or skipped test and no failures. |

Any failing test must be properly addressed with a new issue, detailing the error and the possible cause. 

An extended report of the test results must be attached as a ZIP or TXT file. Please attach any documents, screenshots, or tables to the issue update with the results. This report can be used by the auditors to dig deeper into any possible failures and details.

## Conclusions

All tests have been executed and the results can be found [here]().

|                |             |                     |                |
|----------------|-------------|---------------------|----------------|
| **Status**     | **Test**    | **Failure type**    | **Notes**      |
|                |             |                     |                |

All tests have passed and the fails have been reported or justified. Therefore, I conclude that this issue is finished and OK for this release candidate.

## Auditors validation
The definition of done for this one is the validation of the conclusions and the test results from all auditors.

All checks from below must be accepted in order to close this issue.

- [ ] MODULE OWNER
- [ ] EXTRA REVIEWER
