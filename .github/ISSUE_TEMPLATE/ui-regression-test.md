---
name: Release Candidate - UI regression testing
about: Report the results after running UI manual tests.
title: 'Release [WAZUH VERSION] - Release Candidate [RC VERSION] - Wazuh UI regression testing'
labels: 'level/task, type/test, request/operational'
assignees: ''

---

The following issue aims to run manual tests for the current release candidate, report the results, and open new issues for any encountered errors.

## Wazuh UI tests information
|                                        |     |
|----------------------------------------|-----|
| **Main release candidate issue**       |     |
| **Version**                            |     |
| **Release candidate #**                |     |
| **Tag**                                |     |
| **Previous UI regression tests issue** |     |

## Test report procedure

**TL;DR**
   1. The specified tests will be executed in every platform and version mentioned in this issue.
   2. Include evidence of each test performed.
   3. Report any problem or bug. Open a new issue for each of them and link them here.
   4. Justify skipped tests.


All test results must have one the following statuses: 
|                 |                                                                      |
|-----------------|----------------------------------------------------------------------|
| :white_circle:  | Doesn't apply.                                                       |
| :black_circle:  | The test hasn't started yet.                                         |
| :green_circle:  | All checks passed.                                                   |
| :red_circle:    | There is at least one failed check.                                  |
| :yellow_circle: | There is at least one expected fail or skipped test and no failures. |


For each tester:
- Create a new message with the test report. This should have a `<details><summary>RESULT - TITLE</details>` for each test.

Test considerations: 
- Any failing test must be properly addressed with a new issue, detailing the error and the possible cause.
It must be included in the `Problems` section of the current release candidate issue.
- Any expected fail or skipped test must be justified with a reason. 
All auditors must validate the justification for an expected fail or skipped test.
- An extended report of the test results must be attached as a zip, txt or images. 
This report can be used by the auditors to dig deeper into any possible failures and details.

Test summary:
- [ ] **Write the test conclusions in Conclusions section**
- [ ] **Update the test template table results changing the circle colors with the test results in the Test section**

## Test 

| Test | Chrome         | Firefox        | Safari         |
|------|----------------|----------------|----------------|
| Verify the app package installs and operates as expected. | :black_circle: | :black_circle: | :black_circle: |
| Verify the default `opensearch_dashboards.yml` has the same settings of the repository [opensearch_dashboards.yml](https://github.com/wazuh/wazuh-dashboard/blob/main/config/opensearch_dashboards.prod.yml) | :black_circle: | :black_circle: | :black_circle: |


## Test plan

<details><summary>:black_circle: Verify the app package installs and operates as expected.</summary>


</details>
<details><summary>:black_circle: Verify the default <b>opensearch_dashboards.yml</b> has the same settings of the repository <b>opensearch_dashboards.yml</b> <!-- REPLACE main BRANCH WITH THE CORRESPONDING TAG IN THE LINK  --></summary>


</details>

## Conclusions :black_circle:


<!-- ** Copy and paste as a new comment. Modify as needed. **

## Conclusions

All tests have been executed and the results can be above.


All tests have passed and the fails have been reported or justified. I therefore conclude that this issue is finished and OK for this release candidate.
-->

## Auditors validation
The definition of done for this one is the validation of the conclusions and the test results from all auditors.

All checks from below must be accepted in order to close this issue.

- [ ] @asteriscos
