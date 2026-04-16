---
name: Weekly Integration/Component test task (manager)
about: Weekly operational task to review the scheduled manager integration and component test executions and report their status.
title: '[Week AA] Integration/Component test manager'
labels: 'level/task, request/operational, type/test'
assignees: ''

---

## Previous week issue

| Week | Issue |
|---|---|
| Previous | Add the link to the previous weekly issue here. |

## Description
Use this issue to review the scheduled manager integration and component test executions, confirm the result of each workflow for every branch or tag under review, and document failures or anomalies that need follow-up.

## What needs to be done

1. Identify the version, branch, or tag under review for the current week.
2. Open the latest execution for each workflow listed below.
3. Record the result of every workflow and add the run link.
4. If a workflow fails, summarize the error and the most likely cause.
5. Open follow-up issues when a failure requires product or CI changes.

All test results must have one of the following statuses:
|Color| Details |
|:--:|:--|
| :green_circle: | The **pipeline** has been executed successfully |
| :yellow_circle: | The **pipeline** is unstable or needs manual review |
| :red_circle: | The **pipeline** has failed or it has errors |

Any failed test should be reported, detailing the error and possible cause.

## Workflows to review

The scheduled task executes the following workflows every Wednesday:

| Test                                    | Link                                                                                        |
|-----------------------------------------|---------------------------------------------------------------------------------------------|
|4_testintegration_analysisd-tier-0-1     |https://github.com/wazuh/wazuh/actions/workflows/4_testintegration_analysisd-tier-0-1.yml    |
|4_testintegration_analysisd-tier-2       |https://github.com/wazuh/wazuh/actions/workflows/4_testintegration_analysisd-tier-2.yml      |
|4_testintegration_authd-tier-0-1         |https://github.com/wazuh/wazuh/actions/workflows/4_testintegration_authd-tier-0-1.yml        |
|4_testintegration_integratord-tier-0-1   |https://github.com/wazuh/wazuh/actions/workflows/4_testintegration_integratord-tier-0-1.yml  |
|4_testintegration_logtest-tier-0-1       |https://github.com/wazuh/wazuh/actions/workflows/4_testintegration_logtest-tier-0-1.yml      |
|4_testintegration_remoted-tier-0-1       |https://github.com/wazuh/wazuh/actions/workflows/4_testintegration_remoted-tier-0-1.yml      |
|4_testintegration_remoted-tier-2         |https://github.com/wazuh/wazuh/actions/workflows/4_testintegration_remoted-tier-2.yml        |
|4_testintegration_wazuh_db-tier-0-1      |https://github.com/wazuh/wazuh/actions/workflows/4_testintegration_wazuh_db-tier-0-1.yml     |
|4_testcomponent_vulnerability-scanner    |https://github.com/wazuh/wazuh/actions/workflows/4_testcomponent_vulnerability-scanner.yml    |

<!--
**INSTRUCTIONS:**
1. **Post a NEW COMMENT in this issue for EACH version/tag under test**.
2. Replace `[VERSION_OR_TAG]` below with either:
   - Latest pre-release tag (e.g., `v4.12.0-RC1`) *if available*.
   - *If no tag exists*, use the branch name (e.g., `4.12.0`)
3. Update statuses:
   - :green_circle: = Passing
   - :yellow_circle: = Unstable
   - :red_circle: = Failing

=== COPY FROM HERE ===

## [VERSION_OR_TAG]
| Status                                             | Test| Link      | Coments |
|----------------------------------------------|-----|-----------|--|
| :black_circle: | 4_testintegration_analysisd-tier-0-1     | | |
| :black_circle: | 4_testintegration_analysisd-tier-2       | | |
| :black_circle: | 4_testintegration_authd-tier-0-1         | | |
| :black_circle: | 4_testintegration_integratord-tier-0-1   | | |
| :black_circle: | 4_testintegration_logtest-tier-0-1       | | |
| :black_circle: | 4_testintegration_remoted-tier-0-1       | | |
| :black_circle: | 4_testintegration_remoted-tier-2         | | |
| :black_circle: | 4_testintegration_wazuh_db-tier-0-1      | | |
| :black_circle: | 4_testcomponent_vulnerability-scanner    | | |
-->

<!--
To launch the tests from the command line, use the following commands:

Old workflows:
gh workflow run integration-tests-analysisd-tier-0-1.yml --repo=wazuh/wazuh --ref <VERSION>
gh workflow run integration-tests-analysisd-tier-2.yml --repo=wazuh/wazuh --ref <VERSION>
gh workflow run integration-tests-authd-tier-0-1.yml --repo=wazuh/wazuh --ref <VERSION>
gh workflow run integration-tests-integratord-tier-0-1.yml --repo=wazuh/wazuh --ref <VERSION>
gh workflow run integration-tests-logtest-tier-0-1.yml --repo=wazuh/wazuh --ref <VERSION>
gh workflow run integration-tests-remoted-tier-0-1.yml --repo=wazuh/wazuh --ref <VERSION> --field base_branch=<VERSION>
gh workflow run integration-tests-remoted-tier-2.yml --repo=wazuh/wazuh --ref <VERSION>
gh workflow run integration-tests-wazuh_db-tier-0-1.yml --repo=wazuh/wazuh --ref <VERSION>
gh workflow run vulnerability-scanner-tests.yml --repo=wazuh/wazuh --ref <VERSION>

New workflows:
gh workflow run 4_testintegration_analysisd-tier-0-1.yml --repo=wazuh/wazuh --ref <VERSION>
gh workflow run 4_testintegration_analysisd-tier-2.yml --repo=wazuh/wazuh --ref <VERSION>
gh workflow run 4_testintegration_authd-tier-0-1.yml --repo=wazuh/wazuh --ref <VERSION>
gh workflow run 4_testintegration_integratord-tier-0-1.yml --repo=wazuh/wazuh --ref <VERSION>
gh workflow run 4_testintegration_logtest-tier-0-1.yml --repo=wazuh/wazuh --ref <VERSION>
gh workflow run 4_testintegration_remoted-tier-0-1.yml --repo=wazuh/wazuh --ref <VERSION> --field base_branch=<VERSION>
gh workflow run 4_testintegration_remoted-tier-2.yml --repo=wazuh/wazuh --ref <VERSION>
gh workflow run 4_testintegration_wazuh_db-tier-0-1.yml --repo=wazuh/wazuh --ref <VERSION>
gh workflow run 4_testcomponent_vulnerability-scanner.yml --repo=wazuh/wazuh --ref <VERSION>
-->
