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
2. Open the latest execution of each workflow listed in the comment of that branch or tag.
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

The scheduled task runs every Tuesday. For each branch or tag under review it posts a comment in this issue with the workflows it has dispatched on that ref, and later fills in the result and the link of each run.
