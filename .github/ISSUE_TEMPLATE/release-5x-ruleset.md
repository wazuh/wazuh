---
name: Release - 5.x - Ruleset
about: Report the results after running the ruleset release test for a release stage.
title: 'Release {{VERSION}} - {{STAGE}} - Ruleset'
labels: 'level/task, type/test'
assignees: ''
---

The following issue aims to run the `ruleset` release test for the current release candidate, report the results, and open new issues for any encountered errors.

In 5.x the ruleset is not in this repository: the Wazuh indexer syncs it from CTI. Two components of the release turn a log line into a finding, and this task tests both:

| Component | Repository | Role |
|---|---|---|
| Engine | `wazuh/wazuh` | Decodes the event. The manager runs it on agent events, and the indexer bundles a copy for logtest. |
| Ruleset Management | `wazuh/wazuh-indexer-plugins` | Matches the Sigma rules: the standard detectors write a finding for each matching event. |

The Threat Intel team deploys `{{TAG}}` from its official Docker images, syncs it to the current ruleset, and runs a set of stable test events: events whose decoders and rules have not changed across recent ruleset versions, so their result depends on `{{TAG}}`. Every one must pass.

This template has no `## Workflows` section: the 5.x release test workflow lives outside this repository and has not run green yet, so the release job cannot dispatch it. Until it can, the Threat Intel team starts the run by hand.

## Ruleset tests information
|  |  |
|--|--|
| **Main release stage issue** | {{STAGE_ISSUE}} |
| **Version** | {{VERSION}} |
| **Stage** | {{STAGE}} |
| **Tag** | [{{TAG}}](https://github.com/wazuh/wazuh/tree/{{TAG}}) |
| **Previous ruleset tests issue** | {{PREVIOUS_ISSUE}} |

## Test report procedure
Each check of the release test must have one of the following statuses:

|Color| Details |
|:--:|:--|
| :green_circle: | The check passed |
| :red_circle: | The check failed |

A check the report marks `not measured` has no status: leave its Status cell empty and give the reason from the report in Notes.

Post the report the release test generates as a comment. It holds the checks, the coverage of rules and decoders, the results per integration, the live results, and each failure.

## Conclusion
List every new or known issue that appeared while testing this task, with its link, before closing this issue.

Each row is a check of the report, with the same name. The report's first check, `Release <version> deployed`, has no row: the run produces no report unless it deploys the release.

| Status | Test | Failure type | New or known issues (with link) | Notes |
|---|---|---|---|---|
|  | Ruleset content synced |  |  |  |
|  | Standard detectors built |  |  |  |
|  | Stable set passes through logtest |  |  |  |
|  | Live decoding by the manager's engine |  |  |  |
|  | Live findings by the indexer's detectors |  |  |  |

## Auditors' validation
- [ ] @wazuh/devel-cloud-threatintel
- [ ] @wazuh/devel-xdrsiem-qa-release
