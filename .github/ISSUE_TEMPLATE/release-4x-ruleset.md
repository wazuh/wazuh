---
name: Release - 4.x - Ruleset
about: Report the results after running the ruleset tests for a release stage.
title: 'Release {{VERSION}} - {{STAGE}} - Ruleset'
labels: 'level/task, type/test'
assignees: ''
---

The following issue aims to run the `ruleset` tests for the current release candidate, report the results, and open new issues for any encountered errors. In 4.x, `wazuh-analysisd` decodes the events and matches the rules: the workflow below builds and installs the manager from the tag, then runs `ruleset/testing/runtests.py` against every `.ini` file in `ruleset/testing/tests/`, except the `*geoip.ini` files, which need GeoIP databases.

## Ruleset tests information
|  |  |
|--|--|
| **Main release stage issue** | {{STAGE_ISSUE}} |
| **Version** | {{VERSION}} |
| **Stage** | {{STAGE}} |
| **Tag** | [{{TAG}}](https://github.com/wazuh/wazuh/tree/{{TAG}}) |
| **Previous ruleset tests issue** | {{PREVIOUS_ISSUE}} |

## Workflows
```yaml
workflows:
  - name: "Ruleset integration tests"
    type: "github"
    repository: "wazuh/wazuh"
    workflow: "4_testintegration_ruleset.yml"
    ref: "{{TAG}}"
    inputs: {}
```

## Test report procedure
All workflow results must have one of the following statuses:

|Color| Details |
|:--:|:--|
| :green_circle: | The **pipeline** has been executed successfully |
| :red_circle: | The **pipeline** has failed or it has errors |

Post in a comment the two tables that `runtests.py` prints at the end of the `Run ruleset integration tests` step: the coverage of rules and decoders, and the passed and failed tests of each `.ini` file. For a failed file, copy its entries from the `Failing tests summary` of the same log.

## Conclusion
List every new or known issue that appeared while testing this task, with its link, before closing this issue.

| Status | Test | Failure type | New or known issues (with link) | Notes |
|---|---|---|---|---|
|  | 4_testintegration_ruleset |  |  |  |

## Auditors' validation
- [ ] @wazuh/devel-cloud-threatintel
- [ ] @wazuh/devel-xdrsiem-qa-release
