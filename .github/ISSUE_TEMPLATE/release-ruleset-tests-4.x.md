|                            |                     |
| :------------------------- | :------------------ |
| **Stage issue**            | {{STAGE_ISSUE}}     |
| **Version**                | {{VERSION}}         |
| **Release type**           | {{RELEASE_TYPE}}    |
| **Stage**                  | {{STAGE}}           |
| **Tag**                    | {{TAG}}             |
| **Previous ruleset test**  | {{PREVIOUS_ISSUE}}  |

## Description

Check that the decoders and rules of `{{TAG}}` pass their integration tests. The workflow below builds and installs the manager from `{{TAG}}`, then runs `ruleset/testing/runtests.py` against every `.ini` file in `ruleset/testing/tests/` except the `*geoip.ini` files, which need GeoIP databases. The run fails if any test fails.

## What needs to be done

1. Wait for the workflow run below to finish.
2. Open the log of the `Run ruleset integration tests` step. At its end, `runtests.py` prints a coverage table (rules and decoders) and a table with the passed and failed tests of each `.ini` file.
3. Post both tables in a comment on this issue, so the next release can compare the coverage.
4. If any file has failures, copy its entries from the `Failing tests summary` of the log and list them under Conclusion.

| Status | Meaning |
| :--: | :-- |
| :green_circle: | All tests passed |
| :yellow_circle: | Only known issues were found |
| :red_circle: | A new error was found |

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

## Conclusion

**Status:**

Before you close this issue, list every new or known issue found during the test, with its link.

-
