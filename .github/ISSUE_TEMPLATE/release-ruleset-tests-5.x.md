|                            |                     |
| :------------------------- | :------------------ |
| **Stage issue**            | {{STAGE_ISSUE}}     |
| **Version**                | {{VERSION}}         |
| **Release type**           | {{RELEASE_TYPE}}    |
| **Stage**                  | {{STAGE}}           |
| **Tag**                    | {{TAG}}             |
| **Previous ruleset test**  | {{PREVIOUS_ISSUE}}  |

## Description

Check that `{{TAG}}` syncs the published ruleset and applies it as before. In 5.x the ruleset is not in this repository: the Wazuh indexer's content manager syncs it from CTI into the `standard` space. The Threat Intel team runs its ruleset release test twice with the same ruleset version: on a lab of the previous release, then on a lab with `{{TAG}}` packages. Only the release changes between the two runs, so a difference is caused by `{{TAG}}`. It is a manual task and has no workflow.

The release test checks:

| Check | Passes when |
| :-- | :-- |
| Lab baked for the release | The lab was rebuilt from the `{{TAG}}` packages |
| Ruleset content synced | The ruleset consumer is `ready`, at the published content, with nothing pending |
| Standard detectors built | No standard detector is broken that worked on the previous release |
| Fixtures replay as on the previous release | Every real event of the team's test set that decoded and matched on the previous release still does |

## What needs to be done

1. Run the ruleset release test on a lab with `{{TAG}}` packages.
2. Post the report it generates as a comment on this issue. It holds the checks, the coverage of rules and decoders, the results per integration and each regression.
3. For each regression, open an issue in the repository of the component and list it under Conclusion.

The report counts the events that fail on both releases as known failures. They are defects the Threat Intel team already tracks, so they are not listed one by one.

| Status | Meaning |
| :--: | :-- |
| :green_circle: | Every check passed |
| :yellow_circle: | Only known issues were found |
| :red_circle: | A new error was found |

## Conclusion

**Status:**

Before you close this issue, list every new or known issue found during the test, with its link.

-
