# 008_diff_guard_isolated

Agent `004`'s document is seeded straight into the index through `pre_existing_data.json`, so
the indexer connector's local mirror never holds it. Agent `004` then runs an
`integrity_check_global`, which reconciles the index against that empty mirror.

`result.json` expects the seeded document to survive: an empty per-agent mirror is not evidence
that the index is wrong. No agent-id prefix collision is involved, so this covers the
reconciliation behaviour on its own.
