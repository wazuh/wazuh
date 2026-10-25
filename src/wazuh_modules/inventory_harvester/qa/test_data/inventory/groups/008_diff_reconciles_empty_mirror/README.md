# 008_diff_reconciles_empty_mirror

Agent `004`'s document is seeded straight into the index through `pre_existing_data.json`, so
the indexer connector's local mirror never holds it. Agent `004` then runs an
`integrity_check_global`, which reconciles the index against that empty mirror.

`result.json` expects the index to end up empty: the mirror is this node's view of the agent, and
a document it does not hold is one the node must remove. This is the state of a node an agent has
just moved to, where the previous node's documents are cleared before the agent's sync reinserts
the current ones.
