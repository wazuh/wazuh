# 007_prefix_collision_and_cascade

Agent `250` and agent `2502` both have a group document. Deleting agent `250` must not affect
agent `2502`, whose document id (`2502_wheel`) shares the `250` prefix.

Sequence: index both agents, delete agent `250`, then let agent `2502` run its own
`integrity_check_global` reconciliation. `result.json` expects agent `2502`'s document to
survive.

The `*_wait_rsync.json` files are wall-clock padding, not part of the scenario: the test tool
sleeps one second per input file, and these are `integrity_check_global` events for an agent
that has no documents, so they are no-ops. They give the insert batch time to reach the index
before the deletion is processed, and the deletion time to complete before agent `2502` syncs.
Without them agent `2502` syncs against an index that is still empty and the scenario never
happens.
