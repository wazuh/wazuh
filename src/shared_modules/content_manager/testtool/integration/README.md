# Live-cluster gates

Three properties of this module were identified as unverifiable against a fake, because the fake is
not what would reject them. Two of them turned out not to need the project built at all — they are
pure query-shape questions and are automated here. The third needs the binaries and is described at
the bottom.

## Automated: the query contract

```bash
docker compose -f docker-compose.yml up -d
./query_contract_test.py          # defaults to http://localhost:9400
docker compose -f docker-compose.yml down
```

No build, no dependencies beyond Python 3 — it talks to the REST API directly. The cluster is two
nodes on purpose: the slicing gate is about how a PIT partitions documents across shards, and on a
single-shard cluster every slice but one comes back empty, so the gate would pass without having
tested anything.

What it asserts:

| Gate | Why only a real cluster can answer it |
|---|---|
| The emitted sort works over a PIT spanning both indices | Steady state: the data index maps the cursor field, the consumer index does not. |
| `unmapped_type` saves the cold-start sort | The gate that found something. OpenSearch needs a sort field mapped in **at least one** index of the search, so the consumer index lacking it is harmless on its own — the module's comments used to claim otherwise. The real risk is a fresh install: no documents in the data index means no dynamic mapping, the key is unmapped *everywhere*, and the search is rejected. That is a new manager's first feed load. Asserted both ways — rejected without the injection, accepted with it. |
| `_shard_doc` works over the same PIT | The Engine's topics sort on it and skip the `unmapped_type` injection on the grounds that it is mapped everywhere. That is an assumption about OpenSearch, so it is checked rather than trusted. |
| Consumer documents are excluded query-side | `must_not` on the `_index` metafield. This is exactly where an alias would silently stop matching. |
| Slicing neither loses nor duplicates | The correctness property. Every document must be delivered by exactly one slice. Skew is *reported*, not asserted — it costs wall-clock, not correctness, and it legitimately varies with the cluster's shape. |

The sort bodies in the script are written out literally rather than derived, so what the gate
protects is visible in one place. They must stay in step with `buildSort`; the unit test
`FactoryContentUpdaterTest.InjectsUnmappedTypeOnNonMetafieldSortKeys` pins the other end.

## Not automated: end-to-end promotion

This one needs the built binaries and a configured manager, so it stays a manual gate. Run it
against a live cluster before shipping a change to the cycle, the sinks, or the token rules.

| Scenario | What must hold |
|---|---|
| Vulnerability feed cold start, no consumer document | Deferred, not failed. The feed starts within ~1 minute of the consumer turning `ready` — **not** at the next hourly tick. This is the one that would otherwise ship as an hour of missing CVE data. |
| Vulnerability feed full load with a concurrent consumer update | The cycle is skipped, the cursor does not move, and the next cycle picks up cleanly. |
| Engine ruleset sync with a mid-download consumer flip | The staging namespace is rolled back; the deployed route is untouched. |
| Engine IOC sync with one type changing | Only that type's database is swapped; the others keep serving. |
| On-demand under a running update | `409`, not a silent second cycle. |
| Graceful shutdown mid-download, each consumer | No staging database or namespace left behind, and the stored token has not advanced past content that was discarded. |
| A deleted IOC database | Rebuilt on the next cycle even though the hash matches. |

The [test tool](../main.cpp) registers one topic against a live indexer and prints the delivery
contract as it happens, which covers most of the observation these need.
