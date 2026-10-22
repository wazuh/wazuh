# Agent metadata cache

Header-only C++17 library used by enriched-event ingestion to share parsed, identity-validated
agent metadata across batches. Operator settings and metrics live in the
[engine reference](../../../../docs/ref/modules/engine/README.md#agent-metadata-cache).

## Requirements

| Requirement | Status | Test coverage |
|---|---|---|
| Bind reuse to a canonical trusted ID and identical header bytes; reject ambiguous or mismatched identity | kept | Identity and pair-binding cases |
| Retain at most one header per agent, within each enabled entry/byte limit | kept | Admission and accounting cases |
| Return valid metadata even when retention does not fit | kept | Capacity bypass cases |
| Preserve exact modeled accounting through replacement, expiry and clear | kept | Accounting and lifecycle cases |
| Allow concurrent lookup, admission, cleanup and clear; returned documents remain valid | kept | Thread-safety and shared-lifetime cases |

## Design decisions

| Decision | Reason |
|---|---|
| Index by trusted ID and compare full header bytes | One entry per agent; no content-hash collision ambiguity |
| Parse and validate on a miss outside the lock; double-check before publication | Concurrent identical misses converge without serializing parsing |
| Admit only when both limits fit; do not evict unrelated entries at capacity | Constant-time admission without a victim scan |
| Use replacement's net byte delta; remove the old version if the new one bypasses | Do not retain metadata the agent no longer uses |
| Use TTL expiry with a two-phase sweep | Refreshes use a shared lock and atomic timestamp; phase two revalidates candidates |
| Register pull callbacks with weak ownership | Metrics remain safe after cache destruction |

## Layout

| Path | Responsibility |
|---|---|
| `include/agentcache/agentMetadataCache.hpp` | Cache, limits, cleanup-interval validator and metric registration |
| `include/agentcache/canonicalAgentId.hpp` | Canonical producer identity check |
| `include/agentcache/identityError.hpp` | Typed identity rejection |
| `test/src/unit/agentMetadataCache_test.cpp` | Identity, retention, metrics, lifecycle and concurrency regressions |
| `CMakeLists.txt` | `agentcache::agentcache` interface library and optional test/benchmark targets |

## Consumer contract

Link `agentcache::agentcache` (transitively `base` and `fastmetrics::fastmetrics`) and call
`fastmetrics::registerManager()` before construction. Supply a positive TTL up to 86400 seconds,
`Limits` and optionally a monotonic clock. Each zero limit independently means unlimited.
`Limits::MAX_ENTRIES` and `Limits::MAX_BYTES` bound representable constructor inputs. The engine
resolves defaults through `conf` and calls `validateCleanInterval()` before scheduling cleanup.

`getOrParse(trustedId, header)` returns `shared_ptr<const json::Json>` and an operation:

| Condition | Operation / effect |
|---|---|
| Same ID and exact bytes retained | `Retrieved`; refresh last use, no parse |
| New valid pair fits | `Inserted` |
| Changed valid header fits after releasing old cost | `Updated` |
| Valid header cannot fit | `BypassedCapacity`; return parsed header, remove only its obsolete entry |
| Invalid JSON or identity | Throw; leave existing retention unchanged |

The producer authenticates or otherwise establishes the trusted ID. The cache checks canonical
spelling, a unique string at `/wazuh/agent/id`, and exact equality before admission. Capacity
bypass never skips identity validation. Admission occurs before event-body validation, so a
header-only or later-invalid batch can retain its valid header.

## Accounting model

Each retained entry accounts:

```
raw header length + trusted ID length + Json::getAllocatedMemory() + fixed overhead
```

The fixed overhead is `sizeof(CacheEntry) + sizeof(json::Json) + sizeof(CacheMap::value_type)
+ 6 * sizeof(void*)`, estimating the map node and two shared-owner control blocks. Checked
arithmetic prevents wrapping. A document's allocated pool capacity and saved cost are immutable;
mutation of the index and running total shares one exclusive lock. A new agent that cannot fit
the current snapshot (entry limit reached, or bytes over the limit) bypasses under the shared lock,
so a full cache does not serialise traffic from agents it will not retain; an agent that already
has an entry always takes the exclusive path, because its replacement may fit.

This models retained cache state. It excludes allocator rounding, spare string capacity, bucket
arrays, JSON pool bookkeeping, transient parse candidates and documents kept alive by callers
or queued events after removal. It does not bound process memory or request size. Clearing or
expiry immediately releases accounted bytes even while returned shared pointers remain alive.

## Metrics

Names are defined in [metric_names.hpp](../fastmetrics/interface/fastmetrics/metric_names.hpp).
The cache owns hit, insertion, update, TTL eviction and two capacity-bypass counters; the ingress
handler owns identity rejections. Call `registerCacheMetrics()` once after constructing the
shared cache to expose entries, accounted bytes and configured limits. Pull callbacks use weak
pointers and return zero after destruction. Each failed capacity predicate increments its own
counter; both can increment for one admission. Removing an obsolete entry on bypass is not a
TTL eviction. A bypass also feeds a throttled warning (`reportBypass()`): at most one per 90 s, with
the bypasses since the previous report, occupancy against the limits and the setting to raise. It
uses the steady clock, not the injectable one, and never throws, so reporting cannot fail a batch. See the [operator metric catalog](../../../../docs/ref/modules/engine/README.md#agent-cache-metrics).

## Tests

`test/src/unit/agentMetadataCache_test.cpp` covers canonical/unique/matching identity, exact-byte
hits, replacement, independent/unlimited limits, exact fits, arithmetic overflow, exception
safety, TTL/clear accounting, shared-document lifetime, bypass counters, pull lifetimes and
concurrent mutations. Build and run in the configured engine-test tree:

```bash
cmake --build "$WAZUH_REPO/src/build" -j22 --target agentcache_utest
"$WAZUH_REPO/src/build/engine/source/agentcache/agentcache_utest"
```
