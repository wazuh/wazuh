# Enrichment-join design analysis: cache vs. sync, cold-cache handling

Companion to [requirements-analysis.md](requirements-analysis.md) §2 ("Enrichment join") and the corresponding deliverable row, which flagged this as **Partial** — synchronous + off-thread, no FIM-side cache, drop-only cold-cache handling. This document lays out the pros/cons of the current design against the alternatives the issue asks about, grounded in the actual client/server code rather than generic tradeoffs.

## Current implementation (baseline for comparison)

`fim_handle_container_whodata_event()` (`container_live_fim.cpp:582-739`) does a fresh `ContainerInstancesClient::resolveByCgroupId()` call per event, on a single dedicated worker thread (`ebpf_pop_container_events()`, `ebpf_whodata.cpp:448-479`) fed by a bounded, drop-on-full queue (`containerEventQueue`). Each call is a brand-new `AF_UNIX` connect → send → blocking recv → close (`container_instances_client.hpp:132-200`), no persistent connection, no client-side cache. On any non-`resolved` status (`pending`, `unavailable`, `notContainer`) the event is unconditionally dropped (`container_live_fim.cpp:611-614`) — no retry, no buffering.

Caching already exists, but only **server-side**, inside `container_instances` itself (`ci_impl/src/cache/metadata_store.hpp`, `core/cache_entry.hpp`), keyed by cgroup/inode with TTL-style aging and a deletion grace period. FIM talks to that cache through a pull-only protocol (`wire_protocol.hpp`: `resolve`/`list`/`status`, no push/subscribe).

## Option A — Synchronous, no cache (current)

**Pros**
- Correctness by construction: every answer reflects the server's current state at request time — no staleness window to reason about.
- Simple: no invalidation, no eviction, no cache-consistency bugs to introduce into a spike that already has several found-via-testing bugs (wrong-field parsing, PID-liveness, startup race — see [requirements-analysis.md](requirements-analysis.md)).
- Isolating the round trip on its own worker thread (rather than the ring-buffer-draining thread) was already the important latency fix — it protects kernel-event throughput from the IPC cost, which is the failure mode that actually matters for not losing *host* events.
- No new state to keep consistent with `container_instances`' own cache — one source of truth.

**Cons**
- Serial processing on a single worker thread means IPC latency is fully on the critical path for *container* event throughput: a run of cold lookups (up to ~0.6s each before the server even answers `pending`, per `container_instances_client.hpp:45-46`, with a client timeout ≥1000ms) serializes directly into queue backlog.
- No amortization: a container that's already been resolved once still pays a full connect/send/recv/close cycle for its 1000th event.
- Drop-only cold-cache handling throws away real events, not just adversarial/edge-case ones — `pending` specifically means "ask again shortly," and today "shortly" never happens.
- Under the issue's own stated load target ("thousands of file events/sec on a busy node"), this is the design most exposed to queue overflow (`FIM_FULL_EBPF_CONTAINER_QUEUE`), since nothing shields the queue from a burst of cold lookups.

## Option B — FIM-side cache (cgroup_id → container_id)

**Pros**
- Would eliminate the round trip for repeat events against an already-resolved container — the common case once a container has been up for more than one event.
- Could mask the server's own cold-cache latency after the first successful resolution.

**Cons — and these are the load-bearing ones, not just standard cache-invalidation caveats**
- This codebase has already documented, independently, exactly why a cgroup_id-keyed cache is dangerous here. `cgroup_id` is not a permanent identifier — `container_instances`' own server-side cache calls the field `cgroupInode` (`ci_impl/src/cache/metadata_store.hpp:31`), because it *is* the cgroup's kernfs inode number, and inode numbers get reallocated once freed, same as any filesystem inode. This isn't a theoretical concern: `container_instances`' own cache design builds in explicit countermeasures for it — a terminal `VerdictEntry` is evicted once a `missedScans` counter accumulates, commented as **"cgroup-inode reuse protection"** (`core/cache_entry.hpp:57`), and `ResolvedEntry` carries a `deletedAt` grace period rather than trusting a resolved mapping indefinitely (`cache_entry.hpp:46-53`). Separately, [startup-race-solutions-and-edge-cases.md](startup-race-solutions-and-edge-cases.md) (L191-219) documents the adjacent PID-reuse (TOCTOU) and container-name-reuse races on the FIM side. Put together: a numerically identical `cgroup_id` can legitimately denote two unrelated containers at different points in time, so a stale FIM-side cache entry surviving that reuse would silently misattribute a file event to the wrong (or a deleted) container — a correctness bug in the emitted document, not just a perf issue.
- Short-lived containers are explicitly noted as churning faster than any reasonable poll/refresh interval — the exact profile that makes TTL-based invalidation unsafe: too long a TTL reopens the reuse hazard above; too short defeats the purpose of caching at all.
- The wire protocol has no push/invalidate primitive (`resolve`/`list`/`status` only) — a FIM-side cache would have to guess its own expiry policy independently of the server's actual lifecycle knowledge, duplicating (and potentially disagreeing with) the cache `container_instances` already maintains.
- No precedent for this in the codebase: `container_baseline`'s `DiscoverContainers()` also calls straight through to `listContainers()` with no local cache — the one other place enrichment happens today made the same choice not to cache client-side.
- Net effect: a client-side cache mostly duplicates work the server-side `metadata_store` cache already does, while adding a new, codebase-documented class of misattribution risk to save one connect/recv cycle per event.

## Option C — Keep synchronous, replace drop-only with bounded retry/buffer on `pending`

**Pros**
- Targets the actual documented gap directly: `pending` is a "not yet, try again" signal from the server, not a permanent failure — treating it as equivalent to `notContainer`/`unavailable` throws away resolvable events for no correctness benefit.
- No staleness risk introduced — this only affects *when* an event is processed, not *what* it's resolved against; the eventual resolve() call is still a fresh, authoritative lookup.
- Composes with the existing off-thread design: a short bounded delay/requeue for `pending` (distinct from the hard drop kept for `unavailable`/`notContainer`, which are legitimately terminal) doesn't change the architecture, just the terminal-vs-retryable classification.

**Cons**
- Still adds real complexity: a retry counter/backoff and re-queue path per event, plus a policy for how many attempts before giving up (which becomes a new drop path, just a later one).
- Doesn't fix serial-thread throughput under sustained load — a burst of genuinely cold containers still queues up retries behind each other on the one worker thread; more workers would need thread-safety analysis of `ContainerInstancesClient`'s connect-per-request pattern (each call already opens its own socket, so this is likely safe, but unverified).
- Bounded retry still needs a ceiling on total pending events in flight, or it just moves the queue-overflow problem from "the input queue" to "the retry queue."

## Recommendation

Keep the synchronous, off-thread, no-client-cache design (Option A) as the foundation — the codebase's own lifecycle-race documentation is a strong, specific argument against a FIM-side cache here, not a generic caution. The concrete gap worth closing is the classification in Option C: distinguish `pending` (retry-worthy) from `unavailable`/`notContainer` (legitimately terminal) instead of dropping all three identically. That's the smallest change that closes the acceptance-criteria gap ("cold-cache handling documented/handled") without reopening the cgroup-reuse correctness risk that ruled out caching.
