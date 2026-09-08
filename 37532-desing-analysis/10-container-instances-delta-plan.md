# 10 — Container lifecycle delta: implementation plan for roadmap item 20

Design for [roadmap item 20](08-roadmap.md#p2--architecture-make-it-a-baseline) — *baseline once per
container lifetime, not every interval* — and specifically for its recorded blocker: making
`container_instances` **publish** the lifecycle delta it already computes internally
([09](09-implementation-status.md#not-done--deliberately-deferred), item 20). Items
[22](08-roadmap.md#p2--architecture-make-it-a-baseline) (cache across runs) and
[23](08-roadmap.md#p2--architecture-make-it-a-baseline) (re-baseline triggers) depend on this and are
scoped here too.

- **Branch:** `37532-5-0-0-container-integration` @ `d8e4cd5704`
- **Read-only analysis:** no code was changed to produce this document
- **Date:** 2026-09-03

> ### Status, 2026-09-08 — **not implemented, and one premise is falsified**
>
> **Nothing in this plan is in the code.** No `LifecycleJournal`, no cursor, no `epoch`/`seq`/
> `resync_required`, no `instance_id`, no `pid`/`started_at` on `ContainerRecord`. The query surface
> is still the three ops §10.4 documents (`status`, `list`, `resolve`), and `ContainerRecord` still
> ends at `cgroupId`. Even **Phase 0 is untouched**: Docker's `m_reconcilePending` is still written
> at `docker_connector.cpp:93`, cleared at `:71`, and read nowhere.
>
> **What runs instead, per consumer:**
>
> - **syscollector** — the polling §10.1 set out to remove, kept and made configurable.
>   `scanContainerBaseline()` still re-scans every container × every data class per cycle; what
>   changed is only the cadence (`<container_baseline_interval>` decouples it from the host scan,
>   `0` keeps them coupled). Lifecycle is still reconstructed by diffing `list` against
>   `m_knownContainerIds` and sweeping with `sweepContainerRowsNotIn(keep)`. For syscollector,
>   **item 20 is genuinely not done.**
> - **container FIM** — item 20's *goal* reached by a different mechanism entirely.
>   `fim_run_container_baseline()` runs once from `main.c:493`; after that the change signal is the
>   kernel, not a lifecycle delta, classified into `rebaselineAll` / `rewalkContainer` /
>   `rereadPaths` / `deletePaths`.
>
> **The falsified premise.** This plan assumes a consumer cannot learn about a container created
> after its baseline without something publishing "a container appeared". Measured on 2026-09-08
> ([12 §12.16](12-blocking-decisions.md#1216-the-lifecycle-question-answered-by-measurement-2026-09-08)):
> a container created after the baseline is fully walked **within two seconds**, with five `added`
> alerts and no delta of any kind. `RT_CGROUP_MODE_ALL` means events from a cgroup the map has never
> seen still arrive; that files it unknown, `resolve` identifies it, and `noteContainerLocked()`
> returning `was_unknown` escalates it to a `rewalkContainer`.
>
> **What emits those first events is the container runtime, not the container.** A per-event trace
> showed exactly four, all `RT_EV_FILE_OPEN`, all from runc's init within one second of `docker run`:
> `/proc/<pid>/oom_score_adj`, the AppArmor `exec` label, and two `net.ipv4` sysctls. The container's
> own `sleep 3600` produced none, and an `execve` cannot produce any — read-only opens and
> non-regular files are dropped in the kernel (`rt_file.bpf.c:460`).
>
> So for container FIM this plan buys **latency, cost, and a guarantee**: bounded discovery latency
> instead of "whenever the runtime or the workload happens to write"; the ability to narrow
> `cgroup_mode` to `ALLOWLIST`, which is currently *unsafe* because the allowlist would have nothing
> in it; and a discovery path that does not depend on runc's startup behaviour. That last one is a
> weaker version of what an earlier revision of this note claimed — it said a container quiet enough
> to miss discovery "cannot exist", which is true of runc on Ubuntu and is not a property of this
> design. Full measurement in
> [12 §12.16](12-blocking-decisions.md#1216-the-lifecycle-question-answered-by-measurement-2026-09-08).
>
> **What did land from here, from elsewhere:** [D5](#d5--what-authorises-a-deletion-decided)'s last
> row. Both consumers now refuse to sweep against a set they could not obtain
> (`container_baseline_fim.cpp:672-685`, `syscollectorImp.cpp:2451-2466`), which closes §10.5's
> false-delete hole — the one defect here that never needed the journal. Its converse is now
> [C28](03-findings-correctness.md#c28--with-no-containers-list-reads-as-connector-unavailable): the
> server never sent an empty `containers` array, so "no containers" was indistinguishable from "no
> connector" and the sweep never ran on a container-free host (fixed, `7e059dd5aa`).
>
> **And §10.3's "one real hole" is bigger than stated.** The Docker `m_reconcilePending` bug is
> described here as upstream staleness that today's rescan equally masks. Measured 2026-09-08: it
> also strands *removed* containers, because `REMOVAL_GRACE` only expires inside `applySnapshot()`
> and nothing re-runs that on the Docker path without another event. A container removed with
> `docker rm -f` was still in `list` two minutes later; an unrelated `docker run --rm alpine true`
> flushed it within seconds. The rescan masks the missed create; nothing masks the missed expiry. So
> **Phase 0 is not only a prerequisite for this plan — it is a fix the current design needs** (see
> [C16](03-findings-correctness.md#c16--dockers-deferred-reconcile-is-dropped-not-deferred)).
>
> **What §10.6 D4 warned about, and is now live.** D4 says a baseline-once design without a
> reconciliation floor is strictly worse than the rescan it replaces. The FIM path is exactly that:
> no periodic floor, no `container_baseline_reconcile_interval`, and the only thing that re-runs the
> walk is the drain's own `rebaselineAll` — which fires on kernel loss, not on a schedule. In
> practice the escalation path above covers the case D4 was worried about, but only for containers
> that generate file activity; a container whose create event was lost upstream *and* which never
> touches a monitored path is still never baselined. syscollector's retained polling self-heals that
> within one interval, which is the honest reason its polling should not be removed before this
> plan's floor exists.

## 10.1 Problem statement

`container_baseline` re-scans **every container, every data class, every cycle**
(`syscollectorImp.cpp:2426` calls `scanContainerBaseline` from `scan()`, default interval 1 h;
`container_baseline_scanner.cpp:242` loops over the full discovery result). That is periodic polling
wearing a baseline's clothes, and it is what [06 §S2](06-proposed-architecture.md#61-the-four-structural-changes)
exists to remove.

To baseline a container **once, when it appears**, the consumer needs to know *which containers
appeared, disappeared or materially changed since it last asked*. `container_instances` has that
information — and does not publish it. Its only bulk query is `list`, a flat snapshot
(`query_service.cpp:63-70`), so both consumers reconstruct lifecycle by diffing the whole set against
their own state every cycle (`syscollectorImp.cpp:2328-2347`, `container_baseline_fim.cpp:386-388`).

Doc [06 §6.4](06-proposed-architecture.md#64-timing-model-and-the-one-change-that-makes-it-work)
proposed publishing `ReconcileDelta` (`reconciler.hpp:12-17`) over a new streaming `watch` op.
**Both halves of that proposal are wrong**, for reasons §10.2 and §10.4 establish. This document
replaces them.

## 10.2 Where the delta already exists — and why `ReconcileDelta` is not it

`diffSnapshot()` (`reconciler.hpp:32-67`) computes a three-way diff of one connector's snapshot
against that source's stored map, comparing on `containerId` and, for equality, on `recordEquals()`
(`reconciler.hpp:19-27` — every field of `ContainerRecord` except nothing; it is a full structural
compare including `labels`, `annotations`, `ownerRefs`, `network`, `ociMounts`, `cgroupId`,
`restartCount`).

`MetadataStore::applySnapshot()` (`metadata_store.cpp:129-235`) consumes it at line 137 and then
does four things the delta does not describe:

1. **`removed` is not removal.** For a removed id with a resolvable cgroup, the store only marks
   `ResolvedEntry::deletedAt` (`metadata_store.cpp:169-191`, `cache_entry.hpp:48-53`). The record
   stays in `m_bySource` and is therefore **still returned by `listContainers()`**
   (`metadata_store.cpp:108-127`) for `REMOVAL_GRACE = 60 s` (`metadata_store.hpp:16`). The real
   removal is `eraseResolvedLocked()` at grace expiry (`metadata_store.cpp:225-228`).
   Publishing `ReconcileDelta.removedContainerIds` as "removed" would tell consumers to delete a
   container's rows **60 s before `list` stops reporting it** — re-breaking the stopped-vs-gone
   contract that [09 item 1](09-implementation-status.md#done) just fixed.
2. **`listContainers()` filters on `cgroupId != 0`** (`metadata_store.cpp:118`). A record whose
   cgroup inode has not yet been joined is `added` in `diffSnapshot`'s eyes but **invisible** to
   `list`; it becomes visible on a later reconcile as an `updated`. A consumer driven by
   `diffSnapshot` would see the create event for a container it can never fetch, then never see
   another create.
3. **`upsertResolved()` bypasses the diff entirely** (`metadata_store.cpp:278-282`). It is called by
   both connectors' `refreshOne()` cold path (`docker_connector.cpp:158-181`,
   `kubernetes_connector.cpp:257-297`), which is how a container discovered by an eBPF `resolve`
   query enters the store. Those containers produce **no `ReconcileDelta` entry at all**.
4. **The contested-inode rule can `return` early** (`metadata_store.cpp:306-315`) leaving a record
   in `m_bySource` but not in `m_byCgroup`, so `list` visibility and diff visibility can disagree.

Additionally, `applySnapshot`'s liveness loop (`metadata_store.cpp:148-165`) clears `deletedAt` for a
container that reappears — so **a container that stops and restarts inside the 60 s grace produces
no delta entry whatsoever**, even though its PID, netns, processes and ports are all new.

**Conclusion.** The delta that exists internally is a *snapshot diff of one source's raw records*.
The delta a baseline consumer needs is *a transition log of the set `listContainers()` returns*.
They are different objects. The former must not be published.

### What the transitions can and cannot distinguish today

| Transition | Detectable from `ContainerRecord` today? | Where |
| --- | --- | --- |
| Container appeared | Yes | `diffSnapshot` `added`, once `cgroupId != 0` |
| Container gone | Yes, but only at grace expiry | `eraseResolvedLocked`, `metadata_store.cpp:324-359` |
| Container stopped (still known) | **Docker: no.** `/containers/json` is queried without `all=1` (`docker_api_client.cpp:114-127`), so a stopped container leaves the snapshot → grace → **erased and reported gone after 60 s**. K8s: yes, the `containerStatus` keeps its `containerID` (`k8s_object_parser.hpp:142-166`) |
| Image changed | Yes — `imageDigest` is in `recordEquals` | but in practice a new image means a new container id |
| K8s restart | Yes — new `containerId` ⇒ `removed` + `added` | `k8s_object_parser.hpp:147` |
| Docker restart, new PID | **No.** `RestartCount` (`docker_object_parser.hpp:49`) is bumped by the restart *policy*, not by `docker restart`. `State.Pid` and `State.StartedAt` are in the inspect body and **are not parsed**. `cgroupId` *probably* changes (the cgroup dir is recreated) but that is unverified — see §10.10 | `container_record.hpp:56-74` has no `pid`, no `startedAt`, no `state` |
| New mount added | Yes — `ociMounts` is in `recordEquals` | matters for the FIM mount-boundary rule (P0 item 5) |
| Anything else churning | Yes, and that is the problem: `labels`, `annotations`, `network` and `ownerRefs` all feed `recordEquals`, and K8s annotations churn constantly | `reconciler.hpp:19-27` |

The last row is decisive for item 23: **`updated` is far too noisy to be a re-baseline trigger.**
A pod IP being assigned, an owner chain resolving on the next `OwnershipPoller` generation
(`kubernetes_connector.cpp:81`, 120 s interval per `module_config.hpp`), or a controller writing an
annotation all produce `updated`. The published delta must carry a **change mask**, not a bare
"changed" verb.

## 10.3 Where lifecycle facts enter the module, and their latency

| Source | Mechanism | Ordering / gaps |
| --- | --- | --- |
| Docker | `/events` stream (`docker_connector.cpp:100-156`), `since=` captured **before** the seed (`:116-119`), `(id, action, timeNano)` dedupe (`:76-87`) | Events are **triggers only** — `handleEvent` discards the event content and calls `reSeed()`, a full `list` + `inspect`-each + cgroup scan (`:34-72`). Ordering therefore does not matter; the snapshot is authoritative. |
| Docker, gap | Full `reSeed()` on every (re)connect (`:119`) | Correct for daemon restarts. |
| **Docker, unbounded-latency hole** | `m_reconcilePending = true` at `docker_connector.cpp:93` is **never read anywhere** (write-only; cleared at `:71`). The debounce at `:94` therefore *drops* the deferred reconcile instead of deferring it. | The **last event of any burst inside a 500 ms window is lost** until another event arrives or the stream reconnects. There is **no periodic reconcile floor on the Docker path at all**. The Kubernetes connector does not have this bug — it reads the flag at `:142` and `:195`. |
| Kubernetes | `watch` on pods (`kubernetes_connector.cpp:186-224`), `resourceVersion` tracked (`:125-128`), `gone` ⇒ re-list (`:199-203`), 3 retries then a 60 s degraded cooldown and re-list (`:209-219`) | Watch events are ordered by `resourceVersion`; `gone` is the apiserver's own gap signal and is handled. |
| Kubernetes owners | `OwnershipPoller`, **polling by fixed decision** (`ownership_poller.hpp:17-22`), 120 s | A generation bump makes the next pod event reconcile (`:130-133`). |
| cgroup join | `ProcCgroupResolver::scan()` walks all of `/proc` on every reconcile (`proc_cgroup_resolver.cpp:39-96`) | **The PID is read at `:45-50` and thrown away** — only the first PID per distinct cgroup path is used, and only for its inode. |

So the producer side is snapshot-authoritative and mostly gap-tolerant, with **one real hole** (the
dead Docker `m_reconcilePending`). That hole is upstream of anything this plan builds, and under
today's periodic full rescan it is equally broken — a container whose create event landed at the tail
of a burst is missing from the *store*, so `list` does not report it either. Fixing it is Phase 0.

## 10.4 The current query surface, exactly

Wire format: one line of JSON in, one line of JSON out, **connection closed after one exchange**
(`ipc_server.cpp:199-241`, close at `:240`). Request cap 8192 bytes (`:24`), client read timeout 5 s
(`:25`). Worker pool default **2** (`ipc_server.hpp:26`).

```jsonc
// requests  (wire_protocol.hpp:79-143)
{"version":1,"op":"resolve","cgroup_id":"<decimal string>",   // cgroup_id mandatory
 "container_id":"...","pod_uid":"...","container_name":"..."} // optional secondary keys
{"version":1,"op":"list"}
{"version":1,"op":"status"}

// responses (wire_protocol.hpp:190-244)
{"version":1,"status":"resolved","data":{<record>}}
{"version":1,"status":"pending","retry_after_ms":500}
{"version":1,"status":"not_container","reason":"host_process|host_namespace|cgroupns_host|kata"}
{"version":1,"status":"ok","data":{"records":N,"pending":N,"verdicts":N,"connector":"..."},
                            "containers":[{<record>}, ...]}   // `containers` only for op=list
{"version":1,"status":"error","error":{"code":"bad_request|unsupported_version|internal","message":"..."}}
```

`<record>` is `recordToJson()` (`wire_protocol.hpp:146-188`): `runtime`, `container_id`,
`container_name`, `image`, `image_digest`, `restart_count`, `node_name`, `labels`, `cgroup_id` (a
**decimal string**, deliberately — `:52-53`), `network[]`, `oci_mounts[]`, plus the Kubernetes block
(`pod_uid`, `pod_name`, `namespace`, `annotations`, `owner_refs[]`) only when
`runtime == "kubernetes"`.

**Two version-handling facts that constrain everything below:**

1. `PROTOCOL_VERSION = 1` (`wire_protocol.hpp:15`) and the check is **strict equality**
   (`:87-92`): anything other than `1` gets `unsupported_version`. There is **no forward path** —
   bumping to `2` breaks every deployed client at once, including the eBPF enrichment `resolve` hot
   path.
2. An unknown `op` gets `bad_request` (`:112-115`), and for `op == "list"` the parser **returns
   immediately at `:107-111` without inspecting any other field**. Unknown fields on a `list`
   request are silently ignored. That is the seam this plan uses.

Client side (`container_instances_client.hpp`): header-only, synchronous, **connect-per-request**
(`:146-214`), 1000 ms default timeout (`:63-67`), all failures collapse to `unavailable` with no
distinction from "empty". `listContainers()` (`:81-138`) already parses the full record out of the
`list` reply into `ContainerRef::record` (P1 item 12).

## 10.5 The consumers, and the false-delete hole they have today

`container_baseline`'s discovery seam is `ContainerDiscoverer`
(`container_baseline_scanner.hpp:121`), backed by `DiscoverContainers()`
(`container_baseline_scanner.cpp:130-163`) — one `list` round-trip per run, invoked exactly once
(pinned by `DiscoveryIsInvokedExactlyOncePerRun`). Completeness travels back per container in
`ContainerStatus` (`container_baseline_scanner.hpp:52-72`): `partial`, `netns_host_scoped`,
`netns_unreadable`.

Both consumers derive deletions from set difference:

- **Syscollector**: `cbaseline_list_containers` fills `discoveredIds` (`syscollectorImp.cpp:2328-2338`),
  then `sweepContainerRowsNotIn(discoveredIds)` (`:2347`, implementation `:2039-2085`) emits DELETED
  for every container in the DB but not in that set. Within a container, deletion is suppressed
  per table by `detectDeletionsFor()` (`:2150-2173`) from the `ContainerStatus` flags, and a
  container's first sync is forced quiet (`:2185-2187`).
- **FIM**: `sweepStale(known)` (`container_baseline_fim.cpp:246-280`), same shape, over
  `fim_db_get_distinct_container_ids("file_entry")`.

**Live defect, not previously recorded in [03](03-findings-correctness.md).**
`DiscoverContainers` collapses "socket unavailable" into "empty vector"
(`container_baseline_scanner.cpp:135-150`; after the first success `g_everSawContainers` cuts the
retry to a single attempt, `:136`), `ListContainers` returns only a count
(`container_baseline_scanner.cpp:411-421`), the C glue passes it through
(`container_baseline.cpp:102-111`), and **neither consumer checks it** (`syscollectorImp.cpp:2338`,
`container_baseline_fim.cpp:386`). So if `container_instances` is down, restarting, or merely slow
past the 1 s client timeout at that moment, `keep`/`known` is empty and **every container's rows in
every table are deleted**. FIM is partly shielded by `fim_container_baseline_available()`
(`container_baseline_fim_bridge.c:280-299`, a 5 s socket-existence poll) but only up to the moment of
the check; syscollector has no availability gate at all. This is the same severity class as
[C1](03-findings-correctness.md#c1--fim-deletes-the-state-of-merely-stopped-containers-false-delete-storm)
and it exists **today**, independent of item 20.

FIM's driver runs exactly once, at startup, on syscheckd's `main()` thread (`main.c:486`), before
`realtime_start()` (`main.c:490-492`) — so FIM has no cycle to hang a delta poll on. That is item
14's thread-ownership decision, and item 20 cannot be delivered for FIM without it.

## 10.6 Decisions

### D1 — Pull with a cursor. Not a subscription. **Decided.**

Extend the existing `list` op with an optional cursor. Rejected: the `watch` op that
[06 §6.4](06-proposed-architecture.md#64-timing-model-and-the-one-change-that-makes-it-work)
proposed.

Why the subscription loses:

- **It starves the enrichment hot path.** `IpcServer` dispatches one connection per worker for the
  connection's whole lifetime (`ipc_server.cpp:180-197`), with `workerCount = 2` by default
  (`ipc_server.hpp:26`). Two long-lived watchers (syscheckd + syscollector) occupy **both** workers,
  and every eBPF-driven `resolve` then blocks in the accept backlog. Making `watch` safe means
  rewriting `IpcServer` into a single-threaded `poll()` event loop over all client fds — a
  restructuring of the module that owns the enrichment hot path, to buy latency this design does not
  need.
- **The client cannot host it.** `ContainerInstancesClient` is a header-only synchronous
  connect-per-request struct (`container_instances_client.hpp:146-214`). Streaming needs a
  background thread, reconnect/backoff, and a bounded receive queue *inside each consumer* — and
  neither consumer has a thread to put it on (FIM: `main.c:486`; syscollector: the scan thread).
- **It does not remove the pull.** A subscriber that falls behind, restarts, or reconnects still
  needs "you missed too much, full resync" — i.e. the epoch/cursor machinery of D3 has to exist
  either way. Push would add latency reduction on top, nothing more.
- **The pull is genuinely cheap.** A no-change poll is one connect + ~70-byte reply. At 15 s that is
  8 connections/minute across both consumers, against a server that today absorbs one `resolve` per
  eBPF cache miss.

Cost accepted: up to one poll interval of latency between container-create and baseline. At 15–30 s
that is far below the 1 h it replaces. §10.11 lists a cheap latency reducer if measurement ever shows
it matters.

### D2 — Publish from `MetadataStore`, not from `reconciler.hpp`. **Decided.**

§10.2 is the argument. Concretely: a `LifecycleJournal` owned by `MetadataStore`, appended from
inside `insertResolvedLocked()` (`metadata_store.cpp:284-322`) and `eraseResolvedLocked()`
(`:324-359`) under the same `unique_lock`. Those two functions are the chokepoints every mutation
path already goes through — `applySnapshot`, `upsertResolved`, and all three expiry sweeps.

**The invariant, stated once:**

> The journal is a log of transitions of exactly the set that `listContainers()` returns. For any
> two cursors `s1 < s2` with no ring overrun between them, applying the entries in `(s1, s2]` to the
> set observed at `s1` yields the set that `listContainers()` would have returned at `s2`.

Everything in §10.7's correctness argument reduces to that sentence. It also forces the journal to
respect the `cgroupId != 0` filter (`metadata_store.cpp:118`): a record inserted with `cgroupId == 0`
appends **nothing**, and the later insert that gives it a nonzero inode appends `added`. That is
exactly the transition a consumer can act on, and it is the one `diffSnapshot` gets wrong.

### D3 — Epoch + monotonic sequence + explicit `resync_required`. **Decided.**

- `epoch`: a `std::uint64_t` chosen once per `MetadataStore` construction (`std::random_device`).
  Changes iff the module restarted. A cursor from a different epoch ⇒ `resync_required`.
- `seq`: monotonic, incremented per journal entry, never reset within an epoch.
- The journal is a **bounded ring**, default 4096 entries. Entries hold a `ContainerRecordPtr`
  (`container_record.hpp:78`, already `shared_ptr<const ContainerRecord>`), so retaining one is a
  pointer copy, not a record copy.
- `since_seq < oldestSeq` (ring overrun) ⇒ `resync_required`.
- A `resync_required` reply **carries the full container list in the same round-trip**, so there is
  no window between "you must resync" and the resync.

Rejected: a single "generation" counter with no per-entry sequence (cannot tell *which* containers
changed, so it degenerates into today's full-set diff), and a per-consumer server-side subscription
registry (server-side state keyed by an unauthenticated client is exactly what the
connect-per-request design avoids).

### D4 — The reconciliation floor is mandatory, not a safety net. **Decided.**

Item 20 does **not** eliminate periodic work. It changes it from *"re-scan 11 data classes × N
containers, hourly"* to:

1. one cursor poll per interval (near-zero),
2. a **fingerprint sweep** of the image-derived tier every cycle (§10.9),
3. a **full re-baseline of every container** every `container_baseline_reconcile_interval`,
   default 24 h, `0` = never.

[06 §6.3](06-proposed-architecture.md#63-the-baselineebpf-handoff) lists long-interval reconciliation
as *"not the primary mechanism"*. I am making it **mandatory** for one reason a transport-level
epoch cannot cover: `resync_required` recovers from a *consumer* falling behind, but nothing recovers
from the **producer** never having learned about a container. The Docker `m_reconcilePending` hole
(§10.3) is a live instance of exactly that, and the general class — a connector bug, an inspect that
404'd during `reSeed` (`docker_connector.cpp:46-53`), a cgroup join that never happened — cannot be
detected from inside the delta at all. Under today's full rescan those failures self-heal within an
hour. Under baseline-once without a floor they are permanent. **A baseline-once design without a
reconciliation floor is strictly worse than the redundant rescan it replaces**, and that is the
sentence to hold onto.

### D5 — What authorises a deletion. **Decided.**

Replaces "absent from `list`" with a three-valued signal. The decision table extends
[06 §6.8](06-proposed-architecture.md#68-deletion-semantics-stated-once):

| Signal | Consumer action |
| --- | --- |
| `removed` journal entry | Sweep that container's rows in **all** tables. The entry only fires at grace expiry (`metadata_store.cpp:225-228`), so "stopped" has already been given its 60 s. |
| `added` | Baseline it; first sync quiet via `m_knownContainerIds` (`syscollectorImp.cpp:2185-2187`). |
| `changed` + a mask bit in §10.9's trigger set | Re-baseline the affected tiers. Delete detection **within** the container is unchanged: `detectDeletionsFor(table, absence)` (`syscollectorImp.cpp:2150-2173`) still governs, driven by the same `ContainerStatus` flags (`container_baseline_scanner.hpp:52-72`). |
| `changed`, no trigger bit | **Nothing.** Do not scan. Do not delete. |
| No entry for a container | **Nothing.** This is the change from today. |
| `resync_required` | Take the attached full list as authoritative, re-derive the known set, baseline unknown ids, sweep ids absent from it. Identical to today's behaviour — the fallback *is* the current design. |
| **Transport unavailable / `epoch` absent from the reply** | **Suppress all sweeping this cycle.** Never sweep against a set you could not obtain. |

The last row is the fix for §10.5's live defect and it composes with the existing `partial` /
`netns_host_scoped` / `netns_unreadable` rules by strict nesting: *the delta decides whether a
container's rows may be swept at all; `detectDeletionsFor` decides which of that container's tables
may be swept.* Neither can override the other into deleting more.

### D6 — `instance_id`, and adding `pid`/`started_at` to `ContainerRecord`. **Decided.**

Item 23 needs "the running instance changed". Nothing in `ContainerRecord` expresses that for Docker
(§10.2 table, row 7). Add two fields to `ContainerRecord` (`container_record.hpp:56-74`), both
already present in the API bodies the connectors parse:

- `startedAt` — Docker `State.StartedAt`, K8s `containerStatuses[].state.running.startedAt`.
  **This is the discriminator.** `cgroupId` and `restartCount` are corroboration at best (§10.10).
- `pid` — Docker `State.Pid`; for Kubernetes it must come from `CgroupEntry`, which reads it at
  `proc_cgroup_resolver.cpp:45-50` and discards it. Publishing it also completes roadmap item 11's
  *preferred* fix and lets `PidIndex::Build()`'s `/proc` sweep be deleted outright.

`instance_id` is then a store-computed opaque token over
`(containerId, startedAt, cgroupId, restartCount)`. Opaque on purpose: consumers must compare it, not
interpret it, so the composition can be corrected without a wire change.

### D7 — Compatibility: additive under version 1, degrading to today's behaviour. **Decided.**

Because the version check is strict equality (`wire_protocol.hpp:87-92`), **`PROTOCOL_VERSION` must
stay `1`.** The delta is added as optional fields on the existing `list` op:

| Direction | Behaviour |
| --- | --- |
| New client → old server | The old parser returns at `wire_protocol.hpp:107-111` **without reading any field beyond `op`**, so the cursor is silently ignored and a full list comes back. The reply has no `epoch`, so the client detects "no delta support" and falls back to full-set diff — **today's behaviour, no error path**. |
| Old client → new server | Sends no cursor; server returns the full list exactly as now. Additive by construction. |
| New client → new server | Cursor honoured. |

Rejected: a new `list_since` op — an old server answers `bad_request` (`:112-115`), so the client
needs explicit error-code-driven fallback, which is strictly more code and more failure modes than
"the field I asked for is absent". Rejected: bumping to version 2 — it breaks every deployed
`resolve` caller during a partial upgrade.

Recommended as a **separate small change**, not part of this work: relax the check to
`version <= PROTOCOL_VERSION`, so the protocol acquires a forward path it does not currently have.
Today a v2 is simply not reachable without a flag day.

## 10.7 Proposed API

### Internal — `IMetadataStore` (`cache/i_metadata_store.hpp`)

```cpp
/// A transition of the set listContainers() returns. `kind` is derived from
/// journal position, never from a raw snapshot diff (see §10.2).
struct LifecycleEvent
{
    enum class Kind : std::uint8_t { added, changed, removed };

    /// Which fields moved. Only meaningful for `changed`. A consumer that
    /// re-baselines on `identity` alone is correct but wasteful; one that
    /// ignores `mounts` will miss a newly declared FIM subtree.
    enum class Field : std::uint32_t
    {
        none        = 0,
        identity    = 1u << 0,  ///< instance_id moved: restart / new PID / new cgroup
        image       = 1u << 1,  ///< image or image_digest
        mounts      = 1u << 2,  ///< oci_mounts
        network     = 1u << 3,  ///< network[]
        metadata    = 1u << 4,  ///< labels, annotations, owner_refs, node_name, names
    };

    std::uint64_t      seq {0};
    Kind               kind {Kind::added};
    std::string        containerId;
    std::string        instanceId;   ///< empty for `removed`
    std::uint32_t      changed {0};  ///< bitmask of Field
    ContainerRecordPtr record;       ///< null for `removed`; otherwise the record AT `seq`
};

struct LifecycleCursor
{
    std::uint64_t epoch {0};
    std::uint64_t seq {0};
};

struct LifecycleDelta
{
    bool                        resyncRequired {false}; ///< epoch mismatch or ring overrun
    LifecycleCursor             cursor;                 ///< resume point; commit only after applying
    std::vector<LifecycleEvent> events;                 ///< empty when resyncRequired
    std::vector<ContainerRecordPtr> containers;         ///< full set, ONLY when resyncRequired
};

class IMetadataStore
{
public:
    // ... existing members unchanged ...

    /// Transitions in (cursor.seq, now]. A zero/foreign epoch, or a seq older
    /// than the ring holds, returns resyncRequired with the full set attached.
    [[nodiscard]] virtual LifecycleDelta lifecycleSince(const LifecycleCursor& cursor) const = 0;

    /// Current cursor without reading any events (for a cold consumer that has
    /// just taken a full list and wants to resume from there).
    [[nodiscard]] virtual LifecycleCursor lifecycleCursor() const = 0;
};
```

### Wire — additive fields on `op: "list"` (`ipc/wire_protocol.hpp`)

```jsonc
// request — both cursor fields optional; omitting either means "no cursor"
{"version":1,"op":"list","since_epoch":"17384927364512","since_seq":"4210"}

// reply, delta available
{"version":1,"status":"ok",
 "data":{"connector":"docker@/var/run/docker.sock",
         "epoch":"17384927364512","seq":"4231","delta":true},
 "events":[
   {"seq":"4225","kind":"added","container_id":"3f2b...","instance_id":"a91c...",
    "data":{ /* recordToJson(), unchanged */ }},
   {"seq":"4229","kind":"changed","container_id":"7d10...","instance_id":"55e0...",
    "changed":["identity","network"],
    "data":{ /* ... */ }},
   {"seq":"4231","kind":"removed","container_id":"b884..."}
 ]}

// reply, cursor unusable — full set attached, same round-trip
{"version":1,"status":"ok",
 "data":{"connector":"...","epoch":"17384927364512","seq":"4231",
         "delta":false,"resync_required":true},
 "containers":[{ /* recordToJson() */ }, ...]}

// reply, no cursor sent (an old client, or a cold consumer)
{"version":1,"status":"ok",
 "data":{"connector":"...","epoch":"17384927364512","seq":"4231","delta":false},
 "containers":[ ... ]}
```

`epoch`, `seq` and `since_seq` travel as **decimal strings**, for the reason already documented at
`wire_protocol.hpp:52-53`: cJSON-based consumers parse JSON numbers as `double` and corrupt silently
above 2^53. `changed` is an array of names rather than a bitmask integer, so an unrecognised future
field name is skippable rather than a silent misinterpretation.

`instance_id` and the two new record fields (`pid`, `started_at`) are added to `recordToJson()`
(`wire_protocol.hpp:146-188`) in the same additive way — an existing consumer ignores unknown keys.

### Client — `shared_modules/container_instances_client/include/container_instances_client.hpp`

```cpp
struct LifecycleEventRef
{
    std::string    kind;        ///< "added" | "changed" | "removed"
    std::string    containerId;
    std::string    instanceId;
    std::uint64_t  cgroupId {0};
    std::vector<std::string> changed;   ///< field names; empty unless kind=="changed"
    nlohmann::json record;              ///< as ContainerRef::record; null for "removed"
};

struct ContainerDelta
{
    bool          available {false};       ///< false = transport failure; DO NOT SWEEP
    bool          deltaSupported {false};  ///< false = old server, `containers` is a full list
    bool          resyncRequired {false};
    std::string   epoch;                   ///< opaque; hand back verbatim
    std::string   seq;
    std::vector<LifecycleEventRef> events;
    std::vector<ContainerRef>      containers; ///< populated iff !deltaSupported || resyncRequired
};

/// One round-trip. Pass an empty epoch/seq for a cold start.
[[nodiscard]] ContainerDelta listContainersSince(const std::string& epoch,
                                                 const std::string& seq) const;
```

`available == false` is the field that fixes §10.5. It must be a distinct value from
"`containers` is empty", and the existing `listContainers()` (`:81-138`) should gain the same
distinction.

### `container_baseline` C API (`include/container_baseline.h`)

```c
typedef enum {
    CB_LIFECYCLE_ADDED   = 0,
    CB_LIFECYCLE_CHANGED = 1,
    CB_LIFECYCLE_REMOVED = 2
} cb_lifecycle_kind_t;

/* Bitmask; mirrors LifecycleEvent::Field. Unknown bits must be treated as
 * "something changed I do not understand" => re-baseline, never ignore. */
#define CB_CHANGED_IDENTITY (1u << 0)
#define CB_CHANGED_IMAGE    (1u << 1)
#define CB_CHANGED_MOUNTS   (1u << 2)
#define CB_CHANGED_NETWORK  (1u << 3)
#define CB_CHANGED_METADATA (1u << 4)

typedef void (*cb_lifecycle_event_sink_t)(const char*         container_id,
                                          cb_lifecycle_kind_t kind,
                                          unsigned int        changed_mask,
                                          const char*         instance_id,
                                          void*               user_data);

/* Fetches lifecycle transitions since (`in_epoch`, `in_seq`); pass NULL/"" for a
 * cold start. On return `out_epoch`/`out_seq` hold the cursor to persist AFTER
 * the events have been applied.
 *
 * Return value:
 *   >= 0  number of events reported through `sink`
 *   CB_DELTA_RESYNC (-2)  cursor unusable; `sink` was invoked with
 *                         CB_LIFECYCLE_ADDED for every container that exists.
 *                         The caller MAY sweep ids absent from that set.
 *   CB_DELTA_UNAVAILABLE (-1)  the module could not be reached. `sink` was NOT
 *                         invoked. The caller MUST NOT sweep anything.
 */
EXPORTED int cbaseline_lifecycle_since(const char* connector_socket_path,
                                       const char* in_epoch,  const char* in_seq,
                                       char*       out_epoch, size_t out_epoch_len,
                                       char*       out_seq,   size_t out_seq_len,
                                       cb_lifecycle_event_sink_t sink,
                                       void*       user_data);

/* Baseline exactly the containers named in `container_ids`. Same row/status
 * callback contract as cbaseline_run_syscollector_dbsync() — rows for one
 * container are contiguous and followed by exactly one status callback. */
EXPORTED int cbaseline_run_syscollector_dbsync_for(const char*  connector_socket_path,
                                                   const char** container_ids,
                                                   int          container_count,
                                                   cb_dbsync_row_sink_t       sink,
                                                   cb_container_status_sink_t status_sink,
                                                   void*        user_data);
```

The `_for` variants need no new orchestrator: `ContainerDiscoverer`
(`container_baseline_scanner.hpp:121`) is already the injection point, and
`Run*DbsyncBaselineFrom` (`:130-142`) already takes it. A filtered discoverer is the whole change,
and the row-contiguity/status contract both consumers stream on is preserved by construction.

Also: **`cbaseline_list_containers` must gain a failure return** (`-1`), and its doc comment at
`container_baseline.h:148-157` must say that a negative return forbids sweeping. That is Phase 0 and
it stands alone.

## 10.8 Correctness under missed events

Enumerate every way a consumer can lose a transition, and name the recovery:

| Failure | Detection | Recovery | Invariant preserved |
| --- | --- | --- | --- |
| Agent/module restart | `epoch` differs from the persisted cursor | `resync_required` + full list in the same reply | Every existing container is reported `added`; unknown-to-`container_instances` ids are swept |
| Consumer restart (cursor not persisted) | Empty cursor | Cold start = full list, then resume from the returned `seq` | Same |
| Consumer slower than producer, ring overrun | `since_seq < oldestSeq` | `resync_required` | Same |
| Socket drop / timeout mid-poll | `available == false` | **Cursor is not advanced**; nothing swept; retry next interval | No transition is consumed, so none is lost. Sweep suppression prevents §10.5's false deletes |
| Consumer crashes *after* applying events, *before* persisting the cursor | Not detected | Events replay | Safe: re-baselining is idempotent — rows go through a scoped `DBSyncTxn` (`syscollectorImp.cpp:2201` → `:387-419`) which computes INSERTED/MODIFIED/DELETED against stored state, so a replayed `added` emits nothing if nothing changed. Persist **after** applying, never before |
| Docker daemon restart | Connector re-seeds on reconnect (`docker_connector.cpp:119`) | Store-side delta reflects the reseed; consumer sees `added`/`removed`/`changed` normally | — |
| K8s watch `resourceVersion` expired | `WatchOutcome::gone` (`kubernetes_connector.cpp:199-203`) | Re-list + reconcile ⇒ store-side delta | — |
| **Producer never learned of a container** (Docker debounce hole, `reSeed` 404, cgroup never joined) | **Not detectable from the delta** | **The reconciliation floor (D4), and only that** | This is why D4 is mandatory |

Two invariants, stated so they can be tested:

- **No container stays un-baselined.** A container is baselined if it appears as `added`, as
  `changed` with a trigger bit, in a `resync_required` full set, or in a floor cycle. The floor
  makes the union unconditional: if the delta path fails in any way, including silently, the
  container is baselined within one floor interval.
- **No removed container's rows linger.** Rows are swept on a `removed` entry, or on absence from a
  `resync_required` full set, or on absence during a floor cycle. Sweeping is suppressed only when
  the set could not be obtained (`available == false`) — a state that cannot persist past the next
  successful poll, and one in which no sweep is *correct* anyway.

## 10.9 Re-baseline triggers (item 23) and the tiering

Mapping the [06 §6.6](06-proposed-architecture.md#66-tiering-the-data-classes-s4) tiers onto the
journal:

| Journal signal | Image-derived (packages, users, groups, OS, services) | Event-maintained (FIM files, processes, ports) | Sampled (interfaces, addresses, protocols, hardware) |
| --- | --- | --- | --- |
| `added` | scan | scan | scan |
| `changed` \| `identity` (restart, new PID, new cgroup) | scan **only if** the `ImageContentCache` fingerprint moved — a restart preserves the writable layer, so `/etc/passwd` and the package DB are normally byte-identical | **must** scan: processes and ports are per-instance, and (item 21) the eBPF per-container filter must be re-attached against a fresh baseline | **must** scan: new netns |
| `changed` \| `image` | scan (the cache key moved anyway) | scan | scan |
| `changed` \| `mounts` | no | **must** scan the FIM walk: a newly declared mount destination is a subtree the mount-boundary rule (P0 item 5) now permits descending into, and the previous walk could not have covered it | no |
| `changed` \| `network` | no | no | scan |
| `changed` \| `metadata` only | no | no | no — but the `container_json` blob every row carries is now stale. See §10.10 |
| `changed` \| unknown bit | scan | scan | scan (fail toward re-scanning) |
| `removed` | sweep | sweep | sweep |
| eBPF ring-buffer drop (#37203-2) | — | re-baseline that container (item 21) | — |
| Floor tick | fingerprint sweep, scan only where it moved | full scan | full scan |

**The honest cost of item 20, stated plainly.** An `exec`-driven change inside a container —
`docker exec … apt-get install` — produces *no* `container_instances` event, *no* record change, and
no journal entry. Under an hourly full rescan that install shows up within an hour. Under
baseline-once it would show up only at the floor. That is a real regression and it must not be
buried.

The mitigation is already in the tree and costs almost nothing: `FingerprintImageSources(pid)`
(`image_content_cache.hpp:77`) is a handful of `stat()` calls over `/etc/passwd`, `/etc/group`, the
os-release candidates and each package-DB location. Re-fingerprinting 100 containers per cycle is
~500 `stat()`s — noise next to the 300 full `/proc` walks that were just removed. So the image-derived
tier keeps a **per-cycle change check** and only rescans where the fingerprint moved. That converts
"hourly full rescan" into "hourly stat sweep plus rescan of what actually changed" and reduces the
staleness window for that tier from the floor interval back to one cycle. Services stay excluded
from the cache and therefore from the fingerprint (`image_content_cache.hpp:33-36`), so the services
class genuinely does become floor-latency — acceptable, given
[07 §7.2](07-options-matrix.md#72-the-matrix) already records that its `state` is always `"unknown"`
and the class is of limited value.

### Interaction with item 22 — the dependency direction in the roadmap is backwards

`ImageContentCache` is constructed **per run** (`container_baseline_scanner.cpp:239`) and dies with
it. Its ~85% saving comes entirely from *within-cycle* reuse across replicas of one image. Under item
20 a cycle scans only the containers named in the delta — often one, often none — so **within-cycle
reuse goes to approximately zero and the cache's entire benefit evaporates unless it outlives the
run.**

[08](08-roadmap.md#p2--architecture-make-it-a-baseline) lists item 22 as unlocked *by* item 20.
It is the reverse: **item 22 must land with or before item 20's Phase 3**, or Phase 3 is a
regression for the image-derived tier on a replica-heavy node (20 replicas appearing at once would be
scanned 20 times, where today they are scanned once). What item 20 changes is that the cache becomes
*worth* keeping across runs, because the fingerprint check (§10.9) is now the routine path rather
than a within-cycle optimisation.

Lifetime, concretely: move the cache onto the long-lived `BaselineService` object item 29 wants; keep
the `image_digest` + fingerprint key unchanged (the fingerprint is exactly what makes a cross-run
cache safe — `image_content_cache.hpp:26-32`); bound it with an LRU cap (~32 digests) and drop
entries whose digest is absent from every live container after a floor tick.

## 10.10 Phased implementation

Ordered so each phase is independently mergeable and the first one is a standalone bug fix.

### Phase 0 — de-risk, no new API (S)

1. `cbaseline_list_containers` returns `-1` on transport failure; `DiscoverContainers`
   (`container_baseline_scanner.cpp:130-163`) stops collapsing unavailability into an empty vector;
   both consumers skip the sweep on a negative return (`syscollectorImp.cpp:2338-2347`,
   `container_baseline_fim.cpp:386-388`). **Fixes a live false-delete class** (§10.5), independent of
   everything below.
2. Make `docker_connector.cpp`'s deferred reconcile actually fire: `m_reconcilePending` is write-only
   (`:93`), so the last event of a burst is dropped. Either check it after `streamEvents` returns (as
   `kubernetes_connector.cpp:195` does) *and* on a read deadline inside the stream loop, or drop the
   debounce for lifecycle-relevant actions. **Without this the delta has an unbounded-latency hole at
   its source.**

Deliverable: two contained fixes, both testable, neither touching the wire.

### Phase 1 — the journal, internal only (S–M)

`LifecycleJournal` + `lifecycleSince()`/`lifecycleCursor()` on `IMetadataStore`, appended from
`insertResolvedLocked`/`eraseResolvedLocked` (D2). No wire change, no consumer change. `instanceId`
is computed here from whatever `ContainerRecord` carries at this point, so Phase 4 can improve its
composition without touching anything else.

**Smallest first useful step, and it is genuinely useful on its own:** the journal makes the store's
lifecycle behaviour observable and therefore testable. Several claims in §10.2 — the grace-window
visibility of a stopped container, the `cgroupId == 0` invisibility window, `upsertResolved` bypassing
the diff — are currently unverifiable from outside the store.

### Phase 2 — the wire, nothing consuming it (S)

Optional `since_epoch`/`since_seq` on `list`; reply gains `epoch`, `seq`, `delta`, `events[]`,
`resync_required`. Client gains `listContainersSince()`. `container_baseline` gains
`cbaseline_lifecycle_since()` and the `_for` run variants. Baseline behaviour unchanged.

Mergeable and end-to-end testable (a `status`-shaped smoke test against a running module) with zero
behavioural risk, and it lets the two consumers be migrated independently afterwards.

### Phase 3 — syscollector goes delta-driven (M)

`scanContainerBaseline` (`syscollectorImp.cpp:2087-2360`) becomes:

```
cursor := persisted (m_containerCursor)
d := cbaseline_lifecycle_since(cursor)
if d unavailable            -> log, return, sweep nothing, cursor unchanged
if d resync_required        -> today's path exactly: full list, baseline unknown, sweep absent
else                        -> baseline ids from added / changed-with-trigger;
                               sweep ids from removed;
                               fingerprint-sweep the image-derived tier for all known ids
if floor elapsed            -> full re-baseline of every known id
persist cursor              (AFTER applying, never before)
```

Requires item 22 to have landed (§10.9). Config: `container_baseline_reconcile_interval` (default
24 h) and a poll cadence — note that syscollector's own interval (default 1 h) is *already* the poll
cadence, so no new timer is needed unless a shorter create-to-baseline latency is wanted, in which
case the cursor poll needs its own 15–30 s timer.

FIM is **not** in this phase. It has no cycle at all (`main.c:486`, one shot on `main()`), so giving
it a delta poll is item 14's thread-ownership decision and should be sequenced with it rather than
smuggled in here.

### Phase 4 — `instance_id` earns its name (M)

Add `startedAt` and `pid` to `ContainerRecord`, parse them (`docker_object_parser.hpp:43+`;
`k8s_object_parser.hpp:142-166`; `CgroupEntry` in `i_cgroup_resolver.hpp:20-29` for the K8s pid),
publish them in `recordToJson()`, and recompose `instanceId` over them. Then the item 23 trigger
table (§10.9) is fully implementable, and `PidIndex::Build()`'s `/proc` sweep can be deleted
(roadmap item 11's preferred fix, `proc_cgroup_resolver.cpp:45-50` already has the data).

### Phase 5 — out of scope here

Item 21 (the handoff), which needs #37203-2's event contract and its overflow signal, and FIM's
migration behind item 14.

## 10.11 Optional, only if measurement demands it

If create-to-baseline latency ever needs to be sub-second, the cheap option is **not** a streaming
`watch` (D1). It is a level-triggered hint that costs no IPC worker: the module writes the current
`epoch:seq` into `queue/sockets/container_instances.epoch` on every journal append; consumers `stat`
or read that file at high frequency and issue the `list` cursor call only when it moved. One `stat`
per check, no connection, no server-side state, and it degrades to the poll interval if the file is
missing. Cost: one more file to create, permission and unlink correctly. **Not recommended for the
first pass** — 15–30 s is already 120× better than the hour it replaces, and this should be driven by
the item 39 node-level benchmark, not by taste.

## 10.12 Test plan

`ci_impl/tests/` **does not exist** — `container_instances/CMakeLists.txt:70-81` guards for its
absence with a `message(WARNING)` (it was lost in the rebase, [09 environment note 1](09-implementation-status.md#environment-notes-found-while-verifying)).
Phase 1 therefore has to create that tree, which is real work and should be estimated as such.

**New: `ci_impl/tests/CMakeLists.txt`, `ci_impl/tests/metadata_store_test.cpp`**

| Case | Pins |
| --- | --- |
| `AddedIsPublishedOnlyOnceTheCgroupInodeIsKnown` | The `cgroupId == 0` window (`metadata_store.cpp:118`): first insert with inode 0 appends nothing; the insert that supplies the inode appends `added` |
| `RemovedIsPublishedAtGraceExpiryNotAtSnapshotAbsence` | 60 s grace (`metadata_store.hpp:16`): absence from a snapshot appends nothing and `listContainers()` still reports the container; only the expiry sweep appends `removed` |
| `StopAndRestartInsideGracePublishesAChangedIdentityEvent` | The §10.2 hole. **Expected to fail until Phase 4** — record it as a known gap rather than deleting it |
| `UpsertResolvedFromTheColdPathIsPublished` | `upsertResolved` (`:278-282`) bypasses `diffSnapshot`; the journal must still see it |
| `JournalMirrorsListContainersExactly` | The D2 invariant, as a property test: random insert/erase/snapshot sequences, then assert `apply(events, set@s1) == listContainers()@s2` |
| `ContestedInodeDoesNotDesynchroniseTheJournal` | `metadata_store.cpp:306-315`'s early `return` |
| `RingOverrunReportsResyncRequiredWithTheFullSet` | Ring bound + the attached full set |
| `ForeignEpochReportsResyncRequired` | Module restart |
| `SeqIsMonotonicUnderConcurrentWriters` | The `applySnapshot` (connector thread) vs `upsertResolved` (IPC worker) threading contract at `i_metadata_store.hpp:39-42` |
| `ChangeMaskDistinguishesMetadataChurnFromIdentityChange` | Item 23: an annotation-only change must not set `identity` |

**New: `ci_impl/tests/wire_protocol_test.cpp`**

| Case | Pins |
| --- | --- |
| `ListWithoutACursorIsByteIdenticalToTheV1Reply` | D7, old client → new server |
| `ListIgnoresAnUnknownCursorFieldShape` | Garbage `since_seq` degrades to a full list, never to an error |
| `EpochAndSeqAreDecimalStrings` | `wire_protocol.hpp:52-53`'s 2^53 rule, applied to the new fields |
| `ChangedIsAnArrayOfNames` | Forward-compatibility of the mask |
| `ProtocolVersionStaysOne` | A regression guard on D7 — this test's failure is the signal that someone bumped the version and broke every deployed `resolve` caller |

**New: `container_instances_client` tests** (there are none today) — `listContainersSince` against a
scripted fake server: `AvailableFalseOnSocketMissing`, `DeltaSupportedFalseWhenTheReplyHasNoEpoch`,
`ResyncRequiredCarriesTheFullList`.

**Extend `container_baseline_impl/tests/container_baseline_scanner_test.cpp`** (17 cases today; the
`ContainerDiscoverer` seam at `container_baseline_scanner.hpp:121` makes all of these fakeable):

| Case | Pins |
| --- | --- |
| `OnlyContainersInTheDeltaAreScanned` | The core of item 20 |
| `RowContiguityAndStatusOrderingSurviveAFilteredDiscoverer` | The contract both consumers stream on, re-pinned for the `_for` path |
| `UnknownChangeMaskBitForcesARescan` | Fail-toward-rescanning |
| `MountsChangeRescansTheFimWalkButNotThePackageDb` | §10.9's row 4 |

**Extend the syscollector consumer** (it has no tests — [09 item 30](09-implementation-status.md#not-done--deliberately-deferred);
needs the DBSync test double that item is blocked on):

| Case | Pins |
| --- | --- |
| `UnavailableDeltaSweepsNothing` | §10.5's live defect. **Write this one in Phase 0**, before any delta code exists |
| `ResyncRequiredBehavesExactlyLikeTodaysFullListPath` | The fallback is the current design |
| `CursorIsPersistedOnlyAfterEventsAreApplied` | The crash-window argument in §10.8 |
| `ReplayedAddedEmitsNoEvents` | The idempotence the whole recovery story rests on |
| `FloorTickReBaselinesEverything` | D4 |

## 10.13 Open questions and what I could not verify

1. **Does `docker restart` change the container's cgroup inode?** §10.2 and D6 lean on `startedAt`
   precisely so this does not have to be true, but if it *is* reliably true then `cgroupId` alone
   would be a sufficient discriminator and Phase 4 shrinks. Needs an experiment on a real node with
   both the cgroupfs and systemd cgroup drivers. **Cannot be tested in WSL** — same constraint as
   [09 environment note 2](09-implementation-status.md#environment-notes-found-while-verifying) and
   roadmap items 39–40.
2. **Should Docker's `listContainers` pass `all=1`?** Today it does not
   (`docker_api_client.cpp:114-127`), so a container stopped for more than the 60 s grace is reported
   *gone* and its rows are deleted — which contradicts row 3 of
   [06 §6.8](06-proposed-architecture.md#68-deletion-semantics-stated-once) and the "stopped-vs-gone
   handling is correct" claim in [09](09-implementation-status.md#done). `all=1` would fix it but
   changes what "known to `container_instances`" means for every consumer including the eBPF
   enrichment path, and it would put exited containers into the `list` reply indefinitely. **This is
   the `container_instances` owner's decision, not mine** — but the semantics need writing down
   either way, because two consumers are deriving deletions from it.
3. **Ring size and floor interval defaults.** 4096 and 24 h are placeholders. Both should come from
   the item 39 node-level benchmark (churn rate at N=100, and the observed frequency of the
   producer-side gaps D4 exists to cover), not from this document.
4. **The `metadata` change class and the per-row `container_json` blob.** A label-only change makes
   the blob copied into every stored row (P1 item 17) stale, but re-baselining a container to refresh
   a label is absurd. If item 17's container dimension row lands, a metadata-only `changed` becomes a
   single-row update and the question dissolves. Until then there is no good answer, and I am
   deliberately not inventing one: §10.9 says "no action" and accepts stale labels on stored rows.
5. **Whether item 21 wants the journal or something else.** The handoff needs an eBPF *event*
   sequence watermark per container (`S0`/`S1` in
   [06 §6.3](06-proposed-architecture.md#63-the-baselineebpf-handoff)), which is #37203-2's
   sequence space, not this journal's. I have assumed the two are independent and that
   `instance_id` is the join key between them. **That assumption needs confirming against #37203-2's
   contract**, and if it is wrong the `instance_id` composition (D6) is the piece that changes.
6. **FIM's thread ownership.** Phase 3 deliberately excludes FIM. Whether FIM's delta poll belongs on
   its own thread, on the realtime thread, or in a shared `BaselineService` thread serving both
   consumers is item 14's call and interacts with item 21's ordering. I have not tried to pre-empt it.
7. **Not compiled or run.** Everything here is static reading of `d8e4cd5704`. No build or test was
   executed for this document; the signatures in §10.7 are designs, not verified-compiling code.

## 10.14 Contradictions with the existing design docs

Recorded explicitly so they can be corrected rather than propagated:

1. **[06 §6.4](06-proposed-architecture.md#64-timing-model-and-the-one-change-that-makes-it-work) —
   "add a `watch` op that streams `ReconcileDelta` as NDJSON".** Both halves are wrong. `watch`
   starves the 2-worker enrichment server (D1), and `ReconcileDelta` is a snapshot diff of raw
   records, not a transition log of the published set — publishing its `removedContainerIds` would
   delete a stopped container's rows 60 s early (§10.2).
2. **[08](08-roadmap.md#p2--architecture-make-it-a-baseline) — item 22 is unlocked *by* item 20.**
   Reversed: item 20 destroys the within-cycle reuse that item 22's saving comes from, so 22 must land
   with or before 20's Phase 3 (§10.9).
3. **[06 §6.3](06-proposed-architecture.md#63-the-baselineebpf-handoff) — long-interval
   reconciliation is "*not* the primary mechanism".** True but under-stated. It is the *only*
   mechanism that recovers from a producer-side gap, so it is mandatory rather than a safety net
   (D4).
4. **[09](09-implementation-status.md#done) item 1 and
   [06 §6.8](06-proposed-architecture.md#68-deletion-semantics-stated-once) row 3 — "a stopped
   container's rows are left untouched".** True for Kubernetes; for Docker it holds only for 60 s,
   because `/containers/json` is queried without `all=1` (open question 2).
5. **`docker_connector.hpp:20-23`'s class comment** implies the reconcile-on-event path is
   gap-covered. `m_reconcilePending` is write-only (`docker_connector.cpp:93`), so the last event of
   any 500 ms burst is dropped with no periodic floor to recover it (§10.3).
6. **Not previously recorded anywhere:** if `container_instances` is unreachable at the moment either
   consumer asks, the empty list is treated as authoritative and **every container's rows are
   deleted** (§10.5). Severity class of
   [C1](03-findings-correctness.md#c1--fim-deletes-the-state-of-merely-stopped-containers-false-delete-storm);
   belongs in [03](03-findings-correctness.md) and in P0.
