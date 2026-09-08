# 06 — Proposed architecture

This is the design I would take forward. It keeps the branch's correct central decision
(`/proc/<pid>/root` addressing, zero new dependencies) and changes the four structural choices that
cause the findings in [03](03-findings-correctness.md), [04](04-findings-performance.md) and
[05](05-findings-clean-design.md).

## 6.1 The four structural changes

| # | Current | Proposed |
| --- | --- | --- |
| S1 | The **result set** is the unit of work: scan everything, buffer it all, then write. | The **container** is the unit of work: open its transaction, stream its rows into it, commit, move on. |
| S2 | **Everything is re-scanned** on a fixed cadence (hourly for Syscollector) or never again (FIM). | **Baseline once per container lifetime**, then maintain by event; re-baseline only on explicit triggers. |
| S3 | Rows are **self-contained** — the container context blob is copied into every row. | Rows **reference** a container dimension row; context is stored once. |
| S4 | Data classes are **uniform** — all eleven scanned identically, every cycle. | Data classes are **tiered** by volatility: image-derived, event-maintained, sampled. |

S2 is the one that matters most: it is what makes the feature a *baseline* (which the eBPF stream then
diffs, as #37532 intends) rather than a container-shaped re-implementation of periodic polling.

## 6.2 Component structure

```
                     ┌──────────────────────────────────────┐
                     │      container_instances (#37203-1)  │
                     │  + publish pid, cgroupPath           │  ← additive change
                     │  + `watch` op (lifecycle push)       │  ← additive change
                     └───────────────┬──────────────────────┘
                                     │ 1 × list  (full records; no per-container resolve)
                                     ▼
┌───────────────────────────────────────────────────────────────────────────────┐
│ BaselineService                     (owns all per-run state; no globals)      │
│                                                                               │
│  ContainerRegistry     known containers, generation, baseline status          │
│  ImageContentCache     image_digest → {packages, users, groups, os, services} │
│  PidIndex              one /proc sweep, or PIDs straight from the record      │
│  Budget                files/sec (check_max_fps), cycle deadline, row caps    │
│                                                                               │
│  AsyncValueDispatcher<ContainerTask>  (N=2..4 workers)   ← collection only    │
│        │                                                                      │
│        ▼                                                                      │
│  ContainerScan  ──  ContainerHandle {rootfs_fd, netns_fd, scope}              │
│        │                                                                      │
│        │  IContainerCollector[]  (file, process, port, user, group, package,  │
│        │                          os, iface, addr, protocol, service, hw)     │
│        ▼                                                                      │
│  RowSink (streamed, back-pressured)                                           │
└───────────────────────────────┬───────────────────────────────────────────────┘
                                │ serialised hand-off (one container at a time)
                                ▼
              ┌──────────────────────────────────────────┐
              │ Consumer: scoped DBSync txn per container│
              │  FIM: file_entry   Syscollector: 11 tbls │
              └──────────────────────────────────────────┘
```

Collection fans out across workers; **DB writes stay serialised**, because `DBSyncTxn` and
`m_knownContainerIds` are not thread-safe (`syscollector.hpp:488` is a plain `std::set`). That split
gets the I/O parallelism where it matters without touching the delta engine's threading model.

## 6.3 The baseline↔eBPF handoff

> **Read [§6.10](#610-corrections--the-sketch-versus-the-implemented-contract) first.** This section
> was written before #37396's engine existed, against an assumed contract. Four of its premises were
> wrong, one of its steps is actively unsafe, and two more defects were found only by measuring the
> real engine. The *shape* — subscribe-first, scan, reconcile-by-re-read — survived and is what
> shipped; the details below did not. §6.10 says what each one became.

This is #37532's stated "correctness core" and is entirely missing today
([D4](02-requirements-gap.md#22-deliverables)). The FIM path currently does the *worst* available
ordering — it baselines and only then calls `realtime_start()` (`main.c:308-318`), so every change
during the scan is lost.

### Algorithm: subscribe-first, scan, reconcile-by-re-read

```
per container C:
  1. SUBSCRIBE   attach the eBPF filter for C; buffer its events in a bounded
                 per-container queue. Record S0 = current event sequence.
  2. SCAN        walk / collect, streaming rows into C's scoped transaction.
                 Record S1 = sequence at completion.
  3. RECONCILE   drain the buffer. For each buffered event on path P:
                   - P not visited by the scan       → apply as a normal change
                   - P visited, event seq in (S0,S1] → RE-READ P now; emit one
                                                       diff (baseline row → current state)
                   - (no event can predate S0: the scan started after S0)
  4. COMMIT      mark C baselined at S1; from here events apply directly,
                 unbuffered.
```

**Why this is correct.**

- *No lost change.* Subscription precedes the scan, so no event in the window is dropped. An event
  before `S0` cannot be missed either: the scan reads the file *after* `S0`, so the file's state
  already embodies that event.
- *No double-count.* Events in the ambiguous window are not applied blindly. They trigger a
  **re-read**, and exactly one diff is emitted per affected path, computed against the row the
  baseline actually stored. The re-read makes the result independent of whether the event landed
  before or after the walk touched that file — which is what removes the need to store a per-file
  read timestamp, and with it the whole class of ordering bugs a watermark scheme has to reason
  about.
- *Bounded cost.* Only paths that genuinely changed during the scan window are re-read — normally a
  handful.

**Buffer overflow is a first-class outcome, not an error.** If C's queue fills, or #37203-2 signals a
ring-buffer drop for C, mark C's baseline *suspect* and re-run step 1–4 for C. This is safe because
**a re-baseline is idempotent**: rows are pushed through a scoped DBSync transaction, which computes
INSERTED/MODIFIED/DELETED against what is already stored. Re-running produces no events if nothing
changed. That single property is what lets every recovery path be "just re-baseline C".

### Re-baseline triggers

| Trigger | Source | Action |
| --- | --- | --- |
| Agent start | — | Baseline every running container (bounded pool, budgeted). |
| Container create | `container_instances` lifecycle | Baseline that container only. |
| Container restart | `restart_count` / new container id | Fresh baseline; the previous id's rows age out as DELETED. |
| eBPF ring-buffer drop | #37203-2 backpressure signal | Re-baseline the affected container. |
| Handoff buffer overflow | This algorithm | Re-baseline that container. |
| Config reload widening scope | `syscheck` / syscollector reload | Baseline newly in-scope containers; **reuse the existing first-sync guard** (`m_knownContainerIds` + `notifyOverride`, `syscollectorImp.cpp:1961-1963`) so a reload does not re-alert or drop the seed — this directly addresses the known first-sync-after-reload data-loss class. |
| Long-interval reconciliation | Timer (e.g. 24 h) | Safety net against silent event loss — **not** the primary mechanism. |

## 6.4 Timing model, and the one change that makes it work

The blocker is that `container_instances` is **poll-only**: `Op` is `{list, resolve, status}`, there
is no subscribe, and the server closes the connection after one request/response
(`ipc_server.cpp:240`). It *computes* the lifecycle delta internally —

```cpp
struct ReconcileDelta {
    std::vector<ContainerRecord> added;
    std::vector<ContainerRecord> updated;
    std::vector<std::string>     removedContainerIds;
};
```
`ci_impl/src/cache/reconciler.hpp:12-17`

— and then discards it at the store boundary, even though the upstream Docker `/events` stream and
the Kubernetes watch already feed it.

**Preferred:** add a `watch` op that holds the connection open and streams `ReconcileDelta` as NDJSON
(the client already has an NDJSON framer, `ci_impl/src/transport/ndjson_framer.hpp`). Consumers then
baseline on container-create and never poll.

**Interim, no protocol change:** poll `list` on a short timer (30–60 s). This is *one* IPC call
returning full records — negligible next to today's 1+N resolve storm — and diff the returned ids
against `ContainerRegistry`. Baseline only ids that are **new**; do nothing for ids already
baselined. This alone converts Syscollector's hourly full re-scan into "baseline once, maintain
after", and gives FIM the container-create trigger it completely lacks.

## 6.5 The collector seam

Today each scanner is a free function taking a `pid_t`, which hardcodes both the addressing scheme
and the liveness strategy, and makes the orchestrator untestable
([D13](05-findings-clean-design.md#d13--test-coverage-inverted-against-risk)).

```cpp
// A container's addressing handle. Constructed once per scan; the held fds pin
// the namespace references, so a PID exiting mid-scan cannot invalidate them.
class ContainerHandle {
public:
    int  rootfsFd() const;      // O_PATH fd on /proc/<pid>/root
    int  netnsFd()  const;      // fd on /proc/<pid>/ns/net
    ScopeKind netScope() const; // Container | HostCollapsed  (C4)
    ScopeKind pidScope() const;
    const IdMap& uidMap() const;  // /proc/<pid>/uid_map  (C7)
};

class IContainerCollector {
public:
    virtual ~IContainerCollector() = default;
    virtual Tier tier() const = 0;                       // ImageDerived | EventMaintained | Sampled
    virtual void collect(const ContainerHandle&, IRowSink&) = 0;  // streams, never accumulates
};
```

Three properties follow directly:

1. **Holding `rootfsFd`/`netnsFd` for the scan's duration fixes [C10](03-findings-correctness.md#c10--arbitrary-pid-selection-with-no-liveness-strategy)** — an exiting PID can no
   longer invalidate the walk mid-flight, and `openat`-relative traversal replaces string
   concatenation of `/proc/<pid>/root/...`.
2. **`netScope()`/`pidScope()` fix [C4](03-findings-correctness.md#c4--hostnetwork--hostpid-collapse-is-undetected-host-state-attributed-to-a-container)** — compare `/proc/<pid>/ns/{net,pid}` against `/proc/1/ns/{net,pid}`; on
   collapse, emit no container-scoped network rows and record the collapse as an attribute instead of
   silently reporting host state as container state.
3. **`uidMap()` fixes [C7](03-findings-correctness.md#c7--uidgid-semantics-are-inconsistent-between-data-classes-and-wrong-under-user-namespaces)** — translate file `st_uid`/`st_gid` into the container's id space, then
   resolve `owner`/`group` names by joining against the user/group rows already collected for that
   container.

Longer term, the in-idiom form of this seam is `class ContainerSysInfo : public ISysInfo`, since
`ISysInfo` is already an injection point in three modules (`syscollector.hpp:53`,
`agent_info_impl.hpp:54`, `sca_policy_check.hpp:141`). That requires threading a rootfs prefix or
`IFileSystemWrapper` through sysinfo's Linux collectors, which today construct the concrete wrapper
on the stack ([D7](05-findings-clean-design.md#d7--there-is-no-way-to-point-sysinfo-at-a-rootfs-and-that-is-the-real-architectural-gap)) — a worthwhile but separate piece of work.

## 6.6 Tiering the data classes (S4)

| Tier | Classes | Cadence | Rationale |
| --- | --- | --- | --- |
| **Image-derived** | packages, users, groups, OS, services | Once per `image_digest`; invalidate on container restart or writable-layer mtime change | Pure image-layer content. 20 replicas of one image ⇒ **one** scan, not 20 ([P6](04-findings-performance.md#p6--no-image-digest-de-duplication-the-single-largest-available-saving-never-attempted)). |
| **Event-maintained** | FIM files, processes, ports | Baseline once, then eBPF | This is the tier #37532 exists for. |
| **Sampled** | interfaces, addresses, protocols, hardware | Low-frequency refresh with volatile fields excluded | No eBPF coverage, and mostly counters rather than state ([C9](03-findings-correctness.md#c9--volatile-counters-in-state-rows-make-every-periodic-scan-a-full-change-event)). |

The `ImageContentCache` keys on `image_digest`, which `ContainerContext` already carries. Caveat to
document: a container *can* modify `/etc/passwd` or its package DB in its writable layer, so the cache
must be invalidated by the upper layer's mtime, or the trade-off made configurable and stated.

### Volatile fields — use the mechanism that already exists

DBSync already supports suppressing change detection on named columns:

```cpp
auto itIgnoredFields { it->find("ignore") };
if (it->end() != itIgnoredFields) {
    ignoredColumns = itIgnoredFields->is_array() ? itIgnoredFields.value() : ignoredColumns;
}
```
`shared_modules/dbsync/src/sqlite/sqlite_dbengine.cpp:172-180`, applied at `:1568-1602`;
builder at `dbsync.cpp:1095` (`SyncRowQuery::ignoreColumn`).

The **only** in-tree use is `input["options"]["ignore"] = {"sync"}` in `setVersion()`
(`syscollectorImp.cpp:3236`). Extending `updateChanges` to take a per-table ignore list is *wiring,
not new machinery*, and it fixes the host path too.

Important detail: `getItemChecksum` hashes `item.dump()` — the **whole row**
(`syscollectorImp.cpp:184-190`) — and that checksum feeds the manager-side integrity comparison. So
volatile columns must be excluded from **both** the ignore list and the checksum, or the row checksum
churns even when no MODIFIED event fires. FIM's own checksum is already an explicit field allowlist
(`file.c:712-753`) — that is the pattern to copy.

## 6.7 Budgets and back-pressure (NFR3)

| Control | Value | Mechanism |
| --- | --- | --- |
| Files/second | `syscheck.max_files_per_second` | **Call the existing `check_max_fps()`** (`run_check.c:462`, declared `syscheck.h:201`). Process-global, so the container walk correctly shares one budget with the host walk. |
| Concurrent container scans | 2–4, configurable | `Utils::AsyncValueDispatcher(fn, N, maxQueued)` (`asyncValueDispatcher.hpp:46`) |
| Per-cycle deadline | configurable | On expiry, stop and **resume from the next container** next cycle; rotate order so a node too large to fully baseline in one cycle still converges rather than starving its tail. |
| Rows per container / per cycle | configurable | Replaces the hardcoded `max_files = 20000` / `max_hash_bytes = 100 MiB` (`container_baseline_fim_bridge.c:157-212`). |
| Hash size limit | `syscheck.file_max_size` | **Skip and blank the digests** above the limit, as host FIM does — never emit a prefix digest ([C2](03-findings-correctness.md#c2--truncated-hashes-are-emitted-as-if-they-were-whole-file-hashes)). |
| Mount-boundary policy | `oci_mounts` + `st_dev` + `skip_fs` | Descend into declared volume mounts; refuse anything else, never the host root ([C8](03-findings-correctness.md#c8--the-file-walk-has-no-mount-boundary-guard-and-can-escape-into-the-host-filesystem)). |
| Partial-baseline flag | per container | On truncation or deadline, mark the baseline partial and **suppress deletes** for that container, so absence is never read as removal ([C1](03-findings-correctness.md#c1--fim-deletes-the-state-of-merely-stopped-containers-false-delete-storm), [C6](03-findings-correctness.md#c6--truncation-and-missing-path-signals-are-computed-then-discarded)). |

Neither consumer may run this on a thread others depend on: FIM must move it off syscheckd's
`main()`, and Syscollector must move it off the scan thread's critical path.

## 6.8 Deletion semantics, stated once

Absence of a row must never by itself imply deletion. The decision table:

| Container state | Rows produced | Correct action |
| --- | --- | --- |
| Known, live, scan complete | full set | Normal diff; absent rows ⇒ DELETED |
| Known, live, scan **partial** (cap/deadline/PID died) | subset | Upsert present rows; **suppress deletes** |
| Known, **stopped** (no live PID) | none | **Leave rows untouched** — a restart resumes diffing |
| **Not known** to `container_instances` | none | Emit DELETED for all its rows |

Syscollector implements rows 1, 3 and 4 correctly today. FIM implements only row 1 and gets 2, 3 and
4 wrong. This table belongs in one shared helper used by both consumers, not duplicated in each.

## 6.9 What this yields

Steady state on the reference node (100 containers, 15 distinct images), compared with
[04](04-findings-performance.md#p9--summary-cost-model-and-the-reductions-available):

- `/proc` sweeps per cycle: **300 → 0** (PID from the record) or 1.
- IPC round-trips per cycle: **101 × 2 consumers → 1**.
- Duplicated context bytes: **~45 MB → ~150 KB**.
- Peak buffered memory: **400 MB–4 GB → O(one row)**.
- Image-derived scans per cycle: **100 → 15**, and at steady state **→ 0** (only on create/restart).
- Digest CPU: **3 digests always → per config**.
- Spurious MODIFIED events per cycle: **~20,000 → ~0**.

At steady state the dominant cost stops being "re-scan everything" and becomes "handle the events
that actually happened" — which is what the spike set out to achieve.


---

## 6.10 Corrections — the sketch versus the implemented contract

§6.3 was a sketch written against an assumed eBPF contract. The engine now exists
([11](11-ebpf-provider-import-plan.md)) and the consumer is built
([09](09-implementation-status.md)), so the sketch can be checked against reality rather than
against expectation. Its central claim held: **subscribe-first, scan, reconcile-by-re-read is what
shipped**, and re-reading rather than trusting the event payload turned out to be not merely
preferable but the only possible design. Six of its details did not hold.

Listed so that nobody plans from §6.3 as written.

| § | The sketch said | What is true, and what shipped |
| --- | --- | --- |
| 6.3 step 1 | "attach the eBPF filter **for C**" | There is no per-container attach. Subscription is one global handle; filtering is by cgroup allowlist inside the BPF program (`rt_allow_cgroup`, `d560d22b37`) — which did **not** exist when [11](11-ebpf-provider-import-plan.md) recorded this as unimplementable, and now does. The consumer still runs unfiltered (`RT_CGROUP_MODE_ALL`) because an unlisted cgroup is *invisible* rather than unattributed, which would remove the only discovery path for a container created after startup. Narrowing waits on item 20's create trigger. |
| 6.3 step 1 | "Record S0 = current event **sequence**" | No sequence exists, and none was minted. The design does not need one: events are staged in a map keyed by `(container, path)` and reconciled after the walk commits, so ordering never has to be compared. `timestamp_ns` is not globally ordered and is used for nothing. |
| 6.3 trigger table | "a ring-buffer drop **for C** → re-baseline C" | Also recorded as unimplementable in [11](11-ebpf-provider-import-plan.md) against a single global counter, and also now true: `rt_drain_drops()` (`c590808019`, [D14](12-blocking-decisions.md)) reports loss per cgroup. This matters more than it sounds — measured, 203 dropped events surfaced as three flag-bearing events, so a consumer acting on the global counter would re-baseline every container three times for a 0.1% loss belonging to one. |
| 6.3 step 4 | "P not visited by the scan → apply as a normal change" | **Unsound.** A single-row upsert racing the same container's open scoped transaction silently lost 502 of 504 rows on a real node. Every staged event is now held until the walk commits, enforced by a release gate rather than by ordering luck ([12 §12.10](12-blocking-decisions.md)). |
| 6.6 | Event-maintained = "FIM files, processes, ports" | The engine has no process and no socket event class. Only **files** hand off; processes and ports move to Sampled. |
| 6.8 | Deletion semantics, three rows | Needs a fourth, which is [D15](12-blocking-decisions.md): **a path reconcile may never infer a deletion.** A staged path that resolves to nothing may mean the file was deleted, or that it was a [C22](03-findings-correctness.md) host-form path, or that the container just restarted — indistinguishable at the read, and two of the three make a DELETE a false positive. Only a walk may delete, because only a walk sees whole directories and can tell absence from unreadability. Enforced by the type the consumer acts on (`may_detect_deletions`), not by convention. |

### Two things the sketch could not have anticipated

Both were found by running the engine against real containers, not by reading it.

**A rename is a deletion nobody reports** ([C21](03-findings-correctness.md)). The rename hook
submits the **destination** path only; the source is never named by any event, before or after. So
`mv /etc/passwd /etc/passwd.bak` inside a container would have §6.3 reconcile the new name and leave
the row for `/etc/passwd` asserting a file that no longer exists. A rename now escalates its
container to a re-walk — which is cheap, not expensive, because Suspect is a set keyed by container,
so a thousand renames coalesce into one.

**An attribute change on the rootfs carries a host path** ([C22](03-findings-correctness.md)). A
`touch` emits two events, the second naming
`/var/lib/containerd/.../snapshots/117/fs/tmp/x` — under the *container's* cgroup. §6.3's
reconcile-by-re-read would resolve that under `/proc/<pid>/root/` and find nothing. Staged paths are
therefore prefix-filtered against the configured container directories before any read, and the
result of a failed read is never a deletion (the §6.8 correction above).

### What was confirmed rather than corrected

Worth stating, because it is the load-bearing part:

- **Re-reading beats trusting the payload.** §6.3 argued it as a preference. It is now the only
  option: `rt_file_event` carries no mode, uid/gid, size, mtime or hash, and its `inode`/`dev` are
  contract-documented as diagnostic-only.
- **Re-baselining is safe as the universal recovery.** Rows go through a scoped DBSync transaction
  that diffs against what is stored, so a re-walk finding nothing changed emits nothing. That single
  property is what lets every Suspect edge collapse to "re-walk C", exactly as §6.3 argued.
- **`cgroup_id` identifies a container.** Measured twice on a real node — it is the cgroup directory
  inode, matching `stat -c %i`, and every event from a container carried it.
