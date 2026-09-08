# 09 — Implementation status

Tracks which [roadmap](08-roadmap.md) items are implemented on branch
`37532-5-0-0-container-integration` (a rebase of the original spike branch onto `5.0.0`).

- Commits (oldest first):

  *Review pass on the inherited spike code*
  - `7c90011b5c` — build guard for the missing `ci_impl/tests` directory
  - `9d6e3eb725` — P0 correctness + P1 scaling change set
  - `70cca0ccec` — `container_baseline` enable/disable config option
  - `d8054738d6` — image-derived row reuse across replicas + mid-scan liveness
  - `257184741c` — shared `ContainerScoped` row base
  - `6a08712dbe` — orchestrator lifecycle/ordering tests + discovery seam
  - `d8e4cd5704` — addressable-PID selection
  - `943a50935f` — no row deletion when the container connector is unreachable (C15)

  *After [12](12-blocking-decisions.md)'s decisions — D1 → hybrid, D2 → port the spike tail forward*
  - `9554439005` — container scope out of the row checksum (C19, C20)
  - `dcfacdb43c` — **`ebpf_provider` imported** from `9113442eb4` (Track E A1)
  - `1f6ecea90f` — provider: link teardown, ABI guard, log seam, cgroup-v1 detection (A2 items 4, 6, 3, 5)
  - `57deeb1e5f` — provider: the 12,416-byte ABI pin and `rt_open`'s contracts (A2 item 9)
  - `c5bc0a1d76` — wait out a warming connector, once per process; plus the five `spike-37533/` documents
  - `843b1efb76` — provider: teardown proven on a real kernel (VM)
  - `c590808019` — provider: **per-cgroup drop attribution** (A2 item 2, D14 → counter map)
  - `b5ac4089e8` — stop tracking the standalone build's artifacts
  - `d560d22b37` — provider: **in-kernel cgroup filtering** (A2 item 1)
  - `7a45ead0bf` — syscheckd: the drain↔consumer staging buffer (D5's first increment)
  - `0c631dd87c` — syscheckd: **`cgroup_id` → `container_id` attribution** (A3)
  - `dbd4db569b` — syscheckd: **the routing policy** joining the map to the staging buffer (A3)
  - `f3c4eb4900` — syscheckd: a rename re-walks its container ([03 C21](03-findings-correctness.md))
  - `ba8c642007` — syscheckd: **D15 enforced** — a path reconcile may never authorise deletion
  - `ed24a606ce` — container_baseline: **per-container FIM entry point** + the path guard ([13](13-container-baseline-api-plan.md))
  - `fc6e088b1a` — syscheckd: **A3 closed** — the drain, resolver and reconcile consumer, wired into `main.c`
  - `41ab9e27d3` — container_instances_client: correct what `LookupResult::json` holds

  *After the 2026-09-07 end-to-end run and the whole-tree review of the spike branch ([14](14-spike-integration-plan.md))*
  - `69303187cd` — `fim_file_data` carries the container scope (port order step 5)
  - `4b365c11d6` — `<container_baseline_interval>`: the container pass gets its own cadence
  - `4e096f9537` — its config-parser cases, rewritten once cmocka could run them
  - `1bdfb0990e` — **`rt_file.bpf.o` is installed** — without it a packaged agent could never load the engine
  - `fdcca35d0c` — `OS_MD5_SHA1_SHA256_File` declared with C linkage
  - `7117b9fb08` — **the scoped `file_entry` transaction contract, pinned against real `libfimdb`**
  - `888c29a4a6` — **container FIM changes now raise an alert**, not just a stateful row ([14](14-spike-integration-plan.md) WP2)
  - `c0e5f162bb` — a missing eBPF engine is a *warning*, and only where container directories are configured
  - `60182a3a17` — **[D16](12-blocking-decisions.md) resolved** — a staged path settles before it is re-read ([C23](03-findings-correctness.md))
  - `1cab48878c` — **[D17](12-blocking-decisions.md) resolved** — the status facts are separated ([C24](03-findings-correctness.md)) and `RT_EV_FILE_UNLINK` deletes exactly its own path
  - `da90a18c5b` — the prebuilt `rt_file.bpf.o` lookup is per-architecture
  - `2ea083add8` — **container inventory gets its own document budget** ([14](14-spike-integration-plan.md) WP4)

  *After the 2026-09-08 run of the integrated agent ([12 §12.15](12-blocking-decisions.md#1215-the-integrated-agent-on-a-real-node-2026-09-08))*
  - `a98549d807` — **`<container_instances>` is dispatched** — the module could not start at all before ([C25](03-findings-correctness.md))
  - `f39967c55c` — **a changed container file reports MODIFIED** — every modification was dropped ([C26](03-findings-correctness.md)), plus the two transaction cases that pin it and [C27](03-findings-correctness.md)
  - `7e059dd5aa` — **`list` always carries a `containers` array**, so "no containers" stops reading as "no connector" ([C28](03-findings-correctness.md#c28--with-no-containers-list-reads-as-connector-unavailable))
  - `d3a8e394d9` — **a path reconcile no longer deletes the container's other rows** ([C27](03-findings-correctness.md), [D18](12-blocking-decisions.md#d18--how-does-a-path-reconcile-persist-a-row-without-authorising-a-sweep-resolved-2026-09-08--the-non-transactional-upsert-d3a8e394d9)) — a non-transactional per-row upsert, plus case 7 pinning it

- Verified in WSL: `make build TARGET=agent` clean; **164 module unit tests, 163 pass / 1 skipped**
  (needs a running container), up from 112 with 2 failing; **14 staging-buffer tests** pass; the
  provider's own contract tests pass (`make check` in `shared_modules/ebpf_provider`). `-Wformat-security` in
  `container_baseline_fim.cpp` also cleared (7 warnings → 3, the rest pre-existing
  `-Wformat-nonliteral` inherent to a printf wrapper).
- Verified on the `wazuh_manager` VM (Ubuntu 24.04.4, kernel 7.0.0-30, cgroup v2, bpf LSM active) —
  everything WSL structurally cannot do: the BPF object compiles and loads, programs attach and
  poll, `rt_close` detaches completely, drops are attributed per cgroup, and the in-kernel filter
  delivers exactly the allowlisted cgroup's events. Details in
  [12 §12.9](12-blocking-decisions.md#129-d4-answered--the-loss-proof-measured) and the four
  `test/rt_engine_*_test.c` programs.
- **On the remote** — `origin/37532-5-0-0-container-integration` is at `f39967c55c`. `d3a8e394d9`
  and `7e059dd5aa` are committed locally and **not pushed**

## Planning documents

Written when the two largest remaining items were externally blocked. Item 21 is no longer blocked
and is partly implemented (see [the provider section](#the-ebpf-provider--item-21s-foundation) below);
item 20 still is.

- **[10 — `container_instances` delta plan](10-container-instances-delta-plan.md)** (item 20).
  Recommends a cursor on the existing `list` op over a `watch` stream (the IPC server hands a
  connection to a worker for its lifetime with only 2 workers, so watchers starve the eBPF
  `resolve` path), and — the load-bearing finding — publishing the delta from `MetadataStore`'s
  own mutation chokepoints rather than from `ReconcileDelta`, whose diff diverges from the set
  `listContainers()` returns in four separate ways.
- **[11 — `ebpf_provider` import plan](11-ebpf-provider-import-plan.md)** (item 21). Item 21 is
  **no longer blocked**: #37396's extraction gives a versioned event contract and an in-band
  drop flag. Import the tree at `9113442eb4`, not the `2676bb86c8` named in the request (a
  non-working intermediate: no `bpf_obj_path`, no PIC, `RT_ABI_MINOR 0`). Reconcile-by-re-read
  is not merely preferable but **forced** — `rt_file_event` carries no mode, uid/gid, size,
  mtime or hash, so an event can only name a `(container, path)`.
- **[12 — Blocking decisions](12-blocking-decisions.md)**, which supersedes both plans' *sequencing*.
  This branch is a truncated cut of `spike/37533-37534-fim-syscollector-ebpf-integration` at
  `66301af90d`, and **14 commits of that spike's feature work were never integrated** — among them
  `5a9021e285`, which replaces the inventory state model with a durable SQLite prior-state
  reconciler and deletes the `syscollectorImp.cpp` call path doc 10's Phase 3 rewrites. Doc 10's
  Track S is therefore on hold pending [D1](12-blocking-decisions.md#blocking-now--every-further-design-step-depends-on-these);
  doc 11's Track E is collision-free and is the recommended next work.

## Done

| # | Item | Notes |
| --- | --- | --- |
| 1 | FIM stops deleting stopped containers' state | Sweep now compares against `cbaseline_list_containers()`; a per-container status callback carries completeness |
| 2 | No prefix digests | `max_hash_bytes` is now a "don't hash above this" threshold; hash fields left empty, mirroring `syscheck.file_max_size`. Regression test added |
| 3 | `tags` tokenised | `tags="container,prod"` now selects; selected path count logged |
| 4 | Namespace-collapse detection | New `container_scope.{hpp,cpp}`; host-network containers report no netns-scoped rows |
| 5 | Mount-boundary guard | Device-boundary crossing requires an OCI-declared destination, never a host-root mount |
| 6 | Pod-shared socket de-duplication | Shared netns ⇒ only sockets attributable to this container's PIDs |
| 7 | `truncated` / `root_missing` propagated | Per-container status. Suppression is **per container, not per table** — `onStatus(containerId, partial, …)` collapses the reasons, so a missing `CAP_SYS_ADMIN` on one dimension still stalls delete detection for all eleven. The per-table split is seam S1, and [D17](12-blocking-decisions.md) deliberately did not take it. `root_missing` is no longer part of `partial` ([C24](03-findings-correctness.md)) |
| 8 | FIM transaction exception-safe | RAII, return codes checked, `DB_ERROR` logged, `try`/`catch` around the run |
| 9 | uid/gid translated | New `id_map.{hpp,cpp}` reads `/proc/<pid>/{uid,gid}_map`; owner/group names from the container's own account files |
| 10 | Container process churn suppressed | `PROCESSES_IGNORED_FIELDS` applied to the container path (HW/interfaces were already covered on 5.0.0) |
| 11 | `/proc` sweep storm removed | New `PidIndex`: one sweep per run, shared by every scanner; `std::regex` → string compares |
| 12 | 1+N IPC collapsed to 1 | `ContainerRef::record` carries the full record the `list` reply already sent |
| 13 | Streaming per container | Both consumers flush on the status boundary; peak memory is one container, not the node |
| 16 | NFR3 file throttle | `check_max_fps()` passed in as a rate-limit hook; `max_hash_bytes` from `syscheck.file_max_size` |
| 18 | Projected `DISTINCT` stale sweep | New `fim_db_get_distinct_container_ids()`; syscollector queries gained `distinctOpt(true)` |
| 19 | One `lstat` per entry | Cap checked before enqueueing, so the pending queue cannot overrun it |
| 32 | CMake flags appended | `string(APPEND …)` instead of overwriting the parent's optimisation/hardening flags |
| 22 | Image-derived row reuse | New `ImageContentCache` keyed by `image_digest` **and validated by a stat() fingerprint**, so a container that modified `/etc/passwd` or its package DB in its writable layer is still scanned. Packages/users/groups/OS only; services excluded (no sound cheap fingerprint). ~85% less work on a node with ~15 distinct images |
| 24 | Mid-scan PID death | `RootfsStillAddressable()` checked after scanning; a PID that exited mid-walk now reports an incomplete scan instead of a silent partial row set. (The `O_PATH` fd pinning half is still open) |
| 25 | Enable/disable knob | `<container_baseline>yes\|no</container_baseline>`, default `yes` to preserve current behaviour; joins `m_allCollectorsDisabled`, and disabling purges leftover container rows once |
| 27 | Boilerplate collapsed (partial) | `ContainerScoped` base replaces the two fields repeated in all 12 row structs, collapsing 12 `ApplyIdentity` overloads to 1; 95 net lines removed |
| 30 | Orchestrator tested | `ContainerDiscoverer` seam + `PidIndex::FromMap()`; 15 tests pin the skip/count semantics, the **row-contiguity-then-status** contract both consumers stream on, partial reporting, and once-per-run discovery. The contiguity checker is itself pinned by 4 self-checks so it cannot pass vacuously |
| 24 | Addressable-PID selection | `SelectAddressablePid()` skips snapshot entries that have already exited, so a stale leading PID no longer costs a live container its scan; all-gone is handled as "unscanned", not "empty" |
| 32 | `GLOB` staleness | `CONFIGURE_DEPENDS` on all three globs — adding a source file no longer needs a manual `cmake` re-run |
| — | Hash selection honoured | `CHECK_MD5SUM`/`SHA1SUM`/`SHA256SUM` respected (roadmap P7) |
| — | `setns` exception documented | Written up in the header as a narrowly-scoped deviation; `CAP_SYS_ADMIN` failure now reported, not silent |
| — | `process.start` emitted | ISO-8601 no longer dropped by an epoch-only serialiser (C12) |
| — | `/proc/<pid>/stat` parse hardened | `strtoll` instead of `stoll`, so a malformed field cannot throw into `main()` |

## The eBPF provider — item 21's foundation

`src/shared_modules/ebpf_provider/` now exists on this branch: #37396's extracted engine, plus every
gap [11 §11.9](11-ebpf-provider-import-plan.md#119-what-must-be-added-to-ebpf_provider) said item 21
depended on. Nothing consumes it yet, by design — FIM still loads `modern.bpf.o` through its own
libbpf path, and `ebpf_whodata.cpp` is untouched, so item 21 cannot regress host FIM whodata while
it stabilises.

| §11.9 | Item | State |
| --- | --- | --- |
| — | Import the engine (A1) | Done, `dcfacdb43c`. From `9113442eb4`, hand-ported: 9 files, 1 changed line in `src/CMakeLists.txt` |
| **1** | In-kernel cgroup filtering | Done, `d560d22b37`. Allowlist map + `rt_allow_cgroup`/`rt_deny_cgroup`/`rt_set_cgroup_mode`; `RT_CGROUP_MODE_ALL` is the zero value so host whodata is unaffected. Verified: 300 delivered from the allowlisted cgroup, 0 from the excluded one, 0 from the rest of the node |
| **2** | Per-cgroup drop accounting | Done, `c590808019`. `rt_drain_drops()` over a keyed map; **D14 decided as the counter map**, so the event contract is untouched. Verified with two cgroups at 3,651 and 3,678 drops |
| **3** | A logging seam | Done, `1f6ecea90f`. `rt_filter.log`; eight `fprintf(stderr)` sites routed through it, so an eBPF load failure can finally reach `ossec.log` |
| **4** | Destroy the `bpf_link`s in `rt_close` | Done, `1f6ecea90f`; **proven on a real kernel** in `843b1efb76`. Pre-fix leaked 7 descriptors per open/close cycle and double-attached on re-open |
| **5** | Set `RT_F_CGROUP_V1` | **Split.** The reliable half is done (`1f6ecea90f`): the engine detects the host's cgroup version at `rt_open` and exposes `rt_host_cgroup_v1()`, since it is a host constant rather than a per-event property. The per-event flag still needs a BPF config map — see [12 §12.7](12-blocking-decisions.md#127-the-decided-plan-d1--option-3-d2--option-1). **Consumers must use the accessor, not `ev->flags`** |
| **6** | ABI guard | Done, `1f6ecea90f`. Per-event `abi_major` *and* record-size check (a MINOR-older object emits a shorter record, so reading the tail would run off its end), plus `rt_abi_major()`/`rt_abi_minor()` |
| 7 | Occupancy metric (`ring__avail_data_size`) | Not done. Lower value now that [12 §12.9](12-blocking-decisions.md#129-d4-answered--the-loss-proof-measured) measured where loss actually starts |
| **8** | Kernel-portable rename | Not done — [11 open question 3](11-ebpf-provider-import-plan.md#1111-open-questions-and-what-i-could-not-verify) deliberately did not guess a version boundary. Still a silent-detection-gap risk on one kernel family |
| **9** | A unit-test seam | Partly. Four test programs exist: contract/ABI (WSL-runnable), teardown, drop attribution and filtering (kernel + root). The fake-libbpf suite that would cover `rt_open`'s failure branches and the per-event ABI rejection is still missing |

Test programs, and where each can run:

| Program | Needs | Covers |
| --- | --- | --- |
| `rt_engine_contract_test` | nothing (`make check`) | `sizeof(struct rt_file_event) == 12416` + `offsetof` pins, `rt_open` filter validation, the log seam, NULL-handle contracts. **Mutation-checked** — inserting one field trips six assertions |
| `rt_engine_leak_test` | kernel, object, root | `rt_close` releases every descriptor across two open/close cycles |
| `rt_engine_drops_test` | kernel, cgroup v2, root | Per-cgroup drop attribution, **and that `bpf_get_current_cgroup_id()` equals the cgroup directory inode** — the join every container consumer rests on, previously asserted nowhere |
| `rt_engine_filter_test` | kernel, cgroup v2, root | Allowlisted delivered, excluded not, a filter miss not counted as a drop, and the mode as a live switch |

## Thread ownership (item 14 / D5)

**[D5 is resolved](12-blocking-decisions.md#1210-d5-resolved--and-one-of-its-options-never-existed)**,
and resolving it removed an option nobody had checked: *"a shared `BaselineService` thread serving
both consumers"* is **not implementable**, because FIM (`wazuh-syscheckd`) and syscollector (a
wmodule in `wazuh-modulesd`) are **different processes**. Docs 10, 11 §11.8.7 and 12 all listed it.

The decision:

| Where | Threads | Why |
| --- | --- | --- |
| syscheckd | Two — a drain that only stages, and a consumer that reconciles. The **walk stays on `main()`** at its current call site | A thread doing both drain and walk overflows the ring while it walks; but moving the walk off `main()` would race host FIM's own `file_entry` transactions for no benefit the ordering needs |
| syscollector | None new | The provider has no process or socket event class, so syscollector's data cannot come from the event stream at all; its existing scan interval *is* the delta-poll cadence |
| both | One `BaselineService` object per process | Items 22 and 29 — the single-ownership benefit the shared-thread idea was actually after |

**This largely retires item 14's FIM half.** What moves off `main()` is the drain and the reconcile,
not the walk: "FIM baselines on `main()`" turns out to be
[11 §11.8.1](11-ebpf-provider-import-plan.md#1181-ordering)'s deliberate design (an *unchanged call
site*) rather than the defect [08](08-roadmap.md) treats it as.

Implemented so far — `container_event_staging.hpp` (`7a45ead0bf`), the point where the two threads
meet:

| Property | Pinned by |
| --- | --- |
| Nothing reaches the consumer before `release()` | 2 tests; **both fail** if the gate is removed. This is the 502-of-504 row loss |
| De-duplication bounds memory: 5,000 events on one path → 1 entry, 4,999 dedups | 1 test. The reason this is a map and not the in-tree `fim::BoundedQueue`, which is a FIFO with no dedup |
| **Suspect supersedes staged paths** — exceeding a budget escalates to a re-walk rather than dropping | 2 tests; **fails** if mutated into a silent discard. This is what stops the buffer being a second silent loss channel |
| An attributed drop escalates only its own container | 1 test — the whole-node re-baseline that `c590808019`'s per-cgroup map exists to avoid |
| Unattributed loss escalates every container, and is served **once**, not forever | 2 tests — a repeat would put the consumer in a re-baseline loop |
| 8,000 paths across 4 producer threads are served exactly once each | 1 test |

Then `cgroup_container_map.hpp` (`0c631dd87c`) and `container_event_router.hpp` (`dbd4db569b`,
`f3c4eb4900`), which turn a cgroup into a container and decide what happens to each event:

| Property | Pinned by |
| --- | --- |
| Resolution never happens on the drain thread — the map is a pure in-memory lookup | By construction: the class does no I/O at all, which is also what makes it unit-testable |
| A stale positive cannot outlive its container (cgroup inodes are **reused**) | 2 tests — positives are replaced wholesale from the connector's list, never accumulated |
| A stale negative cannot hide a new container on a reused inode | 2 tests — positive evidence clears it, and a verdict contradicted by the connector's list is never recorded |
| A busy unresolved cgroup is queued **once**, not once per event | 1 test — otherwise an IPC round-trip per host file open |
| Events seen before a container was identified escalate it to a re-walk | 3 tests — the paths are unrecoverable, so the weaker action is replaced by a stronger one |
| **5,000 unidentified cgroups reporting drops produce zero global escalations** | 1 test. The load-bearing one: the "safe" choice of escalating unknown drops globally would re-baseline the node continuously in `RT_CGROUP_MODE_ALL`, and no single-event test can show it |
| Loss nobody can ever resolve (the pending set overflowing) still escalates — once | 1 test |
| A rename re-walks its container instead of staging the destination | 4 tests; **fails** if mutated into staging the destination. [C21](03-findings-correctness.md) |
| A thousand renames coalesce into one re-walk | 1 test — which is why the safe choice is also the cheap one |

Every claim above was mutation-checked; three tests exist *because* a first mutation pass showed the
guards they cover were untested, and that pass also found `cgroup_id` 0 being queued for a resolver
that can never answer it.

**A3 paused here, at [12 §12.11](12-blocking-decisions.md) / D15 — now resolved.** Two VM measurements confirmed
what the drain depends on — `cgroup_id` is the cgroup directory inode, and rootfs, tmpfs and
bind-mount paths all render container-absolute — but also turned up
[C22](03-findings-correctness.md): an `ATTR` event on the rootfs carries a *host*-side path under the
container's cgroup. That made "may the consumer infer a deletion from a path it cannot find?" a
question that had to be answered before the consumer was written rather than after, because
retrofitting an inference ban onto code that already deletes is exactly how C15 happened.

D15 is answered **no**, and `container_reconcile_plan.hpp` (`ba8c642007`) enforces it in the type the
consumer acts on rather than in a comment asking it to behave: a `Batch` becomes a `ReconcileRequest`
carrying `may_detect_deletions`, and no path batch ever sets it. Only a walk may delete, because only
a walk sees whole directories and can tell absence from unreadability. An empty path batch is a no-op
rather than being promoted to a walk — promoting it would convert "nothing to reconcile" into "delete
whatever I cannot find", and that mutation fails four tests. The accepted cost, recorded rather than
hidden: a file deleted inside a container goes unreported until the next walk of that container.

The per-container `container_baseline` entry point the consumer needs is **built**
(`ed24a606ce`, [13](13-container-baseline-api-plan.md)). It came out smaller than expected — **one**
new export rather than two, because the walker is already path-rooted and a non-directory
`internal_path` emits exactly one row, so re-reading one file is the existing walk with different
arguments; and the orchestration seam (`RunFimDbsyncBaselineFrom`) already took an injectable
container list, so there is no new row-emission, transaction or partial-accounting logic.

What is genuinely new is `IsSafeInternalPath()`. This entry point breaks an invariant
`rootfs_file_walker.hpp` states outright — "`..`-escaping is impossible by construction … never by
resolving a caller-supplied path containing `..`" — because it *does* resolve a caller-supplied path,
and in the eBPF consumer that path arrives in a kernel event emitted by a process **inside** the
container. It rejects rather than normalises (rewriting `/etc/../x` into `/x` would silently scan
something else) and a rejection forces `partial`, so a dropped path suppresses delete detection
instead of passing unnoticed. The entry point also returns a tri-state rather than a count, so a
connector blip cannot read as "this container has no files any more".

**A3 is closed** (`fc6e088b1a`). The ordering in `main.c` is now:

```c
fim_initialize();
fim_container_events_start();    /* subscribe: events stage from here */
fim_run_container_baseline();    /* unchanged: still blocks main() */
fim_container_events_release();  /* only now may the consumer touch file_entry */
realtime_start();
```

Three threads, each with a reason it cannot be folded into another: the **drain** does one hash
lookup per event and nothing else (a ~675-record ring is ~2.4 s of an 8,400 events/s burst); the
**resolver** cannot share it because the IPC client's default timeout is 1 s; the **consumer** cannot
share the resolver because it blocks on disk for the length of a walk, during which unidentified
cgroups keep missing and the pending set fills — turning a slow walk into a whole-node re-baseline.

Every refusal is a degradation, never a startup failure: no engine, an ABI major mismatch, or a
cgroup v1 host (where every container shares one `cgroup_id`, so attribution would file every
container's events under whichever resolved first — wrong attribution being worse than none). The
list refresh is gated on the client's `reachable` flag, because `install()` REPLACES the positive
map and an unreachable connector's empty list would un-attribute every container at once: C15's
shape one level down. `RT_CGROUP_MODE_ALLOWLIST` still waits on item 20's create trigger; the drain
opens in mode ALL, which needs none.

D15 reaches the database here: `BaselineDriver` gained `may_detect_deletions`, and a path reconcile
passes false. Staged paths are prefix-filtered against the configured container directories before
reaching the walker, which is what discards [C22](03-findings-correctness.md)'s host-form `ATTR`
paths — they arrive under the container's own cgroup and would otherwise be looked up inside the
container, where they do not exist.

### The spike's unintegrated tail is ported (2026-09-07)

Steps 4–9 of the decided port order are worked through; the outcome is in
[12 §12.13](12-blocking-decisions.md#1213-the-port-order-finished-2026-09-07). Three commits came out
of it — `69303187cd` (`fim_file_data` carries the container scope, 3 new tests, mutation-checked),
`4b365c11d6` (`<container_baseline_interval>`: the container inventory pass gets a cadence of its own,
one loop and two deadlines, 1 new test) and `4e096f9537` (its config-parser cases, rewritten once
cmocka was available and they could actually be run) — and four steps turned out to be moot, because their content
lives entirely in `container_live_fim.cpp` and the Model B reconciler, neither of which this branch
imports, or was already here in a stronger form.

Two parts of the tail are **decision-blocked, not skipped**: seam S1 (per-table `partial`) and the
per-dimension container row limits both define what an incomplete scan authorises, which is exactly
what [D17](12-blocking-decisions.md) is open on.

### Validated end to end on 2026-09-07, and what still is not

The success path has now been run for real on `wazuh_manager` — real kernel, real BPF engine, the
real `container_instances` module in its own process on its real IPC socket, real Docker containers,
the real `container_baseline` scanner — and it works. Full evidence table in
[12 §12.12](12-blocking-decisions.md#1212-the-end-to-end-run-2026-09-07-and-the-two-decisions-it-forces);
in short: subscribe-first ordering holds, a whole-node baseline produced 47 correctly-attributed
`file_entry` rows for a live container, a container created *after* startup was resolved by the
resolver thread with nothing seeding it, two containers of the same image were never confused, a
rename produced the `DELETE` no event reports ([C21](03-findings-correctness.md)), every path
reconcile refused to delete ([D15](12-blocking-decisions.md)), the C22 host-form paths were discarded
by the prefix filter, and an unreachable connector kept its rows and recovered on its own.

**Two defects only a running system could show, both now recorded:**
[C23](03-findings-correctness.md) — the re-read races the write that triggered it and silently keeps
the pre-write row, so a writer that holds a file open is not reported until the next scheduled
baseline (**high**, needs [D16](12-blocking-decisions.md)) — and
[C24](03-findings-correctness.md) — one configured path absent from an image suppresses that
container's delete detection permanently (**medium**, needs
[D17](12-blocking-decisions.md)).

**FIM's real DBSync layer — four properties now pinned, the rest still open.** The run replaced
`libfimdb` with an in-memory store carrying DBSync's callback shape, so what it validated was
everything deciding *what* to hand the database and nothing about `libfimdb` itself. Reviewing the
spike branch turned that from a gap into a risk worth measuring, because that branch asserts
`fim_db_transaction_deleted_rows()` is required to flush a transaction — and
[D15](12-blocking-decisions.md) makes a path reconcile close without it, so if true, every path
reconcile would have persisted almost nothing. `src/syscheckd/src/ebpf/tests/txn/` (`7117b9fb08`) now
pins the four assumptions the consumers actually rest on, against the real database: closing without
`deleted_rows` loses no row callback (500 of 500), `container_id` is genuinely part of the primary
key, a scoped sweep deletes only its own scope's untouched rows (495 of 500), and another container's
rows survive it. Mutation-checked; details in
[12 §12.14](12-blocking-decisions.md#1214-the-spike-branch-reviewed-as-a-whole-2026-09-07). What is
still unexercised **as of this run** is the *rest* of `libfimdb` in the live path — the sync-protocol
persist, the stale sweep's real queries, and `FileItem`'s typed round-trip. This run's harness
compiled the real `container_baseline_fim.cpp`/`container_event_drain.cpp` directly and stubbed
syscheckd's bridge (config, logging, `abspath`, the fps budget), because disk on the VM was down to
1.1 GB and a full agent build did not fit. Superseded on 2026-09-08: the whole agent was built and
run, with real `libfimdb` throughout — see below.

Also unvalidated: the `rebaselineAll` (unattributable-loss) path, which needs a real drop storm;
container *removal* and the stale sweep, which only runs in the whole-node baseline; and cgroup v1
hosts, where `start()` refuses by design.

### The integrated agent, validated on 2026-09-08 — and what still is not

The daemons themselves were run this time, not a harness around the pieces: `wazuh-modulesd` and
`wazuh-syscheckd` built from this branch, real `libfimdb`, real `container_instances` in
`modulesd`'s own process, real Docker containers, on Ubuntu 24.04.4 / kernel 7.0.0-31 / cgroup v2.
Evidence table in
[12 §12.15](12-blocking-decisions.md#1215-the-integrated-agent-on-a-real-node-2026-09-08).

What that closes, in this document's terms:

- **The provider builds from source on a modern kernel.** `rt_file.bpf.o` is produced through the
  host-BTF fallback, so the WP6 packaging problem is confined to hosts without `clang` + `bpftool`
  — it is not a code problem.
- **The engine attaches, and picks the LSM variant.** `4 program(s) attached, ABI 1.1`.
- **D16, D17 and WP2 hold on the integrated agent**, including [C24](03-findings-correctness.md)'s
  absent-root case with a deliberately missing `<directories>` entry.
- **WP4 works and `4b365c11d6`'s bug is fixed**: container limits arrive over the wire, the
  container budget is spent independently of the host's, and the independent
  `<container_baseline_interval>` pass now promotes its rows to `sync=1`.
- **`libfimdb` in the live path is now exercised**, which is what turned up
  [C26](03-findings-correctness.md) and [C27](03-findings-correctness.md) — both invisible from the
  database, both requiring the real DBSync callback contract to show at all.

What it did **not** close:

- [C27](03-findings-correctness.md) was left open here and is now **closed** by the second run of
  2026-09-08 ([12 §12.16](12-blocking-decisions.md#1216-the-lifecycle-question-answered-by-measurement-2026-09-08)),
  which measured what it cost at the alert level — only the first modification per container was
  reported as a modification — and fixed it in `d3a8e394d9`.
- [C28](03-findings-correctness.md#c28--with-no-containers-list-reads-as-connector-unavailable) is
  new and **also closed** (`7e059dd5aa`): with no containers on the host, `list` omitted the
  `containers` key and the client read that as an unreachable connector, so the stale-row sweep never
  ran. The fix keeps D5's rule — a socket that answers nothing still suppresses the sweep.
- [C16](03-findings-correctness.md#c16--dockers-deferred-reconcile-is-dropped-not-deferred) turned
  out to be a live defect rather than only an item-20 blocker: a removed container stays in `list`
  indefinitely on an idle Docker host, so its rows are never swept. Open, and now a P0 item in
  [08](08-roadmap.md).
- The **stateful documents still do not validate**: no schema in `external/indexer-plugins` carries
  a `container` field, so ten indices reject every container row. Detection and stateless events are
  unaffected. #37203-3/-4, and not fixable from this branch.
- Still unvalidated for the same reasons as before: the `rebaselineAll` drop-storm path, container
  removal and the stale sweep, and cgroup v1.
- WP5 (A4 — host FIM whodata onto `rt_engine`) is untouched, and WP6 has no committed object yet.

### Post-startup container discovery, validated 2026-09-08

A second run answered a question this document had recorded as an open risk of item 20's absence:
a container created **after** the one-shot `fim_run_container_baseline()` is fully walked within two
seconds, five files, five `added` alerts with the container block attached. Nothing publishes a
lifecycle delta; the events that expose the new cgroup come from **runc's init** — four
`RT_EV_FILE_OPEN`s (`/proc/<pid>/oom_score_adj`, the AppArmor `exec` label, two `net.ipv4` sysctls) —
and resolving that unknown cgroup escalates it to a `rewalkContainer`. The container's own command
emitted nothing, and an `execve` cannot: read-only opens are dropped in the kernel.

Two consequences for planning, in opposite directions:

- **`RT_CGROUP_MODE_ALL` is load-bearing until item 20 lands.** Narrowing `cgroup_mode` to
  `ALLOWLIST` — an obvious-looking cost reduction, since the drain currently sees host file activity
  too — would delete post-startup container discovery outright, because the allowlist would have
  nothing to put in it.
- **But that discovery is incidental.** It rests on the container runtime's startup writes, not on
  anything this design guarantees, so it is not a reason to consider item 20 satisfied. Measurement
  and the correction to an earlier, stronger claim in
  [12 §12.16](12-blocking-decisions.md#1216-the-lifecycle-question-answered-by-measurement-2026-09-08).

### The spike branch reviewed as a whole (2026-09-07)

[14](14-spike-integration-plan.md) reviews `spike/37533-37534-fim-syscollector-ebpf-integration`'s
whole tree against this branch, not just the commits
[12 §12.13](12-blocking-decisions.md#1213-the-port-order-finished-2026-09-07)'s port order named.
Five commits came out of it (`1bdfb0990e`, `fdcca35d0c`, `7117b9fb08`, `888c29a4a6`,
`c0e5f162bb`), and two status facts change:

- **`rt_file.bpf.o` was never installed, and still has no supply.** `CB_RT_BPF_OBJECT_PATH` is
  `"lib/rt_file.bpf.o"` relative to the install directory, and `inst-functions.sh` only installed
  `modern.bpf.o`. On any packaged agent `rt_open()` could not find its object, so the entire
  container event path would have taken its silent "no engine" degradation — the one path A3 is
  designed to take *without* complaining, so nothing would have reported it. The install rule, rpm
  spec and lintian override are fixed (`1bdfb0990e`), but the object is **never built** in the
  packaging pipeline either: `libbpf-bootstrap` is fetched precompiled, so `modern.bpf.o` arrives
  prebuilt and the vendored `vmlinux.h` is absent, and `rt_file.bpf.o`'s last CMake branch needs
  clang + libbpf headers + a working `bpftool`, which a package-build container has none of. Until
  it is supplied (deps tarball, or the `prebuilt/` path the CMake already honours) the feature does
  not run on a package. `c0e5f162bb` makes that failure a **warning** rather than a debug line, and
  only where a `<directories>` entry is tagged `container` — being invisible is how the install half
  survived unnoticed. See [14 §14.6](14-spike-integration-plan.md).
- **Container FIM rows were persisted and never alerted on — fixed, `888c29a4a6`.**
  `fim_persist_baseline_row()` ended at `validate_and_persist_fim_event()`, which builds only the
  stateful document, so a file changing inside a container updated `wazuh-states-fim-files` and
  produced no FIM alert and no `changed_fields`. This was a gap in *this* branch that no finding had
  named, because every test here asserts on rows rather than on alerts.
  `fim_send_container_stateless_event()` closes it out of host FIM's own `fim_attributes_json()` /
  `fim_calculate_dbsync_difference()`, so a container alert has a host alert's shape; the initial
  whole-node baseline stays silent, mirroring `notify_scan`. 27 assertions in
  `src/syscheckd/src/ebpf/tests/alert/`, five mutations. Details and the three questions it had to
  settle: [14 WP2](14-spike-integration-plan.md).

Seven defects in the spike are recorded there so they are not inherited — chief among them a leaked
transaction per live event, the container scope back inside the row checksum
([C19/C20](03-findings-correctness.md)), and a delete inferred from a failed `lstat` with a TOCTOU
window, which is [D15](12-blocking-decisions.md) at single-row granularity.

## Not done — deliberately deferred

| # | Item | Why |
| --- | --- | --- |
| 14 | Move the work off critical threads | **Largely resolved — see [Thread ownership](#thread-ownership-item-14--d5).** D5 is decided; the drain and reconcile move off `main()`, the walk deliberately stays. The staging buffer is implemented; the drain thread and consumer are A3's remaining work |
| 15 | Bounded concurrency over containers | **Deprioritised, and now ruled out for the live path** — the spike's 502-of-504 row loss above is what concurrent scoped transactions for one container actually cost. **Deprioritised on the evidence** for the walk too. Its value fell sharply once the `/proc` storm, the 1+N IPC pattern and the image rescans were removed: the remaining cost is dominated by FIM file hashing, which is I/O-bound and deliberately rate-limited by `check_max_fps`, so parallelising past a throttle buys little. It would also add real thread-safety surface (a shared image cache, and the row-contiguity contract the consumers stream on). Worth revisiting only if a node-level benchmark shows collection wall-clock is actually the bottleneck |
| 17 | Container context stored once | Replacing the per-row `container_json` blob with a dimension row is a schema change for #37203-3/-4 |
| 20 | Baseline once per lifetime + create trigger | The largest remaining win, and the one that makes this a *baseline*. **Now planned in [10](10-container-instances-delta-plan.md)**; still needs the `container_instances` change that plan specifies |
| 21 | Baseline↔eBPF handoff | **In progress.** The provider is imported and all four gaps it depended on are closed and kernel-verified (in-kernel filtering `d560d22b37`, per-cgroup loss attribution `c590808019`, link teardown `1f6ecea90f`, ABI guard). What remains is the *consumer* — A3 in [11 §11.7](11-ebpf-provider-import-plan.md#117-phased-plan) — which is gated on **[D5](12-blocking-decisions.md#blocking-the-next-phase)** (thread ownership) and, because allowlist filtering makes an unknown cgroup invisible rather than merely unattributed, on item 20's create trigger |
| 22 | Cache across runs, not just within one | The fingerprint makes it safe; it needs somewhere to live other than the per-run context, i.e. the `BaselineService` object item 29 wants. **Note the dependency runs the other way from what [08](08-roadmap.md) says** — see [10 §risk 2](10-container-instances-delta-plan.md): `ImageContentCache`'s saving is within-cycle reuse across replicas, so once item 20 makes a cycle scan only the delta the saving evaporates. 22 must land with or before 20 |
| 23 | Re-baseline triggers | Depends on 20/21 |
| 24 | `O_PATH` fd pinning + `openat` traversal | Selection and liveness detection are done. Pinning would let a scan *survive* a mid-scan exit, but its value is now questionable: if the container has genuinely gone, completing the scan reports state for something that no longer exists, and if only that PID died, selection already recovers |
| 26 | Delete the dead sync-protocol path | `Build*Json` has 18 live test assertions and all three QA runners depend on it; removing it is a larger collateral change with no correctness benefit in this pass |
| 27 | Collapse the `Build*` families | Deliberately not done — see the refactor commit: twelve field-descriptor tables would trade greppable assignments for indirection without removing the per-class knowledge |
| 28 | Reuse `LinuxPortWrapper` / `NetworkLinuxInterface` / `getDpkgInfo` / `UsersProvider` | Each needs a build-graph or injection change in `data_provider` |
| 29 | Remove `g_everSawContainers` | Correct as written; belongs with the `BaselineService` refactor |
| 30 | Consumer-side tests | The orchestrator is covered, and the *scoped-transaction contract* is pinned against the real `libfimdb` (`7117b9fb08`, extended in `f39967c55c` with the `MODIFIED` payload shape and what `close()` does to untouched rows, and in `d3a8e394d9` with the non-transactional upsert that replaces it). What is still untested is the consumers' own transaction *handling* — the `BaselineDriver` state machine and its error branches, which is where [C26](03-findings-correctness.md) and [C27](03-findings-correctness.md) both lived. Neither would have been caught by a test that reads `fim.db` back: C27's damage sat in an uncommitted transaction (see [12 §12.16](12-blocking-decisions.md#1216-the-lifecycle-question-answered-by-measurement-2026-09-08)) |
| — | ~~Stateless alerts for container FIM~~ | **Done, `888c29a4a6`** ([14](14-spike-integration-plan.md) WP2). Both questions it had to settle are answered there: a container path resolves against container-tagged `<directories>` entries only, and the whole-node baseline does not alert |
| — | `rt_file.bpf.o` is not yet supplied | **Newly identified**, [14 §14.6](14-spike-integration-plan.md). Route decided (a committed per-architecture prebuilt) and the lookup path is in place (`da90a18c5b`); what remains is fetching the portable vendored `vmlinux.h`, compiling, and **load-testing on a real kernel** before a binary is committed. Until then the container event path does not run on a package |
| — | ~~Per-dimension container row limits~~ | **Done, `2ea083add8`** ([14](14-spike-integration-plan.md) WP4), and the premise it was deferred on was wrong: container rows already traverse `checkDocumentLimit()` on this branch, so the enforcement had somewhere to land. The spike needed its Model B reconciler because *its* path bypassed dbsync. Validated on the node: 32 container package rows collected against a container budget of 2, 2 promoted, host counts untouched |
| 31 | Module boundaries and naming | `container_baseline` is still a library that looks like a wmodule, and the FIM driver still lives under `src/ebpf/` |
| 33 | Remove `IsOverlayWhiteout` / `OsBaselineRow::family` | Kept and documented instead: the whiteout helper is the one piece an M1 lower-layer fallback would need |
| 39–40 | Node-level benchmark and hash-vs-oracle validation | Require a real multi-container node; cannot be done in WSL |

## Environment notes found while verifying

1. **`TEST=yes` cannot configure on this branch** without commit `7c90011b5c` —
   `container_instances/CMakeLists.txt` referenced a `ci_impl/tests` directory lost in the rebase,
   and `add_subdirectory()` on a missing path is a hard CMake error that broke the whole agent
   build, not just that module's tests.
2. **`TEST=yes` still cannot complete in this WSL environment**, for an unrelated reason: CMake
   4.4.2 has dropped compatibility with `cmake_minimum_required(VERSION 2.8.12)`, which the
   vendored `external/googletest` still declares. Not caused by these changes; the module's tests
   were therefore built and run directly against a locally compiled gtest. This is also why the
   provider's contract tests are plain C with a two-line harness rather than gtest — they are worth
   having wherever the tree builds.
3. **`/usr/sbin/bpftool` is a dispatch stub on both hosts.** Debian/Ubuntu ship it as a
   kernel-version dispatcher that exits non-zero with `bpftool not found for kernel …` when no
   matching `linux-tools` package is installed. `find_program(bpftool)` finds it and it does not
   work — the provider's CMake therefore *probes* it rather than trusting the path, and at the time
   the VM needed `make BPFTOOL=/usr/lib/linux-hwe-7.0-tools-7.0.0-29/bpftool` to build the object.
   This cost one failed build before being diagnosed. **No longer needed on that host as of
   2026-09-08**: a real `bpftool v7.7.0` is now on `PATH` there, the probe accepts it, and
   `make build TARGET=agent` produces `rt_file.bpf.o` with no override. The probe is what makes both
   cases work, so it stays.
4. **No `vmlinux.h` and no libbpf headers are vendored in a normal checkout.** Both come from
   `external/libbpf-bootstrap`'s ExternalProject, which `src/external/CMakeLists.txt`
   short-circuits whenever a prebuilt `modern.bpf.o` is present — the common case. The deps tarball
   ships `libbpf.so`/`.a` and nothing else. This is why the provider shadows libbpf's types locally
   (`rt_libbpf_shim.h`) instead of including `<bpf/libbpf.h>`, and why the object build is gated
   rather than `REQUIRED`. [11 §11.6](11-ebpf-provider-import-plan.md#116-build-integration--the-largest-single-import-risk)
   point 4 assumed the vendored header was present; it is not. **Measured 2026-09-08:** on a host
   with `clang` and a working `bpftool`, the fallback branch fires and does produce the object —
   `eBPF Module: vendored vmlinux.h absent; generating one from this host's kernel BTF` — so the
   gap is the *packaging* pipeline, not the code. A header generated from one host's BTF is not
   portable, which is exactly why [14 §14.6](14-spike-integration-plan.md)'s committed prebuilt
   still needs the vendored header rather than this one.
5. **BPF has no 32-bit atomic swap.** `__sync_fetch_and_and(counter, 0)` and `__sync_fetch_and_sub`
   both fail to compile for `-target bpf` ("unsupported atomic operation, please use 64 bit
   version"); add is the only 32-bit atomic arithmetic available. An atomic read-and-clear has to be
   an add of the two's complement with the result discarded.
6. **The module's test suite was red on the branch as delivered** — two failures, both fixed here:
   `BuildProcessJson` asserted a string `pid` against the numeric one the code emits, and a test
   pinned the hash-truncation behaviour that finding C2 identifies as a defect.
