# 08 — Remediation roadmap

Ordered by "what would block a release" first, then "what makes it viable at 100 containers", then
"what makes it maintainable". Effort is rough: **S** ≤ 1 day, **M** ≤ 1 week, **L** > 1 week.

> **This is the original plan, not the current state.** Much of P0/P1 and item 21 are built;
> [09](09-implementation-status.md) is the authoritative status and
> [12](12-blocking-decisions.md) carries the decisions that reshaped several items. Four things are
> worth flagging here, because the tables below either state them wrongly or do not mention them:
>
> - **Item 21 is done** (`fc6e088b1a`). It also turned out to need far more than "the #37203-2 event
>   contract": a staging buffer, cgroup→container attribution, a routing policy, a release gate, and
>   a per-container entry point in `container_baseline`'s API that did not exist.
> - **Two P0 items came out of the 2026-09-07 end-to-end run, and both are now fixed** —
>   [C23](03-findings-correctness.md) (the re-read raced the write it was triggered by, so a
>   modification could go unreported entirely) by [D16](12-blocking-decisions.md)'s staged-path
>   settle, `60182a3a17`; and [C24](03-findings-correctness.md) (a configured path absent from an
>   image disabled that container's delete detection permanently) by
>   [D17](12-blocking-decisions.md)'s separation of the status facts, `1cab48878c`. That commit also
>   makes an in-container `rm` reportable, by acting on `RT_EV_FILE_UNLINK` instead of staging it as
>   a re-read that can only find nothing. **Both have now run on a real node** (2026-09-08,
>   [12 §12.15](12-blocking-decisions.md#1215-the-integrated-agent-on-a-real-node-2026-09-08)).
> - **Two items came out of reviewing the 37533/37534 spike branch as a whole**
>   ([14](14-spike-integration-plan.md)), and neither is in the tables either. **Container FIM rows
>   were persisted but never alerted on** — `fim_persist_baseline_row()` built only the stateful
>   document, so a change inside a container reached `wazuh-states-fim-files` and produced no FIM
>   alert. That was the largest remaining *functional* gap, since an alert is what a user sees, and
>   it is **now closed** (`888c29a4a6`, [14](14-spike-integration-plan.md) WP2).
>   And `rt_file.bpf.o` was never installed, so a packaged agent could not load the engine at all;
>   the install rule is fixed (`1bdfb0990e`) but the object is **still never built** by the packaging
>   pipeline, which needs a decision on where it comes from
>   ([14 §14.6](14-spike-integration-plan.md)). That one blocks shipping the event path at all, so it
>   belongs in P0 rather than in the tables' tail.
> - **Three P0 items came out of the 2026-09-08 run of the *integrated agent*, and none is in the
>   tables.** [C25](03-findings-correctness.md) — `<container_instances>` was never dispatched, so
>   the module could not start and neither consumer could reach container metadata; the whole
>   feature was unreachable from a real agent (fixed, `a98549d807`).
>   [C26](03-findings-correctness.md) — a change to an already-known container file raised no alert,
>   because `MODIFIED` arrived unwrapped and the callback discarded it; only first sightings got
>   through (fixed, `f39967c55c`). [C27](03-findings-correctness.md) — a path reconcile deleted the
>   rest of its container's rows, because closing a scoped transaction sweeps untouched rows whether
>   or not delete detection was asked for. Measured at the alert level on 2026-09-08, only the
>   *first* modification per container was ever reported as a modification; every later one arrived
>   as `added` (fixed, `d3a8e394d9`, [D18](12-blocking-decisions.md#d18--how-does-a-path-reconcile-persist-a-row-without-authorising-a-sweep-resolved-2026-09-08--the-non-transactional-upsert-d3a8e394d9)).
> - **A fourth came out of the follow-up run.**
>   [C28](03-findings-correctness.md#c28--with-no-containers-list-reads-as-connector-unavailable) —
>   `list` omitted the `containers` key when there were none, and the client reads a missing key as
>   an unreachable connector, so on a host with no containers the stale-row sweep never ran and both
>   consumers logged a fault that was not occurring (fixed, `7e059dd5aa`).
> - **[C16](03-findings-correctness.md#c16--dockers-deferred-reconcile-is-dropped-not-deferred) is a
>   live defect, not just an item-20 blocker, and belongs in P0.** Measured 2026-09-08: a container
>   removed with `docker rm -f` stayed in `list` for two minutes — past the 60 s removal grace —
>   because the grace only expires inside `applySnapshot()` and nothing re-runs it on the Docker path
>   without another event. The rescan masks the missed create; nothing masks the missed expiry, so on
>   an idle host a removed container's FIM and inventory rows are never swept.
> - **Item 20 has a constraint the tables do not record.** Post-startup container discovery works
>   today only because `RT_CGROUP_MODE_ALL` lets the drain see events from cgroups it has never heard
>   of. The events that expose a new container come from **runc's init** — measured: four write-intent
>   opens of procfs/sysfs files within a second of `docker run` — and resolving that unknown cgroup
>   escalates it to a re-walk in ~2 s. Two things follow: narrowing the filter before item 20 lands
>   would remove that discovery path entirely, and the path itself depends on runtime behaviour this
>   design does not control, so it is not a reason to treat item 20 as satisfied
>   ([12 §12.16](12-blocking-decisions.md#1216-the-lifecycle-question-answered-by-measurement-2026-09-08)).
> - **Per-dimension container row limits are done** (`2ea083add8`,
>   [14](14-spike-integration-plan.md) WP4), on a corrected premise: container rows already traverse
>   `checkDocumentLimit()` here, so the "nowhere for the enforcement to land" reason this was
>   deferred on was wrong.
> - **Item 14's FIM half is retired, not deferred.** "FIM baselines on `main()`" is
>   [11 §11.8.1](11-ebpf-provider-import-plan.md)'s deliberate design — an *unchanged call site* —
>   not the defect this roadmap treats it as. Moving the walk off `main()` would buy latency the
>   design already chose to spend, at the cost of racing host FIM's `file_entry` transactions.

## P0 — Correctness blockers

These produce wrong security data. None is architectural; all are contained fixes.

| # | Fix | Where | Effort |
| --- | --- | --- | --- |
| 1 | **Stop deleting stopped containers' FIM state.** Call `cbaseline_list_containers` and sweep only ids absent from *that* set — mirror `syscollectorImp.cpp:1987-2020`. Extract the [deletion decision table](06-proposed-architecture.md#68-deletion-semantics-stated-once) into one shared helper both consumers use. | `container_baseline_fim.cpp:163-182` | S |
| 2 | **Never emit a prefix digest.** Above the size limit, skip hashing and blank the fields, as `file.c:858-883` does. Honour `CHECK_MD5SUM`/`CHECK_SHA1SUM`/`CHECK_SHA256SUM`. Reuse `OS_MD5_SHA1_SHA256_File`. | `hash_helper.cpp`, `rootfs_file_walker.cpp:92-99` | S |
| 3 | **Fix the tag match.** Tokenise `path->tag` on `,` instead of `strcmp(tag, "container")`; the feature currently no-ops for any `tags="container,…"`. Add a startup log naming how many container paths were selected. | `container_baseline_fim_bridge.c:157-212` | S |
| 4 | **Detect namespace collapse.** Compare `/proc/<pid>/ns/{net,pid}` against `/proc/1/ns/*`; on `hostNetwork`, emit no container-scoped port/interface rows and record the collapse as an attribute. | `network_scanner.cpp`, `interface_scanner.cpp` | S |
| 5 | **Bound the file walk.** Record the root's `st_dev`; descend across a device boundary only into a declared `oci_mounts` destination, never into a host-root mount. Adopt `HasFilesystem`/`skip_fs`. | `rootfs_file_walker.cpp:107-129` | M |
| 6 | **Deduplicate pod-shared sockets.** Emit a port row only when its inode maps to a PID in *this* container's cgroup. | `network_scanner.cpp:186-197` | S |
| 7 | **Propagate `truncated` / `root_missing`** out of the C API; log on truncation; mark the baseline partial and suppress deletes for that container. | `container_baseline_scanner.cpp:314-322`, `container_baseline.h` | S |
| 8 | **Make the FIM transaction exception-safe.** Use RAII (or the existing `DBSyncTxn` pattern), check return codes, log `DB_ERROR`, and wrap `fim_run_container_baseline` in a `try`/`catch` so it cannot throw into `main()`. | `container_baseline_fim.cpp:109-127` | S |
| 9 | **Translate uid/gid through `/proc/<pid>/uid_map`** so file ownership and `/etc/passwd` share one id space; resolve `owner`/`group` names from the user/group rows already collected. | `rootfs_file_walker.cpp:84-85` | M |
| 10 | **Suppress volatile counters** from change detection *and* from the row checksum — wire `options.ignore` into `updateChanges` (the engine already supports it, `sqlite_dbengine.cpp:172-180`, `dbsync.cpp:1095`), or drop the counter columns from container rows. | `syscollectorImp.cpp:361-412`, `baseline_rows.cpp` | M |

## P1 — Scaling: viable at 100 containers

| # | Fix | Gain | Effort |
| --- | --- | --- | --- |
| 11 | **Eliminate the `/proc` sweep storm.** Best: add `pid` + `cgroupPath` to `ContainerRecord` and the wire record (additive, backward-compatible) so the baseline never walks `/proc`. Interim, no cross-module change: build **one** `cgroup-leaf → [pids]` index per run and pass it to every scanner. Replace the two `std::regex_match` calls with string compares. | **~300×** on resolver cost (~5–6 s/cycle → ~0) | S–M |
| 12 | **Collapse the 1+N IPC round-trips.** Parse `containers[]` from the existing `list` reply — it already carries full records — and delete the per-container `resolve` loop. Client-header change only. | **~100×** fewer connections | S |
| 13 | **Stream rows into an already-open per-container transaction.** Invert the consumer loops so the container is the outer unit of work; commit per container. | Peak memory **400 MB–4 GB → O(one row)** | M |
| 14 | **Move the work off critical threads.** FIM off syscheckd's `main()`; Syscollector off the scan thread's critical path. Remove the ~10 s of fixed startup sleeps in favour of surfacing "not ready" to the caller. | No startup stall | M |
| 15 | **Bounded concurrency** over containers with `Utils::AsyncValueDispatcher(fn, 2..4, maxQueued)`; keep DB writes serialised. Add a per-cycle deadline with rotating scan order so large nodes converge. | **2–4×** wall-clock | M |
| 16 | **Call `check_max_fps()`** in the container walk — the throttle NFR3 asks for already exists and is process-global. Make `max_files` / `max_hash_bytes` configurable instead of hardcoded. | NFR3 compliance | S |
| 17 | **Store the container context once.** Replace the per-row `container_json` blob with a container dimension row + reference; retain it under a tombstone so DELETE events stay self-contained. Cache the *parsed* blob per container so `ecsData` parses it once, not per row. | **~45 MB → ~150 KB** per scan; large CPU win | M–L |
| 18 | **Fix FIM's stale sweep query** — `SELECT DISTINCT container_id`, not `fim_db_get_every_element` materialising every row as cJSON. | Removes hundreds of MB of transient cJSON | S |
| 19 | **Single `lstat` per entry** in the walk (use `readdir`'s `d_type`); check the `max_files` cap before enqueueing so the pending deque cannot grow unbounded. | **2×** fewer stat syscalls | S |

## P2 — Architecture: make it a baseline

This is the group that closes the gap with #37532's actual intent.

| # | Change | Effort |
| --- | --- | --- |
| 20 | **Baseline once per container lifetime, not every interval.** Add a `ContainerRegistry` tracking baseline status; on each cycle baseline only *new* containers. Interim trigger: poll `list` every 30–60 s (one cheap IPC call) and diff ids. Preferred: add a `watch` op to `container_instances` streaming its already-computed `ReconcileDelta` (`reconciler.hpp:12-17`) as NDJSON. | M–L |
| 21 | ~~**Implement the handoff algorithm**~~ — **DONE** (`fc6e088b1a`). Subscribe-first, scan, reconcile-by-re-read, as [06 §6.3](06-proposed-architecture.md#63-the-baselineebpf-handoff) sketched and [06 §6.10](06-proposed-architecture.md#610-corrections--the-sketch-versus-the-implemented-contract) corrects. Overflow does escalate to "re-baseline this container", and re-baselining being idempotent is exactly what makes every Suspect edge collapse to that. | L |
| 22 | **Tier the data classes** and add the `image_digest` cache for image-derived classes (packages, users, groups, OS, services). ~85% reduction now, ~100% at steady state. Invalidate on container restart or writable-layer mtime. | M |
| 23 | **Re-baseline triggers**: eBPF drop signal, container restart, reload-widened scope, long-interval reconciliation. Reuse the existing first-sync guard so a reload neither re-alerts nor drops the seed. | M |
| 24 | **Add the `ContainerHandle` seam** — hold `O_PATH` fds on `/proc/<pid>/root` and `/proc/<pid>/ns/net` for the scan's duration (fixes the mid-scan PID-death race), expose `netScope`/`pidScope`/`uidMap`, and traverse with `openat` rather than string concatenation. Prefer the lowest PID; fall back to the next candidate on failure. | M |
| 25 | **Add an enable/disable config knob** for the Syscollector container baseline — it currently runs unconditionally on every Linux agent with no gate, unlike every sibling collector. | S |

## P3 — Maintainability

| # | Change | Effort |
| --- | --- | --- |
| 26 | **Delete the dead sync-protocol path** — `cbaseline_run_fim`, `cbaseline_run_syscollector`, and all 12 `Build*Json` functions (~170 lines, uncalled and demonstrably unvalidated — see [C12](03-findings-correctness.md#c12--processstart-is-silently-dropped-in-the-sync-protocol-path)). Option A won; record that and remove Option B. | S |
| 27 | **Collapse the boilerplate** — one `ContainerScoped` base replaces 12 `ApplyIdentity` overloads; a field-descriptor table per row type replaces 12 hand-written dbsync serialisers and makes the column set inspectable so it can be *checked* against `syscollectorTablesDef.hpp` instead of drifting. | M |
| 28 | **Reuse instead of reimplement**: `LinuxPortWrapper`/`PortImpl` for `/proc/net` parsing, `NetworkLinuxInterface`/`FactoryLinuxNetwork` for the `ifaddrs*` transform, `getDpkgInfo(libPath, cb)` for the dpkg driver (fix the TU split rather than working around it), `UsersProvider` with a rootfs-prefixing `ISystemWrapper::fopen`. See [05 reuse table](05-findings-clean-design.md#reuse-summary). | M |
| 29 | **Replace the process-global `g_everSawContainers`** with per-run state on a `BaselineService` object that owns the client, caches, PID index and budgets. | S |
| 30 | **Test the orchestrator.** Inject `IContainerSource` / `IPidIndex` / `IContainerCollector` so the lifecycle, deletion-semantics and truncation paths can be tested against fakes. Add integration tests for both consumers. Wire the `qa/` harnesses into ctest or delete them. | M |
| 31 | **Fix the module boundaries and naming.** Either register a real wmodule or rename the library so it does not claim to be one; move the FIM driver out of `src/syscheckd/src/ebpf/` (it has nothing to do with eBPF); correct `container_baseline.h:53-54`, which still documents a removed `<directories type="kubernetes">` config surface. | S |
| 32 | **Build hygiene**: `string(APPEND CMAKE_CXX_FLAGS …)` or `target_compile_options` instead of overwriting the parent's optimisation/hardening flags; replace `file(GLOB)` with explicit source lists; add a `src/Makefile` install rule. Convert `ponytail:` markers to `TODO:` so tooling sees them. | S |
| 33 | **Remove dead members** — `IsOverlayWhiteout` (cannot fire under `/proc` addressing) and `OsBaselineRow::family` (parsed then dropped). | S |

## P4 — The spike deliverables

#37532 is not closeable without these, independent of the code.

| # | Deliverable | Source |
| --- | --- | --- |
| 34 | Options matrix with primary + fallback per data class | [07-options-matrix.md](07-options-matrix.md) — review and ratify |
| 35 | In-container-exec accept/reject rationale, **and the `setns` exception written up and signed off** by #37203-4 | [07 §7.4](07-options-matrix.md#74-in-container-execution-evaluation-and-rejection-deliverable-d6) |
| 36 | Rootfs-resolution note: why `/proc/<pid>/root` supersedes per-runtime overlay resolution, with the userns and mount-boundary caveats | [07 §7.2](07-options-matrix.md#72-the-matrix), [03](03-findings-correctness.md) |
| 37 | Handoff algorithm + re-baseline triggers | [06 §6.3](06-proposed-architecture.md#63-the-baselineebpf-handoff) |
| 38 | Timing & triggering model | [06 §6.4](06-proposed-architecture.md#64-timing-model-and-the-one-change-that-makes-it-work) |
| 39 | **Cost & limits report with real numbers** — benchmark on a real multi-container node: wall-clock per rootfs size, cold-start storm at N=10/50/100, image-digest de-dup saving, and throttle defaults derived from those numbers rather than picked | To be produced; [04](04-findings-performance.md) gives the model and a micro-benchmark, not node-level measurements |
| 40 | **Hash-vs-oracle validation** — compare M2 hashes against in-container `sha256sum` for symlinks, sparse files, hardlinks, files on tmpfs/secret mounts, and userns-remapped containers. This is an explicit acceptance criterion and was never performed. | To be produced |
| 41 | Docker parity + edge-case table | [07 §7.6](07-options-matrix.md#76-runtime-parity-and-edge-cases-deliverable-d8) |

## Suggested sequencing

1. **P0 items 1–4, 6–8** (all S) — a few days, removes every false-alert and silent-no-op class.
2. **P1 items 11, 12, 18, 19** (S) — a few days, ~300× and ~100× wins for very little code.
3. **P4 items 34–38** — write up the decisions; get the `setns` exception signed off. Unblocks review.
4. **P1 items 13–17** + **P0 items 5, 9, 10** — the substantive scaling and correctness work.
5. **P2 items 20, 22, 24, 25** — turn it into an actual baseline; the biggest steady-state win.
6. **P2 item 21** — the handoff, once #37203-2's contract exists.
7. **P3** — cleanup, ideally folded into the work above rather than deferred.
8. **P4 items 39–40** — benchmark and oracle-validate on a real node; these numbers should feed back
   into the throttle defaults chosen in step 4.

Steps 1 and 2 together are roughly one engineer-week and address the highest-severity findings in
this analysis.
