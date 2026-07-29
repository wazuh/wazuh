# #37533 — FIM integration (eBPF events + container enrichment as synchronized state): requirements analysis

Source: https://github.com/wazuh/wazuh/issues/37533 ("Spike: FIM integration — consuming eBPF events + container enrichment as synchronized state"). Parent objective: #37203 (Container runtime security). Worktree analyzed: `37533-spike` (branch `spike/37533-fim-ebpf-integration`).

This document maps the issue's own structure (Scope → Constraints → Possible angles → Deliverables → Acceptance criteria) against the code actually present in this worktree, distinguishing three states:

- **Done** — implemented and reasonably traceable to working code.
- **Partial** — a real piece exists but doesn't cover the full ask.
- **Missing** — no code, or only comments/TODOs marking the gap.

Two implementation waves are visible in this worktree's history: an earlier one (branch history references spike #37532 "baseline acquisition") that built `container_instances`, `container_baseline`, and the FIMDB schema changes; and changes made in this session that added a **live** (continuous, event-driven) container FIM path on top of that baseline. Both are covered below, with the session's own additions called out explicitly since they have not been compiled or tested.

---

## Scope

**In scope** (per issue): eBPF event contract consumption, enrichment join, path-resolution algorithm, synthetic identity/primary key, container-aware state model + sync, change-event emission with `changed_fields`, configuration surface, compatibility/limits story.

**Out of scope** (per issue): eBPF engine internals (owned by #37203-2), credential acquisition and container→pod metadata resolution (owned by #37203-1 / `container_instances`).

The worktree respects this boundary: FIM-side code never talks to Docker/K8s APIs or does cgroup→container resolution itself — it always goes through `container_instances`' IPC socket via `ContainerInstancesClient` (`src/shared_modules/container_instances_client/include/container_instances_client.hpp`). Good adherence to the stated seam.

---

## Angle-by-angle status

### 1. State model & primary key

**Done.** `file_entry`'s primary key was widened from `path` alone to `(container_id, path)`, `WITHOUT ROWID` (`src/syscheckd/src/db/src/db/fimDB.hpp:34-59`, `container_id` defaulting to `''` for host rows). This directly answers the issue's own question ("what is the stable primary key for a container file state?") with option `(container-scoped identity, internal path)`. `container_id`/`container_json` columns exist on the table for exactly this purpose (`fimCommonDefs.h:17-23`).

**Partial.** The in-memory C struct `fim_file_data` (`src/config/include/syscheck-config.h:279-305`) was **not** extended with `container_id`/`container_json` — only the SQL schema and the raw-JSON-row transaction API (`fim_db_transaction_sync_row_json`) carry them. This is why both the baseline path and this session's live path bypass the "normal" typed single-row update function (`fim_db_file_update`) and go through raw JSON rows instead. Extending `fim_file_data` itself (so container files could use the exact same code path as host files, including `fim_db_file_update`) remains undone and would be a larger, more invasive change touching Windows registry code sharing the same union.

**Not done.** No validation against the indexer/dashboard mapping is present in this worktree (that's a cross-team review step, not code).

### 2. Enrichment join

**Partial — baseline case done, live case newly added but limited.**

- The baseline path (`container_baseline_fim.cpp`/`container_baseline_fim_bridge.c`) resolves enrichment via `cbaseline_run_fim_dbsync()`, which internally lists containers and queries `container_instances` — this was already working before this session.
- This session added a **per-event** join for the live path: `fim_handle_container_whodata_event()` (`src/syscheckd/src/ebpf/src/container_live_fim.cpp`) calls `ContainerInstancesClient::resolveByCgroupId(cgroup_id)` per event.
- **Cache vs. synchronous decision**: the issue explicitly asks "synchronous per-event lookup vs a cached resolver: latency budget under load." This session chose synchronous, but moved it to a **dedicated worker thread** (`ebpf_pop_container_events`, fed by a new `containerEventQueue`) so the ring-buffer-draining thread never blocks on the up-to-~1s cold-cache IPC round trip (`container_instances_client.hpp:45-46`). There is **no in-process cache** in FIM itself — every event does a fresh connect-per-request IPC round trip. Under sustained load (the issue's own "thousands of file events/sec on a busy node") this queue will fill and drop, logged via a new `FIM_FULL_EBPF_CONTAINER_QUEUE` warning — no adaptive backoff or cache-then-refresh strategy.
- **Cold-cache / lifecycle-race handling**: implemented, but as an unconditional **drop**, not buffer-and-retry. `pending` and `unavailable` statuses are both dropped immediately (`container_live_fim.cpp`, the `lookup.status != resolved` check). The issue lists buffer/drop/emit-unenriched/retry as the options considered; this implementation picked the simplest (drop) and did not implement buffering or retry.
- **Container reaped between event and lookup**: no special handling; `notContainer` and any other non-`resolved` status is treated identically (drop).

### 3. Path resolution & volume semantics (FIM-owned)

**Partial — solved for the common case via an approach not anticipated in the issue text, but the volume-type matrix itself is undone.**

The issue frames this as needing OCI-mount-aware longest-prefix matching against a container's mount specs. The worktree's actual answer, present since the earlier baseline work and reused by this session's live path, is simpler and arguably more robust: **`/proc/<pid>/root/<in-container-path>`**, letting the kernel do the mount-namespace translation instead of reimplementing overlay/mount math in userspace. This is implemented in `rootfs_file_walker.cpp` (baseline, directory-walk form) and mirrored by this session's `fim_handle_container_whodata_event()` (single-path form, `container_live_fim.cpp`).

What this buys: no OCI-mount parsing code needed at all for the common case (rootfs writes, bind mounts, most volume types — because they're all just directory entries under the container's mount namespace, and `/proc/<pid>/root` walks through that namespace transparently).

What it does **not** solve:
- **Requires a live PID.** If the PID that triggered the event has exited by the time the event is processed, there is no fallback to another live PID in the same container. `ResolvePidsForContainer()` (`container_baseline/container_baseline_impl/include/pid_resolver.hpp`) already exists and does exactly this, but it is a private symbol of `CONTAINER_BASELINE_IMPL` (a static library linked `PRIVATE` into `container_baseline.so` — confirmed via `container_baseline/CMakeLists.txt`), not linkable from `container_live_fim.cpp`. This session's code drops the event in that case rather than duplicating or exposing that resolver.
- **The volume-type behavior table the issue explicitly asks for** (hostPath / emptyDir / configMap / secret / PVC / ephemeral CSI / image-volume / Docker bind & named volume — does the hook fire? what path semantic? recommended handling) **does not exist anywhere in this worktree.** The `/proc/pid/root` approach likely handles most of these transparently (they're all still visible under the container's mount namespace), but this has not been validated against real pod configs, and cases like NFS-backed PVCs or CSI drivers with unusual semantics are unverified.
- **Logical vs. host path duality**: the issue asks for `(logical_path, host_path)` as a pair — FIM needs both (logical to match config/identity, host to do I/O). The current code computes `host_path` only to perform I/O, and only ever persists `logical_path` (the kernel-reported path) as the row's `path` — this matches the intent but was not designed as an explicit named pair anywhere; it's implicit in the code.

### 4. Sync layer

**Done for the mechanism, partial for the specific concerns the issue raises.**

- FIM already had a working, generic sync mechanism before this session: `AgentSyncProtocol` (`src/shared_modules/sync_protocol/`), used identically by host FIM and syscollector, targeting `wazuh-states-fim-files` etc. (`syscheck.h:37-40`). The baseline path already proved container rows can ride this same mechanism (`container_baseline_fim_bridge.c`'s `fim_persist_baseline_row()` → `validate_and_persist_fim_event()` → `asp_persist_diff`).
- This session's live path reuses the identical entry point (`fim_persist_baseline_row()`), so **no new sync-protocol code was needed** — this is the strongest "already behaves like endpoint FIM state" result in the whole spike.
- **First-sync / reload semantics**: the issue explicitly flags this as "a live concern in the codebase." A concrete instance was found during research: `src/wazuh_modules/inventory_sync/benchmark/scenarios/session_mixup_repro.json` documents a real bug class where concurrent sync sessions (e.g. FIM and syscollector starting sessions at the same time) can cross-attribute sequence numbers. This was **found, not fixed** — container FIM adds more concurrent sync traffic on the same agent and inherits this risk unmodified.
- **Deletion propagation when a container disappears**: **not implemented**. `container_instances`' IPC protocol only supports `resolve`/`list`/`status` — there is no push notification when a container is removed. Neither the baseline (which does its own reconciliation by diffing `cbaseline_list_containers()` against the DB on each startup run) nor this session's live path have a mechanism to detect "this whole container is gone" outside of that startup reconciliation. A pod churning through many short-lived containers would leave stale per-file rows until the next agent restart re-runs the baseline reconciliation.

### 5. Change events + `changed_fields`

**Partial, and this is the most significant gap surfaced this session.**

- The diff machinery itself (`fim_calculate_dbsync_difference`, `src/syscheckd/src/file/events.c:25+`) is fully reusable and was not touched — it already diffs size/permissions/uid/gid/hashes/mtime/attributes field-by-field.
- **However**: `validate_and_persist_fim_event()` — the function both the baseline and this session's live path call — only produces the **stateful/synced document** (the `wazuh-states-fim-files` row). The **stateless alert** (the one carrying `changed_fields`) is built separately, upstream, inside `file.c`'s DBSync transaction callback (around line 330-457), a code path specific to the host `fim_db_file_update`/`fim_db_transaction_start(FIMDB_FILE_TXN_TABLE)` flow.
- Net effect: **a live container file change updates state correctly but does not currently generate a stateless FIM alert with `changed_fields`.** For the one-shot baseline this is arguably correct (no alerts wanted for pre-existing files). For the *live* path added this session, it is a real gap — a user would expect an alert when a container file is actually modified right now, the same way host whodata produces one. Wiring `fim_calculate_dbsync_difference`-style diffing into the container live path, and deciding what "changed_fields" means when several attributes (owner/group names, `attributes`) are simply never populated for container rows, is unstarted work.
- **Report-changes / content diff**: not implemented for container files; `FileBaselineRow`'s own doc comment already flags `owner`/`group` as deliberately left empty (needs the container's own `/etc/passwd`, called out as a separate, unaddressed data class).

### 6. Configuration surface

**Partial.** `<directories tags="container">` already exists as the selector mechanism (`directory_t.tag` in `syscheck-config.h`, checked via `strcmp(path->tag, "container")` in `container_baseline_fim_bridge.c:174,192`), and this session's live path reuses the exact same tag/config surface (via `fim_collect_container_monitored_paths()`) to decide which raw eBPF events are container-candidates at all. This means container FIM configuration today is genuinely unified between the baseline and the live path — no divergence introduced.

What's missing: the richer selector vocabulary the issue asks for (path prefix **plus** container/image/namespace/label selectors, generalized across Docker and Kubernetes) does not exist — today it's a single boolean tag on a directory, with no way to scope monitoring to, say, "only containers with label X" or "only namespace Y."

### 7. Coverage & limits

**Mostly not started.** No unavailable-options table exists in this worktree (which `<syscheck>` options — `whodata`, `realtime`, `recursion_level`, `restrict`, scheduled-scan semantics — are meaningless for event-driven container FIM is undocumented, though it can be inferred: recursion_level/restrict apply to the baseline's directory walk, not to the live per-event path, which has no directory-walk concept at all). No configurable item limits (NFR3) exist for container FIM specifically — the baseline hardcodes `max_files = 20000` and `max_hash_bytes = 104857600` per monitored path (`container_baseline_fim_bridge.c:198-199`), which are not configurable and not benchmarked against real numbers. No policy exists for "what happens at the ceiling" (stop tracking new / evict / alert).

### 8. Baseline / scan model

**Done, and this session's work is additive to it, not a replacement.** The one-shot startup baseline (`fim_run_container_baseline()`, called once from `main.c:318`) already existed and is unchanged. This session's contribution closes exactly the gap that baseline's own header comment flags as out of scope: `container_baseline_fim.h:26-39` states plainly that the baseline "does not yet handle live/ongoing container file-change events" and that a referenced `fim_handle_k8s_event()` "only ever emits a stateless alert... never a stateful baseline row" — that function did not actually exist in the codebase prior to this session. `fim_handle_container_whodata_event()` is the closest thing to it now, though (per the change-events gap above) it currently does the *opposite* of what that old comment described: it produces a stateful row but no stateless alert.

### 9. Edge cases

**Not addressed**, and explicitly documented as such in this session's new code rather than silently ignored:
- **hostPath volume also monitored by host FIM** (dedup vs. double-emit): `container_live_fim.h`'s doc comment states the live path always drops on `notContainer` rather than falling back to host semantics, calling this an open question matching the issue's own framing — not resolved.
- **Shared host namespaces** (`hostNetwork`/`hostPID`/`cgroupns=host`): not handled; on a cgroup-v1 host, `cgroup_id` collapses to an ambiguous constant per the kernel comment added in `modern.bpf.c`, and there is no fallback correlation via `mnt_ns` on the `container_instances` side (the field is carried through the event contract but nothing consumes it yet).
- **Init/sidecar/ephemeral containers, pause sandbox**: not addressed; attribution is whatever `container_instances` resolves for the triggering cgroup, with no special-casing.
- **Kata/VM-isolated runtimes**: not addressed; consistent with the #37396 eBPF spike's own conclusion that host-side eBPF likely can't see in-guest file ops, this was not revisited here.

---

## Deliverables — status summary

| Deliverable | Status |
|---|---|
| FIM container-state data model (PK, document shape) | **Done** (schema); indexer/dashboard review not done |
| Path-resolution algorithm + volume-type behavior table | **Partial** — `/proc/pid/root` technique solves the common case; volume-type matrix and PID-liveness fallback missing |
| Enrichment-join design (cache vs. sync, cold-cache handling) | **Partial** — synchronous + off-thread, no cache, drop-only cold-cache handling |
| Sync integration note (reuse existing infra, first-sync/reload, deletion bounding) | **Partial** — reuse proven; reload race found but not fixed; container-removal deletion not implemented |
| Change-event spec (`changed_fields`, host-side I/O needs) | **Partial** — diff machinery reusable but not wired; stateless alerts not produced for live container events |
| Configuration & selectors | **Partial** — tag-based selector works and is unified; richer selector vocabulary missing |
| Coverage/limits report | **Not started** |

## Acceptance criteria — status summary

- *Data model reviewed by FIM team, validated against indexer mapping* — **not done** (process step, not code).
- *End-to-end prototype on kind: synchronized doc + `changed_fields` event across an agent restart, file hashed via host path* — **partially achievable**: the hashing-via-host-path and sync-persistence pieces exist; the `changed_fields` stateless-event piece does not, so this criterion is not currently met end-to-end.
- *Path-resolution algorithm + volume-type table validated against real pod configs* — **not done**; no volume-type table exists to validate.
- *Enrichment-join and sync design reviewed against the first-sync-after-reload failure class* — **not done**; the failure class was located (`session_mixup_repro.json`) but not reviewed against this specific design or fixed.
- *Coverage limitations, edge cases, item limits documented with benchmarked defaults* — **not done**.

## Overall assessment

The strongest result across both implementation waves is that **container FIM state genuinely rides the same sync/persistence infrastructure as host FIM** — the schema, the sync-protocol call, and (for the live path) the path-resolution technique are all real, working-by-inspection code, not stubs. The weakest result is that **this is currently a "state-sync-only" implementation**: it keeps `wazuh-states-fim-files` correct but does not yet produce the alerting behavior (`changed_fields`) a live FIM change is expected to produce, and several of the issue's explicitly-named research deliverables (volume-type matrix, item limits, selector vocabulary, deletion-on-container-removal) remain undone. None of this session's additions have been compiled or tested — the worktree has no initialized `libbpf-bootstrap` submodule and no build directory.
