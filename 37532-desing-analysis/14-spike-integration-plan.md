# 14 — The 37533/37534 spike branch, reviewed against this one

What `spike/37533-37534-fim-syscollector-ebpf-integration` has that
`37532-5-0-0-container-integration` does not, which of it is worth taking, which of our
[open decisions](12-blocking-decisions.md) it settles, and a plan for the rest.

- **Spike branch:** `spike/37533-37534-fim-syscollector-ebpf-integration` at `0080d7d294`
  (worktree `~/wazuh/source/37534-spike`), last touched 2026-08-05, based on a 2026-07-02 5.0.0.
- **This branch:** `37532-5-0-0-container-integration` at `f39967c55c`, 54 commits ahead of
  `origin/5.0.0`, and the remote branch is at the same commit.
- **Review date:** 2026-09-07. **WP1, WP2, WP3 applied and WP6 unblocked, 2026-09-07** (§14.6);
  **WP4 applied and WP1–WP3 validated on the integrated agent, 2026-09-08**
  ([12 §12.15](12-blocking-decisions.md#1215-the-integrated-agent-on-a-real-node-2026-09-08)).
  **D18 resolved and C27 fixed, 2026-09-08** (`d3a8e394d9`), which clears WP5's remaining gate;
  WP5 and WP6 remain, WP5 now gated only on [D9](12-blocking-decisions.md).

> This is the review [12 §12.6](12-blocking-decisions.md#126-d2-in-depth--which-way-integration-runs)
> promised would happen **once, deliberately**. [D2](12-blocking-decisions.md) settled the
> direction — the spike's work comes forward onto this branch — and
> [§12.13](12-blocking-decisions.md#1213-the-port-order-finished-2026-09-07) worked through the
> commit-by-commit port order. This document is the other half: the spike's *whole tree* against
> ours, including the parts no commit in that order touched.

## 14.1 Method, and why a branch diff is useless here

`git diff HEAD spike/… -- src/` is 1,840 files and 1.3 M lines: almost all of it is the two
branches' different 5.0.0 bases, not anybody's feature work. The spike's own contribution is
`git diff 66301af90d spike/…` — 82 files, +5,417/−2,978 — because this branch is a truncated cut of
that spike at `66301af90d`. Everything below is read from that diff.

Two claims that the whole plan turns on were **measured against the real libraries** rather than
read, because reading them wrong would send the plan the wrong way. Both are in §14.3.

## 14.2 The inventory

| # | Spike element | Where | This branch | Verdict |
| --- | --- | --- | --- | --- |
| 1 | **`rt_file.bpf.o` install rule** | `src/init/inst-functions.sh` | absent — `CB_RT_BPF_OBJECT_PATH` pointed at a file nothing installed | **Ported, `1bdfb0990e`** |
| 2 | **`extern "C"` on `OS_MD5_SHA1_SHA256_File`** | `md5_sha1_sha256_op.h` | absent | **Ported, `fdcca35d0c`** |
| 3 | **Live container FIM path** (event ⇒ single-row upsert/delete, `changed_fields` alert, lazy catch-up walk) | `container_live_fim.cpp`, 836 lines | absent; A3 reconciles by re-walking instead | **One piece taken, `888c29a4a6`** (the stateless alert, WP2); rest rejected — §14.5 |
| 4 | **`fim_db_container_file_delete()` + `DB::removeFile(path, containerId)`** | `db/src/file.cpp`, `db.h` | absent | **Port with [D17](12-blocking-decisions.md)** (WP3) |
| 5 | **A4 — host FIM whodata cut over to `rt_engine`** | `ebpf_whodata.cpp` rewritten; `modern*.bpf.c` deleted | not done, deliberately (ADR-001, [D9](12-blocking-decisions.md)) | **Plan separately** (WP5); do not take as written — §14.5 |
| 6 | **Per-dimension container row limits** + manager→agent delivery | `module_limits.{h,c}`, `remoted/{config,manager}.c`, `client-agent/{agcom,start_agent}.c`, `test_module_limits.c` | absent | **Transport portable now, enforcement is not** — §14.3, WP4 |
| 7 | **Model B — durable SQLite prior-state reconciler** | `container_baseline_impl/…/reconcile/*` (~1,300 lines + tests) | not imported | **Reject** — [D1 = Option 3](12-blocking-decisions.md#125-d1-in-depth--the-two-inventory-state-models) |
| 8 | **`<container_baseline_interval>`** | `wmodules-syscollector.c`, `syscollectorImp.cpp` | ported `4b365c11d6` | Done |
| 9 | **`container_id`/`container_json` in `fim_file_data`** | `syscheck-config.h`, `dbFileItem.*`, `file.c` | ported `69303187cd` | Done |
| 10 | **`ebpf_provider` tree** | 9 files as imported from `9113442eb4` | same import, plus in-kernel filtering, per-cgroup drops, link teardown, ABI guard and 4 kernel tests (+1,936 lines) | **We are ahead** — nothing to take |
| 11 | **`container_instances` changes** | *none* — only its `CMakeLists.txt` | — | **The spike answers neither [D6](12-blocking-decisions.md) nor [D7](12-blocking-decisions.md)** |
| 12 | **The five design documents** | `spike-37533/` | byte-identical copies already here | Done |
| 13 | **`libbpf_external` / `modern.bpf.o` removal** | `src/external/CMakeLists.txt` | kept | Part of WP5, not separable from A4 |

## 14.3 What the spike settles

### The `deleted_rows` flush claim is wrong, and that de-risks our D15 path

`container_live_fim.cpp`'s `catch_up_container_baseline()` states, of
`fim_db_transaction_deleted_rows()`:

> Required to actually flush/commit the synced rows — confirmed on real hardware: without this call,
> a multi-row transaction like this one … only persisted 1-2 of several hundred synced rows, the rest
> silently lost.

If that were true it would be a **critical defect in our A3**, because [D15](12-blocking-decisions.md)
makes a path reconcile close its transaction with `fim_db_transaction_close()` and never call
`deleted_rows` — so every path reconcile would be persisting almost nothing, and our end-to-end run
could not have shown it (the harness replaced `libfimdb` with an in-memory store that persists on
`sync_row`).

It is not true. Measured against the **real `libfimdb`**, now pinned by
`src/syscheckd/src/ebpf/tests/txn/` (`7117b9fb08`):

| Property | Measured |
| --- | --- |
| `close()` with no `deleted_rows` | 500 rows in, **500 callbacks out**, 0 lost |
| Same against `libdbsync` directly | 1, 500 and 5,000 rows — every callback delivered |
| Same with the transaction **never closed at all** | still 500 of 500 |

The mechanism: dbsync's `Pipeline` dispatches results through `Utils::ReadNode`, whose `Dispatcher`
template parameter **defaults to `SyncDispatcher`** (`pipelineNodesImp.h:25`) — the callback runs
inline on the calling thread, so `threadNumber` and `maxQueueSize` do not gate delivery at all, and
there is nothing for a flush to flush. The spike's row loss is far more likely the *transaction
overlap* the same file identifies two functions later ("an async version of this … walked several
hundred files correctly but only 2 ended up persisted"), which is the same shape as the 502-of-504
loss already recorded in [09](09-implementation-status.md#thread-ownership-item-14--d5).

The same test closes three more of [09](09-implementation-status.md)'s "libfimdb never exercised"
gaps: `container_id` is genuinely part of the primary key (the same 500 paths under a second
container insert rather than update), a scoped `deleted_rows` sweep deletes exactly the untouched
rows *in that scope* (495 of 500), and another container's rows survive it. Mutation-checked: dropping
the scope clause fails two cases, collapsing every row's `container_id` fails two.

> **Correction, 2026-09-08 — this de-risked less than it looked like.** Everything above still
> holds: `close()` loses no row *callback*, and there is nothing for a flush to flush. What none of
> those four cases asked is what `close()` does to the rows the transaction did **not** touch. It
> deletes them — `DBSyncImplementation::closeTransaction()` runs `deleteRowsByStatusField()`
> unconditionally — so D15's path reconcile, whose row set is a subset by design, wipes the rest of
> its container's state on every close. That is
> [C27](03-findings-correctness.md#c27--a-path-reconcile-deletes-the-rest-of-the-containers-rows),
> found on the integrated agent and now pinned as case 6 of the same suite. The spike's row loss and
> ours turn out to have the same *symptom* from different causes, which is part of why reading its
> claim did not surface this.
>
> The suite also missed [C26](03-findings-correctness.md#c26--a-change-to-an-already-known-container-file-raises-no-alert)
> for a related reason: its own callback counted `MODIFIED` regardless of the payload's shape, while
> the production callback discards any `MODIFIED` that is not wrapped as `{"old","new"}`. Case 5 now
> asserts the shape, not just the count.

### D9 is answered in practice — the spike did A4

The spike deleted `modern.bpf.c`/`modern-arm.bpf.c` (1,449 lines) and rewrote `ebpf_whodata.cpp`
around `rt_open`/`rt_poll`/`rt_close`, so host FIM whodata and the container path share **one**
engine, one ring and one drain thread. That is A4, and it demonstrably built and ran. So the answer
to "is the duplicated BPF load acceptable until A4?" is that A4 is reachable and someone has already
walked it — but see §14.5 for what it cost.

### Item 20's create trigger has a substitute that needs no `container_instances` change

`startup-race-solutions-and-edge-cases.md`'s Option C, implemented as
`maybe_catch_up_container_baseline()`: when the live path first resolves a container that has **zero**
`file_entry` rows, walk its configured directories once. No `list` cursor, no delta API, no
[D7](12-blocking-decisions.md).

**Already superseded on this branch, and by something stronger.** Our resolver thread re-walks a
container as soon as it is identified, whatever its row count — which is why the end-to-end run
picked up a container created 8 minutes in with nothing seeding it. Option C would miss a container
that already has rows but has drifted, and its gate (`fim_db_get_every_element` with a `WHERE …
LIMIT 1`) is the query shape [item 18](08-roadmap.md) exists to remove.

### One spike-open finding this branch has already closed

The spike's test plan records finding #2 — FIM's one-shot baseline racing the Docker connector's
warm-up, so whichever containers were not yet known were never baselined — as **"not fixed in code
this pass"**. `c5bc0a1d76` fixes it here (`kListRetryAttempts` × `kListRetryDelay`, latched once per
process).

## 14.4 What it does not settle

| Our block | Spike's position |
| --- | --- |
| **[D16](12-blocking-decisions.md)** — how a path reconcile sees post-write state | Not addressed. Its live path re-reads immediately too, so it has the same race. Its test plan reports create+modify *working*, which is explained by its own finding #3b: the writing PID is usually already dead by the time the event is processed, so the write has completed. That is a real datum — see the fourth D16 option below — but not a design. |
| **[D17](12-blocking-decisions.md)** — what "incomplete" authorises | Not addressed; `partial` collapses the same three facts. |
| **[D6](12-blocking-decisions.md)** — Docker `all=1` | Untouched. `container_instances` has no source change on that branch at all. |
| **[D7](12-blocking-decisions.md)** — the delta/create-trigger API | Untouched, same reason. |
| **[D11](12-blocking-decisions.md)** — cgroup v1 | Not addressed, and its live path would mis-attribute: `container_live_fim.h` itself documents `cgroup_id` as "0 or a cgroup-v1-ambiguous constant on cgroup-v1 hosts" and then resolves it anyway. |
| Real-node cost numbers ([items 39–40](08-roadmap.md)) | Not produced. |

### A fourth option for D16, which the spike's finding #3b suggests

[§12.12](12-blocking-decisions.md#1212-the-end-to-end-run-2026-09-07-and-the-two-decisions-it-forces)
lists three shapes: trailing re-read, re-read until stable, or a close-write event from the provider.
The spike's measurement adds a cheaper one: **settle the path in the staging buffer before
reconciling it** — hold a staged path until either the triggering PID has exited or a bounded delay
has elapsed, then read once. Cost is one stat+hash rather than two, the delay is bounded, and it needs
no new per-path state because the staging buffer's dedup map is already keyed by exactly that path.
It does not fix a writer that outlives the delay, which no consumer-side option can.

## 14.5 What the spike gets wrong, so we do not inherit it

1. **Every live event leaks a transaction.** `upsert_container_file_row()` calls
   `fim_db_transaction_start()` then `fim_db_transaction_sync_row()` and **returns** — no
   `deleted_rows`, no `close`. `PipelineFactory::create()` keeps the `Pipeline` in `m_contexts` until
   someone calls `destroy()`, so each monitored write inside a container leaks a pipeline object and
   an open DB transaction context, forever. Not a row-loss bug (§14.3), but unbounded growth
   proportional to container file activity.
2. **The container scope is back inside the row checksum.** Both checksum sites in
   `container_live_fim.cpp` feed `container_id` and `container_json` into
   `fim_compute_row_checksum()` — which is [C19/C20](03-findings-correctness.md), fixed here in
   `9554439005`. Any port of that file has to drop those two lines.
3. **It deletes on a failed `lstat`, which is what [D15](12-blocking-decisions.md) forbids** —
   "Confirmed live pid, missing file: genuine delete." The liveness check is
   `access("/proc/<pid>", F_OK)` and the delete decision is an `lstat` of
   `/proc/<pid>/root<path>` **afterwards**, so anything that makes the rootfs unreadable in that
   window — the container exiting, the fallback PID exiting, a permissions failure — deletes the row
   *and* emits a stateless `deleted` alert. This is C15's shape at single-row granularity.
4. **It throws away the kernel's own event type.** `handle_event()` never reads `ev->event_type`,
   even though the contract it imported defines `RT_EV_FILE_UNLINK` and `RT_EV_FILE_RENAME`
   (`rt_event_contract.h:42-47`). So it re-derives "deleted" by inference from a failed read while
   discarding the event that *states* the removal — precisely backwards from what
   [D17](12-blocking-decisions.md)'s unlink question proposes.
5. **A4 was paid for with test coverage.** Four `fimEbpfWhodataTest` files were deleted
   (`init_libbpf`, `init_bpf_obj`, `init_ring_buffer`, `close_libbpf` — 370 lines) and
   `ebpf_whodata_test.cpp` and `ebpf_mock_utils.hpp` cut back by 305 more, replaced by a 62-line
   `link_stubs.cpp`. Those are the tests ADR-001 kept out of item 21's blast radius on purpose.
6. **Debug instrumentation its own comments say to delete** is still in both
   `container_live_fim.cpp` and `ebpf_whodata.cpp` ("TEMPORARY instrumentation … remove once that
   investigation is closed"), on the per-event path.
7. **Its `inst-functions.sh` fix is incomplete for packaging.** It updates the install rule and
   nothing else; the rpm spec's `find-debuginfo.sh` dance, the deb lintian override and the four
   `check_files` manifests all still name only `modern.bpf.o`. `1bdfb0990e` covers the first three.

## 14.6 Integrated today

| Commit | What | Verified |
| --- | --- | --- |
| `1bdfb0990e` | `rt_file.bpf.o` installed alongside `modern.bpf.o`; rpm spec + lintian override | `bash -n`; the CI manifests still need a real package build |
| `fdcca35d0c` | `OS_MD5_SHA1_SHA256_File` declared with C linkage | clean full `make -j` of the agent target |
| `7117b9fb08` | 4-case scoped-transaction contract test against real `libfimdb` | `make check` 4/4; 2 mutations, each killing 2 cases |
| `888c29a4a6` | **WP2** — the container FIM stateless alert | `make check` 27/27; 5 mutations, each killing the cases naming what it breaks |
| `c0e5f162bb` | the missing engine is a warning, and only when container directories are configured | clean full build; both standalone suites still pass |
| `60182a3a17` | **WP1** — D16's settle in the staging buffer | 35 assertions, 5 clean consecutive runs; 6 mutations, all killed |
| `1cab48878c` | **WP3** — D17's separated status facts and the unlink path | 39 + 17 assertions; 6 + 3 mutations, all killed |
| `da90a18c5b` | **WP6's prerequisite** — the prebuilt object path is per-architecture | configure names the exact path it looks for |

`1bdfb0990e` is the one that mattered: `CB_RT_BPF_OBJECT_PATH` is `"lib/rt_file.bpf.o"` relative to
the install directory and **nothing installed it**, so on a real agent `rt_open()` could never find
its object and the whole container event path would take its silent "no engine" degradation. The
end-to-end run could not show this because the harness passes an explicit path into the build tree.

### `1bdfb0990e` only fixed half of it: the object has no supply

Chasing WP6 turned up the other half. `libbpf-bootstrap` is fetched as a **precompiled** external
resource (`src/Makefile`'s `external-precompiled` list), so `modern.bpf.o` arrives prebuilt —
1,000,448 bytes, dated with the deps tarball — and `external/CMakeLists.txt` short-circuits its
`ExternalProject` entirely. That is also what makes the vendored per-architecture `vmlinux.h`
absent, as `ebpf_provider/CMakeLists.txt` says in as many words. `rt_file.bpf.o` therefore falls
through to its last branch, which needs `clang` **and** libbpf development headers **and** either
that vendored `vmlinux.h` or a working `bpftool` plus `/sys/kernel/btf/vmlinux`. A package-build
container has none of those.

So on a packaged agent the object is **not produced**, `inst-functions.sh`'s `-f` guard installs
nothing, and the silent degradation happens anyway. Confirmed in this checkout: no
`src/build/lib/rt_file.bpf.o`, no `external/libbpf-bootstrap/vmlinux.h/`, and
`external/libbpf-bootstrap/build/modern.bpf.o` present as a shipped binary.

Two supply routes, and picking one is a **decision** (see §14.7 WP6):

| Route | Cost |
| --- | --- |
| Add `rt_file.bpf.o` to the deps tarball, exactly as `modern.bpf.o` is | a deps revision (`RESOURCES_URL`/`DEPS_VERSION`) and a per-architecture build of it, owned by whoever owns that pipeline |
| Commit `src/shared_modules/ebpf_provider/prebuilt/rt_file.bpf.o` — a path the CMake **already** honours as its first branch | a binary in the repo, and one object per architecture to keep current |

`c0e5f162bb` does not fix the supply; it makes the failure diagnosable, which is the part that let
the first half survive. The drain now starts only once a `<directories>` entry is tagged
`container`, so the "no engine" message can be a `mwarn` that fires exactly when the operator asked
for container FIM and is not getting it. Its old wording was wrong as well — it promised a fallback
to "scheduled baselines only", and there is no scheduled container baseline:
`fim_run_container_baseline()` is called once from `main()` and the only thing that re-runs it is the
drain's own `rebaselineAll`, so with no drain container FIM is a startup snapshot that never updates.

## 14.7 The plan

Ordered by whether the feature is wrong without it. Each package names its gate, so nothing here is
blocked on reading this document twice.

**State, 2026-09-07.** Three decisions were taken (D16 = settle in the staging buffer, D17 = the
narrow fix plus the unlink half, and the object supply = a committed per-architecture prebuilt), so:

| | State |
| --- | --- |
| **WP1** | **Done**, `60182a3a17` |
| **WP2** | **Done**, `888c29a4a6` |
| **WP3** | **Done**, `1cab48878c` |
| **WP4** | **Done**, `2ea083add8` — see below for why the "nowhere to land" premise was wrong |
| **WP5** | Open, and deliberately not started. Both of its earlier gates are cleared — WP1–WP3 proved out on a real node, and C27/D18 is fixed — so it is now gated only on D9 |
| **WP6** | Unblocked and half-done, `da90a18c5b`. What remains is producing the object and the CSV rows, together |

### WP1 — D16: settle the post-write read — **DONE, `60182a3a17`**

**D16 decided: settle in the staging buffer.** A staged path is held until the pid that triggered it
has exited or a bounded delay (`DrainConfig::settle_delay_ms`, 500 ms) has elapsed, then read once.
Chosen over the trailing re-read on cost — one stat+hash instead of two, and no verify-later set to
carry — and over re-read-until-stable, which is unbounded on an append-heavy file.

The buffer already keyed its pending set by exactly the path that needs settling, so this cost one
pid and one deadline per staged path and no new structure. The pid is what makes it cheap in the
common case: the spike's finding #3b measured that the writing process is usually already gone by
the time the event is processed, so most paths are released on the liveness probe and never pay the
delay at all. It remains a **bound, not a guarantee** — a writer that outlives it is still read
mid-write, which no consumer-side option can prevent.

Four things that are decisions rather than incidentals:

- A repeat event takes the newer pid — so the probe asks about the writer actually holding the file —
  but does **not** extend the deadline. Extending it per write is precisely how an append-heavy log
  starves, which is the objection to re-read-until-stable arriving by the back door.
- Suspect work bypasses the settle: a re-walk reads whole directories, so there is no single write
  for it to race.
- `nextBatch()` re-arms its own wait rather than returning "no work" while something is settling —
  the consumer's loop calls straight back in and would otherwise spin a core. It re-checks every
  50 ms, so the early release is not deferred to the consumer's own 500 ms poll.
- Pid probes are capped at 64 per call, because they run under the mutex the drain needs. At the
  measured 8,400 events/s the drain wants that lock every ~119 µs; 64 `/proc` lookups is ~200 µs
  against 2.4 s of ring capacity.

The delay defaults to **0 in the buffer** and 500 ms in `DrainConfig`: the buffer is the mechanism,
the policy belongs to the config. A 0 delay is exactly the pre-settle behaviour and costs no probe,
which is what keeps the fourteen existing gtest cases in `tests/unit/` valid unchanged.

*Verified:* `tests/settle/`, 35 assertions, five clean consecutive runs (it is timing-dependent, so
that matters), six mutations all killed. One of them initially **survived**: the append-heavy case
drained after the writes stopped, which passes whether or not the deadline is being pushed out. It
had to observe the path being served *while writes were still arriving*.

*Still worth doing:* the deferred-write probe from the end-to-end run, as a harness regression test —
an 8-second-deferred write must now produce a `MODIFIED`. Only a real node can show that.

### WP2 — the stateless alert for container FIM rows — **DONE, `888c29a4a6`**

The gap: this branch persisted container FIM rows and never alerted on them.
`fim_persist_baseline_row()` ended at `validate_and_persist_fim_event()`, which builds only the
stateful document — so a file changing inside a container updated `wazuh-states-fim-files` and
produced no FIM alert at all, no `changed_fields`, nothing an analyst sees. No finding named it,
because every test here asserts on rows.

`fim_send_container_stateless_event()` lives in `container_baseline_fim_bridge.c`, not in a new
file and not in the C++ driver: the bridge already includes `syscheck.h`, so it reaches host FIM's
own `fim_attributes_json()` and `fim_calculate_dbsync_difference()` in C with no `extern "C"`
wrestling at all — which is the whole trap [§12.13 step 4](12-blocking-decisions.md#1213-the-port-order-finished-2026-09-07)
records. `container_txn_callback()` now also forwards DBSync's `"old"` object, which is what
`changed_fields` is derived from, and sends the alert before persisting (file.c's order).

The three questions the port had to answer, none of which the spike addresses:

| Question | Answer, and why |
| --- | --- |
| Which `<directories>` entry supplies the check options and tag? | **Not `fim_configuration_directory()`.** It searches every entry, so with `<directories tags="container">/etc</directories>` and a host-only `<directories>/etc/ssl</directories>`, a container row for `/etc/ssl/cert.pem` would resolve to the host-only entry and take *its* options and tag. A container row can only have come from a container-tagged root, so `fim_container_configuration_directory()` resolves against those only — and matches on `->path`, not `fim_get_real_path()`, because symlink resolution is a property of the host filesystem and means nothing inside a container's mount namespace. |
| Does the initial whole-node baseline alert? | **No.** The first walk inserts every file in every container; alerting on all of them is a startup flood. Host FIM suppresses exactly this via `notify_scan` / `<notify_first_scan>`, and the container walk cannot borrow that flag — it runs one-shot from `main()` before the host's first scan has necessarily finished, so that flag's value says nothing about whether the *container* baseline is a first scan. `fim_container_events_release()` is already the "baseline committed, consumer is live" boundary, so it latches this too. |
| What does `mode` report? | A walk is `"scheduled"`, an eBPF-event-driven reconcile is `"whodata"` — rather than the spike's hardcoded `"whodata"`. `cb_fim_origin_t` carries the intent across the bridge so the C++ driver need not hard-code `fim_event_mode`'s numeric values. |

One deliberate divergence from `file.c`: an empty `changed_fields` withholds only the **alert** and
still persists the row. The row really did change — DBSync said so — and the stored state should say
so; host FIM's `goto end` drops both.

*Verified:* `src/syscheckd/src/ebpf/tests/alert/`, 27 assertions, plain C with its own Makefile for
the same reason [`tests/txn/`](#143-what-the-spike-settles) is — it must be runnable wherever the
tree builds. C rather than C++ because `syscheck.h` has no `extern "C"` guard and reaches `<atomic>`
transitively, so a C++ test can neither wrap it nor leave it unwrapped. The real
`fim_attributes_json`/`fim_calculate_dbsync_difference` are linked out of `libsyscheckd_lib.a`,
which is the point: an alert whose shape drifts from a host FIM alert is the defect the test exists
to catch. Five mutations, each killing the cases that name the property it breaks — dropping the
container-tag restriction (3), the first-scan latch (1), the empty-diff exit (1), the delete's
attribute suppression (2), the mode selection (1).

*Still worth doing:* extend the end-to-end harness's log sink to assert one alert per reconciled
change on a real node. The unit test pins the alert's shape; only the harness can pin that one is
actually emitted per reconcile.

### WP3 — D17, including the unlink half — **DONE, `1cab48878c`**

**D17 decided: the narrow fix plus the unlink half** (seam S1's per-table `partial` was the third
option and was not taken — see "Not planned" below).

**The narrow fix.** `partial` collapsed three facts and any one of them switched delete detection off
for the whole container; the absent-root case is static, so the switch never flipped back
([C24](03-findings-correctness.md)). An absent root is now its own fact and is deliberately **not**
part of `partial`: the walk looked, and there is nothing there. One bad `<directories>` entry no
longer stops deletions being detected under every other entry.

What makes that split safe is a single check, and it is the whole point of the change:
`/proc/<pid>/root/<path>` **also fails with ENOENT once the pid has exited**, so errno alone would
report a vanished container as a set of vanished directories — C15's mass false delete arriving one
root at a time. `WalkContainerPath()` now confirms the rootfs is still addressable before calling a
root absent, and reports `root_unreadable` otherwise.

`cb_container_status_sink_t` becomes a struct-taking callback. That is a break for both consumers
(FIM and Syscollector, both updated), taken deliberately: the reasons will keep accruing, and a
struct lets a field be added without touching a consumer that does not read it.

**The residue, stated plainly.** The decision's text says "scope delete detection to the roots that
did resolve". What landed lets delete detection run *over the whole container scope* once no
suppressing fact is present, which means rows under a root that has genuinely vanished are deleted —
the truthful outcome, and the dangerous case (a vanished rootfs) is now `root_unreadable` and still
suppresses. Preserving those rows instead is **not expressible with today's DBSync**: a scoped
transaction is a single-column equality, so "everything except this path prefix" cannot be said, and
preserving them means re-syncing full stored rows, which needs the durable prior-state reconciler
[D1](12-blocking-decisions.md#125-d1-in-depth--the-two-inventory-state-models) declined.

**The unlink path.** `RT_EV_FILE_UNLINK` names the file the kernel removed, so acting on it is not
the inference D15 forbids — D15 refuses to read a *failed read* as a removal, because a failed read
has three causes and two of them are wrong. There is nothing to infer from an event that states the
removal, and the spike had this exactly backwards: it never read `ev->event_type` and then re-derived
"deleted" from a failed `lstat`.

`fim_db_container_get_path()` was written rather than pairing a read with
`fim_db_container_file_delete()`: the row about to be removed carries the checksum and document
version the stateful DELETE needs, so it is read first and reported through the same
`container_txn_callback` every other change goes through. One code path builds the alert and the
stateful document. A path with no stored row produces nothing — the ordinary case, since most files
unlinked inside a container were never baselined.

Routing decisions worth keeping: an unlink supersedes a pending re-read of the same path and a later
write supersedes the unlink (newer event wins both ways); unlinks bypass the settle; they are served
before staged paths; a re-walk supersedes them entirely; and overflowing the unlink budget escalates
to a re-walk rather than handing over a truncated list. The C22 prefix filter applies, because an
event can carry a host-form path into a runtime snapshot directory and deleting on one of those would
remove a row for a file that is fine.

*Verified:* `tests/unlink/` 39 assertions and `tests/walker/` 17, with six and three mutations
respectively, all killed — including both directions of the ENOENT classification and the removal of
the rootfs guard. Three of the walker mutations initially "survived": neither that Makefile nor
`tests/alert/`'s listed the **static** archive it links as a prerequisite, so a rebuilt library left
the test binary exercising the code it was first linked against. Both are fixed.

*Still worth doing:* on a real node, an in-container `rm` must produce a `DELETE` for exactly that
path and nothing else, and a container whose image lacks one configured root must still report
deletions under the roots it has. Both are already scripted in the harness.

### WP4 — per-dimension container row limits — **DONE, `2ea083add8`**

> **The gate this was held on did not exist.** The reason recorded here was that the enforcement
> "terminates in `BuildContainerDocumentLimits()` → `cb_document_limits_t` → `cbaseline_reconciler_*`,
> the Model B reconciler [D1](12-blocking-decisions.md) declined, and this branch has no
> equivalent." That is true of the *spike*, and it is why the spike needed a reconciler: its
> container path bypassed dbsync. On this branch container rows already traverse
> `checkDocumentLimit()` — `Accumulator::flush` → `updateChanges` → `notifyChange` → `processEvent`
> → `checkDocumentLimit` — so the enforcement had somewhere to land all along. The claim was wrong,
> not the plan.

What landed:

- **Two budgets, not one.** `LimitScope { host, container }`, with `scopeFilter()` appending
  `AND container_id=''` or `AND container_id<>''` to every count and promote query.
  `checkDocumentLimit()` derives the scope from the row's own `container_id`, so container rows can
  no longer spend the host's per-dimension caps and vice versa.
- **The transport, ported as-is**: `syscollector_containers_limits_t` (ten dimensions, all defaulting
  to `0` = unlimited) through remoted's handshake JSON, `getDefine_Int_default` on the manager side,
  the agent's parse, and a `syscollector_containers` branch in `agcom`. Additive and optional on both
  sides, so an older manager cannot fail the handshake.
- **A bug of ours, fixed.** `4b365c11d6`'s independent `<container_baseline_interval>` pass skipped
  `scan()`'s sync bookkeeping, so container rows stayed `sync=0` and could be re-emitted as duplicate
  CREATEs. `runContainerBaselinePass()` now does the same `updateSyncFlagInDB` / `promoteItemsAfterScan`
  / `deleteFailedItemsFromDB` sequence, in `scan()`'s order.
- Host log strings are kept byte-identical with a `" [container]"` **suffix**, because
  `syscollectorImp_test.cpp` asserts several of them verbatim.

`test_module_limits` 14/14, three mutations killed per new case. Validated on the node
([12 §12.15](12-blocking-decisions.md#1215-the-integrated-agent-on-a-real-node-2026-09-08)): limits
`{"packages":2,"processes":3}` arrived over the wire, 32 container package rows were collected, and
`Post-scan promotion [container]: … Successfully promoted 2 records` — the cap enforced against the
container budget on the independent cadence, with host counts untouched.

FIM's own cap is still the literal `CONTAINER_BASELINE_MAX_FILES_PER_PATH` in the bridge; wiring it
to a config knob was not part of this package.

### WP5 — A4, on our terms *(gate: [D9](12-blocking-decisions.md) + [D18](12-blocking-decisions.md#d18--how-does-a-path-reconcile-persist-a-row-without-authorising-a-sweep-resolved-2026-09-08--the-non-transactional-upsert-d3a8e394d9); size L)*

**Still not started, but for a different reason than before.** The original gate — "WP1–WP3 proven
on a real node" — is **met**: all three ran on the integrated agent on 2026-09-08
([12 §12.15](12-blocking-decisions.md#1215-the-integrated-agent-on-a-real-node-2026-09-08)),
including D17's absent-root case and WP2's alert. What replaced it was
[C27](03-findings-correctness.md) — a path reconcile deleting the rest of its container's rows, so
the container path's write behaviour was not yet correct, and collapsing the two engines underneath a
consumer that is still losing state would have made the next failure ambiguous between the collapse
and D18's fix.

**That gate is now cleared too**: C27 is fixed in `d3a8e394d9` and D18 is decided. What remains is
[D9](12-blocking-decisions.md) alone, which is a decision, not a defect. Note the measurement WP5
inherits from [12 §12.16](12-blocking-decisions.md#1216-the-lifecycle-question-answered-by-measurement-2026-09-08):
`RT_CGROUP_MODE_ALL` is load-bearing until item 20 lands, because post-startup container discovery
depends on seeing events from cgroups the map has never heard of. A collapse that narrows the filter
to serve host whodata more cheaply would silently remove container discovery, so the filter mode is
a constraint on WP5's design, not a free variable.

Collapse the two engines into one. The spike proves the destination is reachable; the route it took
is not acceptable here, because it deletes the host-whodata tests ADR-001 exists to protect. So:

1. Keep all seven `fimEbpfWhodataTest` files. `rt_engine`'s dlopen dispatch table is already
   mockable the way `wrapper_bpf.h` was — the `rt_engine_api_t` indirection in the spike's
   `ebpf_whodata.hpp` is the right seam; its `link_stubs.cpp` is the wrong use of it.
2. Move host whodata onto `rt_engine`'s `RT_CGROUP_MODE_ALL` first, with the container drain still on
   its own handle, and measure `bpftool prog list` `run_cnt`/`run_time_ns` before and after — the
   number D9 asks for and nobody has.
3. Only then merge the two handles, and switch the container path to
   `RT_CGROUP_MODE_ALLOWLIST` — which needs item 20's create trigger
   ([D7](12-blocking-decisions.md)), because an unlisted cgroup becomes invisible rather than merely
   unattributed.
4. Retire `modern*.bpf.c`, the `libbpf_external` rule and the `modern.bpf.o` install/packaging
   entries as the *last* step, not the first.

### WP6 — supply `rt_file.bpf.o`, then the packaging manifests *(decided: a committed per-architecture prebuilt; half-done, `da90a18c5b`)*

Two findings changed this package's shape, both from reading rather than building.

**1. The checker does reject unlisted files, so this is a CI blocker.** `check_files.py` ends with
`sys.exit` when `len(not_listed) != 0`, and any installed file matching no CSV row lands in
`not_listed`. So the moment `rt_file.bpf.o` *is* installed, the four manifests fail the job. The
same exit condition also fires the other way — `len(current_items) < len(expected_items)` — so a row
for a file the build does not produce fails too. The two halves have to land together.

**2. The byte size need not block it.** `file_diff()` reads `size_bytes` and skips the comparison
when it is `0` (`if (expected_size_bytes and …)`), while still asserting owner, group, mode, type and
permissions — which is everything the install rule actually controls. So a row can land with
`size_bytes=0` and be tightened from a real build later, rather than waiting for one.

**3. But the object has no supply at all** — see [§14.6](#1bdfb0990e-only-fixed-half-of-it-the-object-has-no-supply).
That is the real blocker, and it comes first: adding CSV rows for a file the packaging pipeline never
produces fails CI just as surely as omitting them.

**Decided: a committed per-architecture prebuilt**, `shared_modules/ebpf_provider/prebuilt/<arch>/`,
which is the branch the CMake already tries first. `da90a18c5b` makes that path per-architecture —
it was arch-blind, and an x86 object copied onto an arm64 host is compiled with the wrong
`-D__TARGET_ARCH_` and the wrong `vmlinux.h`, so its CO-RE relocations and `pt_regs` offsets are
wrong: installed, then unloadable, and indistinguishable from "this host has no eBPF" — see
`prebuilt/README.md`.

**What remains, and why it is not just a build.** A *shippable* object wants the portable vendored
`vmlinux.h` (`github.com/libbpf/vmlinux.h`, per-architecture), not one dumped from the build host's
own kernel BTF — the CMake says as much where it takes that fallback, and a host-generated header
yields an object most reliable only on that kernel. That clone is skipped whenever the precompiled
`modern.bpf.o` is present, which is always. So producing one means fetching that header deliberately,
compiling against it, and **load-testing the result on a real cgroup-v2 kernel**
(`rt_engine_open_test` / `rt_engine_filter_test`, both needing root) before a binary is committed.

WSL has clang and libbpf headers and `/sys/kernel/btf/vmlinux`, but its `bpftool` is the Debian
kernel-dispatch stub and cannot dump BTF, so it can compile against a fetched `vmlinux.h` and cannot
verify the result loads. The load test belongs on `wazuh_manager`.

**Measured there on 2026-09-08, and it narrows this package considerably.** A plain
`make deps TARGET=agent && make build TARGET=agent` on that host produced
`build/lib/rt_file.bpf.o` through the host-BTF fallback
(`eBPF Module: vendored vmlinux.h absent; generating one from this host's kernel BTF`), and the
resulting object **loads and attaches**: `eBPF engine ready: 4 program(s) attached, ABI 1.1`, with
`active LSM list includes "bpf" -> preferring LSM file_open variant`. So:

- The compile branch, the CO-RE relocations and the attach paths are all **correct code** — this was
  never a code defect, only a supply one. What is missing is a *portable* object, not a working one.
- The remaining work is exactly: fetch the per-architecture vendored `vmlinux.h`, compile against it
  instead of the host dump, load-test that binary the same way, commit it, and add the four CSV rows
  with `size_bytes` from the real package.
- A host with `clang` + a working `bpftool` needs none of this; it builds its own. The prebuilt is
  for the packaged agent, which has neither.

### Not planned, and why

| Item | Reason |
| --- | --- |
| Model B reconciler + `row_diff` + `SqlitePriorStateStore` | [D1 = Option 3](12-blocking-decisions.md#125-d1-in-depth--the-two-inventory-state-models). Only its three seams come across, and S3 already has. |
| `container_live_fim.cpp` as an architecture | Its per-event single-row upsert is the model A3 replaced with reconcile-by-re-walk, after [D15](12-blocking-decisions.md) ruled out inferring deletions. Taking it back would re-open D15 with worse evidence than we now have. |
| Option C's lazy catch-up walk | Superseded by the resolver-driven re-walk — §14.3. |
| Its `<containers><enabled>` config spelling | A second switch for `<container_baseline>`. Already rejected in [§12.13](12-blocking-decisions.md#what-step-7-left-out-and-why). |
| Its `ebpf_provider` tree | We are 1,936 lines ahead of it. |
| Seam S1 — per-table `partial` (`5a9021e285`) | Was WP3's third option and was not taken. D17's narrow fix answers C24 at the layer that produces the facts (the walker) rather than at the layer that reports them per table, and the struct-taking `cb_container_status_sink_t` is now the place a per-table breakdown would go if a consumer ever needs one. Taking S1 as well would have been a second contract change for a consumer that does not exist yet. |
