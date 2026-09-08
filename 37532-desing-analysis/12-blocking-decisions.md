# 12 — What to continue with, and the decisions that block the roadmap

- **Branch:** `37532-5-0-0-container-integration` (`f39967c55c`), 54 commits ahead of `origin/5.0.0` (`077a85b3f7`, 2026-09-02), and the remote branch is at the same commit — last updated 2026-09-08
- **Date:** 2026-09-04
- **Purpose:** answer "which changes do we continue with", and register every decision that has to
  be made by a person before the next phase of [08](08-roadmap.md) can start.

---

## 12.1 The finding that reorders the roadmap

While checking [11 open question 8](11-ebpf-provider-import-plan.md#1111-open-questions-and-what-i-could-not-verify)
— *"a separate reconcile on `spike/37533-37534-fim-syscollector-ebpf-integration`, coordination
question I could not settle"* — the factual half turned out to be settleable, and the answer is not
what that question assumed.

**That branch is not a parallel effort. It is the source this branch was cut from.**

```
origin/5.0.0 ..origin/spike/37533-37534-fim-syscollector-ebpf-integration   91 commits
merge-base(HEAD, that spike)  = da844a6fda   (2026-07-02)
this branch  = the spike prefix through `66301af90d` ("change naming from k8s to container"),
               rebased onto a 2026-09-02 5.0.0, plus 8 review fixes
spike tip    = 0080d7d294  (2026-08-05, idle since)
```

Every one of this branch's first 13 commits is a rebased mirror of a spike commit
(`8369745959`…`187c69f635` ↔ `51dffa1f02`…`66301af90d`). The cut point is `66301af90d`. **Fourteen
commits of the spike's feature work were never integrated**, and they are not incidental:

| Spike commit | What it does | Collides with |
| --- | --- | --- |
| `2541026edb` | refactor: wip | — |
| `2676bb86c8` | the new eBPF module | none — [11 §11.1](11-ebpf-provider-import-plan.md#111-which-version-to-import-and-why-not-the-one-named): superseded, do not import this one |
| `0ce0c2fbc0` | integrate the eBPF module into FIM | `ebpf_whodata.cpp`, `modern.bpf.c`, externals |
| `9113442eb4` | whodata tests | **the version to import** (11 §11.1) |
| `c4357e6481` | `changed_fields` alerting for the live container FIM path | FIM alerting |
| `583f9a52d1` | include ordering (the `extern "C"` trap) | build only |
| `6022673065`, `adf6ae0a74` | bug fixes / improvements | eBPF consumer |
| `415e7a2204` | container field into `fim_file_data` | **FIM schema**, `ebpf_whodata.hpp` mock seam |
| `5a9021e285` | **the #37534 inventory reconciler** | **`container_baseline_scanner.cpp` (−260), `syscollectorImp.cpp` (−159), `container_baseline.h` (+34)** |
| `92a3f4d3be` | post-cherry-pick fixes | as above |
| `4b4bd3c1bb` | syscollector scan interval + documented limits | syscollector config |
| `f6fd510207` | checksum computation error | reconciler |
| `0080d7d294` | test improvement | reconciler tests |

### Why `5a9021e285` is the one that matters

It is not "another reconcile with a confusing name". It **replaces the inventory state model this
branch uses**:

- deletes `cbaseline_run_syscollector_dbsync()` and `cbaseline_list_containers()` from the
  syscollector call path entirely;
- introduces `cbaseline_reconciler_create/run/destroy` over a **durable on-disk SQLite prior-state
  store** (`CB_DEFAULT_PRIOR_STATE_DB_PATH = queue/container_baseline/prior_state.db`) with its own
  `row_diff`, emitting CREATE/MODIFY/DELETE itself instead of feeding syscollector's DBSync;
- keeps deletes correct across agent restarts (a container that exited while the agent was down
  still produces a delete) via a first-scan-after-reload guard — which is a capability the current
  DBSync-plus-stale-sweep model does **not** have;
- adds `container_baseline_impl/tests/CMakeLists.txt` and a `sysCollectorImp` test CMakeLists —
  i.e. it already builds the test tree that [09 item 30](09-implementation-status.md#not-done--deliberately-deferred)
  and [10 §10.12](10-container-instances-delta-plan.md#1012-test-plan) say is missing.

Two direct consequences for work already done and work already planned:

1. **The C15 fix (`943a50935f`) was independently reached by that spike.** Its
   `cbaseline_reconciler_run()` is documented as *"Returns … −1 when the pass was skipped because the
   Container Instances module was unreachable (never a partial delete)"* — the same rule, in the
   replacement API. So the syscollector half of `943a50935f` is redundant against `5a9021e285`; the
   `listContainers(bool*)` / `ListContainers()` / FIM-consumer halves are not, because that spike
   does not touch the FIM sweep gate. Nothing to undo, but the overlap should be known before anyone
   re-litigates it in review.
2. **[10 Phase 3](10-container-instances-delta-plan.md#phase-3--syscollector-goes-delta-driven-m) is
   written against a function `5a9021e285` deletes.** Its rewrite of `scanContainerBaseline`
   (`syscollectorImp.cpp:2087-2360`) targets code that no longer exists in the spike's model. Doc 10
   is not wrong — it is written against the wrong base.

---

## 12.2 What to continue with

Three tracks, separable, in this order. The ordering principle: **do the track that has no
collision surface and no unowned decision first.**

### Track E — the eBPF provider *(start now)*

[11 A1](11-ebpf-provider-import-plan.md#a1--the-provider-lands-nothing-consumes-it-smallest-first-useful-step) → A2, in that
order. Recommended because it is the only track that is simultaneously:

- **collision-free** — `src/shared_modules/ebpf_provider/` does not exist on this branch, so A1 is
  8 new files and 1 changed line in `src/CMakeLists.txt`;
- **independent of the state-model decision (D1)** — it touches neither
  `container_baseline_scanner.cpp` nor `syscollectorImp.cpp`;
- **behaviour-neutral** — after A1 nothing consumes the provider; FIM still uses `modern.bpf.o`;
- **unblocked but for one word** — only D3 below, and [11 §11.1](11-ebpf-provider-import-plan.md#111-which-version-to-import-and-why-not-the-one-named)
  already carries the argument.

Concretely, in dependency order:

1. **A1** — port `9113442eb4:src/shared_modules/ebpf_provider/` by hand (not cherry-pick: `0ce0c2fbc0`
   alone touches 22 files), with the `CMakeLists.txt` rewritten per
   [11 §11.6](11-ebpf-provider-import-plan.md#116-build-integration--the-largest-single-import-risk)
   — drop `REQUIRED`, gate the object build on `EXISTS ${prebuilt}` then on toolchain, keep
   `rt_engine` building unconditionally. WSL proves configure+link; the VM proves the object.
2. **A2 items 4, 5, 3, 6** — `bpf_link` teardown in `rt_close` (a real correctness bug: probes stay
   attached, the freed ring keeps being written, re-open double-attaches), actually set
   `RT_F_CGROUP_V1`, the `log` callback on `rt_filter` (today an eBPF load failure never reaches
   `ossec.log`), and the ABI guard. All four are additive, provider-local, and decision-free.
3. **A2 item 9** — the provider's own gtest suite against a fake libbpf, including the
   `sizeof(struct rt_file_event) == 12416` + `offsetof` pins. WSL-runnable, and it is the test that
   prevents a silent 12 KB mis-parse. It also has to **replace** the coverage A4 would delete
   (`close_libbpf_test.cpp`, `init_bpf_obj_test.cpp`, `init_libbpf_test.cpp`,
   `init_ring_buffer_test.cpp` = 331 lines).
4. **A2 items 1–2** — in-kernel cgroup filtering and per-cgroup drop accounting. Gated on **D4**;
   see below, and run the VM loss proof
   ([11 §11.10 test 5](11-ebpf-provider-import-plan.md#vm-only-wazuh_manager)) before deciding scope.

Also worth doing inside this track, because it is free and stops a confusing adjacency from getting
worse right as new eBPF code arrives: [A0 step 3](11-ebpf-provider-import-plan.md#a0--prep-no-code) —
move `container_baseline_fim.{cpp,h}` and `container_baseline_fim_bridge.{c,h}` out of
`src/syscheckd/src/ebpf/` (the first half of [08 item 31](08-roadmap.md#p3--maintainability)).

### Track S — the inventory state model *(hold for D1)*

Everything in [10 Phases 1–4](10-container-instances-delta-plan.md#1010-phased-implementation), item
20, item 22, item 23 and item 30's test double. **Do not start.** Each of those edits
`container_baseline_scanner.cpp`, `syscollectorImp.cpp` or `container_baseline.h` — the three files
`5a9021e285` rewrites — so work done before D1 is either discarded or turns into a merge conflict
across ~1,600 added lines.

The one exception, safe under either outcome:
[10 Phase 0 item 2](10-container-instances-delta-plan.md#phase-0--de-risk-no-new-api-s) — make Docker's
deferred reconcile actually fire (C16: `m_reconcilePending` is write-only at
`docker_connector.cpp:93`, so the last event of every 500 ms burst is dropped, with no periodic floor
to recover it). It lives in `container_instances`, is unaffected by which state model wins, and is a
live bug under today's rescan as much as under a baseline-once design. It is **not our module**, so
it should go to that owner as a small standalone change rather than into this branch.

### Track F — FIM schema *(after Track E, needs D1 only for sequencing)*

`415e7a2204` (container field in `fim_file_data`) and `c4357e6481` (`changed_fields` alerting for the
live path). Track E's A3 consumer port depends on `415e7a2204`'s `rt_engine_api_t` mock seam
(`ebpf_whodata.hpp:27-34`), so this lands between A2 and A3.

---

## 12.3 Blocking decisions

Ranked by how much they block. Each names its owner, because five of the twelve are not this
project's to make.

### Blocking now — every further design step depends on these

> **D1 and D2 were decided on 2026-09-04: D1 → Option 3 (hybrid), D2 → Option 1 (port the tail
> forward onto this branch).** The consequences are worked through in
> [§12.7](#127-the-decided-plan-d1--option-3-d2--option-1). The two entries below are kept as the
> statement of what was decided and why it mattered.

**D1 — Which inventory state model wins?** *(owner: this project + #37534's author)* — **DECIDED:
Option 3, hybrid.** Keep DBSync as the inventory transport; adopt the reconciler's three
model-independent seams (per-dimension `CollectStatus`, `ContainerListing::available`,
`ReconcileScope{single_container_id}`). `SqlitePriorStateStore` and `row_diff` are **not** imported —
DBSync already holds the prior state.

Durable SQLite prior-state reconciler (`5a9021e285`) or syscollector-DBSync-plus-stale-sweep (this
branch, and what doc 10 assumes)? They are mutually exclusive: one owns the diff in
`container_baseline`, the other delegates it to syscollector's existing delta pipeline. The
reconciler additionally survives agent restarts, which the current model does not.

**Analysed in full in [§12.5](#125-d1-in-depth--the-two-inventory-state-models)**, with a
side-by-side on the eleven axes that differ, the three options, and a recommendation (hybrid: keep
DBSync as the transport, take the reconciler's three model-independent seams).

> Blocks: [10](10-container-instances-delta-plan.md) Phases 1–4 in their entirety, roadmap items 20,
> 22, 23, 30, and any further edit to `container_baseline_scanner.cpp` / `syscollectorImp.cpp`.
> **Every day this is open, Track S work risks being written twice.**

**D2 — Which direction does integration run?** *(owner: this project + spike author)* — **DECIDED:
Option 1.** The spike's unintegrated tail is ported forward onto `37532-5-0-0-container-integration`.
This branch keeps the current 5.0.0 base and stays the integration target.

Port the spike's 14 unintegrated commits onto this branch, or move this branch's 8 review fixes onto
the spike? 91 commits vs 23, forked 2026-07-02, spike idle since 2026-08-05 while this branch sits on
a 2026-09-02 5.0.0. Whichever way it runs, it should run **once**, deliberately — not as a
commit-by-commit drift.

**Analysed in full in [§12.6](#126-d2-in-depth--which-way-integration-runs)**: the conflict surface
is exactly 16 files, concentrated in four, and the tail contains fixes this branch still carries as
live bugs (C19).

> Blocks: everything, including the answer to D1 in practice.

**D3 — Ratify the eBPF import version.** *(owner: this project; one word)*

Import `9113442eb4`'s `ebpf_provider/` tree, not the `2676bb86c8` named in the original request.
`2676bb86c8` is a non-working intermediate: no `bpf_obj_path` (a systemd-managed agent cannot find
its `.bpf.o`), no PIC (so `rt_engine` will not link into `fimebpf`), `RT_ABI_MINOR 0`. Argument in
full at [11 §11.1](11-ebpf-provider-import-plan.md#111-which-version-to-import-and-why-not-the-one-named).

> Blocks: Track E A1 — i.e. the only track otherwise ready to start.

### Blocking the next phase

**D4 — In-kernel cgroup filtering: A3 prerequisite, or optimisation?** *(owner: this project)* — **ANSWERED
by measurement, [§12.9](#129-d4-answered--the-loss-proof-measured): an optimisation, not a
prerequisite — but the measurement inverts item 1 and item 2's priority, and raises D14.**

Today the provider has **no** in-kernel filtering: every write-intent open on the host becomes a
12,416-byte record in an 8 MiB ring (~675 in flight). If drops are routine, the algorithm degrades to
permanent re-baselining and item 1 is a hard prerequisite; if they are rare, it is an optimisation.
Nobody has ever measured the drop counter on a realistic node
([11 open question 4](11-ebpf-provider-import-plan.md#1111-open-questions-and-what-i-could-not-verify)).
Decide it with [11 §11.10 test 5](11-ebpf-provider-import-plan.md#vm-only-wazuh_manager), run before
and after, both numbers recorded.

> Blocks: A3's scope and schedule. Not A1 or A2's other items.

**D5 — Thread ownership (item 14).** *(owner: this project)* — **DECIDED, see
[§12.10](#1210-d5-resolved--and-one-of-its-options-never-existed).** Two threads in syscheckd, none
new in syscollector, the walk stays on `main()`, and one `BaselineService` object per process.

Now **mandatory**, not deferred: the provider handle must open before the walk (`main.c:486`), and
the drain must be on its own thread for the two to interleave. FIM has no cycle at all — one shot on
`main()`. Options: a dedicated drain thread, the realtime thread, or a shared `BaselineService`
thread serving both consumers (which is also what item 22 and item 29 want).

> Blocks: Track E A3, and doc 10 Phase 3's FIM half (deliberately excluded from that phase for
> exactly this reason).

**D6 — Does Docker's `listContainers` pass `all=1`?** *(owner: `container_instances`)*

Today it does not (`docker_api_client.cpp:114-127`), so a container stopped longer than the 60 s
grace window is reported **gone** and its rows are deleted — contradicting
[06 §6.8](06-proposed-architecture.md#68-deletion-semantics-stated-once) row 3 and the
"stopped-vs-gone is correct" claim in [09](09-implementation-status.md#done) (true for Kubernetes
only). `all=1` fixes it but changes what "known to `container_instances`" means for every consumer,
and puts exited containers in the reply indefinitely.

> Blocks: the deletion-authorisation rule under **either** state model. Two consumers already derive
> deletions from this list, so the semantics need writing down whichever way it goes.

**D7 — Does `container_instances` accept the delta API?** *(owner: `container_instances`)*

The journal + additive `epoch` / `seq` / `delta` / `events[]` / `resync_required` on `op: "list"`
([10 §10.7](10-container-instances-delta-plan.md#107-proposed-api), decisions D1–D7 there). Needed
under either state model — the create trigger is what makes baseline-once possible at all — but the
consumer side differs by D1.

> Blocks: roadmap item 20 entirely; and Track E A3's `cgroup_id → container_id` map refresh, without
> which every container created after startup is a permanent cold miss
> ([11 §11.8.7](11-ebpf-provider-import-plan.md#1187-interaction-with-items-20-and-23)).

**D8 — Does `docker restart` change the container's cgroup inode?** *(owner: needs a real node)*

If reliably yes, `cgroupId` alone discriminates a restart and [10 Phase 4](10-container-instances-delta-plan.md#phase-4--instance_id-earns-its-name-m)
shrinks. If no, `ContainerRecord` needs `startedAt` + `pid` before item 23's trigger table is
implementable at all (C18). Needs both the cgroupfs and systemd cgroup drivers. **Cannot be tested in
WSL.**

> Blocks: item 23's trigger table, `instance_id` composition, and the deletion of `PidIndex::Build()`'s
> `/proc` sweep.

**D9 — Is A3's duplicated BPF load acceptable until A4?** *(owner: this project)*

A3 deliberately adds a *second* consumer rather than cutting host whodata over: two `bpf_object`
loads, two 8 MiB rings, two drain threads, duplicate kprobes on the same hooks. That keeps host FIM
whodata and its seven test files (734 lines) out of item 21's blast radius, and ADR-001 sanctions it.
The cost is roughly double kernel-side file-hook work while both coexist. Measure with `bpftool prog
list` run_cnt/run_time_ns; if unacceptable, A4 stops being optional.

> Blocks: A3-vs-A4 ordering. Should be stated in the commit message either way, not left for a
> reviewer to discover.

**D10 — Accept that item 22 lands *with or before* item 20.** *(owner: this project)*

[08](08-roadmap.md#p2--architecture-make-it-a-baseline) has this dependency backwards.
`ImageContentCache`'s saving is *within-cycle* reuse across replicas of one image; once item 20 makes
a cycle scan only the delta, that saving evaporates. Accepting the reversal means the
`BaselineService` object (item 29) has to land early, since a cross-run cache needs somewhere to live.

> Blocks: doc 10 Phase 3 — or rather, silently wastes it.

### Product-visible, decide before A3 ships

**D11 — cgroup v1 policy.** *(owner: this project)* Full fallback to periodic rescan with an INFO
log, or attempt partial attribution? `RT_F_CGROUP_V1` is declared and never set
(`rt_file.bpf.c:256,274`), so a v1 host today would silently mis-attribute **every** event on the
node to one bogus cgroup. Affects the supported-platform claim for AL2 / RHEL8.

**D12 — Startup healthcheck: serial or parallel?** *(owner: this project)*
[11 §11.8.1](11-ebpf-provider-import-plan.md#1181-ordering) recommends running the four-action
healthcheck **before** the walk, accepting up to ~40 s of worst-case added startup latency, because a
walk that races an unfinished healthcheck was unmonitored and forces a re-baseline of every
container. That is a deliberate latency-for-correctness trade and someone other than the author
should agree to it.

### Not blocking — safe defaults, decide with data

| Question | Placeholder | Decide from |
| --- | --- | --- |
| Lifecycle journal ring size | 4096 | item 39 node benchmark (churn at N=100) |
| Reconciliation floor interval | 24 h | item 39 (observed producer-side gap frequency) |
| Delta poll cadence | syscollector's own 1 h interval | only needs its own 15–30 s timer if create-to-baseline latency matters; [10 §10.11](10-container-instances-delta-plan.md#1011-optional-only-if-measurement-demands-it) has the cheap level-triggered option, explicitly *not* recommended first |
| `metadata`-only change class | no action, stale labels accepted | dissolves if item 17's container dimension row lands |

---

## 12.4 Recommended immediate sequence

Assuming D3 is ratified and D1/D2 are put to the people who own them in parallel:

| Step | Work | Blocked by | Verifiable in |
| --- | --- | --- | --- |
| 1 | A0 step 3 — move the FIM baseline driver out of `src/syscheckd/src/ebpf/` | — | WSL |
| 2 | A1 — the provider lands, nothing consumes it | D3 | WSL (configure+link), VM (object+harness) |
| 3 | A2 items 4, 5, 3, 6 — teardown, `RT_F_CGROUP_V1`, log seam, ABI guard | — | VM |
| 4 | A2 item 9 — provider gtest + the 12,416-byte ABI pin | — | WSL |
| 5 | VM loss proof (§11.10 test 5) | steps 2–4 | VM |
| 6 | A2 items 1–2 — in-kernel filtering, per-cgroup drops | **D4** (answered by step 5) | VM |
| 7 | Correct [06](06-proposed-architecture.md) against the two contradiction tables | — | **done** ([06 §6.10](06-proposed-architecture.md#610-corrections--the-sketch-versus-the-implemented-contract)) |

Steps 1, 3, 4 and 7 need **no decision from anyone**. Step 7 matters more than its size suggests: doc
06 §6.3 and §6.6 currently describe a per-container eBPF filter, per-container drop signalling, an
engine-supplied sequence number, and processes/ports in the event-maintained tier — **none of which
exist**. Left uncorrected, the next person to plan from doc 06 plans against a contract that isn't
there.

VM work goes to `wazuh_manager` — WSL cannot build or load the `.bpf.o`.

---

## 12.5 D1 in depth — the two inventory state models

### Both models are already in the tree, and always were

`container_baseline_scanner.hpp` has carried **two emit paths** since the original spike:

| Path | Row shape | Destination |
| --- | --- | --- |
| `RunSyscollectorBaseline` | `EmittedRow{id, operation, index, json, version}` | pre-shaped sync-protocol documents for `wazuh-states-inventory-*` |
| `RunSyscollectorDbsyncBaseline` | `DbsyncRow{container_id, table, json}` | flat dbsync columns for syscollector's own tables |

This branch hardened the **dbsync** path and treated the other as vestigial —
[09 item 26](09-implementation-status.md#not-done--deliberately-deferred) calls it "the dead
sync-protocol path", kept only because `Build*Json` has 18 live test assertions and three QA runners
depend on it.

`5a9021e285` **revived the other one and put a diff engine behind it.** That is what D1 is actually
about. It is not "should we add a reconciler"; it is *which of the two emit paths carries container
inventory, and therefore who owns the delta.*

### Model A — DBSync (this branch)

```
scanner → DbsyncRow → syscollector per-container scoped DBSync txn (scope column)
        → updateChanges / notifyChange / processEvent → sync_protocol
```

- **State of record:** syscollector's own DBSync database, holding full row payloads.
- **Deletions:** the scoped transaction's own delete detection, plus
  `sweepContainerRowsNotIn(discoveredIds)` for containers absent from the live list.
- **Incomplete scans:** container-granular `ContainerStatus{partial, netns_host_scoped,
  netns_unreadable}`, with `options.ignore` to suppress delete detection.

### Model B — durable prior-state reconciler (`5a9021e285`)

```
scanner → CollectorResult per dimension → diffRows(prior, current)
        → CREATE / MODIFY / DELETE → RowSink → sync_protocol
prior := prior_row(id, container_id, idx, content_hash, version)
         in queue/container_baseline/prior_state.db
```

- **State of record:** its own 5-column SQLite fingerprint table. Payloads are *not* stored — only
  an FNV-1a 64-bit `content_hash`, on the explicit reasoning that "the full JSON payload lives in
  the sync queue, not here (re-storing it would just duplicate the queue)."
- **Deletions:** per row (id in prior, absent from current) and per container (id in the store,
  absent from the live list), then `purgeContainer`.
- **Incomplete scans:** per-**dimension** `CollectStatus::Ok|Failed`. A failed dimension's prior rows
  are erased from the diff input, so "collector errored" cannot read as "every row in that dimension
  vanished". The enum's comment states this as its whole purpose.
- **Ordering:** emit-first, then `applyDelta` — a crash in between re-emits harmlessly next pass.
  `applyDelta` is properly wrapped in `BEGIN`/`COMMIT`/`ROLLBACK`.

### Side by side, on the axes that actually differ

| Axis | A — DBSync | B — prior-state reconciler |
| --- | --- | --- |
| Who computes the delta | syscollector's DBSync | `container_baseline` itself |
| Container rows in syscollector's DB | **yes** — same tables as host rows, so item 18's `distinctOpt(true)` queries and any other DB reader see them | **no** — bypasses the DB entirely |
| Schema alignment | same tables, same normalizer, same ECS path as host rows | its own comment: *"draft JSON shape … pending #37203-4's schema"*, *"not yet aligned with `Syscollector::ecsData()`"* |
| Module unreachable | needed the C15 fix (`943a50935f`) bolted on | built in from the start — `ContainerListing::available`, with the false-empty reasoning written into the header |
| Failed dimension | container-granular `partial` + `options.ignore` | **per-dimension**, unrepresentable-by-construction — strictly more precise |
| First scan after restart | `isFirstSync` → `notifyOverride=false`, plus `g_everSawContainers` | `m_first_pass` suppresses all deletes for one pass |
| Container exited while agent was down | detected on the first post-restart scan — which is exactly when the live list is least trustworthy (C15) | detected on the **second** pass; the reload guard defers it by one interval |
| Targeted single-container refresh | not available: the transaction is per-container but the orchestrator always walks every container | `ReconcileScope{single_container_id}`, documented as "the seam an eBPF cgroup event (#37396) would drive" |
| Document limits (NFR3) | DBSync's promotion machinery | blunt "first N tracked rows win", no fairness — flagged as such in its own `ponytail:` note |
| Row `version` | DBSync-managed | stored per row; a store loss resets it to 1 — **needs checking against the indexer's version semantics** |
| Extra storage | none beyond DBSync | one more SQLite file; roughly `len(id) + len(index) + 16 B` per row |
| Carries this branch's 8 review fixes | yes | **no** — forked 2026-07-02, before all of them |

### What each option costs

**Option 1 — Model A only.** Keep dbsync; port B's *ideas* rather than its code.
Keeps schema alignment and the DB-visibility of container rows; keeps all 8 review fixes in place.
Costs: re-implement the per-dimension failure model, the availability gate (partly done — C15) and
the targeted scope by hand, and item 21's per-container reconcile has to be built from scratch.

**Option 2 — Model B only.** Adopt the reconciler; retire the dbsync inventory path.
Gets a working diff engine, the correct availability and per-dimension semantics, ~420 lines of tests
and the test CMake trees [09 item 30](09-implementation-status.md#not-done--deliberately-deferred)
needs, and the exact `ReconcileScope` seam doc 11's algorithm asks for.
Costs: container inventory **leaves syscollector's database**, breaking item 18's distinct queries and
any future reader; the row shape is admittedly a draft pending #37203-4; the 8 review fixes must be
re-applied on top; and the `version`-after-store-loss question has to be answered.

**Option 3 — hybrid (recommended).** Keep **A** as the transport, take **B's three seams**.

Rationale: B's advantages divide cleanly into two groups, and only one group is tied to its storage
model. The seams — per-dimension `CollectStatus`, `ContainerListing::available`, and
`ReconcileScope{single_container_id}` — are *model-independent*; they are better semantics that would
improve Model A unchanged. What is tied to B's storage model is `SqlitePriorStateStore` and
`row_diff` — and under Model A those are redundant, **because DBSync already is the prior-state
store**, holding full payloads rather than fingerprints and already computing exactly this diff.

The seam that makes the hybrid cheap already exists: this branch's transactions are *already*
per-container and scoped (`scope` column), so a single-container targeted reconcile is a call-site
change, not new machinery. That is the specific reason to prefer Option 3 over Option 1 — item 21's
requirement is nearly free here, rather than something to build.

What Option 3 still owes B: its test suite. `container_inventory_reconciler_test.cpp` (230 lines),
`row_diff_test.cpp` (96) and `sqlite_prior_state_store_test.cpp` (96) do not transfer, but the
*cases* do — particularly the failed-dimension anti-flap and reload-guard cases, which are exactly
what item 30 lacks.

### Independent of D1

Two things must be settled whichever model wins, because both models have the defect:

- **C20** — the container context blob is inside the row's change signal (Model A digests
  `container_json` into `getItemChecksum`; Model B digests `row.json` into `contentHash`). A label
  edit re-emits the container's entire inventory. Item 17's separate container dimension row is the
  fix under either model.
- **C19** — host rows stamp `container_id` before the checksum. Present on this branch, already
  fixed in the unintegrated tail (`f6fd510207`).

---

## 12.6 D2 in depth — which way integration runs

### The divergence, measured

From the cut point `66301af90d` / `187c69f635`:

```
ours   (187c69f635 → HEAD)          106 files changed
theirs (66301af90d → spike tip)      88 files changed
both                                 16 files      ← the entire conflict surface
```

Sixteen files, and the pain is concentrated in four:

| File | Ours | Theirs | Why it conflicts |
| --- | --- | --- | --- |
| `container_baseline_scanner.cpp` | +214 / −181 | +131 / −175 | **The worst case.** Their −175 is largely a *move*: `ContextFromResolveData` and friends were extracted into `reconcile/resolve_identity.cpp`. Our edits sit inside functions that moved to a different file, which git cannot auto-merge — it sees a delete and an unrelated add |
| `syscollectorImp.cpp` | +312 / −80 | +244 / −126 | Both rewrote `scanContainerBaseline`; theirs replaces it with the reconciler call |
| `container_baseline.h` | +105 / −81 | +55 / −0 | Ours rewrote the sink signatures and contracts; theirs appends the reconciler API. Largely disjoint hunks, but in the same regions |
| `container_baseline_fim.cpp` | +334 / −88 | +47 / −1 | Ours dominates; theirs is the small live-FIM hookup. Cheap either way |

The other twelve are small and mostly **different features rather than competing edits** —
`wmodules-syscollector.c` is ours +8 (the `<container_baseline>` knob) against theirs +45 (the
syscollector scan-interval feature), and `db.h` is +15 / −0 on *both* sides, plausibly the identical
change. Those merge.

### The options

**Option 1 — port the tail forward onto this branch (recommended).**
Track E is the proof it works: 8 new files and 1 changed line, zero conflict, because
`src/shared_modules/ebpf_provider/` does not exist here. Track F is small. Only Track S hits the
four-file collision, and D1 decides how much of Track S is ported at all — under Option 3 above,
what transfers is three seams and a set of test cases, not 1,600 lines.

**Option 2 — move this branch's 8 fixes onto the spike.**
Superficially attractive (91 commits vs 23) but it re-incurs the expensive part: the spike sits on a
2026-07-02 base and would still need the rebase onto a current 5.0.0 that **this branch has already
paid for**, including the `container_instances` CMake and include repairs (`7c90011b5c`,
`257c71a89c`, `d3335e571b`) that rebase cost. Not recommended.

**Option 3 — re-derive, integrate nothing.**
Only defensible for Track S, and only if D1 chooses Model A. It is not defensible for Track E (the
provider is 8 files that already exist and work), for Track F, or for the individual fixes below.

### Why the direction matters concretely, not just tidily

The unintegrated tail is not only features. It contains **fixes to bugs this branch still carries**,
and the reverse is also true — which is the real cost of leaving the two lines drifting:

- `f6fd510207` fixes the host checksum-ordering bug. **Verified still present here** at
  `syscollectorImp.cpp:1731` and `:1879` — recorded as C19. Two swapped lines, and without them
  every host package and process row re-syncs on upgrade.
- Five spike design documents exist only on that branch — `startup-race-solutions-and-edge-cases.md`,
  `container-fim-syscollector-test-plan-and-results.md`, `volume-type-behavior-matrix.md`,
  `requirements-analysis.md`, `enrichment-join-design-analysis.md`. Doc 11 cites the first two as
  sources it **could not read**; [11 open questions 1 and 7b](11-ebpf-provider-import-plan.md#1111-open-questions-and-what-i-could-not-verify)
  may already be answered in them.
- `4b4bd3c1bb` adds a syscollector scan interval and documents the limits — a feature this branch
  simply lacks.
- Conversely, all eight review fixes (C1–C15, the image cache, the row base, the orchestrator tests)
  exist **only here**, and the reconciler in `5a9021e285` was written against the pre-fix collectors.

Whichever direction is chosen, the argument for choosing *soon* is the same: both sides are
accumulating fixes the other needs, in the same four files.

---

## 12.7 The decided plan (D1 → Option 3, D2 → Option 1)

Decided 2026-09-04. This section is the working plan; §12.2's track split still holds, but Track S
is no longer on hold — it is redefined by D1.

### What D1 = Option 3 means concretely

**Not imported:** `SqlitePriorStateStore`, `row_diff`, `container_inventory_reconciler`,
`cbaseline_reconciler_create/run/destroy`, `CB_DEFAULT_PRIOR_STATE_DB_PATH`. DBSync remains the
prior-state store and the delta engine; `syscollectorImp.cpp`'s `scanContainerBaseline` survives
rather than being replaced, so [10 Phase 3](10-container-instances-delta-plan.md#phase-3--syscollector-goes-delta-driven-m)
is valid against the current base after all.

**Imported as behaviour, re-expressed on top of DBSync** — three seams, in dependency order:

| # | Seam | Model B's version | What it becomes here |
| --- | --- | --- | --- |
| S1 | Per-dimension failure | `CollectStatus{Ok,Failed}` on `CollectorResult`; failed dimension's prior rows dropped from the diff input | Extend `ContainerStatus` from container-granular `partial` to a per-table failure set, and drive `options.ignore` per table from it. Today a `setns` failure in one dimension can still delete that dimension's rows for a container whose other dimensions scanned fine |
| S2 | Availability | `ContainerListing{available, identities}` | Mostly landed as C15 (`943a50935f`). What remains is formalising the seam so the flag travels with the identity list rather than in a separate out-parameter |
| S3 | Targeted scope | `ReconcileScope{single_container_id}` | `cbaseline_run_*_for(container_id)`. Cheap here because the transactions are **already** per-container and scoped — this is a call-site change, not new machinery. This is the seam [11 §11.8](11-ebpf-provider-import-plan.md#118-subscribe-first-scan-reconcile-by-re-read--against-the-real-contract)'s Reconciling state needs |

**Also taken:** the test *cases* from `container_inventory_reconciler_test.cpp` (230 lines),
`row_diff_test.cpp` (96) and `sqlite_prior_state_store_test.cpp` (96). The code does not transfer;
the cases do, in particular failed-dimension anti-flap, the reload guard, and container-exit
deletes. These are most of what [09 item 30](09-implementation-status.md#not-done--deliberately-deferred)
is missing, and their CMake trees (`container_baseline_impl/tests/CMakeLists.txt`, the
`sysCollectorImp` one) come across as-is.

**Still owed under Option 3, and not free:** Model B got container-exit deletes across an agent
restart from its durable store. Model A gets the same from the stale sweep — but only if the sweep is
trustworthy on the first post-restart scan, which is exactly when the live list is least reliable
(C15). S2 plus the reload-guard test case is what makes that safe; it is not automatic.

### What D2 = Option 1 means concretely

`37532-5-0-0-container-integration` stays the integration target and keeps its current 5.0.0 base.
The 14 unintegrated commits are ported **forward**, by hand where they conflict, in this order:

| Order | From | What | Conflict |
| --- | --- | --- | --- |
| 1 | `f6fd510207` | host checksum ordering (C19) | none — **done**, see below |
| 2 | `9113442eb4` | `ebpf_provider/` (Track E A1) | none — directory absent here |
| 3 | — | provider gaps (A2 items 4, 5, 3, 6, 9) | none — provider-local |
| 4 | `583f9a52d1` | the `extern "C"` include-ordering trap | build only |
| 5 | `415e7a2204` | container field in `fim_file_data` (Track F) | FIM schema; needed for A3's mock seam |
| 6 | `c4357e6481` | `changed_fields` for the live FIM path | FIM alerting |
| 7 | `4b4bd3c1bb` | syscollector scan interval + documented limits | `wmodules-syscollector.c`, additive against our +8 |
| 8 | `5a9021e285` | **seams only** (S1–S3) + test cases, per D1 | the four-file collision, reduced to three call-site changes |
| 9 | `6022673065`, `adf6ae0a74`, `92a3f4d3be`, `0080d7d294` | fixes; review individually, several may be moot | small |
| — | `2676bb86c8`, `0ce0c2fbc0`, `2541026edb` | **not** ported — superseded by 2, or the A4 whodata cutover | n/a |

Also copy across the five spike design documents that exist only on that branch
(`startup-race-solutions-and-edge-cases.md`, `container-fim-syscollector-test-plan-and-results.md`,
`volume-type-behavior-matrix.md`, `requirements-analysis.md`,
`enrichment-join-design-analysis.md`) — doc 11 cites the first two as sources it could not read, and
[11 open questions 1 and 7b](11-ebpf-provider-import-plan.md#1111-open-questions-and-what-i-could-not-verify)
may already be answered there.

### Progress

| Step | Work | Commit | State |
| --- | --- | --- | --- |
| 1 | C19 + C20 — container scope out of the row checksum | `9554439005` | **done** |
| 2 | A1 — the provider lands, nothing consumes it | `dcfacdb43c` | **done** |
| 3 | A2 items 4, 5, 3, 6 — link teardown, cgroup v1, log seam, ABI guard | `1f6ecea90f` | **done** (item 5's BPF half deferred, see below) |
| 4 | A2 item 9 — the ABI pin and rt_open's contracts | `57deeb1e5f` | **done** |
| 5 | VM loss proof ([11 §11.10 test 5](11-ebpf-provider-import-plan.md#vm-only-wazuh_manager)) | `843b1efb76` + [§12.9](#129-d4-answered--the-loss-proof-measured) | **done** — D4 answered, and the teardown fix is now proven on a real kernel |
| 6a | A2 item 2 — per-cgroup drop attribution | `c590808019` | **done**, D14 → counter map. Also settled [11 open question 2](11-ebpf-provider-import-plan.md#1111-open-questions-and-what-i-could-not-verify) |
| 6b | A2 item 1 — in-kernel cgroup filtering | `d560d22b37` | **done**. 300 delivered from the allowlisted cgroup, 0 from the excluded one, 0 counted as drops. Note it makes item 20's create trigger a hard prerequisite for A3: an unlisted cgroup becomes invisible, not merely unattributed |
| 7 | Correct [06](06-proposed-architecture.md) against the contradiction tables | — | **done** — [06 §6.10](06-proposed-architecture.md#610-corrections--the-sketch-versus-the-implemented-contract). Grew in the doing: two rows of [11](11-ebpf-provider-import-plan.md)'s table were no longer true (the provider gained cgroup filtering and per-cgroup drops), and two new corrections came from C21/C22 |
| 8 | Port order steps 4–9 (the spike's unintegrated tail) | `69303187cd`, `4b365c11d6`, `4e096f9537` | **done, and mostly by deciding not to** — see [§12.13](#1213-the-port-order-finished-2026-09-07) |

**Step 1.** `getRowChecksum()` in `syscollectorImp.cpp`, plus the same exclusion in
`container_baseline_fim.cpp`. Verified rather than assumed: the pinned upstream expectations
`expectedPersistPackage` = `403cf592…` and `expectedPersistProcess` = `e4f22515…` are the SHA-1s of
those fixtures **without** `container_id`, computed independently — so both assertions have been
failing since the stamp landed on this branch, and the fix restores them. C20 went further than
`f6fd510207` did: the upstream commit only reordered the host stamp, leaving `container_json` inside
the container rows' digest in both consumers.

**Step 2.** 9 files, 1,491 lines. Two forced deviations from a verbatim import, both worth knowing:

1. **The `CMakeLists.txt` had to be rewritten, and §11.6's point 4 was wrong about this tree.** That
   section recommended preferring the vendored per-arch `vmlinux.h` at
   `external/libbpf-bootstrap/vmlinux.h/include/${ARCH}/`. It does not exist here: it is fetched by an
   ExternalProject that `src/external/CMakeLists.txt` short-circuits whenever a prebuilt
   `modern.bpf.o` is present — which is the normal case. The deps tarball ships `libbpf.so`/`.a` and
   *no* headers and *no* `vmlinux.h`. The gate therefore has three arms (prebuilt object → compile →
   skip) and additionally requires libbpf headers.
   Also: `find_program(bpftool)` succeeding is not the same as having a working bpftool. Debian ships
   `/usr/sbin/bpftool` as a kernel-version dispatch stub that exits non-zero when no matching
   `linux-tools` package is installed, which is the case in this WSL environment — the first build
   attempt failed on exactly that. It is now probed rather than trusted.
2. **New `include/rt_libbpf_shim.h`.** `rt_engine.c` included `<bpf/libbpf.h>` purely for the types
   in its dlopen dispatch table, which would make the loader — a library every consumer links
   unconditionally — depend on a libbpf development package on the build host. Shadowed locally
   instead, the same pattern and the same reasoning as syscheckd's own `wrapper_bpf.h`.

**Step 3.** The link-teardown item was the real bug: `bpf_program__attach`'s return value was
discarded and `rt_close` destroyed nothing, and `bpf_object__close` does not detach. Every program
stayed attached for the life of the process, the kernel kept writing into a ring buffer with no
consumer, and a second `rt_open` attached a second copy of every program — duplicate events for
every file operation.

**§11.9 item 5 is now split, deliberately.** Setting `RT_F_CGROUP_V1` inside `rt_file.bpf.c` (as
§11.9 specified) needs a config map written by userspace at load time and re-read by the program —
not buildable or loadable here. What landed is the reliable half: cgroup version is a *host*
constant, not a per-event property, so the engine determines it from the mount layout at `rt_open`,
warns, and exposes `rt_host_cgroup_v1()`. **Consumers must use that accessor and must not test
`ev->flags` for it** until the BPF half lands. This is a genuine correction to §11.9's framing, not
just a deferral.

**Step 4.** The ABI pin was mutation-checked before being committed: inserting one `unsigned int`
before `inode` trips six assertions with exact offsets rather than passing silently. Runnable as
`make check` in the module directory — no BPF object, no kernel, no root.

### Remaining decisions, unchanged

D3 is subsumed by the port order above (step 2 imports `9113442eb4`, not `2676bb86c8`). **D4–D12
still stand**, and of those, [D5 (thread ownership)](#blocking-the-next-phase) is the one that now
gates the most: it blocks Track E A3 and doc 10 Phase 3's FIM half, and nothing in D1 or D2 answers
it.

---

## 12.8 What the five spike documents settled

Landed on the branch by `c5bc0a1d76` (`spike-37533/`). Doc 11 cited two of them as sources it could
not read; here is what they actually contain, including one place doc 11 overstated its evidence.

### A new blocking dependency — D13

**D13 — Nothing container-enriched reaches the indexer.** *(owner: manager / indexer templates,
#37203-3 / -4)*

Every document carrying a `container` or `kubernetes` field is rejected at persistence:

```
ERROR: Schema validation failed for container FIM baseline row <id>:<path>
       (index: wazuh-states-fim-files). Errors: container: Field not allowed in strict mode
ERROR: Schema validation failed for Syscollector message
       (table: dbsync_processes, index: wazuh-states-inventory-processes).
       Errors: - container: Field not allowed in strict mode
```

72 occurrences for FIM and **4,528 for syscollector** in one session, and confirmed against the
indexer directly: `wazuh-states-fim-files*` had 0 hits for `exists: container` out of 7,905
documents; ports and processes likewise 0. The rows are correct in the agent's **local** database —
verified with `sqlite3` against `fim.db` — so this is purely a manager-side index-template gap.

It was declared out of scope for that spike pass by explicit direction, which is reasonable for a
spike about agent-side collection. It is **not** reasonable to leave unrecorded here: as things
stand, the entire feature produces nothing an analyst can see. Every performance and correctness
decision in docs 03–12 is about getting rows *right*; this is about whether they are *accepted*, and
no amount of agent-side work resolves it.

> Blocks: end-to-end validation of anything in this roadmap, and any acceptance criterion phrased in
> terms of what appears in the indexer. Does **not** block the agent-side work itself.

### A correction to doc 11

[11 open question 1](11-ebpf-provider-import-plan.md#1111-open-questions-and-what-i-could-not-verify)
says the container-relative path property was *"confirmed for the overlay rootfs and for the volume
types in the matrix by the VM run."* **The matrix document says the opposite about itself:** it is
derived from code inspection plus general Kubernetes/Docker semantics and was explicitly *"not been
validated against a running kind cluster"*, with `configMap`/`secret` attribution called "a logical
deduction", and the NFS attribute-caching and FUSE-permission rows flagged as unverified.

There *was* a real kind-cluster run — in the test-plan document, which is a different artefact — but
it covered baseline and live-path behaviour, not the volume-type matrix. So doc 11's open question 1
stands **fully open**, including its own narrower concern (peer/slave mount propagation, and a bind
mount whose source lies above the container root).

### Doc 11's open question 7b, answered

The readiness signal is **Option A** in the startup-race document: have `container_instances` track
per-connector "initial enumeration complete" and expose it in its existing `status` reply, which
today returns `connector`/`records`/`pending` but no `ready` boolean. It was **not implemented** —
assessed as architecturally correct but a genuine cross-module change (connector state, wire
protocol, client library) and explicitly left as something "worth proposing to whoever owns
`container_instances`."

That folds into **D7**: the readiness boolean and the lifecycle cursor are the same conversation with
the same owner, and should be proposed together rather than as two separate asks.

### Strong input to D5 (thread ownership)

The spike implemented Option C — a catch-up walk triggered when the live path sees a container with
no existing rows — which is the same mechanism as
[11 §11.8.3](11-ebpf-provider-import-plan.md#1183-per-container-state-machine)'s Staging state,
arrived at independently. Two bugs it hit are the most useful empirical facts available for D5:

1. **A detached thread for the walk lost 502 of 504 rows.** The walk ran concurrently with the
   triggering event's own `upsert_container_file_row()`, both opening a scoped `file_entry`
   transaction for the *same* `container_id`. This is the source of the claim in doc 11's
   contradiction table — now confirmed as an observed failure, not an inference.
2. **The fix was to run it synchronously on the single dedicated consumer thread**, which deleted the
   mutex, the dedup set and the detached thread outright.

So D5's answer is constrained by evidence rather than taste: **concurrent scoped transactions for one
container silently lose rows**, so whatever owns the walk must serialise per container. That also
retires any lingering appeal of item 15 (bounded concurrency over containers) for the *live* path.

A third bug is worth noting because this branch is already immune: the catch-up walk's hand-built
rows omitted `checksum`, which `file_entry.checksum` requires `NOT NULL`, so a 9-file walk persisted
one row. This branch's `dbsync_sink()` computes it — the same code path C20 has just been fixed in.

### Already-known gaps these documents confirm rather than change

- **configMap / secret / downwardAPI / projected updates are invisible to the live path.** The
  kubelet's atomic-writer performs the write from *its own* cgroup, so `resolveByCgroupId()` returns
  `notContainer` and the event is dropped identically to a cold-cache miss. Baseline captures
  whatever exists when it runs. Already pinned as
  [11 §11.10 VM test 8](11-ebpf-provider-import-plan.md#vm-only-wazuh_manager); the matrix adds the
  mechanism and the suggestion of a path-based fallback lookup for host-attributed-but-
  container-relevant writes.
- **`oci_mounts` is collected and never consulted by the resolver** — confirmed by grep in that
  document. Resolution is mount-*namespace*-based, not mount-*spec*-based, which is why it is largely
  agnostic to volume type. Consistent with [07](07-options-matrix.md)'s mechanism choice.
- **cgroup v1 degrades every row of the matrix**, because nothing consumes the `mnt_ns` fallback.
  That is what `rt_host_cgroup_v1()` (step 3) now makes detectable, and what D11 has to decide.
- **Kata / VM-isolated runtimes are outside host-side eBPF entirely**, independent of volume type.

---

## 12.9 D4 answered — the loss proof, measured

Run on `wazuh_manager` (Ubuntu 24.04.4, kernel 7.0.0-30, bpf LSM active, 10 cores, a kind cluster
resident), using the committed `rt_engine_harness` — a deliberately slow consumer, one
`fprintf`+`fflush` per event.

### Reproduction

```bash
cd ~/ebpf_provider_37532
make BPFTOOL=/usr/lib/linux-hwe-7.0-tools-7.0.0-29/bpftool   # the Debian stub cannot do this
sudo ./rt_engine_harness A all > events.log &
# producer: N parallel shells, each creating 20 000 files
for j in $(seq 1 10); do ( mkdir -p /tmp/s/d$j; cd /tmp/s/d$j;
    for i in $(seq 1 20000); do echo x > f$i; done ) & done; wait
```

Do **not** stop the harness with `pkill -f rt_engine_harness` over SSH — the pattern matches the
remote shell's own command line and kills the session. Kill it by PID.

### Results

| Producer | Events delivered | Drop-flagged events | Events lost | Loss |
| --- | --- | --- | --- | --- |
| 1 shell, 20 000 creates in 2.39 s (≈8 400 ev/s) | 20 056 | **0** | 0 | 0 % |
| 10 parallel shells, ≈198 000 creates | 197 807 | **3** | 203 | ≈0.10 % |

The 203 is corroborated two independent ways: the three flagged events carried `dropped` = **188, 11
and 4** (sum 203), and comparing files actually created against events delivered per directory gives
≈204 missing. That also settles a contract detail the header is vague about — `dropped` is a
**read-and-reset delta**, not a running total, so a consumer that treats it as cumulative will
badly under-count.

### What this decides

**Drops are real and reachable, not hypothetical** ([11 open question 4](11-ebpf-provider-import-plan.md#1111-open-questions-and-what-i-could-not-verify)
is closed: the ~675-event in-flight figure was arithmetic; loss now has a measured onset). But they
took tens of thousands of events per second to provoke. A single-threaded 8 400 ev/s burst lost
nothing, and only 15 distinct cgroups were active across the whole run.

**So in-kernel filtering (§11.9 item 1) is an optimisation at these rates — and the measurement
inverts doc 11's ranking of items 1 and 2.** Doc 11 calls item 1 "the single most important item"
and item 2 second. For *correctness* it is the other way round, and the numbers above are why:

> 203 lost events surfaced as **3** flag-bearing events, from a single unkeyed global counter.

Under [11 §11.8.7](11-ebpf-provider-import-plan.md#1187-interaction-with-items-20-and-23)'s
escalation rule — *any* event with `RT_F_DROPS_BEFORE` marks every non-`Live` container Suspect —
those three flags re-baseline **every container on the node**, three times over, for a 0.1 % loss
that in this run belonged entirely to one shell in one cgroup. The escalation is not merely
pessimistic; it is unusable at any real churn rate. Item 2 is what makes the trigger implementable;
item 1 only reduces how often it fires.

Recommendation: **do item 2 first, then item 1.** Item 1 keeps its own strong justification —
without it a container-scoped consumer still receives every write-intent open on the host, so it
pays the full firehose to learn about a handful of containers — but it is a cost and exposure
argument, not the correctness argument doc 11 presents it as.

### D14 — how per-cgroup drop accounting is delivered — **DECIDED: the counter map**

§11.9 item 2 offers "per-cgroup counters, or a synthetic `RT_EV_DROP` record carrying `cgroup_id`".
That is a versioned-ABI decision and it should be made deliberately:

- **A new `rt_event_type` value** is additive under ADR-003 (a MINOR bump; old consumers ignore an
  unknown type) but spends a 12,416-byte record to carry two integers.
- **A per-cgroup counter map the consumer reads on demand** costs no record and no contract change
  at all, but needs a new engine entry point (`rt_take_drops(handle, cgroup_id)` or a bulk drain),
  and the consumer must decide when to poll it.

**Decided: the counter map**, implemented in `c590808019` as `rt_drain_drops()`. The event contract is
untouched, so no ABI bump. The in-band global counter and `RT_F_DROPS_BEFORE` stay exactly as they
were — they remain the "something was lost" signal; the map answers "by whom".

Two things worth carrying forward from building it:

- **BPF has no 32-bit atomic swap.** Both `__sync_fetch_and_and(counter, 0)` and
  `__sync_fetch_and_sub` fail to compile ("unsupported atomic operation, please use 64 bit
  version"); add is the only 32-bit atomic arithmetic available. §11.9 item 2's "make the read-reset
  atomic" is therefore an add of the two's complement with the result discarded — and that is
  *better* than the read-then-store it replaces, because an increment landing between the read and
  the clear survives it.
- **Keys must be collected before any are removed.** Deleting the current key mid-iteration makes
  `bpf_map_get_next_key` restart from the beginning, which can loop forever or skip entries.

### Two incidental findings for A3's consumer

1. **Non-filesystem paths are in the stream.** 107 of 197 807 events carried a pseudo-path, 102 of
   them `anon_inode:[…]` (pidfd and friends), plus 725 events with an empty `cwd`. A consumer that
   feeds `filename` straight into `/proc/<pid>/root` + path composition must reject these first —
   they are not paths and will compose into nonsense.
2. **Teardown verified a second way.** After every run, `bpftool link list` reported **0** links,
   including after a harness left over from an aborted run was killed. Consistent with
   `843b1efb76`'s fd census.

---

## 12.10 D5 resolved — and one of its options never existed

**D5 — thread ownership (item 14). DECIDED**, but not as any of the three options as written. The
third option, *"a shared `BaselineService` thread serving both consumers"*, is **not
implementable**, and neither [10](10-container-instances-delta-plan.md),
[11 §11.8.7](11-ebpf-provider-import-plan.md#1187-interaction-with-items-20-and-23) nor
[§12.3](#blocking-the-next-phase) noticed:

```
syscheckd/CMakeLists.txt:169     add_executable(wazuh-syscheckd .../src/main.c)
fim_run_container_baseline()     called only from syscheckd/src/main.c
Syscollector::scanContainerBaseline()  → wm_syscollector.c → wazuh-modulesd
```

**FIM and syscollector are different processes.** There is no `wm_syscheck` wmodule; FIM lives
entirely in `syscheckd/` as its own daemon, and syscollector is a wmodule inside
`wazuh-modulesd`. A thread cannot serve both consumers — that needs shared memory or IPC.

What the option was reaching for — single ownership of the image cache, the discovery latches, the
lifecycle cursor and the PID index — is worth having, and is achievable as **one `BaselineService`
object per process**. That is the part to keep.

### The decision

| Where | Threads | Rationale |
| --- | --- | --- |
| **syscheckd** | **Two**, and the initial walk is on **neither**. A ring-drain thread that only copies events into a bounded queue, and a consumer thread that pops it and reconciles per container. `fim_run_container_baseline()` stays on `main()` at its current call site | See below — one thread doing both drain and walk is actively harmful, and now measurably so; but moving the walk *off* `main()` is also wrong |
| **syscollector** | **None new.** Delta poll on its existing scan cycle | The provider has only four event classes, all file — no process and no socket class — so syscollector's data cannot come from the event stream at all. Processes and ports are Sampled. [10 Phase 3](10-container-instances-delta-plan.md#phase-3--syscollector-goes-delta-driven-m) already notes its own interval *is* the poll cadence |
| **both** | One `BaselineService` object per process | Items 22 and 29, and the single-ownership benefit the shared-thread idea was actually after |

### Why syscheckd needs two threads and not one

The drain must never block, and [§12.9](#129-d4-answered--the-loss-proof-measured) puts numbers on
what happens if it does. The 8 MiB ring absorbed a 2.4-second burst at 8,400 events/s. A FIM walk of
a single container takes far longer than 2.4 seconds — it is hashing, deliberately throttled by
`check_max_fps`. A thread that both drains and walks therefore **overflows the ring while it is
walking**, manufacturing exactly the drops the algorithm then has to recover from, and each drop
escalates to a re-baseline. Self-defeating.

The spike reached the same two-stage shape empirically: its ring-buffer thread hands off to a
dedicated `ebpf_pop_container_events` consumer, and the fix for the 502-of-504 row loss was to run
the catch-up walk **synchronously on that consumer**, which deleted the mutex, the dedup set and the
detached thread outright.

### Why the walk stays on `main()`

My first answer here was "put the walk on the consumer thread". That was wrong on two counts, and
the correction matters because it changes what gets built.

It contradicts [11 §11.8.1](11-ebpf-provider-import-plan.md#1181-ordering), which places
`fim_run_container_baseline()` at an **unchanged call site** — the walk blocks `main()`, and only
the *drain* moves ahead of it. Nothing about the ordering requires the walk to be on a thread: the
staging that makes subscribe-first work happens in the **drain thread's queue**, not in the walk.

And moving it would add real, unvalidated risk. Today `main()` blocks for the walk, so nothing else
touches `file_entry` while it runs. On a thread, the walk would run concurrently with
`realtime_start()` and host FIM's own transactions — and concurrent scoped `file_entry` transactions
are exactly what lost 502 of 504 rows. That case was same-container, so different scopes may well be
safe, but "may well be" is not a basis for moving a working startup path. Verifying it needs a real
agent on the VM, and it buys only startup latency that
[11 §11.8.1](11-ebpf-provider-import-plan.md#1181-ordering) has already decided to spend.

So the ordering is:

```
fim_initialize();
cfim_events_start();           /* drain thread starts; events accumulate in the queue */
fim_run_container_baseline();  /* unchanged: still blocks main() */
cfim_events_release();         /* NEW: only now may the consumer touch file_entry */
realtime_start();
```

The consumer thread starts **parked**. It must not process a staged event before the walk's
transaction commits, or it reproduces the 502-row bug directly: a single-row upsert for container C
racing C's open scoped transaction. Gating it on walk completion is what
[11 §11.8.4](11-ebpf-provider-import-plan.md#1184-reconcile-by-re-read-validated-and-now-forced)
means by reconciling after the commit.

This also resolves most of **item 14's FIM half**: what moves off `main()` is the drain and the
reconcile, not the walk. "FIM baselines on `main()`" turns out to be the deliberate design rather
than the defect the roadmap treats it as.

### Two consequences

1. **The queue is a second loss channel.** The contract's own comment on `RT_F_DROPS_BEFORE` says
   "ring buffer full, **or this consumer's own queue was full**". A bounded queue overflowing is
   loss with no in-band signal at all, so the consumer must fold its own overflow into the same
   Suspect escalation as a kernel-side drop. Easy to forget, and silent when forgotten.
2. **Some "shared" state actively wants to be per-process.** The discovery latches
   (`g_everSawContainers`, and `g_warmupWindowClosed` / `g_containersStable` from `c5bc0a1d76`) are
   statics in a shared library, so each process gets its own — which is correct, not accidental:
   each process independently has to wait out the connector on *its* own startup. The lifecycle
   cursor **must** be per-consumer for the same reason
   [10 §10.8](10-container-instances-delta-plan.md#108-correctness-under-missed-events) persists it
   only after applying: a shared cursor would let one consumer's progress mask the other's failure.

Item 22's cross-run image cache also loses most of its appeal here — it cannot span processes
anyway, and the two walks hash largely different things (FIM the monitored paths, syscollector the
package DBs and account files), so the overlap sharing would have exploited is small.

---

## 12.11 A3 (closed in `fc6e088b1a`), and D15

### What was built

| Commit | Piece | Verified |
|---|---|---|
| `7a45ead0bf` | `container_event_staging.hpp` — the drain/consumer handoff | 14 tests, mutation-checked |
| `0c631dd87c` | `cgroup_container_map.hpp` — `cgroup_id` → `container_id` | 21 tests, mutation-checked |
| `dbd4db569b` | `container_event_router.hpp` — the routing policy | 15 tests, mutation-checked |
| `f3c4eb4900` | rename ⇒ re-walk ([C21](03-findings-correctness.md)) | 19 tests, mutation-checked |

All four are header-only and I/O-free by design, so every one of them is reachable from a unit test
without a kernel, a BPF object or root. The router's `HostCgroupDropStormNeverEscalatesGlobally` is
the one worth keeping an eye on: 5,000 unidentified cgroups reporting drops must produce zero global
escalations, and no single-event test can show that.

Two VM measurements re-confirmed A3's foundation: **`cgroup_id` is the cgroup directory inode** (40576
and 42418, matching `stat -c %i` both times), every event from a container carried it, and paths for
the rootfs, a tmpfs volume and a bind mount all render as correct **container-absolute** paths. So the
drain can attribute events, and it can trust the path for ordinary container file activity.

They also turned up two defects, both now handled or recorded:
[C21](03-findings-correctness.md) (a rename never names its source path — fixed by re-walking) and
[C22](03-findings-correctness.md) (an `ATTR` event on the rootfs carries a host-side path under the
container's cgroup — needs the inference ban below).

### D15 — May the consumer infer a deletion from a path it cannot find? **RESOLVED: no. Enforced in `ba8c642007`.**

This is the one decision left before the reconcile consumer can be written, and C22 makes it sharp.

A staged path that resolves to nothing inside the container has three possible causes, and they are
indistinguishable at the point of the read:

1. The file really was deleted → a DELETE is correct.
2. The path was a C22 host-form artifact that slipped past the prefix filter → a DELETE is a **false
   positive on a file that is fine**.
3. The container restarted, or its PID is momentarily unresolvable → a DELETE is a **mass false
   positive**, which is [C15](03-findings-correctness.md) all over again.

Two of the three are wrong, and the wrong ones are the damaging direction: a false DELETE tells an
operator a file vanished when it did not. So the consumer should upsert what it can read and leave
what it cannot alone, exactly as `container_baseline.h` already instructs its callers ("no rows is not
removed"). Real deletions are then detected by the next walk's per-container delete detection, which
sees the whole directory rather than one path and can tell absence from unreadability.

The cost is latency on genuine deletions: a file removed inside a container is not reported until the
next baseline. That is a real gap and should be recorded as such rather than hidden — but it is the
same gap the module already has today, and it is strictly better than emitting deletions that are
wrong.

**Not blocked on anyone else.** Unlike D6–D14 this needed no cross-module agreement; it is a rule the
consumer enforces on itself. It was settled *before* the consumer was written rather than after —
retrofitting an inference ban onto code that already deletes is how C15 happened.

#### How it is enforced

`container_reconcile_plan.hpp` (`ba8c642007`) turns a staged `Batch` into a `ReconcileRequest`
carrying `may_detect_deletions`, and no path batch ever sets it. The rule therefore lives in the type
the consumer acts on rather than in a comment asking it to behave.

| Batch | Mode | May delete |
| --- | --- | --- |
| Suspect, no container id | `rebaselineAll` | yes |
| Suspect, with container id | `rewalkContainer` | yes |
| Paths | `rereadPaths` | **never** |

Two details are load-bearing:

- `may_detect_deletions` decides only whether deletions are **reported**, not whether rows are
  deleted. `ScopedContainerTxn` calls `fim_db_transaction_deleted_rows()` for a scan reported
  complete and `fim_db_transaction_close()` otherwise — and the second one deletes the untouched
  rows just the same, because `DBSyncImplementation::closeTransaction()` runs
  `deleteRowsByStatusField()` unconditionally. Measured on the node: a container with six baselined
  files, one file changed, one row reconciled, **one row left**
  ([C27](03-findings-correctness.md#c27--a-path-reconcile-deletes-the-rest-of-the-containers-rows)).
  So the rule above holds for the alerts and fails for the state, and a path reconcile currently
  wipes the rest of the container. D18 is what closes it.
- An empty path batch is a **no-op**, deliberately not promoted to a walk. Promoting it would convert
  "nothing to reconcile" into "delete whatever I cannot find" — the forbidden inference arriving
  through a convenience. The mutation that makes that promotion fails four tests.

`NoPathBatchMayEverAuthoriseDeletion` pins the rule across every shape of path batch, including the
C22 host-form and mount-relative paths, rather than one chosen example.

### What A3 needed after D15 — all done in `fc6e088b1a` / `ed24a606ce`

- The `rt_poll` drain thread and the resolver thread (`listContainers` → `install`, `takeUnresolved` →
  `resolveByCgroupId`). Structure is settled; the resolver must gate `install()` on the client's
  `reachable` flag, since `install({})` clears the positive map and an unreachable connector would
  otherwise un-attribute every container — the C15 failure shape, one level down.
- `fimebpf` must link `rt_engine` and gain the two include paths. `rt_engine` is already built
  `POSITION_INDEPENDENT_CODE ON` for exactly this.
- `cfim_events_start()` / `cfim_events_release()` in `main.c`, around the unchanged
  `fim_run_container_baseline()` call site (§12.10).
- The reconcile consumer itself, which needs a **per-container** entry point in `container_baseline`'s
  C API — `cbaseline_run_fim_dbsync()` walks every container and there is no way to ask it for one.
  Planned in [13-container-baseline-api-plan.md](13-container-baseline-api-plan.md): **one** new
  export, not two, because the existing walker is already path-rooted with
  `recursion_level = 0` meaning "entry only", so re-reading a specific file is the same call with
  different arguments.
- `RT_CGROUP_MODE_ALLOWLIST` stays unavailable until item 20's create trigger exists, since an
  unlisted cgroup is then invisible rather than merely unattributed. Mode ALL needs no trigger and is
  what the drain should open with.

---

## 12.12 The end-to-end run (2026-09-07), and the two decisions it forces

A3 was built with everything below the connector unit-tested and only the *engine-unavailable*
degradation path exercised end to end. It has now been run for real on `wazuh_manager`: the real BPF
engine on a real kernel, the real `container_instances` module in its own process talking over its
real IPC socket, real Docker containers, and the real `container_baseline` scanner. Only two things
were stand-ins — syscheckd's bridge (config, logging, abspath, fps budget) and FIM's DBSync layer,
replaced by an in-memory store with DBSync's callback shape. So this validated everything that
decides *what* to hand the database, and nothing about `libfimdb` itself.

### What held up

| Property | Evidence |
|---|---|
| Subscribe-first ordering | engine attached 09:25:38.486, drain started 09:25:40.403, walk opened its first transaction 09:25:40.913 |
| Whole-node baseline against a live container | 47 `file_entry` rows, container-absolute paths, correct `container_id` |
| `cgroup_id` → `container_id` through the real connector | `list` answered `cgroup_id:"22959"` (= `stat -c %i` of the cgroup dir) for the right container |
| Containers created *after* startup | a container started 8 minutes into the run was resolved by the resolver thread and re-walked, with nothing seeding it |
| Attribution with two identical images | two alpines with distinguishable `/etc/profile`; a write to one produced `MODIFIED` for that one only, with its own size |
| [C21](03-findings-correctness.md) rename ⇒ re-walk | `mv /etc/issue /etc/issue.moved` → re-walk → `CREATE /etc/issue.moved` **and `DELETE /etc/issue`** — the deletion no event reports |
| [D15](#1211-a3-closed-in-fc6e088b1a-and-d15) | every path reconcile closed "WITHOUT delete detection"; `rm /etc/e2e-new.conf` produced 0 rows and deleted nothing |
| [C22](03-findings-correctness.md) filtering | the prefix filter discarded exactly the host-form paths — `ATTR /var/lib/containerd/…/snapshots/126/work/work/#1988178` (×4 per write) and `OPEN /proc/10/task/10/attr/apparmor/exec` from `runc:[2:INIT]` |
| Connector unreachable | a rename escalation with the connector down logged "connector unavailable while re-walking … its rows are kept", deleted nothing, and resumed on its own once the connector was back |

### What broke

Two defects, both of which only a running system could show:
[C23](03-findings-correctness.md) — the re-read races the write that triggered it, and silently keeps
the pre-write row — and [C24](03-findings-correctness.md) — one configured path that an image lacks
suppresses that container's delete detection permanently.

### D16 — How does a path reconcile see the *post*-write state? **RESOLVED 2026-09-07 — settle in the staging buffer (`60182a3a17`)**

> **Decided:** the fourth option below (§12.14) — hold a staged path until the pid that triggered it
> has exited or a bounded 500 ms delay elapses, then read once. Chosen over the trailing re-read on
> cost (one stat+hash, no verify-later set) and over re-read-until-stable, which is unbounded on an
> append-heavy file. A repeat event takes the newer pid but does **not** extend the deadline, which
> is what stops an append-heavy log starving. Implementation and the six mutations that pin it:
> [14 WP1](14-spike-integration-plan.md). It remains a bound, not a guarantee — a writer that
> outlives the delay is still read mid-write, which no consumer-side option can prevent.

The analysis that led there:


`RT_EV_FILE_OPEN` fires on open-with-write-intent, so the event precedes the modification; the
consumer re-reads once, immediately, and a writer that holds the file open loses the race
(measured: an 8-second-deferred write was never reported). The provider has no write-completion
event, so the settle has to come from the consumer. Three shapes:

| Option | Cost | Objection |
|---|---|---|
| **Trailing re-read**: a path whose re-read produced *no* change goes into a verify-later set and is re-read once after a settle delay | one extra stat + hash per unchanged reconciled path | picks a delay with no principled value; a writer slower than the delay still escapes |
| **Re-read until stable**: repeat until two consecutive reads agree | unbounded for an actively-written file | an append-heavy log file never stabilises |
| **Ask the provider for a close-write event** | a change in #37396's contract, and a new event class | `RT_EV_FILE_OPEN`'s "write intent" is knowable at open; "the write finished" needs `fsnotify`-style close tracking, which is a real cost in the hot path |

### D17 — What does "the scan was incomplete" authorise? **RESOLVED 2026-09-07 — the narrow fix plus the unlink half (`1cab48878c`)**

> **Decided:** report the reasons separately and act on `RT_EV_FILE_UNLINK`; seam S1's per-table
> `partial` was the third option and was **not** taken, because the narrow fix answers C24 at the
> layer that produces the facts (the walker) rather than the layer that reports them per table.
>
> An absent configured root is now its own fact and is deliberately not part of `partial` — the walk
> looked, and there is nothing there — so one bad `<directories>` entry no longer suppresses that
> container's deletions forever. What makes the split safe is that `/proc/<pid>/root/<path>` also
> fails with ENOENT once the pid exits, so the walker confirms the rootfs is still addressable
> before calling a root absent; otherwise a vanished container reads as a set of vanished
> directories, which is C15 one root at a time. `cb_container_status_sink_t` became a struct-taking
> callback (both consumers updated).
>
> One clause of the decision did not land: rows under an absent root are **deleted**, not preserved.
> Preserving them is not expressible with today's DBSync — a scoped transaction is a single-column
> equality, so "everything except this path prefix" cannot be said, and preserving them means
> re-syncing full stored rows, which needs the Model B reconciler
> [D1](#125-d1-in-depth--the-two-inventory-state-models) declined. Deleting them is the truthful
> outcome when the directory really is gone, and the dangerous case is now `root_unreadable` and
> still suppresses. See [14 WP3](14-spike-integration-plan.md).
>
> The unlink half: `fim_db_container_get_path()` reads the row before removing it, so the checksum
> and document version the stateful DELETE needs are still there, and reports it through the same
> callback every other change goes through — one code path for the alert and the document.

The analysis that led there:


`partial` currently collapses three different facts — a row cap was hit, a configured root is absent
from the image, and a namespace could not be read — and any one of them switches delete detection off
for the whole container. The absent-root case is static, so the switch never flips back
([C24](03-findings-correctness.md)).

The narrow fix is to report the absent root separately and scope delete detection to the roots that
did resolve. That is a change to `cb_container_status_sink_t`'s contract, which is why it is a
decision and not a patch: the status callback is `container_baseline`'s public C API, consumed by
Syscollector as well as FIM.

The same decision should settle a smaller question the run surfaced: `RT_EV_FILE_UNLINK` carries the
path and is the kernel *stating* that the file was unlinked, but the drain stages it like any other
path event, the re-read finds nothing, and D15 correctly refuses to infer a deletion from a failed
read. So an in-container `rm` is not reported until something else forces a re-walk. An explicit
unlink event is not an inference, and could authorise deleting exactly that one path — which D15 does
not forbid, since D15 is about absence, not about an event that names the removal.

---

## 12.13 The port order, finished (2026-09-07)

Steps 4–9 of [§12.7](#127-the-decided-plan-d1--option-3-d2--option-1)'s table are worked through.
Two of the six produced code; the other four produced the finding that they should not.

| Step | Commit | What actually applied |
| --- | --- | --- |
| 4 — `583f9a52d1` (the `extern "C"` include-ordering trap) | — | **Moot.** Every hunk is inside `container_live_fim.cpp` or its CMake entry, and that file arrived in `2541026edb`, which the port order does not port. The trap it documents is real and will bite when the live path lands (A4); it is recorded here rather than ported as dead code. |
| 5 — `415e7a2204` (container field in `fim_file_data`) | `69303187cd` | **Ported, schema half only.** `fim_file_data` carries `container_id`/`container_json`, `FileItem` round-trips them, `createJSON()` stops writing a hardcoded `""`. Its *other* half — rewriting the container baseline's sync from `fim_db_transaction_sync_row_json()` to the typed `fim_db_transaction_sync_row()` — was deliberately dropped: the scanner already emits dbsync column format, so the typed path means parse → struct → re-serialise through `FileItem::createJSON()`, whose column list becomes a second place every future column must be added or be silently dropped. A3 also replaced `sync_container(rows)` with per-row streaming, so the diff no longer applies as written. |
| 6 — `c4357e6481` (`changed_fields` for the live FIM path) | — | **Moot, with one deliberate skip.** The body is `container_live_fim.cpp`. Its CMake hunk is self-cancelling in the spike's own history (step 4, two hours later, removes exactly what it adds). Its one live piece — moving `send_syscheck_msg`/`persist_syscheck_msg` inside an `extern "C"` block — is **not** taken: this branch's `syscheck.h` has no such block at all, nothing here includes it from C++, and the deliberate alternative (the bridge shims in `container_baseline_fim_bridge.h`) is already in place. A4 should bring it when it needs it. |
| 7 — `4b4bd3c1bb` (syscollector interval + documented limits) | `4b365c11d6`, `4e096f9537` | **Ported, cadence half only.** `<container_baseline_interval>` decouples the container pass from the host `<interval>`; one loop, two deadlines. See below for the three parts left out. |
| 8 — `5a9021e285` seams S1–S3 | partly already done | **S3 is done** (`ed24a606ce`'s per-container FIM entry point is exactly `ReconcileScope{single_container_id}` for the FIM half; the Syscollector half has no consumer yet). **S1 is not being taken.** D17 is now resolved without it (`1cab48878c`): the reasons behind `partial` are separated at the layer that produces them, and `cb_container_status_sink_t` became a struct-taking callback, which is where a per-table breakdown would go if a consumer ever needed one. S1 would be a second contract change for a consumer that does not exist yet — see [14 WP3](14-spike-integration-plan.md). **S2** (fold `reachable` into the identity list) is unblocked but cosmetic; the property it protects is already enforced and tested (`ListContainers.UnreachableConnectorReportsFailureNotAnEmptyNode`). |
| 9 — `6022673065`, `adf6ae0a74`, `92a3f4d3be`, `0080d7d294` | — | **All four moot**, checked hunk by hunk. `6022673065`'s only non-live-FIM hunk is *temporary debug instrumentation* its own comment says to delete. `92a3f4d3be` is a missing brace plus a sink for the Model B reconciler this branch does not import. `adf6ae0a74`'s scanner hunk (the quiescence poll) is **already here, in a stronger form** — ours also handles the connector going away mid-check. `0080d7d294`'s one applicable line (`process.pid` as a number, not a string) is already the assertion in our `baseline_rows_test.cpp`. |

The five spike design documents §12.7 asks to copy across are **already on this branch** at `spike-37533/`,
byte-identical to the spike branch's copies. That line of §12.7 was wrong.

### What step 7 left out, and why

- **`<containers><enabled>`** — a second spelling of this branch's own `<container_baseline>`, which
  the spike branch did not have. Two switches for one collector is worse than either.
- **Its `syscollectorImp` scan body** — built on `cbaseline_reconciler_create` /
  `CB_DEFAULT_PRIOR_STATE_DB_PATH`, i.e. the durable prior-state reconciler that
  [D1 = Option 3](#125-d1-in-depth--the-two-inventory-state-models) chose not to import. Those hunks
  describe a model this branch does not have, and they *remove* the DBSync path it does.
- **The per-dimension container row limits** (`syscollector_containers_limits_t` plus the
  remoted/agent handshake that delivers them) — deferred on the same reasoning as S1: a row cap is
  one of the three things that make a scan `partial`. D17 has since answered that — a row cap sets
  `row_cap_hit`, which suppresses delete detection — so what still blocks the limits is where
  per-dimension enforcement lives, not what a cap means. See [14 WP4](14-spike-integration-plan.md).

### The config parser's tests, and what running them changed (`4e096f9537`)

Step 7 first landed two cmocka cases that could not be run — cmocka was not installed. It is now,
and running them showed **both were wrong**: they drove `Test_WModule()`, whose `<agent_config>`
plumbing never reached `wm_syscollector_read()` here, so a pass meant only "nothing objected", which
is also what "nothing was parsed" returns. They are rewritten against `Read_WModule()` with
`agent_cfg` set — three cases now, asserting the **parsed value** rather than a return code — and
mutation-checked, one case killed per mutation.

Three things about this suite are worth writing down, because each one cost time:

- **`test_wmodules-config` links both `libconfig.a` and `libCONFIG_O.a`, and `libconfig.a` wins.**
  Rebuilding the loose object, or `libCONFIG_O.a`, leaves the test binary running the *old* code —
  which made two full mutation passes report every mutation as survived. `make config` in
  `src/build` is also required.
- **`libCONFIG_O.a` is a configure-time GLOB of the main build's `.o` files**, declared
  `EXTERNAL_OBJECT`, so nothing tracks their contents: the archive *and* the test binary have to be
  deleted to force a relink.
- **It is only built for `TARGET=manager`**, needs `libwazuh_test.a` (i.e. a `UNIT_TEST=ON`
  configure of the main build), and needs a `queue/sockets/.agent_info` in its working directory or
  `Test_WModule()` logs `(1103)` and every `merror` expectation shifts by one.

And the 7 pre-existing cases in that file **all fail, before and after** — `ReadConfig()` emits
`mdebug2` while walking `<agent_config>` and the wrapper is strict, so every one dies on "No entries
for symbol `__wrap__mdebug2`". Left alone deliberately.

### Two things measured while porting

- **The container connector's warm-up retry costs ~4.5 s, once per process, on a host with no
  `container_instances` socket** — `kListRetryAttempts` × `kListRetryDelay` (10 × 500 ms) in
  `container_baseline_scanner.cpp`, latched by `g_warmupWindowClosed`. Every pass after it returns in
  ~1 ms. It is why the new cadence test needs a 12-second window.
- **17 of 81 `syscollectorimp_unit_test` cases fail on this branch**, in a standalone build of that
  target. They fail identically on the pristine tree and still fail with the container pass disabled
  outright, so they are not the container work's doing — but they are also not diagnosed, and the
  build was standalone, so it may be an artifact of that rather than a branch defect. Worth a look
  before anyone trusts that suite.
- Also fixed in passing: `syscollectorimp_unit_test` never linked `container_baseline`, though
  `syscollectorImp.cpp` has called `cbaseline_run_syscollector_dbsync()` since #37532 landed.

---

## 12.14 The spike branch reviewed as a whole (2026-09-07)

[§12.13](#1213-the-port-order-finished-2026-09-07) worked the *commit* order. The spike's whole tree
has now been reviewed against this branch as well — the parts no commit in that order touched — and
the result is [**14**](14-spike-integration-plan.md), with the plan for what remains. Three things
belong here because they change decisions recorded above.

**A libfimdb claim that would have been a critical defect in A3, disproved.** The spike's
`container_live_fim.cpp` states that `fim_db_transaction_deleted_rows()` is "required to actually
flush/commit the synced rows — without this call … only persisted 1-2 of several hundred synced
rows". [D15](#1211-a3-closed-in-fc6e088b1a-and-d15) makes a path reconcile close with
`fim_db_transaction_close()` and never call `deleted_rows`, so if that were true every path reconcile
would be persisting almost nothing — and the [end-to-end run](#1212-the-end-to-end-run-2026-09-07-and-the-two-decisions-it-forces)
could not have shown it, because the harness replaced `libfimdb` with an in-memory store.

Measured against the real `libfimdb`, and now pinned by `src/syscheckd/src/ebpf/tests/txn/`
(`7117b9fb08`): 500 rows in, 500 callbacks out, none lost — and unchanged at 5,000 rows against
`libdbsync` directly, and even when the transaction is never closed at all. dbsync dispatches result
callbacks through `Utils::ReadNode`, whose `Dispatcher` defaults to `SyncDispatcher`
(`pipelineNodesImp.h:25`), i.e. inline on the calling thread; there is nothing for a flush to flush.
The same test also closes three of [09](09-implementation-status.md)'s "libfimdb never exercised"
gaps: `container_id` is genuinely in the primary key, a scoped sweep deletes only its own scope's
untouched rows, and another container's rows survive it.

**D16 gains a fourth option.** The spike's live path re-reads immediately too, so it shares
[C23](03-findings-correctness.md)'s race — but its test-plan finding #3b measured that the writing
PID is usually *already dead* by the time the event is processed, which is why its create/modify
tests passed. That suggests a cheaper shape than the three in
[§12.12](#d16--how-does-a-path-reconcile-see-the-post-write-state-resolved-2026-09-07--settle-in-the-staging-buffer-60182a3a17): **settle the path in the
staging buffer** — hold it until the triggering PID exits or a bounded delay elapses, then read once.
One stat+hash instead of two, and no new per-path state, because the dedup map is already keyed by
path.

**D17 is cheaper than [§12.13](#1213-the-port-order-finished-2026-09-07) implies, and its unlink half
has an export waiting.** The per-dimension row limits' *transport* is decision-free — it extends
5.0.0's existing `module_limits_t` additively, defaults to unlimited, and is optional on the agent
side — so only the enforcement waits on D17, and the enforcement as written terminates in the Model B
reconciler [D1](#125-d1-in-depth--the-two-inventory-state-models) declined. Separately, the spike's
`fim_db_container_file_delete()` + `DB::removeFile(path, containerId)` (40 lines) is exactly the
export D17's unlink question needs; this branch currently has no way to delete a single container
row.

**What the spike does not settle:** [D6](#blocking-the-next-phase), [D7](#blocking-the-next-phase) —
it makes no source change to `container_instances` at all — [D11](#product-visible-decide-before-a3-ships),
and D16 and D17, both of which have since been decided here rather than taken from it. And [D9](#blocking-the-next-phase) is answered only in the sense that the spike *did* A4:
it cut host whodata over to `rt_engine`, at the cost of deleting four `fimEbpfWhodataTest` files and
cutting back two more. [14 §14.7](14-spike-integration-plan.md) plans that route with the tests kept.

### What the review's own plan has since produced (2026-09-07)

- **WP2 is done, `888c29a4a6`.** The one gap on this branch that no finding had named: container FIM
  rows were persisted and never alerted on. It needed no decision, and the three questions it *did*
  raise are settled in [14 WP2](14-spike-integration-plan.md) — a container path resolves against
  container-tagged `<directories>` entries only (not `fim_configuration_directory()`, which a longer
  untagged host entry would win), the initial whole-node baseline does not alert, and `mode` is
  `"scheduled"` for a walk and `"whodata"` for an event-driven reconcile.
- **WP1 and WP3 are done too**, on the D16 and D17 decisions recorded above: `60182a3a17` settles a
  staged path before re-reading it, and `1cab48878c` separates the status facts and acts on
  `RT_EV_FILE_UNLINK`. **Both have since run on the integrated agent**
  ([§12.15](#1215-the-integrated-agent-on-a-real-node-2026-09-08)), so that gate on
  [WP5](14-spike-integration-plan.md) is met. [C27](03-findings-correctness.md) blocked it next, and
  that is now cleared too — fixed in `d3a8e394d9` under
  [D18](#d18--how-does-a-path-reconcile-persist-a-row-without-authorising-a-sweep-resolved-2026-09-08--the-non-transactional-upsert-d3a8e394d9),
  leaving WP5 gated on [D9](#123-blocking-decisions) alone.
- **A new decision, and it is the one that stops this shipping.** `1bdfb0990e` fixed the *install*
  of `rt_file.bpf.o`; chasing WP6 showed the packaging pipeline never **builds** it either, because
  `libbpf-bootstrap` is fetched precompiled and so the vendored `vmlinux.h` that `rt_file.bpf.o`'s
  compile branch needs is absent. Someone has to choose where the object comes from — the deps
  tarball, as `modern.bpf.o` does, or a committed `ebpf_provider/prebuilt/rt_file.bpf.o`, a path the
  CMake already honours. Until then the container event path silently does not run on a package.
  `c0e5f162bb` makes it not silent: a `mwarn`, raised only where the operator configured container
  directories. **Decided 2026-09-07: the committed prebuilt**, and `da90a18c5b` makes that lookup
  per-architecture — it was arch-blind, and an x86 object on an arm64 host installs and then fails
  to load, which is indistinguishable from having no eBPF. No object is committed yet: a shippable
  one needs the portable vendored `vmlinux.h` rather than a host-generated header, and a load test
  on a real cgroup-v2 kernel.
- **WP6's own question is answered:** `check_files.py` exits non-zero on any installed file matching
  no CSV row, so the manifests are a **CI blocker**, not a completeness item — and its size check is
  skipped when `size_bytes` is `0`, so the rows can land without waiting for a byte count.

---

## 12.15 The integrated agent on a real node (2026-09-08)

The first run of the **whole agent** — `wazuh-modulesd` and `wazuh-syscheckd` built from
`37532-5-0-0-container-integration`, on `wazuh_manager` (Ubuntu 24.04.4, kernel 7.0.0-31, cgroup v2)
— against real Docker containers. Every prior run drove the pieces directly; this one drove the
daemons, which is why it found three things static reading and the piece-wise harness could not.

Scope was detection and event generation. The indexer and dashboard do not accept these documents
yet, so nothing downstream of the agent queue was in play.

### Method

No install and no manager. The agent's daemons run from an isolated `WAZUH_AGENT_HOME`, with two
stubs standing in for the rest of the deployment: a `SOCK_DGRAM` listener bound to
`queue/sockets/queue`, which is every stateless event the daemons generate, and a `SOCK_STREAM`
server on `queue/sockets/agent` answering `getstartupgate` (otherwise `modulesd` blocks on the
startup hash gate forever), `getdoclimits fim` and `getdoclimits syscollector` (both retry until
success), and `getdoclimits syscollector_containers` — which is also what made WP4's per-scope
limits testable without a real handshake.

### What held up

| Claim | Measured |
| --- | --- |
| The provider builds from source on a modern kernel | `make build TARGET=agent` clean; `rt_file.bpf.o` produced via the host-BTF fallback (`vendored vmlinux.h absent; generating one from this host's kernel BTF`) |
| The engine attaches | `eBPF engine ready: 4 program(s) attached, ABI 1.1, cgroup filter off`, and `active LSM list includes "bpf" -> preferring LSM file_open variant` — the LSM variant, not the kprobe fallback |
| WP1's subscribe-first ordering | `started; staging container file events until the baseline walk commits` precedes `baseline walk committed; the reconcile consumer is now live` |
| D17 / [C24](03-findings-correctness.md) | `1 of 2 configured directories are absent from container '…' image; delete detection proceeds over the 1 that resolved` — with `/absent-root` configured alongside `/data` |
| WP2's alert | a new file inside a container produced `"type":"added"` on the queue with the container block attached |
| WP4's separate budget, and the `4b365c11d6` bug fix | container limits `{"packages":2,"processes":3}` arrived over the wire; 32 container package rows collected, `Post-scan promotion [container]: … Successfully promoted 2 records` on the independent 60 s cadence, host counts untouched |
| Container inventory events | 77 stateless syscollector events carrying `container.id`, `container.image.digest`, `container.name`, `container.network`, `container.runtime` |

### What broke

Three defects, in the order they blocked the run:

- **[C25](03-findings-correctness.md#c25--the-container_instances-block-is-never-dispatched-so-the-module-cannot-start)**
  — `Read_ContainerInstances()` had no caller, so `<container_instances>` was accepted and ignored,
  the module never started, and `queue/sockets/container_instances` was never bound. Nothing in the
  feature could reach a real agent. Fixed, `a98549d807`; every row in the table above depends on it.
- **[C26](03-findings-correctness.md#c26--a-change-to-an-already-known-container-file-raises-no-alert)**
  — `MODIFIED` arrived unwrapped, so `container_txn_callback` returned on every modification and a
  change to a known container file raised no alert at all. Six files changed → six rows updated in
  `file_entry` → zero callbacks. Fixed, `f39967c55c`.
- **[C27](03-findings-correctness.md#c27--a-path-reconcile-deletes-the-rest-of-the-containers-rows)**
  — `fim_db_transaction_close()` deletes the rows the transaction did not refresh, which is the
  opposite of what D15's implementation note claims. Fixed, `d3a8e394d9`, after §12.16 measured what
  it did to the alerts; D18 below records the choice.

### A known gap, now measured rather than predicted

No schema in `external/indexer-plugins/*.json` mentions `container`, `fim-files.json` included, so
every container row fails `container: Field not allowed in strict mode` and its **stateful document
is discarded** on ten indices: `wazuh-states-fim-files`, `-packages`, `-processes`, `-users`,
`-groups`, `-hardware`, `-networks`, `-protocols`, `-interfaces`, `-system`. Local `file_entry` rows
and stateless events are unaffected, which is why detection works at all. This is #37203-3/-4 and it
ships from an `external-precompiled` dependency, so it cannot be closed from this branch.

One new observation for [D6](#123-blocking-decisions): `container_instances` logs
`Cold-cache resolution of cgroup inode NNNN failed (attempt 1/3)` three times per unresolvable
cgroup. With `cgroup filter off` the drain sees host file activity too, so on a busy node this is a
`WARNING` per host event.

### D18 — How does a path reconcile persist a row without authorising a sweep? **RESOLVED 2026-09-08 — the non-transactional upsert (`d3a8e394d9`)**

[C27](03-findings-correctness.md#c27--a-path-reconcile-deletes-the-rest-of-the-containers-rows) is
not a bug in D15's *rule* — no path batch may infer a deletion, and that still holds — it is a bug
in the mechanism chosen to enforce it. A scoped DBSync transaction deletes untouched rows on close
whether or not the closer asks for delete detection, so a reconcile that names one file cannot use
one at all.

Two shapes, and the choice needs recording because it changes which layer owns container FIM's
writes:

| Option | Cost | Objection |
| --- | --- | --- |
| **Non-transactional per-row upsert.** A new `fim_db_container_file_sync()` alongside the `DB::removeFile`/`DB::getFile` pair the unlink half already uses, calling `syncTableRowData` with `inTransaction=false` and `return_old_data` | one statement per row; no scope, so no sweep to suppress | the path reconcile stops sharing a code path with the walk, so the two can drift |
| **Keep the transaction, restore the untouched rows.** Re-sync the container's stored rows alongside the reconciled one so nothing has `db_status_field_dm=0` at close | reads and re-syncs every row of the container for a one-file change — the 1+N shape [04](04-findings-performance.md) already objects to | needs the full stored row, i.e. the Model B reconciler [D1](#125-d1-in-depth--the-two-inventory-state-models) declined |

**Decided: the first.** It is the only one whose cost is proportional to what changed, and the
unlink half already proved the non-transactional container-scoped path works. Landed as
`fim_db_container_file_sync()` in `d3a8e394d9`; `onStatus()` returns early on the reconcile path too,
because opening a transaction for a container that produced no rows — so its stored rows could age
out — is meaningless for a reconcile and was a second route to the same sweep.

The stated objection stands and is worth restating rather than dismissing: `ScopedContainerTxn` is no
longer the single writer for container `file_entry` rows, so the walk and the reconcile can drift.
Two things bound that. The checksum is computed once in `onRow`, above the branch, so both paths
digest a row identically — that column is what DBSync diffs on, and a divergence there would be the
expensive kind. And both paths hand the same `container_txn_callback` the same
`{"old","new"}`-shaped `MODIFIED`, so the alert half cannot drift without a test noticing: case 7 of
the scoped-transaction suite asserts the direct upsert's payload shape explicitly, next to case 5
doing the same for the transactional one.

What this does **not** change: the walk paths (whole-node baseline, per-container re-walk) keep the
scoped transaction and their delete detection, still gated on the scan being reported complete. D15's
rule is untouched — the reconcile still never infers a deletion — and the unlink half remains the
only path that removes a container row on an event, because the kernel named it.

## 12.16 The lifecycle question, answered by measurement (2026-09-08)

A second run on the same node, asking one question doc
[10](10-container-instances-delta-plan.md) never got to test: **what happens to a container created
after the baseline?** `fim_run_container_baseline()` is called once from `main.c:493`, and
[10](10-container-instances-delta-plan.md) is unimplemented, so nothing publishes a "container
appeared" event to trigger a walk. On paper that reads like a gap.

### It is not a gap — and the reason matters

| Time | Event |
|---|---|
| 21:46:43 | `docker run -d --name cfimquiet cfim:1 sleep 3600` — five files baked into `/data` at image build, so the container performs no writes of its own |
| 21:46:45 | `Container FIM reconcile: re-walked container 'fcc59efab…' (1), 5 row(s).` |
| 21:46:45 | five `added` alerts, one per file, `mode: whodata`, full `container` block |

Two seconds, whole container, no restart, no lifecycle delta. The path is:
`RT_CGROUP_MODE_ALL` → events arrive from a cgroup the map has never seen → `classify()` files it
unknown → `resolve` → `noteContainerLocked()` returns `was_unknown` → `escalate()` →
`onDrops(container_id)` → `rewalkContainer`.

### What actually generates the first event — measured, and not what I first wrote

I initially recorded the trigger as the container's own startup `execve` reading its interpreter and
binary. **That is impossible**, and the BPF source says so: read-only opens and non-regular files are
dropped in the kernel.

```c
/* rt_file.bpf.c:460 — O_RDONLY == 0, so a plain read never leaves the kernel */
if (!(f_mode & FMODE_CREATED) && !(f_flags & O_CREAT) && !(f_flags & O_ACCMODE))
    return 0;
if (!d_inode || !is_regular_file(d_inode))
    return 0;
```

A temporary per-event trace settled it. A container created after the baseline emits **exactly four**
events from its own cgroup, all `RT_EV_FILE_OPEN`, all within one second of `docker run`, and all
issued by **runc's init** rather than by the container's command:

```text
type=1 cgroup=21124 pid=13320 path=/proc/13320/oom_score_adj
type=1 cgroup=21124 pid=13323 path=/1/task/1/attr/apparmor/exec
type=1 cgroup=21124 pid=13323 path=/sys/net/ipv4/ip_unprivileged_port_start
type=1 cgroup=21124 pid=13323 path=/sys/net/ipv4/ping_group_range
```

`sleep 3600` produced none. None of the four paths is in the container's rootfs or under a monitored
directory, which does not matter: escalation fires when an **unknown cgroup is resolved**, whatever
path exposed it. The reason it wins the race is timing — these land ~1 s after `docker run`, before
`container_instances` has finished its `reSeed`, so the drain's 5 s `refreshContainerList()` cannot
have installed the mapping yet.

### So how much can be leaned on this?

Less than the first write-up implied, and the difference is the point:

- **`RT_CGROUP_MODE_ALL` is still load-bearing.** The comment at `container_event_drain.cpp:403-411`
  — "until `container_instances` has a create-time trigger (item 20), narrowing the filter would
  trade a bounded cost for a silent gap" — is correct and not merely cautious. An allowlist has
  nothing to put in it until a create trigger exists.
- **But discovery is incidental, not designed.** All four writes are the *runtime's* behaviour, not
  the container's: `oom_score_adj` and the two sysctls are Docker defaults, and the AppArmor label
  write needs an enforcing LSM. Reliable on Docker + Ubuntu; guaranteed by nothing. A runtime that
  performs none of them leaves a container undiscovered until its workload opens a regular file for
  writing.
- **My claim that a "quiet container cannot exist" was wrong**, and so was the prediction it
  replaced. The honest statement is narrower: *on this runtime*, a container's startup always emits
  qualifying events before it can be mapped, so the escalation path always fires. That is an
  observation about runc, not an invariant of this design — which is exactly why
  [10](10-container-instances-delta-plan.md)'s Phase 0 and its reconciliation floor still matter.

One incidental measurement from the same trace: **the agent's own writes are events too.** The
diagnostic logged to `ossec.log`, whose write-intent open is itself an event, which logged again —
2.3 M lines in 22 s before the loop was capped. Excluding the agent's own paths, the idle node
produced 17 host events in 20 s. The loop was an artefact of the instrumentation, but the underlying
fact is not: with `cgroup filter off`, everything the agent writes traverses the router.

### What the same run did find

Looking for the wrong defect found two real ones, both of which needed a running agent:

- **[C27](03-findings-correctness.md#c27--a-path-reconcile-deletes-the-rest-of-the-containers-rows)'s
  actual cost.** §12.15 had it as a row-count fact (6 → 1). Measured at the alert level it is worse:
  only the *first* modification per container is reported as a modification, every later one arrives
  as `added` with no `changed_fields`, and no `deleted` alert is raised for the rows that vanish.
  Fixed in `d3a8e394d9`; D18 records the choice; C27 carries both before-and-after tables.
- **[C28](03-findings-correctness.md#c28--with-no-containers-list-reads-as-connector-unavailable)** —
  `list` omitted the `containers` key when the list was empty, and the client reads a missing key as
  "connector unreachable". A healthy host with no containers was therefore indistinguishable from a
  dead connector, so the stale-row sweep never ran there and both consumers logged a fault that was
  not occurring. Fixed, `7e059dd5aa`, with the negative control kept: a socket that is present but
  answers nothing still suppresses the sweep, because only the meaning of "empty list" changed.
- **[C16](03-findings-correctness.md#c16--dockers-deferred-reconcile-is-dropped-not-deferred) is
  worse than "masked by the rescan".** Chasing C28's test found that a container removed with
  `docker rm -f` was still returned by `list` **two minutes on**, well past `REMOVAL_GRACE = 60 s`:
  the grace is evaluated only inside `applySnapshot()`, and on the Docker path nothing calls that
  again without another event. An unrelated `docker run --rm alpine true` produced one, and `list`
  emptied within seconds. The periodic rescan masks C16's missed *create*; nothing masks the missed
  *expiry*, so on an idle host a removed container's rows are never swept by either consumer. That
  promotes Phase 0 of [10](10-container-instances-delta-plan.md) from "prerequisite for item 20" to
  a fix the current design needs on its own.

### The methodological note worth keeping

C27 stayed invisible through a full end-to-end run, six contract-test cases and a static review
because **the damage was uncommitted**. DBSync holds one long-lived sqlite transaction and a path
reconcile never commits it, so `sqlite3` showed five healthy rows while DBSync's own view was down to
one; forcing the commit with a `SIGTERM` is what exposed it. And a restart re-inserts the missing rows
silently, so any test that restarts the agent between steps sees a clean database.

Two rules follow for anything else in this feature that writes through DBSync outside a
`deleted_rows` path: **an external read of `fim.db` proves nothing while `fim.db-journal` exists**,
and a step sequence that includes a restart cannot be used to check convergence.
