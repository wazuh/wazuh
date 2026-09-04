# #37533 — Startup race solutions and additional edge cases

Follow-up to [container-fim-syscollector-test-plan-and-results.md](container-fim-syscollector-test-plan-and-results.md)'s
finding #2 (FIM's one-shot container baseline can miss a container that's already running, if
`container_instances`' relevant connector is still warming up). This is an **analysis of solution
options**, not an implementation — nothing here has been coded or tested.

## The problem, precisely

`RunFimBaseline()` (and every other `Run*Baseline()`) calls `DiscoverContainers()`
(`container_baseline_scanner.cpp:143-176`), which calls `client.listContainers()`. The existing
retry logic:

```cpp
constexpr int kListRetryAttempts = 10;
constexpr auto kListRetryDelay = std::chrono::milliseconds{500};
std::atomic<bool> g_everSawContainers{false};
...
const int attempts = g_everSawContainers.load() ? 1 : kListRetryAttempts;
for (int attempt = 1; attempt <= attempts; ++attempt) {
    refs = client.listContainers();
    if (!refs.empty() || attempt == attempts) break;
    std::this_thread::sleep_for(kListRetryDelay);
}
if (!refs.empty()) g_everSawContainers.store(true);
```

only retries when the list comes back **completely empty**. A list that's non-empty but
*incomplete* — e.g. the Kubernetes connector's watch is already warm and returns 3 pods, but the
Docker connector hasn't finished its initial `docker ps`-equivalent enumeration yet — is accepted
immediately as final. This was confirmed directly this session: killing and restarting only
`wazuh-syscheckd` (leaving an already-warm `container_instances` untouched) took the FIM baseline
from 3 containers to the correct 4, with nothing else changed.

A second, related detail: **`g_everSawContainers` is a process-lifetime latch, never reset.** Once
any call has seen a non-empty list, every subsequent call — including the recurring syscollector
baseline scan, and any call after `container_instances` itself restarts mid-agent-life (crash,
OOM-kill, manual restart) — gets exactly one attempt with no retry at all, even on a list that's
empty or partial because the module is warming back up. The window is much narrower after the very
first successful list (a live agent almost certainly polls again long after any restart settles),
but the mechanism itself doesn't distinguish "first-ever list" from "list right after the connector
restarted."

## Solution options

### Option A — connector-readiness signal from `container_instances`

Have `container_instances` track, per connector (Docker, Kubernetes), whether its initial
enumeration has completed, and expose that in its `status` reply (`wire_protocol.hpp`'s `status`
op already returns `data.connector`/`data.records`/`data.pending` for one connector — there's no
"ready" boolean today). `DiscoverContainers()` would then poll `status` first and wait (bounded,
like the existing `fim_container_baseline_available()` socket-wait pattern: 5s total, 200ms poll)
until all *configured* connectors report ready, before calling `list`.

- **Pro**: architecturally correct — "is this connector done warming up" is a fact `container_instances`
  actually knows and a consumer currently has to infer from list contents.
- **Con**: a real cross-module change — touches `container_instances`' internal connector state
  tracking, its wire protocol (`wire_protocol.hpp`, `query_types.hpp`), and the client library
  (`container_instances_client.hpp`), not just the baseline scanner. Not a one-file fix.

### Option B — extend the existing retry to detect a still-growing list

Keep the existing empty-list retry, and add: if two consecutive polls return a **non-empty but
different-sized** list, treat that as "still warming" and retry (bounded, reusing
`kListRetryAttempts`/`kListRetryDelay`) until two consecutive polls agree, or attempts run out.

```cpp
// sketch, not implemented
std::vector<ContainerRef> refs, prev;
for (int attempt = 1; attempt <= attempts; ++attempt) {
    refs = client.listContainers();
    bool stable = !refs.empty() && refs.size() == prev.size();  // crude size-based quiescence check
    if (stable || attempt == attempts) break;
    prev = refs;
    std::this_thread::sleep_for(kListRetryDelay);
}
```

- **Pro**: self-contained to `container_baseline_scanner.cpp`, no protocol change, and follows the
  same philosophy the existing empty-list retry already uses (bounded, opt-out once "settled").
- **Con**: heuristic, not authoritative — a size-based quiescence check can't distinguish "still
  warming up" from "a container legitimately started or stopped between polls," and a genuinely
  slow connector could still exceed the bounded retry window. A content-based comparison (same IDs,
  not just same count) would be slightly more robust than size alone but no more authoritative.

### Option C — lazy per-container catch-up baseline from the live path

When the live path (`fim_handle_container_whodata_event()`) resolves a `container_id` that has zero
existing rows in `file_entry`, trigger a one-time walk of the configured container-tagged
directories for *that specific container* (reusing `WalkContainerPath()`, already used by the
baseline) before or alongside persisting the triggering event, rather than relying on the
process-wide one-shot baseline to have already covered it.

- **Pro**: closes *two* related gaps at once — this session's finding #2 (startup race) and part of
  finding #4's residual gap (a container that starts *after* the agent, and is never touched by
  the one-shot baseline, previously only got files added to state by live writes *after* the
  container started — a file present unchanged since container start would stay invisible forever).
  A first-sight catch-up walk means *any* newly-encountered container gets its full existing state
  captured, regardless of why the baseline missed it.
- **Con**: doing a directory walk on the container-event consumer thread would violate the "never
  block on IPC/slow work here" principle the queue split was built for — this would need its own
  thread (mirroring how `ebpf_pop_container_events` already keeps IPC off the ring-buffer thread),
  plus de-duplication so a burst of events for the same brand-new container doesn't trigger the
  walk multiple times concurrently.

### Option D — fixed startup delay before running the baseline — rejected

Simplest to write, but a magic-number timeout can't be right for every environment (a busy node's
Docker daemon may take longer than a fixed delay; a quiet one wastes the wait every time), and it
does nothing for the `container_instances`-restart-mid-life variant of the same problem. Not
recommended.

## Recommendation

**B** is the smallest, most self-contained fix and directly closes this session's finding #2 with
no cross-module changes — reasonable as an immediate fix. **C** is the more complete answer (it
also subsumes the "started after agent" half of finding #4) and is worth doing as a follow-up
regardless of whether B lands, since it's the only option that also covers containers that live
their entire life without ever being caught by *any* periodic/one-shot baseline pass. **A** is the
architecturally "correct" fix but is a bigger, cross-module piece of work — worth proposing to
whoever owns `container_instances` rather than doing informally as a syscheckd-side workaround.

## Implementation status

**B and C are now implemented** (A was not — see above for why it's a bigger, separate piece of
work):

- **B**: `container_baseline_scanner.cpp`'s `DiscoverContainers()` now has a second, independent
  retry loop (`g_containersStable`/`kQuiescenceRetryAttempts`) that runs after the existing
  empty-list retry, comparing the *set* of container ids (not just the count) across consecutive
  polls, and only latching "stable" once two consecutive polls agree. Bounded at 5 extra attempts
  (2.5s) and — like the pre-existing `g_everSawContainers` latch — paid at most once per process
  lifetime once quiescence is actually observed.
- **C**: `container_live_fim.cpp` gained `container_has_existing_rows()` (a `LIMIT 1` query scoped
  to the resolved `container_id`), `catch_up_container_baseline()` (walks every configured
  container-tagged path via `WalkContainerPath()` — the same function the real baseline uses — and
  persists the results through a scoped, non-alerting transaction, mirroring
  `container_baseline_fim.cpp`'s own `sync_container()`), and `maybe_catch_up_container_baseline()`
  (the dedup + detached-thread wrapper, called from `fim_handle_container_whodata_event()` right
  after `container_json` is built). This required adding
  `container_baseline/container_baseline_impl/include/` to `syscheckd/src/ebpf/CMakeLists.txt`'s
  include path and switching from a hand-declared `ResolvePidsForContainer()` forward-declaration to
  including `pid_resolver.hpp`/`rootfs_file_walker.hpp` directly — `WalkContainerPath()` returns
  `FileBaselineRow`/`WalkResult` *by value*, and a hand-duplicated struct layout that drifted from
  the real one would corrupt memory rather than fail to link, unlike `ResolvePidsForContainer`'s
  plain `vector<pid_t>`/`string` signature.

**Verified on real infrastructure** (after the `wazuh_manager` VM came back — it had gone
unreachable partway through this work, `ssh: connect to host ... No route to host`, and turned out
to have rebooted, which conveniently also gave a clean re-test of the whole startup sequence):

- **B**: confirmed the baseline now reports the correct container count on a fresh restart once
  `my-nginx` was running again (4, matching reality, vs. the 3 seen pre-fix in the original
  finding). Not isolated from natural warm-up timing as cleanly as the original finding-#2
  reproduction (restarting only `wazuh-syscheckd`) was, but consistent with the fix working.
- **C**: this is where the real verification effort went, because the first attempt at C had a
  real bug of its own, found and fixed through the same build-deploy-observe loop as everything
  else in this session:
  - **First attempt** ran the catch-up walk on a **detached thread** (to avoid blocking the
    container-event consumer thread). Walked correctly (504 files logged for `my-nginx`, 9 for a
    fresh test pod), but only 1-2 rows actually persisted to `fim.db` — the rest silently lost.
    Root cause: this ran *concurrently* with the triggering event's own
    `upsert_container_file_row()` on a different thread, both opening a scoped `file_entry`
    transaction for the *same* `container_id` at nearly the same time.
  - **Fix**: made the catch-up walk run **synchronously** on the caller's thread instead. Safe to
    do because `fim_handle_container_whodata_event()` (the only caller) already runs on a single
    dedicated consumer thread (`ebpf_pop_container_events`) — there is no cross-thread concurrency
    to worry about for this function specifically, only the concurrent-transaction case above. This
    dropped the mutex/dedup-set/detached-thread machinery entirely.
  - **Still broken after that fix** — a *second*, independent bug: even single-threaded, a
    9-file catch-up only persisted 1 row. Root cause: the hand-built row JSON never included a
    `checksum` field, which `file_entry.checksum` requires (`NOT NULL`) — the real baseline's own
    row-sink (`dbsync_sink()` in `container_baseline_fim.cpp`) computes this
    (`fim_compute_row_checksum()` over the row's own JSON dump) before persisting, and the
    single-triggering-file code path elsewhere in this same file already did the same; the
    catch-up walk's row-building code just never did.
  - **Fixed** by computing and adding `checksum` the same way. Verified end-to-end afterward on
    three separate fresh Kubernetes test pods (busybox, `/etc` walks of 9 files each) — all 9 files
    correctly persisted every time, including the file that triggered the catch-up in the first
    place.

## Other edge cases to take into consideration

- **The `g_everSawContainers` latch never resets on a `container_instances` restart.** If the
  module crashes/OOMs/gets manually restarted while `wazuh-syscheckd` keeps running, the *next*
  `DiscoverContainers()` call gets exactly one attempt (no empty-list retry either), because the
  latch was already set true from before the restart. Any fix to the startup race should also
  reset (or otherwise account for) this case — a module restart is functionally the same "cold
  connector" situation as agent startup, but the current code can't tell the difference.

- **PID/cgroup reuse (TOCTOU) on the live path.** `fim_handle_container_whodata_event()` checks
  `access("/proc/<pid>")` for liveness, then (if alive) builds `/proc/<pid>/root/<path>` from that
  same PID. Between the liveness check and the actual `lstat`/hash, the kernel could in principle
  have recycled that PID number to a *different*, unrelated process (container exits, PID reaps,
  a new process — possibly in a different container or the host — gets the same number very
  quickly). This is a narrow window and wasn't observed this session, but nothing currently
  verifies the PID still belongs to the *expected* container_id at the point of use, only that
  *some* process holds that PID number. A stronger check would re-derive the container_id from
  `/proc/<pid>/cgroup` at resolution time and compare it against the `container_id` already in
  hand, matching the technique `ExtractContainerIdFromCgroupPath()` already implements for the
  baseline's own `ResolvePidsForContainer()`.

- **Short-lived containers (e.g. a Kubernetes Job) that start and exit within one baseline/poll
  interval.** If a container's entire lifetime is shorter than the time between polls, neither the
  one-shot baseline nor Option B's retry window nor the recurring syscollector scan would ever see
  it — only the live path could, and only if its file events happen to be processed (not dropped
  under queue pressure) before the container exits. Option C (catch-up walk on first live sight)
  narrows this but doesn't eliminate it — the walk still needs a live PID to address the rootfs
  through, which a fully-exited container no longer has.

- **A container name/identity reused by a brand-new container with a different container_id**
  (common in Kubernetes: a Deployment's pod is replaced, same name pattern, new pod UID and
  container_id). The old container_id's `file_entry` rows have no mechanism to be cleaned up
  outside of the next baseline's own scope+`deleted_rows` reconciliation sweep for that specific
  container_id — already flagged in `requirements-analysis.md` as "deletion propagation... not
  implemented." Worth calling out again here because it interacts with the startup-race fixes
  above: whichever option is chosen should make sure it doesn't *also* need to positively identify
  "this container_id is gone for good" (a different, harder problem than "this container_id was
  just slow to appear").

- **File hashing surviving a delete-mid-hash race.** Checked this session:
  `OS_MD5_SHA1_SHA256_File()` returns `-1` on a failed `fopen`, and both the baseline
  (`rootfs_file_walker.cpp`) and the live path (`container_live_fim.cpp`) already treat a non-zero
  return as "no hash available" rather than a fatal error — a file that disappears between the
  `lstat()` that discovers it and the hash attempt degrades gracefully to a hash-less row rather
  than crashing or blocking. No action needed, noted for completeness since it's directly adjacent
  to the races above.

- **An unexplained duplicate log line, observed but not root-caused this session.** Every real
  test write this session produced *two* identical `handle_event: container-candidate path=... 
  cgroup_id=... pid=...` routing lines in the log, but only *one* set of downstream
  `fim_handle_container_whodata_event()` processing lines (entry/fallback/proceeding/alert-sent).
  This could be: two genuinely distinct kernel events for one logical write (e.g. an implicit
  attribute change alongside the open), a single kernel event somehow delivered to `handle_event()`
  twice, or a logging artifact — the temporary trace added this session didn't log the event
  *type*, so the three explanations can't yet be distinguished from the log alone. Worth adding
  `ev->event_type` to the routing trace before trusting event counts/dedup behavior on this path
  for anything volume-sensitive (e.g. the container queue's full/drop accounting).

- **cgroup-v1 hosts and `hostNetwork`/`hostPID`/`cgroupns=host` pods** — already documented in
  [volume-type-behavior-matrix.md](volume-type-behavior-matrix.md)'s cross-cutting caveats section;
  repeated here only as a pointer, since they're the same category of "correlation key doesn't
  mean what the code assumes" problem as the PID-reuse point above, just for `cgroup_id` instead of
  `pid`.
