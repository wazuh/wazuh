# 13 — Plan: a per-container entry point in `container_baseline`'s C API

Status: **implemented in `ed24a606ce`.** Prerequisite for the reconcile consumer
([12 §12.11](12-blocking-decisions.md)). Written against `ba8c642007`.

## 13.0 Outcome

All five steps done. Two things landed differently from the plan, both smaller:

- **Step 0 answered from the code, not by experiment.** `rootfs_file_walker.cpp:210` already handles a
  non-directory `internal_path` with an explicit `emitLeaf()` and an early return, at any recursion
  level. The shortcut in §13.2 holds, and `RereadingOneFileEmitsExactlyOneRow` now pins it so it
  cannot regress silently.
- **`TranslatePaths()` needed a `keep_unusable` flag.** Not in the plan, and found while wiring the
  shim: it silently skips entries whose `internal_path` is null or empty. Harmless for config-sourced
  paths, but on this entry point it would let a caller ask for three paths, receive rows for two, be
  told the scan was complete, and delete the third's stored rows — the same false-delete the guard
  exists to prevent, arriving one layer up.

18 new tests, suite 164 → 182 (181 pass, 1 skipped, unchanged). Four mutations checked, each failing
four tests: dropping the path guard, reporting success for a fully-rejected path set, not forcing
`partial` on a rejection, and dropping the container filter.

**Known gap:** the `extern "C"` shim's own guards have no permanent test, because this module has no
C-API test target and inventing one was outside this plan. They were verified ad hoc — null socket
→ `-1`, null and empty container id → `0`, unreachable socket → `-1` end to end through
`DiscoverContainers()`. Worth a target if the C surface grows further.

**Not measured yet:** the `/proc` sweep cost in §13.6. `ResolvePidsForContainer()` shipped as planned
because it is correct and already tested; whether it needs the `cgroup.procs` optimisation is still
an open question that only a re-walk storm on a real node will answer.

## 13.1 What the consumer needs, and what exists

`container_reconcile_plan.hpp` produces three actions. Two of them have no entry point today:

| Mode | Needs | Exists? |
| --- | --- | --- |
| `rebaselineAll` | walk every container | yes — `cbaseline_run_fim_dbsync()` |
| `rewalkContainer` | walk **one** container, all configured paths | **no** |
| `rereadPaths` | re-read **specific paths** in one container | **no** |

`cbaseline_run_fim_dbsync()` walks every container the connector reports, over every configured
`<directories tags="container">` entry. There is no way to ask it for less.

## 13.2 The finding that halves this work: one new export, not two

`rereadPaths` looks like it needs a new "stat these files" capability. It does not.

`cb_monitored_path_t.recursion_level` already documents `0 = entry only`, and
`WalkContainerPath(pid, internal_path, recursion_level, max_files, max_hash_bytes, …)` is rooted at an
arbitrary `internal_path`. So "re-read `/etc/passwd` in container X" is the *existing* walk, called
with `internal_path = "/etc/passwd"` and `recursion_level = 0`.

The two modes are therefore the same call with different arguments — the caller supplies either the
configured monitored paths (re-walk) or one zero-recursion path per staged path (re-read). **One new
export, parameterised by its `paths` argument.**

> **Verify first (step 0).** The walker is documented as producing "a `FileBaselineRow` per regular
> file / symlink **found**" by recursing into `readdir()` results. Whether it emits a row when
> `internal_path` is itself a *file* rather than a directory is not stated and decides whether this
> shortcut holds. If it does not, that is a small fix inside `rootfs_file_walker.cpp`, not a new API —
> but it must be established before the rest of the plan is built on it.

## 13.3 The orchestration seam already exists too

```cpp
int RunFimDbsyncBaselineFrom(const ContainerDiscoverer& discover,   // <- returns the containers
                             const PidIndex&            pids,       // <- and their live PIDs
                             const std::vector<MonitoredPath>& paths, …);
```

`ContainerDiscoverer` is a `std::function` seam added so the orchestrator could be tested without a
connector. A one-element discoverer plus a one-container `PidIndex::FromMap()` *is* a per-container
run. **No new orchestration logic, no new row-emission logic, no new transaction logic** — the
per-container loop, the `SelectAddressablePid()` retry, the `partial` accounting and the status
callback all apply unchanged.

## 13.4 Proposed C API

```c
/* Baseline ONE container's FIM files, over the paths the caller supplies.
 *
 * Returns  1  the container was baselined (had a live, addressable PID);
 *          0  known to the connector but not baselined (stopped, no resolvable PID);
 *         -1  the connector could not be reached, or answered malformed.
 */
EXPORTED int cbaseline_run_fim_dbsync_container(const char*                connector_socket_path,
                                                const char*                container_id,
                                                const cb_monitored_path_t* paths,
                                                int                        path_count,
                                                cb_dbsync_row_sink_t       sink,
                                                cb_container_status_sink_t status_sink,
                                                cb_rate_limit_fn           rate_limit,
                                                void*                      user_data);
```

### Why the return value is not just a count

`cbaseline_run_fim_dbsync()` returns "how many were baselined" and therefore **cannot express
`unreachable`** — 0 means both "nothing to do" and "I could not ask". For the whole-node walk that is
survivable because `cbaseline_list_containers()` carries the reachability signal separately, and its
contract is emphatic about it (`-1`, and callers "MUST check for -1 before using this list to
authorise deletions" — the [C15](03-findings-correctness.md) fix).

For a single container the same distinction decides the same thing, with no list call to lean on:

- `1` — walked. Delete detection is legitimate **if** the scan is also reported complete.
- `0` — the container exists but is stopped. Its stored rows must be **kept**.
- `-1` — we do not know anything. Its stored rows must be **kept**.

Collapsing `0` and `-1` would reintroduce C15 one container at a time: a connector blip during a
reconcile would look exactly like "this container has no files any more". So the tri-state is not a
nicety, it is the whole safety property, and it should be in the signature rather than in a separate
call the caller might forget.

## 13.5 Security: per-path mode breaks an invariant the walker currently relies on

`rootfs_file_walker.hpp` states plainly:

> `..`-escaping is impossible by construction: this walks by recursing into directory entries returned
> by `readdir()`, never by resolving a caller-supplied path containing `..`.

**Per-path mode resolves a caller-supplied path.** Worse, in this consumer the path originates in an
eBPF event, and the process that produced that event is *inside the container* — so the path is
attacker-influenceable. A container that creates `/etc/../../../../root/.ssh` and touches it would,
with a naive implementation, have the agent resolve that under `/proc/<pid>/root/` and hash whatever
it lands on, attributing host content to the container.

The mount-boundary guard already in the walker (crossing devices only into destinations the OCI mount
list declares, never into a mount whose source is the host root) is a second line, but it is defending
against a different threat and should not be the only one.

Required, in order of where it belongs:

1. **The consumer prefix-filters** staged paths against the configured monitored paths before they
   ever reach this API. That is needed anyway to discard the [C22](03-findings-correctness.md)
   host-form paths.
2. **The API rejects** any `internal_path` that is not lexically absolute and normalised — no `..`
   component, no `.` component, no empty component. Defence in depth, and cheap: a string check before
   any syscall. A rejected path should count as `partial` for that container rather than being
   silently dropped, so the gap is visible.

This is the single most important thing in this plan and it does not exist in any form today.

## 13.6 Implementation steps

| # | Step | Where | Size |
| --- | --- | --- | --- |
| 0 | Establish whether a zero-recursion walk of a *file* emits a row | `rootfs_file_walker` + a test | small; blocks 3 |
| 1 | Path validation helper (absolute, normalised, no `..`) + tests | `container_baseline_impl` | small |
| 2 | `RunFimDbsyncBaselineForContainer()` on the existing `*From` seam | `container_baseline_scanner.{hpp,cpp}` | small |
| 3 | `extern "C"` shim reusing `TranslatePaths`/`MakeRowSink`/`MakeStatusSink` | `src/container_baseline.cpp` | trivial |
| 4 | Declaration + contract docs, incl. the tri-state return | `include/container_baseline.h` | trivial |
| 5 | Tests through the `*From` seam — no connector, no containers | `tests/container_baseline_scanner_test.cpp` | medium |

### Step 2 in detail

Two sub-problems, each with a cheap-but-wrong option worth naming:

**Discovery — how to get one container's `ContainerIdentity`.** The client's `resolve` op is keyed by
`cgroup_id`, which this API does not take. Reuse `DiscoverContainers()` and filter by id instead: it
is still one IPC round-trip (the `list` reply already carries each container's full record), and it
keeps the reachability, warm-up and quiescence handling in exactly one place rather than growing a
second copy that will drift. The cost is that a 100-container node ships 100 records per reconcile.
Acceptable to start; if it shows up, the fix is an optional `cgroup_id` argument enabling a targeted
`resolve`, not a second discovery path.

**PIDs — `PidIndex` for one container.** `ResolvePidsForContainer()` exists but performs its own full
`/proc` sweep, so a 2,000-process node pays ~2,000 `/proc/<pid>/cgroup` reads *per reconcile batch*.
That is the one genuine performance risk in this plan, and under a re-walk storm it is per container
per batch. The cheap fix is to read `/sys/fs/cgroup/<path>/cgroup.procs`, which lists a cgroup's PIDs
directly in one file read — but it needs the cgroup *path*, and the consumer holds the cgroup *inode*.
Recommendation: ship `ResolvePidsForContainer()` first because it is correct and already tested, and
**measure it** before optimising; note that `cgroup.procs` is the known answer if the measurement says
it matters.

## 13.7 What this deliberately does not do

- **No `rebaselineAll` entry point.** `cbaseline_run_fim_dbsync()` already is one.
- **No syscollector equivalent.** The eBPF consumer is FIM-only; `RunSyscollectorDbsyncBaselineFrom()`
  has the same seam if that changes, and the same tri-state return argument would apply.
- **No delete-detection logic.** It stays where it is, in syscheckd's `ScopedContainerTxn`. This API
  emits rows and reports completeness; whether that authorises deletion is
  [D15](12-blocking-decisions.md), enforced caller-side by `ReconcileRequest::may_detect_deletions`.
  Keeping the decision out of this module is deliberate: `container_baseline` has two consumers (FIM
  and syscollector) with different delete semantics, and it has never been the one to decide.

## 13.8 Compatibility

Additive only: one new exported symbol on `libcontainer_baseline.so`, no change to any existing
signature or behaviour. `EXPORTED` (`__attribute__((visibility("default")))`) is already applied to
every entry point in `container_baseline.h`.
