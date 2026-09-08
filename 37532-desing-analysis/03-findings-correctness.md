# 03 — Correctness findings

Ordered by severity. Each finding names the mechanism, the concrete failure, and the fix.

---

## C1 — FIM deletes the state of merely *stopped* containers (false DELETE storm)

**Severity: high.** `container_baseline_fim.cpp:163-182`

The stale sweep compares the FIM database against `container_rows` — the set of containers that
**produced rows in this scan** — and emits `DELETED` for every row of every container not in it:

```cpp
for (const auto& stale_id : db_container_ids) {
    if (container_rows.find(stale_id) == container_rows.end()) {
        sync_container(stale_id, {});   // empty rows → all existing rows become DELETED
    }
}
```

A container produces no rows whenever `ResolvePidsForContainer` returns empty
(`container_baseline_scanner.cpp:308`: `if (pids.empty()) continue;`) — i.e. when it is **stopped but
still known**, restarting, or racing a PID exit. It also produces no rows when the monitored path
doesn't exist in that image (`WalkResult::root_missing`) or when `max_files` truncated the walk to
zero.

The module's own C header warns against exactly this, and exports an API to prevent it:

```c
/* Lists every container currently known to the container-connector module —
 * including a container that is momentarily stopped (known, but no live PID) …
 * Callers that need to tell "stopped" apart from "gone" … should compare this
 * list against the run_* functions' output instead of treating "absent from a
 * scan" as "removed". */
EXPORTED int cbaseline_list_containers(...);
```

`cbaseline_list_containers` is **never called from syscheckd**. The Syscollector side calls it and
gets this right (`syscollectorImp.cpp:1975-1996`); FIM does not.

**Effect:** a container restart produces a full `DELETED` sweep of its FIM state, then a full
re-`CREATE` on the next agent start — a false-positive alert flood on exactly the event a security
product must report accurately.

**Fix:** call `cbaseline_list_containers` and sweep only ids absent from *that* set, mirroring
`syscollectorImp.cpp:1987-2020`. Additionally propagate `WalkResult::root_missing` / `truncated`
(currently discarded, see C6) so a partial scan can never be mistaken for an empty one.

---

## C2 — Truncated hashes are emitted as if they were whole-file hashes

**Severity: high.** `hash_helper.cpp:61-86`, `rootfs_file_walker.cpp:92-99`

`HashFile` stops reading at `max_bytes` (default 100 MiB) and then finalises the digests anyway:

```cpp
while ((n = std::fread(buf, 1, sizeof(buf), fp)) > 0) {
    if (max_bytes != 0 && total_read + n > max_bytes) { n = max_bytes - total_read; ... }
    EVP_DigestUpdate(...);
    total_read += n;
    if (max_bytes != 0 && total_read >= max_bytes) break;
}
...
out.sha256 = ToHex(sha256_digest, sha256_len);   // digest of a PREFIX, labelled as the file's hash
```

The row is then stored in `hash_sha256` with nothing marking it as partial. Two consequences:

1. **It will never match** the hash any other tool — or Wazuh's own host-side FIM — computes for that
   file. The spike's acceptance criterion is "hash matching an in-container oracle"; for any file
   >100 MiB this silently fails.
2. **It collides.** Two different 200 MiB files sharing their first 100 MiB produce identical
   `hash_md5`/`sha1`/`sha256`. A change beyond the cutoff is undetectable — a tamper-evasion
   primitive in a file-integrity feature.

**Fix:** on truncation, leave the hash fields **empty** and set an explicit
`hash_truncated`/`partial` marker, exactly as FIM's host path treats files above its size limit.
Never emit a prefix digest in a field named `hash_sha256`.

---

## C3 — `tags="container"` only matches when it is the *only* tag

**Severity: high (silent feature no-op).** `container_baseline_fim_bridge.c:157-212`

```c
if (path == NULL || path->path == NULL || path->tag == NULL ||
    strcmp(path->tag, "container") != 0) {
    continue;
}
```

Wazuh's `<directories tags="...">` attribute is a **comma-separated list**. A perfectly ordinary
configuration —

```xml
<directories tags="container,prod" recursion_level="3">/etc</directories>
```

— fails `strcmp` and the directory is silently skipped. The user gets no container FIM baseline, no
warning, and no way to tell why. The whole feature no-ops.

**Fix:** tokenise on `,` and compare each token (trimmed). Better: introduce an explicit attribute
rather than overloading the free-form `tags` field, since "container" is now load-bearing
configuration rather than a label. Note the header still documents a
`<directories type="kubernetes">` syntax (`container_baseline.h:53-54`) that no longer exists.

---

## C4 — `hostNetwork` / `hostPID` collapse is undetected: host state attributed to a container

**Severity: high.** `network_scanner.cpp:175-198`, `process_scanner.cpp:119-165`,
`interface_scanner.cpp:117-147`

The issue asks explicitly to *"confirm namespace scoping is reliable … under `hostPID`/`hostNetwork`
(K8s) / `--pid=host`/`--network=host` (Docker), where scoping collapses to the host."* Nothing in the
module checks for it.

- **Ports:** `ScanContainerNetwork` reads `/proc/<representative-pid>/net/tcp`. With
  `--network=host`, that file *is* the host's socket table. Every listening socket on the node is
  emitted as a row belonging to that container.
- **Interfaces:** `SameNetns(pid)` returns true for a host-network container, so
  `CollectCurrentNetns()` runs and reports **the host's** interfaces, MACs, and byte counters as the
  container's — including per-container duplicates of the host's inventory for every such container.
- **Processes:** scoping is by cgroup, which does *not* collapse under `hostPID`, so processes are
  actually safe. But the inverse now holds: with `hostPID` the container can *see* host processes that
  the baseline will not report, so the "complete state" promise is broken in the other direction.

**Effect:** on a node running any host-network DaemonSet (extremely common — CNI agents, node
exporters, ingress controllers), the inventory is polluted with the host's entire network state
duplicated once per such container.

**Fix:** compare `/proc/<pid>/ns/{net,pid}` inode against `/proc/1/ns/{net,pid}`. When they match,
emit **no** container-scoped network/interface rows and record the collapse as a documented
`scope: host` attribute on the container, so the manager can render it correctly instead of being
lied to. `container_instances` already computes closely related verdicts
(`VerdictReason::hostNamespace`, `cgroupnsHost`) and could supply this directly.

---

## C5 — Kubernetes pod-shared netns duplicates every socket across every container in the pod

**Severity: medium-high.** `network_scanner.cpp:186-197`

Containers in a Kubernetes pod share one network namespace. `ScanContainerNetwork` is called once per
container and reads that shared socket table each time, so **the same socket is emitted as a row for
every container in the pod**. The code comments claim otherwise:

```cpp
// Any PID in the container sees the same net namespace (Docker: one per
// container; Kubernetes: shared across the pod but disambiguated here by
// only ever reading files under a PID we've already confirmed belongs to
// this container's cgroup).
```

Reading the file *through* a container-owned PID does not disambiguate anything — the file's contents
are namespace-wide, identical regardless of which PID in the pod is used. The only real
disambiguation is the `BuildInodeOwnerMap` fd→inode join, which is correctly scoped to the
container's PIDs — but sockets whose inode is **not** matched (owned by a sibling container, or by an
exited process) still get emitted, with `process_pid == 0`.

This is precisely the trap #37532 names: *"in Kubernetes the net namespace … is shared across a pod's
containers, so a naive scope attributes all sockets/processes to the pod — disambiguate per container
by cgroup."*

**Effect:** an N-container pod reports each socket N times. A 3-container pod (app + sidecar +
istio-proxy) triples its port inventory. Row ids differ only by `container_id`
(`baseline_rows.cpp:241-243`), so nothing dedupes them downstream.

**Fix:** emit a socket row **only** when its inode resolves to a PID in *this* container's cgroup.
Unattributed sockets belong to the pod, not to any container — model them once at pod scope, or drop
them, but do not multiply them.

---

## C6 — Truncation and missing-path signals are computed, then discarded

**Severity: medium-high.** `container_baseline_scanner.cpp:314-322`

`WalkContainerPath` returns `WalkResult{rows, truncated, root_missing}`. The orchestrator uses only
`rows`:

```cpp
const auto walk = WalkContainerPath(pid, mp.internal_path, mp.recursion_level,
                                     mp.max_files, mp.max_hash_bytes);
for (auto row : walk.rows) { ... }      // walk.truncated and walk.root_missing never read
```

Both `RunFimBaseline` and `RunFimDbsyncBaseline` do this. Consequences:

- Hitting the 20,000-file cap is **invisible** — no log, no metric, no flag on the rows. NFR3 requires
  defined "behaviour at the ceiling (skip + log, partial baseline flagged)".
- A partial walk feeds C1's false-delete path: the files beyond the cap are absent from the row set,
  so on a subsequent scan they are reported `DELETED`. With a non-deterministic `readdir` order, *which*
  20,000 files survive can differ between runs, producing a churning DELETE/CREATE oscillation.

**Fix:** propagate both flags out of the C API, log on truncation, and mark the container's baseline
as partial so the delta engine suppresses deletes for it rather than treating absence as removal.

---

## C7 — UID/GID semantics are inconsistent between data classes, and wrong under user namespaces

**Severity: medium.** `rootfs_file_walker.cpp:84-85` vs `user_scanner.cpp:41-60`

- The file walker records `st_uid`/`st_gid` from a host-side `lstat`. Under a userns-remapped
  container these are **host** ids (e.g. 100000), not the container's view (0).
- The user scanner reads `/etc/passwd` from the rootfs and records **in-container** ids (0 = root).

So `file.uid = 100000` and `user.id = 0` describe the same principal in the same container, in the
same baseline, and nothing reconciles them. `owner`/`group` name fields are deliberately left empty
(`rootfs_file_walker.hpp:25-26`), so there is no name to join on either.

The issue names this trap twice ("UID/GID namespace remapping (userns → owner shown on host differs
from in-container)", "userns-remapped containers — ownership/UID translation").

**Fix:** read `/proc/<pid>/uid_map` and `/proc/<pid>/gid_map` once per container and translate file
ids into the container's id space (the same space `/etc/passwd` uses). Then resolve `owner`/`group`
names by joining against the already-collected user/group rows — cheap, since both are in hand.

---

## C8 — The file walk has no mount-boundary guard and can escape into the host filesystem

**Severity: medium.** `rootfs_file_walker.cpp:107-129`

The walk recurses through every directory entry under `/proc/<pid>/root/<path>` with no check on
`st_dev`. Because `/proc/<pid>/root` presents the container's **full mount namespace view**, the walk
follows bind mounts and volumes wherever they lead. A pod with

```yaml
volumeMounts: [{ name: host, mountPath: /host }]
volumes:      [{ name: host, hostPath: { path: / } }]
```

and a configured monitored path of `/` (or any ancestor of `/host`) will walk **the entire host
filesystem**, hashing it, attributing every file to that container. Node-monitoring DaemonSets mount
`/` exactly like this.

Traversing into mounts is normally the *desired* behaviour (it is how volumes get covered), so this
must be a policy decision, not an accident.

**Fix:** record the root's `st_dev`, and on crossing a device boundary consult the container's
`oci_mounts` — already available in `ContainerContext` and currently **unused by the walker**. Walk
into declared volume mounts; refuse to descend into anything else, and never into a mount whose
source is the host root. Add a total-files-per-container budget on top of the per-path cap.

---

## C9 — Volatile counters in state rows make every periodic scan a full change event

**Severity: medium (design).** `hardware_scanner.cpp:105-116`, `interface_scanner.cpp:87-97`,
`process_scanner.cpp:136-138`

State rows carry monotonically-increasing or constantly-changing fields:

| Row | Volatile fields |
| --- | --- |
| `HardwareBaselineRow` | `memory_used`, `memory_free` (from `memory.current`) |
| `InterfaceBaselineRow` | `rx_bytes/packets/errors/dropped`, `tx_*` (8 counters) |
| `ProcessBaselineRow` | `utime`, `stime` |

Syscollector stamps `row["checksum"] = getItemChecksum(row)` over the whole row and lets DBSync diff
it. Every one of these fields changes between any two scans of a live container, so **every hardware
row, every interface row, and every process row of every container yields a `MODIFIED` event on every
scan interval** — permanently, with no underlying security-relevant change.

This is pre-existing host behaviour, so it is not a regression. But containers multiply it: a node
with 100 containers × (1 hardware + ~3 interfaces + ~200 processes) generates on the order of
**20,000 spurious MODIFIED events per interval**, each carrying a `changed_fields` list of counters,
each re-parsing and re-emitting the duplicated `container_json` blob (see
[04](04-findings-performance.md#p3--the-container-context-blob-is-duplicated-into-every-single-row)).

**Fix:** exclude volatile counters from the change-detection checksum (they belong in a metrics path,
not a state path), or drop them from container rows entirely. This is a decision for #37203-3/-4 and
is exactly the kind of item the missing options matrix should have surfaced.

---

## C10 — Arbitrary PID selection with no liveness strategy

**Severity: medium.** `container_baseline_scanner.cpp:191`, `:311`, `:355`

Every rootfs-addressing data class uses `pids.front()`:

```cpp
const auto pid = pids.front();
```

`ResolvePidsForContainer` builds its vector in `readdir` order, so `front()` is an arbitrary PID, not
the container's PID 1. Problems:

- **Mid-scan death.** If that PID exits during the walk, `/proc/<pid>/root` vanishes and every
  subsequent `lstat`/`open` fails. The walk returns whatever it had, silently — which then feeds
  C1/C6's false-delete path. Short-lived containers and init containers hit this routinely (an
  edge case the issue calls out).
- **No retry**, despite `user_scanner.cpp:92-93` documenting that *"the caller decides whether to
  retry with another PID"*. No caller ever does.
- A short-lived helper process is as likely to be chosen as the long-lived main process.

**Fix:** prefer the lowest PID (closest to the container's entrypoint), verify liveness by holding an
open `O_PATH` fd on `/proc/<pid>/root` for the duration of the scan (which pins the reference), and
fall back to the next candidate PID on failure. Better still: have `container_instances` supply the
PID — it computes it in `proc_cgroup_resolver.cpp` and throws it away (see
[04](04-findings-performance.md#p1--the-proc-sweep-storm-on_containers--n_processes)).

---

## C11 — FIM transaction leaks on exception; DBSync errors are swallowed

**Severity: medium.** `container_baseline_fim.cpp:109-127`, `:45-83`

```cpp
TXN_HANDLE txn = fim_db_transaction_start(txn_str.c_str(), container_txn_callback, &ctx);
if (!txn) return;                                    // silent

for (const auto& row_json : rows) {
    fim_db_transaction_sync_row_json(txn, "file_entry", row_json.c_str());   // return unchecked
}

fim_db_transaction_deleted_rows(txn, container_txn_callback, &ctx);          // return unchecked
```

- `fim_db_transaction_deleted_rows` is the **only** thing that closes the transaction
  (`db.cpp:470-485` calls `dbsync_close_txn` inside it). Any throw between `start` and that call —
  `nlohmann::json` allocation, `std::string` growth — **leaks the transaction handle**. There is no
  RAII wrapper, and no `try`/`catch` anywhere in `fim_run_container_baseline`, so an exception
  propagates into syscheckd's `main()`.
- `DB_ERROR` from DBSync falls into `default: return;` in `container_txn_callback` and is discarded
  without a log. The Syscollector path at least logs it (`syscollectorImp.cpp:241-244`).

The Syscollector side uses the existing `DBSyncTxn` RAII wrapper and `TRY_CATCH_TASK`. FIM should use
the same primitives rather than hand-rolling the lifetime.

---

## C12 — `process.start` is silently dropped in the sync-protocol path

**Severity: low (dead code, but diagnostic).** `baseline_rows.cpp:214`, `process_scanner.cpp:153-158`

```cpp
row.start = Utils::rawTimestampToISO8601(...);   // e.g. "2026/09/02 18:04:11"
...
SetNumericIfDigits(process, "start", row.start);  // requires all-digits → always false
```

`SetNumericIfDigits` returns false for any non-numeric string, so the field is omitted from every
process row — despite the comment asserting `// schema: process.start is 'date' (epoch)`. The
scanner produces ISO-8601 and the serialiser accepts only epoch digits.

This lives in the **dead** `BuildProcessJson` path (no caller in-tree, see
[01](01-work-done.md#14-output-shapes-two-parallel-undecided-paths)), which is why it was never
caught. It is worth recording because it demonstrates that the unused half of the row-builder layer
is not merely redundant but unvalidated — an argument for deleting it rather than maintaining it.

---

## C13 — Dead overlay-whiteout handling signals an unresolved mechanism choice

**Severity: low (cleanliness).** `rootfs_file_walker.cpp:34-37`, `:78`

```cpp
bool IsOverlayWhiteout(mode_t mode, dev_t rdev) {
    return S_ISCHR(mode) && major(rdev) == 0 && minor(rdev) == 0;
}
```

Whiteouts are an artefact of reading overlay **lower/upper layers directly**. Reading through
`/proc/<pid>/root` gets the kernel's already-merged view, in which whiteouts are — by
construction — invisible. The check can never fire, and it has a dedicated unit test asserting
behaviour that cannot occur in production.

Harmless, but it is evidence that the two candidate mechanisms (overlay arithmetic vs. `/proc`
addressing) were partially implemented in parallel and the choice was never written down and
consolidated — the same root cause as the dead `Build*Json` path.

---

## C14 — Smaller items

| Item | Location | Note |
| --- | --- | --- |
| `listContainers` returns containers inside the 60 s removal grace | `metadata_store.cpp:108-127` | `deletedAt` is not filtered, so a just-removed container is still "known" — this *protects* against C1-style deletes but also delays genuine removals by a grace period nobody documented. |
| Last-writer-wins on shared socket inodes | `network_scanner.cpp:66` | `owners[inode] = ...`; a socket shared across forked PIDs is attributed to whichever PID `readdir` returned last. |
| `readlink` buffer 256 B | `network_scanner.cpp:53` | Fine for `socket:[…]`, but silently truncates longer targets rather than reporting. |
| `os_scanner` computes `row.family` then it is dropped | `os_scanner.cpp:82`, `baseline_rows.cpp:318` | `ID_LIKE` parsed and discarded by the serialiser. Dead field. |
| Host `uname()` reported as container kernel | `os_scanner.cpp:84-85` | Factually right (shared kernel) but unlabelled; a reader cannot tell it is the host's. |
| Host CPU model/speed reported as container hardware | `hardware_scanner.cpp:113` | N containers each report the same host silicon, keyed by `serial_number = container_id`. Conceptually questionable as "inventory". |
| `std::stoll` on `/proc/<pid>/stat` fields without guard | `process_scanner.cpp:59-62` | Kernel-generated so well-formed in practice; throws on a malformed read. Caught by `TRY_CATCH_TASK` in Syscollector, uncaught in FIM's path. |
| Symlink target not recorded | `rootfs_file_walker.cpp:90` | `is_symlink` is set but the target is never read, so a symlink repoint is undetectable. |
| IPv4-only default routes | `protocol_scanner.cpp:64-66` | Acknowledged in a `ponytail:` marker comment; IPv6-only containers get no protocol rows. |
| `ponytail:` marker comments | `hardware_scanner.cpp:94`, `protocol_scanner.cpp:64` | Non-standard TODO tag; invisible to normal `TODO|FIXME` tooling. |

---

# Findings added after the initial pass

Found while planning items 20 and 21 (docs [10](10-container-instances-delta-plan.md) and
[11](11-ebpf-provider-import-plan.md)), all verified in the code rather than inferred.

## C15 — An unreachable container connector deleted every container's rows

**Severity: the highest in this document.** Worse than a missed detection: it manufactures
false ones, in bulk, on a healthy node.

Both consumers use the `container_instances` list as the authority on what still exists and
delete the stored rows of every container absent from it. But every failure mode of
`listContainers()` — unreachable socket, unparseable reply, `status != "ok"` — returned an
empty vector, indistinguishable from a node that genuinely runs no containers:

- `DiscoverContainers` collapsed unavailability into an empty vector with no error channel
  (`container_baseline_scanner.cpp:130-163`).
- `ListContainers` returned only a count (`:411-421`).
- Syscollector fed that straight into `sweepContainerRowsNotIn(discoveredIds)` with **no
  availability gate at all** (`syscollectorImp.cpp:2328-2347`).
- FIM's `sweepStale(known)` (`container_baseline_fim.cpp:386-388`) was only partly shielded by
  `fim_container_baseline_available()` (`container_baseline_fim_bridge.c:280-299`), which
  covers up to the moment of its own check and not the query that follows.

So a momentary outage — agent startup ordering, a connector restart, a Docker daemon reload —
deleted every container's rows in every table and re-created them on the next cycle: a mass
false-delete followed by a mass re-insert. The retry loop reduced the window but could not
close it, because an empty result was still returned as authoritative.

Note how close this sits to the *correct* reasoning already in the code: the comment at
`syscollectorImp.cpp:2338` carefully distinguishes "stopped" from "gone" — and never considers
"we could not ask".

**Fixed** in `943a50935f`: an explicit reachability signal is threaded through
`listContainers(bool*)` → `DiscoverContainers` → `ListContainers`/`cbaseline_list_containers`,
which now return **-1** rather than 0 when the connector could not be reached; both consumers
skip the sweep and log it. Retries now continue only while the connector has not answered at
all, since a well-formed empty list is authoritative. Two regression tests pin it — both fail
against the previous behaviour.

## C16 — Docker's deferred reconcile is dropped, not deferred

`m_reconcilePending` is set at `docker_connector.cpp:93` and cleared at `:71` but **never
read** — the Kubernetes connector reads its equivalent at `kubernetes_connector.cpp:142` and
`:195`. So the 500 ms debounce at `:94` *discards* the coalesced reconcile: the last event of
any burst is lost until another event arrives or the event stream reconnects, and there is no
periodic reconcile floor on the Docker path at all.

Under today's full periodic rescan this is masked. Under item 20's baseline-once it becomes
permanent staleness, which is why [10](10-container-instances-delta-plan.md) makes it Phase 0.

### Measured on 2026-09-08: it also strands removed containers in `list`

The masking is weaker than "under today's rescan this is fine" suggests, because the *removal grace*
is evaluated only inside `applySnapshot()` — and on the Docker path nothing calls that again without
another event. After `docker rm -f`, the container was still returned by `list` **two minutes later**,
far past `REMOVAL_GRACE = 60 s`:

```jsonc
// 00:15:42, ~112 s after `docker rm -f cfimquiet`
{"containers":[{"container_id":"ae4da3eb…","container_name":"cfimquiet","cgroup_id":"15677",…}]}
```

Launching an unrelated throwaway container (`docker run --rm alpine true`) produced an event, which
triggered a `reSeed`, which ran `applySnapshot`, which expired the grace — and `list` went to `[]`
within seconds. So on an **idle** Docker host a removed container is reported as existing
indefinitely, and because both consumers treat "still known" as "do not sweep" (correctly — that is
the stopped-vs-gone contract, [C1](#c1--fim-deletes-the-state-of-merely-stopped-containers-false-delete-storm)
and [C17](#c17--docker-containers-stopped-for-more-than-the-grace-period-are-reported-gone)), its FIM
and inventory rows are never cleaned up either.

This makes C16 a **live correctness defect on the current design**, not only a blocker for item 20:
the periodic rescan masks the missed *create*, but nothing masks the missed *expiry*. The Phase 0 fix
— read `m_reconcilePending`, and give the Docker path a reconcile floor — closes both.

## C17 — Docker containers stopped for more than the grace period are reported *gone*

`docker_api_client.cpp:117` queries `/containers/json` **without `all=1`**, so only running
containers come back. Past `MetadataStore`'s 60 s grace window a stopped container is reported
as removed and its rows are deleted.

This contradicts the "a stopped container's rows are left untouched" property stated in
[06 §6.8](06-proposed-architecture.md#68-deletion-semantics-stated-once) row 3 and in
[09](09-implementation-status.md) item 1 — that holds for Kubernetes only. A Docker container
stopped for a minute and then restarted loses and re-seeds its whole baseline.

## C18 — Docker restart-with-a-new-PID is undetectable from `ContainerRecord`

`RestartCount` (`docker_object_parser.hpp:49`) is incremented by the restart *policy*, not by
an explicit `docker restart`; `State.Pid` and `State.StartedAt` are present in the inspect body
but never parsed; and `container_record.hpp:56-74` carries no `pid`, `startedAt` or `state`.

A container that stops and restarts inside the 60 s grace window therefore produces **no delta
at all** (`metadata_store.cpp:148-165` clears `deletedAt`), so a baseline-once consumer would
never re-baseline it even though its rootfs and PID are new. Item 23's re-baseline triggers
need `startedAt` added before they can be correct.

## C19 — Host rows stamp `container_id` *before* the checksum, changing every host row's checksum

`syscollectorImp.cpp:1731-1732` (packages) and `:1879-1884` (processes):

```cpp
rawData[CONTAINER_ID_COLUMN] = HOST_CONTAINER_ID;   // "" — syscollectorTablesDef.hpp:19
rawData["checksum"] = getItemChecksum(rawData);
```

`getItemChecksum()` digests the whole object, so every host package and process row now carries
`"container_id":""` inside its checksum. Against a pre-container agent the same host row hashes
differently, so **every host inventory row reads as MODIFIED on upgrade** — a full re-sync of the
host's packages and processes, on a node with no containers at all.

Swapping the two lines fixes it. The upstream spike already did exactly that in `f6fd510207`
("fix: checksum computation error"), which is one of the 14 commits never integrated onto this
branch ([12 §12.1](12-blocking-decisions.md#121-the-finding-that-reorders-the-roadmap)) — so this
is a bug we still carry and they do not.

## C20 — `container_json` is inside the container rows' checksum, so a label change re-emits every row

`syscollectorImp.cpp:2195-2199` computes the container rows' checksum over the **whole row**, and
that row carries the per-row `container_json` blob (P1 item 17). Any change to a label, an
annotation, or any other field of the container context therefore changes the checksum of *every*
row of that container, in every table — a mass MODIFY of the container's whole inventory in
response to a metadata edit that touched no package, process, port or file.

This is strictly worse than [10 open question 4](10-container-instances-delta-plan.md#1013-open-questions-and-what-i-could-not-verify)
records. That question accepts "stale labels on stored rows" as the cost of doing nothing; in fact
doing nothing costs a re-emit storm instead, because the blob is not merely stored alongside the
row — it is digested into the row's change signal.

Note the same exposure exists in #37534's reconciler, whose `contentHash()` is taken over
`row.json` (`reconcile_types.hpp`). Whichever state model wins
([12 §12.5](12-blocking-decisions.md#125-d1-in-depth--the-two-inventory-state-models)), the container
context must be excluded from the row's change signal — the natural fix being item 17's separate
container dimension row, which removes the blob from the row entirely.

## C21 — A rename inside a container is a deletion no event ever reports

`bpf/rt_file.bpf.c:645-697` (`kprobe__vfs_rename`) builds its path from `new_dentry` and submits a
single `RT_EV_FILE_RENAME` carrying the **destination**. The source path is never named by any
event — not by this one, and not by a later one, since nothing touches the old name again.

So `mv /etc/passwd /etc/passwd.bak` inside a monitored container produces exactly one event, for
`/etc/passwd.bak`. A consumer that reconciles the paths it is given re-reads the new name, stores a
row for it, and leaves the row for `/etc/passwd` describing a file that no longer exists. Nothing
in the pipeline ever corrects it: the next scheduled baseline would, but between baselines FIM
reports a file as present that an attacker has moved away. **A deletion FIM never reports is the
worst failure this consumer can have** — worse than a missed modification, because the stale row
actively asserts the wrong thing.

Note the event is not useless: it carries `inode`/`dev` read from `old_dentry->d_inode`, i.e. the
**source** inode paired with the **destination** path. A consumer storing inodes could find the
stale row that way — but `rt_event_contract.h` documents `inode`/`dev` as diagnostic-only, and FIM's
`file_entry` is keyed by path, so this is not a usable lookup today.

Handled in `container_event_router.hpp` by escalating the container to Suspect on any rename rather
than staging the destination. That is cheaper than it sounds — Suspect is a set keyed by container
in the staging buffer, so a package upgrade renaming a thousand files coalesces into one re-walk,
costing exactly what a single rename costs (`ManyRenamesCoalesceIntoOneReWalk`).

The real fix belongs in the engine: append the source path to `struct rt_file_event`, which ADR-003
makes a MINOR bump (purely additive, old consumers ignore the tail). It is **not free** and should
be measured before being taken — the record grows from 12,416 to ~16,512 bytes, cutting the 8 MiB
ring from ~675 records to ~508 for *every* event class in order to fix one. Whether that trade is
worth it depends on the rename rate a real node sees, which nothing has measured yet.

## C22 — Attribute-change events on a container's rootfs carry a *host* path

Measured on `wazuh_manager` (kernel 7.0.0-30-generic, Docker + containerd, cgroup v2) with a purpose-built
probe printing `dev`/`inode` alongside the path, against throwaway `nginx:latest` containers.

First, the good news, because it is load-bearing for A3 and was verified twice: **`cgroup_id` is the
cgroup directory inode** (40576 and 42418 in two runs, both matching `stat -c %i`), and every event
produced by a process in the container carried it. Attribution by cgroup works.

**Paths are container-absolute for real mounts.** A container was started with a tmpfs at `/data` and a
bind mount of a host directory at `/mnt/host`, then wrote one file in each of its three mount types:

| Write | Events | `dev` | Emitted `path=` |
|---|---|---|---|
| `/tmp/ROOTFSFILE` (overlay rootfs) | 2 | `255`, `8388610` | `/tmp/ROOTFSFILE` (both) |
| `/data/TMPFSFILE` (tmpfs) | 1 | `269` | `/data/TMPFSFILE` |
| `/mnt/host/BINDFILE` (bind mount) | 1 | `8388610` | `/mnt/host/BINDFILE` |

All three render the correct in-container absolute path — including the bind mount, which reports its
container path (`/mnt/host/BINDFILE`) and not its host one (`/tmp/rtbind/BINDFILE`). A prefix filter
against configured `<directories tags="container">` entries is therefore sound for ordinary container
file activity, which is the case that matters.

**The defect is narrower and specific to attribute changes.** A `touch` on the overlay rootfs emits two
events, and the second one names a host path while still carrying the *container's* cgroup:

```
type=ATTR cgroup_id=40576 path=/tmp/RTPROBEMARKER
type=ATTR cgroup_id=40576 path=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/117/fs/tmp/RTPROBEMARKER
```

The hook fires once on the overlay inode and again on the underlying upper filesystem's inode, whose
dentry renders as the host-side snapshot path. Writes (`OPEN`) do not do this — both of their events
carried the correct container path, differing only in `dev` — so this is an `ATTR`-path artifact, not a
general one.

**`dev` cannot be used to filter it out.** The obvious fix is to keep only events whose `dev` matches the
container's rootfs device, but the measurements rule it out: the bind mount reports `dev=8388610`, the
host root filesystem's device — the same device the spurious rootfs duplicate reports. Filtering to the
rootfs device would discard every bind-mounted file, which is legitimate monitored content. `dev` also
disagrees with userspace: `stat -c %d /proc/<pid>/root` returned `24` for a rootfs whose events reported
`255`, so it is not usable as a correlation key without first establishing what it encodes —
consistent with `rt_event_contract.h` documenting `inode`/`dev` as diagnostic-only.

**Consequence for the consumer.** A host-form path only reaches the consumer if it matches a configured
container prefix, which `/var/lib/containerd/...` does only when `/var` itself is monitored. When it
does, it resolves to `/proc/<pid>/root/var/lib/containerd/...`, which does not exist inside the
container — so **the consumer must never infer a deletion from a path it cannot find**.
`container_baseline.h` already mandates exactly that inference ban ("no rows is not removed"); C22 is a
second, independent reason for it, and makes it a hard requirement rather than a caution.

Scope actually measured: one runtime (Docker/containerd), one storage driver (overlayfs), one kernel,
one file per mount type, `OPEN` and `ATTR` only. `UNLINK` on a bind mount and `RENAME` on a tmpfs were
not exercised.

### Correction

An earlier version of this finding claimed paths are rendered relative to their own filesystem's mount
root and are therefore unusable in general, inferring it from container-setup events such as
`/sys/net/ipv4/ping_group_range` (i.e. `/proc/sys/net/ipv4/ping_group_range` with its mountpoint lost).
The follow-up measurement above refutes that: tmpfs and bind-mount paths render correctly with their
mountpoint intact. Those mangled paths come from `runc`/`containerd` during container setup, not from
the container's own file activity, and the general claim was wrong.

---

## C23 — The event-driven re-read can capture a file *before* the write it was triggered by

**Severity: high.** `container_event_drain.cpp:302-316`, `container_baseline_fim.cpp:447-517`,
`rt_event_contract.h:44`

Found by the end-to-end run on `wazuh_manager` (2026-09-07), not by reading the code.

`RT_EV_FILE_OPEN` is documented as "create, or open with write intent" — it fires when the file is
*opened*, before any data reaches it. The consumer takes a batch as soon as one exists
(`nextBatch(batch, 500)` waits for a batch to *be there*, not for the writes to settle) and
`ReconcileBatch` re-reads the staged paths immediately, exactly once. So the reconcile races the write
that produced the event, and when the write loses the race the row it stores is the *pre-write* row.
DBSync then sees no change, and nothing ever looks again.

Demonstrated deterministically by holding the descriptor open and writing late:

```sh
docker exec -d e2e-E sh -c 'exec 3>>/etc/inittab; sleep 8; echo LATE-WRITE >&3'
```

| | size | mtime | sha1 |
|---|---|---|---|
| Baseline row | 570 | 1774381254 | `ce9586d2acf1` |
| Consumer's re-read, 0.4 s after the open event | 570 | 1774381254 | `ce9586d2acf1` |
| The file on disk afterwards | **581** | **1788785146** | — |

No `MODIFIED` was emitted, and no further reconcile followed: the modification is invisible until the
next *scheduled* whole-node baseline. The same staleness was also observed on ordinary
`echo x >> /etc/profile` appends — nondeterministically, since there the write lands within
milliseconds and usually wins.

This is not a variant of C22 or of D15: attribution was correct, the path was in-container, the file
was found, and delete detection was not involved. The reconcile simply read too early.

**Why it matters more than a missed row.** The event-driven path exists to make container FIM timely.
A writer that holds a file open — an editor, a log rotator, a package manager, anything writing a
large file — is exactly the case that loses the race, so the feature silently degrades to periodic
scanning for the writes most worth reporting promptly. And it degrades *quietly*: the stored row is
self-consistent, so nothing marks it as uncertain.

**Fix direction** (a decision, see D16): a trailing re-read. Keep a path whose re-read produced *no*
change in a verify-later set and re-read it once more after a settle delay, emitting the change if it
differs. The provider has no write-completion event to key off — only `OPEN`/`ATTR`/`UNLINK`/`RENAME`
— so the settle delay has to come from the consumer.

---

## C24 — One configured path that is absent from an image suppresses that container's delete detection *permanently*

**Severity: medium.** `container_baseline_scanner.cpp:309`, `container_baseline_fim.cpp:277`

Also found by the end-to-end run. `WalkContainerPath` reports `root_missing` when a configured path
does not exist in the container, which makes the scan `partial`, which makes the driver close the
transaction without delete detection:

```cpp
finishCurrent(m_may_delete && !partial);
```

That gate is right for a *capped* walk or an unreadable namespace: those are transient and the next
cycle may complete. "The image does not contain `/data`" is neither — it is a static property of the
image, so the gate never opens again for that container.

Measured, changing only the configured path list:

| Configured | Rename inside the container | Result |
|---|---|---|
| `/etc`, `/data` (absent) | `mv /etc/motd /etc/motd.renamed` | `CREATE /etc/motd.renamed`, **no delete** — `partial=1` |
| `/etc` only | `mv /etc/issue /etc/issue.moved` | `CREATE /etc/issue.moved` **and `DELETE /etc/issue`** — `partial=0` |

One `<directories tags="container">` list applied across a node's images — the normal way this gets
configured — is enough to disable deletion reporting for every container whose image lacks any one of
those paths, with only a debug line to say so.

**Fix direction** (see D17): report "root path absent" separately from "walk incomplete" in the status
callback, and scope delete detection to the paths that did resolve, rather than abandoning it for the
whole container.

---

## C25 — The `<container_instances>` block is never dispatched, so the module cannot start

**Severity: high (blocker).** `config/src/config.c`, `config/src/wmodules-container-instances.c:205`

Found by trying to run the integrated agent. Every piece of the module was present and compiled —
the XML parser, `WM_CONTAINER_INSTANCES_CONTEXT` with its `main`/`stop`/`dump` routines, and
`container_instances_start()` exported from `libcontainer_instances.so` — but `Read_ContainerInstances()`
had **no caller**:

```console
$ grep -rn "Read_ContainerInstances" --include=*.c --include=*.h src/
src/config/src/wmodules-container-instances.c:205:int Read_ContainerInstances(const OS_XML* xml, xml_node* node, void* d1)
```

`config.c` recognises `wodle`, `sca`, `agent-info` and the rest, but nothing matched
`container_instances`, so the element fell through to the unknown-element path. The module never
entered `modulesd`'s `wmodules` list, never ran, and never bound
`queue/sockets/container_instances`.

That socket is where both consumers get container metadata: `CB_DEFAULT_CONNECTOR_SOCKET_PATH` in
`container_baseline.h`. With nothing bound, container FIM and container inventory were unreachable
from a real agent regardless of what `ossec.conf` said — a `<container_instances>` block was
accepted and silently ignored.

Measured before and after adding the dispatch branch, same `ossec.conf`:

| | `modulesd` log |
|---|---|
| Before | *(nothing — no mention of the module)* |
| After | `INFO: Starting container_instances module.` → `INFO: Enrichment query socket listening at queue/sockets/container_instances` |

With the socket bound, Docker enrichment reaches rows on both sides: `container.id`,
`container.image.digest`, `container.image.name`, `container.name`, `container.network`,
`container.runtime`.

**Fixed** in `a98549d807`: a dispatch branch guarded `#if defined(__linux__) && defined(CLIENT)`,
shaped like the `agent-info` branch above it, passing `d1` (the `wmodules` list) the way
`Read_AGENT_INFO` does.

---

## C26 — A change to an already-known container file raises no alert

**Severity: high.** `syscheckd/src/db/src/db.cpp` (`fim_db_transaction_sync_row_json`),
`container_baseline_fim.cpp:96` (`container_txn_callback`)

`fim_db_transaction_sync_row_json()` did not set DBSync's `return_old_data` option, so a `MODIFIED`
result arrived as the bare updated row rather than an `{"old":…,"new":…}` pair. The container
callback unwraps that pair to derive `changed_fields`, so it returned immediately on every
modification:

```cpp
case MODIFIED:
    row_data = cJSON_GetObjectItem(result_json, "new");
    if (!row_data) return;              // ← taken for every MODIFIED
```

Only first sightings survived, because `INSERTED` is not wrapped. The result: a container file that
changed produced **no FIM alert and no stateful document**.

What made this survive review and unit tests is that it is invisible from the database. DBSync
applies the update before notifying, so `file_entry` converged perfectly while the notification for
it was dropped. Measured by changing six files inside a running container and re-baselining:

| | Observed |
|---|---|
| Rows handed to `syncRow` | 6 |
| `file_entry` rows updated | 6 — `size` 6→25, new `checksum`, `version` incremented |
| Callbacks delivered | **0** |
| Alerts on the agent queue | **0** |

Host FIM was unaffected in the same run, which is what localised it: `dbFileItem.cpp:102` sets
`return_old_data` for the host path, and a host file modified in the same scan produced
`"type":"modified","changed_fields":["file.size","file.mtime","file.hash.md5","file.hash.sha1","file.hash.sha256"]`
while the container file produced nothing.

**Fixed** in `f39967c55c`. The same change on the same node now yields, for the container file:

```json
"type":"modified","changed_fields":["file.size","file.mtime","file.hash.md5","file.hash.sha1","file.hash.sha256"]
```

Pinned by case 5 of the scoped-transaction suite, which runs against the real `libfimdb`: it fails
`MODIFIED=3 wrapped=0` without the option — the production callback's silent-return condition
written as an assertion.

---

## C27 — A path reconcile deletes the rest of the container's rows

**Severity: high. Fixed, `d3a8e394d9`.** `container_baseline_fim.cpp:203`
(`ScopedContainerTxn::finish`), `shared_modules/dbsync/src/dbsync_implementation.cpp:162`

`finish(false)` closed the scoped transaction with `fim_db_transaction_close()`, on the stated
grounds that this avoids deleting rows the walk did not cover:

```cpp
} else {
    fim_db_transaction_close(m_txn);     // "close without delete detection so a
}                                        //  half-finished scan cannot delete rows"
```

It does not avoid that. `fim_db_transaction_close()` → `dbsync_close_txn()` →
`DBSyncImplementation::closeTransaction()`, which runs the sweep **unconditionally**:

```cpp
void DBSyncImplementation::closeTransaction(const DBSYNC_HANDLE handle, const TXN_HANDLE txn)
{
    …
    ctx->m_dbEngine->deleteRowsByStatusField(tnxCtx->m_tables, tnxCtx->m_scope);
    ctx->deleteTransactionContext(txn);
}
```

`deleteRowsByStatusField` issues `DELETE FROM file_entry WHERE db_status_field_dm=0 AND container_id=?`.
Choosing `close()` over `deleted_rows()` therefore suppresses the `DELETED` **callbacks** and nothing
else: the rows are gone either way.

This lands squarely on D15's path reconcile, whose row set is a subset of the container's files *by
design* — one changed file means one row synced, and every other row of that container has
`db_status_field_dm=0` at close.

### What it did to the alerts, measured

On the isolated agent ([12 §12.15](12-blocking-decisions.md#1215-the-integrated-agent-on-a-real-node-2026-09-08)),
one container with five baselined files under a `tags="container"` directory, appending one line to
one file at a time:

| Time | Action | Alert emitted | Correct? |
|---|---|---|---|
| 21:56:29 | append to `/data/f1.txt` | `modified`, `changed_fields: [size, mtime, md5, sha1, sha256]` | yes |
| 21:56:40 | append to `/data/f2.txt` | **`added`**, no `changed_fields` | no — its row was gone |
| 21:56:50 | append to `/data/f3.txt` | **`added`**, no `changed_fields` | no |

Committed `file_entry` rows for that container afterwards: **1 of 5.** So **only the first
modification per container was ever reported as a modification**; every later one arrived as a file
addition, which carries no `changed_fields` at all — a rule watching for modifications of a monitored
container file fires once and never again. **Zero `deleted` alerts** were emitted in the whole run:
`deleteRowsByStatusField` is a plain `DELETE` with no callback, so nothing downstream could observe
the loss.

### Why nobody had seen it

DBSync holds **one long-lived sqlite transaction** (`m_transaction`, opened at DB construction) and
commits it in only three places: `returnRowsMarkedForDelete` (`sqlite_dbengine.cpp:428`), the
`SQLiteDBEngine` destructor, and `closeAndDeleteDatabase`. A path reconcile takes the
`detect_deletions=false` branch and therefore **never commits**. Consequences of that, both measured:

- `fim.db-journal` stayed open from the first reconcile until shutdown, with syscheckd holding an fd
  on it. An external reader sees the pre-transaction snapshot, so `sqlite3` reported a healthy five
  rows while DBSync's own view was already down to one. Forcing the commit is what exposed it:

  ```text
  BEFORE (external read):  f1 f2 f3 f4 f5   ← pre-transaction snapshot
  SIGTERM → destructor commits
  AFTER:                   f1               ← what was actually in the transaction
  ```

- An agent restart hides it as well: the startup baseline re-inserts the missing rows, and the
  first-scan gate (`fim_container_events_release`) keeps those inserts silent. "Lose four rows →
  restart → five rows back, no alerts" is exactly the sequence that makes this invisible to any test
  that restarts the agent between steps.

The durability half is not container-specific — it is DBSync's global model, and host FIM's scheduled
scan commits on every pass because it always calls `deleted_rows`. The **row deletion** half is
container-specific: only the container path opens a scoped transaction per change.

### The fix

The reconcile path no longer opens a transaction. Rows go through a new non-transactional per-row
upsert, `fim_db_container_file_sync()`, which is what host FIM's realtime path already does
(`FIMDB::updateItem` → `syncRowData(inTransaction=false)`): no scope, no status field, no sweep, so a
row is compared against its stored self and nothing else is touched. `return_old_data` is still
requested, so a change arrives as `{"old","new"}` and `changed_fields` survives (C26).
`onStatus()` also returns early on that path — it used to open a transaction for a container that
produced no rows so stored rows could age out, which is meaningless for a reconcile and was a second
way to reach the sweep. The whole-node walk and the per-container re-walk keep the transaction and
their delete detection, still gated on the scan being reported complete.

Same sequence on the same agent after the fix:

| Time | Action | Alert emitted |
|---|---|---|
| 22:17:26 | append to `/data/f1.txt` | `modified` + `changed_fields` |
| 22:17:36 | append to `/data/f2.txt` | `modified` + `changed_fields` |
| 22:18:09 | append to `/data/f3.txt` | `modified` + `changed_fields` |
| 22:18:34 | `rm /data/f4.txt` | exactly one `deleted` |

Committed rows afterwards: `f1|9 f2|9 f3|9 f5|7` — three modifications persisted, the unlinked row
gone, and the untouched fifth row still there.

Case 6 of the scoped-transaction suite still pins the transactional behaviour (`close() still deletes
the rows it did not refresh`), and case 7 pins the replacement: the direct upsert reports `MODIFIED`
with `old`+`new`, and re-reporting the rows it did not touch produces **no** `INSERTED` — the
assertion case 6 deliberately fails.

## C28 — With no containers, `list` reads as "connector unavailable"

**Severity: medium. Fixed, `7e059dd5aa`.**
`wazuh_modules/container_instances/ci_impl/src/ipc/wire_protocol.hpp:221`,
`shared_modules/container_instances_client/include/container_instances_client.hpp:119`

`serializeResponse` omits the `containers` key entirely when the list is empty:

```cpp
data["connector"] = response.connectorName;
body["data"] = std::move(data);
if (!response.containers.empty())      // ← the key is absent, not []
{
    …
    body["containers"] = std::move(containers);
}
```

The client treats a missing key as unreachable, directly under a comment asserting the opposite:

```cpp
const auto containersIt = parsed.find("containers");
if (containersIt == parsed.end() || !containersIt->is_array())
{
    return result;                     // ← reachable stays false
}

// From here the reply is a well-formed `ok` list: an empty array now
// means "no containers", which is authoritative.
```

The server never sends that empty array, so the authoritative "no containers" reply the comment
describes is unreachable. Measured on the isolated agent with the connector healthy and one container
in its store whose cgroup inode had not been joined:

```jsonc
op status → {"data":{"connector":"docker","pending":2,"records":1,"verdicts":15},"status":"ok"}
op list   → {"data":{"connector":"docker"},"status":"ok"}          // no "containers" key
```

and both consumers logged, in the same second:

```text
WARNING: Container connector unavailable; skipping stale-container cleanup to avoid deleting rows
         for containers that still exist.
ERROR: Container FIM baseline: container connector unavailable, skipping stale-container cleanup to
       avoid false deletions.
```

The suppression itself is correct — it is D5's last row, and never sweeping against a set you could
not obtain is the right rule. The defect is that a **healthy host with no containers is
indistinguishable from a dead connector**, so:

- rows belonging to containers that have all gone away are never swept, for as long as no container
  exists on the host — the stale-row cleanup both consumers rely on simply never runs;
- every container baseline on such a host logs an `ERROR` (FIM) and a `WARNING` (syscollector) that
  describe a fault that is not occurring.

### The fix

`list` now serialises `containers` unconditionally, empty array included. `QueryResponse` carries an
explicit `listReply` flag rather than inferring the op from whether `stats` is set: `Status::ok` is
shared with the `status` op, whose reply says nothing about the container set and must not grow the
key. No wire-compatibility cost — an older client reads the array it already expects — and the client
itself is unchanged, its "an empty array is authoritative" branch simply became reachable.

Verified on the same agent, with no containers on the host:

| Check | Before | After |
|---|---|---|
| `op list` | no `containers` key | `"containers": []` |
| `op status` | no key | no key — shape intact |
| "connector unavailable" lines at startup | 2 (FIM `ERROR` + syscollector `WARNING`) | **0** |
| The stale sweep | never ran | `container '…' is gone; ageing out its FIM rows` → `1 stale container(s) cleaned`, rows 5 → **0** |

**The negative control matters more than the fix**, because the fix must not weaken
[D5](12-blocking-decisions.md#1210-d5-resolved--and-one-of-its-options-never-existed): with the socket *present but answering nothing*, the
`listed < 0` guard still fires, still logs the suppression, and still keeps all five rows. Only the
meaning of "empty list" changed, not the meaning of "no answer".

Reaching that guard at all needed a fake socket that accepts and closes without replying — with
`modulesd` simply stopped, `fim_container_baseline_available()` skips the whole baseline on the
missing socket file and the `listed < 0` path is never entered. Worth knowing before anyone tries to
test container-connector failure handling by killing `modulesd`.
