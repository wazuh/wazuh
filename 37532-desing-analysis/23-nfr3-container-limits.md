# 23 — NFR3 limit values for the container scopes (O10 / #40097)

Status: **WP1 measured, decision pending WP2–WP5.**

#37203's NFR3 asks for configurable limits on what FIM and IT Hygiene track, with values derived
"based on benchmarking and capacity planning". Roadmap item 39 — the node-level benchmark those
values depend on — had never been run. This document records it.

---

## 23.1 Method

`wazuh_manager` (Ubuntu 24.04, kernel 7.0, 10 vCPU, 11.7 GB RAM, cgroup v2), agent built from
`37532-cgroup-v1-unified-resolver` @ `914c83f483`, measured on branch
`37532-nfr3-container-limits`.

Load: `bench<N>` containers rotating through `alpine:latest`, `ubuntu:24.04`, `nginx:latest` and
`cfim:1`, each writing **2000 files into `/data`** — the one container-scoped FIM directory, at
`recursion_level="5"`. Alongside them, the pre-existing KinD set (`demo-control-plane` plus its pod
containers).

Counts are taken from the agent's own `Container baseline scan finished (...)` line and from direct
`sqlite3` queries against `queue/fim/db/fim.db`. **Every FIM count was taken with `fim.db-journal`
absent**; readings taken mid-walk differ by up to 4x and are not reported.

**What cannot be measured here.** #40092 means container inventory rows are rejected by the agent's
own schema validator and deleted inside the DBSync transaction, so no row with a `container_id`
survives in any syscollector table. Every inventory figure below is therefore **collection-side**.
FIM is unaffected: its rows are written to `file_entry` first and persist.

---

## 23.2 Scaling

| Containers | Inventory rows | Rows/container | FIM container rows | Walk settle |
| --- | --- | --- | --- | --- |
| 6 (KinD only) | 578 | 96.3 | 14 | — |
| 16 (10 bench + 6) | 1925 | 120.3 | 20,014 | ~290 s |
| 56 (50 bench + 6) | 7425 | 132.6 | **91,420 — capped** | ~700 s |

FIM scales exactly while there is room: 10 containers x 2000 files produced 20,014 rows, the extra 14
belonging to the KinD set. Rows per container **rise** with N (96 -> 120 -> 133) because the image mix
shifts toward distro-base images. A per-container ceiling must therefore be set against the fattest
plausible image, not against an average.

Agent cost at N=56 is modest: `wazuh-syscheckd` 45 MB RSS, `wazuh-modulesd` 65 MB.

### Per dimension (N=6 control; sums to 578, so the breakdown is complete)

| Dimension | Rows | | Dimension | Rows |
| --- | --- | --- | --- | --- |
| packages | 173 | | network_iface | 16 |
| **services** | **144** | | network_protocol | 6 |
| groups | 112 | | hwinfo | 6 |
| users | 48 | | osinfo | 4 |
| network_address | 33 | | | |
| processes | 19 | | | |
| ports | 17 | | | |

The breakdown is only valid on the **first** scan after a change; steady-state scans emit deltas
only. The authoritative totals are the scan-finished lines.

---

## 23.3 Finding 1 — `services` is collected, is the second-largest dimension, and has no cap

D14 records *"Services is collected but always empty — containers run no init"*, and
`syscollector_containers_limits_t` omits `services` on exactly that basis: *"the container scanner
does not collect those, so a cap for them would be a knob with nothing behind it"*
(`module_limits.h:92-94`).

Measured: **144 service rows, 25% of the node's entire container inventory, all from one container**
— `b1b6ccc5c742...`, the KinD node, which runs systemd.

That container is visible *because of* Fix 1 (`1b9ba77373`), which made a container whose init system
owns its cgroups resolvable. Fix 1 invalidated D14's premise, and the limits struct still encodes it.
`services` is now a producing container dimension with **no container-scope cap at all**: the scope
map has no `services` key, so `limitsFor(container)` yields 0 = unlimited.

It also settles Decision 1 on measurement rather than argument: **one container produced a quarter of
the node's inventory.** A node-wide budget alone cannot express that; a per-container ceiling can.

---

## 23.4 Finding 2 — container FIM fills the host's table, and the fill is silent

`setTableMaxRow("file_entry", file_entry_limit)` is **scope-blind** and the default is 100,000.
Container rows land in the same table.

At N=56 the table pinned at **exactly 100,000**: host 8,580, container 91,420. Roughly 8,600 container
rows were refused.

**During the fill, the agent said nothing.** Zero occurrences of `Reached maximum files limit`,
`max_rows`, or any `database is N% full` message while the table filled.

The warning arrived **only on the next host FIM scan**, after an agent restart:

```
2026/10/08 18:33:28 wazuh-syscheckd fim_scan.c:265 at fim_check_db_state():
  WARNING: (6926): File database is 100% full.
```

Two things follow. The condition was reported roughly **30 minutes after it arose**, because
`fim_check_db_state()` runs inside `fim_scan()` — the host scan — and nothing equivalent runs on the
container path. And it names the *file database*, giving an operator no indication that containers
caused it.

### Coverage at the cap is decided by walk order, and is not flagged

| Outcome | Containers |
| --- | --- |
| Complete (2005 rows) | 45 |
| Partial (1371 of 2005) | 1 |
| Absent from FIM entirely | 4 |

Meanwhile every scan in that window reported:

```
Container baseline scan finished (56 container(s), 7425 row(s), 0 partial scan(s), 0 stale cleaned)
```

**`partial` is driven by the walker's own `max_files` cap, not by the database refusing inserts.** So a
container whose rows were refused carries an incomplete row set that is not flagged partial — which is
the precondition D11 rule 4 ("never let a partial view delete") exists to prevent. The consequence was
**not** observed in this run and is not claimed: no false delete occurred. The precondition is what is
measured; the consequence needs its own test.

### The host is not starved — it competes

A container row disappeared during the restart (container `7b4467ec67d3...`, 1 row) and the host's new
`/etc` probe file took the freed slot. That container no longer existed in Docker or containerd, so
the sweep was **correct**, not a false delete. Free slots are first-come-first-served; the host is not
systematically starved, but neither is it protected.

### The walk reports rows it produced, not rows that were stored

```
18:33:19  Container FIM baseline finished: 56 container(s) scanned, 100063 row(s),
          0 partial scan(s), 1 stale container(s) cleaned, 56 container(s) known.
```

The walk produced **100,063 rows**; the table holds **91,420**. The ~8,600-row shortfall appears in no
counter and in no log line. The baseline counts what it handed to the database, not what the database
accepted, so even the row total cannot be used to detect the condition.

---

## 23.5 Finding 3 — a saturated table stays saturated for up to 12 hours

The 50 bench containers were deleted at 18:38. Two hours later:

| | State |
| --- | --- |
| Syscollector inventory | recovered — 6 containers, 578 rows, `0 stale containers cleaned` |
| FIM `file_entry` | **still 100,000 rows**, 49 distinct `container_id`s, 48 of them for containers that no longer exist |

FIM's `sweepStale()` runs only inside the container FIM baseline pass, and that pass is on the
syscheck frequency — `<frequency>43200</frequency>`, **12 hours**. The last one had run at 18:33,
triggered by `scan_on_start`.

So while the table is full, `updateTableRowCounter` refuses **every** insert, host and container
alike, and the agent records no new file state at all. The sole diagnostic remains the single
`File database is 100% full` WARNING from the host scan.

**The sweep itself is cheap** — the constraint is purely cadence. Forced by a restart:

```
20:41:57  Container FIM baseline finished: 6 container(s) scanned, 3 row(s),
          0 partial scan(s), 46 stale container(s) cleaned, 6 container(s) known.
```

91,416 rows deleted in **under 40 seconds**, table back to 8,584. That also answers #37837's angle 2
("a pod with thousands of tracked files produces that many deletes at once"): mass deletion is fast.

---

## 23.6 The limits, validated end to end (WP4, 2026-10-09)

Measured on `wazuh_manager` with the branch build deployed, against the same 50-container x 2,000-file
load 23.4 used. Two notes on the method, because both bound what these numbers mean:

- The local build links with **RUNPATH** where the package links with **RPATH**. RPATH is inherited by
  a binary's dependencies and RUNPATH is not, so the packaged `libfimebpf.so` resolves its siblings
  through the daemon's RPATH and a locally built one cannot. The agent refused to start until
  `LD_LIBRARY_PATH` was set. Not a product defect — the package works — but locally built binaries are
  **not drop-in replaceable** on a packaged install.
- `CMAKE_BUILD_TYPE` is empty, so this is an unoptimised build. Row counts, refusals and the `partial`
  flag are unaffected; **wall-clock is not comparable** to 23.2 and is not quoted.

### Test A — a node budget sized for a node that runs containers

`fim.file_entry_limit` raised from the host-era 100,000 to 300,000; no per-container ceiling.

| | 23.4 (before) | Test A |
| --- | --- | --- |
| Table total | **pinned at 100,000** | **108,644** |
| Container rows | 91,420 | **100,063** |
| Rows the walk PRODUCED | 100,063 | 100,063 |
| **Produced vs stored** | **8,643 refused** | **0 — identical** |
| Containers complete | 45 of 50 | **50 of 50** |
| Containers with no rows at all | **4** | **0** |

The decisive line is produced == stored. The same walk produces the same 100,063 rows either way; what
changed is that none are now turned away. `0 partial scan(s)` is finally *correct* — in 23.4 the same
message was emitted while 8,643 rows were being refused.

### Test B — a per-container ceiling, and the flag it makes possible

`fim.container_file_entry_limit` = 500, against containers offering 2,000 files each.

```
56 container(s) scanned, 100063 row(s), 50 partial scan(s), 0 stale container(s) cleaned
```

| Rows stored | Containers |
| --- | --- |
| 500 | **50** — every bench container, truncated exactly at its ceiling |
| 1 | 3 — KinD containers, under the ceiling |

Each truncated container logs its own warning, naming itself and both limits:

```
Container FIM baseline: container 'ff705e46...' stored 500 row(s) and 1500 were refused
  (per-container limit 500, node limit 300000). Its file state is incomplete, so delete
  detection is suppressed for it this pass.
```

**The control holds:** 50 partial of 56 scanned — the six containers under the ceiling are not
flagged, so the flag is not simply always-on.

### The falsifier

`container_scan_is_partial()` reverted to `return walker_partial;` — refusals ignored — rebuilt and
redeployed:

```
56 container(s) scanned, 100063 row(s), 0 partial scan(s)      <- while 54 refusal warnings were logged
```

That is 23.4's condition reproduced on demand: rows refused, scan reporting itself whole. Restoring
the guard returned `50 partial scan(s)`. **The rule is load-bearing, not decorative.**

### What this does NOT show

- Only on `wazuh_manager`. Both sides are glibc 2.39; Ubuntu 22 (2.35) and Debian 13 reject these
  artefacts, so the ceiling is unvalidated there.
- The **reconcile path** (`syncRowDirect`) is not capped — it has no transaction to count within.
  Bounded in practice by event rate and corrected at the next baseline, but it is a gap.
- A *false delete* was still never observed. 23.4 measured the precondition and this measures the
  guard; neither measures the consequence.

---

## 23.7 What this implies for the decision

1. **Two levels are required, not one.** One container produced 25% of the node's inventory (23.3), and
   walk order decided which containers were monitored at all (23.4). A node-wide budget bounds the
   manager; only a per-container ceiling keeps one container's blow-up local.
2. **Admission control, not truncation.** The measured truncation left 45 complete, 1 partial and 4
   invisible containers with no signal of any kind. A cap that cannot say which containers it dropped
   is not a limit.
3. **Recovery is not a substitute for not reaching the cap.** 23.5 shows the ceiling, once reached,
   holds for up to 12 hours, during which the agent records no new file state at all. Nothing
   downstream undoes that quickly, so the control has to act before the ceiling, not after.
4. **`services` needs a container cap**, and `syscollector_containers_limits_t` needs the dimension its
   own comment says has nothing behind it.
5. **Container FIM needs its own document limit** (none exists today) and must stop spending the host's
   scope-blind `file_entry` allowance.
6. **Saturation must be reported where it happens**, and must count rows *stored*, not rows produced —
   today the only upward signal fires on the host scan, names the host's database, and the baseline's
   own row count hides the shortfall.

Values are proposed in WP5 once WP2-WP4 land; nothing here is a shipped default yet.
