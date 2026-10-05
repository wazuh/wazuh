# 19 — Option C (in-kernel cgroup filtering): test report

**Change under test:** the container event drain opens the eBPF engine in
`RT_CGROUP_MODE_ALLOWLIST` instead of `RT_CGROUP_MODE_ALL`, and keeps the kernel's allowlist in
step with the container list it already polls.

**Date:** 2026-10-02 · **Branch:** `37532-o7-ebpf-engine-convergence` · **Issues:** #37532 / #37396

**Verdict:** the change does what it was proposed to do, by a wide and consistent margin on **both**
`file_open` variants, and the discovery regression it was expected to cause does not materialise as
a correctness regression. Three failure modes are covered by tests; five are not covered by anything
and are listed in §5 — the largest being the absence of any end-to-end run against real containers.

---

## 1. What was tested

Three distinct claims, because they fail independently.

| # | Claim | Why it needs its own test |
| --- | --- | --- |
| C1 | The kernel filter delivers exactly the allowlisted cgroups and nothing else, and a filtered event is not counted as a drop | Pre-existing. Re-run as a regression check |
| C2 | The allowlist is **live** — a cgroup added to an already-open handle starts being delivered, and one removed stops | **New.** This is the mechanism the whole change rests on. Without it, filtering could only ever monitor the containers that existed at agent startup |
| C3 | Filtering measurably reduces cost | The premise. Option C was chosen over continuing work on option D specifically because it was predicted to be the bigger lever |

And three consumer-side policy rules, which are where a filter quietly breaks change detection:

| # | Rule |
| --- | --- |
| C4 | A newly listed container is walked **when filtering is on** — its earlier events were discarded in the kernel, so the list is the only evidence it exists |
| C5 | A newly listed container is **not** walked when filtering is off — its events have been arriving all along, and walking would be pure cost |
| C6 | An **unchanged** list escalates nothing. Without this, every container on the node would be re-walked on every 5 s refresh, forever |

C6 is the one worth dwelling on: it is a regression far worse than the host traffic the filter was
added to remove, it is invisible in any single-refresh test, and nothing but a dedicated assertion
would have caught it.

---

## 2. How it was tested

### 2.1 Environment

| | |
| --- | --- |
| Kernel-level tests and benchmark | `wazuh_manager` VM — Ubuntu 24.04, kernel 7.0.0-34-generic, 10 cores, cgroup v2 |
| Active LSM list | `lockdown,capability,landlock,yama,apparmor,bpf,ima,evm` — includes `bpf`, so the engine attaches the **LSM** `file_open` variant by default |
| Forcing the kprobe path | The engine picks its variant from that list, which cannot be changed without a reboot. A temporary VM-only patch made `is_bpf_lsm_active()` honour a `WAZUH_FORCE_KPROBE` environment variable. Never committed; reverted afterwards and the file's hash re-checked against the repo |
| Variant confirmation | Every run echoes the engine's own selection line (`preferring LSM` / `preferring kprobe`). This is not decoration: three runs earlier in this work were labelled kprobe and were actually LSM, because `sudo` strips the environment. All runs below use `sudo -E` and are confirmed individually |
| Unit tests | WSL2, g++ 17, `-fsanitize=address,undefined` |
| Background load | The installed agent was left running (5 daemons, load average ≈ 1.0). It is realistic background, and it is identical in both arms of every pair |

### 2.2 Unit tests — C4, C5, C6 and the list delta

`cgroup_container_map_test` (24 tests) and `container_event_router_test` (23 tests), both built with
ASan and UBSan. **Seven tests are new** — three in the map, four in the router — plus one new
assertion inside an existing map test:

- the delta reports which cgroups **entered** and **left** across two refreshes;
- a cgroup whose inode was reused by a *different* container counts as added and **not** as removed
  — the opposite would have the consumer deny a cgroup it had just allowed;
- an unchanged list produces an empty delta (C6);
- a `cgroup_id` of 0 — the connector's "could not determine" sentinel — never reaches the allowlist;
- filtering off: a quiet newly listed container is not walked (C5);
- filtering on: a newly listed container **is** walked with no event ever arriving (C4);
- the seeding list is applied *before* filtering is announced, so the containers that already exist
  at startup are not all walked immediately after the baseline walk that just read them.

### 2.3 Kernel test — C1 and C2

`rt_engine_filter_test`, extended from three properties to five. Two cgroups are created, one
allowlisted and one not, each with a child process generating file events, and a parent polling.

The two new phases exercise the live path **while still in allowlist mode**, which no previous test
did: `rt_allow_cgroup()` the second cgroup on the open handle and confirm its events start
arriving, then `rt_deny_cgroup()` it and confirm they stop.

> **Negative control.** Each new phase asserts that its child actually joined the cgroup. "No events
> from that cgroup" is also exactly what a child that failed to join produces, so without this the
> deny assertion would pass against a completely broken `rt_deny_cgroup()`. The first version of
> this test had that hole; it was found by re-reading the test rather than by it failing.

Run on **both** `file_open` variants. The five properties hold identically on each — same counts,
to the event — which matters because the kprobe and LSM paths build an event's `filename` by
completely different means (a manual dentry walk versus `bpf_d_path`), and the filter decision sits
upstream of both.

### 2.4 Benchmark — C3

A standalone binary, not the full agent. The full-agent harness was tried for the earlier option D
measurement and rejected: a ±20% run-to-run spread cannot resolve an effect this size.

- **Load:** 20,000 iterations of `open(O_WRONLY|O_CREAT|O_TRUNC)` + `write` + `close` on host
  files, from the host's own cgroup. This is traffic the container consumer discards under *either*
  setting — which is the point. It produced ≈39,942 delivered events in mode ALL.
- **Design:** alternating paired runs, 5 pairs, ALL then ALLOWLIST each time, so drift in
  background load affects both arms equally.
- **Both arms set `RT_SKIP_PROC_CONTEXT`**, as the production consumer does. The question asked is
  what filtering saves *on top of* the field mask, not instead of it.
- **In allowlist mode the map is non-empty** (one unmatchable cgroup id), so the measurement is not
  accidentally benchmarking an empty-map fast path.
- **Measured in-process** with `getrusage`: `RUSAGE_SELF` for the consumer, `RUSAGE_CHILDREN` for
  the writer.
- **Run twice over, once per `file_open` variant** — 5 pairs on LSM and 5 pairs on kprobe, 20 runs
  in total. kprobe is the majority configuration in the field, so measuring only LSM would have
  left the common case to inference.

> **A first attempt at the kernel-side cost was discarded, not reported.** It read
> `bpftool prog list` run_time_ns deltas, snapshotting *after* the benchmark exited — by which time
> `rt_close()` had unloaded the programs, so the "after" snapshot contained nothing. The figures it
> produced (0–6,970 ns) were meaningless. It was replaced with the in-process `RUSAGE_CHILDREN`
> measurement, which captures the same cost from the other side.

---

## 3. Results

### 3.1 Correctness

| Test | LSM path | kprobe path |
| --- | --- | --- |
| `rt_engine_filter_test` (5 properties) | **pass**, 3 consecutive clean runs, identical counts | **pass** |
| `rt_engine_leak_test` | **pass** | **pass** |
| `rt_engine_drops_test` | **pass** | **pass** |
| `rt_engine_creds_test` | **pass** | **pass** |
| `rt_engine_skip_test` | **pass** | **pass** |
| `rt_engine_contract_test` | **pass** | n/a (no kernel) |
| `cgroup_container_map_test` | **24/24 pass** (ASan + UBSan) | n/a (no kernel) |
| `container_event_router_test` | **23/23 pass** (ASan + UBSan) | n/a (no kernel) |

Filter test output — **byte-identical on both paths**, and stable across runs:

```text
  events from the allowlisted cgroup: 300
  events from the excluded cgroup   : 0
  events from every other cgroup    : 0
  after allowlisting the second cgroup mid-flight, its events: 600
  after removing it from the allowlist again, its events: 0
  after switching to mode ALL, events from the previously excluded cgroup: 600
```

The third line matters as much as the second: no event leaked in from anywhere else on a host that
was running a full agent at the time.

### 3.2 Cost

Ten alternating pairs, five per `file_open` variant. **The allowlist won every pair on every
metric, on both paths** — twenty runs, sixty comparisons, no exceptions. On every column the two
distributions do not overlap: the worst allowlist run still beats the best unfiltered one.

All figures in seconds, for the whole 20,000-iteration arm.

**LSM path**

| Pair | wall ALL | wall ALLOW | consumer ALL | consumer ALLOW | writer ALL | writer ALLOW |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 11.765 | 5.576 | 0.585 | 0.032 | 10.798 | 4.501 |
| 2 | 10.383 | 5.572 | 0.430 | 0.024 | 9.378 | 4.683 |
| 3 | 11.505 | 5.565 | 0.493 | 0.032 | 10.520 | 4.559 |
| 4 | 10.788 | 5.333 | 0.575 | 0.022 | 9.913 | 4.477 |
| 5 | 8.720 | 5.831 | 0.387 | 0.101 | 7.842 | 4.805 |

**kprobe path** (the majority configuration)

| Pair | wall ALL | wall ALLOW | consumer ALL | consumer ALLOW | writer ALL | writer ALLOW |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 13.115 | 5.927 | 0.714 | 0.032 | 12.298 | 4.938 |
| 2 | 10.268 | 7.361 | 0.551 | 0.052 | 9.518 | 6.429 |
| 3 | 13.255 | 6.961 | 0.590 | 0.031 | 12.194 | 5.948 |
| 4 | 11.853 | 5.588 | 0.614 | 0.033 | 10.696 | 4.673 |
| 5 | 9.411 | 4.858 | 0.436 | 0.023 | 8.232 | 3.801 |

**Medians**

| Metric | | mode ALL | allowlist | Change |
| --- | --- | ---: | ---: | ---: |
| Consumer CPU | LSM | 0.493 s | 0.032 s | **−93.5%** |
| | kprobe | 0.590 s | 0.032 s | **−94.6%** |
| Writer CPU | LSM | 9.913 s | 4.559 s | **−54.0%** |
| | kprobe | 10.696 s | 4.938 s | **−53.8%** |
| Wall clock | LSM | 10.788 s | 5.572 s | **−48.3%** |
| | kprobe | 11.853 s | 5.927 s | **−50.0%** |
| Events delivered | both | ~39,942 | 0 | — |

### 3.3 LSM versus kprobe

The two paths differ less than expected, and the difference is not where it was predicted.

| | LSM | kprobe | kprobe is |
| --- | ---: | ---: | ---: |
| Unfiltered writer CPU | 9.913 s | 10.696 s | +7.9% dearer |
| Unfiltered consumer CPU | 0.493 s | 0.590 s | +19.7% dearer |
| **Filtered** writer CPU | 4.559 s | 4.938 s | +8.3% dearer |
| Absolute writer saving | 5.354 s | 5.758 s | +7.5% larger |
| **Proportional** writer saving | 54.0% | 53.8% | **the same** |

kprobe is uniformly ~8% dearer — filtered and unfiltered alike — which is consistent with D9's
finding that the kprobe path costs more per event. But because the *floor* rises by the same
proportion as the *ceiling*, the filter removes the same **fraction** of the cost on both paths.

**This corrects a speculation made before the measurement.** The first version of this report said
the saving on kprobe was "plausibly larger" because kprobe is dearer per event. In absolute seconds
that is weakly true (+7.5%); as a proportion it is **not true at all**. The honest summary is that
option C's benefit is insensitive to which variant is attached, which is a better result than the
one guessed at — it means the figure does not need qualifying by deployment.

---

## 4. What the results mean

### 4.1 The consumer saving was expected. The writer saving was not.

A BPF program runs **in the context of the process that made the syscall**. Building a 12,416-byte
record, walking a path and reserving ring space for an event is therefore charged to the process
calling `open()` — not to the agent that asked for it.

Unfiltered, every program on the host that wrote a file paid roughly **twice** the CPU for those
writes, on behalf of a consumer that then discarded the result. That cost is invisible to any
measurement that looks only at the agent's own CPU, including D9's, and it is the strongest
argument for the change.

### 4.2 Honest limits on these numbers

- **The ratios transfer; the absolute values do not.** 20,000 back-to-back writes is an extreme
  rate. A measured idle node produced **17 host events in 20 s** once the agent's own writes were
  excluded ([12 §12.16](12-blocking-decisions.md)) — roughly one per second, against this
  benchmark's ~3,600. Nothing here says what the change saves on a quiet machine; only what it
  saves *per unit of host write traffic*.
- **The writer delta should not be divided by the event count.** Doing so gives ≈134 µs per event,
  which is far too large to be the BPF program alone; cache pressure and scheduling under a
  40,000-event-per-arm load are mixed into it. The aggregate ratio is defensible, a per-event
  attribution is not.
- **Both `file_open` variants were measured** (§3.3), so the result does not rest on which one a
  given host attaches. What is still a single data point is the *host*: one VM, one kernel, one
  storage stack.

### 4.3 The discovery change is latency, not correctness

Before: a container created after startup announced itself. Its runtime's four startup writes
arrived from an unknown cgroup, resolving that cgroup escalated the container, ~1 s after
`docker run`. Those writes are now discarded in the kernel, so discovery falls to the connector's
list — at most `resolver_interval_ms` (5 s).

The outcome is **identical**, which is why this is a latency change:

| | Before | After |
| --- | --- | --- |
| Discovery trigger | runc's startup writes, via an unknown cgroup | the connector's list refresh |
| Latency | ~1 s | ≤ 5 s |
| **What the container then gets** | `rewalkContainer` | `rewalkContainer` |
| Host traffic through the ring | all of it | none |

A container identified after its events happened has **never** had those paths replayed — they were
classified against an unidentified cgroup and discarded before anyone knew whose they were. The
answer was always a walk of current on-disk state. A file created *and* deleted inside the
discovery window is missed under both settings.

### 4.4 Startup: the drain does not wait for the first container snapshot

Worth stating because it is easy to assume otherwise. `start()` makes **one** synchronous
`listContainers()` call, bounded by the client's 1 s timeout, and proceeds whatever it returns. It
does not block for the connector and does not retry.

The component immediately after it *does* retry. `fim_run_container_baseline()` waits up to
10 x 500 ms, because the `container_instances` socket **binds before its first enumeration
completes** — so "reachable but empty" is a normal cold-start answer, not a failure
(`container_baseline_scanner.cpp`). The drain runs *first*, with no such protection, which makes it
strictly more exposed to the race than the component designed around it.

The three outcomes:

| Seed result | Kernel allowlist after `start()` | Consequence |
| --- | --- | --- |
| Containers returned | populated | Clean. Filtering is enabled *after* seeding, so none of them escalate |
| Reachable, empty | empty | Correct if the node really has no containers |
| Unreachable | empty | Nothing is delivered until the resolver's first successful refresh — which runs immediately, then every 5 s |

In the second and third rows **with containers actually present**, the first non-empty list marks
every container as newly listed, so every container is escalated and the node is walked a second
time just after the baseline walked it.

**That is wasteful, not wrong**, and it is a widening of existing behaviour rather than a new one:
before this change a failed seed also escalated every container that happened to emit an event. A
re-walk reads current state and produces no alerts for unchanged rows, so the cost is CPU and I/O,
once per agent start.

It is also the deliberate choice. Suppressing those escalations would mean trusting that the
baseline covered every container — and the baseline takes its list at a single instant, so a
container created while the walk is still running would be in neither that list nor the suppressed
set, and would end up allowlisted but never walked. **A duplicated walk is recoverable; a container
whose rootfs is never enumerated is not.**

Item 20's create trigger removes this class of problem rather than narrowing it.

### 4.5 A claim in three design documents was wrong

[10 §10.0](10-container-instances-delta-plan.md), [12 §12.16](12-blocking-decisions.md) and
[15](15-spike-resume.md) all stated that an allowlist "has nothing to put in it" until
`container_instances` grows a create trigger (roadmap item 20), and [16 Q8](16-open-design-questions.md)
listed the filter mode as blocked on it.

That was wrong, and wrong in a specific way worth recording: it was **copied between documents
rather than re-derived**. The allowlist has had the connector's container list available all along
— the same list `refreshContainerList()` already polls to drive attribution. Item 20 supplies a
create *event*, not the only possible source of entries.

Item 20 remains worth doing. It would cut the discovery window from 5 s to near zero. It is an
optimisation of this change, not a prerequisite for it. All four documents have been corrected.

---

## 5. What was **not** tested

Stated plainly, because a test report that only lists passes is not a test report.

| Gap | Risk |
| --- | --- |
| **No end-to-end run with real containers.** The drain's own allowlist bookkeeping was never exercised against live KinD/Docker traffic — only its policy layer in unit tests and the engine beneath it on a kernel | The highest-value gap. The seams between `install()`, `syncAllowlist()` and the kernel are covered by construction, not by observation |
| ~~**Discovery latency was not measured.**~~ **Closed 2026-10-05** — see §7 | — |
| **The map-full fallback never ran.** `disableAllowlist()` — which turns filtering off for the whole handle — has no test. The BPF map holds 4,096 entries against a `max_containers` of 512, so it is hard to reach and correspondingly easy to get wrong | A node with thousands of containers would take an untested path |
| **The stale-object retry never ran.** `rt_open()` refuses allowlist mode on a BPF object without the filtering maps; the drain retries unfiltered. Not exercised | `rt_file.bpf.o` is in no packaging manifest, so a stale object is a real configuration, not a hypothetical — this path is likelier than it looks |
| **cgroup v1 untested** | Out of scope: the drain already refuses v1 hosts before reaching any of this |
| **One host.** Both variants were measured, but on a single 10-core VM with virtualised storage | Nothing here speaks to a different kernel, a different filesystem, or bare metal |
| **The cold-start seeding race was reasoned about, not observed** (§4.4) | The startup path most likely to behave unexpectedly is the one with no test |

---

## 6. Pros and cons

### Pros

1. **Large, consistent, independently reproduced cost reduction.** −93% consumer CPU, −54% writer
   CPU, −48% wall, winning all five paired runs with no distribution overlap.
2. **It removes cost from processes that never asked for it.** The writer-side saving benefits
   every program on the host that writes a file, not just the agent. This is the part no previous
   measurement had seen.
3. **It attacks the duplicate-engine cost at the root.** Option D removed per-event work; option C
   removes the events. The two compose — both are active, and the benchmark measured C *on top of* D.
4. **The benefit does not depend on which `file_open` variant is attached.** LSM and kprobe give the
   same proportional saving (§3.3), so the figure needs no deployment-specific qualification.
5. **No correctness regression.** The outcome for a late-discovered container is unchanged (§4.3).
6. **It fails loudly in both directions it can fail.** A map that cannot take a container turns
   filtering off rather than leaving that container silently unmonitored; a BPF object too old to
   filter gets an unfiltered retry rather than leaving container FIM off entirely.
7. **Reversible.** `cgroup_allowlist: false` restores the previous behaviour exactly.
8. **It unblocks nothing else, and blocks nothing else.** It does not depend on item 20 and does not
   prevent it.

### Cons

1. **Discovery now has a single point of failure.** Previously there were two independent routes —
   the connector's list and the event stream. There is now one. The lost route was itself
   incidental, depending on runc's startup behaviour rather than on anything designed, and a
   container the connector never lists was never baselined either — so the blindness is shared, not
   introduced. But "two routes to one" is a real reduction in redundancy.
2. **Discovery latency rises from ~1 s to ≤ 5 s.** Bounded and tunable, but worse.
3. **More state to keep consistent.** The kernel allowlist must track the map, across inode reuse,
   container removal, connector unavailability and resolver races. That is four new failure modes
   where there were none, three of which have unit tests and one of which (§5, map-full) does not.
4. **The benchmark is synthetic.** It establishes the ratio under write pressure, not the saving on
   a representative node (§4.2).
5. **Measured on one host.** Both `file_open` variants were covered, but a single VM with
   virtualised storage is one data point for the absolute figures (§4.2, §5).
6. **A new config surface that is not reachable from `ossec.conf`.** `cgroup_allowlist` is a
   `DrainConfig` field with no XML binding, so the escape hatch requires a rebuild. Deliberate —
   the knob exists for bisecting a field problem, not for operators — but it is a half-wired option
   until something asks for it.

### Recommendation

**Keep it, and close the §5 gaps before the change ships** — specifically the end-to-end run with
real containers and a timed discovery measurement.

The cost case is now settled on both `file_open` variants and needs no further benchmarking. What
remains thin is integration evidence: every layer has been tested in isolation and the seams
between them have not been observed working together against live container traffic. That
asymmetry, not the performance, is what should gate the merge.

---

## 7. Discovery latency, measured (2026-10-05)

§5 listed this as reasoned about rather than observed. It has now been timed, on the same VM, with
the full agent built from `37532-container-lifecycle-notify`.

The probe measures `docker run` → the container actually **walked**, read from the harness's own
`PERSIST CREATE <cid>` lines. That is stricter than timing the cgroup being admitted: under the
allowlist the drain only walks what it has admitted, and only admits what it has discovered, so a
CREATE row proves the whole chain. Timed from the shell either side, so nothing is inferred from
internal state.

| | min | **median** | max | discovered |
| --- | ---: | ---: | ---: | ---: |
| Notifications active | 667 ms | **1262 ms** | 1428 ms | 5/5 |
| Notifications suppressed | 3859 ms | **5202 ms** | 5532 ms | 5/5 |

**4.1× faster, and the distributions do not overlap** — the worst notified run beats the best
floor-only run by 2.4 s. The control was the notification socket alone: removing it makes the
module's `sendto` fail while the drain keeps polling, and restoring it returned the fast path
(929/1219 ms), so the difference is the channel rather than drift.

The suppressed figures clustering at ~5.2 s match `resolver_interval_ms = 5000` plus walk time,
which confirms §4.3's mechanism and not merely its outcome: without notifications, discovery really
is bounded by the poll, because with the kernel filter on nothing else can admit a new container.

**The sub-second target in the original plan is not met.** The measurement is end to end and
includes the 500 ms reconcile debounce, an IPC round trip and a walk of 47 files; discovery alone is
earlier than the figure shown. Reported as measured rather than quoting a more flattering internal
milestone.
