# Design analysis — `container_baseline` module (#37532)

Design review of the `wazuh_module` **`container_baseline`** as implemented on branch
`spike/container-instance-and-fim-syscollector-baseline`, compared against the requirements of
[wazuh/wazuh#37532](https://github.com/wazuh/wazuh/issues/37532).

- **Branch reviewed:** `spike/container-instance-and-fim-syscollector-baseline` (`66301af90d`), diffed against `631afacfc2`
- **Worktree:** `~/wazuh/source/37532-container-integration`
- **Review date:** 2026-09-02 — **last updated:** 2026-09-08

> ### Status, 2026-09-08
>
> **The review below is a snapshot of the branch as reviewed; it is no longer the current state.**
> Work since then is on `37532-5-0-0-container-integration`, **56 commits ahead of `origin/5.0.0`
> (`7e059dd5aa`).** The remote branch is two behind, at `f39967c55c`.
>
> - [09](09-implementation-status.md) is the **authoritative status**: what is built, what is
>   deferred and why, and what is validated.
> - [12](12-blocking-decisions.md) carries the **decisions** (D1–D18) and, in
>   [§12.15](12-blocking-decisions.md#1215-the-integrated-agent-on-a-real-node-2026-09-08) and
>   [§12.16](12-blocking-decisions.md#1216-the-lifecycle-question-answered-by-measurement-2026-09-08),
>   the evidence tables for the integrated agent.
> - [15](15-spike-resume.md) is the **walk-through**: how the feature works end to end, with
>   diagrams, and what is implemented versus not. Read it before the finding and decision documents.
> - [10](10-container-instances-delta-plan.md) is a **plan that was not implemented**; its own
>   header now records what runs instead, and why the gap it was written to close turned out not to
>   be one for container FIM.
> - [06 §6.10](06-proposed-architecture.md#610-corrections--the-sketch-versus-the-implemented-contract)
>   corrects the handoff sketch against the contract that actually shipped. **Read it before planning
>   from §6.3.**
>
> Headline: **the whole agent now runs this feature on a real node.** `wazuh-modulesd` and
> `wazuh-syscheckd` built from this branch, real `libfimdb`, the real `container_instances` module in
> `modulesd`'s own process, real Docker containers, Ubuntu 24.04.4 / kernel 7.0.0-31 / cgroup v2.
> Every earlier run drove the pieces through a harness; this one drove the daemons.
>
> What that measured, replacing what these documents used to predict:
>
> - **The eBPF provider builds from source and attaches** — `rt_file.bpf.o` is produced through the
>   host-BTF fallback, then `4 program(s) attached, ABI 1.1`, choosing the LSM `file_open` variant
>   over the kprobe fallback. So WP6 is a *packaging* gap, not a code gap.
> - **[D16](12-blocking-decisions.md), [D17](12-blocking-decisions.md) and WP2 hold**, including
>   [C24](03-findings-correctness.md)'s absent-root case with a deliberately missing `<directories>`
>   entry, and a container file change raising a FIM alert with `changed_fields`.
> - **WP4 is done** (`2ea083add8`) and its deferral premise was wrong: container rows already
>   traverse `checkDocumentLimit()` here, so the enforcement had somewhere to land. 32 container
>   package rows against a container budget of 2 → 2 promoted, host counts untouched.
>
> - **A container created after the baseline is fully covered** — five files, five `added` alerts,
>   ~2 s, with no lifecycle delta from `container_instances`. The trigger, traced per event, is
>   **runc's init**: four write-intent opens of procfs/sysfs files arrive from a cgroup nobody has
>   mapped yet, and resolving it escalates to a re-walk. So `RT_CGROUP_MODE_ALL` is load-bearing
>   until [item 20](08-roadmap.md) lands — and equally, that discovery rests on runtime behaviour
>   this design does not control
>   ([12 §12.16](12-blocking-decisions.md#1216-the-lifecycle-question-answered-by-measurement-2026-09-08)).
>
> And four defects only the integrated agent could show:
>
> - **[C25](03-findings-correctness.md)** — `<container_instances>` was never dispatched, so the
>   module could not start and the socket both consumers read metadata from was never bound. The
>   feature was unreachable from a real agent no matter what `ossec.conf` said. Fixed,
>   `a98549d807`; everything above depends on it.
> - **[C26](03-findings-correctness.md)** — `MODIFIED` arrived unwrapped, so the container callback
>   discarded every modification: six files changed, six rows updated in `file_entry`, **zero**
>   alerts. Invisible from the database, which is why it survived review. Fixed, `f39967c55c`.
> - **[C27](03-findings-correctness.md)** — closing a scoped transaction deletes the rows it did not
>   refresh, so a path reconcile wiped the rest of its container's state. This is the opposite of
>   what [D15](12-blocking-decisions.md)'s implementation note claims. Measured at the alert level:
>   modifying one file reported `modified`, modifying the next reported **`added`**, and 1 of 5 rows
>   survived. Fixed, `d3a8e394d9`, under
>   [D18](12-blocking-decisions.md#d18--how-does-a-path-reconcile-persist-a-row-without-authorising-a-sweep-resolved-2026-09-08--the-non-transactional-upsert-d3a8e394d9).
> - **[C28](03-findings-correctness.md#c28--with-no-containers-list-reads-as-connector-unavailable)**
>   — with no containers on the host, `list` omitted the `containers` key and the client reads that as
>   an unreachable connector. The stale-row sweep therefore never ran there, and both consumers logged
>   a fault that is not occurring. Fixed, `7e059dd5aa`, with D5's suppression intact for a connector
>   that genuinely does not answer.
>
> And one existing finding got worse on measurement:
> **[C16](03-findings-correctness.md#c16--dockers-deferred-reconcile-is-dropped-not-deferred)** — a
> container removed with `docker rm -f` stayed in `list` for two minutes, past the 60 s removal
> grace, because the grace only expires inside `applySnapshot()` and nothing re-runs it on the Docker
> path without another event. On an idle host a removed container's rows are never swept by either
> consumer. That makes it a live defect, not just an item-20 blocker.
>
> A gap that is now measured rather than assumed: no schema in `external/indexer-plugins` carries a
> `container` field, `fim-files.json` included, so ten indices reject every container row and the
> **stateful documents are discarded**. Local `file_entry` rows and stateless events are unaffected,
> which is why detection works. That is #37203-3/-4, shipped from an external precompiled
> dependency, and not closable from this branch.
>
> Still open besides C27: item 20 (`container_instances`' create trigger), WP5 (A4 — host FIM
> whodata onto `rt_engine`), and WP6, which needs a portable per-architecture `vmlinux.h`, a
> load-tested object committed under `ebpf_provider/prebuilt/<arch>/`, and the four
> `check_files` CSV rows landing with it.

## Documents

| # | Document | Contents |
| --- | --- | --- |
| 01 | [What was actually built](01-work-done.md) | Module inventory, chosen mechanism, data-class coverage, how the two consumers drive it, testing, documentation |
| 02 | [Gap analysis against #37532](02-requirements-gap.md) | The eight deliverables, the acceptance criteria, constraint compliance, and what the branch got right |
| 03 | [Correctness findings](03-findings-correctness.md) | 28 findings: false deletes, truncated hashes, namespace collapse, userns, mount escape, volatile state, (C15–C20) the unreachable-connector mass delete, Docker's dropped reconcile and two checksum defects, (C21–C24) four defects found by measurement rather than reading — a rename that reports no deletion, attribute events carrying host paths, a re-read that races the write it was triggered by, and an absent configured path that disables delete detection for good — and (C25–C28) four found only by running the whole agent: a config block that was never dispatched, a modification that raises no alert, a path reconcile that deletes the rest of its container's rows, and a `list` reply that reads as an unreachable connector whenever the host has no containers |
| 04 | [Performance and scaling findings](04-findings-performance.md) | The `/proc` storm, the 1+N IPC pattern, per-row context duplication, unbounded buffering, no concurrency, no image de-dup — with a cost model and a micro-benchmark |
| 05 | [Clean design and reuse findings](05-findings-clean-design.md) | ~700 lines with in-tree equivalents, 36 near-identical functions, dead code, globals, build hygiene, inverted test coverage |
| 06 | [Proposed architecture](06-proposed-architecture.md) | Four structural changes, component design, **the baseline↔eBPF handoff algorithm**, timing model, collector seam, tiering, budgets, deletion semantics |
| 07 | [Options matrix](07-options-matrix.md) | The missing spike deliverable: 7 mechanisms × 11 data classes, primary + fallback per class, the in-container-exec rejection, the `setns` exception, edge-case table |
| 08 | [Remediation roadmap](08-roadmap.md) | 41 prioritised actions (P0 blockers → P4 spike deliverables) with effort estimates and suggested sequencing |
| 09 | [Implementation status](09-implementation-status.md) | What is implemented on `37532-5-0-0-container-integration`, what was deliberately deferred and why, plus environment findings |
| 10 | [`container_instances` delta plan](10-container-instances-delta-plan.md) | Roadmap item 20: how to publish the container lifecycle delta, and the gap-recovery invariant a baseline-once design needs |
| 11 | [`ebpf_provider` import plan](11-ebpf-provider-import-plan.md) | Roadmap item 21: importing #37396's extracted eBPF module, and the baseline↔eBPF handoff algorithm derived against its real contract |
| 12 | [Blocking decisions](12-blocking-decisions.md) | What to continue with next, and the decisions that block the roadmap (D1–D18) — including the finding that this branch is a truncated cut of `spike/37533-37534-…`, with 14 unintegrated commits that replace the inventory state model |
| 13 | [`container_baseline` API plan](13-container-baseline-api-plan.md) | The per-container FIM entry point the reconcile consumer needs, why it is one export rather than two, and the path guard it required — the first entry point to resolve a caller-supplied path |
| 14 | [Spike branch integration plan](14-spike-integration-plan.md) | `spike/37533-37534-…` reviewed as a whole against this branch: what was taken, the six work packages (WP1–WP4 done; WP5 and WP6 remain), the three things it settles — including a libfimdb claim that would have been a critical A3 defect, and the 2026-09-08 correction showing it de-risked less than it looked like — and the seven defects not to inherit |
| 15 | [How the feature works](15-spike-resume.md) | **Start here to understand the flow.** A diagrammed walk-through of what this branch implements: the three processes and one socket, how a `cgroup_id` becomes container metadata, the subscribe-first startup, the event-to-alert path and its four reconcile modes, the two writers of `file_entry`, and a table of what is and is not built |
| — | [`bench/`](bench/) | Reproducible micro-benchmark for the `/proc` resolver claim, plus captured output |

---

## Executive summary

### Verdict

The branch made **the right core technical decision and the wrong process decision.** Addressing
containers through `/proc/<pid>/root` — letting the kernel do the mount-namespace translation instead
of reconstructing overlay layers — is the correct answer to the spike's central question, and it is
implemented cleanly for eleven data classes with zero new dependencies. That mechanism choice should
be kept.

But #37532 is a **research spike** whose deliverables are eight documents and two validated
prototypes. The branch delivered ~2,150 lines of production-shaped C++ that ships in every Linux
agent, and **zero documents** (`git diff --stat -- '*.md'` is empty; no `.md` file in the repository
mentions 37532). The system-level questions the spike existed to answer — when does this run, how
does it hand off to eBPF, what does it cost at 100 containers, what happens when it cannot
finish — were never asked, and several were answered wrongly by default.

**0 of 8 deliverables produced. 3 partially satisfied by code that lacks its rationale.**

### The five things that matter most

> **Which of these five still stand, as of 2026-09-08.** #1 and #2 are closed: the handoff exists
> (`fc6e088b1a`), and a container started after syscheckd's startup is picked up by the resolver
> thread and baselined without anything seeding it — both measured on a real node. #3's four
> multipliers are removed (see [09](09-implementation-status.md)'s Done table, items 11, 12, 13, 22
> and 16). #4 and #5 are process findings about the spike and are unchanged by any commit. Read
> the five as the review's original diagnosis, not as current defects.

1. **It is not a baseline.** #37532's premise is *baseline once, then let the eBPF change stream
   maintain state*. The two consumers implemented two **opposite** models, neither of them that one:
   FIM runs the scan **once at startup**, synchronously on syscheckd's `main()` thread, and never
   again — so any container started later is never baselined. Syscollector re-scans **all eleven data
   classes for every container on every scan interval** (default 1 hour), which makes the eBPF stream
   largely redundant for those classes. Neither coordinates with eBPF in any way.

2. **The handoff algorithm — the issue's stated "correctness core" — does not exist.** No watermark,
   no buffering, no replay, no overflow-triggered re-scan. Worse, FIM picked the losing ordering:
   it baselines and *then* calls `realtime_start()`, so every change during the scan is lost. A
   correct algorithm (subscribe-first, scan, reconcile-by-re-read) is designed in
   [06 §6.3](06-proposed-architecture.md#63-the-baselineebpf-handoff).

3. **It does not scale to a realistic node.** Four independent multipliers, all avoidable:
   - `ResolvePidsForContainer` walks **all of `/proc`** per container, and is called **three times per
     container** — 300 full `/proc` walks per Syscollector scan at 100 containers, ~4–6 s of pure
     parsing producing no output. **The PID is already computed by `container_instances` and thrown
     away.** Measured structural reduction: **~300×**.
   - The IPC client does **1 + N round-trips** when the first reply already contains every record it
     then re-requests. **~100×** avoidable.
   - The container context blob is **copied into every row** — ~45 MB per Syscollector scan, ~300 MB
     per FIM run — and re-parsed per row on emission.
   - Both consumers **buffer the entire node's baseline in RAM** before the first DB write: 400 MB at
     the reference node, and up to ~4 GB at the `max_files` ceiling the code actually permits.

   There is **no concurrency anywhere**, no per-cycle budget, and no image de-duplication — even
   though four data classes read immutable image content and `image_digest` is already in hand.
   FIM's own rate limiter (`check_max_fps`) exists, is process-global, and is never called.
   NFR3 is unmet in every respect except two hardcoded per-path caps.

4. **Three correctness defects produce wrong security data.**
   - FIM **deletes the entire FIM state of a merely *stopped* container**, then re-creates it — a
     false-alert flood on container restart. The module's own header exports an API specifically to
     prevent this and warns against exactly this mistake; FIM never calls it, Syscollector does.
   - Hashes are **truncated at 100 MiB and emitted as if whole**. They cannot match any oracle, and
     two different files sharing a 100 MiB prefix hash identically — a tamper-evasion primitive in a
     file-integrity feature. Host FIM *skips* such files instead.
   - `strcmp(path->tag, "container")` means the feature **silently no-ops** for any ordinary
     `tags="container,prod"` configuration, since Wazuh tags are comma-separated.

   Add to these: `hostNetwork` collapse is undetected (the host's entire socket and interface
   inventory is attributed to each host-network container), pod-shared netns duplicates every socket
   N× across a pod's containers, the file walk has no mount boundary and can escape into the host
   filesystem via a `hostPath: /` mount, and file uid/gid are reported in the **host** id space while
   `/etc/passwd` ids are in the **container's**.

5. **A "no-in-container-execution" exception was silently adopted.** `setns(CLONE_NEWNET)` — what
   `nsenter --net` does — is used for interface collection. The issue named `nsenter` as a candidate
   to *"evaluate and most likely reject"* and required any unavoidable use to be *"explicitly
   justified and flagged as a documented exception, not silently adopted"*. My assessment is that the
   mechanism is **defensible** (it enters only the network namespace, executes no container code, and
   needs nothing in the image — so distroless still works, and there is genuinely no host-side way to
   get MAC/MTU/bound addresses). But it must be written up and signed off, and its silent
   `CAP_SYS_ADMIN` requirement must be logged with a degraded fallback rather than returning an empty
   result.

### What was done well

Worth stating plainly, since the findings list is long and the function-level craftsmanship is not
the problem:

- The `/proc/<pid>/root` mechanism choice is **correct** and covers Docker, containerd and CRI-O with
  one code path, no overlay arithmetic, and bind/volume/secret mounts for free.
- **Zero new dependencies**, honoured strictly — including reusing sysinfo's header-only package
  parsers without linking libsysinfo.
- **Distroless handled deliberately** (`/var/lib/dpkg/status.d` with a synthesised `Status:` line).
- The **rpmdb-over-`/proc` problem was correctly diagnosed and solved** (sqlite canonicalises the
  magic symlink onto a nonexistent host path), with the private-copy fix also solving read-only
  layers and stale WAL files.
- **Coverage exceeds the ask** — eleven inventory classes against the four-to-six requested.
- **DBSync scoped transactions** are a clean reuse, and make re-baselining naturally idempotent —
  a property the proposed architecture leans on heavily.
- The Syscollector integration's **first-sync-quiet guard** directly addresses the
  first-sync-after-reload data-loss class the issue flags, and its stopped-vs-gone handling is
  correct.
- **Parser-level unit testing is solid** — 1,232 lines over the fiddly decode paths.

### Recommended next steps

> **Largely executed — see [09](09-implementation-status.md).** Steps 1 and 2 are done, step 4's
> handoff algorithm is done (roadmap item 21), and step 3 is what documents 06–13 are. What is left
> of this list is the spike write-up's ratification (the `setns` exception sign-off) and benchmarking
> on a real multi-container node, which is also what would validate the handoff end to end.

Roughly one engineer-week clears the highest-severity findings:

1. **Days 1–3 — P0 correctness:** stopped-container deletes, hash truncation, the tag match,
   namespace-collapse detection, pod-socket duplication, truncation signalling, FIM transaction
   safety. All small, contained changes ([08 P0](08-roadmap.md#p0--correctness-blockers)).
2. **Days 4–5 — the cheap 300× and 100× wins:** kill the `/proc` sweep storm (ideally by publishing
   `pid` from `container_instances`, which already has it), collapse the 1+N IPC pattern by parsing
   the `list` reply, fix the two pathological queries ([08 P1](08-roadmap.md#p1--scaling-viable-at-100-containers)).
3. **Then — write the spike up.** Ratify the options matrix, get the `setns` exception signed off,
   and benchmark on a real multi-container node so the throttle defaults come from measurement rather
   than from guesswork ([08 P4](08-roadmap.md#p4--the-spike-deliverables)).
4. **Then — make it an actual baseline:** baseline-once plus a container-create trigger, tiered data
   classes with `image_digest` de-duplication, streamed per-container transactions, and the handoff
   algorithm once #37203-2's event contract exists ([06](06-proposed-architecture.md)).

At steady state, the proposed design shifts the dominant cost from "re-scan everything, hourly,
serially" to "handle the events that actually happened" — which is what the spike set out to achieve.
