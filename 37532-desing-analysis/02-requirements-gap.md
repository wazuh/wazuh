# 02 — Gap analysis against issue #37532

Issue: [wazuh/wazuh#37532](https://github.com/wazuh/wazuh/issues/37532) — *"Spike: Baseline acquisition —
how FIM & Syscollector build the initial container state that eBPF then diffs"*.
Labels: `type/research`, `spike`. State: OPEN.

## 2.1 The category error

#37532 is a **research spike**. Its deliverables are eight documents and two validated prototypes; its
acceptance criteria are about *decisions being reviewed and signed off*, not about production code
existing. The branch delivered the inverse: ~2,150 lines of production-shaped, CMake-registered,
consumer-wired C++ that ships in `libcontainer_baseline.so` and runs unconditionally on every Linux
agent — and **zero documents**.

That inversion is the root of most gaps below. Decisions that a spike would have surfaced for review
(the `setns` exception, the throttle defaults, the scan-vs-subscribe ordering, whether re-scanning
hourly is the intended model) were instead made silently in code, and three of them are wrong.

## 2.2 Deliverables

| # | Deliverable required by #37532 | Delivered | Assessment |
| --- | --- | --- | --- |
| D1 | **Options matrix**: mechanism × data class × (works? no-exec? no-new-dep? cost? runtime coverage? caveats), with chosen primary + fallback per data class | ❌ None | No document. A primary mechanism was *implicitly* chosen per class by writing one implementation; no alternative was evaluated, no fallback exists for any class. Reconstructed in [07-options-matrix.md](07-options-matrix.md). |
| D2 | **Rootfs/overlay resolution note (per runtime)**: Docker overlay2, containerd snapshots, CRI-O; whiteout/opaque/userns caveats | ❌ None | The `/proc/<pid>/root` choice makes per-runtime resolution unnecessary — a genuinely good outcome that is *nowhere written down*. Whiteout handling was implemented (`IsOverlayWhiteout`) but is dead code under this mechanism (see [03](03-findings-correctness.md#c13--dead-overlay-whiteout-handling-signals-an-unresolved-mechanism-choice)). userns is unhandled and undocumented. |
| D3 | **Host-side baseline design**: file walk + hashing procedure and `/proc`-scoped process/network enumeration | ⚠️ Code only | The code exists and works. There is no design document, and the design it embodies has the scaling defects in [04](04-findings-performance.md). |
| D4 | **Baseline↔eBPF handoff algorithm**: ordering/buffering/replay guaranteeing no lost and no double-counted change; re-baseline triggers; first-sync-after-reload wiring | ❌ None | **The issue's stated "correctness core" is entirely absent.** No watermark, no buffering, no replay, no overflow-triggered re-scan. `grep -rn "watermark\|replay\|handoff\|re-baseline"` over `syscheckd`, `wazuh_modules`, `shared_modules` returns nothing relevant. Explicitly deferred in `container_baseline_fim.h:38-39`. Designed in [06](06-proposed-architecture.md#63-the-baselineebpf-handoff). |
| D5 | **Timing & triggering model**: agent start / container-create / reload / periodic reconciliation | ⚠️ Contradictory | Two consumers implemented two *opposite* models, neither documented, neither matching the issue. FIM: one-shot at startup only. Syscollector: full re-scan hourly. No container-create trigger on either side (`container_instances` exposes no subscribe API). |
| D6 | **In-container-exec evaluation**: explicit accept/reject for `docker exec` / CRI `Exec` / `nsenter` | ❌ None | Never evaluated in writing. Worse: a namespace-entry mechanism (`setns(CLONE_NEWNET)`) *was silently adopted* for interfaces/addresses without the "documented exception" the issue mandates. See §2.4. |
| D7 | **Cost & limits report**: wall-clock/IO per rootfs size, cold-start-storm behaviour, image-digest de-dup saving, benchmarked throttle defaults | ❌ None | No benchmark exists. The two limits that shipped (`max_files = 20000`, `max_hash_bytes = 100 MiB`) are hardcoded magic numbers in `container_baseline_fim_bridge.c:157-212`, unbenchmarked, with no config knob and no log when they truncate. Cold-start storm is unbounded and serial. Image-digest de-dup was never attempted despite being the single largest available saving. Measured in [04](04-findings-performance.md). |
| D8 | **Docker parity + edge-case table**: distroless / userns / read-only rootfs / short-lived / Kata | ⚠️ Partial in code | Distroless handled well and deliberately (`status.d` parsing, absent-file → empty result). Kata is handled *upstream* by `container_instances` (`VerdictReason::kata`). userns, read-only rootfs, and short-lived containers are unhandled. No table. |

**Score: 0 of 8 deliverables produced. 3 partially satisfied by code that lacks its rationale.**

## 2.3 Acceptance criteria

| Criterion | Met | Notes |
| --- | --- | --- |
| Options matrix reviewed by FIM and Syscollector spike owners; primary + fallback agreed; no-exec and no-new-dep constraints explicitly satisfied or exception signed off | ❌ | No matrix to review. No fallback per data class. The `setns` exception is neither documented nor signed off. |
| Host-side prototype on kind produces correct FIM rows (hash matching an in-container oracle) + process/network baseline for ≥1 Docker and ≥1 containerd/CRI container, **without executing inside the container** | ⚠️ | `qa/m4..m6_runner.cpp` are real, working harnesses against real containers — but they are hand-compiled from a `g++` line in a comment, not in CI, and there is **no hash-vs-`sha256sum`-oracle comparison anywhere**. The criterion's central validation was not performed. |
| Handoff algorithm demonstrated to lose no change and double-count no change when a modification races the scan | ❌ | No algorithm, therefore no demonstration. The FIM ordering actually chosen (baseline *then* `realtime_start()`) is the losing ordering. |
| Rootfs/overlay resolution validated for Docker overlay2 + containerd snapshots, CRI-O designed; whiteout/userns caveats documented | ⚠️ | Made moot by `/proc/<pid>/root` — correct engineering, undocumented. userns caveat not documented and not handled. |
| Users/packages host-side feasibility incl. distroless documented well enough for #37203-4's in/out decision | ⚠️ | Feasibility *proven in code* (the strongest part of the branch), but #37203-4 gets no document to decide from. |
| Re-baseline triggers and first-sync-after-reload wiring reviewed against the known data-loss failure class | ⚠️ | No re-baseline triggers exist. First-sync *is* addressed on the Syscollector side (`m_knownContainerIds` + `notifyOverride`, `syscollectorImp.cpp:1961-1963`) — a real and thoughtful contribution. Not addressed on the FIM side. |
| Cost numbers back the throttle/limit defaults; cold-start-storm behaviour bounded | ❌ | No numbers; defaults unjustified; storm unbounded. |
| Dependencies cross-referenced (#37203-1/-2/-3/-4) | ⚠️ | `#37203-1` is consumed correctly. `#37203-2` (eBPF contract, overflow signal) is not referenced at all. `#37203-3/-4` schema is acknowledged as *unresolved* in code comments (`baseline_rows.hpp:59-64`) rather than resolved. |

## 2.4 Constraint compliance

| Constraint | Status | Evidence |
| --- | --- | --- |
| **No external dependencies** — no runtime SDK, no CRI gRPC/protobuf, no `nsenter`/`crictl`/`docker` CLI | ✅ **Fully satisfied** | Everything is `/proc`, `/sys`, and vendored libs already in-tree (OpenSSL EVP, sqlite3, libdb, nlohmann). No new third-party dependency. Reusing sysinfo's header-only parse helpers without linking libsysinfo (`package_scanner.cpp:4-11`) is a genuinely elegant way to honour this. |
| **No in-container execution** | ⚠️ **Satisfied in letter, undocumented deviation in spirit** | No binary is ever executed inside a container, and nothing needs to be present in the image — so the hard constraint holds, including for distroless. **But** `ScanContainerInterfaces` calls `setns(/proc/<pid>/ns/net, CLONE_NEWNET)` (`interface_scanner.cpp:149-162`), which is precisely what `nsenter --net` does. The issue named `nsenter` as a candidate "to evaluate and most likely reject", and required that any unavoidable use be "explicitly justified and flagged as a documented exception, not silently adopted". It was silently adopted. It also silently requires `CAP_SYS_ADMIN`, degrading to an empty result without a log when absent. My assessment: the mechanism is **defensible** (it enters only the network namespace, executes no container code, needs nothing in the image) but it must be written up and signed off, and its capability requirement must be logged rather than silently swallowed. |
| **Both connectors (K8s containerd/CRI-O + Docker) over the same seam** | ✅ | One `/proc/<pid>/root` path for all runtimes. `container_instances` abstracts the identity side. |
| **Baseline reads from the host** | ✅ | All reads are host-side. |
| **Bounded cost (NFR3)** — throttled and limited so it does not stall the agent or the node | ❌ **Violated** | Two per-path caps exist but nothing else: no rate limiting, no concurrency bound, no cap on containers, no total-work budget, no CPU/IO throttle. FIM blocks syscheckd's `main()` for the whole scan plus up to ~10 s of fixed sleeps; syscollector blocks its scan thread. Both buffer the entire result set in RAM before writing. See [04](04-findings-performance.md). |

## 2.5 What the branch got right

Stated plainly, because the gaps above are long and the engineering underneath is not bad:

1. **The core mechanism choice is correct.** `/proc/<pid>/root` sidesteps overlay arithmetic, per-runtime
   snapshot layouts, whiteouts and opaque dirs entirely, and covers bind mounts / volumes / secret
   tmpfs for free. This is the right answer to the spike's central question, arrived at and
   implemented — it just needed to be *argued* in a document.
2. **Zero new dependencies, honoured strictly**, including the neat trick of using sysinfo's
   header-only package parsers without dragging in libsysinfo.
3. **Distroless is handled deliberately**, not accidentally — `/var/lib/dpkg/status.d` per-package
   files with a synthesised `Status:` line (`package_scanner.cpp:225-265`).
4. **The rpmdb-over-`/proc` problem was correctly diagnosed and solved** (sqlite canonicalises the
   magic symlink onto a host path that doesn't exist), with the private-copy workaround also solving
   read-only-layer and stale-WAL issues (`package_scanner.cpp:55-94`).
5. **Coverage exceeds the ask** — eleven inventory classes vs. the four-to-six requested.
6. **DBSync scoped transactions** are a clean reuse: a per-container scope means one container's scan
   can never delete another's rows, and empty-row-set-as-delete falls out naturally.
7. **The Syscollector integration's first-sync-quiet guard** directly addresses the
   "first-sync-after-reload data-loss failure class" the issue flags.
8. **Parser-level unit testing is solid** — 1,232 lines covering the fiddly decode paths
   (hex socket addresses, `/proc/pid/stat` comm-with-parens, os-release quoting, cgroup `cpu.max`).

The problem is not craftsmanship at the function level. It is that the *system-level* design questions
the spike existed to answer — when does this run, how does it hand off to eBPF, what does it cost at
100 containers, what happens when it can't finish — were never asked.
