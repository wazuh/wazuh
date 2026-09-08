# 07 — Baseline-mechanism options matrix

This is deliverable **D1** of #37532, reconstructed. The branch chose mechanisms implicitly by
implementing one of them per data class; no alternative was evaluated and no fallback exists. This
document supplies the comparison and the primary/fallback selection so the decision can be reviewed.

## 7.1 Mechanisms under evaluation

| ID | Mechanism | How |
| --- | --- | --- |
| **M1** | Host overlay/rootfs read | Locate the runtime's merged dir (`/var/lib/docker/overlay2/<id>/merged`, containerd snapshots, CRI-O) or reconstruct from `lowerdir`/`upperdir`, then read host-side |
| **M2** | `/proc/<pid>/root` addressing | Let the kernel translate the container's mount-namespace view; read through the magic symlink |
| **M3** | `/proc` scan, cgroup-scoped | Enumerate host `/proc`, filter by the container's cgroup; read `stat`, `cmdline`, `net/*`, `ns/*` |
| **M4** | `setns(CLONE_NEWNET)` + native API | Enter the container's *network* namespace on a throw-away thread; call `getifaddrs`/`ioctl`/netlink |
| **M5** | Host cgroupfs read | Read the container's resource envelope from the host's `/sys/fs/cgroup/<path>` |
| **M6** | eBPF-derived / replay-from-create | Derive initial state from observing the runtime create and start the container |
| **M7** | In-container execution | `docker exec` / CRI `Exec` / `kubectl exec` / `nsenter --mount --pid` a reader inside the container |

## 7.2 The matrix

Legend — **Works**: produces correct, complete data. **No-exec**: complies with the
no-in-container-execution constraint. **No-dep**: adds no external dependency.
**Cost**: L/M/H. **Coverage**: which runtimes.

| Data class | Mech | Works | No-exec | No-dep | Cost | Coverage | Correctness caveats |
| --- | --- | :-: | :-: | :-: | :-: | --- | --- |
| **File metadata** | **M2** ✅ *primary* | ✅ | ✅ | ✅ | L | all | Needs a live PID. Host-side `st_uid` under userns ([C7](03-findings-correctness.md#c7--uidgid-semantics-are-inconsistent-between-data-classes-and-wrong-under-user-namespaces)). Crosses mount boundaries — needs a policy ([C8](03-findings-correctness.md#c8--the-file-walk-has-no-mount-boundary-guard-and-can-escape-into-the-host-filesystem)). |
| | M1 *fallback* | ⚠️ | ✅ | ✅ | M | per-runtime | Whiteouts, opaque dirs, layer assembly, per-runtime snapshot layout. **Does not see bind/volume/secret mounts at all** — a decisive weakness. Works with no live PID, which is its one advantage. |
| | M7 | ✅ | ❌ | ❌ | H | all | Rejected — §7.4. |
| **File hash** | **M2** ✅ *primary* | ✅ | ✅ | ✅ | H (I/O) | all | Must skip, not truncate, above the size limit ([C2](03-findings-correctness.md#c2--truncated-hashes-are-emitted-as-if-they-were-whole-file-hashes)). Honour `CHECK_*` flags. Sparse/special files must be excluded. |
| | M1 *fallback* | ⚠️ | ✅ | ✅ | H | per-runtime | Same as above, plus mount-invisibility: hashes files the container may not even see. |
| **Processes** | **M3** ✅ *primary* | ✅ | ✅ | ✅ | L | all | Scope by **cgroup**, not pid-ns — correct under `hostPID`. Race: PID exits between enumerate and read. |
| | M6 *fallback* | ⚠️ | ✅ | ✅ | L | all | Can maintain but **cannot enumerate** pre-existing processes; only viable for containers that start after the agent. |
| **Network ports** | **M3** ✅ *primary* | ⚠️ | ✅ | ✅ | L | all | Two real traps: pod-shared netns duplicates rows N× ([C5](03-findings-correctness.md#c5--kubernetes-pod-shared-netns-duplicates-every-socket-across-every-container-in-the-pod)); `hostNetwork` collapses scope to the host ([C4](03-findings-correctness.md#c4--hostnetwork--hostpid-collapse-is-undetected-host-state-attributed-to-a-container)). Both must be detected explicitly. Attribute only sockets whose inode maps to a PID in *this* cgroup. |
| | M4 *fallback* | ✅ | ⚠️ | ✅ | L | all | Needs `CAP_SYS_ADMIN`; see §7.4. |
| **Interfaces / addresses** | **M4** ⚠️ *primary, documented exception* | ✅ | ⚠️ | ✅ | L | all | **No `/proc/<pid>/`-relative view exists** — sysfs and netlink answer for the caller's netns. Requires `CAP_SYS_ADMIN`; currently degrades to an empty result with no log. Under `hostNetwork` reports host interfaces as the container's. |
| | M3 *fallback* | ⚠️ | ✅ | ✅ | L | all | `/proc/<pid>/net/dev` gives names + counters only — no MAC, no MTU, no bound addresses. Strictly weaker, but fully no-exec and needs no capability: the right degraded mode when `CAP_SYS_ADMIN` is absent. |
| **Routes / protocols** | **M3** ✅ *primary* | ✅ | ✅ | ✅ | L | all | `/proc/<pid>/net/route` is namespace-relative — no `setns` needed. IPv4 only today; IPv6 needs `ipv6_route` (different layout). |
| **Users / groups** | **M2** ✅ *primary* | ✅ | ✅ | ✅ | L | all | Reports in-container ids — correct, but inconsistent with M2's host-side file `st_uid` ([C7](03-findings-correctness.md#c7--uidgid-semantics-are-inconsistent-between-data-classes-and-wrong-under-user-namespaces)). Distroless: absent ⇒ empty, handled. Misses LDAP/SSSD-backed users (a documented limitation, same as host). |
| **Packages** | **M2** ✅ *primary* | ✅ | ✅ | ✅ | M–H | all | rpm sqlite backend cannot be opened over the `/proc` magic symlink — needs the private-copy workaround (already solved, `package_scanner.cpp:63-94`). BDB vs sqlite backend selection. Distroless `status.d` layout. Image-derived ⇒ cacheable by digest. |
| | M7 | ✅ | ❌ | ❌ | H | all | Would avoid all DB-format parsing by running the package tool. Rejected — §7.4. |
| **OS** | **M2** ✅ *primary* | ✅ | ✅ | ✅ | L | all | `/etc/os-release` then `/usr/lib/os-release`. Kernel is necessarily the **host's** — must be labelled as such. Scratch images: absent ⇒ empty. |
| **Services** | **M2** ⚠️ *primary* | ⚠️ | ✅ | ✅ | L | all | Static unit-file view only: `state` is always `"unknown"` because runtime state needs the container's own systemd over D-Bus. Most containers run no init at all, so the class is of limited value. Image-derived ⇒ cacheable. |
| **Hardware** | **M5** ⚠️ *primary* | ⚠️ | ✅ | ✅ | L | cgroup v2 | Reports the cgroup envelope + **host** CPU model/speed. `memory_used`/`free` are metrics, not state ([C9](03-findings-correctness.md#c9--volatile-counters-in-state-rows-make-every-periodic-scan-a-full-change-event)). cgroup v1 unsupported. Questionable as an inventory class at all. |
| **Any class, Kata / VM-isolated** | — | ❌ | — | — | — | none | The host cannot see the guest rootfs or namespaces. Out of scope, consistent with eBPF. `container_instances` already classifies these (`VerdictReason::kata`) — the baseline must skip them explicitly rather than produce empty rows. |

## 7.3 Primary + fallback selection

| Data class | Primary | Fallback | Degraded mode |
| --- | --- | --- | --- |
| File metadata + hash | **M2** `/proc/<pid>/root` | M1 overlay merged dir (only when no live PID exists) | Metadata without hash when over size limit |
| Processes | **M3** cgroup-scoped `/proc` | — | — |
| Ports | **M3** + inode→cgroup attribution | M4 | Emit nothing on host-netns collapse |
| Interfaces / addresses | **M4** `setns` *(documented exception)* | **M3** `/proc/<pid>/net/dev` | Names + counters only, no MAC/MTU/addresses |
| Routes | **M3** | — | IPv4 only until `ipv6_route` is added |
| Users / groups | **M2** | — | Empty on distroless |
| Packages | **M2** + private-copy for rpm sqlite | — | Empty on distroless without `status.d` |
| OS | **M2** | — | Empty on scratch |
| Services | **M2** static view | — | `state = unknown` always |
| Hardware | **M5** cgroup v2 | cgroup v1 controller paths | Omit when cgroup not visible |

**M2 is the primary mechanism for six of ten classes, M3 for three.** That concentration is the
branch's key insight and deserves to be stated as the headline decision: *one addressing scheme,
`/proc/<pid>/root` plus cgroup-scoped `/proc`, covers Docker, containerd and CRI-O identically, with
no overlay arithmetic and no per-runtime snapshot knowledge.* M1 survives only as a narrow fallback
for containers with no live PID, and it is strictly worse wherever mounts matter.

## 7.4 In-container execution: evaluation and rejection (deliverable D6)

### What M7 would genuinely solve better

Stated honestly, because the rejection is only defensible if the trade-off is real:

1. **userns-remapped ownership.** A reader inside the container sees the container's own uid/gid
   directly, eliminating the `uid_map` translation and the [C7](03-findings-correctness.md#c7--uidgid-semantics-are-inconsistent-between-data-classes-and-wrong-under-user-namespaces) inconsistency entirely.
2. **Exotic package DB formats.** Running `rpm -qa` / `dpkg -l` delegates format parsing to the tool
   that owns it — no BerkeleyDB reader, no sqlite blob parsing, no private-copy workaround, and
   immunity to future backend changes.
3. **Name resolution.** `getpwuid()` inside the container resolves LDAP/SSSD/NSS-backed users that
   reading `/etc/passwd` cannot see.
4. **Interfaces without `CAP_SYS_ADMIN`.** `ip addr` inside the container needs no host capability.
5. **No live-PID requirement** for `docker exec` (the runtime starts a process for you).

### Why it is rejected

| Reason | Detail |
| --- | --- |
| **Explicitly excluded** | The #37203-4 "no in-container execution" constraint is a hard requirement, not a preference. |
| **Requires something in the image** | Distroless and `scratch` images have no shell and no package tooling. The mechanism fails exactly where M2 succeeds — and distroless is a *growing* share of production workloads. |
| **New dependency** | CRI `Exec` needs a gRPC/protobuf client; `docker exec` needs the Docker API or CLI. Both violate the no-external-dependency constraint feature-wide. |
| **Privilege escalation surface** | `exec` is write-equivalent runtime privilege. An agent that can exec into any container is a far more valuable target than one that can only read `/proc`. |
| **Observability side-effects** | It creates processes inside the monitored workload — polluting the very process inventory being collected, and potentially tripping the container's own security policy. |
| **Reliability** | Depends on the runtime API being healthy; M2 depends only on the kernel. |

**Verdict: reject M7 for all data classes.** No class has a host-side answer weak enough to justify
it: the userns problem is solved by `uid_map` translation, package formats are already solved in
code, and NSS-backed users are a documented limitation shared with the host agent.

### The one exception that must be documented and signed off

**M4 (`setns(CLONE_NEWNET)`) for interfaces and addresses.** It is what `nsenter --net` does, and the
issue named `nsenter` as a candidate to *"evaluate and most likely reject"*, requiring that any
unavoidable use be *"explicitly justified and flagged as a documented exception, not silently
adopted"*. It was silently adopted (`interface_scanner.cpp:149-162`).

My assessment: **accept it, with conditions.** It is materially weaker than M7 —

- it enters **only** the network namespace, never the mount or pid namespace;
- it executes **no code inside the container** and requires **nothing present in the image**, so
  distroless is unaffected;
- there is **no host-side alternative** that yields MAC, MTU and bound addresses: sysfs and netlink
  answer for the caller's netns, and `/proc/<pid>/net/dev` gives only names and counters;
- it is the same technique `ip netns exec` uses and needs no new dependency.

Conditions for accepting it:

1. Write it up as a decision record and get #37203-4 sign-off.
2. **Log** when `setns` fails for lack of `CAP_SYS_ADMIN` instead of returning an empty scan silently,
   and fall back to the M3 degraded mode (`/proc/<pid>/net/dev`) so the class is not simply absent.
3. Never extend the technique to `CLONE_NEWNS`/`CLONE_NEWPID` — that would cross into genuine
   nsenter-equivalence and must go back for review.

## 7.5 eBPF-assisted baseline (M6): assessed and set aside

The issue asks whether any baseline could be derived from eBPF rather than a scan — specifically,
whether observing the runtime unpack a rootfs and exec PID 1 could substitute for a file walk on
containers that start *after* the agent.

Assessment: **not viable as a substitute, useful as an optimisation later.**

- It cannot help the case that most needs help: containers **already running** at agent start have no
  replayable history. Those always need a scan, so the scan code exists regardless.
- Maintaining two baseline paths (replay-based for new containers, scan-based for pre-existing ones)
  doubles the correctness surface for no reduction in code.
- Replay correctness depends on having observed *every* write since container creation — which
  requires exactly the lossless-buffering guarantees that [06](06-proposed-architecture.md#63-the-baselineebpf-handoff)'s handoff provides. Build that first.
- eBPF cannot enumerate a cgroup's pre-existing tasks on attach. Whether #37203-2 exposes an
  enumerate-on-attach hook is an open question to raise with that spike; absent one, user-space
  `/proc` walking (M3) is required.

**Recommendation:** keep M6 out of v1. Revisit once the handoff is implemented and measured — at
which point the interesting question becomes whether a *freshly created* container can skip its
file-walk entirely, which is a genuine saving on high-churn nodes.

## 7.6 Runtime parity and edge cases (deliverable D8)

| Case | Behaviour | Status |
| --- | --- | --- |
| Docker (overlay2) | M2 — no overlay knowledge needed | ✅ Works by construction |
| containerd / CRI (kind, K8s) | M2 — identical code path | ✅ Works by construction |
| CRI-O | M2 — identical code path | ✅ Works by construction; cgroup leaf pattern `crio-<id>.scope` is handled (`pid_resolver.cpp:45-47`) |
| Distroless / scratch | Absent files ⇒ empty rows; `status.d` package layout handled | ✅ Handled deliberately |
| userns-remapped | File uid/gid reported in **host** id space | ❌ Unhandled — [C7](03-findings-correctness.md#c7--uidgid-semantics-are-inconsistent-between-data-classes-and-wrong-under-user-namespaces) |
| Read-only rootfs | Reads only; rpm private-copy avoids writing to the layer | ✅ Handled |
| tmpfs / secret mounts | Visible via M2; may be root-only | ⚠️ Works, but no policy on whether secrets *should* be hashed and reported |
| Short-lived / init containers | PID may exit mid-scan ⇒ silent partial result | ❌ Unhandled — [C10](03-findings-correctness.md#c10--arbitrary-pid-selection-with-no-liveness-strategy) |
| `hostNetwork` / `--network=host` | Host sockets and interfaces reported as the container's | ❌ Unhandled — [C4](03-findings-correctness.md#c4--hostnetwork--hostpid-collapse-is-undetected-host-state-attributed-to-a-container) |
| `hostPID` / `--pid=host` | Processes still cgroup-scoped, so *safe*; container sees host processes the baseline omits | ⚠️ Safe but undocumented asymmetry |
| Pod-shared netns (multi-container pods) | Sockets duplicated per container | ❌ Unhandled — [C5](03-findings-correctness.md#c5--kubernetes-pod-shared-netns-duplicates-every-socket-across-every-container-in-the-pod) |
| Kata / VM-isolated | Host cannot see guest state | ⚠️ Correctly out of scope; needs an explicit skip rather than empty rows |
| cgroup v1 hosts | Hardware class returns nothing | ⚠️ Documented in a `ponytail:` comment, not in any doc |
