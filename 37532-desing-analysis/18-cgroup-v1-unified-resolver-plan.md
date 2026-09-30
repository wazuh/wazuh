# 18. A unified cgroup v1/v2 resolver

Implementation plan for **O4** of the agent-side integration issue (#37203): what a cgroup v1 host
does to this feature today, and how to build one resolution engine that serves both hierarchies.

Everything in *Current behaviour* was read from the code on
`37532-5-0-0-container-integration` @ `f1bfcbd3e6`. Everything under *Proposed* is design, not
measurement, and is marked as such.

---

## 18.1 Why this is not just "FIM is off on v1"

`bpf_get_current_cgroup_id()` collapses to the root cgroup id — one constant for every task — on a
pure v1 hierarchy. That is a kernel property, not a bug we can fix, and it is why
`container_event_drain.cpp:429` refuses to start the event-driven reconcile there.

The damage is wider than that refusal, and it is silent. Three facts compose:

1. **The resolver only understands v2.** `parseCgroupV2Line()` accepts a line only if it begins
   `0::`, and returns `nullopt` otherwise. A pure v1 `/proc/<pid>/cgroup` has no `0::` line at all —
   only numbered controller lines (`11:devices:/docker/abc…`). Every line is rejected, so the scan
   returns no container entries.
2. **Every record therefore gets `cgroupId = 0`.** `docker_connector.cpp:66` joins the API snapshot
   against the resolver's inode map; a container absent from that map is assigned zero.
3. **`list` drops every zero-keyed record.** `metadata_store.cpp:118` skips any record whose
   `cgroupId == 0`, so the IPC `list` operation returns an empty array.

The consequence, which #37534 assumed was safe: **IT Hygiene is dead on v1 too.** Its container pass
discovers containers through `list`, and `list` is itself gated on the key the v1 host cannot
produce. The reasoning that inventory "does not use cgroup_id" is true of the *collection* path and
false of the *discovery* path.

And `container_instances` never detects cgroup v1 nor mentions it in any log. The module starts,
binds its socket, the connectors authenticate and return real containers — and then every one is
dropped for having a zero key. An operator sees a healthy module and no data, with nothing naming
the cause.

| Component | On a v1 host today |
| --- | --- |
| eBPF engine (`rt_open`) | warns, loads anyway (`rt_engine.c:445`) |
| Container FIM drain | refuses, logs ERROR naming cgroup v1 — **the only correct diagnosis emitted** |
| `container_instances` resolver | finds nothing, says nothing |
| `list` / IT Hygiene | empty, silently |
| Container baseline | never runs: no containers discovered |

---

## 18.2 The idea: separate two roles that happen to coincide on v2

One number currently plays two parts:

- **The store's index key** — what a record is filed under, so a consumer lookup finds it.
- **The eBPF correlation key** — what the kernel stamps into each event.

On v2 these are the same value, and that identity is the design's elegance: *"the two meet on one
number with no translation"* (#37382). On v1 they cannot be the same, because the kernel side is a
constant. Unifying the two hierarchies means **separating the two roles** and letting the host
decide which concrete key fills each.

The v1 correlation key already exists in the contract and is already populated: every event carries
`mnt_ns`, written at `rt_file.bpf.c:407` from `nsproxy->mnt_ns->ns.inum`. `rt_engine.c:460` already
tells consumers to use it. Nothing consumes it yet.

### Proposed key abstraction

```cpp
enum class KeyKind : std::uint8_t { cgroupInode, mntNsInode };

struct HostKey
{
    KeyKind       kind;
    std::uint64_t value;
};
```

`kind` is a **host constant**, decided once at startup from the mount layout — never per record, and
never inferred from an event. Mixing kinds within one store would reintroduce exactly the ambiguity
this is meant to remove.

| Host | Store index key | eBPF correlation key |
| --- | --- | --- |
| cgroup v2 (unified) | cgroup inode | `ev->cgroup_id` — unchanged, identical value |
| cgroup v1 (legacy) | canonical-controller cgroup inode | `ev->mnt_ns` |
| hybrid (v2 at `/sys/fs/cgroup/unified`) | treated as v2 | `ev->cgroup_id` |

Hybrid follows v2 because `bpf_get_current_cgroup_id()` returns unified-hierarchy ids there, which is
already how `detect_cgroup_v1()` classifies it.

---

## 18.3 Work packages

### WP1 — One shared host-mode probe *(prerequisite; ship regardless of O4's outcome)*

`detect_cgroup_v1()` lives in `rt_engine.c:138` and is private to the eBPF provider. Extract it to a
shared header so the provider and `container_instances` cannot reach different conclusions about the
same host — the failure mode ADR-001 warned about for capability probes, applied to cgroups.

Report three modes: `unified`, `legacy`, `hybrid`.

Then make `container_instances` **log its mode at startup, and log at ERROR when it is `legacy` and
no v1 support is compiled in**. This one change converts today's silent nothing into a diagnosable
failure, and it is worth doing before any decision on the rest of this plan.

Effort: S.

### WP2 — Teach the resolver v1 lines

Replace `parseCgroupV2Line()` with a `parseCgroupLine()` returning `{hierarchyId, controllers, path}`:

- v2: `0::/kubepods.slice/…/cri-containerd-abc.scope`
- v1: `11:memory:/kubepods/burstable/pod<uid>/abc…`

**`extractContainerId()` needs no change.** It matches the *leaf basename* against the runtime
naming schemes (`cri-containerd-|crio-|docker-` + hex, or bare hex for the cgroupfs driver), and
those leaves are identical on v1. This is the part of the design that already generalises for free.

What v1 adds is a choice the v2 path never had: **each controller is a separate mount with a
separate inode**, so the resolver must pick one deterministically. Proposed priority:
`memory` → `pids` → `cpu,cpuacct` → `name=systemd`. Any one works as a local index key provided it
is the *same* one everywhere; record the choice in the entry so a mismatch is detectable rather than
silently wrong. If none of the four is mounted, produce no key — the record is then unlisted exactly
as today, but the mode log from WP1 explains why.

Effort: M.

### WP3 — Read the mount-namespace inode during the same walk

The scan already iterates `/proc/<pid>` and opens `/proc/<pid>/cgroup`. Add one `stat` of
`/proc/<pid>/ns/mnt` per pid and carry `mntNsInode` alongside `cgroupInode` in `CgroupEntry`.

Cost is one extra stat per process per scan, on a walk that already does one open and one read per
process.

Populate **both** keys on **both** hierarchies, not just the one in use. It makes the v1 and v2 paths
structurally identical, and it lets a v2 host cross-check attribution during testing.

Effort: S.

### WP4 — Key the store by `HostKey`

- `m_byCgroup` → `m_byHostKey`
- `lookupByCgroup(std::uint64_t)` → `lookup(HostKey)`
- `listContainers()`'s `record->cgroupId == 0` guard → "record has a valid host key"

The verdict and pending machinery (`upsertVerdict`, `upsertPending`, liveness eviction against
`allInodes`) is already key-agnostic — it stores and compares an opaque integer. `allInodes` becomes
"all observed keys of the host's kind".

**This is the package that unblocks IT Hygiene**, because it is what makes `list` return records
again.

Effort: M.

### WP5 — Protocol version 2

The wire carries a field literally named `cgroup_id`, and `PROTOCOL_VERSION` is checked by **strict
equality**, so client and server must move together.

```jsonc
// v1 (current)
--> {"version":1,"op":"resolve","cgroup_id":"44522"}

// v2 (proposed)
--> {"version":2,"op":"resolve","key_kind":"mnt_ns","key":"4026532281"}
<-- {"version":2,"status":"resolved","data":{…}}
```

Two additions worth making at the same time:

- Accept `cgroup_id` for one version as an alias for `key_kind:"cgroup"`, so the two sides can be
  rolled independently once.
- Extend `status` to report the host's `key_kind`, so a consumer **discovers** which key to send
  instead of probing the host itself. Two components independently classifying the same host is the
  defect WP1 exists to prevent; the protocol should not reintroduce it.

Keep the decimal-string encoding. `mnt_ns` is a 32-bit inode today, but the field is the same JSON
slot that carries 64-bit cgroup inodes, and the cJSON-double hazard has not gone away.

Effort: M.

### WP6 — Drain selects the key by host mode

Replace the refusal at `container_event_drain.cpp:429` with selection:

```cpp
const auto key = (hostMode == CgroupMode::legacy)
                     ? HostKey{KeyKind::mntNsInode, ev->mnt_ns}
                     : HostKey{KeyKind::cgroupInode, ev->cgroup_id};
```

`cgroup_container_map` and the router's `onEvent`/`onUnlink`/`onRename`/`onDrops` signatures become
key-kind aware. Keep a refusal for the case where **neither** key is usable, so the "wrong
attribution is worse than none" rule still has a floor to stand on.

Effort: M–L. This is the largest package and the only one that touches FIM's hot path.

### WP7 — IT Hygiene

No dedicated work. Syscollector discovers through `list` and collects through
`/proc/<pid>/root` + `setns`, neither of which uses the correlation key. It starts working when WP4
lands.

---

## 18.4 What `mnt_ns` costs us, stated honestly

It is a weaker key than the cgroup inode, and the plan should not pretend otherwise.

| Case | Behaviour | Handling |
| --- | --- | --- |
| Containers in a Kubernetes pod | **Each has its own mount namespace** (unlike the network namespace, which is shared), so pod-mates stay distinguishable | works |
| Host processes | share the root mount namespace | resolves to the existing `host_process` verdict, same as the v2 root cgroup |
| `unshare -m` inside a container | the process gets a mount namespace the resolver never saw | unknown key → existing pending/escalation path; attribution is lost for that process until the next scan. **Document as a v1 limitation** |
| Two containers deliberately sharing a mount namespace | one key, two containers | must resolve **ambiguous**, never pick one (delete-safety rule 5) — needs an explicit verdict reason |
| `cgroupns=host` containers | already a documented v2 limitation | unchanged |

There is also an honest asymmetry to record in the release notes: on v1 the feature is *correlating
on a namespace*, not on a cgroup, and the two do not fail in the same ways.

---

## 18.5 Phasing — and how it maps onto the O4 decision

The packages split cleanly along the exact line O4 asks about.

| Phase | Packages | Delivers | O4 option |
| --- | --- | --- | --- |
| **0** | WP1 | v1 detected and logged; silent failure becomes diagnosable | ship regardless |
| **1** | WP2 + WP3 + WP4 | container **inventory and baseline** work on v1. No protocol change, no FIM change | *"inventory-only support"* |
| **2** | WP5 + WP6 | event-driven container **FIM** works on v1, correlating on `mnt_ns` | *"full support"* |

Phase 1 needs no wire-protocol change, because syscollector only calls `list`. That is a genuinely
useful property: **inventory-only v1 support is reachable without touching the IPC contract or FIM's
hot path**, which makes it a far smaller commitment than Phase 2.

If the decision is instead *"declare the feature cgroup-v2-only"*, **Phase 0 is still required** —
otherwise RHEL 8 and Amazon Linux 2 operators get a module that appears healthy and produces nothing.

---

## 18.6 Verification

**Reproducing a v1 host cheaply.** Ubuntu boots v2, but `systemd.unified_cgroup_hierarchy=0` on the
kernel command line plus a reboot gives a pure v1 hierarchy on the existing `wazuh_manager` VM — no
new box needed. RHEL/Alma 8 and Amazon Linux 2 boot v1 by default and remain the fleet-accurate
targets.

**Negative control first, as with every change in this branch.** On the v1 host, with today's build:
confirm `list` returns `[]` and the container baseline reports zero containers. That failing
baseline is what the phase-1 build has to flip; without capturing it first, a passing run proves
nothing.

| Level | What |
| --- | --- |
| Unit | `parseCgroupLine()` fixtures: pure v2, pure v1 (multi-controller), hybrid, and a malformed line. Controller-priority selection when `memory` is absent |
| Unit | `extractContainerId()` against v1 leaves for docker, containerd and CRI-O, systemd and cgroupfs drivers — asserting the existing regexes need no change |
| Contract | store keyed by `HostKey`: both kinds, verdict liveness, `list` filtering |
| Integration | the `~/e2e-int` harness on a v1 host: `list` non-empty, inventory events carry `container.*`, FIM refused in phase 1 and working in phase 2 |
| Regression | the whole v2 capture from §15.10 re-run unchanged — the v2 path must be byte-identical, since `HostKey{cgroupInode, …}` carries the same number it does today |

That last row is the one that matters most: this plan changes the shape of code that currently works
on every supported host. The v2 evidence in §15.10 is the baseline it has to reproduce.

---

## 18.7 Open questions

1. **Is `mnt_ns` stable enough to be a correlation key in production?** Measured behaviour under
   container restart, `docker exec`, and init systems inside containers is unknown. Worth a probe
   before committing to Phase 2.
2. **Which controller should be canonical on v1?** The priority list above is a proposal; a survey of
   what RHEL 8 and AL2 actually mount by default would settle it.
3. **Does the 32-bit `mnt_ns` field need widening?** Namespace inodes are inode numbers; the contract
   declares `unsigned int`. Confirm against the kernel type before it becomes a wire value.
4. **Should Phase 2 exist at all?** Correlating FIM on a namespace rather than a cgroup is a
   different security property. If the answer is no, WP5/WP6 drop and O4 resolves to
   "inventory-only, permanently".
