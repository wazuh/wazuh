# 20 — Why a legacy-cgroup host needs `mnt_ns` as its key, and why that forces `RT_CGROUP_MODE_ALL`

**Subject:** the two consequences of correlating container events on a mount namespace instead of a
cgroup, both of which were found by measurement rather than by reading, and neither of which is
stated in `18-cgroup-v1-unified-resolver-plan.md` as written.

**Date:** 2026-10-06 · **Branch:** `37532-cgroup-v1-unified-resolver` · **Issues:** #37203 (O4) / #37532 / #37396

**Verdict:** `mnt_ns` works as a correlation key, but it is **unique in space and not in time** — the
kernel hands the same inode number to the next container started. Three mechanisms in the store
assume the opposite. Separately, the in-kernel allowlist **as the BPF program is written today**
cannot select containers on such a host, so phase 2 built on the current object has to run
`RT_CGROUP_MODE_ALL` and filter in userspace, carrying back the cost that `541077159e` was written
to remove.

> **Correction, 2026-10-06, after this document's first revision.** The paragraph above originally
> said the kernel *cannot* supply a per-container number on a legacy host. That is false, and the
> distinction matters more than anything else here: the **helper** cannot, the **kernel** can. A BPF
> program can read the v1 controller's cgroup id directly, which removes both problems in this
> document rather than mitigating them. See §20.4.1 — it is now the recommended route, and §20.3 to
> §20.5 describe the fallback, not the plan.

---

## 20.1 Context: one number doing two jobs

Container attribution rests on a single join. The eBPF engine stamps a number into every file
event; `container_instances` files every container under a number; FIM looks one up with the other.
On a unified (v2) cgroup hierarchy those two numbers are the same cgroup directory inode, and that
identity is the whole elegance of the design — no translation, no lookup table, no ambiguity.

On a **legacy (v1)** hierarchy the identity breaks, for a kernel reason that cannot be worked
around: `bpf_get_current_cgroup_id()` returns the id of the task's cgroup **in the v2 hierarchy**,
and on a pure v1 host there is no such hierarchy, so it collapses to one constant for every task on
the machine (spike #37396, ADR-002). The number is still there in every event. It just identifies
nothing.

The event contract has carried a second number all along for exactly this case:

```c
unsigned int mnt_ns;   /* rt_event_contract.h:89 */
```

written from `nsproxy->mnt_ns->ns.inum` (`bpf/rt_file.bpf.c:380-390`, `:433`). `rt_open()` has been
telling consumers to use it since the engine landed (`rt_engine.c:465`). Nothing ever did.

Plan 18 proposes to be the first: separate the **store index key** from the **eBPF correlation
key**, and let the host decide which concrete number fills each.

| Host | Store index key | eBPF correlation key |
| --- | --- | --- |
| unified (v2) | cgroup inode | `ev->cgroup_id` — the same value |
| legacy (v1) | mount namespace inode | `ev->mnt_ns` |
| hybrid | cgroup inode (unified hierarchy) | `ev->cgroup_id` |

That is sound. What follows is what it costs, which the plan did not know.

---

## 20.2 The measurement

Run on `wazuh_manager` (Ubuntu 24.04, kernel 7.0.0-34, Docker 29.1.3) on 2026-10-06. The host is v2, but
every property below is a property of **mount namespaces**, not of cgroup versions, so it transfers.

### What holds

| Property | Result | Why it matters |
| --- | --- | --- |
| Distinct between containers running **at the same time** | **pass** — 4 containers, 4 distinct inodes | Pod-mates stay distinguishable, unlike the network namespace which a pod shares |
| Distinct from the host's root namespace | **pass** (`4026531832` for pid 1 and for sshd) | Host processes resolve to the existing `host_process` verdict, exactly as the v2 root cgroup does |
| Stable for the life of a running container | **pass** — 5 samples over 5 s, identical | A container does not change identity under its own feet |
| `docker exec` processes share the container's namespace | **pass** | **Not a given, and load-bearing.** An exec'd shell writing to the container's filesystem produces events that attribute to the container. Had exec got its own namespace, every `docker exec` would have been an attribution hole |

### What does not

| Property | Result |
| --- | --- |
| Distinct across **sequential** containers | **FAIL** |

Eight containers created and destroyed in sequence, each with a different container id:

```
run 1: id=fd90508de7a1   mnt_ns=4026532274
run 2: id=8b56f4050c90   mnt_ns=4026532274
run 3: id=b633762a987d   mnt_ns=4026532274
...
run 8: id=840db7751cf4   mnt_ns=4026532274
```

**Eight containers, one inode.** The control run — the identical sequence, reading the cgroup inode
instead — is what makes the contrast unarguable:

```
run 1: cgroup_inode=55212
run 2: cgroup_inode=55292
...
run 8: cgroup_inode=55772      8 of 8 distinct, monotonically increasing
```

The reason is structural, not incidental. A cgroup inode comes from **kernfs**, which allocates
inode numbers from a counter that advances; a namespace inode comes from **nsfs**, which allocates
from a small pool and **reuses a number as soon as the namespace it belonged to is destroyed**. The
`+80` stride in the cgroup column is Docker creating a handful of sibling cgroups per container; the
point is the direction of travel, not the gap.

`docker restart` and `stop`+`start` likewise came back with the **same** inode — the same mechanism
seen from the inside of one container's lifetime.

---

## 20.3 What breaks: three places that assume a key outlives its container

A key being reusable is only a problem where something holds one after the container is gone. The
store does this deliberately, in three places, each for a good reason on v2.

### 20.3.1 The removal grace — the serious one

`MetadataStore` does not erase a removed container immediately. It marks `deletedAt` and keeps the
entry for `REMOVAL_GRACE` (60 s, `metadata_store.hpp:16`), **specifically so that events still in
flight can be attributed**. That is correct and valuable on v2: the cgroup inode will never belong
to anything else, so a late event is either this container's or nobody's.

On a legacy host the same 60 seconds is a window in which the kernel may already have given that
inode to a **new** container. The grace then does not merely fail to help:

> a late lookup during the grace returns the **dead** container's record for an event produced by
> the **live** one.

Both halves are wrong at once — the new container's activity is filed under the old container's
identity, and the new container's own registration collides with a stale entry it did not create.
This is worse than no attribution, and it is silent: every record involved is well-formed.

**Mitigation: the grace must be zero on a legacy host.** The grace exists to serve late events
against a key that is still unambiguously one container's. On legacy no such guarantee exists, so
there is nothing it can safely serve, and holding the entry only creates the collision.

### 20.3.2 The pending / cold-resolve path

An unknown key is parked as a `PendingEntry` and retried for `PENDING_TTL` (60 s,
`metadata_store.hpp:15`). The same reasoning applies: the key that could not be resolved at time T
may belong to a different container by the time it is.

### 20.3.3 Any key cached across a container's lifetime

In FIM's `CgroupContainerMap`, in a consumer's cursor state, or in a scanner that remembers what it
walked. On v2 a stale key is harmlessly unresolvable. On legacy it is resolvable, and to the wrong
thing.

### The discriminator already exists

`ContainerRecord::startedAt` landed with WP-P4 and is already part of `LIFECYCLE_IDENTITY`, because
a restart keeps the container id and may reuse the cgroup inode. It turns out to be the same tool
this needs: wherever a stale entry could survive on a legacy host, the key must be paired with the
start time, so "same number, different run" is distinguishable from "same container".

---

## 20.4 Why the in-kernel filter cannot be used *as the program stands*

This is independent of the reuse problem.

The allowlist is implemented in the BPF program, before the ring-buffer reservation, and it keys on
exactly one thing:

```c
statfunc int event_is_wanted(__u64 cgroup_id)        /* bpf/rt_file.bpf.c:173 */
{
    ...
    if (!mode || *mode == RT_CGROUP_MODE_ALL)
    {
        return 1;
    }
    return bpf_map_lookup_elem(&cgroup_allow_map, &cgroup_id) != NULL;
}
```

with `cgroup_id` coming from `bpf_get_current_cgroup_id()` (`:210`) — the collapsed constant. So on
a legacy host the allowlist has exactly two reachable behaviours:

| `cgroup_allow_map` contents | Result |
| --- | --- |
| does not contain the constant | **no event on the host is submitted** — the drain sees nothing at all |
| contains the constant | **every event on the host is submitted** — identical to `RT_CGROUP_MODE_ALL`, with a map lookup added per event |

Neither is filtering. There is no third case **given this input**, because `cgroup_id` is the same
for every task on the machine.

But that is a statement about the **helper**, not about the kernel — and conflating the two is the
mistake the first revision of this document made.

### 20.4.1 The kernel does have a per-container number on v1, and BPF can read it

`bpf_get_current_cgroup_id()` is not magic. It returns `cgrp->kn->id` for the task's cgroup **in the
v2 hierarchy**, which is why it degenerates when there is no v2 hierarchy. The v1 controllers'
cgroups are kernfs nodes too, with ids of exactly the same kind, and they are reachable by an
ordinary CO-RE walk:

```
task_struct -> cgroups                       (struct css_set *)
            -> subsys[memory_cgrp_id]        (struct cgroup_subsys_state *)
            -> cgroup                        (struct cgroup *)
            -> kn                            (struct kernfs_node *)
            -> id                            (u64)
```

**Every link verified in this host's BTF** (`bpftool btf dump file /sys/kernel/btf/vmlinux`,
kernel 7.0.0-34): `css_set.subsys[15]`, `cgroup_subsys_state.cgroup`, `cgroup.kn`, `kernfs_node.id`, and
`enum cgroup_subsys_id` with `memory_cgrp_id = 4`.

The one subtlety is that **4 is not a constant across kernels.** The enum is generated from
`cgroup_subsys.h` and its ordering depends on which controllers are compiled in — this kernel has 15
and another build will differ. Hardcoding the index would silently read the wrong controller's
cgroup, which is the worst possible failure here: a plausible number for the wrong thing. It must be
resolved from BTF at load time with `bpf_core_enum_value(enum cgroup_subsys_id, memory_cgrp_id)`,
which is precisely what CO-RE enum relocation exists for.

**Why this is the better route, by some distance:**

| | `mnt_ns` (§20.2–20.5) | v1 cgroup id via CO-RE |
| --- | --- | --- |
| Reused across containers | **yes** — the whole of §20.3 | **no** — kernfs ids advance, measured 8/8 distinct |
| Removal grace, pending TTL, cached keys | each needs a legacy-specific mitigation | unchanged from v2 |
| In-kernel filtering | impossible without a second map and a second key space | **works with `cgroup_allow_map` untouched** |
| Engine mode on legacy | `RT_CGROUP_MODE_ALL` + userspace filter | `RT_CGROUP_MODE_ALLOWLIST`, as on v2 |
| Cost of §20.5 | paid in full | **not paid at all** |
| Store and kernel meet on | two different numbers | **one number**, as on v2 |

That last row is the point. The resolver **already computes this exact value** on a legacy host:
WP2 picks the `memory` controller first and stats
`/sys/fs/cgroup/memory/<path>` (`proc_cgroup_resolver.cpp`), so the store is keyed on the memory
controller's cgroup inode before anything about `mnt_ns` is involved. Reading the same cgroup's
`kn->id` in BPF restores the design's original property — one number, no translation — on the
hierarchy where it was thought to be impossible.

**What it costs, honestly:**

- Four pointer dereferences per event before the reservation. The program already does far longer
  CO-RE walks on this path (the dentry/mount chain in `get_path_str()` is a bounded loop), and
  `event_is_wanted()` already performs a map lookup, so this is a small addition to a hot path
  rather than a new kind of work on it.
- **It is BPF work**, but less of it than this originally claimed. `prebuilt/x86/` and
  `prebuilt/arm64/` are both empty and no `check_files` manifest lists `rt_file.bpf.o`: nothing is
  shipped prebuilt, so the object is compiled from source wherever the toolchain exists and skipped
  with a diagnostic where it does not. The development environment's missing clang and bpftool
  affect local *testing*, not shipping — and the work was in fact built, loaded and regression-tested
  on `wazuh_manager`, which has the full toolchain.
- **The assumption was measured on 2026-10-06, and mostly holds. See §20.4.3.**

### 20.4.3 Measured: the walk works, and one trap came with it

A working CO-RE prototype was built and run on `wazuh_manager` (kernel 7.0.0-34) on 2026-10-06 — the
program WP6a would need, not a simulation of it. Against a host process in a nested cgroup
(`/user.slice/user-1000.slice/session-608.scope`):

| | Value |
| --- | ---: |
| `stat()` of the cgroup directory | **73645** |
| `bpf_get_current_cgroup_id()` | **73645** |
| `subsys[4]->cgroup->kn->id` (the CO-RE walk) | **73645** |
| `bpf_core_enum_value(enum cgroup_subsys_id, memory_cgrp_id)` | 4 |
| `memory`'s index counted from `/proc/cgroups` | 4 |

Four things are settled by that run:

1. **The walk yields the kernfs id, and it equals `stat()`** — the assumption this route rested on.
2. **A variable index works.** `bpf_core_field_offset(struct css_set, subsys)` plus manual pointer
   arithmetic, with the index bounds-checked, is accepted by the verifier and returns the right
   object. This was the part that could not be taken on trust, because `BPF_CORE_READ(cset,
   subsys[i])` requires a constant.
3. **Both index-resolution routes agree**, which is the cross-check WP6a specifies — and they agreed
   on a host where the answer happens to be the documented 4, so the mechanism is confirmed even
   though the value is unsurprising.
4. **`bpf_core_enum_value_exists()` guards cleanly**, so a kernel without the enumerator degrades
   instead of failing to load.

**And a trap that the v2 run exposed by accident.** Reading a *second* subsystem on the same task
returned a different cgroup:

```
subsys[4]  (memory) -> 73645     the task's own cgroup
subsys[0]  (cpuset) -> 217       an ANCESTOR
```

On cgroup v2 a controller is only enabled in cgroups whose ancestors enabled it through
`cgroup.subtree_control`, so `css_set.subsys[i]` points at the nearest ancestor where controller `i`
is enabled — **not necessarily the task's own cgroup**. Had `memory` not been enabled on the
container's cgroup, the walk would have returned an ancestor's inode: a real, plausible number for
the wrong cgroup, attributing a container's events to its parent slice.

This does not affect the plan, because on a unified host the engine uses the helper and never takes
this path. It does mean **the walk must be gated on the host being legacy**, where it cannot happen:
every task is in exactly one cgroup per mounted v1 hierarchy, which is also precisely the cgroup
`/proc/<pid>/cgroup` names and the resolver stats. WP6a must assert that gate rather than leave it
implied.

### 20.4.4 Closed: measured on a non-unified host

`wazuh_manager` was rebooted with `systemd.unified_cgroup_hierarchy=0` on 2026-10-06 and restored
to its default afterwards. systemd came up **hybrid** — v1 controllers at `/sys/fs/cgroup/<ctrl>`
with a v2 hierarchy at `/sys/fs/cgroup/unified` — which is the layout the shared probe calls
`hybrid`, and it reported exactly that. Docker ran with `Cgroup Version: 1`, driver `cgroupfs`, so
containers landed in `/docker/<id>` in every v1 hierarchy.

A process was moved into a **real container's** cgroups in both hierarchies, and probed:

| | Value |
| --- | ---: |
| `stat /sys/fs/cgroup/memory/docker/<id>` | **8387** |
| `subsys[4]->cgroup->kn->id` (the CO-RE walk) | **8387** |
| `stat /sys/fs/cgroup/unified/docker/<id>` | **6225** |
| `bpf_get_current_cgroup_id()` | **6225** |

**Both equations hold, and they are different numbers.** That settles three things at once:

1. **The open question is closed.** On a host with real v1 controller hierarchies,
   `subsys[idx]->cgroup` *is* the task's cgroup in that controller's hierarchy, and its `kn->id` is
   the inode `stat()` returns for the directory the resolver reads from `/proc/<pid>/cgroup`. WP6a
   rests on a measurement now, not an expectation.
2. **WP2's hybrid rule is confirmed end to end.** The `0::` path is relative to
   `/sys/fs/cgroup/unified`, and statting it there yields precisely what the helper reports — which
   is what the plan asserted and what the pre-WP2 code got wrong by statting it at the root.
3. **The two key spaces are genuinely distinct** — 8387 and 6225 for the same task at the same
   instant. The separation this design is built on is not theoretical.

A fourth, smaller result: `subsys[0]` (cpuset) returned **1**, the root cgroup, because this task's
cpuset line was `/`. Per-controller cgroups are independent, exactly as WP6a's configured index
assumes.

**What is still not measured:** a *pure* legacy host, with no unified hierarchy at all. systemd's
`unified_cgroup_hierarchy=0` produces hybrid, not legacy; pure v1 additionally needs
`systemd.legacy_systemd_cgroup_controller=1`. The one claim that remains inferred rather than
observed is that `bpf_get_current_cgroup_id()` collapses to a constant there — #37396 ADR-002's
premise. Nothing in this work depends on it being *exactly* constant: the design only needs the
helper's value to be unusable for attribution, and on a pure v1 host there is no unified hierarchy
for it to report from. It is recorded as the one remaining inference.

### 20.4.2 The fallback, if the BPF work cannot be scheduled

On a legacy host, open the engine in `RT_CGROUP_MODE_ALL` and discard unwanted events in userspace
by comparing `ev->mnt_ns` against the keys held. Unified and hybrid hosts are untouched and keep the
in-kernel allowlist exactly as it is today. This is what §20.5 prices, and it is the only route that
needs no new BPF object — which is its sole advantage.

---

## 20.5 What that costs, stated against the measurement that justified the filter

`541077159e` moved the drain from `RT_CGROUP_MODE_ALL` to `RT_CGROUP_MODE_ALLOWLIST` precisely
because unfiltered delivery is expensive. Doc 19 measured it (5 pairs per variant, medians):

| Metric | | mode ALL | allowlist | Change |
| --- | --- | ---: | ---: | ---: |
| Consumer CPU | LSM | 0.493 s | 0.032 s | **−93.5%** |
| | kprobe | 0.590 s | 0.032 s | **−94.6%** |
| Writer CPU | LSM | 9.913 s | 4.559 s | **−54.0%** |
| | kprobe | 10.696 s | 4.938 s | **−53.8%** |

Read in the other direction, that is what a legacy host pays: roughly **15× the consumer CPU** and
**about twice the writer CPU** of a filtered host, under the same synthetic write load.

Two things make this less alarming than the raw numbers suggest, and one makes it worse.

- The benchmark is a deliberate worst case — a tight write loop with no other load — so it
  measures the *ceiling* of the effect, not a typical node.
- The **userspace** filter still removes everything the consumer would otherwise do per event
  (resolve, enrich, persist). What returns is the kernel-side submission cost and the ring-buffer
  traffic, which is the writer-CPU column, not the consumer-CPU one. The consumer-CPU figure above
  is the saving from *not being delivered* events; a userspace filter recovers most of that work
  but none of the delivery.
- Against that: it applies to the whole host, including every host process, not only to containers.

**The honest summary is that container FIM on a legacy host is materially dearer than on a unified
one, and there is no version of phase 2 that avoids this without new BPF work (§20.4).** Any
decision to ship phase 2 is a decision to accept that on RHEL 8 and Amazon Linux 2.

---

## 20.6 What this changes in the plan

| Plan 18 said | Reality | Action |
| --- | --- | --- |
| WP6: "Replace the refusal with selection" (`container_event_drain.cpp:694`) | Key selection is necessary but not sufficient — the filter mode must change with it | WP6 selects **both** the key and the engine mode by host mode |
| §18.4 lists `unshare -m` and deliberate namespace sharing as the `mnt_ns` weaknesses | The dominant weakness is **sequential reuse**, which §18.4 does not mention | §18.7 Q1 updated with the measurement; this document is the long form |
| §18.7 Q1: "worth a probe before committing to phase 2" | Probed. Usable with mitigations | Q1 closed |
| Nothing about filter mode | Legacy hosts cannot filter in-kernel **with the current BPF object**; with a new one they can, on a better key than `mnt_ns` (§20.4.1) | Recorded here and in §18.7 |

**Still open, and genuinely a judgement call rather than an engineering one.** There are now three
answers, not two:

1. **Phase 2 on the v1 cgroup id (§20.4.1).** The best outcome and the most work: new BPF code, a
   rebuilt object per architecture, and one measurement on a real v1 host before any of it is
   trusted. Legacy hosts then behave like unified ones, with none of §20.3's mitigations and none of
   §20.5's cost.
2. **Phase 2 on `mnt_ns` (§20.4.2).** No BPF work. Carries §20.3's three mitigations and §20.5's
   cost on legacy hosts only.
3. **Inventory-only.** Works on legacy hosts **today**, as of WP2/WP4, and costs nothing extra —
   inventory discovers through `list` and collects through `/proc/<pid>/root`, neither of which
   touches the event stream.

Option 1 does not block option 2: the key kind is already a host constant behind one abstraction
(`KeyKind`, `18-…` WP4), so moving a legacy host from `mnt_ns` to a v1 cgroup id later is a change
of which number fills the key, not a change of shape.

---

## 20.7 How to reproduce

Both probes are plain shell and need only Docker and root. They are reproduced here rather than
committed as test scripts, because they measure a **kernel property** that no change in this
repository can alter — a test asserting it would be testing Linux, and would fail on the day a
kernel changed its allocator for reasons nothing here controls.

```bash
# Sequential reuse: the finding.
for i in $(seq 1 8); do
  docker run -d --name rc$i alpine sh -c 'while :; do sleep 1; done' >/dev/null
  P=$(docker inspect -f '{{.State.Pid}}' rc$i)
  echo "run $i: id=$(docker inspect -f '{{.Id}}' rc$i | cut -c1-12)" \
       "mnt_ns=$(stat -Lc %i /proc/$P/ns/mnt)" \
       "cgroup=$(stat -c %i /sys/fs/cgroup$(awk -F: '/^0::/{print $3}' /proc/$P/cgroup))"
  docker rm -f rc$i >/dev/null; sleep 1
done

# Uniqueness among concurrently live containers: the property that does hold.
for i in 1 2 3 4; do docker run -d --name cc$i alpine sh -c 'while :; do sleep 1; done' >/dev/null; done
for i in 1 2 3 4; do
  stat -Lc %i /proc/$(docker inspect -f '{{.State.Pid}}' cc$i)/ns/mnt
done | sort -u | wc -l        # expect 4
```

To reproduce on a genuinely legacy host rather than inferring from a v2 one, boot the VM with
`systemd.unified_cgroup_hierarchy=0` (§18.6). The namespace behaviour will not differ — nsfs does
not know about cgroups — but the *consequences* in §20.3 and §20.4 only become observable there.
