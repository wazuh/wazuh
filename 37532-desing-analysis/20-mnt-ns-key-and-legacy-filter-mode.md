# 20 — Why a legacy-cgroup host needs `mnt_ns` as its key, and why that forces `RT_CGROUP_MODE_ALL`

**Subject:** the two consequences of correlating container events on a mount namespace instead of a
cgroup, both of which were found by measurement rather than by reading, and neither of which is
stated in `18-cgroup-v1-unified-resolver-plan.md` as written.

**Date:** 2026-10-06 · **Branch:** `37532-cgroup-v1-unified-resolver` · **Issues:** #37203 (O4) / #37532 / #37396

**Verdict:** `mnt_ns` works as a correlation key, but it is **unique in space and not in time** — the
kernel hands the same inode number to the next container started. Three mechanisms in the store
assume the opposite. Separately, the in-kernel cgroup allowlist **cannot select containers at all**
on such a host, so phase 2 there has to run `RT_CGROUP_MODE_ALL` and filter in userspace. That is
not a design preference; it is the only mode that can work, and it carries back the cost that
`541077159e` was written to remove.

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

Run on `wazuh_manager` (Ubuntu 24.04, kernel 6.8, Docker 29.1.3) on 2026-10-06. The host is v2, but
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

## 20.4 Why the in-kernel filter cannot be used on a legacy host

This is independent of the reuse problem, and it is the harder constraint.

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

Neither is filtering. There is no third case, because there is no per-container input to filter on:
the one number the kernel can supply is the same for every task on the machine.

**Could the BPF program filter on `mnt_ns` instead?** Not as the engine stands. The value is read
per event into the event struct, but `event_is_wanted()` runs *before* the record is reserved and
populated, which is the entire point of filtering there — the saving comes from never reserving. A
`mnt_ns` allowlist would mean reading `nsproxy->mnt_ns->ns.inum` on every event before deciding,
which is a CO-RE read per event on the hot path, plus a second allowlist map, plus a config flag to
choose between them, plus a rebuild and redeployment of `rt_file.bpf.o` on every supported
architecture. That is a real option, and it is **not a small one**; it is noted here as future work
rather than smuggled into WP6.

**Therefore, on a legacy host, phase 2 must open the engine in `RT_CGROUP_MODE_ALL` and discard
unwanted events in userspace, by comparing `ev->mnt_ns` against the keys it holds.** Unified and
hybrid hosts are untouched and keep the in-kernel allowlist exactly as it is today.

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
| Nothing about filter mode | Legacy hosts cannot filter in-kernel at all | Recorded here and in §18.7 |

**Still open, and genuinely a judgement call rather than an engineering one:** whether the cost in
§20.5 is acceptable for the hosts in question, or whether O4 should resolve to *inventory-only* —
which works on legacy hosts **today**, as of WP2/WP4, and costs nothing extra because inventory
discovers through `list` and collects through `/proc/<pid>/root`, neither of which touches the event
stream.

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
