# 18. A unified cgroup v1/v2 resolver

Implementation plan for **O4** of the agent-side integration issue (#37203): what a cgroup v1 host
does to this feature today, and how to build one resolution engine that serves both hierarchies.

Everything in *Current behaviour* was **re-read from the code on 2026-10-05**, on
`37532-container-lifecycle-notify` @ `da972670a1`, after the lifecycle-delta work landed. It was
first written against `37532-5-0-0-container-integration` @ `f1bfcbd3e6`; §18.1, §18.1.1, WP4, WP5,
WP6 and §18.6 changed in the re-read, and §18.7 lost one question. Everything under *Proposed* is
design, not measurement, and is marked as such.

---

## 18.1 Why this is not just "FIM is off on v1"

`bpf_get_current_cgroup_id()` collapses to the root cgroup id — one constant for every task — on a
pure v1 hierarchy. That is a kernel property, not a bug we can fix, and it is why
`container_event_drain.cpp:694` refuses to start the event-driven reconcile there.

The damage is wider than that refusal, and it is silent. Three facts compose:

1. **The resolver only understands v2.** `parseCgroupV2Line()` accepts a line only if it begins
   `0::`, and returns `nullopt` otherwise. A pure v1 `/proc/<pid>/cgroup` has no `0::` line at all —
   only numbered controller lines (`11:devices:/docker/abc…`). Every line is rejected, so the scan
   returns no container entries.
2. **Every record therefore gets `cgroupId = 0`.** `docker_connector.cpp:66` joins the API snapshot
   against the resolver's inode map; a container absent from that map is assigned zero.
3. **`list` drops every zero-keyed *running* record.** `metadata_store.cpp:124` skips a record
   when `cgroupId == 0 && isRunning(record->state)`. Until the `all=1`/`ContainerState` work it
   skipped every zero-keyed record outright; the state half was added so a *stopped* container —
   which has no inode either — stays listed rather than reading to consumers as a deletion. On a v1
   host **every** record is zero-keyed, so the guard no longer rejects everything, it partitions by
   state: a v1 `list` returns exactly the containers that are **not running**, and hides every
   container that is.

The consequence, which #37534 assumed was safe: **IT Hygiene is dead on v1 too.** Its container pass
discovers through `list` — now through the lifecycle delta with `list` as its floor — and both are
gated on the key the v1 host cannot produce. The reasoning that inventory "does not use cgroup_id"
is true of the *collection* path and false of the *discovery* path.

**The state-aware filter changed the symptom, not the outcome**, and it is worth being precise about
which. A v1 `list` is no longer empty. But everything in it is unscannable by construction:
`container_baseline_scanner.cpp:290` and `:437` skip any container with no live PID, which is exactly
the set a v1 host now publishes. The operator still gets zero inventory — from a module that now
also looks busy.

And `container_instances` never detects cgroup v1 nor mentions it in any log — re-checked on
2026-10-05, and still true: the string does not appear anywhere under `ci_impl/src/`. The module
starts, binds its socket, the connectors authenticate and return real containers — and then every
*running* one is dropped for having a zero key. An operator sees a healthy module, a list of dead
containers, and no inventory, with nothing naming the cause.

| Component | On a v1 host today |
| --- | --- |
| eBPF engine (`rt_open`) | warns, loads anyway (`rt_engine.c:450`) |
| Container FIM drain | refuses, logs ERROR naming cgroup v1 — **the only correct diagnosis emitted** |
| `container_instances` resolver | finds nothing, says nothing |
| `list` / IT Hygiene | silently useless: only **exited** containers listed, and those have no PID to collect from |
| Container baseline | never runs: every discovered container is pid-less |

### 18.1.1 A v1-only inversion the lifecycle journal introduced

The journal added for the delta work logs transitions of **what `listContainers()` returns**, not of
what the store holds. That is the right definition on v2, where visibility tracks resolution. On v1
it inverts, because the visibility test *is* the state test:

| v1 event | Visibility | Journal emits | What a consumer does with it |
| --- | --- | --- | --- |
| `docker stop` | hidden → visible | `added` | baseline the container |
| `docker start` | visible → hidden | `removed` | **sweep its rows** |

So on a v1 host, starting a container reads as a deletion and stopping it reads as a creation —
exactly backwards. **Nothing reaches this today**: FIM refuses on v1 before the drain binds, and
syscollector never writes rows for a pid-less container, so a `removed` has nothing to sweep. It is
latent, not live.

It matters because **WP4 is the package that would arm it.** Giving v1 records a real host key makes
`isRunning()` stop being the whole filter, which fixes the inversion at the same stroke — but only if
WP4 keeps both halves of the guard, which is why that bullet now says so explicitly. A WP4 that
restored v1 keys while a stale single-term guard survived anywhere would ship the inversion live.

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
`mnt_ns`, written at `bpf/rt_file.bpf.c:433` from `get_mnt_ns_inum()`, which reads
`nsproxy->mnt_ns->ns.inum` (`:390`). `rt_engine.c:465` already tells consumers to use it, and
`rt_host_cgroup_v1()` is exported for them to branch on. Nothing consumes either yet.

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
| cgroup v1 (legacy) | canonical-controller cgroup inode | **the same inode**, read in BPF from that controller's own `kernfs_node.id` |
| hybrid (v2 at `/sys/fs/cgroup/unified`) | treated as v2 | `ev->cgroup_id` |

**Revised 2026-10-06.** The legacy row originally read `ev->mnt_ns`, and measurement killed it: a
mount-namespace inode is recycled by the kernel the moment its namespace dies, so eight consecutive
containers were handed the same number while their cgroup inodes were all distinct
(`20-mnt-ns-key-and-legacy-filter-mode.md` §20.2). More usefully, the measurement also showed the
premise behind that choice was wrong. `bpf_get_current_cgroup_id()` degenerates on a legacy host
because it reports the task's cgroup in the **v2** hierarchy; the v1 controllers' cgroups are
kernfs nodes with ids of exactly the same kind, and a BPF program can read one directly. So the two
roles do **not** have to be filled by different numbers after all — they are filled by the same
number, read by a different route. `mnt_ns` stays in the contract and is still collected (WP3), as
a cross-check and as the fallback if the BPF work cannot be scheduled.

Hybrid follows v2 because `bpf_get_current_cgroup_id()` returns unified-hierarchy ids there, which is
already how `detect_cgroup_v1()` classifies it.

---

## 18.3 Work packages

### WP1 — One shared host-mode probe *(prerequisite; ship regardless of O4's outcome)* — **DONE, `718f9ff4fb`**

`detect_cgroup_v1()` lives in `rt_engine.c:143` and is private to the eBPF provider. Extract it to a
shared header so the provider and `container_instances` cannot reach different conclusions about the
same host — the failure mode ADR-001 warned about for capability probes, applied to cgroups.

There is now a cheaper half-measure, if the extraction is judged too invasive to do first:
`rt_host_cgroup_v1(NULL)` falls back to a fresh `detect_cgroup_v1()` (`rt_engine.c:796`), so it works
as a standalone probe with no handle. It is a real option but a worse one — it makes
`container_instances` link the eBPF provider for a question that has nothing to do with eBPF, and it
leaves the one implementation private, which is the thing ADR-001 objects to. Prefer the extraction;
record the fallback so the choice is a choice.

Report three modes: `unified`, `legacy`, `hybrid`.

Then make `container_instances` **log its mode at startup, and log at ERROR when it is `legacy` and
no v1 support is compiled in**. This one change converts today's silent nothing into a diagnosable
failure, and it is worth doing before any decision on the rest of this plan.

Effort: S.

**Shipped, and two things came out differently from this write-up.**

The probe went to `shared_modules/common/cgroup_host_mode.h` and takes a **root parameter**, which
this package did not anticipate and which turned out to be the point: every host the tree builds and
tests on is unified, so without injection the `legacy` and `hybrid` branches would have shipped
having never once executed, and the first machine to run them would have been a customer's. They are
now covered by directory fixtures in `rt_engine_contract_test`.

And the duplicate probe was not one copy, it was **three**: `rt_engine_drops_test.c` and
`rt_engine_filter_test.c` each carried their own `stat("/sys/fs/cgroup/cgroup.controllers")`. They
were not converted to the usable-key helper, because they create cgroups directly under
`/sys/fs/cgroup` and therefore need v2 **at the root** — a hybrid host would pass a usable-key test
and then fail for an unrelated reason. They compare against `unified` exactly, which is a
distinction the old two-state probe could not express and this one can.

The message wording lives in `ci_impl/src/core/cgroup_mode_report.hpp` rather than in the facade, so
"a legacy host is reported at ERROR" is asserted without a v1 host to assert it on.

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

**The choice has to be reachable from outside this package.** WP6a configures the BPF program to
read the *same* controller's cgroup, so the selection cannot stay private to the resolver: it must
expose which controller it settled on, as an index userspace can write into the engine's config map.
`CgroupEntry::keyController` carries the name per entry already; what WP6a additionally needs is the
host-level answer, once.

Effort: M.

### WP3 — Read the mount-namespace inode during the same walk *(no longer the key; still worth having)*

The scan already iterates `/proc/<pid>` and opens `/proc/<pid>/cgroup`. Add one `stat` of
`/proc/<pid>/ns/mnt` per pid and carry `mntNsInode` alongside `cgroupInode` in `CgroupEntry`.

Cost is one extra stat per process per scan, on a walk that already does one open and one read per
process.

Populate **both** keys on **both** hierarchies, not just the one in use. It makes the v1 and v2 paths
structurally identical, and it lets a v2 host cross-check attribution during testing.

**Reframed 2026-10-06.** `mnt_ns` is no longer the planned legacy key — WP6a reads the v1 cgroup id
instead — so this package's output is now a cross-check and the fallback's key, not the main line.
It stays in, cheaply: one `stat` per process on a walk that already opens and reads a file per
process, and it is what route 2′ would need if WP6a slips. Its one genuinely load-bearing
contribution is unchanged: the lowest-pid rule, which stops `unshare -m` inside a container deciding
that container's identity.

Effort: S. **Landed** in `56812f73e8`.

### WP4 — Key the store by `HostKey`

- `m_byCgroup` → `m_byHostKey`
- `lookupByCgroup(std::uint64_t)` → `lookup(HostKey)`
- `listContainers()`'s guard → "**no** valid host key **and** running". Note the second half. The
  guard is `cgroupId == 0 && isRunning(record->state)` today, and an earlier draft of this package
  said to replace it with a plain key test — which would drop the state term and silently undo
  stopped-container retention (#37203 D20), re-teaching every consumer that a stop is a delete. The
  same two-part guard appears **three** times (`metadata_store.cpp:124`, `:394`, `:505`); they move
  together, and a missed one is the §18.1.1 inversion shipped live

The verdict and pending machinery (`upsertVerdict`, `upsertPending`, liveness eviction against
`allInodes`) is already key-agnostic — it stores and compares an opaque integer. `allInodes` becomes
"all observed keys of the host's kind".

**This is the package that unblocks IT Hygiene**, because it is what makes `list` return records
again.

Effort: M.

### WP5 — Protocol version 2

The wire carries a field literally named `cgroup_id` in **four** places now, not the one this
package was scoped against: the `resolve` request, where it is mandatory
(`wire_protocol.hpp:145-152`); the per-record reply payload (`:197`); the per-event payload on
lifecycle deltas (`:287`); and both of those again on the consumer side
(`container_instances_client.hpp:280`, `:426`) plus `cb_lifecycle_event_t` in the baseline C ABI.
Re-estimate from four call sites, not one.

`PROTOCOL_VERSION` is still checked by **strict equality** (`wire_protocol.hpp:92`) — doc 10's
proposed relaxation to `<=` was not taken when the delta work landed — so client and server must
still move together, and the one-version alias below is still the only independent-rollout route.

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

### WP6a — Teach the BPF program to read a legacy host's cgroup id *(the key package)*

`event_is_wanted()` keys on `bpf_get_current_cgroup_id()` (`bpf/rt_file.bpf.c:173-185`, `:210`),
which on a legacy host is one constant for every task — so an allowlist there admits the whole node
or none of it. That is a property of the **helper**, not of the kernel. The v1 controller's cgroup
is a kernfs node with an id of the same kind, reachable by a CO-RE walk the program is already doing
longer versions of:

```
task_struct -> cgroups              (struct css_set *)
            -> subsys[<index>]      (struct cgroup_subsys_state *)
            -> cgroup -> kn -> id   (u64)
```

Every link verified in BTF on kernel 7.0.0-34 (`20-…` §20.4.1). The value it yields is **the inode WP2
already keys the store on**, so store and kernel meet on one number again — the property the whole
design rests on, restored on the hierarchy where it was believed impossible.

**The subsystem index is CONFIGURED, not compiled in.** Three reasons, and the third is the one that
settles it:

1. `enum cgroup_subsys_id` is generated from `cgroup_subsys.h` and its ordering depends on which
   controllers the kernel was built with. `memory_cgrp_id` is 4 on the test host and need not be
   anywhere else.
2. Reading the wrong controller's cgroup is the worst failure available here — a plausible number
   for the wrong object, with nothing to notice it.
3. **WP2 does not always choose `memory`.** Its priority is `memory` → `pids` → `cpu,cpuacct` →
   `name=systemd`, and it falls down that list on a host where the earlier ones are not mounted. The
   BPF side must read *whichever controller userspace chose*, so the index cannot be a compile-time
   constant of any kind — not even a correct one.

So userspace resolves the index for the controller it selected and writes it into the existing
`filter_cfg` map under a new key; the program reads `subsys[idx]` with a bounds check. Two ways to
resolve it, and taking both costs almost nothing:

- **`/proc/cgroups` ordering** — the file lists subsystems in enum order, verified against BTF on
  the test host (`cpuset, cpu, cpuacct, blkio, memory, …` ↔ `0,1,2,3,4,…`; note position 3 is
  `io_cgrp_id` in the enum and `blkio` in the file, the same subsystem under its v1 name). Userspace
  counts to its chosen controller. Needs no BTF and handles any controller uniformly, with no switch
  over enum constants.
- **`bpf_core_enum_value(enum cgroup_subsys_id, …)`** — the CO-RE relocation built for exactly this,
  resolved from the *running* kernel's BTF at load. Guard with `bpf_core_enum_value_exists()`, or a
  kernel lacking the enumerator fails to load rather than degrading.

Use `/proc/cgroups` as the source of truth (it tracks WP2's choice directly) and the CO-RE value as
a startup cross-check: disagreement means one of the two readings is wrong, which is worth an ERROR
and a refusal rather than a coin toss.

**One implementation note worth recording before someone hits it.** `BPF_CORE_READ(cset, subsys[i])`
needs a *constant* index — CO-RE computes a field offset at load time. A variable index means taking
the array's base offset with `bpf_core_field_offset(struct css_set, subsys)` and reading at
`base + idx * sizeof(void *)`, with `idx` bounds-checked first so the verifier accepts it.

**Measured 2026-10-06 on a host rebooted into a non-unified layout** (`20-…` §20.4.4). For a real
container's cgroups, `subsys[4]->cgroup->kn->id` and `stat /sys/fs/cgroup/memory/docker/<id>` both
returned **8387**, while `bpf_get_current_cgroup_id()` and `stat /sys/fs/cgroup/unified/docker/<id>`
both returned **6225**. The premise holds and the two key spaces are demonstrably distinct — this
package no longer rests on an expectation. Still extend `rt_engine_drops_test` to pin it, as it
pins the v2 equivalent (28126/28206, since `9e884232c5`).

**A constraint found while building it: the priority list is shorter for the engine than for the
resolver.** `name=systemd` is a *named* hierarchy with no controller, so it has no entry in
`enum cgroup_subsys_id` and none in `css_set.subsys[]` — `wz_cgroup_subsys_index("systemd")` returns
-1, confirmed on the test host alongside `memory`=4, `pids`=11, `cpuacct`=2. Userspace can still
stat its directories, so it stays a valid key for the resolver and for inventory; what it cannot do
is give the BPF program anything to read. **A host offering only `name=systemd` can be inventoried
but not filtered in-kernel**, and must fall back to route 2′ or refuse. The engine's usable priority
is therefore `memory` → `pids` → `cpuacct`.

**One trap the same measurement exposed, which WP6a must guard.** On a *unified* host
`css_set.subsys[i]` points at the nearest ancestor where controller `i` is enabled, not necessarily
the task's own cgroup — a second subsystem read on the same task returned an ancestor. The walk is
therefore only valid on a host with real v1 hierarchies, where every task is in exactly one cgroup
per mounted hierarchy. Assert that gate; do not leave it implied.

**Cost — and this was overstated when the package was written.** Four pointer dereferences per event
before the ring-buffer reservation, on a path that already performs a map lookup and a bounded
dentry walk. The "rebuilt object per architecture" price quoted here originally does **not** apply:
`prebuilt/x86/` and `prebuilt/arm64/` are both **empty**, and no `check_files` manifest lists
`rt_file.bpf.o`. Nothing is shipped today — the object is compiled from source wherever clang, libbpf
headers and a `vmlinux.h` exist, and skipped with a diagnostic where they do not
(`ebpf_provider/CMakeLists.txt`'s three-way gate). So WP6a is a source change like any other; the
build environment's lack of a BPF toolchain affects whether it can be *tested* locally, not whether
it can ship.

Effort: M. Files: `bpf/rt_file.bpf.c`, `include/rt_engine.h` (the new `filter_cfg` key and a setter),
`src/rt_engine.c`, `prebuilt/<arch>/rt_file.bpf.o`, and the four
`.github/actions/check_files/*.csv` manifests that pin the object.

### WP6b — Drain selects the key and the engine mode by host mode — **DONE**

Replace the refusal at `container_event_drain.cpp:694` with selection. With WP6a in place the
selection is almost trivial, because the key kind no longer changes:

```cpp
// WP6a landed: the kernel reports the host's own cgroup id either way.
rt_set_v1_subsys_index(handle, resolver.selectedSubsysIndex());   // legacy only
filter.cgroup_mode = RT_CGROUP_MODE_ALLOWLIST;                    // unchanged from v2
```

`cgroup_container_map` now has **two** entry points, `install()` and `applyDelta()`, both producing
the same `CgroupListDelta`; `applyDelta()` additionally treats a zero `cgroup_id` as a withdrawal, a
rule that needs restating as "no valid key" rather than "zero". Keep a refusal for the case where
**neither** key is usable, so "wrong attribution is worse than none" still has a floor.

**If WP6a cannot be scheduled**, this package instead opens the engine in `RT_CGROUP_MODE_ALL` on
legacy hosts and filters on `ev->mnt_ns` in userspace, with the removal grace and pending TTL forced
to zero there (`20-…` §20.3). That route works, costs what `19-option-c-test-report.md` measured —
roughly 15× the consumer CPU and about twice the writer CPU — and must say so in the release notes.
The two routes differ only in which number fills `KeyKind`, which WP4 already made a host constant
behind one abstraction, so neither forecloses the other.

**What it turned out to involve, now that it is done.** Less than the package assumed, and for a
reason worth recording: `cgroup_container_map` needed **no change at all**. It compares opaque
integers and never interprets them, so a host keyed by a v1 controller's cgroup inode flows through
`install()` and `applyDelta()` exactly as a unified one does — the zero-means-no-key rule holds
because zero is still what a producer sends when there is no key, whichever hierarchy supplied it.
Only its comment needed restating. That the map was already key-agnostic is why WP4's abstraction
paid off here rather than merely moving the problem.

The selection itself is one call to `wz_cgroup_v1_select_subsys()`, which applies two tests a
candidate must both pass: **mounted as a v1 hierarchy** (or there is no cgroup under it to read) and
**possessing a subsystem slot** (or the BPF program has nothing to index). The second is what rules
out `name=systemd`. The old refusal survives as the floor for a host where neither test can be
satisfied, so "wrong attribution is worse than none" still stands.

Effort: M. The only package that touches FIM's hot path.

### WP7 — IT Hygiene

No dedicated work, and the conclusion survives the delta work unchanged — but the mechanism
sentence does not. Syscollector no longer discovers purely through `list`: it discovers through
`cbaseline_lifecycle_since()` with a periodic full `list` as its floor. Both are keyed the same way,
and collection is still `/proc/<pid>/root` + `setns`, which uses no correlation key at all. So it
still starts working when WP4 lands.

### WP-ISSUE — update the issue description *(last, after the shipped phase is measured)*

`/home/rovogel/wazuh/source/37203-agent-integration-issue.md` is the authoritative index for #37203,
and this plan is the resolution of **O4**, which that file still carries as open. Updating it is the
closing step, not a changelog line — several of its recorded statements become wrong, and **which
ones depends on the phase that actually ships**, so this package is written per phase.

**Owed already, before any phase ships.** O4's note currently reads *"the v1 posture is exactly where
it was"*. That was written against the running-container case and is right about it, but it is
understated: §18.1 found that a v1 `list` is no longer empty — it now publishes exited containers.
Correct the note whether or not the rest of this plan proceeds, so the next reader is not told the
filter change was a no-op on v1.

**After Phase 0 (WP1).**
- **O4 narrows, it does not close.** The decision it asks for is still unmade; what changes is that
  the failure is now diagnosable. Say that, rather than ticking it off.
- **Add a decision** (next free id is **D21** — D18 sorts after D20 in that table, so read the ids,
  do not count rows) recording that the host cgroup mode is probed once, in one place, and logged,
  and that `container_instances` refuses silently no longer. Name the shared-probe choice and why
  the `rt_host_cgroup_v1(NULL)` shortcut was declined, if it was.

**After Phase 1 (WP2+WP3+WP4).**
- **O4 closes as "inventory-only".** Record it as the decision taken, with the measured v1 evidence,
  not as the option the plan listed.
- **D12 needs splitting.** It currently reads *"cgroup v1 is refused, not degraded"* as a single
  statement over the whole feature. After Phase 1 that is true of FIM and false of inventory. Amend
  it to scope the refusal to the event-driven path, and let the new decision carry the inventory
  half — do not leave D12 standing as written.
- **§18.1.1's inversion must be recorded as fixed**, with the control from §18.6 that proves it. If
  WP4 shipped without that control, say so instead.
- **Compatibility floor table.** Its two v1 rows carry `n/a` under *`cgroup_id` == `st_ino`*, which
  reads as "untested" where it means "not applicable, and the feature is dead here". Phase 1 makes
  those rows partially supported; the table needs a column or a footnote, because a support matrix
  that says `n/a` where the answer is now "inventory yes, FIM no" is the single most misread cell
  in the file.
- **Deliverables / Acceptance criteria** — any row that states a supported-platform set.

**After Phase 2 (WP5+WP6).**
- **D12 is superseded outright**, not amended: v1 is then degraded rather than refused.
- **Contracts to freeze #2 breaks.** The IPC protocol is published there as version 1 with a
  `cgroup_id` field; WP5 moves it to version 2 with `key_kind`/`key`. This is the only breaking
  change to a frozen contract in the whole of #37203 — it gets its own entry, with the one-version
  alias window spelled out, not a quiet edit to the existing bullet.
- **Add a decision** that FIM on v1 correlates on a *namespace*, not a cgroup, and that this is a
  different security property (§18.4). The honest asymmetry belongs in the decision record, where a
  reader looking for "is v1 supported?" will find it, rather than only in this plan.

**If the decision is "cgroup-v2-only, permanently".** The update is still owed, and is the shortest
of the four: close O4 with that answer, keep D12 as written, record Phase 0 as shipped, and record
§18.1.1's inversion as a **known latent defect that will stay latent** — it is only reachable if
someone later gives v1 records a real key, and the next person to try must find that written down.

---

## 18.4 What `mnt_ns` costs us, stated honestly

**This section now describes the FALLBACK route (`20-…` §20.4.2), not the plan.** It is kept because
the fallback is real and may be taken, and because the first row below is the measurement that moved
the plan off it.

| Case | Behaviour | Handling |
| --- | --- | --- |
| **Sequential containers** | **the inode is REUSED — 8 containers, 1 inode, measured** | fatal for a key held past its container's death: removal grace must be 0, pending TTL likewise, and no key may be cached. The reason this route is the fallback |

It is a weaker key than the cgroup inode in every other respect too, and the plan should not pretend
otherwise.

| Case | Behaviour | Handling |
| --- | --- | --- |
| Containers in a Kubernetes pod | **Each has its own mount namespace** (unlike the network namespace, which is shared), so pod-mates stay distinguishable | works |
| Host processes | share the root mount namespace | resolves to the existing `host_process` verdict, same as the v2 root cgroup |
| `unshare -m` inside a container | the process gets a mount namespace the resolver never saw | unknown key → existing pending/escalation path; attribution is lost for that process until the next scan. **Document as a v1 limitation** |
| Two containers deliberately sharing a mount namespace | one key, two containers | must resolve **ambiguous**, never pick one (delete-safety rule 5) — needs an explicit verdict reason |
| `cgroupns=host` containers | already a documented v2 limitation | unchanged |
| Start/stop on v1 *before* WP4 | visibility, and therefore the lifecycle journal, inverts | §18.1.1 — fixed by WP4, not by this table |

There is also an honest asymmetry to record in the release notes: on v1 the feature is *correlating
on a namespace*, not on a cgroup, and the two do not fail in the same ways.

---

## 18.5 Phasing — and how it maps onto the O4 decision

The packages split cleanly along the exact line O4 asks about.

| Phase | Packages | Delivers | O4 option |
| --- | --- | --- | --- |
| **0** | WP1 | v1 detected and logged; silent failure becomes diagnosable | ship regardless — **shipped 2026-10-05** |
| **1** | WP2 + WP3 + WP4 | container **inventory and baseline** work on v1. No protocol change, no FIM change | *"inventory-only support"* |
| **2** | WP5 + **WP6a** + WP6b | event-driven container **FIM** works on v1, correlating on the **same cgroup inode the store uses**, filtered in-kernel exactly as on v2 | *"full support"* — **chosen 2026-10-06** |
| 2′ | WP5 + WP6b only | the fallback: correlating on `mnt_ns`, filtered in userspace | taken only if WP6a's BPF rebuild cannot be scheduled |
| **close** | WP-ISSUE | #37203's index tells the truth about v1 | every option, including "v2-only" |

WP-ISSUE runs **last in whichever phase turns out to be the last**, once that phase is measured —
its content is phase-dependent, so running it early writes down an outcome that has not happened
yet. It is not optional on the "declare it v2-only" branch either: that is an answer to O4, and an
answer still has to be recorded.

Phase 1 needs no wire-protocol change, because syscollector only calls `list`. That is a genuinely
useful property: **inventory-only v1 support is reachable without touching the IPC contract or FIM's
hot path**, which makes it a far smaller commitment than Phase 2.

**Phase 2 was chosen on 2026-10-06, on route 2 rather than 2′.** The deciding facts were measured,
not argued: `mnt_ns` is recycled across containers and would need the removal grace and pending TTL
disabled on legacy hosts, while the v1 cgroup id is not recycled, is the number WP2 already keys the
store on, and filters with `cgroup_allow_map` untouched — so route 2 carries none of §18.4's
mitigations and none of `19-option-c-test-report.md`'s cost. Its price is a BPF rebuild per
architecture in an environment that cannot produce one, which is why 2′ is kept as a fallback rather
than deleted.

If the decision is instead *"declare the feature cgroup-v2-only"*, **Phase 0 is still required** —
otherwise RHEL 8 and Amazon Linux 2 operators get a module that appears healthy and produces
nothing, or, since the state-aware filter, a module that appears healthy and produces a list of dead
containers. Phase 0 plus WP-ISSUE is then the whole of the work.

---

## 18.6 Verification

**Reproducing a v1 host cheaply.** Ubuntu boots v2, but `systemd.unified_cgroup_hierarchy=0` on the
kernel command line plus a reboot gives a pure v1 hierarchy on the existing `wazuh_manager` VM — no
new box needed. RHEL/Alma 8 and Amazon Linux 2 boot v1 by default and remain the fleet-accurate
targets.

**Negative control first, as with every change in this branch — and it is no longer "`list` is
empty".** Since the state-aware filter (§18.1) a v1 host publishes its *exited* containers, so on any
box that has ever run a container without `--rm`, `list` returns a non-empty array and an "is it
empty?" control passes while the feature is still dead. Capture instead, on the v1 host with today's
build:

1. `list` contains **no container whose state is running**, with at least one running container up —
   that is the real breakage, and it is what phase 1 has to flip.
2. The container baseline reports **zero** containers, despite a non-empty `list`.
3. The lifecycle delta emits `added` for a `docker stop` and `removed` for a `docker start`
   (§18.1.1). This is the control that proves WP4 fixed the inversion rather than preserving it, and
   it has no v2 counterpart to compare against — on v2 the same two actions emit `changed` twice.

| Level | What |
| --- | --- |
| Unit | `parseCgroupLine()` fixtures: pure v2, pure v1 (multi-controller), hybrid, and a malformed line. Controller-priority selection when `memory` is absent |
| Unit | `extractContainerId()` against v1 leaves for docker, containerd and CRI-O, systemd and cgroupfs drivers — asserting the existing regexes need no change |
| Unit | the three `listContainers()`-family guards under a `HostKey`: running-without-a-key hidden, stopped-without-a-key listed, running-with-a-key listed. Pins both halves of the WP4 guard so the §18.1.1 inversion cannot come back |
| Contract | store keyed by `HostKey`: both kinds, verdict liveness, `list` filtering |
| Integration | the `~/e2e-int` harness on a v1 host: `list` non-empty, inventory events carry `container.*`, FIM refused in phase 1 and working in phase 2 |
| Kernel | **WP6a's prerequisite**: on a v1 host, that the id read from `subsys[idx]->cgroup->kn->id` equals `stat()` of that controller's directory. Extend `rt_engine_drops_test`, which already asserts the v2 equivalent; until it passes, WP6a rests on an assumption |
| Kernel | the configured subsystem index is the controller WP2 chose — assert the `/proc/cgroups` count and the `bpf_core_enum_value()` reading agree, and that a disagreement refuses rather than picks one |
| Integration | on a v1 host with the allowlist active: an allowlisted container's events arrive, a non-allowlisted container's do not. The same five properties `rt_engine_filter_test` asserts on v2, which is the point — route 2 means legacy hosts behave like unified ones |
| Regression | the whole v2 capture from §15.10 re-run unchanged — the v2 path must be byte-identical, since `HostKey{cgroupInode, …}` carries the same number it does today |

That last row is the one that matters most: this plan changes the shape of code that currently works
on every supported host. The v2 evidence in §15.10 is the baseline it has to reproduce.

---

## 18.7 Open questions

1. ~~**Is `mnt_ns` stable enough to be a correlation key in production?**~~ **Measured 2026-10-06 on
   `wazuh_manager` (Ubuntu 24.04, kernel 7.0.0-34, Docker 29.1.3). Answer: unique in SPACE, not in TIME —
   usable, but only with the mitigations below.**

   | Property | Result |
   | --- | --- |
   | Distinct between concurrently running containers | **pass** (4/4 distinct) |
   | Distinct from the host's root namespace | **pass** |
   | Stable while the container runs | **pass** (5 samples) |
   | `docker exec` processes share the container's namespace | **pass** — their file events attribute correctly |
   | Survives `docker restart` / `stop`+`start` | same inode reused |
   | **Distinct across sequential containers** | **FAIL — 8 different containers, 8 different ids, all got inode `4026532274`** |

   The last row is the finding. Namespace inode numbers come from `nsfs` and are **recycled
   immediately**: destroy a container and the next one started is handed the same number. The
   control run makes the contrast unambiguous — over the identical sequence, cgroup inodes were
   `55212, 55292, …, 55772`, **8 of 8 distinct and monotonically increasing**.

   So `mnt_ns` is strictly weaker than the cgroup inode, and weaker in the one dimension this design
   leans on hardest. Three places assume a key stays meaningful for a while after its container
   stops, and each is now wrong on a legacy host:

   - **The removal grace.** `MetadataStore` deliberately keeps a removed container's entry for
     `REMOVAL_GRACE` so late events can still be attributed. Within that window the kernel may
     already have given the inode to a new container, so the grace does not merely fail to help —
     it **mis-attributes the new container's events to the dead one**. On a legacy host the grace
     must be **zero**: there is nothing a late event can safely be served against.
   - **The pending / cold-resolve path.** An unknown key is parked and resolved later. By then it
     may belong to a different container.
   - **Any cached key held across a container's lifetime**, in FIM or in a consumer.

   `startedAt` (WP-P4, already landed) is what distinguishes one run from the next and should be
   paired with the key wherever a stale entry could survive.

2. **The in-kernel filter cannot select containers on a legacy host, and WP6 as written does not say
   so.** `event_is_wanted()` looks up `cgroup_allow_map` by `bpf_get_current_cgroup_id()`
   (`bpf/rt_file.bpf.c:173-185`), which is the collapsed constant there — so an allowlist built on
   the **current BPF object** matches either every event on the node or none of them. Phase 2 on
   that object has to run `RT_CGROUP_MODE_ALL` and filter on `ev->mnt_ns` in userspace, which is
   precisely the mode the allowlist change (`541077159e`) moved away from and measured a cost for.

   **The helper is the limit, not the kernel.** `bpf_get_current_cgroup_id()` returns the task's
   cgroup id in the *v2* hierarchy; a BPF program can read the v1 controller's own kernfs id by
   CO-RE (`task->cgroups->subsys[memory_cgrp_id]->cgroup->kn->id`, every link verified in BTF). That
   is the **same inode the resolver already keys on** after WP2, it is not recycled, and it filters
   with `cgroup_allow_map` untouched — so it removes the reuse problem and the cost together. It
   costs a rebuilt BPF object per architecture, which this build environment cannot produce.

   Both of these are set out at length, with the raw probe output, the kernfs/nsfs reason behind
   them and the cost restated against doc 19's medians, in
   [`20-mnt-ns-key-and-legacy-filter-mode.md`](20-mnt-ns-key-and-legacy-filter-mode.md).
3. **Which controller should be canonical on v1?** The priority list above is a proposal; a survey of
   what RHEL 8 and AL2 actually mount by default would settle it. **Raised in importance by the
   route-2 decision:** the choice is no longer merely "any one, as long as it is the same one" — it
   is now also what the BPF program is configured to read, so a host where the resolver and the
   engine disagree about it attributes events to the wrong cgroup rather than to none. The mechanism
   that keeps them in step is WP6a's configured index; this question is about picking well, not
   about keeping them consistent.
4. ~~**Does the 32-bit `mnt_ns` field need widening?**~~ **Closed, 2026-10-05, no.** The BPF side
   reads `ns.inum` into a `__u32` (`get_mnt_ns_inum()`, `bpf/rt_file.bpf.c:380-390`) and the contract
   declares `unsigned int mnt_ns` (`rt_event_contract.h:89`) — the two match the kernel's own type
   for a namespace inode exactly, so there is nothing to widen. It still travels as a decimal string
   on the wire (WP5): the JSON slot is shared with 64-bit cgroup inodes, and the encoding is a
   property of the slot, not of the value in it.
5. **Should Phase 2 exist at all?** Correlating FIM on a namespace rather than a cgroup is a
   different security property. If the answer is no, WP5/WP6 drop and O4 resolves to
   "inventory-only, permanently".
