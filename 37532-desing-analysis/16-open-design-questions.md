# Open design questions — what still has to be refined to complete #37203

The questions that remain unanswered across the whole container-runtime-security effort, not just on
this branch. Twenty-one of them, each with an owner, what is true today, and what it would take to
answer it.

- **Written against:** `37532-5-0-0-container-integration` (`9ced58d751`), rebased onto
  `origin/5.0.0` (`c57890a8ea`) on 2026-09-22
- **Date:** 2026-09-23
- **Scope:** [#37203](https://github.com/wazuh/wazuh/issues/37203) and its five spikes —
  [#37382](https://github.com/wazuh/wazuh/issues/37382) (closed),
  [#37532](https://github.com/wazuh/wazuh/issues/37532),
  [#37533](https://github.com/wazuh/wazuh/issues/37533),
  [#37534](https://github.com/wazuh/wazuh/issues/37534),
  [#37837](https://github.com/wazuh/wazuh/issues/37837) (no comments — never started)

> **This is not [12](12-blocking-decisions.md).** Doc 12 holds D1–D18: the decisions that block *this
> branch's* roadmap, eleven of which are now resolved and recorded there with their evidence. This
> document is wider and later. It asks what is still undecided across the six issues — including the
> issue nobody on this branch owns (#37837), and the ends that #37382 left open when it closed.
> Where a question is already framed as a decision in doc 12, its D-number is given and the argument
> is **not** restated.

---

## 16.1 How to read this

Each question carries four things, because the question alone has never been the hard part:

| Field | Why it is here |
| --- | --- |
| **Owner** | Nine of the twenty-one are not this project's to answer. Naming the owner is what turns a question into a request. |
| **True today** | What the code actually does right now, with the file and line, so the question is asked against the implementation rather than against the plan. |
| **Answerable by** | A measurement on a real node, a team outside this project, or a decision someone is willing to sign. These are not interchangeable and they do not take the same time. |
| **Blocks** | What stays unbuildable, or ships wrong, while it is open. |

A question is in this document only if the answer **changes what gets built or what gets shipped**.
Questions whose answer is "a safe default, revisit with data" are in
[12 §12.3](12-blocking-decisions.md#123-blocking-decisions) under *Not blocking*, and are not
repeated here.

---

## 16.2 Index

| Q | Question | Issue | Owner | Answerable by |
| --- | --- | --- | --- | --- |
| **Q1** | What is the indexer document shape for container context? | #37837 | indexer / #37203-3 | decision + schema change |
| **Q2** | Does container inventory get its own index, or ride the existing state indices? | #37837 | indexer / #37203-3 | decision |
| **Q3** | How is `rt_file.bpf.o` supplied, and is a committed binary acceptable? | #37533 | build / release engineering | decision + policy |
| **Q4** | Does Docker's `listContainers` pass `all=1`? *(D6)* | #37382 | `container_instances` | decision |
| **Q5** | What authorises deleting a container's state, on a host where nothing is happening? | #37532 / #37534 | this project | decision + fix |
| **Q6** | Which id space do `uid`/`gid` mean on a container row? | #37837 / #37534 | this project + indexer | decision + schema wording |
| **Q7** | Does an event carry the container-internal path, the host path, or both? | #37533 / #37837 | this project + indexer | decision + schema wording |
| **Q8** | Does `container_instances` publish a lifecycle delta? *(D7)* | #37532 | `container_instances` | decision |
| **Q9** | What is the *guaranteed* create trigger for container FIM? | #37533 | this project | decision (measurement done) |
| **Q10** | Does `docker restart` change the cgroup inode? *(D8)* | #37382 | needs a real node | measurement |
| **Q11** | What re-baselines a container that is already known? | #37532 | this project | decision, after Q8/Q10 |
| **Q12** | What does the agent do on cgroup v1? *(D11)* | #37533 | this project + product | decision |
| **Q13** | What kernel and LSM configuration is *claimed* supported? | #37533 | this project + product | decision + test matrix |
| **Q14** | What privileges does the feature require, and what degrades without them? | #37203 | this project + product | decision + code |
| **Q15** | Do two eBPF engines ship, or does A4 land first? *(D9)* | #37533 | this project | measurement |
| **Q16** | What is v1's supported container count, and what happens above it? | #37203 | product + this project | measurement (item 39) |
| **Q17** | Which shipped defaults are still placeholders? | #37532 / #37534 | this project | measurement (item 39) |
| **Q18** | What is the operator-facing configuration surface across two consumers? | #37203 | product + this project | decision |
| **Q19** | How does an operator know container coverage is *not* working? | #37203 | this project + product | decision |
| **Q20** | Who signs the coverage matrix and the `setns` exception? | #37532 | #37203-4 | sign-off |
| **Q21** | Who executes the two acceptance criteria that were never run? | #37532 | this project | measurement (items 39–40) |

---

## 16.3 Tier A — nothing ships until these are answered

### Q1 — What is the indexer document shape for container context?

*(owner: indexer / #37203-3 · issue: #37837)*

**True today.** Every container row carries its context as a per-row blob. No schema in
`external/indexer-plugins` carries a `container` field — `fim-files.json` included — so ten indices
reject every container document under strict mapping, measured 2026-09-08. Local `file_entry` rows
and stateless alerts are unaffected, which is exactly why detection looks like it works while the
**stateful half delivers nothing**.

> Verification note: `external/indexer-plugins` is a fetched external and is not present in this
> checkout (`schema_validator/CMakeLists.txt:26-27` still globs it from outside the tree), so this
> could not be re-verified after the rebase. Nothing observed suggests it changed.

**The question is not just "add a field."** Three shapes are possible and they cost differently:

1. **An inline `container` object on every state row.** Simplest to emit, and what the code does
   today. Duplicates image name, digest, labels and runtime on every one of potentially millions of
   file rows.
2. **A container dimension row plus a `container_id` foreign key.** This is roadmap item 17, deferred
   precisely because it is a schema change nobody had authority to make. Cheapest at rest, requires
   the consumer to join.
3. **Both** — a small denormalised subset inline (id, name, image) for filtering, the full record in
   a dimension row.

**Answerable by:** a decision from whoever owns the state indices, followed by mappings. Not
closable from this branch under any of the three shapes.

**Blocks:** the entire stateful path for both consumers; roadmap item 17; and the per-row context
duplication finding in [04](04-findings-performance.md), which only shape 2 or 3 fixes.

### Q2 — Does container inventory get its own index, or ride the existing state indices?

*(owner: indexer / #37203-3 · issue: #37837)*

**True today.** Syscollector collects eleven data classes per container (processes, ports, users,
groups, packages, OS, net interfaces, addresses, protocols, services, hardware). Each is written
through the same DBSync path as its host equivalent, so each lands — or would land — in the same
index as the host's rows for that class.

**The question.** Do a host's packages and a container's packages belong in one index distinguished
by a field, or in separate indices? One index keeps queries uniform and doubles down on Q1's field
question. Separate indices make cardinality and retention independently tunable, which matters
because a hundred containers multiply row counts by roughly a hundred for classes like packages,
while host rows stay constant.

There is also a row that has no host equivalent at all: **the container itself**. Q1 shape 2 needs
somewhere to put it.

**Answerable by:** the same decision-maker as Q1, and ideally in the same sitting.

**Blocks:** capacity planning (#37837's stated scope), retention policy, and the shape of Q1.

### Q3 — How is `rt_file.bpf.o` supplied, and is committing a binary acceptable?

*(owner: build / release engineering · issue: #37533)*

**True today.** The lookup path is in place (`94d697c39d`) and the route is *provisionally* decided
in [14 §14.6](14-spike-integration-plan.md#bd2721021b-only-fixed-half-of-it-the-object-has-no-supply)
— a committed per-architecture prebuilt. But:

- `shared_modules/ebpf_provider/prebuilt/arm64/` and `.../x86/` exist and are **empty**; only
  `README.md` and `.gitignore` are committed.
- **Zero** of the four `check_files` CSVs name `rt_file.bpf.o`; all four name `modern.bpf.o`.
- The compile-from-source branch needs `clang`, libbpf headers, `bpftool` and a vendored per-arch
  `vmlinux.h`, none of which a package-build container has — `libbpf-bootstrap` arrives precompiled.

So a **packaged agent has no engine**, and container FIM degrades to a startup snapshot that is
never updated. Everything else in the FIM path is moot until this lands.

**The question has two halves, and only the first is technical.** The technical half is which route
— a committed prebuilt, a build-time compile, or shipping the object through the deps tarball the
way other precompiled artefacts already arrive. The second half is policy: **does this repository
accept a committed, load-tested `.o` binary**, with what reproducibility and re-signing story when
the BPF source changes? Nobody outside this analysis has been asked.

**Answerable by:** a decision from whoever owns the packaging pipeline, then per-architecture builds,
a load test on a real kernel per architecture, and four CSV rows.

**Blocks:** shipping the event path at all. This is the single largest gap between "validated on a
node" and "works when installed".

---

## 16.4 Tier B — the semantics both consumers read

Both FIM and Syscollector derive **deletion** from the same `container_instances` list. Anything
ambiguous about that list is ambiguous twice, in two processes, with no shared code to fix.

### Q4 — Does Docker's `listContainers` pass `all=1`? *(D6)*

*(owner: `container_instances` · issue: #37382)*

**True today.** It does not — `docker_api_client.cpp:117` requests
`/v<version>/containers/json` with no query. A container stopped for longer than the 60 s removal
grace is therefore reported **gone**, and both consumers delete its rows. The "stopped is not gone"
guarantee stated in [06 §6.8](06-proposed-architecture.md#68-deletion-semantics-stated-once) holds
for **Kubernetes only**.

**The question, restated as product behaviour:** after `docker stop`, should the agent keep
reporting that container's files and packages? `all=1` says yes, and puts exited containers in the
reply indefinitely — which is its own problem, because "indefinitely" is how a node accumulates
thousands of dead entries. No is defensible; it just has to be *written down*, because two consumers
already depend on the answer and neither states it.

**Answerable by:** a decision. Small code change either way; the semantics note is the deliverable.

### Q5 — What authorises deleting a container's state on a host where nothing is happening?

*(owner: this project · issue: #37532 / #37534)*

**True today, and this is a live defect.** `m_reconcilePending` is written at
`docker_connector.cpp:93` and cleared at `:71`, and **read nowhere**. The removal grace only expires
inside `applySnapshot()`, and nothing re-runs it on the Docker path without another event. Measured:
a container removed with `docker rm -f` stayed in `list` for **two minutes** past its 60 s grace; an
unrelated `docker run --rm alpine true` flushed it in seconds
([C16](03-findings-correctness.md#c16--dockers-deferred-reconcile-is-dropped-not-deferred)).

So on an idle host, **a removed container's rows are never swept by either consumer**. The rescan
masks a missed create; nothing masks a missed expiry.

**The question behind the bug.** The immediate fix is small — read the flag, add a floor. But the
design question it exposes is whether the system has a **reconciliation floor at all**: a periodic
"no matter what events did or did not arrive, reconcile now" interval, under which every event-driven
path is a latency optimisation rather than a correctness dependency.
[06](06-proposed-architecture.md) assumes one exists. It does not.

**Answerable by:** a decision on the floor interval (placeholder: 24 h) plus the C16 fix. The
interval wants item 39's numbers; the floor's *existence* does not.

**Blocks:** any claim that container state converges. Also blocks Q8/Q11 being safe to build on —
a lifecycle delta without a floor is strictly worse than the rescan it replaces.

### Q6 — Which id space do `uid` and `gid` mean on a container row?

*(owner: this project + indexer · issue: #37837 / #37534)*

**True today, and it changed since [C7](03-findings-correctness.md#c7--uidgid-semantics-are-inconsistent-between-data-classes-and-wrong-under-user-namespaces) was written.** The file walker now translates:
`rootfs_file_walker.cpp:174-175` reads `/proc/<pid>/uid_map` and `gid_map`, and `:200-201` emit
`container_uid` / `container_gid` through `IdMap::toContainer()`. But `toContainer` is used **only
there** — `grep` finds it in `rootfs_file_walker.cpp`, `id_map.cpp` and their tests, nowhere else.
Meanwhile `process_scanner.cpp` collects **no uid at all**, and the user and group scanners read the
container's own `/etc/passwd`, which is already container-space by construction.

Net effect: file rows are container-space, user rows are container-space, process rows have no
owner, and **host rows in the same index are host-space** — one field name, two meanings, no marker
saying which.

**The question.** Does a container row's `uid` mean "as the container sees it" (the current
direction, and the useful one for a rule about a container's own contents) or "as the host sees it"
(the useful one for correlating with a host process)? If both are wanted, the document needs two
fields, which makes this a Q1 schema question too.

**Answerable by:** a decision, then either wording in the schema or a second field.

### Q7 — Does an event carry the container-internal path, the host path, or both?

*(owner: this project + indexer · issue: #37533 / #37837)*

**True today.** Baseline rows are read through `/proc/<pid>/root/<internal_path>` and stored under
the container-internal path, keyed `(container_id, path)`.
[C22](03-findings-correctness.md) found attribute events carrying **host** paths — that specific
defect was fixed, but the underlying contract was never written down anywhere a reviewer or a rule
author could find it.

**The question.** `/etc/passwd` inside a container and `/etc/passwd` on the host produce rows with
the same `path` and different `container_id`. That is correct for the primary key and ambiguous for
anyone writing a rule or reading an alert. Does the document need a host-side path (which only
exists while a PID is alive, so it is not stable), a mount-source reference, or nothing beyond
`container_id`?

**Answerable by:** a decision, then a line in the schema and a line in the user documentation.

---

## 16.5 Tier C — the lifecycle contract

### Q8 — Does `container_instances` publish a lifecycle delta? *(D7)*

*(owner: `container_instances` · issue: #37532)*

**True today.** No delta API. [10](10-container-instances-delta-plan.md) specifies one — a journal
plus additive `epoch` / `seq` / `delta` / `events[]` / `resync_required` on `op: "list"` — and it was
**not implemented**; the header of that document now records what runs instead. Syscollector
re-scans all eleven data classes for every container every cycle, which is the polling this work was
meant to remove.

**What changed since doc 10 was written, and why the question is narrower now.** Container FIM
reached the goal by another route and does **not** need the delta to discover new containers
(measured — see Q9). So the delta is no longer a correctness prerequisite for FIM. It remains the
prerequisite for *Syscollector* baseline-once, and for switching the eBPF filter from
`RT_CGROUP_MODE_ALL` to `RT_CGROUP_MODE_ALLOWLIST`, which is what would stop the whole host's
write-intent opens flowing through the ring.

**Answerable by:** a decision from `container_instances`' owner. The consumer side is specified.

**Blocks:** roadmap item 20 in its entirety, item 22, item 23, and the allowlist filter mode.

### Q9 — What is the *guaranteed* create trigger for container FIM?

*(owner: this project · issue: #37533)*

**True today, and this is the one measured answer in this tier.** A container created after the
baseline **is** fully covered: five files, five `added` alerts, about two seconds, with no lifecycle
delta. Traced per event, the trigger is **runc's init** — four write-intent opens of procfs and
sysfs files (`/proc/<pid>/oom_score_adj`, `.../attr/apparmor/exec`,
`/proc/sys/net/ipv4/ip_unprivileged_port_start`, `.../ping_group_range`) arriving from a cgroup
nobody has mapped yet, which escalates to a re-walk
([12 §12.16](12-blocking-decisions.md#1216-the-lifecycle-question-answered-by-measurement-2026-09-08)).

`filter.cgroup_mode = RT_CGROUP_MODE_ALL` is hardcoded at `container_event_drain.cpp:410`, so this
works because the engine sees the **entire host**.

**The question.** Is "a container runtime will, in the course of starting a container, perform at
least one write-intent open on a regular file from the new cgroup" a property this project is
willing to depend on? It is not a documented contract of runc, containerd or CRI-O; it is observed
behaviour of one runtime at one version. It would not survive the move to `ALLOWLIST` (an unmapped
cgroup becomes invisible, not merely unattributed), and it has never been checked against CRI-O or a
gVisor/Kata runtime.

**Answerable by:** a decision — accept the dependency and document it, or require Q8's delta, or add
an independent floor (Q5) that makes the trigger a latency optimisation. The third is the only
option that does not depend on someone else's implementation detail.

### Q10 — Does `docker restart` change the container's cgroup inode? *(D8)*

*(owner: needs a real node · issue: #37382)*

**True today.** The correlation key is the cgroup v2 inode. Whether it survives a restart has never
been tested, on either the cgroupfs or the systemd cgroup driver. **Cannot be tested in WSL.**

If it reliably changes, `cgroupId` alone discriminates a restart and
[10 Phase 4](10-container-instances-delta-plan.md) shrinks. If it does not, `ContainerRecord` needs
`startedAt` and `pid` before Q11's trigger table is implementable at all
([C18](03-findings-correctness.md)).

**Answerable by:** one afternoon on a real node, both drivers. This is the cheapest open question in
the document and it gates the most design work per hour spent.

### Q11 — What re-baselines a container that is already known?

*(owner: this project · issue: #37532)*

**True today.** Nothing, by design: the baseline runs once at startup and eBPF events maintain it
thereafter. Re-baselining happens only as an *error* response — a cgroup that cannot be resolved, or
a drop counter that forces `rewalkContainer`.

**The question.** Roadmap item 23 calls for a trigger table: restart, image change, a mount added, a
drop burst, an interval elapsing. Which of those actually warrant a full re-walk, at what cost, and
which are better served by Q5's floor? A trigger table written before Q10's answer will get restart
detection wrong.

**Answerable by:** a decision, sequenced after Q8 and Q10.

---

## 16.6 Tier D — platform and privilege envelope

### Q12 — What does the agent do on cgroup v1? *(D11)*

*(owner: this project + product · issue: #37533)*

**True today, and doc 12's own text for D11 is now stale.** D11 says a v1 host "would silently
mis-attribute **every** event on the node to one bogus cgroup". That is no longer possible: the
branch refuses v1 at open — `container_event_drain.cpp:429` bails on `rt_host_cgroup_v1()`, and
`rt_engine.c:456-460` tells consumers to correlate on `mnt_ns` instead. Refusing is the right
default; wrong attribution is worse than none.

**The question is therefore not "prevent the bug" but "what do we claim".** RHEL 8 and Amazon Linux
2 default to v1. Options: no container coverage on v1 with an INFO log (current behaviour, needs
documenting); a `mnt_ns`-based correlation path (the engine already suggests it, nothing implements
it); or periodic-rescan-only coverage with no event path. Each is a different supported-platform
statement.

**Answerable by:** a product decision about the supported matrix, then either documentation or code.

### Q13 — What kernel and LSM configuration is claimed supported?

*(owner: this project + product · issue: #37533)*

**True today.** `rt_engine.c:473-476` probes `/sys/kernel/security/lsm` and prefers the
`lsm/file_open` program when BPF LSM is active, falling back to a kprobe variant otherwise. The
object is built through a host-BTF fallback when no vendored `vmlinux.h` is present. Validated on
exactly one configuration: Ubuntu 24.04.4, kernel 7.0.0-31, cgroup v2, BPF LSM active.

**The question.** Which of these does the product claim: BPF LSM required, kprobe fallback
supported, CO-RE with vendored BTF, host-BTF only? Each implies a different minimum kernel and a
different test matrix — and Q3's packaged object has to be built for whichever answer wins, because
the vendored-`vmlinux.h` decision is downstream of this one.

**Answerable by:** a decision plus a test matrix run on more than one kernel.

### Q14 — What privileges does the feature require, and what degrades without them?

*(owner: this project + product · issue: #37203)*

**True today.** The feature needs, at minimum: BPF load privileges, read access to the Docker socket
or a kubeconfig, `/proc/<pid>/root` traversal, and `CAP_SYS_ADMIN` for the `setns(CLONE_NEWNET)`
exception that network interfaces and addresses depend on
([07 §7.4](07-options-matrix.md#the-one-exception-that-must-be-documented-and-signed-off)). Two of
the three conditions attached to accepting that exception are **not met**: `setns` failing for lack
of capability does not log, and there is no fallback to the degraded `/proc/<pid>/net/dev` mode — the
class is simply absent.

**The question.** Is there a supported reduced-privilege mode, and what does it cover? An agent that
can read the Docker socket but cannot load BPF, or can load BPF but cannot `setns`, currently
produces a partial picture with no statement of what is missing — which is the "silent degradation"
pattern [03](03-findings-correctness.md) names as the root cause of several findings.

**Answerable by:** a decision on the supported modes, then the two missing conditions implemented.

### Q15 — Do two eBPF engines ship, or does A4 land first? *(D9)*

*(owner: this project · issue: #37533)*

**True today.** Two, still. `ebpf_whodata.cpp` does its own libbpf loading of
`lib/modern.bpf.o` (`#define BPF_OBJ_INSTALL_PATH` at line 33, twelve libbpf references in the file)
alongside `rt_engine`'s object. Two `bpf_object` loads, two 8 MiB rings, two drain threads, duplicate
kprobes on the same hooks — roughly double kernel-side file-hook work while both coexist. ADR-001
sanctions it; WP5 would collapse host whodata onto `rt_engine` and end it.

**The question is still waiting on its measurement.** `bpftool prog list` run_cnt / run_time_ns, on
a node under load, has never been run. If the cost is acceptable, A4 stays optional and WP5 is
cleanup. If it is not, WP5 becomes a ship blocker and joins Tier A.

**Answerable by:** one measurement on the VM, then a decision. Should be stated in the commit
message either way rather than left for a reviewer to discover.

---

## 16.7 Tier E — scale, defaults, operator experience

### Q16 — What is v1's supported container count, and what happens above it?

*(owner: product + this project · issue: #37203)*

**True today.** No node-level benchmark exists (roadmap item 39, never run — it needs a real
multi-container node). [04](04-findings-performance.md) models the costs and micro-benchmarks the
`/proc` resolver, but the numbers that matter — wall-clock per rootfs size, cold-start storm at
N = 10 / 50 / 100, image-digest de-dup saving — have never been taken. Per-dimension row budgets are
implemented (`ce04396e50`) and validated at small N.

**The question.** Is v1 stated to support 10 containers, 50, 100? And above the stated number, does
the agent degrade (longer intervals), cap (budgets, already present), or refuse? "Untested above N"
is an acceptable answer only if N is written down.

**Answerable by:** item 39, then a product statement.

### Q17 — Which shipped defaults are still placeholders?

*(owner: this project · issue: #37532 / #37534)*

**True today.** At least these, all picked rather than derived: the lifecycle journal ring size
(4096), the reconciliation floor interval (24 h — and see Q5, the floor does not exist yet), the
delta poll cadence, `container_baseline_interval`, the settle delay (500 ms), the resolver interval
(5 s), `max_resolves_per_cycle` (32), and the 8 MiB ring size the provider inherits.

**The question.** Which of these are user-configurable in v1, and which are internal? Every one made
configurable is a support surface and a compatibility commitment; every one left internal needs to be
right by default at the scale Q16 names.

**Answerable by:** item 39's numbers, then one pass over the configuration schema.

### Q18 — What is the operator-facing configuration surface across two consumers?

*(owner: product + this project · issue: #37203)*

**True today.** One `<container_instances>` block configures the metadata module in `modulesd`.
Container FIM is enabled by tagging `<directories>` entries `container`. Syscollector's container
scanning has its own interval inside the syscollector wodle. Three places, two daemons, one feature.

**The question.** Can an operator turn "container security" on and off as one thing? Can they enable
container FIM without container inventory, or vice versa? What happens when `<container_instances>`
is absent but a `container`-tagged directory is configured — which is currently reachable and, since
[C25](03-findings-correctness.md), no longer silent, but is also not documented as a supported state.

**Answerable by:** a product decision on the configuration model, then documentation.

### Q19 — How does an operator know container coverage is *not* working?

*(owner: this project + product · issue: #37203)*

**True today.** Better than it was, and still mostly by inference.
[C28](03-findings-correctness.md#c28--with-no-containers-list-reads-as-connector-unavailable) made
both consumers log a connector fault that was not occurring, on any host with no containers — fixed
in `976c7459c0`, with D5's genuine-unavailability suppression intact. But the positive signal is
still absent: nothing tells an operator that the BPF object failed to load, that the engine is
running in `ALL` mode, that a container's walk was truncated, or that events are being dropped.

**The question.** What is the minimum observable set — a log line, a state document, a metric — that
lets someone conclude "container FIM is covering these N containers right now"? Without it, Q3's
missing object and Q12's v1 refusal both look identical to working.

**Answerable by:** a decision, then a small amount of code. Cheap, and it makes every other question
on this list easier to verify in the field.

---

## 16.8 Tier F — the sign-offs the spikes still owe

### Q20 — Who signs the coverage matrix and the `setns` exception?

*(owner: #37203-4 · issue: #37532)*

**True today.** [07](07-options-matrix.md) contains the matrix — seven mechanisms across eleven data
classes, with a primary and a fallback per class, the in-container-exec rejection, and the `setns`
exception argued in full. **None of it has been ratified by anyone but its author.** #37532 named
`nsenter` as a candidate to "evaluate and most likely reject", and required that any unavoidable use
be "explicitly justified and flagged as a documented exception, not silently adopted". It was
silently adopted at `interface_scanner.cpp:149-162`; the write-up exists, the sign-off does not.

**The question is procedural, not technical:** who ratifies, and is the write-up in
[07 §7.4](07-options-matrix.md#74-in-container-execution-evaluation-and-rejection-deliverable-d6)
sufficient as a decision record, or does it need to be restated in the issue? Note Q14: two of the
three conditions the exception was conditionally accepted under are still unimplemented, so a
sign-off today would be signing off something the code does not yet do.

**Answerable by:** a sign-off. Deliverables 34, 35, 36, 41 are all in this state — written, unsigned.

### Q21 — Who executes the two acceptance criteria that were never run?

*(owner: this project · issue: #37532)*

**True today.** Two of #37532's own acceptance criteria have never been performed:

- **Item 39, cost and limits on a real node** — see Q16. Several deferred decisions are explicitly
  waiting on these numbers (Q15, Q17, and the floor interval in Q5).
- **Item 40, hash-versus-oracle validation** — comparing the baseline's hashes against in-container
  `sha256sum` for symlinks, sparse files, hardlinks, files on tmpfs and secret mounts, and
  userns-remapped containers. This is an explicit acceptance criterion of the issue and it has
  simply not been done.

**The question.** Item 40 in particular is the only thing that would catch a *systematically wrong*
hash — the class of defect that produces confident, consistent, incorrect alerts forever. Q6's
userns work makes it more urgent, not less, because ownership translation now differs between data
classes.

**Answerable by:** a real multi-container node and a day. Both are blocked on nothing but access.

---

## 16.9 What this document deliberately does not ask

Eleven of doc 12's eighteen decisions are **resolved**, with their evidence, and are not reopened
here: D1 (hybrid state model), D2 (port direction), D3 (import version), D4 (in-kernel filtering is
an optimisation — measured), D5 (thread ownership), D13, D14 (per-cgroup drop accounting),
D15 (never infer a deletion from an unreadable path), D16 (settle in the staging buffer),
D17 (what an incomplete scan authorises), D18 (the non-transactional upsert). The three still open
there — D6, D7, D8 — appear above as Q4, Q8 and Q10 because they are owned outside this project and
need to be *asked of someone*, not merely decided.

Also excluded: the maintainability tail (roadmap items 17, 22, 24, 26–29, 31, 33). Those are
engineering choices with obvious defaults, recorded in
[09](09-implementation-status.md#not-done--deliberately-deferred) with the reason each was deferred.
They do not need refinement; they need time.

---

## 16.10 Suggested order, and who has to be in the room

| Order | Questions | Who | Why first |
| --- | --- | --- | --- |
| 1 | **Q10** | anyone with a real node | One afternoon. Gates Q11 and shrinks doc 10 Phase 4. Cheapest answer-per-blocked-hour in the document. |
| 2 | **Q1, Q2** | indexer owners + #37203-3 | Longest external lead time, and the stateful half of the feature is worthless until they land. Start the conversation before anything else needs it. |
| 3 | **Q3** | packaging / release | Same reason: it is a policy question with an approval chain, not an afternoon of code. |
| 4 | **Q5** | this project | The one live defect in the list. Fix C16 and decide whether a floor exists, because Q8, Q9 and Q11 all change meaning depending on the answer. |
| 5 | **Q4, Q6, Q7** | `container_instances` + indexer | Three semantics decisions that should be made together and written into one note, since two consumers read all three. |
| 6 | **Q15, Q21** | this project, on the VM | Two measurements. Q15 decides whether WP5 is cleanup or a blocker; Q21 is an acceptance criterion that is simply owed. |
| 7 | **Q8, Q9, Q11** | `container_instances` + this project | The lifecycle contract, once Q5 and Q10 have made it safe to design. |
| 8 | **Q12, Q13, Q14, Q16, Q18** | product + this project | The supported-envelope conversation. One meeting, five answers, all of them documentation-shaped. |
| 9 | **Q17, Q19, Q20** | this project, then #37203-4 | Defaults, observability, signatures. Last because each depends on an earlier answer. |

Two observations about the shape of this list.

**Nine of twenty-one are not ours.** Q1, Q2, Q3, Q4, Q8, Q10, Q12, Q16 and Q20 need a decision,
sign-off or measurement from outside this project. Every day they stay unasked is a day of lead time
nobody is spending. The technical work they block is, in most cases, already specified.

**Only one is a bug.** Q5 is the single question in this document that describes something currently
broken rather than something currently undecided. Everything else is code that works, waiting for
someone to say what it should mean.
