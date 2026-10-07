# 22 — Container runtime security: end-to-end validation on real VMs

**Subject:** the first end-to-end run of container resolution, container FIM and container
syscollector inventory against real containers — the gap `19-option-c-test-report.md` §5 calls
*"the highest-value gap… the seams between `install()`, `syncAllowlist()` and the kernel are covered
by construction, not by observation."*

**Date:** 2026-10-07 · **Branch:** `37532-cgroup-v1-unified-resolver` @ `81f1581eda`
(contains `37532-5-0-0-container-integration` and `37532-container-lifecycle-notify`)
**Issues:** #37203 / #37532 / #37396 · **Indexer traffic: out of scope**

> **Status: IN PROGRESS.** Docker passes are complete on Ubuntu 22.04 and Debian 13; Kubernetes is
> complete on the manager host. The cgroup hybrid/legacy passes, the degradation injections and the
> manager-side alert assertions are not yet run. Rows marked *not-run* are not claims.

---

## 22.1 Headline results

| # | Result | Where |
|---|---|---|
| 1 | **GAP 1 confirmed in a real package and a real install.** The agent `.deb` ships no `rt_file.bpf.o`, so container file-change detection is dead on arrival in an officially built package. | §22.3 |
| 2 | **The BPF object cannot be built on Ubuntu 22.04 from distro packages** — its libbpf is too old for the cgroup-v1 controller walk. The obvious remedy for GAP 1 does not work on a supported LTS. | §22.4 |
| 3 | **Container inventory persists nothing.** Every one of the 9 producing dimensions is rejected by the agent's own schema validator and deleted from DBSync. 702 discards observed; 0 rows with a `container_id` survive in any table. | §22.7 |
| 4 | **C16 is still live, on both hosts.** Containers removed in a burst remain in `list` indefinitely on an idle host — 3 of 5 stranded on Ubuntu 22.04 *and* Debian 13 — until one unrelated Docker event flushes them. O9 was recorded as fixing this. | §22.6 |
| 5 | Container **resolution**, **live FIM detection** and the **host negative control** pass on both hosts, across both BPF variants (kprobe and LSM). | §22.5, §22.8 |
| 6 | **Kubernetes passes in full**, including the two assertions nothing had tested: one independent record per container in a multi-container pod, and the transitive `ReplicaSet → Deployment` owner chain. | §22.9 |
| 7 | **A container running an init system is never resolved and is silently invisible** — no `list` entry, no baseline, no inventory, no log line. Triggered by PID 1 creating child cgroups, so it covers systemd-in-container images generally, not just KinD. | §22.9.1 |
| 8 | **GAP 2 fix verified in the production build** — no `libcurl.so.4` dependency. | §22.3 |

---

## 22.2 Environment

| | `wazuh_agent_ubuntu_22` | `wazuh_agent_debian_13` | `wazuh_manager` |
|---|---|---|---|
| OS | Ubuntu 22.04 LTS | Debian 13 (trixie) | Ubuntu 24.04.4 LTS |
| Kernel | 6.8.0-111-generic | 6.12.85+deb13-amd64 | 7.0.0-34-generic |
| cgroup | unified (v2) | unified (v2) | unified (v2) |
| LSM list includes `bpf` | **no** → kprobe variant | yes | yes |
| Docker | 29.1.3 (installed here) | 29.5.0 (present) | 29.1.3 |
| clang / bpftool | **absent** → installed 14.0.0 / 7.4.0 | **absent** → installed 19.1.7 / 7.5.0 | 18.1.3 / 7.7.0 |
| libbpf-dev | **0.5.0 — too old (§22.4)** | 1.5.0 — sufficient | sufficient |
| BTF | present | present | present |
| Pre-existing Wazuh | **wazuh-manager 4.14.6, live, 11 GB** — purged | wazuh-agent 5.0.0 — purged | manager 5.x + agent |
| Role | agent | agent | manager + agent + KinD |

Package under test: `wazuh-agent_5.1.0-0_amd64_81f1581.deb`, built from this worktree in the
standard Debian 7 packaging image.

**The LSM difference is load-bearing.** Ubuntu 22.04's LSM list has no `bpf`, so the engine logs
*"active LSM list does not include \"bpf\" -> preferring kprobe file_open variant"* and attaches
**4 programs, not 5**. Doc 19 measured the LSM variant; this is the first end-to-end run on the
**kprobe** path, which D13 calls the portable default.

---

## 22.3 Packaging: what actually ships

```
$ dpkg-deb -c wazuh-agent_5.1.0-0_amd64_81f1581.deb | grep -E 'libcontainer|rt_file|modern'
./var/ossec/lib/libcontainer_instances.so
./var/ossec/lib/libcontainer_baseline.so
./var/ossec/lib/modern.bpf.o
```

`rt_file.bpf.o` is **absent**, and absent from `/var/ossec/lib` after `dpkg -i`. `modern.bpf.o`
ships because it arrives as a precompiled external built on a separate clang-15 image; the eBPF
Module's object has no such arrangement, and no packaging image has clang or bpftool
(`packages/externals/build_external.sh:553` says so outright). Configure confirms it:

```
-- eBPF Module: skipping rt_file.bpf.o — no vendored vmlinux.h and no usable bpftool;
   no prebuilt at .../prebuilt/x86/rt_file.bpf.o; librt_engine still builds,
   rt_open() will report eBPF unavailable at runtime.
```

**Consequence:** an agent installed from an official package performs the startup baseline and then
detects no further container file changes. Everything in §22.5 below required hand-building and
installing the object.

**GAP 2 verified in the production build.** The packaged `libcontainer_instances.so` needs only
`libwazuhext.so` — the `libcurl.so.4` dependency is gone. Shipped sizes 941,840 and 1,880,304 bytes.

---

## 22.4 The BPF object cannot be built on Ubuntu 22.04 from distro packages

The obvious remedy for GAP 1 is "build it on the target". On Ubuntu 22.04 that fails:

```
rt_file.bpf.c:232:33: warning: implicit declaration of function 'bpf_core_field_offset'
rt_file.bpf.c:232:55: error: expected expression
rt_file.bpf.c:232:71: error: use of undeclared identifier 'subsys'
```

`libbpf-dev` on 22.04 is **0.5.0**, and its `bpf_core_read.h` does not define
`bpf_core_field_offset` — the macro the cgroup-v1 controller walk depends on
(`rt_file.bpf.c:232`). The repo's `external/libbpf-bootstrap` ships only a prebuilt `libbpf.so`
with **no headers**, so `find_path(RT_LIBBPF_HEADER_DIR bpf/bpf_helpers.h)` resolves to the distro's.

Built successfully after dropping in upstream libbpf 1.4.5 headers: 1,352,840 bytes, all five
programs present (`lsm/file_open`, `kprobe/vfs_open`, `kprobe/security_inode_setattr`,
`kprobe/vfs_unlink`, `kprobe/vfs_rename`). Debian 13 needs no workaround — libbpf 1.5.0 has the
macro. **Any plan to close GAP 1 by building on the target must account for this.**

---

## 22.5 Resolution and FIM — Ubuntu 22.04, Docker

| # | Assertion | Result | Evidence |
|---|---|---|---|
| 1.1 | Both daemons report the host cgroup mode, and agree | **PASS** | modulesd `Host cgroup hierarchy: unified (v2); container attribution is supported`; syscheckd `cgroup_id is a usable correlation key`; `stat -fc %T` = `cgroup2fs` |
| 1.2 | Enrichment socket listening | **PASS** | `Enrichment query socket listening at queue/sockets/container_instances` |
| 1.3 | **`list` key equals `stat()` of the container's cgroup** | **PASS** | `"key":"13774"`, `"cgroup_id":"13774"`; `stat -c %i` of the cgroup dir = **13774** |
| 1.3b | Reply is protocol v2 and declares its key kind | **PASS** | `"version":2`, `"data":{"connector":"docker","key_kind":"cgroup"}` |
| 1.6 | eBPF engine loads in allowlist mode | **PASS** | `4 program(s) attached, ABI 1.1, cgroup filter allowlist, skip mask 0x1` |
| 2.1 | Handoff pair, in order | **PASS** | `started; staging container file events until the baseline walk commits.` → `baseline walk committed; the reconcile consumer is now live.` |
| 2.3 | Live create / modify / delete detected and attributed | **PASS** | `"type":"modified"` `/data/f1.txt`, `"type":"added"` `/data/f3.txt`, `"type":"deleted"` `/data/f2.txt`, each `"mode":"whodata"` |
| 2.5 | **Host writes are not attributed to a container** | **PASS** | wrote `/data/hostfile.txt` on the host → **0** events carrying a `container` block |
| 2.6 | `docker stop` keeps rows, keeps listing, emits no deletes | **PASS** | still listed; `"key":"0"`; **0** `deleted` events; `fim.db` rows intact |
| 2.6b | `docker start` re-resolves to the **new** cgroup | **PASS** | key `13774` → **`19660`**; `stat` agrees |
| 2.8 | **Burst of 5 starts inside one debounce window** | **PASS** | 5 of 5 in `list`, including the last started — O9's serious half |
| 2.7 | Removal sweep on an idle host | **FAIL — §22.6** | 3 of 5 stranded |

The full enrichment block is correct and complete — `container.id`, `image.{name,digest}`, `name`,
`network[{ip,name:"bridge"}]`, `oci_mounts`, `restart_count`, `runtime:"docker"`, `pid`, `started_at`.
`network[].name` is `"bridge"` for Docker, as documented.

---

## 22.6 DEFECT — C16 is still live: burst removals strand entries in `list`

Five containers removed with `docker rm -f` on an otherwise idle host. Three were never reconciled:

```
t+0s   burst still listed = 3
t+30s  burst still listed = 3
t+60s  burst still listed = 3      <- past REMOVAL_GRACE (60 s)
t+90s  burst still listed = 3
docker ps -a | grep -c '^burst'  ->  0     (gone from Docker)

# one unrelated event
docker run --rm alpine true
t+15s  burst still listed = 0
```

Stable across four samples and well past the grace, then flushed entirely by a single unrelated
Docker event. That is precisely the C16 signature recorded in `12-blocking-decisions.md` §12.16 —
*"an unrelated `docker run --rm alpine true` produced one and `list` emptied within seconds"*.

**This matters because O9 is recorded as fixed** (`37203-agent-integration-issue.md:260`, the
trailing-edge debounce driven by the event stream's idle tick). The fix evidently handles a single
removal but not a burst: the trailing edge fires once and reconciles the snapshot it sees, leaving
removals suppressed earlier in the burst stranded until some later event.

**Consequence:** on an idle host a removed container stays in `list`, so consumers keep its rows and
FIM keeps its cgroup allowlisted. Reproduce with the block above. Needs a fix and a regression test
that removes **several** containers inside one debounce window, not one.

---

## 22.7 DEFECT/BOUNDARY — container inventory persists nothing

The collection half works. Persistence does not.

```
Container baseline scan finished (1 container(s),  78 row(s), 0 partial, 0 stale cleaned)
Container baseline scan finished (5 container(s), 390 row(s), 0 partial, 0 stale cleaned)
```

78 rows per container, scaling exactly. Then:

```
Schema validation failed for Syscollector message
  (table: dbsync_processes, index: wazuh-states-inventory-processes).
  Errors:   - container: Field not allowed in strict mode
"Discarding invalid Syscollector message" × 702
```

Rejected tables — **9 distinct**, i.e. every producing dimension except `services`, which D14 says is
always empty for containers: `dbsync_groups`, `dbsync_hwinfo`, `dbsync_network_address`,
`dbsync_network_iface`, `dbsync_network_protocol`, `dbsync_osinfo`, `dbsync_packages`,
`dbsync_processes`, `dbsync_users`.

```sql
SELECT count(*) FROM dbsync_packages      WHERE container_id <> '';  -- 0
SELECT count(*) FROM dbsync_processes     WHERE container_id <> '';  -- 0
SELECT count(*) FROM dbsync_osinfo        WHERE container_id <> '';  -- 0
SELECT count(*) FROM dbsync_network_iface WHERE container_id <> '';  -- 0
```

**The SCA load-order question is answered, and it is the bad case.** SCA is enabled in the stock
agent configuration, SCA initialises the process-wide `schema_validator` singleton, and syscollector
then validates against templates that have no `container` property. Container inventory therefore
produces **nothing persistent at all** on a default install — not merely "nothing reaches the
indexer".

**Container FIM is affected differently and less severely.** Its baseline rows are rejected the same
way:

```
Schema validation failed for container FIM baseline row <cid>:/data/f1.txt
  (index: wazuh-states-fim-files). Errors: container: Field not allowed in strict mode
```

but the local `file_entry` rows are written first and survive, which is why detection in §22.5 works:

```sql
SELECT container_id, path FROM file_entry WHERE container_id <> '';
19860b3e...|/data/f1.txt
19860b3e...|/data/f2.txt
```

The rejected payload is a well-formed, fully enriched document — the schema is the only thing
refusing it. This is #37203-3/-4 and is external to this branch, but the **syscollector** half is a
stronger statement than the design notes make: not "invisible in the indexer", but "collected,
discarded, and deleted from DBSync".

> `fim.db-journal` was present during these reads, so row counts are indicative; the log lines are
> the authoritative evidence.

---

## 22.8 Debian 13 — the same Docker passes, the other BPF variant

Debian 13 uses the **LSM** `file_open` variant (its LSM list includes `bpf`) where Ubuntu 22.04 used
**kprobe**. Both attach 4 programs: the engine picks one `file_open` implementation, not both.

| # | Assertion | Result | Evidence |
|---|---|---|---|
| 1.1 | Both daemons agree on the cgroup mode | **PASS** | `unified (v2); container attribution is supported` + `cgroup_id is a usable correlation key` |
| 1.3 | `list` key equals `stat()` | **PASS** | `"key":"7857"`; `stat -c %i` = **7857** |
| 1.6 | Engine in allowlist mode | **PASS** | `4 program(s) attached, ABI 1.1, cgroup filter allowlist`; `active LSM list includes "bpf"` |
| 2.3 | Live create / modify / delete | **PASS** | `modified` f1.txt, `added` f3.txt, `deleted` f2.txt, all `"mode":"whodata"` |
| 2.5 | Host writes unattributed | **PASS** | 0 container-attributed events for `/data/hostfile.txt` |
| 2.8 | Burst of 5 starts | **PASS** | 5 of 5 listed |
| 2.7 | Burst removal | **FAIL** | **C16 reproduces identically — see §22.6** |
| 3 | Inventory collection | **PASS** | `Container baseline scan finished (1 container(s), 78 row(s)…)` — same 78 rows/container as Ubuntu 22 |

The inventory row count per container (78) and the stranded-removal count (3 of 5) are **identical
across both hosts**, two kernels and two BPF variants.

---

## 22.9 Kubernetes — manager host, KinD `demo` / node `demo-control-plane`

Side-by-side topology (D4): a KinD node under the host dockerd, agent on the host. Scripted at
`37532-desing-analysis/kind-setup.sh`; a two-container pod (`writer` + `sidecar`) exists precisely so
assertion 4.5 is testable.

| # | Assertion | Result | Evidence |
|---|---|---|---|
| 4.1 | kubeconfig accepted, no insecure-TLS warning | **PASS** | client-cert credentials; no `TLS verification … DISABLED` line |
| 4.3 | `runtime`, container-level name, pod network, qualified image | **PASS** | `"runtime":"kubernetes"`; names `writer` / `sidecar` (not the pod's); `"network":[{"ip":"10.244.0.5","name":"pod"}]`; `docker.io/library/busybox:latest` |
| 4.4 | `kubernetes` object complete, empty keys **omitted** | **PASS** | `{"annotations":{"wazuh.com/spike":"37532"},"namespace":"default","node":{"name":"demo-control-plane"},"owner_refs":[…],"pod":{"name":"cfim-k8s-demo-68467ffc64-8dcpk","uid":"1cdf1384-…"}}`. `local-path-provisioner` has **no `annotations` key at all** rather than `{}` |
| 4.5 | **Multi-container pod → one independent record per container** | **PASS** | `writer` id `fc01731c…` key **16097**; `sidecar` id `f7e200f7…` key **16177** — distinct cgroups, same pod IP, identical `kubernetes` object |
| 4.6 | Transitive owner chain | **PASS** | `owner_refs:[{ReplicaSet cfim-k8s-demo-68467ffc64},{Deployment cfim-k8s-demo}]` |
| D15 | `kubernetes` nested **inside** `container`, never a sibling | **PASS** | 172 occurrences, all inside the `container` object; zero top-level siblings |
| — | serviceaccount mount surfaced | **PASS** | `oci_mounts:[{"destination":"/var/run/secrets/kubernetes.io/serviceaccount","ro":true,"source":"kube-api-access-ss7k5"}]` |

Dual-runtime registration confirmed: `"data":{"connector":"kubernetes,docker","key_kind":"cgroup"}`.
Baselines ran over the pod containers — `Container FIM baseline finished: 5 container(s) scanned,
2 row(s)` (only `writer`/`sidecar` have `/data`) and `Container baseline scan finished (5
container(s), 170 row(s))`.

---

## 22.9.1 DEFECT — a container that runs an init system is never resolved, and is silently invisible

The KinD node `demo-control-plane` is a running Docker container on this host and does **not** appear
in `list`. It is not an exclusion and the Docker connector is not broken — a plain container started
on the same host at the same moment appears immediately:

```
plainc                   docker      key=18201        <- resolved, listed
writer / sidecar / …     kubernetes  key=16097 …      <- resolved, listed
demo-control-plane       (absent)
```

**The mechanism.** `ProcCgroupResolver` joins a container to the cgroup inode that its processes sit
in *directly*. `kindest/node` runs systemd as its PID 1, so the container's own cgroup holds no
processes at all — they live in nested children:

```
/sys/fs/cgroup/system.slice/docker-b1b6….scope/            cgroup.procs: 0      inode 7964
/sys/fs/cgroup/system.slice/docker-b1b6….scope/init.scope/ cgroup.procs: 1      inode 9358
  child cgroups: init.scope, kubelet, kubelet.slice, dev-hugepages.mount, sys-kernel-config.mount, …

/sys/fs/cgroup/system.slice/docker-7b4467ec….scope/        cgroup.procs: 1      inode 18201
  child cgroups: none                                       <- plainc, the flat control
```

Both halves of the join then fail, and the store says so in two different ways:

| `resolve` | Answer |
|---|---|
| `7964` — the container's canonical cgroup | `{"status":"pending","retry_after_ms":500}` — parked and retried forever; no process ever appears there |
| `9358` — `init.scope`, where PID 1 actually is | `{"status":"not_container","reason":"host_process"}` |
| `18201` — `plainc`, control | fully resolved, with `container_id`, `container_name`, `image`, … |

So the container is listed by the Docker API, fails to join a cgroup, keeps `cgroupId == 0`, and is
then hidden by the *hide unresolved running* filter. **Nothing is logged** — it is indistinguishable
from the container not existing.

**Why this is more than a KinD curiosity.** The trigger is "PID 1 creates child cgroups", which is
exactly what any init system does. That covers systemd-in-container images (RHEL UBI `init`
variants, legacy applications packaged with systemd, CI runners-in-containers) as well as KinD.
For every such container:

- it is absent from `list`, so it is never baselined and never inventoried;
- its cgroup is never allowlisted, so its file events are filtered out in the kernel;
- an event from inside it that does reach userspace resolves to `host_process` and is discarded;
- the `pending` entry is retried indefinitely rather than reaching a verdict.

The `pending` answer is itself the evidence that this is not a deliberate exclusion: a container the
module meant to ignore would get a `VerdictEntry`, not an eternal retry.

**Not yet established:** whether the fix is to walk up to the nearest ancestor cgroup matching
`docker-<id>.scope` / the container id, or to key on the *container's* cgroup from the runtime's own
metadata rather than from `/proc/<pid>/cgroup`. Both have implications for the cgroup v1 path, which
derives its key the same way.

---

## 22.10 Not yet run

the fix direction for §22.9.1 · cgroup hybrid and legacy passes (Phase 5) · degradation injections (Phase 6: missing `rt_file.bpf.o`,
notify-socket unbind, map-full `disableAllowlist()`, drop-storm `rebaselineAll`) · manager-side alert
assertions via the engine file output · hash-versus-oracle (item 40) · ConfigMap live-invisibility
(4.9) · the Docker-connector observation in §22.9.

---

## 22.9 Incidents and deviations from the plan

- **A live snapshot of the manager VM stalled and had to be aborted.** `VBoxManage snapshot take
  --live` on a 12 GB VM degraded from ~450 KB/s to ~800 B/s, froze the VM for ~90 minutes and never
  completed; the agent VMs' enrolment failed meanwhile because the manager was unreachable. Recovered
  by killing the VM process tree: VirtualBox discarded the partial snapshot and reattached the base
  disk cleanly, and the KinD cluster survived. **Cold snapshots of powered-off VMs took seconds.**
  Snapshot cold, not live. `wazuh_manager` has no rollback point as a result.
- **`wazuh_agent_ubuntu_22` hosted a live 4.14.6 manager** (11 GB, enrolled agents), not an agent.
  Purged with the user's approval; snapshot `pre-37532-e2e` is the rollback.
- **Enrolment needed a distinct `<agent_name>`** — the manager already held `ubuntu-2204`. The tag
  belongs in `<agent><enrollment><agent_name>`; placing it directly under `<agent>` is rejected with
  `(1230): Invalid element in the configuration: 'agent_name'`.
- `WAZUH_MANAGER` is ignored by the 5.0 package: *"registration is configured by
  WAZUH_ENROLLMENT_TOKEN alone; this variable no longer has any effect."* The token's `adr` claim
  populated `<endpoint>` by itself.
