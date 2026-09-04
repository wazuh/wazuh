# #37533 — Path-resolution volume-type behavior matrix

Deliverable requested by the issue: *"Path-resolution algorithm and volume-type behavior matrix... validated against real pod configurations."* This document is the matrix. It is derived from **code inspection of this worktree** (branch `spike/37533-fim-ebpf-integration`), not from a live kind cluster — see [Validation status](#validation-status) at the end for exactly what would still need a real cluster to confirm.

## How resolution actually works today (grounding)

Both the baseline walk (`rootfs_file_walker.cpp:39-138`) and the live per-event path (`container_live_fim.cpp:224`) resolve a container-internal path the same way:

```
host_path = "/proc/<pid>/root" + internal_path
```

`<pid>` is a live PID inside the container's PID namespace, obtained either from `ResolvePidsForContainer()` (baseline, scans `/proc/*/cgroup`) or from the eBPF event's own `pid` field (live path). This delegates all mount/overlay/bind-mount math to the kernel's own mount-namespace resolution — **no OCI mount-spec parsing is used for the resolution itself**.

`container_instances` *does* collect an `oci_mounts` list (`source`/`destination`/`ro`, see `container_record.hpp:41-51`, populated by `k8s_object_parser.hpp:65-94` for Kubernetes and `docker_object_parser.hpp:84-90` for Docker), and it rides through to the emitted document as descriptive metadata (`baseline_rows.cpp:108-115`). **It is never consulted by the resolver** — confirmed by grep, `oci_mounts`/`ContextFromResolveData` only ever writes into `ContainerContext`/JSON output, no read site outside serialization.

Two consequences that matter for the matrix below:

1. Because resolution is mount-**namespace**-based rather than mount-**spec**-based, it is largely agnostic to *which* volume type backs a given directory — a configMap tmpfs mount and a PVC block-device mount both just look like "a directory under `/proc/<pid>/root`" to this code. What actually varies across volume types is **not path resolution** but **whether the writing process's cgroup is the container's own** (this determines whether the eBPF event even attributes to the container at all) — see the next section.
2. The K8s enrichment's own mount parsing (`k8s_object_parser.hpp:63-64,72-79`) only distinguishes `hostPath` specially (it resolves the real host path); every other K8s volume type — `emptyDir`, `configMap`, `secret`, `downwardAPI`, `projected`, PVC, ephemeral CSI, image volume — collapses to `source = <volume name>`, an opaque string. **The enrichment data cannot itself tell you which volume type a given mount is**, so any matrix entry below that says "recommended handling: X" is a recommendation for future work, not something the current code acts on.

## The variable that actually matters: who writes, not what backs the mount

`fim_handle_container_whodata_event()` resolves enrichment via `ContainerInstancesClient::resolveByCgroupId(cgroup_id)` (`container_live_fim.cpp:188`) and drops the event unless the status is `resolved` (`container_live_fim.cpp:193-196`) — `notContainer` is dropped identically to a cold cache.

This means: **an event is only ever attributed to a container if the process that triggered it was running inside that container's cgroup at the time of the write.** For several Kubernetes volume types, the party that actually performs the write is not a process inside the container:

- **configMap / secret volumes**: the kubelet's periodic sync (`syncPod` reconciliation loop) updates these via an atomic symlink swap in a directory it owns (kubelet's own `atomic-writer`, historically ~1 min resync period) — this write happens **on the host, from the kubelet's own process/cgroup**, not from any process inside the pod's containers. A configMap update after the pod is already running will fire the eBPF hook (a real `rename`/`open` happens), but `cgroup_id` will resolve to the kubelet's cgroup → `resolveByCgroupId()` returns `notContainer` → **the event is silently dropped by the current live path.**
- **image volumes** (K8s 1.31+): mounted read-only by the kubelet/CRI at pod start, not written to at all in steady state — no live-write case to miss, but also nothing to test beyond baseline's initial directory walk.
- **hostPath, emptyDir, PVC, ephemeral CSI, Docker bind/named volume**: in the common case the write comes from a process *inside* the container (the application itself), so `cgroup_id` correctly resolves to that container and the event is captured normally.

This asymmetry — not filesystem type — is the dominant factor in the matrix below.

## Matrix

| Volume type | Typical writer | Hook fires? | cgroup → container resolves? | `/proc/pid/root` traversal | Live-path outcome (today) | Baseline-walk outcome (today) | Recommended handling |
|---|---|---|---|---|---|---|---|
| **Container rootfs (overlay)** | in-container process | Yes (`vfs_open`/`security_inode_setattr`/`vfs_unlink`/`vfs_rename`, `rt_file.bpf.c`) | Yes | Yes — reference case | **Works** | **Works** | None needed; this is the validated baseline case |
| **hostPath** | usually in-container process; *also* writable directly from the host if an admin/other workload touches the same host dir | Yes | Yes, when written from inside the container | Yes | **Works** for in-container writers. Writes from the host side (or another pod/process touching the same host dir) resolve to `notContainer` → dropped, silently invisible to container FIM | Works (directory walk sees current state regardless of who wrote it) | Document that only in-container-attributed writes are captured live; a host-side edit of a hostPath-backed file is invisible to container FIM until the next baseline/reconciliation. Cross-reference the existing host-FIM dedup question (§9 of the issue) — if the same host dir is also configured under regular `<directories>`, that's the only way a host-side edit gets alerted on at all today |
| **emptyDir (disk-backed, default)** | in-container process (app writes its own scratch data) | Yes | Yes | Yes | **Works** | **Works** | None needed for the common case; note that emptyDir contents are ephemeral and tied to pod lifetime — deletion-on-pod-removal is the existing, separately-tracked gap (container-removal deletion propagation, not this matrix) |
| **emptyDir (`medium: Memory`, tmpfs)** | in-container process | Yes (tmpfs opens still go through the generic VFS hooks) | Yes | Yes | **Works**, same as disk-backed emptyDir | **Works** | None needed; flagged only because tmpfs is sometimes assumed to bypass normal VFS instrumentation — it does not here |
| **configMap** | **kubelet** (atomic symlink swap on update), read-only from inside the container | Yes (fires on the host) | **No — resolves to kubelet's own cgroup, not the container's** | N/A — event dropped before path resolution is reached | **Update after pod start is silently dropped**; only the value present at baseline time is ever captured | **Works** for whatever state exists when the baseline walk runs | This is a real, previously-undocumented gap for the *live* path. Two options for future work: (a) accept configMap/secret as "baseline-only, no live updates" and document it explicitly as an unavailable-live-tracking case; (b) have the live path fall back to a **path-based** container lookup (does this path fall under any known container's monitored mount?) instead of relying solely on cgroup attribution, for exactly this class of host-attributed-but-container-relevant write |
| **secret** | same as configMap (kubelet atomic writer) | Yes | **No**, same mechanism as configMap | N/A | Same gap as configMap | Works at baseline time | Same recommendation as configMap |
| **downwardAPI / projected** | kubelet (same atomic-writer mechanism as configMap/secret for the pieces sourced from configMap/secret/downward API) | Yes | **No**, same mechanism | N/A | Same gap as configMap | Works at baseline time | Same recommendation as configMap; not independently verified against a real pod (no test cluster used for this pass) |
| **PVC (local-path-provisioner, e.g. kind's default)** | in-container process | Yes | Yes | Yes — it's a normal bind/block mount under the container's mount namespace | **Works** | **Works** | None needed for the common local-path case |
| **PVC (NFS-backed)** | in-container process | Yes (NFS client still goes through VFS) | Yes | Yes, but NFS attribute caching can make a freshly-changed remote file's `stat()` (mtime/size) briefly stale from the host's viewpoint depending on cache settings — could cause a missed or delayed diff, not investigated further here | **Likely works, with possible staleness** | **Likely works, with possible staleness** | Flag as unverified; needs a real NFS-backed PVC in a cluster to confirm attribute-cache behavior doesn't cause missed changes |
| **PVC / ephemeral CSI (FUSE-backed drivers, e.g. object-storage CSI)** | in-container process | Yes, FUSE still traverses the VFS layer on the host | Yes | Traversal via `/proc/pid/root` should work, but reading through a FUSE mount from *outside* the mounting context can be blocked by the FUSE daemon's `allow_other`/permission model depending on driver config and the UID `wazuh-syscheckd` runs as | **Untested — plausible failure mode**: hashing (`OS_MD5_SHA1_SHA256_File` in `container_live_fim.cpp:263`) could fail permission checks even though the eBPF hook fired and cgroup resolution succeeded | Same untested risk applies to the baseline walk's `HashFile()` call | Needs validation against an actual FUSE-based CSI driver; if it fails, the row would still get created (stat succeeds) but with hashes silently omitted (both code paths already tolerate `HashFile`/`OS_MD5_SHA1_SHA256_File` failure by just omitting the hash fields) |
| **Ephemeral CSI (generic, block-backed)** | in-container process | Yes | Yes | Yes | Same as PVC (local) | Same as PVC (local) | Treat as PVC-equivalent; the "ephemeral" lifecycle (tied to pod, not a separate PVC object) only affects cleanup, not the live-write path |
| **Image volumes (K8s 1.31+, OCI artifact mounted read-only)** | nobody — mounted read-only, populated once by the CRI at pod start | N/A in steady state (no writes expected) | N/A | Yes, for the one-time baseline read | Baseline captures the initial content; no live-update case exists by design (read-only) | **Works** | None needed beyond confirming read-only mounts don't need write-hook coverage; not independently verified (feature is new, not exercised in this pass) |
| **Docker bind mount** | in-container process, or a host process touching the same host path | Yes | Yes when written from inside the container; `notContainer` when written from the host side | Yes | Same profile as Kubernetes hostPath | Works | Same recommendation as hostPath |
| **Docker named volume** | in-container process (named volumes are Docker-managed directories under `/var/lib/docker/volumes/<name>/_data`, almost never written from the host side directly) | Yes | Yes | Yes | **Works** | **Works** | None needed; effectively the same mechanism as a local PVC |

## Read-only mounts (configMap, secret, downwardAPI, projected, and any volume/mount marked `readOnly: true` — visible in `oci_mounts[].ro`)

Since these are mounted read-only *inside* the container, a container process cannot itself trigger a write-class hook (`ATTR`/`UNLINK`/`RENAME`) on them — the only possible in-container operation is `FILE_OPEN` (read). Any observed *content change* on a read-only mount necessarily came from outside the container (kubelet atomic-writer, or an unusual host-side edit) — reinforcing the configMap/secret finding above rather than being a separate case.

## Cross-cutting caveats already known and unaffected by volume type

- **Live-PID requirement** (`container_live_fim.cpp:219-222`, `pid_resolver.hpp`): every row in this matrix that says "Works" still requires that the PID captured in the eBPF event is still alive when the event is processed. This is a separate, already-documented gap (no PID-liveness fallback wired to the live path) that applies uniformly across all volume types, not specific to any one of them.
- **cgroup-v1 hosts**: `cgroup_id` is not a meaningful correlation key at all on cgroup-v1 (per `rt_event_contract.h`'s `RT_F_CGROUP_V1` flag) — every row above degrades to "cannot resolve to a container" regardless of volume type on such hosts, since nothing currently consumes the `mnt_ns` fallback field.
- **Kata / VM-isolated runtimes**: host-side eBPF cannot see in-guest file operations at all, independent of volume type — this excludes the entire matrix for `runtimeClassName: kata` pods, consistent with the eBPF spike's (#37396) own conclusion.

## Validation status

Everything above is derived from reading this worktree's code plus general Kubernetes/Docker volume semantics — **it has not been validated against a running kind cluster**, which is what the issue's acceptance criteria actually calls for ("Path-resolution algorithm and volume-type behavior table validated against real pod configs (rootfs + at least hostPath, configMap, PVC)"). In particular:

- The **configMap/secret cgroup-attribution gap** is a logical deduction from how `resolveByCgroupId()` and the kubelet's atomic-writer are known to work — it has not been observed empirically (e.g., by editing a live ConfigMap and confirming no event is emitted).
- The **NFS attribute-caching** and **FUSE-permission** rows are flagged explicitly as unverified plausible risks, not confirmed behavior.
- **Image volumes** could not be exercised (feature requires a recent kubelet/CRI combination not confirmed available in this environment).

Closing this out for real requires standing up a kind cluster with pods covering at minimum: rootfs write, hostPath (both in-container and host-side writers), configMap update post-startup, and a PVC (local-path-provisioner is sufficient for the common case; NFS/CSI-FUSE would need a separate storage class). That is infrastructure work beyond this pass — flagging it rather than fabricating results.
