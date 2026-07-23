# Event Contract Spec — reusable eBPF component (#37396)

Core deliverable. Defines the raw event schema, flat in-memory layout, contract versioning, and the subscription/filter API. Constraint: **hand-rolled flat layout, C/C++ only, no protobuf/gRPC, no new deps**.

> **Boundary note (ADR-001 = option (b)):** there is **no IPC** — the component is a shared library linked into each module, and events are consumed **in the same process** that produced them. What survives from the earlier (a)-oriented draft: the **flat event layout** (fixed header + packed payload + length-delimited trailing strings), the **versioning policy** (the library and its linking modules still ship independently, §4), the **correlation keys** (§2), and the **subscription/filter API as a library interface** (§5). What no longer applies: the unix-socket **wire transport**, the connect-time **handshake frame**, per-**subscriber** fan-out queues, and "same wire format over a socket". The `struct` layout below is now an in-process contract between the shared library and the module linking it, not a serialized frame. References to "wire format"/"handshake" below are retained only as the in-process ABI equivalent and annotated inline.

> **Review gates:** every field marked 🅵 must be reviewed by the **FIM spike** owner; every field marked 🅷 by the **IT Hygiene / Syscollector spike** owner (#37533/#37534). Path *resolution* (raw→logical/host) is FIM-owned and out of scope here — the contract only carries the **raw kernel path** plus the mount-ns inode FIM needs to resolve it.

## 1. Design principles

1. **Raw, not enriched.** The library emits kernel-level facts only. No uid→name, no path canonicalization, no container identity. The linking module enriches (touch-points C2/C3 in the audit).
2. **Correlation keys are optional.** Every correlation field has a defined "absent" value (`0`). A host (non-container) event carries zeros and is fully valid — **FIM's entire current use is host-side and needs none of them** (see §6).
3. **Flat + length-delimited + append-only growth.** Fixed header carries `total_len`; consumers never parse past it. New fields are appended; old consumers ignore trailing bytes. This is how engine and consumers ship independently (§4).
4. **Native, same-process.** Delivery is in-process (b), so events are native structs — native byte order, natural alignment with explicit padding, no serialization step. The `abi_major` echoed per event (§2) lets a module self-protect if it links a differently-versioned build of the shared library.

## 2. Common event header (all events)

```c
/* contract ABI: bump RT_ABI_MAJOR on any incompatible change to header/payload
 * layout; bump RT_ABI_MINOR when APPENDING fields only. */
#define RT_ABI_MAJOR 1
#define RT_ABI_MINOR 0

enum rt_event_type : uint16_t {
    RT_EV_FILE_OPEN      = 1,   /* create / write-open (regular files) */
    RT_EV_FILE_UNLINK    = 2,
    RT_EV_FILE_RENAME    = 3,
    RT_EV_FILE_ATTR      = 4,   /* setattr: mode/owner/size/time change */
    RT_EV_PROC_EXEC      = 10,
    RT_EV_PROC_EXIT      = 11,  /* optional; Syscollector process table upkeep */
    RT_EV_NET_CONNECT    = 20,
    RT_EV_NET_ACCEPT     = 21,
    RT_EV_NET_BIND       = 22,
};

enum rt_flags : uint16_t {
    RT_F_PATH_TRUNCATED  = 1 << 0,  /* kernel path walk hit MAX_PATH_COMPONENTS */
    RT_F_DROPS_BEFORE    = 1 << 1,  /* >=1 event was dropped before this one (see hdr.dropped) */
    RT_F_LSM_SOURCE      = 1 << 2,  /* emitted from an LSM hook (vs kprobe/tracepoint) */
    RT_F_CGROUP_V1       = 1 << 3,  /* cgroup_id semantics are v1 (ambiguous) — see compat doc */
};

struct rt_event_header {          /* 64 bytes, 8-byte aligned */
    uint16_t abi_major;           /* == RT_ABI_MAJOR of the emitting engine */
    uint16_t event_type;          /* enum rt_event_type */
    uint32_t total_len;           /* full frame length: header + payload + trailing path bytes */

    uint64_t timestamp_ns;        /* bpf_ktime_get_boot_ns(); CLOCK_BOOTTIME domain (§7) */

    uint32_t pid;                 /* tgid (userspace PID) */
    uint32_t tid;                 /* kernel pid (thread) */
    uint32_t ppid;
    uint32_t uid;                 /* real uid */🅵🅷
    uint32_t gid;                 /* real gid */🅵🅷

    /* --- correlation keys; 0 == unknown / not applicable (host) --- */
    uint64_t cgroup_id;           /* bpf_get_current_cgroup_id() (v2 unified) */🅷
    uint32_t mnt_ns;              /* mount-namespace inode  (task->nsproxy->mnt_ns->ns.inum) */🅵🅷
    uint32_t pid_ns;              /* pid-namespace inode */🅷
    uint32_t net_ns;              /* net-namespace inode */🅷

    uint16_t flags;               /* enum rt_flags */
    uint16_t payload_len;         /* bytes of the class payload that follow this header */
    uint32_t dropped;             /* running count of events dropped for THIS module's stream */
};
/* container_id is intentionally ABSENT: not reliably derivable in-kernel.
 * Consumers derive it from cgroup_id / mnt_ns via the Container module (#37382). */
```

`abi_major` is echoed in every event so a module can self-protect if it links a shared-library build whose ABI differs from the header it compiled against.

## 3. Per-class payloads

Payload immediately follows the header. Variable-length strings (paths, comm, args) are stored as **`{uint16_t len; char bytes[len];}` trailing runs** after the fixed part of the payload, in declared order. `payload_len` covers the fixed part; trailing strings run from `hdr + sizeof(header) + payload_len` to `hdr + total_len`.

### 3.1 File activity — `RT_EV_FILE_*`
```c
struct rt_file_payload {          /* fixed part */
    uint64_t inode;               /* d_inode->i_ino */🅵
    uint64_t dev;                 /* super_block->s_dev */🅵
    uint32_t mode;                /* i_mode (type+perm) */🅵
    uint32_t open_flags;          /* O_* for OPEN; attr mask for ATTR */🅵
    /* trailing strings, in order:
     *   [0] path       — raw kernel path (bpf_d_path or manual walk)  🅵
     *   [1] comm       — actor task comm (TASK_COMM_LEN cap)
     *   [2] cwd        — actor cwd (optional; present iff the module asked)
     *   [3] dest_path  — RENAME only: destination path 🅵
     */
};
```
Maps 1:1 onto today's `file_event` minus the FIM-specific `whodata_evt` fields; adds `mode`/`open_flags`. FIM's adapter builds `whodata_evt` from this. **🅵 confirm** `inode`+`dev`+`mnt_ns`+`path` is the minimal set FIM needs to resolve logical/host path.

### 3.2 Process exec — `RT_EV_PROC_EXEC`  (source: tracepoint `sched_process_exec`, very portable)
```c
struct rt_exec_payload {
    uint32_t exit_code;           /* EXIT only; 0 for EXEC */
    uint32_t auid;                /* login uid (task->loginuid) — audit correlation */🅷
    uint64_t start_boottime_ns;   /* process start time; stable PID-reuse discriminator */🅷
    /* trailing strings:
     *   [0] exe_path   — resolved executable path 🅷
     *   [1] comm
     *   [2] args       — NUL-joined argv (OPTIONAL, opt-in per module; costly) 🅷
     */
};
```
**🅷 #37534 owns** whether exec/exit go realtime here or are scheduled in Syscollector — this contract just makes them available. `args` capture is opt-in because it is the single most expensive field (unbounded, per-exec copy).

### 3.3 Network — `RT_EV_NET_*`  (source: fentry/kprobe on `tcp_connect`/`inet_csk_accept`/`__sys_bind`; VERIFY per kernel in compat doc)
```c
struct rt_net_payload {
    uint8_t  family;              /* AF_INET / AF_INET6 */🅷
    uint8_t  proto;               /* IPPROTO_TCP / UDP */🅷
    uint8_t  direction;          /* 0=outbound(connect) 1=inbound(accept) 2=bind */
    uint8_t  _pad;
    uint16_t sport;               /* host byte order */🅷
    uint16_t dport;🅷
    uint8_t  saddr[16];           /* v4 in first 4 bytes */🅷
    uint8_t  daddr[16];🅷
    uint64_t socket_cookie;       /* bpf_get_socket_cookie — stable socket id */🅷
    /* trailing strings: [0] comm */
};
```
**🅷 #37534 owns** the network inventory dimensions; this is the raw connect/accept/bind fact only.

## 4. Contract versioning (independent shipping)

| Change kind | Rule | Consumer behavior |
|---|---|---|
| Append a field to a payload / header tail | bump `RT_ABI_MINOR` only | Old consumer reads `total_len`/`payload_len`, ignores the extra tail. New consumer on old engine sees smaller `payload_len`, treats new field as absent. |
| Add a new `rt_event_type` | bump `RT_ABI_MINOR` | A module never installs a class it doesn't request → never receives it. An unknown type encountered while iterating is skipped via `total_len`. |
| Reorder/resize/repurpose an existing field | bump `RT_ABI_MAJOR` | Module refuses at load if `abi_major != its compiled major` (per-event field also self-protects). |

**Why versioning still matters under (b):** the shared library and the modules that link it ship on independent cadences (a module may be built against an older library header, or a packaged `.so` upgraded under a module built earlier). The check is a compile-/load-time **ABI guard**, not a socket handshake: at `rt_open` the library reports its `abi_major`/`abi_minor`; the module refuses on a major mismatch. This is the "grow-by-append, length-delimited, major/minor" model Falco's libscap plugin API uses (see `02-peer-research.md`) — applied to a library ABI rather than a wire protocol. No external dep.

## 5. Filter / API (library interface)

Under (b) each module opens its own library instance with its own filter and consumes its own stream — there is no shared subscriber registry, no cross-module fan-out. The filter still selects which classes/paths/cgroups that module installs and sees.

```c
typedef void (*rt_sink_fn)(const struct rt_event_header* ev, void* user);

struct rt_filter {
    uint32_t type_mask;           /* bitset of rt_event_type this module wants */
    /* path-prefix interest (FILE events); NULL/0 = all paths */
    const char** path_prefixes;   size_t n_prefixes;
    /* cgroup scope */
    enum { RT_SCOPE_ALL, RT_SCOPE_HOST_ONLY, RT_SCOPE_CGROUPS } scope;
    const uint64_t* cgroup_ids;   size_t n_cgroups;   /* for RT_SCOPE_CGROUPS */
    uint32_t want_flags;          /* e.g. RT_WANT_CWD, RT_WANT_ARGS */
};

rt_handle_t rt_open(const struct rt_filter* f);           /* load+attach this module's hooks */
int         rt_poll(rt_handle_t h, rt_sink_fn cb, void* user, int timeout_ms);
void        rt_close(rt_handle_t h);                       /* detach + free this module's ring buffer */
```

### What is filtered kernel-side vs in the module's own consume loop

| Filter | Where | Rationale |
|---|---|---|
| **Event type** (which classes this module installs) | **kernel** (program autoload) | A module autoloads only the programs for its own `type_mask` — FIM installs file hooks, Syscollector installs exec+network. Disabled classes are never attached (zero cost). Reuses today's `select_programs()` autoload (`ebpf_whodata.cpp:447`). Under (b) this is also *how* the disjoint hook sets are realised. |
| **regular-files-only, create/write-only** | **kernel** (already done) | Cheap `i_mode`/flags test in-program; huge volume reduction. Keep as-is. |
| **cgroup scope** (`RT_SCOPE_HOST_ONLY` / specific cgroups) | **kernel** via a `BPF_MAP_TYPE_HASH` cgroup-id allowlist | `bpf_get_current_cgroup_id()` + map lookup is O(1) and drops container/host noise before the ring buffer. |
| **path prefix** | **module's own consume loop** | In-kernel string prefix matching is expensive and verifier-hostile. The module matches prefixes on its own stream before acting (proven on-kernel — PoC `fim` prefix `/etc`, `07-` §3.5). |
| **drop accounting** | **module** | The module owns its ring buffer; drops are counted and surfaced to that module's telemetry (`04-lifecycle-backpressure.md`). No cross-module queue. |

Each module installs exactly the hooks its filter names — nothing more. Adding a 3rd module means that module links the library and installs its own hooks; it does not touch the other modules or a shared instance (consumer-agnostic constraint upheld, per-module).

## 6. Confirming EMPTY correlation keys work (host / non-container)

- On a bare host, `cgroup_id` is the root/systemd-slice cgroup id (nonzero but meaningless for containers), `mnt_ns`/`pid_ns`/`net_ns` are the init-namespace inodes. Consumers that don't care (FIM today) **ignore all four** — the file payload alone (`path,inode,dev,mode`) is exactly today's information. **No regression for host FIM.**
- The defined "absent" sentinel is `0`. A consumer running host-only sets `scope=RT_SCOPE_HOST_ONLY` or simply ignores the keys. An event with all-zero correlation keys is valid and complete.
- Container correlation is purely additive: the Container module (#37382) maps `cgroup_id`/`mnt_ns` → container id **in the consumer module**, never in the eBPF library.

## 7. Timestamp & clock (decision)

Use `bpf_ktime_get_boot_ns()` → **CLOCK_BOOTTIME** domain, carried as `timestamp_ns`. Rationale: monotonic across suspend, comparable to userspace `clock_gettime(CLOCK_BOOTTIME)` for ordering/correlation. Consumers needing wall-clock convert once using a boot-epoch offset sampled at startup. (`bpf_ktime_get_boot_ns` landed 5.7; on older kernels fall back to `bpf_ktime_get_ns` = CLOCK_MONOTONIC — flag in `RT_F_*` if needed. VERIFY floor in `05-compatibility-matrix.md`.)

## 7b. Alignment with the Container Instances Security Module (#37382)

Cross-checked against #37382 (**closed**, decisions recorded in its final comment). Their identifier decision is **made, prototyped and recorded**, not open — quoting the decisions changelog:

> **"Correlation key stays the cgroup v2 inode, the value `bpf_get_current_cgroup_id()` emits."**

Their resolver is `container_id → inode` joined against API metadata, resolving from the host via `/proc/<pid>/cgroup` + `stat(/sys/fs/cgroup/<path>).st_ino`. Their prototype ran on **Ubuntu 24.04 (cgroup v2)** and their edge-case handling gives explicit permanent verdicts for `host_process`, `hostNetwork`/`hostPID` (`host_namespace`), `cgroupns=host`, and Kata (documented v1 limitation).

**Acceptance criterion 6 is satisfied:** their chosen key is the cgroup(v2) id = `bpf_get_current_cgroup_id()`, and this contract emits exactly that (`cgroup_id`), plus `mnt_ns`/`pid_ns`/`net_ns` inodes as additional raw keys and `pid`/`tid` (rotating). The two halves meet on one number with no translation — aligned, no pending sign-off on the identifier itself.

**One measured gap to hand back to #37382 (not a blocker, an addition to their edge-case table):** their key assumes a cgroup **v2** inode, and their validation was on a v2 host. We measured that **RHEL 8 and Amazon Linux 2 boot on cgroup v1 by default** (`07-vm-validation-evidence.md`), where `bpf_get_current_cgroup_id()` collapses to the root v2 cgroup (observed `1`) for every task — so on a v1-booted host the chosen key cannot distinguish containers at all. This is distinct from their per-workload `cgroupns=host`/Kata rows: it is a **whole-host** condition on a mainstream RHEL-family default. The contract flags it with `RT_F_CGROUP_V1` so a consumer can fall back to a namespace-inode key; whether #37382's "unresolvable → explicit verdict" path already absorbs the v1-host case, or whether it needs an added row, is theirs to confirm. Flagged for them, with the measurement attached.

## 8. Open questions / coordinate

- **OQ-C1 🅵** Is `{path, inode, dev, mnt_ns}` sufficient for FIM path resolution, or does FIM also need the mount `fsid`/overlayfs upperdir hints? — FIM spike.
- **OQ-C2 🅷** Do Syscollector's process/network inventories want EXEC/CONNECT as realtime events, or only as table-refresh triggers? (#37534's call, not ours.)
- **OQ-C3** `args` capture policy (truncation length, opt-in default). — IT Hygiene.
- **OQ-C4** Should `RT_EV_FILE_ATTR` split into distinct mode/owner/size/time sub-reasons, or carry a changed-mask? — FIM spike.
- **OQ-C5** cgroup v1 makes `cgroup_id` ambiguous (multiple hierarchies). Contract flags `RT_F_CGROUP_V1`; consumers on v1 hosts must treat `cgroup_id` as best-effort. — see compat doc + Container module owners.
