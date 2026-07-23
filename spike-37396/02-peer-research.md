# Spike #37396 — Peer Research: eBPF Provider Event Contract, Subscription & Fan-out

**Stream:** Peer-research (interface/architecture).
**Goal:** Extract citable design patterns from four mature eBPF projects for the **reusable eBPF component each module links** (ADR-001 option (b)), emitting raw kernel events (file/process/network) **in-process** to the module that loads them (FIM + Syscollector) in a single C/C++ host agent. **No new external deps** (no protobuf/gRPC), hand-rolled flat serialization. The component carries **raw correlation keys** (pid/tid, cgroup id, mount/pid/net ns inodes, container id where derivable); container enrichment happens in the consuming module via a separate module.

**Method / confidence:** Findings are marked **VERIFIED** (backed by an official docs or source URL) or **INFERRED** (design reasoning consistent with cited material). Direct raw-source `WebFetch` was disabled in this environment, so struct byte-layouts are VERIFIED against official docs/API references that mirror the headers rather than line-anchored source reads. Where a struct's exact field names could not be pulled from source, that is called out.

---

## 1. Tetragon (Cilium)

Tetragon is Cilium's eBPF security-observability engine: in-kernel eBPF programs track/filter/enforce; a userspace daemon exports events over a **gRPC** API. Kernel-vs-userspace split documented at [tetragon.io](https://tetragon.io/) and [github.com/cilium/tetragon](https://github.com/cilium/tetragon).

### 1.1 Event contract / schema — VERIFIED
The wire contract is a single protobuf streaming envelope. `GetEventsResponse` carries a **`oneof event`** whose cases are the concrete event types, plus envelope metadata (`node_name`, `time`, `aggregation_info`). The `EventType` enum numbers are kept **in sync with the oneof field numbers**: `PROCESS_EXEC=1`, `PROCESS_EXIT=5`, `PROCESS_KPROBE=9` (also `PROCESS_TRACEPOINT`, `PROCESS_UPROBE`, `PROCESS_LOADER`). Source: [`api/v1/tetragon/events.proto`](https://github.com/cilium/tetragon/blob/main/api/v1/tetragon/events.proto), [gRPC API reference](https://tetragon.io/docs/reference/grpc-api/).

Event bodies (`ProcessExec`, `ProcessExit`, `ProcessKprobe`) embed a shared **`Process`** message and (exec/kprobe) a **`parent` Process**. `Process` fields (VERIFIED via [gRPC-API ref](https://tetragon.io/docs/reference/grpc-api/), [process-execution docs](https://tetragon.io/docs/use-cases/process-lifecycle/process-execution/)):
- **Identity / correlation:** `exec_id` (base64 unique process id correlating *all* activity of a process), `parent_exec_id`, `pid`, `tid`, `uid`, `auid`.
- **Payload:** `binary`, `arguments`, `cwd`, `flags`, `start_time`, `cap`, `ns`/`namespaces`, `refcnt`.
- **Container/k8s correlation:** `docker` (container id) + nested **`Pod`** (`namespace`, `name`, `container{id,name,image,start_time,pid}`, `pod_labels`, `workload`/`workload_kind`). K8s metadata is attached by **userspace enrichment, not the kernel** ([events concepts](https://tetragon.io/docs/concepts/events/)).

**Key design point (VERIFIED):** correlation is *not* by raw pid — pid is reused/racy, so Tetragon mints an **`exec_id`** (encodes node + timestamp + pid) at exec and threads it through exit/kprobe events, plus `parent_exec_id` for the process tree ([execution docs](https://tetragon.io/docs/getting-started/execution/), [ancestors issue #2420](https://github.com/cilium/tetragon/issues/2420)). **INFERRED:** an in-process C/C++ agent solves the same pid-reuse problem with a local process table keyed on (pid, start_time); Tetragon only has to *serialize* it because producer and consumer are separated by a socket.

### 1.2 Subscription & filtering — VERIFIED
Two layers:
- **(a) In-kernel via TracingPolicy selectors.** A `TracingPolicy` CRD declares hook points (kprobe/uprobe/tracepoint/LSM/USDT) plus **selectors compiled into BPF maps** so filtering happens *before* events leave the kernel: `matchPIDs`, `matchNamespaces` (≤4 ns pre-5.3, ≤10 on ≥5.3), `matchBinaries`, `matchArgs`, `matchCapabilities`. The cheap high-volume cut. Sources: [Tracing Policy reference](https://tetragon.io/docs/reference/tracing-policy/), [Selectors](https://tetragon.io/docs/concepts/tracing-policy/selectors/).
- **(b) Userspace export filtering per gRPC client.** `GetEventsRequest` carries `allow_list`/`deny_list` (repeated `Filter`: `binary_regex`, `pid_set`, `namespace`, CEL matchers) and `field_filters` (repeated `FieldFilter`: `event_set`, `fields` FieldMask, INCLUDE/EXCLUDE, `invert_event_set`). Allowlist = default-deny when set; denylist wins on overlap. Sources: [events.proto](https://github.com/cilium/tetragon/blob/main/api/v1/tetragon/events.proto), [Events concepts](https://tetragon.io/docs/concepts/events/).

**Split (VERIFIED):** pid/namespace/binary/arg matching → **kernel** (BPF maps, drop before ringbuffer); field masking, per-client allow/deny, event-type selection → **userspace** (per-request).

### 1.3 Multi-consumer fan-out — VERIFIED (mechanism), INFERRED (naming)
The observer (`pkg/observer/observer.go`) opens a perf/ring reader over the BPF `tcpmon_map`; a reader goroutine calls `perfReader.Read()` → `receiveEvent()` decodes into API events. Fan-out is a **listener pattern**: consumers `AddListener`, `NotifyListener` iterates all listeners calling `Notify`. The gRPC server implements `GetEvents` as a **server-streaming RPC**; **each connected client registers its own listener/stream** and applies its own request-scoped filters. One kernel event → single decode → broadcast → N per-client filtered streams. Source: [Agent internals writeup](https://yuki-nakamura.com/2024/05/23/tetragon-process-lifecycle-observation-tetragon-agent-part/), [gRPC-API ref](https://tetragon.io/docs/reference/grpc-api/).

### 1.4 Contract versioning — VERIFIED (structure), INFERRED (rationale)
Versioned **by path**: `api/v1/tetragon/*.proto`. Independent evolution rides standard proto3 rules: new event types get new oneof/enum numbers (hence the "EventType constants must stay in sync with oneof numbers" comment), fields never renumbered, removals `reserved`. Old consumers ignore unknown fields; new engines add fields without breaking old clients ([events.proto](https://github.com/cilium/tetragon/blob/main/api/v1/tetragon/events.proto); [protobuf version support](https://protobuf.dev/support/version-support/)). **INFERRED:** the `v1` prefix is the escape hatch for a future breaking `v2`.

### 1.5 Drop signaling — VERIFIED
Loss = Prometheus counters, distinguishing kernel-side vs userspace-queue drops ([Metrics reference](https://tetragon.io/docs/reference/metrics/), [perf issue #4821](https://github.com/cilium/tetragon/issues/4821)):
- `tetragon_bpf_missed_events_total` — kernel failed to push (ring full at reserve, `ENOSPC`).
- `tetragon_observer_ringbuf_events_lost_total` — perf/ring records lost kernel→reader.
- `tetragon_observer_ringbuf_queue_events_lost_total` — userspace queue overflow reader→consumers (paired `..._received_total` gives denominator).
- Listener-side counter for events dropped because a **slow gRPC client's buffer was full** (backpressure).

**Design point (VERIFIED):** drops are **counted, not inlined** — no gap marker in the stream; consumers scrape metrics to detect loss.

### 1.6 Why the gRPC/protobuf bus does NOT fit us — INFERRED (analysis)
- **Transport is the architecture.** The whole contract presumes a **process boundary crossed by gRPC/HTTP2 + protobuf** → pulls in gRPC + protobuf runtime + transitive deps. Opposite of a self-contained C/C++ agent.
- **Serialize tax for in-process consumers.** In a single-process agent, producer and consumer share address space; encoding to protobuf and shipping over a socket to yourself is pure overhead with no isolation benefit.
- **Go-centric decode.** Observer fan-out, `exec_id` process cache, k8s enrichment are Go; no C/C++ consumer lib.
- **K8s-shaped.** `Pod`/`workload` correlation and CRD `TracingPolicy` assume a control plane a host agent doesn't need.
- **Worth borrowing (design, not code):** (a) `exec_id`/`parent_exec_id` keyed on (pid,start_time,node); (b) two-tier filter (cheap kernel cut + rich userspace mask); (c) explicit typed drop counters; (d) additive field-number-stable schema.

---

## 2. Falco libs (libsinsp / libscap) — CLOSEST ANALOG

Falco's capture stack is the closest real-world analog to "flat, C, versioned events over a ring buffer." Layering: **kernel drivers** (kmod / legacy-eBPF / modern-eBPF) produce events into **per-CPU ring buffers**; **libscap** reads the raw flat events; **libsinsp** parses, maintains state tables, runs filtering. Plugins reuse the *same* flat protocol to inject non-syscall events. Roles verbatim in [Kernel Events Architecture](https://falco.org/docs/concepts/event-sources/kernel/architecture/).

### 2.1 Event contract / schema — flat wire encoding — VERIFIED
A scap/ppm event is one contiguous blob: fixed header → array of per-parameter lengths → packed parameter payloads back-to-back.

Header (`struct ppm_evt_hdr` kernel-side, mirrored as `scap_evt` userspace) per [Plugins API Reference](https://falco.org/docs/reference/plugins/plugin-api-reference/), cross-referenced with [ppm_events_public.h](https://github.com/falcosecurity/libs/blob/master/driver/ppm_events_public.h):
- `uint64_t ts` — ns from epoch
- `uint64_t tid` — generating thread tid
- `uint32_t len` — total event length **including header**
- `uint16_t type` — event type code
- `uint32_t nparams` — number of parameters

Payload, verbatim: *"an array of lengths of each parameter followed by the content of the parameters themselves"* → `[len p1][len p2]...[len pN][data p1]...[data pN]`. **Variable-width length fields:** the event type "dictates ... whether the length is encoded as a 2 bytes or 4 bytes integer" — width is a **per-event-type property**, not per-param. (`struct scap_evt` mirror lives in [userspace/libscap/scap.h](https://github.com/falcosecurity/libs/blob/master/userspace/libscap/scap.h); field/layout VERIFIED via docs, exact file location INFERRED.)

**Event TYPE enum + schema table — VERIFIED.** Types are C enum `ppm_event_code` with `PPME_*` constants, **one pair per operation**: enter (`_E`) / exit (`_X`), e.g. `PPME_SYSCALL_OPENAT2_E`/`_X`, bounded by `PPM_EVENT_MAX`. `type` indexes a static schema table **`g_event_info[]`** in [driver/event_table.c](https://github.com/falcosecurity/libs/blob/master/driver/event_table.c). Each row: name, category, flags, ordered param list each with a name and **param type** (`PT_ERRNO`, `PT_FD`, `PT_CHARBUF`, `PT_FLAGS`, `PT_DYN`, ...). Described as *"a contract that describes the event data stream ... used by both the drivers and libscap."* **This is the backbone pattern: `type` (uint16) → static table row → ordered typed field schema, compiled into BOTH producer and consumer so decode never guesses.** Plugin events use `type` **322** (`PPME_PLUGINEVENT_E`) with opaque `(plugin_id, blob)` payload ([Plugin proposal](https://github.com/falcosecurity/falco/blob/master/proposals/20210501-plugin-system.md)).

### 2.2 Versioning — VERIFIED
- **Plugin API is semver with an explicit ABI rule.** `plugin_get_required_api_version()` returns semver (currently major `3`). Compat gate: *"a plugin and framework are compatible if their major versions are the same"*; framework minor may be ahead ([Plugins Developer Guide](https://falco.org/docs/developer-guide/plugins/)).
- **Field-schema bump rules (reusable policy):** **patch** → any change; **minor** → **new fields added** (backward-compatible superset); **major** → field modified/removed or semantics changed. Consumer on major N accepts any producer minor ≤ its own; additive fields don't break old consumers because decode is table-driven and consumers ignore unknown trailing fields.
- **Caveat (VERIFIED):** two version axes exist — plugin API semver AND a separate driver `SCHEMA VERSION` that has historically drifted from strict semver ([libs#1283](https://github.com/falcosecurity/libs/issues/1283)). Don't conflate them.

### 2.3 Subscription & filtering — VERIFIED
- **Kernel-side event-type masking ("adaptive/interesting syscalls").** Rule strings → syscall IDs → injected into the driver via a **BPF map (eBPF) or ioctl bitmask (kmod)**, consulted inside `sys_enter`/`sys_exit` so "unnecessary syscalls [are ignored] before any data field extraction ... in the kernel" ([Adaptive Syscalls Selection](https://falco.org/blog/adaptive-syscalls-selection/)). Cheapest possible drop, before the event is built or written.
- **Conditional kernel-side content filtering** (finer than type masking, dropping before ring alloc based on field predicates) is a proposal/direction ([libs#1557](https://github.com/falcosecurity/libs/issues/1557)).
- **Userspace filterchecks.** libsinsp `sinsp_filter_check_*` classes expose `fd.name`, `proc.cmdline`, `syscall.type`, etc. **Coarse type subscription in kernel; rich field predicates in userspace.**

### 2.4 Multi-consumer — VERIFIED (buffers), INFERRED (merge)
- **VERIFIED:** one ring buffer **per CPU** (modern-eBPF can share fewer larger buffers); strict single-producer→single-consumer FIFO.
- **INFERRED (well-established design, not verbatim in docs):** libscap presents a **single unified stream** by reading the head of every per-CPU buffer and returning the event with the **oldest `ts`** (k-way timestamp merge) → libsinsp sees one time-ordered stream. **No fan-out at the scap layer** — one inspector loop (`scap_next` → `sinsp::next`). Multiplexing to many "subscribers" (rules, outputs) happens *above* libsinsp, after parsing. **Implication: fan-out is a userspace concern layered on a single-consumer capture; the ring buffer itself is not multi-consumer.**

### 2.5 Drop signaling — VERIFIED
Drops are **counted, typed by reason**, via `scap_stats` ([Dropping troubleshooting](https://falco.org/docs/troubleshooting/dropping/)):
- `n_drops_buffer` — **full ring buffer** (common perf case); broken down by reason+direction (`n_drops_buffer_clone_fork_enter/exit`, `..._execve_...`).
- `n_drops_bug` — invalid eBPF condition. `n_drops_pf` — page-fault during capture. `n_drops` — aggregate.
- **"Drop mode"/adaptive dropping** under load, buffer sizing (`buf_size_preset`) ([falco#1403](https://github.com/falcosecurity/falco/issues/1403)).

**Pattern to copy:** drops never silent — a typed per-reason counter set travels alongside the stream; ring-buffer-full is a first-class, separately-attributed statistic.

---

## 3. Inspektor Gadget — RAW-EVENT vs CONTAINER-ENRICHMENT SEPARATION

CNCF eBPF observability framework. **Directly relevant:** the eBPF gadget emits only raw kernel correlation keys (mount/net namespace inode IDs, pid, comm); a **separate userspace enrichment layer** maps those keys to container/pod/k8s identity. The gadget knows nothing about containers — exactly the provider-emits-raw / consumer-enriches split we want. Repo: [github.com/inspektor-gadget/inspektor-gadget](https://github.com/inspektor-gadget/inspektor-gadget).

### 3.1 Event contract / schema — VERIFIED
- Event = a plain **C `struct event`** emitted over a **BPF ring buffer** (perf array fallback on old kernels); the struct fields *are* the schema. [Gadget eBPF API](https://inspektor-gadget.io/docs/latest/gadget-devel/gadget-ebpf-api/), [Hello world gadget](https://inspektor-gadget.io/docs/latest/gadget-devel/hello-world-gadget/).
- Macros: `GADGET_TRACER_MAP(name,size)` declares the output map (ringbuf or perf array) and the per-CPU `<map>_lost_samples` counter; `GADGET_TRACER(name,mapname,structname)` binds source name → map → struct. Emission via `gadget_reserve_buf()`+`gadget_submit_buf()` or `gadget_output_buf()`.
- **Raw correlation keys only:** `mntns_id` (mount ns inode), `pid`/`tid`, `comm`, timestamp, netns id for network gadgets. `gadget_get_mntns_id()` from `<gadget/mntns.h>`. Inodes, not container names.
- **The field *type* is the enrichment trigger (key idea, VERIFIED):** a field declared type **`gadget_mntns_id`** (not plain `__u64`) signals userspace that this is a mount-ns inode to run through container enrichment; IG auto-adds a container/pod column. *"Inspektor Gadget will automatically enrich events with container information when the events include the mount namespace inode ID ... with a field of type `gadget_mntns_id`."* **The contract between gadget and framework is expressed in the struct's field types.**
- **Schema described via BTF + metadata.** Struct layout read from compiled BTF (requires Linux ≥5.10 with BTF); human/formatting metadata (per-field description, column width/hidden, JSON skip) layered via the datasource "fields" of `gadget.yaml`. [Metadata](https://inspektor-gadget.io/docs/latest/gadget-devel/metadata/), [metadatav1 types](https://pkg.go.dev/github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1).

### 3.2 Raw event vs container enrichment — THE KEY SEPARATION — VERIFIED
- **Gadget is container-unaware by design.** *"The data that eBPF collects ... is unaware of Kubernetes, container runtimes ... Inspektor Gadget automatically uses kernel primitives like mount namespaces, pids ... to figure out which high-level concepts they relate to ... The process of enhancing the eBPF data with these high-level concepts is termed enrichment."* — [docs](https://inspektor-gadget.io/docs/latest/).
- **Enrichment is a separate operator, not the gadget.** Pipeline = **operators** (`DataOperator`/`ImageOperator`); enrichment, filtering, sorting, export are separate reorderable stages downstream of the gadget/ringbuf. [Operators spec](https://inspektor-gadget.io/docs/latest/spec/operators/).
- **`container-collection` is the mntns→container map.** `pkg/container-collection` tracks container create/remove and holds the inode→metadata lookup (name, image, runtime, namespaces, cgroups). Functional options: `WithContainerRuntimeEnrichment`/`WithMultipleContainerRuntimesEnrichment` (docker/containerd/cri-o/podman), `WithLinuxNamespaceEnrichment`, `WithKubernetesEnrichment`; container events via `containercollection.PubSubEvent`. [pkg tree](https://github.com/inspektor-gadget/inspektor-gadget/tree/main/pkg/container-collection), [Go-from-app blog](https://inspektor-gadget.io/blog/2022/09/using-inspektor-gadget-from-golang-applications/).
- **Two manager operators wrap it and do the actual enrichment + filter-map upkeep:** **LocalManager** (the `ig` binary — tracks host containers via runtimes + fanotify, enriches events, updates eBPF filter maps) and **KubeManager** (k8s DaemonSet — tracks pods via kube-apiserver + runtimes). [LocalManager](https://inspektor-gadget.io/docs/main/spec/operators/localmanager/), [KubeManager](https://inspektor-gadget.io/docs/latest/spec/operators/kubemanager/).

**Takeaway for us:** `mntns_id` inode is the **join key**; the enrichment operator owns a live inode→identity table populated out-of-band from runtime events. Provider stays dumb; identity resolution is swappable (local vs k8s) and lives entirely in the consumer/enrichment layer.

### 3.3 Subscription & filtering — VERIFIED
- **Subscribe with prioritized callback:** `DataSource.Subscribe(callback, priority)` (lower priority runs earlier); fields read via field accessors. [Go API](https://inspektor-gadget.io/docs/latest/api/golang/).
- **In-kernel filtering by mount namespace via a shared BPF map** (`<gadget/mntns_filter.h>`): map **`gadget_mntns_filter_map`** (`BPF_MAP_TYPE_HASH`, key `gadget_mntns_id`, value `__u32`, `max_entries=1024`); toggle `gadget_filter_by_mntns` (bool); gate **`gadget_should_discard_mntns_id(mntns_id)`** returns true when filtering enabled AND inode absent → gadget skips emitting. The manager operators **populate** this map from container-collection, so a `-p`/`-c` selector becomes an in-kernel inode allowlist. Source (fetched verbatim by the research pass): [include/gadget/mntns_filter.h](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/include/gadget/mntns_filter.h).
- **INFERRED:** field-predicate filters run in userspace via a filter operator over decoded fields; the kernel path is specifically the mntns allowlist.

### 3.4 Versioning — VERIFIED
- **Metadata is an explicit versioned API, `metadata/v1`** (`pkg/metadata/v1.GadgetMetadata`); build-time `--validate-metadata` (default on). [metadatav1](https://pkg.go.dev/github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1).
- **Gadgets ship as versioned OCI images**; a separate **gadget/WASM API version** tracks eBPF↔userspace compat (`ig image inspect` surfaces it). [Image-based gadgets](https://inspektor-gadget.io/blog/2024/08/empowering-observability_the_advent_of_image_based_gadgets/).
- **INFERRED:** three independent axes — OCI tag (artifact), `metadata/v1` (declarative schema), gadget/WASM API version (runtime ABI).

### 3.5 Drop signaling — VERIFIED
When the ringbuf is full, `gadget_reserve_buf()` increments a per-CPU **`<map>_lost_samples`** counter (declared by `GADGET_TRACER_MAP()`); the eBPF operator reports counts to userspace. IG previously **silently** dropped events — a security problem (attacker floods buffer with benign events to mask malicious ones); a fix added explicit dropped-event accounting/alerting. [Security audit (Shielder 2026)](https://www.shielder.com/blog/2026/04/inspektor-gadget-security-audit/), [advisory GHSA-wv52-frfv-mfh4](https://github.com/inspektor-gadget/inspektor-gadget/security/advisories/GHSA-wv52-frfv-mfh4).

### 3.6 Legacy Trace CRD (reference) — VERIFIED
Pre-image model used a k8s `Trace` CRD (`gadget.kinvolk.io/v1alpha1`), spec selecting node/gadget/filters + `RunMode` (`Auto`/`Manual`), driven by `kubectl gadget`. Superseded by OCI image-based gadgets + operators. [CRD schema](https://www.inspektor-gadget.io/docs/v0.31.0/legacy/crds/traces.gadget.kinvolk.io). **Does NOT fit us** (k8s control plane).

---

## 4. Cilium / Hubble — IN-KERNEL RING + USERSPACE MULTI-READER FAN-OUT

Core takeaway: **two-level ring architecture** — an in-kernel per-CPU perf ring feeding a single agent reader, then a **userspace in-memory ring with many independent cursor readers**. That second level is the direct analogue for our fan-out. The gRPC/protobuf transport around it does NOT fit us.

### 4.1 Event / flow model — VERIFIED
- **Low-level BPF notification structs (perf ring payloads).** Datapath calls `send_trace_notify` → pushes a **`trace_notify`** struct into `EVENTS_MAP` (perf ring); other routines push **`drop_notify`** via `__send_drop_notify`, plus policy-verdict notifications. Fixed C structs written as raw binary perf samples. Wire discriminator = first byte (`MessageTypeTrace`/`Drop`/`PolicyVerdict`/`AccessLog`/`Agent`, in `pkg/monitor/api`). [Hubble internals](https://docs.cilium.io/en/stable/internals/hubble/).
- **High-level `Flow` proto** (`api/v1/flow/flow.proto`): agent decodes raw structs into a normalized `Flow` — `time`, `verdict` (FORWARDED/DROPPED/ERROR/AUDIT/…), `drop_reason_desc`, L2 `ethernet`, L3 `IP`, L4 `Layer4`, `source`/`destination` `Endpoint` (identity/namespace/pod/labels), `source_names`/`destination_names`, `l7` (HTTP/DNS/Kafka), `Type`, `node_name`, `event_type` (source `CiliumEventType`), `trace_observation_point`, `Summary`. [flow.proto](https://github.com/cilium/cilium/blob/main/api/v1/flow/flow.proto), [rendered API](https://docs.cilium.io/en/stable/_api/v1/flow/README/).
- **Design note:** compact fixed-size binary struct at the kernel boundary; rich self-describing decoded record at the consumer boundary; **decode once, in the single agent reader, before fan-out.**

### 4.2 In-kernel ring + userspace multi-reader fan-out — THE KEY PATTERN — VERIFIED
Three stages:
- **(a)** BPF → **per-CPU perf ring** (`EVENTS_MAP`, `BPF_MAP_TYPE_PERF_EVENT_ARRAY`).
- **(b) Single agent reader → N in-process consumers.** cilium-agent monitor (`pkg/monitor/agent`) runs **one singleton goroutine** reading the perf ring, then notifies **every registered consumer**. `Agent` exposes `RegisterNewConsumer(MonitorConsumer)` / `RegisterNewListener(MonitorListener)` / `SendEvent(...)`. `MonitorConsumer` = `NotifyAgentEvent(typ, message)`, `NotifyPerfEvent(data, cpu)`, `NotifyPerfEventLost(numLostEvents, cpu)`. Two subscriber flavors: **consumers** (in-process, decoded events — Hubble, recorder) and **listeners** (external `cilium monitor` clients over a unix socket, per-connection enqueue). [agent.go](https://github.com/cilium/cilium/blob/main/pkg/monitor/agent/agent.go), [MonitorConsumer](https://pkg.go.dev/github.com/cilium/cilium/pkg/monitor/agent/consumer).
- **(c) Hubble's OWN userspace ring, read by many independent cursors.** Hubble registers as a monitor consumer; every event is decoded into a `Flow` and stored in Hubble's **in-memory ring buffer**; multiple gRPC `GetFlows` clients each get their own reader/cursor into the same ring. Ring impl `pkg/hubble/container/ring.go`: **lock-free** (atomics, no locks); buffer is **power-of-2 with 1 slot reserved for the writer** (`mask = 2^n − 1`, usable = 2^n − 1); **overwrites oldest** when full. `RingReader` (`NewRingReader(ring, start)`) tracks its **own cursor**; supports `Previous()`/`Next()` + a **follow mode** that blocks/continues as the writer advances; `Next()` returns **`ErrInvalidRead`** if the writer lapped this reader. [Hubble internals](https://docs.cilium.io/en/stable/internals/hubble/), [container pkg godoc](https://pkg.go.dev/github.com/cilium/cilium/pkg/hubble/container), [ring_test.go](https://fossies.org/linux/cilium/pkg/hubble/container/ring_test.go).

**Directly applicable principles (VERIFIED):**
- Single writer, atomic monotonic write index, many lock-free readers each with an independent cursor — no per-reader buffer copy.
- Capacity 2^n − 1 with one reserved slot so writer never collides with the current position; masking replaces modulo.
- A slow reader that gets lapped is **detected** (`ErrInvalidRead`) rather than corrupting; **writer never blocks**, overwrites oldest.
- Never hand out the newest slot (may be mid-write) — readers trail the write cursor by one.
- **Decode-once-then-fan-out:** expensive normalization in the single upstream reader, not per subscriber.

**Does NOT fit us:** gRPC `Observer` service, protobuf `Flow`, `hubble-relay` cross-node aggregation, unix-socket "1.2 API" listener transport — Cilium delivery specifics, not the fan-out core.

### 4.3 Monitor aggregation — VERIFIED
`MonitorAggregationLevel` reduces volume by **suppressing repeated trace notifications in the datapath (BPF), before they hit the perf ring**. Levels: `None` (all), `Lowest`/`Low` (RX trace disabled), `Medium` (per-connection: trace only on new connection, unseen TCP flags, ≤ ~once per `monitor-aggregation-interval`). **Drops are NEVER aggregated** — one event per dropped packet always. [pkg/option/monitor.go](https://fossies.org/linux/cilium/pkg/option/monitor.go), [issue #14885](https://github.com/cilium/cilium/issues/14885). **Producer-side rate limiter keyed on connection+state-change; losses/drops bypass it.**

### 4.4 Subscription model — VERIFIED
- In-process consumers `RegisterNewConsumer` + implement `MonitorConsumer`; external clients `RegisterNewListener` (unix socket, per-connection enqueue).
- **Hubble `GetFlows` per-client:** streamed cursor (`RingReader`, follow mode) into the shared ring; per-request `whitelist`/`blacklist` of `FlowFilter`. Within a list: OR; across lists: emit iff allow-match AND NOT deny-match. **Per-subscriber filter is a read-side predicate, not a separate queue** — ring stays shared, each cursor + filter defines the subscriber's view. [Observer service](https://docs.cilium.io/en/stable/_api/v1/flow/README/), [relay observer](https://pkg.go.dev/github.com/cilium/cilium/pkg/hubble/relay/observer).

### 4.5 Drop / lost-event signaling — VERIFIED
- **Kernel perf-ring loss** surfaced to every consumer via `NotifyPerfEventLost(numLostEvents, cpu)` — distinct from `NotifyPerfEvent(data, cpu)`. Underlying `github.com/cilium/ebpf/perf` `Record.LostSamples`. Operationally a "Lost events"/`num_events_lost` counter. [MonitorConsumer](https://pkg.go.dev/github.com/cilium/cilium/pkg/monitor/agent/consumer), [ebpf/perf](https://pkg.go.dev/github.com/cilium/ebpf/perf), [cilium-cli#2162](https://github.com/cilium/cilium-cli/issues/2162).
- **Two independent loss points:** (1) kernel perf-ring overrun (this signal); (2) Hubble userspace ring overwriting unread entries — detected reader-side via lapped-cursor `ErrInvalidRead`. **Model an explicit "you missed N" signal per slow reader.**

---

## 5. Synthesis — Patterns that FIT / DON'T FIT a no-dep C/C++ host agent

### 5.1 FITS (adopt)
1. **Flat C-struct events over a ringbuf, `type`→static schema table (scap `g_event_info` model).** A fixed header (`ts`, tid/pid, `len` incl. header, `type` uint16, `nparams`) + per-param length array + packed payload. `type` indexes a **schema table compiled into BOTH provider and consumers** so decode is table-driven, never guessed. `len` includes the header → an unknown event can be **skipped/forwarded** without decoding (forward compat). Variable 2B/4B length width keyed off event type. This is our closest analog and the recommended wire model. (Falco §2.1.)
2. **Version field + additive/optional trailing fields.** Falco's rule as policy: **minor bump = new fields appended** (old consumers ignore trailing unknowns because decode is table-driven), **major = removal/semantics change/ABI break**. Consumer accepts any producer minor ≤ its own major. Put a schema-version in the header (or a per-type version); keep field numbers/order stable; never renumber. (Falco §2.2, Tetragon §1.4, IG §3.4.)
3. **Kernel-side filter by cgroup/mntns/event-type + userspace fan-out.** Cheap coarse cut in the kernel via a **consumer-populated BPF allowlist map** keyed on the same raw correlation key (IG `gadget_mntns_filter_map` + `gadget_should_discard_*` gate; Falco adaptive syscall mask). Rich per-consumer field predicates in userspace. (IG §3.3, Falco §2.3, Tetragon §1.2.)
4. **Separate raw event from container enrichment (Inspektor Gadget model).** Provider emits **only raw keys** (pid/tid, cgroup id, mount/pid/net ns inodes) and knows nothing about containers. A **separate enrichment module** owns a live inode→identity table (fed out-of-band by runtime events) and joins on the raw key. Make the correlation key a **distinct typed field** so consumers know it's a join key (IG's `gadget_mntns_id` type-as-contract idea). Enrichment is swappable without touching the provider. (IG §3.2 — directly maps to our design.)
5. **In-kernel ring + userspace single-decode + multi-reader fan-out (Hubble level-2 ring).** One writer, atomic monotonic index, **power-of-2−1 capacity with one reserved slot** (mask, not modulo), **overwrite-oldest, writer never blocks**. Each consumer holds an **independent cursor**; a lapped slow reader is **detected** and told how much it missed. Decode/normalize **once** upstream before fan-out. Lock-free. (Hubble §4.2 — directly our fan-out design.)
6. **Explicit, typed, per-reason drop counters — never silent.** Distinguish kernel-ring-full vs userspace-queue-overflow vs per-consumer-backpressure (Tetragon three counters; Falco `n_drops_*` by reason; Hubble `NotifyPerfEventLost` + `ErrInvalidRead`; IG per-CPU `_lost_samples`). Signal **per slow reader** how many it missed. Silent drops are a security bug (IG advisory). (All four.)
7. **Producer-side aggregation/rate-limit for high-volume repeats — but NEVER for drops/errors** (Hubble `MonitorAggregationLevel`). Optional; keep security-relevant events unaggregated. (Hubble §4.3.)
8. **Robust correlation key, not bare pid.** Key process identity on **(pid, start_time)** (Tetragon `exec_id`) to survive pid reuse; carry parent link for the process tree. In-process we keep a local table instead of serializing an exec_id. (Tetragon §1.1.)

### 5.2 DOESN'T FIT (reject)
- **gRPC/protobuf event bus (Tetragon `GetEventsResponse`, Hubble `Observer`/`Flow`).** Pulls in gRPC + protobuf runtime + transitive deps (violates no-new-deps); serialize/deserialize tax is pure overhead for in-process consumers sharing address space; no C/C++ consumer lib. Transport IS the architecture — not reusable without the bus. (Tetragon §1.6, Hubble §4.2.)
- **CRD / Kubernetes control plane (Tetragon TracingPolicy CRD, IG Trace CRD, KubeManager).** Assumes a k8s API server; a host agent has none. Use plain config/structs instead. (Tetragon §1.2, IG §3.6.)
- **Plugin `.so` ABI (Falco plugin API) — likely overkill.** The semver-compat *policy* is worth copying, but a dynamically-loaded plugin ABI with `plugin_get_required_api_version()` negotiation is more machinery than two in-tree consumers (FIM + Syscollector) need. Prefer a compiled-in in-process subscriber interface + a shared schema-version constant. (Falco §2.2.)
- **Unix-socket per-connection listener transport (Hubble "1.2 API" listeners).** Serialization + socket for external clients; our consumers are in-process. Keep the in-process **consumer** path (decoded, direct callback), drop the **listener** path. (Hubble §4.2b.)
- **Rich decoded record as the wire format (Hubble `Flow` self-describing proto).** Good as an *internal decoded view*, wrong as the *wire/ringbuf* format — keep the ring flat/compact (scap-style) and let consumers materialize richer structs. (Hubble §4.1.)

### 5.3 Direct answers to the three cross-cutting questions
- **Contract versioning (engine & consumers ship independently):** header carries a **schema/API version**; evolve by **appending optional trailing fields** (minor) with **stable field order/numbers**; **major** only for removal/renumber/semantics change; decode is **table-driven** (`type`→schema) so old consumers safely ignore unknown trailing bytes using `len`. Compat rule (Falco): consumer accepts any producer whose major == its major and minor ≤ its own. Reserve a version-namespace (`v1`) escape hatch for a future breaking bus.
- **Drop signaling:** **out-of-band, typed, per-reason counters**, plus a **per-reader "you missed N" marker** on lap. Never inline a silent gap. Distinguish kernel-ring-full / userspace-queue-overflow / per-consumer-backpressure. (Hubble `NotifyPerfEventLost`, Falco `n_drops_*`, Tetragon 3-counter split, IG `_lost_samples`.)
- **Per-subscriber filter scoping:** two tiers. (1) **Kernel allowlist map** keyed on the raw correlation key (cgroup/mntns/event-type), populated by userspace — coarse, shared, cheap. (2) **Read-side per-cursor predicate** in userspace over decoded fields (Hubble whitelist/blacklist, Tetragon allow/deny + FieldMask) — the ring stays shared; each subscriber's cursor + filter defines its view (no per-subscriber queue duplication).

---

## 6. Summary table

| Pattern | Source project | Fits Wazuh? | Why |
|---|---|---|---|
| Flat C-struct event: header(`ts,tid,len,type,nparams`) + len-array + packed payload | Falco libscap | YES | Compact, no deps, C-native; closest analog to our wire model |
| `type` (uint16) → static schema table compiled into producer+consumer | Falco `g_event_info` | YES | Table-driven decode, tiny events, forward-compat via `len`-skip |
| Version field + append-only optional trailing fields (semver: minor=add, major=break) | Falco / Tetragon / IG | YES | Lets engine + FIM + Syscollector ship independently |
| Provider emits raw keys (pid/tid, cgroup, mntns/netns/pidns inodes); enrich elsewhere | Inspektor Gadget | YES | Exactly our provider/consumer split; enrichment swappable |
| Typed correlation-key field as enrichment-trigger contract (`gadget_mntns_id`) | Inspektor Gadget | YES | Consumers recognize join keys from the schema, no side channel |
| Kernel allowlist map (cgroup/mntns/type) populated by userspace | IG `gadget_mntns_filter_map` / Falco syscall mask | YES | Cheap coarse pushdown; provider stays identity-unaware |
| In-kernel ring → single decode → userspace multi-cursor fan-out | Hubble level-2 ring | YES | Directly our in-process fan-out to FIM + Syscollector |
| Lock-free ring, 2^n−1 cap, reserved writer slot, overwrite-oldest, per-reader cursor | Hubble `ring.go` | YES | Non-blocking writer, N readers, no per-reader copy |
| Lapped-reader detection ("you missed N") + typed per-reason drop counters | Hubble / Falco / Tetragon / IG | YES | Loss observable, not silent (silent = security bug per IG) |
| Producer-side aggregation for repeats, never for drops/errors | Hubble MonitorAggregation | MAYBE | Optional volume control; keep security events unaggregated |
| Correlation key = (pid, start_time), not bare pid | Tetragon `exec_id` | YES | Survives pid reuse; parent link builds process tree |
| gRPC/protobuf event bus | Tetragon / Hubble | NO | New heavy deps; serialize tax pointless in-process; no C/C++ lib |
| CRD / K8s control plane | Tetragon / IG Trace CRD | NO | Host agent has no k8s API server |
| Dynamic `.so` plugin ABI with runtime version negotiation | Falco plugin API | NO (overkill) | Two in-tree consumers → compile-in interface + shared version const |
| Unix-socket per-connection listener transport | Hubble listeners | NO | Consumers are in-process; keep direct-callback consumer path |
| Rich self-describing record as the WIRE format | Hubble `Flow` proto | NO | Keep ring flat/compact; materialize rich structs consumer-side |

---
*Confidence note: all cited claims are VERIFIED against official docs / API references / godoc / source blobs and issues as linked inline. Byte-exact struct layouts (scap_evt, trace_notify, ring.go internals) are VERIFIED against official docs that mirror the headers; line-anchored raw-source reads were not possible in this environment. Items reasoned from cited material rather than stated verbatim are marked INFERRED in their sections.*
