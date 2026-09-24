# Issue question coverage — every question the six issues ask, and where it stands

The five spikes and their parent objective pose their own design questions, in their *Open questions*,
*Angles to explore*, *Deliverables* and *Acceptance criteria* sections. This document extracts them,
one row each, and records what this branch actually answers.

- **Source:** the issue **descriptions** of
  [#37203](https://github.com/wazuh/wazuh/issues/37203),
  [#37382](https://github.com/wazuh/wazuh/issues/37382),
  [#37532](https://github.com/wazuh/wazuh/issues/37532),
  [#37533](https://github.com/wazuh/wazuh/issues/37533),
  [#37534](https://github.com/wazuh/wazuh/issues/37534),
  [#37837](https://github.com/wazuh/wazuh/issues/37837) — read 2026-09-24, not their comment threads
- **Checked against:** `37532-5-0-0-container-integration` (`9ced58d751`), post-rebase onto `origin/5.0.0`
- **Date:** 2026-09-24

> **How this differs from [16](16-open-design-questions.md).** Doc 16 asks what still needs deciding,
> and was derived from *this analysis*. This document runs the other way: it starts from what the
> **issues themselves** asked and marks each one answered or not. Rows that are still open point at
> their Q-number in doc 16 rather than restating the argument.

## 17.1 Status legend

| | Meaning |
| --- | --- |
| ✅ | **Resolved** — decided, implemented, and verified on a real node |
| 🟢 | **Implemented, unverified** — the code exists; no end-to-end evidence was taken |
| 📄 | **Answered on paper** — written up in these documents, never ratified by the owner the issue names |
| 🟡 | **Partial** — the row states which half does not hold |
| ❌ | **Open** — no answer |
| ➖ | **N/A** — out of this branch's scope by the issue's own wording |

---

## 17.2 #37203 — the objective's own open questions and requirements

The objective lists four explicit spikes under *Notes → Open questions*, plus twelve functional and
four non-functional requirements that each imply a design question.

| # | Question, as the objective asks it | Status | Where this branch stands |
| --- | --- | --- | --- |
| 1 | **Correlation mechanism**: best runtime identifier for eBPF correlation (PID, cgroup, namespace, container ID)? | ✅ | cgroup v2 inode, resolved through `/proc/<pid>/cgroup` + `stat()`. PID rejected (rotates, racy); container id is not kernel-observable at event time. |
| 2 | **eBPF compatibility**: kernel compatibility and fallback mechanisms? | 🟡 | The mechanism exists — `rt_engine.c:473-476` probes `/sys/kernel/security/lsm` and picks the `lsm/file_open` program or a kprobe fallback; the object builds through a host-BTF fallback. What does **not** exist is a statement of which kernels are claimed. Validated on exactly one: Ubuntu 24.04.4 / 7.0.0-31. → [16 Q13](16-open-design-questions.md#q13--what-kernel-and-lsm-configuration-is-claimed-supported) |
| 3 | **FIM integration**: what changes to support container-aware monitoring? | ✅ | Answered in full: primary key `(container_id, path)`, `container_id` as a typed column, a container-tagged `<directories>` selector, the subscribe-first baseline, the four reconcile modes, stateless alerts with `changed_fields`. Validated against Docker and kind. |
| 4 | **IT Hygiene integration**: which inventory sources can leverage eBPF collection? | ❌ | **This is the one the branch does not answer.** `grep` finds zero eBPF references in `wazuh_modules/syscollector/`: all eleven container data classes are collected by periodic host-side scans, none by an event. The question was answered for *feasibility* ([07](07-options-matrix.md)) but the eBPF-driven half of #37534's premise is not built. → [16 Q8](16-open-design-questions.md#q8--does-container_instances-publish-a-lifecycle-delta-d7) |
| 5 | **FR3** — replace the Docker Listener with a generic container runtime connector. | 🟡 | The generic connector exists; the Docker Listener **also still exists** at `wazuh_modules/src/wm_docker.c`, with its config parser and unit tests. Nothing has been replaced yet — they coexist. No deprecation decision has been taken. |
| 6 | **FR9** — store container state in the same `wazuh-states-*` indices, one document per state per agent. | ❌ | Rows are produced and locally correct; ten indices reject them under strict mapping. → [16 Q1](16-open-design-questions.md#q1--what-is-the-indexer-document-shape-for-container-context) |
| 7 | **FR10** — emit a change event on create/modify/delete including `changed_fields`. | ✅ | Implemented and measured for FIM (`3d55895056`, `9b068abb04`). A container file change raises an alert carrying `changed_fields`; baseline rows deliberately do not alert. |
| 8 | **FR11** — expose configuration as a block with `enabled`, `type` (docker/kubernetes), `path`, `credentials`. | 🟡 | **Deliberately diverges.** `config/src/wmodules-container-instances.c` implements `<enabled>` plus nested `<kubernetes>` and `<docker>` sub-blocks (`kubeconfig`, `node_name`, `ownership_poll_interval`, `insecure_skip_tls_verify`; `socket_path`). There is no `type`, `path` or `credentials`. The shape is better — typed per runtime, and it makes the dual-runtime case expressible, which a single `type` cannot — but it contradicts a stated FR and nobody has ratified the change. → [16 Q18](16-open-design-questions.md#q18--what-is-the-operator-facing-configuration-surface-across-two-consumers) |
| 9 | **FR12** — dashboard views for container events and a dedicated summary view. | ➖ | Not started. Explicitly out of scope for every agent-side spike, and out of scope for #37837 too. |
| 10 | **NFR3** — configurable limits on tracked items. | ✅ | Per-dimension container row budgets land in `ce04396e50` and were validated on the node: 32 container package rows against a budget of 2 → 2 promoted, host counts untouched. The **values** are still placeholders → [16 Q17](16-open-design-questions.md#q17--which-shipped-defaults-are-still-placeholders). |
| 11 | **NFR4** — extract the eBPF engine into an independent module. | ✅ | `shared_modules/ebpf_provider` (#37396), imported and kernel-verified: `4 program(s) attached, ABI 1.1`. |
| 12 | **Implementation restriction 4** — supported agent platforms (eBPF, Kubernetes, Docker versions) to be defined. | ❌ | Never defined. → [16 Q12](16-open-design-questions.md#q12--what-does-the-agent-do-on-cgroup-v1-d11), [16 Q13](16-open-design-questions.md#q13--what-kernel-and-lsm-configuration-is-claimed-supported) |

---

## 17.3 #37382 — connection, auth, correlation and metadata *(issue CLOSED)*

The issue is closed, but closure recorded decisions rather than implementations. These rows check the
implementation against what it decided, and mark the deliverables it named that were never produced.

### Part A — connection and authentication

| # | Question | Status | Where this branch stands |
| --- | --- | --- | --- |
| A1 | Kubernetes credential form: kubeconfig, or bare token + CA + endpoint? | ✅ | Kubeconfig, referenced by `<kubeconfig>`. Endpoint, CA and token in one file, as the issue suspected. |
| A2 | Token lifetime and rotation: what re-read trigger? | ✅ | Stronger than the issue's options. `kubernetes_api_client.hpp:22` states the credential is resolved at the top of **every call, token files re-read included**, so external rotation needs no trigger at all. An inline `StaticToken` does not rotate — correctly, since it is a literal. |
| A3 | TLS verification — is `insecure-skip-tls-verify` allowed at all? | 🟡 | Implemented as allowed (`<insecure_skip_tls_verify>`). The issue asked whether it should exist; the code answers yes and no one has agreed. |
| A4 | API endpoint explicit in config, since `KUBERNETES_SERVICE_*` is absent on a host. | ✅ | From the kubeconfig's `server`. |
| A5 | **RBAC manifest + token-provisioning procedure committed under `samples/`.** | ❌ | No YAML anywhere in the tree. The permissions the code needs are implied by the endpoints it calls and were never written down, so an operator cannot provision the ServiceAccount from this branch. This is a named acceptance criterion of a **closed** issue. |
| A6 | Node identity, and one ServiceAccount cluster-wide vs one per node. | 🟡 | `<node_name>` provides identity explicitly. The SA topology recommendation was never written. |
| A7 | Docker: local socket only, or local + remote TCP+TLS, for v1? | ✅ | Local socket only — there is no TLS or `tcp://` code in the Docker connector. A clean scope decision that needs one line of documentation. |
| A8 | Docker socket authorization: what user does the agent run as, does it need the `docker` group? | 🟡 | `<socket_path>` is configurable; the privilege note the issue asks for ("socket ≈ root-equivalent", minimal-exposure recommendation) was never written. → [16 Q14](16-open-design-questions.md#q14--what-privileges-does-the-feature-require-and-what-degrades-without-them) |
| A9 | Docker API version: pin or negotiate? | ✅ | Negotiate. `docker_api_client.cpp:83-110` calls `GET /version` and adopts the negotiated version above a `MINIMUM_API_VERSION` floor; every later call is `/v<negotiated>/…`. |
| A10 | Failure matrix: each error class → log symptom → recovery action, both connectors. | 🟡 | The failure *modes* are handled (socket missing, daemon down, unreachable apiserver, stream disconnect) and D5's suppression rule is deliberate. The matrix as a document does not exist — and [C28](03-findings-correctness.md#c28--with-no-containers-list-reads-as-connector-unavailable) is exactly the class of bug a written matrix catches: an empty reply read as an unreachable connector. |

### Part B — correlation and metadata resolution

| # | Question | Status | Where this branch stands |
| --- | --- | --- | --- |
| B11 | Identifier choice, validated across the angle-17 edge cases. | ✅ | cgroup v2 inode. See #37203 row 1. |
| B12 | Kubernetes metadata source: kubelet `/pods`, apiserver, or CRI? | ✅ | apiserver, list-then-watch on pods plus a 120 s ownership poll. CRI was excluded by the no-SDK constraint, as the issue predicted. |
| B13 | Docker metadata source, and cgroup-driver validation of the id mapping. | ✅ | `GET /containers/json` + `/containers/{id}/json`. The cgroup-driver mapping is validated for cgroupfs; the systemd driver is untested — the same gap as [16 Q10](16-open-design-questions.md#q10--does-docker-restart-change-the-containers-cgroup-inode-d8). Note `all=1` is **not** passed → [16 Q4](16-open-design-questions.md#q4--does-dockers-listcontainers-pass-all1-d6). |
| B14 | Resolution cache: record shape, indexes, threading, memory/CPU budget. | 🟡 | Shape and threading are implemented as specified — `container_record.hpp` carries container id/name, image, digest, labels, network, `ociMounts`, pod/namespace/owner refs, and lookups run off a single watcher. The **memory/CPU budget on a busy node** was never measured. → [16 Q16](16-open-design-questions.md#q16--what-is-v1s-supported-container-count-and-what-happens-above-it) |
| B15 | Watch/lifecycle: `resourceVersion` reconnect, `410 Gone` re-list, Docker `/events` resume, cold-cache policy. | 🟡 | Kubernetes list-then-watch is implemented; Docker `/events` with `since=` resume is implemented (`docker_api_client.cpp:151`); the cold-cache policy is the three-verdict API (`resolved` / `pending` / `not_container`) plus a 5 s resolver retry. **The Docker half has a live defect** — [C16](03-findings-correctness.md#c16--dockers-deferred-reconcile-is-dropped-not-deferred), the deferred reconcile is dropped. → [16 Q5](16-open-design-questions.md#q5--what-authorises-deleting-a-containers-state-on-a-host-where-nothing-is-happening) |
| B16 | Enrichment query API, **reviewed and accepted by both the FIM and Syscollector spike owners**. | 🟡 | Built, and genuinely shared: one socket, one record, both consumers read it, no K8s-vs-Docker branching reaches either. The **acceptance** the issue requires never happened; the consumers are the same author. |
| B17 | Edge cases: `hostNetwork` / `hostPID` / `cgroupns=host` / Kata / pause sandbox / multi-container pods. | ✅ | All six are handled, and handled as *verdicts* rather than silently: `cache_entry.hpp:32-33` defines `hostNamespace` and `cgroupnsHost` reasons, `kubernetes_connector.cpp:91` excludes `hostNetwork`/`hostPID`/Kata pods, and `k8s_types.hpp:37` records that the pause sandbox never enters the container list. This is the most completely-answered angle in the issue. |
| B18 | Deliverables: auth ADRs, identifier ADR, metadata-source ADR, cache spec, watch design, **edge-case decision table**. | 📄 | All six exist as content across [07](07-options-matrix.md), [09](09-implementation-status.md) and [12](12-blocking-decisions.md). None is an ADR in the repository's own decision-record form, which is what the acceptance criterion says. |

---

## 17.4 #37532 — baseline acquisition

| # | Question | Status | Where this branch stands |
| --- | --- | --- | --- |
| 1a | Host-side rootfs read: overlay `merged` dir, layer reconstruction, or `/proc/<pid>/root`? | ✅ | `/proc/<pid>/root/<internal_path>`. One code path for Docker, containerd and CRI-O, no overlay arithmetic, no per-runtime snapshot layout knowledge. The overlay fallback exists only for a container with no live PID. |
| 1b | Overlay whiteouts and opaque directories. | ✅ | Dissolved by the choice in 1a — the kernel presents the merged view, so a whiteout is simply an absent file. `IsOverlayWhiteout` is kept, documented, for the fallback path that would need it. |
| 1c | UID/GID namespace remapping. | 🟡 | Implemented for files: `rootfs_file_walker.cpp:174-175` reads `/proc/<pid>/uid_map` and `gid_map`, `:200-201` emit translated ids. But `toContainer` is used **nowhere else**, so different data classes now report different id spaces. → [16 Q6](16-open-design-questions.md#q6--which-id-space-do-uid-and-gid-mean-on-a-container-row) |
| 1d | **Validate the host-side hash against what an in-container reader computes** (symlinks, sparse files, special files, whiteouts). | ❌ | Never performed. This is an explicit acceptance criterion of the issue, and the only check that would catch a *systematically* wrong hash. → [16 Q21](16-open-design-questions.md#q21--who-executes-the-two-acceptance-criteria-that-were-never-run) |
| 2 | `/proc`-based process and network baseline, scoped by cgroup, correct per-container for both connectors. | ✅ | Implemented and validated. The pod-shares-a-netns attribution nuance the issue flags is handled by scoping on cgroup, not namespace. |
| 3 | Users/groups and packages/OS parsed from the rootfs, host-side. | ✅ | Both, plus nine more classes — eleven of the thirteen dimensions, with no in-container execution. |
| 4 | Can eBPF replace part of the baseline — a "replay from container-create" model? | ✅📄 | Assessed and set aside as a mechanism ([07 §7.5](07-options-matrix.md#75-ebpf-assisted-baseline-m6-assessed-and-set-aside)). Then, unexpectedly, *partially realised*: a container created after startup is discovered and walked because runc's init writes from an unmapped cgroup. That is observed runtime behaviour, not a contract. → [16 Q9](16-open-design-questions.md#q9--what-is-the-guaranteed-create-trigger-for-container-fim) |
| 5a | In-container execution: evaluate and most likely reject, with rationale. | 📄 | Written in full, with what `exec` would genuinely solve better ([07 §7.4](07-options-matrix.md#74-in-container-execution-evaluation-and-rejection-deliverable-d6)). Unsigned. |
| 5b | **Any unavoidable exception explicitly justified, flagged, and signed off.** | ❌ | `setns(CLONE_NEWNET)` was silently adopted at `interface_scanner.cpp:149-162`. The write-up now exists; the sign-off does not, and **two of the three conditions it was conditionally accepted under are unimplemented** (log on `CAP_SYS_ADMIN` failure, fall back to `/proc/<pid>/net/dev`). → [16 Q20](16-open-design-questions.md#q20--who-signs-the-coverage-matrix-and-the-setns-exception) |
| 6a | **When** does a baseline run: agent start, container-create, config reload, periodic reconciliation? | 🟡 | Agent start ✅ (once, from `main.c:493`). Container-create 🟡 — works, incidentally, per row 4. Config reload ❌ — `grep` finds no reload handling in the container FIM path, so a `container`-tagged `<directories>` entry added by a reload is not walked until the agent restarts. Periodic reconciliation ❌ — there is none. |
| 6b | The gap problem: subscribe-first-then-scan vs scan-then-subscribe vs watermark. **Prove no lost and no double-counted change.** | ✅ | Subscribe-first, staged, released at the first-scan boundary. Demonstrated by racing a write against the scan — the whole of [15 §15.5](15-spike-resume.md#155-container-fim-at-startup-subscribe-first-then-walk). The best-answered question in this issue. |
| 6c | Re-baseline triggers: ring overflow, container restart, reload/scope change. | 🟡 | Ring overflow ✅ — per-cgroup drop accounting escalates to `rewalkContainer`. Restart ❌ — undecided, and undecidable before [16 Q10](16-open-design-questions.md#q10--does-docker-restart-change-the-containers-cgroup-inode-d8). Reload ❌ — per row 6a. |
| 6d | Interaction with the **first-sync-after-reload data-loss failure class**. | ❌ | Named by three of the five issues, analysed by none of these documents and unaddressed in the code. Whether container rows are covered by whatever guard exists has never been checked. |
| 7a | Throttling model, cap files-per-container, behaviour at the ceiling. | ✅ | Per-dimension budgets, validated. Files also inherit FIM's `check_max_fps`. |
| 7b | **Cold-start storm: 100 containers at agent start. Measure wall-clock to "node fully baselined".** | ❌ | Never measured — needs a real multi-container node (item 39). → [16 Q16](16-open-design-questions.md#q16--what-is-v1s-supported-container-count-and-what-happens-above-it) |
| 7c | Image-digest de-dup: can a replica of an already-baselined image skip work? | 🟡 | `ImageContentCache` implements it **within a cycle**. Across cycles it needs somewhere to live (item 22/29), and its value inverts once a lifecycle delta exists — the dependency runs the opposite way from the roadmap. |
| 8 | Docker vs Kubernetes parity: overlay/rootfs resolution for Docker overlay2, containerd snapshots, CRI-O. | ✅🟡 | Made moot for all three by the `/proc/<pid>/root` choice. Validated on Docker and containerd (kind); CRI-O is covered by the same code path but has never been run. |
| 9 | Edge cases: distroless, userns, read-only rootfs, tmpfs, short-lived containers, Kata. | 🟡 | Distroless ✅ (absent files return absent, and no in-container binary is needed). Short-lived ✅ (`root_missing` vs `root_unreadable`, and [D15](12-blocking-decisions.md) forbids inferring a deletion from an unreadable path). Kata ✅ (excluded at the connector). userns 🟡 per row 1c. Read-only rootfs and tmpfs/secret mounts — untested. |

---

## 17.5 #37533 — FIM integration

| # | Question | Status | Where this branch stands |
| --- | --- | --- | --- |
| 1a | Stable primary key for a container file state. | ✅ | `(container_id, path)`, with host rows carrying `container_id = ""`. Chosen over a synthetic URI so the existing schema is not forked. |
| 1b | Which enrichment fields are first-class columns vs a nested `container` object? | ❌ | `container_id` is a typed column locally; everything else is a per-row blob, and none of it is mapped server-side. → [16 Q1](16-open-design-questions.md#q1--what-is-the-indexer-document-shape-for-container-context) |
| 2 | Enrichment join: synchronous lookup vs cached resolver; cold cache; container reaped mid-lookup. | ✅ | Cached, with the three-verdict API, a pending queue and a 5 s resolver cycle capped at `max_resolves_per_cycle`. The reaped-mid-lookup race resolves to `not_container` rather than a stale hit. |
| 3a | Path resolution: `(container-identity, kernel_path) → (logical_path, host_path)`, mount-aware, longest-prefix against OCI mounts. | 🟡 | **Solved differently, and the difference matters.** The issue specifies reconstructing a host path from the OCI mount list. This branch never reconstructs one: it addresses through `/proc/<pid>/root/<internal_path>`, so the kernel does the mount resolution. The OCI mount list *is* consumed — but as a **traversal policy**: `rootfs_file_walker.cpp:44-70` permits crossing a mount boundary only into a declared destination, and never into one whose source is `/`, which is what stops a `hostPath: /` volume turning a container baseline into a full host scan. Simpler and safer than the specified algorithm; not what any issue describes. |
| 3b | **Volume-type behaviour table** — hostPath / emptyDir / configMap / secret / PVC / ephemeral CSI / image volume / Docker bind + named volume × does the hook fire? × path semantics × handling. | ❌ | Not produced. The `/proc` addressing makes most rows behave uniformly, which is an argument that the table is *cheap*, not that it is unnecessary — "does the hook fire on a tmpfs secret mount?" is still unanswered. |
| 4a | Sync layer: a new dataset alongside host FIM, or the same dataset with container fields? | ❌ | The same dataset is assumed and was never agreed. → [16 Q2](16-open-design-questions.md#q2--does-container-inventory-get-its-own-index-or-ride-the-existing-state-indices) |
| 4b | First-sync / reload semantics, wired into the guard for the known data-loss class. | ❌ | See #37532 row 6d. |
| 4c | Deletion propagation bounding when a pod with 10k tracked files disappears. | 🟡 | Deletion is implemented and correctly gated ([D15](12-blocking-decisions.md), [D17](12-blocking-decisions.md), [C28](03-findings-correctness.md#c28--with-no-containers-list-reads-as-connector-unavailable)). It is not **bounded**: nothing rate-limits a mass delete, and nothing has produced one at scale. |
| 5a | `changed_fields` reuse; which attributes are observable via eBPF vs need host-side I/O. | ✅ | Reused as-is. The event carries the path; every attribute including the hash comes from a host-side re-read through `/proc/<pid>/root`, settled in the staging buffer so the re-read sees the post-write state ([D16](12-blocking-decisions.md)). |
| 5b | Report-changes / content diff for container files: feasible or out of scope for v1? | ❌ | Never decided, and not implemented — `grep` finds no `report_changes` handling in the container path. An operator enabling it on a container-tagged directory gets silence. |
| 6 | Configuration surface and selectors — path prefix, container/image/namespace, labels — generalising across Docker and Kubernetes. | 🟡 | `<directories tags="container">` works and generalises cleanly. The richer selector vocabulary the issue asks about — by image, namespace or label — does not exist, and was never decided against. |
| 7a | **Unavailable-options table** for docs (`whodata`, `realtime` nuances, `recursion_level`, `restrict`, scheduled scans). | ❌ | Not produced, and the assumption behind it is partly wrong: `recursion_level` **is** honoured for container directories. Scheduled scans genuinely do not apply — there is no scheduled container walk. |
| 7b | Item limits: where enforced, ceiling behaviour, interaction with sync. | ✅ | Per-dimension, validated. Values still placeholders. |
| 8 | Initial baseline walk vs pure event-streaming with lazy state creation. | ✅ | Baseline walk, once, at startup — which is the whole of #37532, and the reason state is complete rather than reactive. |
| 9a | `hostPath` volumes pointing at a directory host FIM already monitors — dedupe, emit twice, or container-only? | ❌ | Undecided and unhandled. With both a host `<directories>` entry and a container-tagged one covering the same host directory, two rows exist under different `container_id` values and both alert. Nobody has said whether that is correct. |
| 9b | Behaviour when enrichment resolves to "host, not a container". | ✅ | The `not_container` verdict; host FIM owns the path and no container row is created. |
| 9c | Init / sidecar / ephemeral containers and the pause sandbox. | ✅ | Each container is its own cgroup and therefore its own rows; the sandbox never enters the container list. |
| 9d | VM-isolated runtimes (Kata). | ✅ | Out of scope and enforced, not merely documented: Kata pods are excluded at the connector. |
| AC | **State survives an agent restart without loss.** | 🟡 | `file_entry` rows persist in `fim.db`, and the baseline re-runs at startup with the first-scan gate suppressing alerts — so state is rebuilt rather than preserved. The distinction was never tested, and [C27](03-findings-correctness.md) showed how invisible a restart can make a defect: uncommitted rows silently re-inserted. |

---

## 17.6 #37534 — IT Hygiene (Syscollector) integration

| # | Question | Status | Where this branch stands |
| --- | --- | --- | --- |
| 1 | **Coverage matrix**, dimension × source × feasible-without-exec × eBPF-driven × v1 in/out — **product-signed-off**. | 📄 | The matrix exists ([07](07-options-matrix.md)): seven mechanisms × eleven data classes, primary and fallback per class. The issue calls scoping "this spike's biggest risk" and requires product sign-off **before any plumbing design**. The plumbing was built first and the sign-off has not happened. → [16 Q20](16-open-design-questions.md#q20--who-signs-the-coverage-matrix-and-the-setns-exception) |
| 2 | Source strategy per dimension: eBPF-driven for processes/network, host-side rootfs read for image-derived. | 🟡 | The host-side half is built for all eleven classes. The eBPF-driven half is **not built at all** — see #37203 row 4. Every dimension, including processes and ports, is a periodic scan. |
| 3 | **Event→state vs snapshot**: event-driven upserts plus periodic reconciliation, or pure periodic scan? | ❌ | Pure periodic snapshot, by omission rather than by decision. The issue's own framing — "container processes/network are naturally event-driven" — is not what shipped, and no document records choosing otherwise. |
| 4a | Container-scoped primary keys, given PID reuse and the same package in many containers. | ✅ | Container-scoped keys across all eleven classes, with `sweepContainerRowsNotIn(keep)` for removal. |
| 4b | First-class vs nested `container` object, aligned with FIM's choice. | ❌ | Consistent with FIM — both blocked on the same schema decision. → [16 Q1](16-open-design-questions.md#q1--what-is-the-indexer-document-shape-for-container-context) |
| 5 | Enrichment join and lifecycle, reusing FIM's resolver decision. | ✅ | Literally the same socket and the same record; no second metadata plane. |
| 6a | Sync-infra integration and the first-sync-after-reload guard. | ❌ | See #37532 row 6d. |
| 6b | Deletion bounding on container exit for a container with many inventory items. | 🟡 | Deletion works and is gated on the connector being available. Unbounded, and worse than FIM's case today because [C16](03-findings-correctness.md#c16--dockers-deferred-reconcile-is-dropped-not-deferred) means an idle host may never trigger it at all. |
| 6c | Item limits per container/agent and ceiling behaviour. | ✅ | `ce04396e50`, validated on the node. |
| 7 | Docker parity for every chosen dimension. | ✅ | All eleven classes run through the same runtime-agnostic record; validated against Docker and kind. |

---

## 17.7 #37837 — server-side reception, mappings and capacity

The issue has no comments and was never started. Every row is open; what this branch adds is that two
of them are now **measured** rather than predicted.

| # | Question | Status | Where this branch stands |
| --- | --- | --- | --- |
| 1 | **Index mappings** — decide the container field shape (ECS `container.*` / `orchestrator.*` vs a nested object) and update the templates plus the vendored copies. | ❌ | Measured 2026-09-08: no schema in `external/indexer-plugins` carries a `container` field, `fim-files.json` included, so ten indices reject every container document. The constraint the issue names — nothing may live under `wazuh.*`, the manager overwrites it — is respected by the agent payload. → [16 Q1](16-open-design-questions.md#q1--what-is-the-indexer-document-shape-for-container-context) |
| 2 | **State identity and deletion** — does `{cluster}_{agent_id}_{data.id}` stay unique across containers, and is mass deletion bounded? | ❌ | Unvalidated in both halves. The agent's key is `(container_id, path)`; whether that survives into `data.id` with uniqueness intact has never been checked end to end, because no document has ever been accepted. Bounding: see #37533 row 4c. |
| 3 | **Change events (FR10)** — trace the engine path; do the schema or ruleset need changes for container fields to be indexed and shown in the existing FIM sections? | ❌ | Untraced. The issue notes "no sibling spike covers this", and none does. The agent emits stateless alerts with container context; whether the engine accepts and routes them is unknown. |
| 4 | **Capacity (NFR3)** — benchmark `inventory_sync` under container churn; size `maxSessions`, `dataValueQuota`, queue size, `indexerBulkSize`, `indexerFlushInterval`. | ❌ | Not started. The agent-side equivalent is equally unmeasured → [16 Q16](16-open-design-questions.md#q16--what-is-v1s-supported-container-count-and-what-happens-above-it). |
| 5 | **New index** — only if a dedicated container-instances dataset is decided for the FR12 view. | ❌ | Depends on row 1's shape decision. → [16 Q2](16-open-design-questions.md#q2--does-container-inventory-get-its-own-index-or-ride-the-existing-state-indices) |

---

## 17.8 Tally

| Issue | Questions | ✅ | 🟢/📄 | 🟡 | ❌ | ➖ |
| --- | --- | --- | --- | --- | --- | --- |
| #37203 | 12 | 5 | — | 3 | 3 | 1 |
| #37382 | 18 | 9 | 1 | 7 | 1 | — |
| #37532 | 18 | 8 | 1 | 5 | 4 | — |
| #37533 | 19 | 8 | — | 4 | 7 | — |
| #37534 | 10 | 4 | 1 | 2 | 3 | — |
| #37837 | 5 | — | — | — | 5 | — |
| **Total** | **82** | **34** | **3** | **21** | **23** | **1** |

Rows counted once; a cell marked ✅🟢 or ✅📄 counts under its first symbol.

## 17.9 What the tally does not show

**The questions that are answered are the hard ones.** Correlation key, the baseline mechanism, the
handoff algorithm, the edge-case matrix, the primary key, the enrichment seam — these were the risky
parts of the design and they are decided, implemented and in several cases proved by racing the case
they were supposed to handle. That is the substance of four spikes.

**Four kinds of thing dominate the 23 open rows**, and only one of them is design work:

1. **Sign-offs and decision records** (#37382 A5/A10/B18, #37532 5a/5b, #37534 1). Content that exists,
   in a form or with an approval that does not. Cheap, and blocking issue closure rather than code.
2. **Measurements never taken** (#37532 1d/7b, #37382 B14, #37837 4). Each needs a real node and an
   afternoon; several open decisions are explicitly waiting on them.
3. **The server side** (#37837, all five). Not started, externally owned, and the reason the stateful
   half of the feature delivers nothing today.
4. **One genuine design gap**: #37534 rows 2 and 3 with #37203 row 4 — **Syscollector was specified as
   an eBPF consumer and is not one.** It polls. Everything else on this list is a decision, a document
   or a measurement; this is the one place where what was built differs in kind from what was asked.

**Three answers diverge from what the issues specify**, each defensibly, none ratified:

| Issue says | Branch does | Why it is arguably better |
| --- | --- | --- |
| FR11: `type`, `path`, `credentials` | nested `<kubernetes>` / `<docker>` blocks with typed children | typed per runtime, validates at parse time, and makes the dual-runtime case expressible — which a single `type` cannot |
| #37533 3a: reconstruct a host path by longest-prefix match against OCI mounts | address through `/proc/<pid>/root`; use the mount list as a **traversal policy** instead | the kernel does the mount resolution; the mount list then buys a `hostPath: /` escape guard the specified algorithm would not have |
| #37532 1: locate the overlay `merged` dir per runtime | `/proc/<pid>/root` for every runtime | one code path for Docker, containerd and CRI-O, and no snapshot-layout knowledge to maintain |

Each of these is a good decision recorded in the wrong place: in the code, and in an analysis
document, rather than in the issue that asked the question.
