# Container FIM/syscollector validation — test plan and results

Target: `wazuh_manager` VM (real Linux, kernel 7.0.0, kernel BPF supported). Branch under test:
`spike/37533-fim-ebpf-integration` at the last commit pushed to origin at the time of this run
(`c4357e6481 "fix: changed_fields alerting for live container fim path"`), plus two build fixes
made and applied directly on the VM during this session (not yet pushed — see below).

Test targets, both pre-existing on the VM:
- **Docker**: `my-nginx` (nginx image, container name `my-nginx`).
- **Kubernetes**: kind cluster `demo`, single node `demo-control-plane` (itself a Docker container
  running containerd + the cluster's system pods).

## Test plan

1. Compile the last pushed content of `spike/37533-fim-ebpf-integration` on the VM.
2. Install the resulting artifacts into the running `/var/ossec` agent.
3. Check the agent's Docker/Kubernetes configuration (`container_instances`, `<syscheck>` selectors)
   and correct anything that would prevent container FIM from running at all.
4. Start manager + agent, trigger real file creates/modifies inside a container on each runtime,
   and check for the resulting syscollector inventory and FIM state/alert events — at the local
   agent DB layer and, where possible, all the way through to the indexer.

## Step 1–2: Compile + install

- Reset the VM's checkout to `origin/spike/37533-fim-ebpf-integration` (`git fetch` + `git reset --hard`;
  the VM's tracked tree was already clean, only harmless untracked scratch docs present, so nothing
  was lost).
- `make build -j$(nproc) TARGET=agent` **failed to link** on the first attempt:

  ```
  /usr/bin/ld: ../lib/libfimebpf.so: undefined reference to `get_iso8601_utc_time(char*, unsigned long)'
  ```

  Root cause: `container_live_fim.cpp`'s own `extern "C" { #include "file.h" #include "time_op.h" }`
  block came *after* the plain `#include "syscheck.h"`, which itself pulls in `time_op.h`
  (via `syscheck-config.h` → `shared.h`) **unwrapped** first. `time_op.h`'s own include-guard then
  made the later, wrapped re-inclusion a silent no-op, leaving `get_iso8601_utc_time()` with C++
  linkage while its actual definition (`time_op.c`) has C linkage.

  Fix attempt 1 (include `file.h` wrapped, first in the file) fixed that symbol but broke the build
  a different way:

  ```
  /usr/include/c++/13/atomic:1525:3: error: template with C linkage
  ```

  `file.h` pulls in `syscheck.h`'s entire chain, which eventually reaches real C++ standard headers
  (`<atomic>`) — wrapping that whole chain in `extern "C"` doesn't compile at all (C++ templates
  cannot have C linkage).

  Final fix: wrap only the small, self-contained `time_op.h` first (before anything else can reach
  it unwrapped), and hand-forward-declare the three `file.h`-specific functions
  (`fim_attributes_json`, `fim_calculate_dbsync_difference`, `fim_configuration_directory`) with
  `extern "C"` after the normal `#include "syscheck.h"`, once `directory_t`/`fim_file_data`/`cJSON`
  are already visible. This built cleanly. Applied to
  `src/syscheckd/src/ebpf/src/container_live_fim.cpp` and `src/syscheckd/src/ebpf/CMakeLists.txt`
  (dropped the now-unused `src/file/` include path) both on the VM and in the local worktree.

- `sudo ./install.sh` — interactive by default; preloaded `etc/preloaded-vars.conf` with
  `USER_LANGUAGE=en`, `USER_INSTALL_TYPE=agent`, `USER_UPDATE=y` to run it non-interactively.
  Update completed; `/var/ossec/etc/ossec.conf` was preserved (not overwritten).

## Step 3: Configuration check — two real, blocking problems found

Reading the deployed `ossec.conf` surfaced two issues that would have silently prevented any of
this from working, independent of the code itself:

1. **Tag mismatch.** The only container-monitoring directory was:

   ```xml
   <directories tags="kubernetes" whodata="yes" recursion_level="5">/test_dir</directories>
   ```

   Every place in the code that decides "is this a container-monitored path"
   (`fim_collect_container_monitored_paths()` in `container_baseline_fim_bridge.c`, and the live
   path's own routing in `ebpf_whodata.cpp`) checks for the literal tag value `"container"`, not
   `"kubernetes"`. With this config, **no directory was ever recognized as container-monitored at
   all** — the tag the issue's own design settled on (`tags="container"`, applying uniformly across
   Docker and Kubernetes) was never actually wired into this deployment's config. `/test_dir` also
   doesn't exist inside any real container image, so even a correct tag would have found nothing to
   walk.

   Fixed: replaced with `<directories tags="container" whodata="yes" recursion_level="5">/etc</directories>`
   — `/etc` exists in effectively every Linux container image, giving both the baseline walk and the
   live path real files to find.

2. **eBPF whodata provider not selected.** `syscheck->whodata_provider` defaults to `AUDIT_PROVIDER`
   (`syscheck-config.c:93`), and nothing in the shipped config overrode it. `run_check.c` only
   launches the eBPF thread when `whodata_provider == EBPF_PROVIDER` — so **the entire eBPF engine,
   and therefore the entire live container-FIM path this spike adds, was never even attempted**. The
   agent was silently running the old Audit-based whodata provider the whole time; nothing in the
   startup log even mentioned eBPF.

   Fixed: added

   ```xml
   <whodata>
     <provider>ebpf</provider>
   </whodata>
   ```

   inside `<syscheck>`. After restart, the eBPF engine loaded for real and passed its full
   healthcheck on actual hardware:

   ```
   (6047): Initializing eBPF driver for FIM whodata.
   (6049): eBPF healthcheck action succeeded: create file.
   (6049): eBPF healthcheck action succeeded: modify content.
   (6049): eBPF healthcheck action succeeded: modify metadata.
   (6049): eBPF healthcheck action succeeded: delete file.
   (6048): Healthcheck for eBPF FIM whodata module success.
   ```

   (`container_instances` was already correctly configured for both connectors — `<docker><socket_path>`
   and `<kubernetes><kubeconfig>/<node_name>` were present and did not need changes.)

## Step 4: Validation results

### What worked

- **Syscollector container inventory, both runtimes, end-to-end to local persistence.** Docker
  (`my-nginx`, `runtime:"docker"`) and Kubernetes (every pod on `demo-control-plane`, including a
  brand-new pod created mid-session, `runtime:"kubernetes"` with full `namespace`/`node`/`pod`/
  `owner_refs` detail) both produced correctly enriched inventory events, and syscollector's own
  container baseline correctly **re-discovers new containers on its recurring cycle** (went from 4
  to 5 tracked containers within about a minute of creating a new test pod).
- **FIM container baseline, for containers present at agent startup.** The three Kubernetes system
  pods running before the agent started (coredns ×2, local-path-provisioner) were baselined and
  their `/etc` contents persisted correctly to the local FIM database, keyed on
  `(container_id, path)` exactly as designed — confirmed directly via `sqlite3` against
  `/var/ossec/queue/fim/db/fim.db`.
- **eBPF engine itself**, on real hardware, fully functional (see healthcheck output above).

### What did not work — four distinct, reproducible problems (initial pass)

1. **Cross-cutting: no container-enriched document of any kind reaches the indexer.**
   Every attempt to persist a document containing a `container` (or `kubernetes`) field — from FIM
   *and* from syscollector — is rejected:

   ```
   ERROR: Schema validation failed for container FIM baseline row <id>:<path>
          (index: wazuh-states-fim-files). Errors: container: Field not allowed in strict mode
   ERROR: Schema validation failed for Syscollector message
          (table: dbsync_processes, index: wazuh-states-inventory-processes).
          Errors: - container: Field not allowed in strict mode
   ```

   72 occurrences for FIM, 4528 for syscollector, across every container tracked. Confirmed directly
   against the indexer:

   ```
   GET wazuh-states-fim-files*/_search {"query":{"exists":{"field":"container"}}}   -> 0 hits (of 7905 total docs)
   GET wazuh-states-inventory-ports*/_search {"query":{"exists":{"field":"container"}}} -> 0 hits
   GET wazuh-states-inventory-processes*/_search {"query":{"exists":{"field":"kubernetes"}}} -> 0 hits
   ```

   The rows exist correctly in the **local** agent database (see above) — this is purely a
   manager/indexer-side index-template gap. **Out of scope for this pass by explicit direction**:
   this issue is about the agent generating correct FIM/syscollector events, not the indexer
   templates — noted here for completeness, not pursued further.

2. **The `my-nginx` Docker container was invisible to FIM's own container baseline**, while fully
   visible to syscollector's. Syscollector's baseline reported 4 containers; FIM's reported only 3
   (`"Container FIM baseline finished (3 container(s) baselined)"`), and only the 3 Kubernetes system
   pods ever appeared in `fim.db` — never `my-nginx`. **Root-caused** (see below): a startup race,
   not a permanent discovery gap.

3. **The live (eBPF whodata) container-FIM path did not produce a single row for any container
   tested, for either runtime.** Real create+modify writes were made at the monitored `/etc` path
   inside `my-nginx` and inside a purpose-created Kubernetes test pod, with the eBPF engine confirmed
   healthy throughout, yet `fim.db` showed no trace of either. **Root-caused and fixed** (see below):
   two real, independent bugs.

4. **FIM's container baseline is a strict one-shot at agent startup**, unlike syscollector's own
   recurring container baseline — by design, not a bug, but worth being explicit that (before the
   fixes below) there was no working path, baseline or live, for a container that both started after
   the agent and wasn't caught by the live path. With finding 3 fixed, the live path now covers this
   case for any container `container_instances` can already resolve.

## Follow-up: root-causing and fixing #2 and #3

Per direction: #1 (indexer schema) and #4 (one-shot baseline design) are expected/out of scope for
this pass, which is about the agent generating correct FIM/syscollector events. #2 and #3 were
investigated further and fixed.

### #2: startup race between FIM's one-shot baseline and `container_instances`' Docker connector

Hypothesis: `RunFimBaseline()`'s one-shot call runs very early in `wazuh-syscheckd`'s startup,
racing `container_instances`' Docker connector (a separate daemon, `wazuh-modulesd`) still doing its
initial container enumeration. `DiscoverContainers()`'s existing retry logic only retries when the
list comes back **empty** — a list that's non-empty but *incomplete* (e.g. the 3 Kubernetes pods
already enumerated, `my-nginx` not yet) is accepted as final.

**Confirmed directly**: killed and restarted only `wazuh-syscheckd` (leaving `wazuh-modulesd`/
`container_instances`, already running for over an hour, untouched) — its cgroup path
(`/system.slice/docker-<id>.scope`) and `ResolvePidsForContainer()`'s regex were never actually the
problem, and the *only* variable that changed was container_instances' warm-up state:

```
Container FIM baseline finished (3 container(s) baselined).   <- fresh agent restart (race)
Container FIM baseline finished (3 container(s) baselined).   <- fresh agent restart (race)
Container FIM baseline finished (4 container(s) baselined).   <- syscheckd-only restart, container_instances already warm
```

`my-nginx` then had 500 files baselined, confirming the discovery mechanism itself is correct once
the race doesn't fire. Not fixed in code this pass (would need `DiscoverContainers()` to also retry
when a list is present but has grown between polls, mirroring the existing empty-list retry) — but
narrowed from "unexplained gap" to a specific, well-understood timing window with a documented
reproduction.

### #3: the live path — two independent bugs, both fixed and verified end-to-end

Instrumented `fim_handle_container_whodata_event()` and `handle_event()`'s container-candidate
routing with temporary `mdebug2`/`logFn(LOG_DEBUG, ...)` trace lines (kept in the code, worth
leaving until this path is more battle-tested) and rebuilt. First trace immediately found bug 3a:

**3a. JSON shape mismatch — the live path's `resolveByCgroupId()` reply parsing never matched
reality.** `fim_handle_container_whodata_event()` looked for a top-level, camelCase `containerId`
field. The actual wire format (verified against `recordToJson()` in
`container_instances/ci_impl/src/ipc/wire_protocol.hpp`, the authoritative serializer) is
`{"status":"resolved","data":{"container_id":...,"container_name":...,...}}` — snake_case, nested
under `"data"`. Every real reply therefore failed the `record.contains("containerId")` check and was
silently dropped, for every container, every time:

```
dropped -- resolved record missing/invalid containerId: {"data":{"cgroup_id":"20852",
  "container_id":"047b7680ac48ae2c90fca3227c459139dc34adc46ccc8b1fb7be4db14c78a6d8",
  "container_name":"my-nginx", ...}, "status":"resolved","version":1}
```

`build_container_json()` had the identical mistake (camelCase `containerName`/`imageDigest`/
`podName`/etc., all actually snake_case and nested under `data`). Fixed both functions to read the
real shape; `build_container_json()` now takes the `data` sub-object directly rather than the whole
reply.

**3b. Dead PID by processing time — turned out to be the dominant case, not a rare race.** With 3a
fixed, the *next* trace showed a second, independent drop:

```
pid 195940 no longer alive (container_id=047b7680...) -- falling back to ResolvePidsForContainer()
```

The eBPF event's `pid` is the process that triggered the hook — for the extremely common case of a
short-lived writer (`sh -c 'echo ... > file'`, exactly what `docker exec`/`kubectl exec` one-liners
produce, but equally representative of real package-manager/config-reload scripts), that process has
already exited by the time the container-event worker thread processes it. This was already a
documented, known limitation ("no fallback to another live PID") — what this pass adds is the
finding that it's not an edge case, it's essentially *always* true for shell-triggered writes.

Fixed by falling back to `wazuh::container_baseline::ResolvePidsForContainer(container_id)` (the
same resolver the #37532 baseline already uses) when the original PID is dead, using any other live
PID in the same container for the `/proc/<pid>/root` translation instead — valid because every
process in a container shares its mount namespace. This symbol turned out to already be a real,
exported C++ symbol of `libcontainer_baseline.so` (confirmed via `nm -D`) despite living under
`container_baseline_impl/` and earlier documentation's assumption that it wasn't linkable — no build
or link changes were needed beyond forward-declaring it.

**Verified end-to-end after both fixes**, for both runtimes — the agent now correctly builds and
sends the full stateless alert with container/kubernetes enrichment, hash, and attributes (only
failing afterward at the already-out-of-scope indexer-schema step):

```
# Docker (my-nginx):
Sending FIM event: {"collector":"file","module":"fim","data":{"event":{"type":"added"},
  "file":{...,"path":"/etc/wazuh_test_v6.txt","mode":"whodata","tags":"container"},
  "container":{"id":"047b7680...","image":{"name":"nginx",...},"labels":{...},"name":"my-nginx"}}}

# Kubernetes (fresh test pod on demo-control-plane):
Sending FIM event: {"collector":"file","module":"fim","data":{"event":{"type":"added"},
  "file":{...,"path":"/etc/wazuh_k8s_v2.txt","mode":"whodata","tags":"container"},
  "container":{"id":"2441b316...","image":{"name":"docker.io/library/busybox:latest"},...},
  "kubernetes":{"namespace":"default","node":{"name":"demo-control-plane"},
                "pod":{"name":"wazuh-fim-test2","uid":"..."}}}}
```

This also incidentally re-validated the `changed_fields` stateless-alerting work from earlier this
session against real traffic for the first time (the `"type":"added"` event above, plus subsequent
`"modified"` events with `changed_fields`, both observed) — that code path is now proven working
against a live container, not just working-by-inspection.

## Recommendations / next steps

- Fix the index templates (finding 1) when in scope — nothing in this feature is observable in the
  indexer/dashboard until `container`/`kubernetes` are allowed fields on `wazuh-states-fim-files` and
  every `wazuh-states-inventory-*` template.
- Give `DiscoverContainers()` a retry-on-growing-list check (not just retry-on-empty) to close the
  startup race behind finding #2, so FIM's one-shot baseline doesn't systematically miss whichever
  connector is slower to warm up.
- The temporary `mdebug2`/`logFn(LOG_DEBUG, ...)` trace lines added to `container_live_fim.cpp` and
  `ebpf_whodata.cpp` are still in place — consider whether to keep them (this path is new enough that
  the visibility seems worth the log volume) or trim them now that the two bugs they found are fixed.
- Push all changes (`container_live_fim.cpp`, `container_live_fim.h`, `ebpf_whodata.cpp`,
  `CMakeLists.txt`) and the config corrections captured here to origin so the next person testing
  this branch starts from a working live path instead of re-discovering these same two bugs.

## Environment notes for reproducing this

- VM checkout: `/home/ubuntu/source/wazuh`, `git reset --hard origin/spike/37533-fim-ebpf-integration`.
- `sudo ./install.sh` after preloading `etc/preloaded-vars.conf` (see the `vm-build-test` skill for
  the exact contents).
- `ossec.conf` needs, inside `<syscheck>`: a `<directories tags="container" ...>` entry pointing at
  a path that exists in the target images (`/etc` is a safe default), and a `<whodata><provider>ebpf</provider></whodata>`
  block — neither is present in the config this VM shipped with.
- `local_internal_options.conf`: `syscheck.debug=2` and `wazuh_modules.debug=2` were enabled for this
  pass and left in place.
- Test containers used: `docker exec my-nginx ...` for Docker; `kubectl run wazuh-fim-test`/
  `wazuh-fim-test2 --image=busybox` (both deleted after this pass) for a guaranteed-writable
  Kubernetes target, since both `coredns` (no shell) and `local-path-provisioner` (no shell) in the
  existing cluster could not be exercised directly.
- To retest a single-daemon restart without re-triggering the container_instances warm-up race
  (used to isolate finding #2): `sudo kill <wazuh-syscheckd pid>` then
  `sudo /var/ossec/bin/wazuh-syscheckd &` directly, rather than `wazuh-control restart` (which
  restarts every daemon, including `wazuh-modulesd`/`container_instances`, together).
