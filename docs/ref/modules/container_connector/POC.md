# Wazuh Agent Spike — Kubernetes Container Monitoring

## Summary

### Issue #36095 — Kubernetes & Docker Connector (container_connector module)

The `container_connector` module runs as a background thread on every node and maintains a live cache of container and pod metadata. For Kubernetes, it authenticates against the API server using a hybrid credential resolution strategy: explicit values in the `<kubernetes>` config block take precedence, and the in-cluster service account defaults (`ca.crt`, bearer token, `KUBERNETES_SERVICE_HOST`) are used as fallback. The bearer token is re-read from disk on every API call so that projected token rotations (default TTL 1 hour in Kubernetes >= 1.21) are handled transparently without a restart. For Docker, the connector accesses the daemon via Unix socket (`/var/run/docker.sock`), calling `GET /containers/json` followed by a per-container inspect to collect name, image, state, labels, and network settings. Both backends share the same poll-based refresh loop (configurable interval, default 60 s, with exponential backoff up to 300 s on failure) and expose their metadata through a single Unix-socket IPC server. The poll model was chosen for its simplicity and resilience; the Kubernetes Watch API was fully analyzed as a future drop-in replacement that would reduce detection latency from up to 5 s to under 100 ms and eliminate missed ephemeral containers, at the cost of `resourceVersion` state management and a reconnect loop. The entire implementation uses only libraries already bundled with Wazuh — OpenSSL and the in-tree libcurl wrapper — with no new dependencies.

### Issue #36101 — Kubernetes Container Log Collection via logcollector

Container log collection is built on direct file-tailing of the kubelet log directory rather than streaming through the Kubernetes API. The agent reads log content from `/var/log/pods/<ns>_<pod>_<uid>/<container>/<N>.log` on disk and queries the Kubernetes API only for enrichment metadata (image, labels, namespace). This is the same architecture used by Fluent Bit, Filebeat, and Vector, and is the only approach that supports exact byte-offset resume: the agent checkpoints each container by inode, byte offset, and last CRI timestamp, and on restart seeks directly to the saved position if the file and inode still match. When they do not — because kubelet rotated the file while the agent was down — a four-tier recovery ladder locates the checkpointed inode among the plain-rotated siblings, drains forward through any newer rotated files, and falls back to a gap marker with a warning if the files have been garbage-collected. The metadata and tail loops are deliberately decoupled: the `container_connector` module owns the API poll and the metadata cache, while the logcollector `read_kubernetes` reader owns filesystem scanning, CRI parsing, enrichment over IPC, and checkpointing. An API outage does not stop collection — tracked containers continue to be drained from the cache, and new containers are picked up from path-derived metadata with labels backfilled when the API returns. The acceptance criterion of zero loss and zero duplicates across a full agent restart was proven on a kind cluster for graceful restart, pod recreation, and a restart spanning a log rotation.

### Issue #36099 — FIM Path Resolution for Kubernetes Container Directories

File integrity monitoring inside containers is built on top of the existing Wazuh eBPF whodata pipeline. The eBPF hooks already intercept VFS-level file operations (create, modify, delete) on the host kernel. We extend the captured file_event struct to include `cgroup_id`. This is the inode of the container's cgroup directory under `/sys/fs/cgroup`, and it is the stable join key between a kernel event and a container identity: all processes belonging to the same container share the same cgroup, so cgroup_id uniquely identifies which container generated a given event. This mechanism works for both Docker containers and Kubernetes pods.

Mapping cgroup_id to container metadata is handled by the Container Connector, a background daemon that polls the Docker and Kubernetes APIs every 5 seconds depending on the configured runtime. On each poll it fetches the list of running containers or pods on the node and performs a single pass over `/proc/*/cgroup` to resolve each container's CRI ID to its cgroup inode via `stat()`. This builds a live `cgroup_id → container/pod metadata` cache. When an eBPF event arrives, the FIM pipeline queries this cache over a Unix socket: if the cgroup_id is known, the event is enriched with runtime-specific metadata — for Kubernetes this includes namespace, pod name, container name, image, and pod UID; for Docker it includes container name, image, and labels. From there, the existing FIM engine produces both stateless events (immediate whodata alerts for each CREATE, MODIFY, or DELETE) and stateful events (periodic scheduled scans that track the full file state and detect drift).

### Issue #36097 — eBPF Compatibility & Kernel Requirements for Kubernetes FIM

The minimum kernel version for the full Kubernetes FIM implementation can remain at 5.8, unchanged from the current floor. The existing LSM vs. kprobe fallback logic handles the most common gap: BPF LSM hooks are not active by default on Ubuntu or Debian even when the kernel supports them, so the kprobe path is the effective code path on most nodes. The practical consequence is that RHEL 8 (4.18) and Ubuntu 20.04 (5.4) fall below the minimum and are unsupported; Debian 11 (5.10), RHEL 9 (5.14), Ubuntu 22.04 (5.15) and Ubuntu 24.04 (6.8) are all functional with kprobes and ring buffer, provided AppArmor (Ubuntu) or SELinux (spc_t, RHEL) are configured to allow BPF syscalls in the DaemonSet.

The investigation also identified two hard constraints that are independent of kernel version. First, network-backed volumes (NFS, CephFS, remote CSI): eBPF hooks only capture writes that originate on the local node — remote writes are invisible at the VFS layer and cannot be intercepted without an agent on the server side. Second, cgroup v1 clusters (Kubernetes < 1.25, legacy Docker): bpf_get_current_cgroup_id() returns the cgroup v2 ID, which has no match in the cgroup v1 hierarchy, causing container identity lookups to fail silently. The userspace mapper needs explicit cgroup v1/v2 detection or these clusters must be documented as unsupported. On the performance side, kprobe/security_inode_setattr is always active regardless of LSM state and fires on every chmod/chown/utimes across all processes on the node — this needs profiling on high-density nodes before production deployment.
---

## POC

### Prerequisites

- Docker and `kind` installed on the VM.
- `kubectl` installed and on `$PATH`.
- `envsubst` available (`gettext` package on Ubuntu/Debian).
- A Wazuh agent installed at `/var/ossec` on the same VM.
- The repo checked out; all paths below are relative to the repo root.

---

### Step 1 — Create the host log directories

The kind worker node bind-mounts these paths from the VM host so that kubelet's pod logs are visible to the Wazuh agent running on the VM. The directories must exist before the cluster is created.

```bash
sudo mkdir -p /var/log/pods /var/log/containers
sudo chmod 755 /var/log/pods /var/log/containers
```

---

### Step 2 — Create the kind cluster

The cluster is defined by `kind-config.yaml`. It creates one control-plane node and one worker node with kubelet log rotation tuned small (1 MiB per file, 3 files) to make rotation scenarios easy to trigger, and mounts `/var/log/pods` and `/var/log/containers` from the host into the worker.

`src/wazuh_modules/container_connector/qa/kind/kind-config.yaml`:
```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: wazuh-spike
nodes:
  - role: control-plane
  - role: worker
    kubeadmConfigPatches:
      - |
        kind: KubeletConfiguration
        containerLogMaxSize: "1Mi"
        containerLogMaxFiles: 3
        maxPods: 150
    extraMounts:
      - hostPath: /var/log/pods
        containerPath: /var/log/pods
      - hostPath: /var/log/containers
        containerPath: /var/log/containers
```

Run `cluster-up.sh` to create the cluster, apply the `loadtest` namespace, and create the RBAC resources the agent needs to list pods:

```bash
./src/wazuh_modules/container_connector/qa/kind/scripts/cluster-up.sh
```

The script is idempotent — safe to re-run. To also deploy the log generator immediately, add `--with-gen`:

```bash
./src/wazuh_modules/container_connector/qa/kind/scripts/cluster-up.sh --with-gen
```

Verify the cluster is healthy:

```bash
kubectl get nodes
# NAME                        STATUS   ROLES           AGE
# wazuh-spike-control-plane   Ready    control-plane   ...
# wazuh-spike-worker          Ready    <none>          ...
```

---

### Step 3 — Deploy log generators

The seqgen deployment runs N pods, each emitting sequenced lines at a fixed rate. This format is designed so `verify-sequences.py` can detect gaps and duplicates later.

Each line has the format:
```
SEQ <pod-name> <counter> <epoch.millis> [padding]
```

`src/wazuh_modules/container_connector/qa/kind/manifests/seqgen.yaml`:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${SEQGEN_NAME}
  namespace: loadtest
spec:
  replicas: ${SEQGEN_REPLICAS}
  selector:
    matchLabels:
      app: ${SEQGEN_NAME}
  template:
    metadata:
      labels:
        app: ${SEQGEN_NAME}
        role: seqgen
    spec:
      terminationGracePeriodSeconds: 1
      containers:
        - name: gen
          image: python:3.12-alpine
          imagePullPolicy: IfNotPresent
          env:
            - name: POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: RATE
              value: "${SEQGEN_RATE}"
            - name: PAD
              value: "${SEQGEN_PAD}"
          command: ["python3", "-u", "-c"]
          args:
            - |
              import os, time
              rate = float(os.environ.get("RATE", "5"))
              pad = int(os.environ.get("PAD", "0"))
              pod = os.environ.get("POD_NAME", "unknown")
              padding = "x" * pad
              i = 0
              interval = 1.0 / rate
              next_t = time.monotonic()
              while True:
                  print(f"SEQ {pod} {i} {time.time():.3f} {padding}", flush=True)
                  i += 1
                  next_t += interval
                  delay = next_t - time.monotonic()
                  if delay > 0:
                      time.sleep(delay)
          resources:
            requests:
              cpu: 10m
              memory: 16Mi
```

Deploy 3 pods at 5 lines/s (skip this if you used `--with-gen` above):

```bash
SEQGEN_NAME=seqgen SEQGEN_REPLICAS=3 SEQGEN_RATE=5 SEQGEN_PAD=0 \
  envsubst < src/wazuh_modules/container_connector/qa/kind/manifests/seqgen.yaml \
  | kubectl apply -f -

kubectl -n loadtest rollout status deploy/seqgen --timeout=120s
kubectl -n loadtest get pods -o wide
```

Verify logs are being written to the host:

```bash
ls /var/log/pods/loadtest_seqgen*/gen/
# 0.log
```

---

### Step 4 — Extract credentials

The agent needs a bearer token for the `wazuh-agent` service account (created by `cluster-up.sh` via the RBAC manifest) and the cluster CA certificate to verify the API server TLS certificate.

The token created here is short-lived (24 hours). Re-run this command and restart the agent before it expires.

```bash
# Bearer token
kubectl -n wazuh create token wazuh-agent --duration=24h \
  | sudo tee /var/ossec/etc/k8s-token > /dev/null

# CA certificate
kubectl config view --raw \
  -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' \
  | base64 -d | sudo tee /var/ossec/etc/k8s-ca.crt > /dev/null

# Permissions
sudo chmod 640 /var/ossec/etc/k8s-ca.crt /var/ossec/etc/k8s-token
sudo chown root:wazuh /var/ossec/etc/k8s-ca.crt /var/ossec/etc/k8s-token
```

Get the values needed for the agent config:

```bash
# API server address
kubectl cluster-info | grep "control plane"
# Kubernetes control plane is running at https://127.0.0.1:43669

# Node name of the worker (must match exactly)
kubectl get nodes
# wazuh-spike-worker
```

---

## Testing the Logcollector Module

### Step 5 — Configure the Wazuh agent

Add the following blocks to `/var/ossec/etc/ossec.conf`. Replace `<api_server>` and `<node_name>` with the values from the previous step.

```xml
<container_connector>
  <kubernetes>
    <enabled>yes</enabled>
    <api_server>https://127.0.0.1:43669</api_server>
    <ca_bundle>/var/ossec/etc/k8s-ca.crt</ca_bundle>
    <token_path>/var/ossec/etc/k8s-token</token_path>
    <node_name>wazuh-spike-worker</node_name>
    <poll_interval>5</poll_interval>
  </kubernetes>
</container_connector>

<localfile>
  <log_format>container</log_format>
  <location>kubernetes</location>
  <filter field="namespace">loadtest</filter>
</localfile>
```

The `<filter>` tag is optional. Remove it to collect logs from every namespace, or filter by other fields: `pod_name`, `container_name`, `image_name`, or `labels`.

Restart the agent to apply the configuration:

```bash
sudo /var/ossec/bin/wazuh-control restart
```

---

### Step 6 — Verify

**Agent logs** — the connector should enumerate the pods on the worker node and the logcollector should start tailing:

```bash
sudo tail -f /var/ossec/logs/ossec.log | grep -E "container-connector|kubernetes|localfile"
```

Expected output:

```
2026/06/24 12:59:49 wazuh-modulesd:container-connector: INFO: Starting Kubernetes connector. node_name='wazuh-spike-worker'.
2026/06/24 12:59:49 wazuh-modulesd:container-connector: INFO: PodWatcher started (polling every 5s; exponential backoff up to 300s on errors).
2026/06/24 12:59:49 wazuh-modulesd:container-connector: INFO: K8s client config resolved: api_server='https://127.0.0.1:43669', ca_bundle='/var/ossec/etc/k8s-ca.crt', token_path='/var/ossec/etc/k8s-token', node_name='wazuh-spike-worker'.
2026/06/24 12:59:49 wazuh-modulesd:container-connector: INFO: IpcServer listening on '/var/ossec/queue/sockets/container_connector'.
2026/06/24 12:59:49 wazuh-modulesd:container-connector: DEBUG: K8s pod: ns='loadtest' name='seqgen-567f64dd45-44w95' uid=28452810-... containers=1 owners=[ReplicaSet/seqgen-567f64dd45]
2026/06/24 12:59:49 wazuh-modulesd:container-connector: DEBUG:   container: name='gen' image='docker.io/library/python:3.12-alpine' id=3628321f9760 restarts=0 cgroup=32909
2026/06/24 12:59:49 wazuh-modulesd:container-connector: INFO: K8s snapshot synced: 5 pod(s), 5 container(s).
```

**Events in the Wazuh dashboard** — events arrive under the `wazuh-events-v5-unclassified` index with full Kubernetes enrichment in `event.original`:

```json
{
  "_index": ".ds-wazuh-events-v5-unclassified-000001",
  "_source": {
    "wazuh": {
      "protocol": { "queue": 49, "location": "gen" },
      "agent": {
        "id": "001",
        "name": "ubuntu-VirtualBox",
        "version": "v5.0.0"
      }
    },
    "event": {
      "original": "{\"collector\":\"logcollector\",\"module\":\"kubernetes\",\"data\":{\"log_line\":\"SEQ seqgen-567f64dd45-fjsp6 32534 1782322043.597 \",\"stream\":\"stdout\",\"timestamp\":\"2026-06-24T17:27:23.597375679Z\",\"kubernetes\":{\"namespace\":\"loadtest\",\"pod_name\":\"seqgen-567f64dd45-fjsp6\",\"pod_uid\":\"bd3ab5ef-9c6d-4fb4-b054-9e0386e113ea\",\"container_name\":\"gen\",\"container_id\":\"60ccadb430ee...\",\"image\":\"docker.io/library/python:3.12-alpine\"}}}"
    },
    "@timestamp": "2026-06-24T17:27:24.030Z"
  }
}
```

Each event carries the original log line plus the Kubernetes context resolved by the connector: namespace, pod name, pod UID, container name, container ID, and image.


---

## Testing the FIM Module

### Step 5 — Build the eBPF kernel object

The installed `modern.bpf.o` shipped with the agent may have been compiled against an older kernel and will be missing the `lsm/file_open` and `lsm/path_unlink` programs. Verify and rebuild if needed.

```bash
# Check which programs are in the installed object
sudo readelf -S /var/ossec/lib/modern.bpf.o | grep -E "kprobe|lsm"
```

If `lsm/file_open` and `lsm/path_unlink` are missing from the output, recompile from source:

```bash
WAZUH_SRC=/path/to/wazuh/src
EBPF_SRC=$WAZUH_SRC/syscheckd/src/ebpf/src
LIBBPF=$WAZUH_SRC/external/libbpf-bootstrap

clang -g -O2 -target bpf \
  -D__TARGET_ARCH_x86 \
  -I$LIBBPF/vmlinux.h/include/x86 \
  -I$LIBBPF/libbpf/src \
  -I$LIBBPF/build/libbpf/bpf \
  -c $EBPF_SRC/modern.bpf.c -o /tmp/modern.bpf.o

# Verify all 5 programs are present
readelf -S /tmp/modern.bpf.o | grep -E "kprobe|lsm"

sudo cp /tmp/modern.bpf.o /var/ossec/lib/modern.bpf.o
```

> **VM note:** On VirtualBox VMs, BPF LSM is detected as active but the shipped `.bpf.o` may be compiled for a different kernel. The symptom is the healthcheck timing out or failing to create its test file. Rebuilding for the running kernel (as above) resolves it. Confirm with `uname -r` and check that `/sys/kernel/btf/vmlinux` exists.

Also create the monitored directory on the host:

```bash
sudo mkdir -p /home/test
```

---

### Step 6 — Configure the Wazuh agent

The `container_connector` block is the same as for the logcollector test. Add or extend the `<syscheck>` block in `/var/ossec/etc/ossec.conf`:

```xml
<container_connector>
  <kubernetes>
    <enabled>yes</enabled>
    <api_server>https://127.0.0.1:43669</api_server>
    <ca_bundle>/var/ossec/etc/k8s-ca.crt</ca_bundle>
    <token_path>/var/ossec/etc/k8s-token</token_path>
    <node_name>wazuh-spike-worker</node_name>
    <poll_interval>5</poll_interval>
  </kubernetes>
</container_connector>

<syscheck>
  <whodata>
    <startup_healthcheck>yes</startup_healthcheck>
    <provider>ebpf</provider>
  </whodata>
  <directories type="kubernetes" whodata="yes">/home/test</directories>
</syscheck>
```

Restart the agent:

```bash
sudo /var/ossec/bin/wazuh-control restart
```

Confirm eBPF initialized correctly — all 5 programs must appear and the healthcheck must pass:

```bash
sudo strings /var/ossec/logs/ossec.log \
  | grep -E "autoload|6047|6048|6049|6051|file_open|path_unlink" | tail -10
```

Expected:
```
INFO: (6047): Initializing eBPF driver for FIM whodata.
INFO: (6051): BPF LSM is active in the running kernel; using LSM hooks for create/modify/delete events.
DEBUG: eBPF program 'kprobe__vfs_open' (kprobe/vfs_open): autoload=false
DEBUG: eBPF program 'kprobe__security_inode_setattr' (kprobe/security_inode_setattr): autoload=true
DEBUG: eBPF program 'kprobe__vfs_unlink' (kprobe/vfs_unlink): autoload=false
DEBUG: eBPF program 'file_open' (lsm/file_open): autoload=true
DEBUG: eBPF program 'path_unlink' (lsm/path_unlink): autoload=true
INFO: (6049): eBPF healthcheck action succeeded: create file.
INFO: (6049): eBPF healthcheck action succeeded: modify content.
INFO: (6049): eBPF healthcheck action succeeded: modify metadata.
INFO: (6049): eBPF healthcheck action succeeded: delete file.
INFO: (6048): Healthcheck for eBPF FIM whodata module success.
```

---

### Step 7 — Generate events from a container cgroup

FIM events with Kubernetes enrichment require the file operation to originate from a container's cgroup. Since kind runs pod processes directly on the host kernel, you can simulate this by temporarily moving a shell into a seqgen pod's cgroup.

```bash
# Find a seqgen pod's PID as seen from the host VM
SEQGEN_PID=$(ps aux | grep "python3 -u -c" | grep -v grep | awk 'NR==1{print $2}')
echo "Seqgen PID: $SEQGEN_PID"

# Get its cgroup path (cgroupv2)
CGROUP_PATH=$(cat /proc/$SEQGEN_PID/cgroup | grep "^0::" | cut -d: -f3)
echo "Container cgroup: $CGROUP_PATH"

# Move current shell into the container's cgroup
echo $$ | sudo tee /sys/fs/cgroup${CGROUP_PATH}/cgroup.procs

# Create/modify/delete files — eBPF captures them with the container's cgroup_id,
# which the connector resolves to pod metadata
touch /home/test/from-pod.txt
echo "hello from pod" >> /home/test/from-pod.txt
rm /home/test/from-pod.txt

# Move back to the user session cgroup
echo $$ | sudo tee /sys/fs/cgroup/user.slice/user-$(id -u).slice/session-$(cat /proc/self/sessionid 2>/dev/null || echo 1).scope/cgroup.procs 2>/dev/null || true
```

> Files created from the host without joining a container cgroup will not produce enriched FIM events — the `type="kubernetes"` attribute causes the pipeline to drop events whose `cgroup_id` does not resolve to a known pod.

---

### Step 8 — Verify

**Agent logs** — watch for the FIM event being sent:

```bash
sudo tail -f /var/ossec/logs/ossec.log | grep -E "FIM event|6321|whodata"
```

Expected:

```
2026/06/24 18:10:32 wazuh-syscheckd[220439] run_check.c:332 at send_syscheck_msg(): INFO: (6321): Sending FIM event: {"collector":"file","module":"fim","data":{"event":{"created":"2026-06-24T21:10:32.838Z","type":"added"},"file":{"path":"k8s://loadtest/seqgen-567f64dd45-4n9fd/gen/home/test/from-pod.txt","mode":"whodata","kubernetes":{"namespace":"loadtest","pod_name":"seqgen-567f64dd45-4n9fd","pod_uid":"018e1034-df8a-4528-8c57-3e03a94e6556","container_name":"gen","container_id":"ca727619179d...","image":"docker.io/library/python:3.12-alpine"},"audit":{"process_name":"touch","user_id":"1000","user_name":"ubuntu","process_id":228317,"ppid":3974,"parent_name":"bash"}}}}
```

The file path is prefixed with `k8s://<namespace>/<pod_name>/<container_name>/` followed by the actual host path, making the container origin explicit.

**Events in the Wazuh dashboard** — events arrive under the `wazuh-events-v5*` index with full Kubernetes enrichment in `event.original`:

```json
{
  "_index": ".ds-wazuh-events-v5-system-activity-000001",
  "_id": "jrR4-54ByZTVCOm5cS48",
  "_version": 1,
  "_score": null,
  "_source": {
    "wazuh": {
      "protocol": {
        "queue": 56,
        "location": "syscheck"
      },
      "agent": {
        "host": {
          "os": {
            "name": "Ubuntu",
            "version": "24.04.4 LTS (Noble Numbat)",
            "platform": "ubuntu",
            "type": "linux"
          },
          "architecture": "x86_64",
          "hostname": "ubuntu-VirtualBox"
        },
        "id": "001",
        "name": "ubuntu-VirtualBox",
        "version": "v5.0.0",
        "groups": [
          "default"
        ]
      },
      "cluster": {
        "name": "wazuh",
        "node": "node01"
      },
      "event": {
        "id": "d6b34d09-7ebc-4553-b34a-6b50136d7244"
      },
      "integration": {
        "category": "system-activity",
        "name": "wazuh-fim",
        "decoders": [
          "decoder/core-wazuh-message/0",
          "decoder/wazuh-fim/0"
        ]
      },
      "space": {
        "name": "standard"
      }
    },
    "event": {
      "original": "{\"collector\":\"file\",\"module\":\"fim\",\"data\":{\"event\":{\"created\":\"2026-06-24T21:10:32.838Z\",\"type\":\"added\"},\"file\":{\"path\":\"k8s://loadtest/seqgen-567f64dd45-4n9fd/gen/home/test/probe.txt\",\"mode\":\"whodata\",\"kubernetes\":{\"namespace\":\"loadtest\",\"pod_name\":\"seqgen-567f64dd45-4n9fd\",\"pod_uid\":\"018e1034-df8a-4528-8c57-3e03a94e6556\",\"container_name\":\"gen\",\"container_id\":\"ca727619179d8763f2a5e94b41c1692b347dc8db13d8782b3cd65bb225dce80f\",\"image\":\"docker.io/library/python:3.12-alpine\"},\"audit\":{\"process_name\":\"rm\",\"user_id\":\"1000\",\"user_name\":\"ubuntu\",\"group_id\":\"1000\",\"group_name\":\"ubuntu\",\"process_id\":228317,\"ppid\":3974,\"parent_name\":\"bash\"}}}}",
      "category": [
        "file"
      ],
      "dataset": "wazuh.fim",
      "kind": "event",
      "action": "created",
      "type": [
        "creation"
      ],
      "outcome": "success"
    },
    "@timestamp": "2026-06-24T21:10:32.840Z",
    "data_stream": {
      "dataset": "wazuh.fim",
      "type": "logs"
    },
    "file": {
      "mode": "whodata",
      "path": "k8s://loadtest/seqgen-567f64dd45-4n9fd/gen/home/test/probe.txt",
      "extension": "txt",
      "directory": "k8s://loadtest/seqgen-567f64dd45-4n9fd/gen/home/test"
    },
    "process": {
      "name": "rm",
      "parent": {
        "name": "bash",
        "pid": 3974
      },
      "pid": 228317
    },
    "user": {
      "group": {
        "id": "1000",
        "name": "ubuntu"
      },
      "id": "1000",
      "name": "ubuntu"
    },
    "related": {
      "user": [
        "ubuntu",
        "ubuntu"
      ]
    }
  },
  "fields": {
    "@timestamp": [
      "2026-06-24T21:10:32.840Z"
    ]
  },
  "sort": [
    1782335432840
  ]
}
```


---

### Teardown

```bash
kind delete cluster --name wazuh-spike
sudo rm -rf /var/log/pods /var/log/containers
```
