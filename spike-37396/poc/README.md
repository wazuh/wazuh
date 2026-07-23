# PoC — single BPF object, LSM+kprobe, user-space selection (#37396)

Throwaway PoC. It demonstrates the load/attach mechanics that hold **under either module boundary**: **one** BPF object carrying both `lsm/file_open` and `kprobe/vfs_open`, a user-space loader that **selects the right variant** for the running kernel, **attaches** it, and **emits** events with the **full path** and a raw **`cgroup_id`** correlation key. A portable exec probe covers the second event class.

> **Boundary note (ADR-001 = option (b)):** the chosen architecture is per-module — each module links the eBPF library and consumes **its own** stream; there is **no central provider and no cross-module fan-out**. This PoC happens to run two mock consumers (`fim`, `syscollector`) in one process, which was shaped for the earlier (a) premise. What that still validates for (b): (1) a single object carries both attach variants and the loader picks one per kernel — exactly what each module's own loader does; (2) full-path reconstruction lets a module filter its own stream by path prefix; (3) `cgroup_id` == cgroupfs `st_ino`; (4) drop-on-full backpressure inside a consume loop. What it does **not** demonstrate as an architectural need any more: multi-consumer fan-out over one shared stream — under (b) each module has its own stream, so the two-consumer sim is an illustration of filtering + backpressure mechanics, not of the shipping design.

## Files
- `file_open.bpf.c` — one program family, two SECs (`lsm/file_open` modern, `kprobe/vfs_open` fallback), one `BPF_MAP_TYPE_RINGBUF`. Emits `{pid, cgroup_id, path}`.
- `exec_probe.bpf.c` / `exec_probe.c` — `tracepoint/sched_process_exec` (most portable class; reference for the new event classes). Emits `{pid, ppid, cgroup_id, comm}`.
- `fanout.h` / `fanout.c` — a small bounded-queue + filter + drop-on-full core (producer never blocks). Under (b) this maps to a single module's own consume loop (queue, path-prefix filter, drop accounting); the PoC just instantiates two of them in one process to show the mechanics side by side.
- `dispatcher.c` — wires either the real ringbuf (`run_bpf`) or a synthetic feeder (`run_sim`) into that core. Two mock consumers: `fim` (prefix `/etc`, slow 5 ms/ev) and `syscollector` (all paths, fast). Raises `RLIMIT_MEMLOCK` before load (required on 5.10-class kernels).
- `Makefile` — `make sim` (no deps) / `make bpf` (clang+libbpf+bpftool+BTF) / `make exec`.

## On real kernels — MEASURED (see ../07-vm-validation-evidence.md)

Run on fresh VMs across 4.18-el8 → 6.8. Both attach paths and the exec tracepoint were exercised; raw captures are in `../evidence_<vm>.txt`.

```
# auto-detect (uses lsm/file_open if bpf is in the active LSM list, else kprobe):
make bpf && sudo ./poc_bpf
sudo ./poc_bpf --kprobe          # force the kprobe fallback
# in another shell: touch /etc/poc_test /tmp/poc_test

make exec && sudo ./exec_probe   # tracepoint/sched_process_exec
```

Representative on-kernel result (AlmaLinux 9.7, 5.14-el9):
```
attach strategy: lsm/file_open   → produced: 5, syscollector delivered=5
attach strategy: kprobe/vfs_open → produced: 5, syscollector delivered=5
EXEC pid=... cgroup_id=4829 comm=echo      ; stat -c %i .../spike37396.test = 4829  (cgroup_id==st_ino)
```

**Proven on-kernel:** the single `.o` carries both SECs; the loader autoloads exactly one based on `/sys/kernel/security/lsm`; both attach and emit real events; exec tracepoint attaches and emits; `cgroup_id`==cgroupfs `st_ino` on cgroup v2 (host, non-container use → the correlation key works with real values).

## Path-prefix filtering on real kernels — DONE

The PoC emits the **full absolute path** (`bpf_d_path` in the LSM variant, the production dentry walker in the kprobe variant), so path-prefix filtering works on-kernel. Measured on AlmaLinux 9.7 (5.14-el9), both attach paths:
```
lsm/file_open:   produced=5, fim delivered=2 (/etc only), syscollector delivered=5
kprobe/vfs_open: produced=5, fim delivered=2 (/etc only), syscollector delivered=5
```
`fim` (prefix `/etc`) sees only `/etc/*`; the unfiltered consumer sees everything. Under (b) the relevant reading is per-module: **a module can filter its own stream by path prefix on both attach paths** — which is what FIM would do. (In the earlier (a) framing this was "two distinct filters over one shared stream"; that shared-stream reading no longer matches the architecture — see the boundary note above and ADR-001 OQ-5 on acceptance criterion 5.) See `../07-vm-validation-evidence.md §3.5`.

The sim run illustrates the intra-consume-loop backpressure a single module needs:
```
$ make sim && ./poc_sim --sim
produced: 30000
  consumer 'fim':          delivered=717   dropped=13318  (slow, prefix /etc ≈ 50% of stream)
  consumer 'syscollector': delivered=30000 dropped=0      (fast, never stalled by the slow one)
```
Reading it per-module: a slow consume loop drops into its own bounded queue (drop-on-full, visible count) while the poll thread never blocks; `cgroup_id` (incl. `0`=host) rides every event.

## Scope / honesty
- **Throwaway** PoC for the attach-path + selection + full-path + correlation-key claims. It is NOT the contract's full flat layout (`03-`) and the network class is design-only. There is **no IPC** to demonstrate — under (b) consumption is in-process per module.
- The two-consumers-in-one-process shape predates the (b) decision; it is retained as a mechanics illustration, not as the shipping architecture (per-module, separate processes).
- BPF mode was executed on real kernels (6.8, 5.14-el9, 4.18-el8, 5.10) incl. a real Docker container; it was NOT run in the spike's own WSL2 environment (no attach there) — only the sim core runs there.
