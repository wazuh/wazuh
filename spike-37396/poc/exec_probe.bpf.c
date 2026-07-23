/* spike #37396 — exec probe: tracepoint/sched_process_exec (most portable class). */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct exec_event { __u32 pid; __u32 ppid; __u64 cgroup_id; char comm[16]; };
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1<<20); } erb SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(void *ctx) {
    struct exec_event *e = bpf_ringbuf_reserve(&erb, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(t, real_parent, tgid);
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
