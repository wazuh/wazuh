// Spike #41434: minimal process hook for eBPF for Windows + ntosebpfext.
#include "bpf_helpers.h"
#include "ebpf_ntos_hooks.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint64_t); /* parent pid */
    __uint(max_entries, 8192);
} proc_create SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, uint64_t); /* exit code */
    __uint(max_entries, 8192);
} proc_exit SEC(".maps");

SEC("process")
int on_process(process_md_t* ctx)
{
    uint32_t pid = (uint32_t)ctx->process_id;
    if (ctx->operation == PROCESS_OPERATION_CREATE)
    {
        uint64_t v = ctx->parent_process_id;
        bpf_map_update_elem(&proc_create, &pid, &v, 0);
    }
    else
    {
        uint64_t v = ctx->process_exit_code;
        bpf_map_update_elem(&proc_exit, &pid, &v, 0);
    }
    return 0;
}
