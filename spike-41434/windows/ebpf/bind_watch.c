// Spike #41434: minimal bind hook for eBPF for Windows.
#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);   /* port */
    __type(value, uint64_t); /* (pid << 8) | protocol */
    __uint(max_entries, 8192);
} binds SEC(".maps");

SEC("bind")
bind_action_t on_bind(bind_md_t* ctx)
{
    if (ctx->operation == BIND_OPERATION_BIND)
    {
        uint32_t port = ((uint32_t)ctx->socket_address[2] << 8) | ctx->socket_address[3];
        uint64_t v = (ctx->process_id << 8) | ctx->protocol;
        bpf_map_update_elem(&binds, &port, &v, 0);
    }
    return BIND_PERMIT_SOFT;
}
