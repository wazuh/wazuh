/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * eBPF Module (#37396) engine — load/attach/select/poll logic extracted
 * from src/syscheckd/src/ebpf/src/ebpf_whodata.cpp and generalized: no FIM
 * types, no callback-registration singleton, no fixed hook set. A caller
 * gets exactly the programs its rt_filter asks for.
 *
 * Simplification made for this validation build, called out explicitly
 * rather than left implicit: production ebpf_whodata.cpp dlopen()s libbpf
 * at runtime so the agent can ship without a hard link-time dependency on
 * platforms without eBPF support. This engine links libbpf directly
 * (`-lbpf`) instead, matching spike #37396's own PoC — the dlopen
 * indirection is a real, separate concern for the "integrate into
 * syscheckd" step, not part of proving the engine's architecture.
 *
 * Also simplified: no dedicated pre-flight ringbuf-creation probe (spike
 * #37396 ADR-002 recommends one instead of a numeric kernel-version gate).
 * Here, attempting bpf_object__load() IS the capability probe — if
 * BPF_MAP_TYPE_RINGBUF or BTF/CO-RE isn't supported, the load simply fails
 * and rt_open() returns NULL. A dedicated probe would give a clearer error
 * message per missing feature; that refinement is deferred.
 */

#include "rt_engine.h"

#include <bpf/libbpf.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BPF_OBJ_PATH "rt_file.bpf.o"
#define LSM_LIST_FILE "/sys/kernel/security/lsm"

struct rt_engine_handle
{
    struct bpf_object* obj;
    struct ring_buffer* rb;
    rt_sink_fn current_sink;
    void* current_user;
};

static int is_bpf_lsm_active(void)
{
    FILE* f = fopen(LSM_LIST_FILE, "r");
    if (!f)
    {
        return 0;
    }
    char line[512] = {0};
    int active = 0;
    if (fgets(line, sizeof(line), f))
    {
        char* tok = strtok(line, ",\n");
        while (tok)
        {
            if (strcmp(tok, "bpf") == 0)
            {
                active = 1;
                break;
            }
            tok = strtok(NULL, ",\n");
        }
    }
    fclose(f);
    return active;
}

/* Maps a BPF program's section name to the rt_event_type bit it serves, so
 * filter->type_mask alone decides what gets autoloaded — no per-consumer
 * branching in this function. */
static unsigned int type_bit_for_section(const char* sec)
{
    if (strstr(sec, "vfs_open") || strcmp(sec, "lsm/file_open") == 0)
    {
        return RT_FILE_OPEN_BIT;
    }
    if (strstr(sec, "setattr"))
    {
        return RT_FILE_ATTR_BIT;
    }
    if (strstr(sec, "vfs_unlink"))
    {
        return RT_FILE_UNLINK_BIT;
    }
    if (strstr(sec, "vfs_rename"))
    {
        return RT_FILE_RENAME_BIT;
    }
    return 0;
}

static void select_programs(struct bpf_object* obj, unsigned int type_mask, int prefer_lsm)
{
    struct bpf_program* prog;
    bpf_object__for_each_program(prog, obj)
    {
        const char* sec = bpf_program__section_name(prog);
        const char* name = bpf_program__name(prog);
        int keep = 0;

        if (sec && (type_bit_for_section(sec) & type_mask))
        {
            keep = 1;

            /* Both file_open variants match RT_FILE_OPEN_BIT; keep only the
             * one matching this run's LSM-activity probe. */
            int is_lsm_variant = (strcmp(sec, "lsm/file_open") == 0);
            int is_kprobe_open_variant = (strstr(sec, "kprobe/vfs_open") != NULL);
            if (is_lsm_variant && !prefer_lsm)
            {
                keep = 0;
            }
            if (is_kprobe_open_variant && prefer_lsm)
            {
                keep = 0;
            }
        }

        bpf_program__set_autoload(prog, keep);
        fprintf(stderr, "[rt_engine] program '%s' (%s): autoload=%s\n", name ? name : "?", sec ? sec : "?",
                keep ? "true" : "false");
    }
}

static int ringbuf_sample_cb(void* ctx, void* data, size_t size)
{
    (void)size;
    struct rt_engine_handle* h = (struct rt_engine_handle*)ctx;
    if (h->current_sink && data)
    {
        h->current_sink((const struct rt_file_event*)data, h->current_user);
    }
    return 0;
}

rt_handle_t rt_open(const struct rt_filter* filter)
{
    if (!filter || (filter->type_mask & RT_FILE_ALL_BITS) == 0)
    {
        fprintf(stderr, "[rt_engine] rt_open: empty/invalid filter\n");
        return NULL;
    }

    struct rt_engine_handle* h = calloc(1, sizeof(*h));
    if (!h)
    {
        return NULL;
    }

    h->obj = bpf_object__open_file(BPF_OBJ_PATH, NULL);
    if (!h->obj)
    {
        fprintf(stderr, "[rt_engine] failed to open %s\n", BPF_OBJ_PATH);
        free(h);
        return NULL;
    }

    const int prefer_lsm = is_bpf_lsm_active();
    fprintf(stderr, "[rt_engine] active LSM list %s \"bpf\" -> preferring %s file_open variant\n",
            prefer_lsm ? "includes" : "does not include", prefer_lsm ? "LSM" : "kprobe");
    select_programs(h->obj, filter->type_mask, prefer_lsm);

    if (bpf_object__load(h->obj))
    {
        fprintf(stderr, "[rt_engine] bpf_object__load failed (capability probe failed — missing "
                        "ringbuf/BTF/CO-RE support, or insufficient privilege)\n");
        bpf_object__close(h->obj);
        free(h);
        return NULL;
    }

    struct bpf_program* prog;
    bpf_object__for_each_program(prog, h->obj)
    {
        if (!bpf_program__autoload(prog))
        {
            continue;
        }
        struct bpf_link* link = bpf_program__attach(prog);
        if (!link)
        {
            fprintf(stderr, "[rt_engine] failed to attach '%s'\n", bpf_program__name(prog));
            bpf_object__close(h->obj);
            free(h);
            return NULL;
        }
    }

    int rb_fd = bpf_object__find_map_fd_by_name(h->obj, "rb");
    if (rb_fd < 0)
    {
        fprintf(stderr, "[rt_engine] ring buffer map 'rb' not found\n");
        bpf_object__close(h->obj);
        free(h);
        return NULL;
    }

    h->rb = ring_buffer__new(rb_fd, ringbuf_sample_cb, h, NULL);
    if (!h->rb)
    {
        fprintf(stderr, "[rt_engine] ring_buffer__new failed\n");
        bpf_object__close(h->obj);
        free(h);
        return NULL;
    }

    return (rt_handle_t)h;
}

int rt_poll(rt_handle_t handle, rt_sink_fn sink, void* user, int timeout_ms)
{
    struct rt_engine_handle* h = (struct rt_engine_handle*)handle;
    if (!h)
    {
        return -1;
    }
    h->current_sink = sink;
    h->current_user = user;
    return ring_buffer__poll(h->rb, timeout_ms);
}

void rt_close(rt_handle_t handle)
{
    struct rt_engine_handle* h = (struct rt_engine_handle*)handle;
    if (!h)
    {
        return;
    }
    if (h->rb)
    {
        ring_buffer__free(h->rb);
    }
    if (h->obj)
    {
        bpf_object__close(h->obj);
    }
    free(h);
}
