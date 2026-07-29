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
 * libbpf is loaded via dlopen() at rt_open() time, not linked at build time
 * (no `-lbpf` anywhere in this file or its CMake target): fimebpf.so is
 * hard-linked into wazuh-syscheckd (see src/syscheckd/CMakeLists.txt), so a
 * build-time libbpf dependency here would make the whole agent binary
 * refuse to start on any host without libbpf installed. Mirrors the same
 * reasoning already documented in ebpf_whodata.cpp's init_libbpf(). This
 * engine resolves the SYSTEM libbpf.so via soname; production's actual
 * cutover should instead resolve the same Wazuh-bundled relative path
 * ebpf_whodata.cpp's so__get_module_handle(LIB_INSTALL_PATH) already uses,
 * which isn't reachable from here without pulling in syscheckd's abspath()
 * helper — a real follow-up once this is actually linked into fimebpf,
 * called out rather than silently left as a system-libbpf assumption.
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
#include <dlfcn.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BPF_OBJ_PATH_FALLBACK "rt_file.bpf.o"
#define LSM_LIST_FILE "/sys/kernel/security/lsm"
#define LIBBPF_SONAME_PRIMARY "libbpf.so.1"
#define LIBBPF_SONAME_FALLBACK "libbpf.so"

/* Function-pointer table for every libbpf entry point this engine needs,
 * resolved via dlsym() once per process. Mirrors bpf_helpers.h's
 * w_bpf_helpers_t dispatch-table pattern (same reason: late-bound, so a
 * missing libbpf.so doesn't stop the containing .so from loading). */
struct libbpf_api
{
    void* module;
    struct bpf_object* (*open_file)(const char*, const struct bpf_object_open_opts*);
    int (*load)(struct bpf_object*);
    void (*close_obj)(struct bpf_object*);
    struct bpf_program* (*next_program)(const struct bpf_object*, struct bpf_program*);
    const char* (*section_name)(const struct bpf_program*);
    const char* (*prog_name)(const struct bpf_program*);
    int (*set_autoload)(struct bpf_program*, bool);
    bool (*autoload)(const struct bpf_program*);
    struct bpf_link* (*attach)(struct bpf_program*);
    int (*find_map_fd_by_name)(struct bpf_object*, const char*);
    struct ring_buffer* (*rb_new)(int, ring_buffer_sample_fn, void*, const struct ring_buffer_opts*);
    int (*rb_poll)(struct ring_buffer*, int);
    void (*rb_free)(struct ring_buffer*);
};

static struct libbpf_api g_libbpf;
static int g_libbpf_resolved = 0; /* 0 = not attempted, 1 = attempted (see g_libbpf.module for outcome) */

#define RT_RESOLVE_SYM(field, sym)                                                                                   \
    do                                                                                                               \
    {                                                                                                                \
        *(void**)(&g_libbpf.field) = dlsym(mod, sym);                                                               \
        if (!g_libbpf.field)                                                                                         \
        {                                                                                                            \
            fprintf(stderr, "[rt_engine] libbpf missing symbol '%s'\n", sym);                                        \
            dlclose(mod);                                                                                           \
            return 0;                                                                                               \
        }                                                                                                            \
    } while (0)

static int ensure_libbpf_loaded(void)
{
    if (g_libbpf_resolved)
    {
        return g_libbpf.module != NULL;
    }
    g_libbpf_resolved = 1;

    void* mod = dlopen(LIBBPF_SONAME_PRIMARY, RTLD_NOW);
    if (!mod)
    {
        mod = dlopen(LIBBPF_SONAME_FALLBACK, RTLD_NOW);
    }
    if (!mod)
    {
        fprintf(stderr, "[rt_engine] dlopen(libbpf) failed: %s\n", dlerror());
        return 0;
    }

    RT_RESOLVE_SYM(open_file, "bpf_object__open_file");
    RT_RESOLVE_SYM(load, "bpf_object__load");
    RT_RESOLVE_SYM(close_obj, "bpf_object__close");
    RT_RESOLVE_SYM(next_program, "bpf_object__next_program");
    RT_RESOLVE_SYM(section_name, "bpf_program__section_name");
    RT_RESOLVE_SYM(prog_name, "bpf_program__name");
    RT_RESOLVE_SYM(set_autoload, "bpf_program__set_autoload");
    RT_RESOLVE_SYM(autoload, "bpf_program__autoload");
    RT_RESOLVE_SYM(attach, "bpf_program__attach");
    RT_RESOLVE_SYM(find_map_fd_by_name, "bpf_object__find_map_fd_by_name");
    RT_RESOLVE_SYM(rb_new, "ring_buffer__new");
    RT_RESOLVE_SYM(rb_poll, "ring_buffer__poll");
    RT_RESOLVE_SYM(rb_free, "ring_buffer__free");

    g_libbpf.module = mod;
    return 1;
}

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
    struct bpf_program* prog = NULL;
    while ((prog = g_libbpf.next_program(obj, prog)) != NULL)
    {
        const char* sec = g_libbpf.section_name(prog);
        const char* name = g_libbpf.prog_name(prog);
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

        g_libbpf.set_autoload(prog, keep);
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

    if (!ensure_libbpf_loaded())
    {
        fprintf(stderr, "[rt_engine] libbpf unavailable — falling back is the caller's responsibility\n");
        return NULL;
    }

    struct rt_engine_handle* h = calloc(1, sizeof(*h));
    if (!h)
    {
        return NULL;
    }

    const char* obj_path = (filter->bpf_obj_path && filter->bpf_obj_path[0]) ? filter->bpf_obj_path : BPF_OBJ_PATH_FALLBACK;

    h->obj = g_libbpf.open_file(obj_path, NULL);
    if (!h->obj)
    {
        fprintf(stderr, "[rt_engine] failed to open %s\n", obj_path);
        free(h);
        return NULL;
    }

    const int prefer_lsm = is_bpf_lsm_active();
    fprintf(stderr, "[rt_engine] active LSM list %s \"bpf\" -> preferring %s file_open variant\n",
            prefer_lsm ? "includes" : "does not include", prefer_lsm ? "LSM" : "kprobe");
    select_programs(h->obj, filter->type_mask, prefer_lsm);

    if (g_libbpf.load(h->obj))
    {
        fprintf(stderr, "[rt_engine] bpf_object__load failed (capability probe failed — missing "
                        "ringbuf/BTF/CO-RE support, or insufficient privilege)\n");
        g_libbpf.close_obj(h->obj);
        free(h);
        return NULL;
    }

    struct bpf_program* prog = NULL;
    while ((prog = g_libbpf.next_program(h->obj, prog)) != NULL)
    {
        if (!g_libbpf.autoload(prog))
        {
            continue;
        }
        struct bpf_link* link = g_libbpf.attach(prog);
        if (!link)
        {
            fprintf(stderr, "[rt_engine] failed to attach '%s'\n", g_libbpf.prog_name(prog));
            g_libbpf.close_obj(h->obj);
            free(h);
            return NULL;
        }
    }

    int rb_fd = g_libbpf.find_map_fd_by_name(h->obj, "rb");
    if (rb_fd < 0)
    {
        fprintf(stderr, "[rt_engine] ring buffer map 'rb' not found\n");
        g_libbpf.close_obj(h->obj);
        free(h);
        return NULL;
    }

    h->rb = g_libbpf.rb_new(rb_fd, ringbuf_sample_cb, h, NULL);
    if (!h->rb)
    {
        fprintf(stderr, "[rt_engine] ring_buffer__new failed\n");
        g_libbpf.close_obj(h->obj);
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
    return g_libbpf.rb_poll(h->rb, timeout_ms);
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
        g_libbpf.rb_free(h->rb);
    }
    if (h->obj)
    {
        g_libbpf.close_obj(h->obj);
    }
    free(h);
}
