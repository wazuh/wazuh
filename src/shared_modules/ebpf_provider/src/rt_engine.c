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

/* Not <bpf/libbpf.h>: libbpf is dlopen()'d, and this tree ships libbpf.so
 * without its headers. See rt_libbpf_shim.h for why the types are shadowed. */
#include "rt_libbpf_shim.h"

#include <dlfcn.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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
    int (*link_destroy)(struct bpf_link*);
};

static struct libbpf_api g_libbpf;
static int g_libbpf_resolved = 0; /* 0 = not attempted, 1 = attempted (see g_libbpf.module for outcome) */

/* Where diagnostics go. Carried separately from the handle because the first
 * failures happen before a handle exists (bad filter, no libbpf, object won't
 * open), and those are precisely the ones a consumer needs to see. */
struct rt_log_target
{
    rt_log_fn fn;
    void* user;
};

/* One line of diagnostics. Falls back to stderr so the standalone harness and
 * any consumer that passes no sink behave as before. The format attribute is
 * what lets -Wformat catch a bad call here rather than at the vsnprintf. */
__attribute__((format(printf, 3, 4))) static void
rt_log(const struct rt_log_target* target, int level, const char* fmt, ...)
{
    char msg[512];
    va_list args;
    va_start(args, fmt);
    const int written = vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    if (written < 0)
    {
        return;
    }

    if (target && target->fn)
    {
        target->fn(level, msg, target->user);
    }
    else
    {
        fprintf(stderr, "[rt_engine] %s\n", msg);
    }
}

/* cgroup v1 vs v2, decided from the mount layout rather than from events.
 *
 * On a v2 (unified) hierarchy the root cgroupfs exposes cgroup.controllers; on
 * a pure v1 host it does not, and bpf_get_current_cgroup_id() collapses to a
 * constant, making every event's cgroup_id useless as a correlation key
 * (spike #37396 ADR-002). A hybrid host mounts v2 at /sys/fs/cgroup/unified,
 * which is treated as v2-capable here: the ids that helper returns are the
 * unified hierarchy's, so they do correlate.
 *
 * Deliberately userspace-side: the version is a host constant, and detecting
 * it in the BPF program would need a config map written at load time — see the
 * RT_F_CGROUP_V1 note in rt_open(). */
static int detect_cgroup_v1(void)
{
    struct stat st;
    if (stat("/sys/fs/cgroup/cgroup.controllers", &st) == 0)
    {
        return 0;
    }
    if (stat("/sys/fs/cgroup/unified/cgroup.controllers", &st) == 0)
    {
        return 0;
    }
    return 1;
}

#define RT_RESOLVE_SYM(field, sym)                                                                                   \
    do                                                                                                               \
    {                                                                                                                \
        *(void**)(&g_libbpf.field) = dlsym(mod, sym);                                                               \
        if (!g_libbpf.field)                                                                                         \
        {                                                                                                            \
            rt_log(log, RT_LOG_ERROR, "libbpf missing symbol '%s'", sym);                                            \
            dlclose(mod);                                                                                           \
            return 0;                                                                                               \
        }                                                                                                            \
    } while (0)

static int ensure_libbpf_loaded(const struct rt_log_target* log)
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
        rt_log(log, RT_LOG_ERROR, "dlopen(libbpf) failed: %s", dlerror());
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
    RT_RESOLVE_SYM(link_destroy, "bpf_link__destroy");

    g_libbpf.module = mod;
    return 1;
}

/* Upper bound on attached programs. rt_file.bpf.c defines a handful of hooks
 * and select_programs() can only ever keep a subset of them, so a fixed array
 * avoids a heap allocation on the attach path; the assert-like guard below
 * turns a future overflow into a refused open rather than memory corruption. */
#define RT_MAX_LINKS 16

struct rt_engine_handle
{
    struct bpf_object* obj;
    struct ring_buffer* rb;
    rt_sink_fn current_sink;
    void* current_user;

    /* Every link returned by bpf_program__attach. These were previously
     * dropped on the floor: bpf_object__close does NOT detach them, so the
     * programs stayed attached for the life of the process. The kernel then
     * kept writing into a ring buffer with no consumer (the program holds a
     * reference to the map, so freeing our side does not stop it), the drop
     * counter climbed against nobody, and a subsequent rt_open attached a
     * second copy of every program — duplicate events for every operation. */
    struct bpf_link* links[RT_MAX_LINKS];
    unsigned int link_count;

    struct rt_log_target log;

    int cgroup_v1;

    /* Rejected-record accounting; reported once per handle so a stale object
     * cannot flood the log. */
    unsigned long long rejected;
    int rejected_reported;
};

/* Detach every attached program. Ordered before the ring buffer is freed so
 * the kernel stops producing before the consumer goes away. */
static void destroy_links(struct rt_engine_handle* h)
{
    for (unsigned int i = 0; i < h->link_count; ++i)
    {
        if (h->links[i])
        {
            g_libbpf.link_destroy(h->links[i]);
            h->links[i] = NULL;
        }
    }
    h->link_count = 0;
}

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

static void select_programs(struct bpf_object* obj, unsigned int type_mask, int prefer_lsm,
                            const struct rt_log_target* log)
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
        rt_log(log, RT_LOG_DEBUG, "program '%s' (%s): autoload=%s", name ? name : "?", sec ? sec : "?",
               keep ? "true" : "false");
    }
}

static int ringbuf_sample_cb(void* ctx, void* data, size_t size)
{
    struct rt_engine_handle* h = (struct rt_engine_handle*)ctx;
    if (!h->current_sink || !data)
    {
        return 0;
    }

    const struct rt_file_event* ev = (const struct rt_file_event*)data;

    /* ABI guard. The BPF object is a separate build artefact from this
     * library, so a stale .bpf.o against a newer contract is a real
     * possibility — and the record is exchanged by raw memory
     * reinterpretation, which makes such a mismatch silent and its effects
     * arbitrary. Two independent checks:
     *
     *   abi_major   the object stamps its own RT_ABI_MAJOR into every event;
     *               a difference means fields moved or changed size.
     *   size        per ADR-003 a MINOR bump appends fields, so an object
     *               built against an older MINOR emits a SHORTER record than
     *               this build's struct — reading our tail fields would run
     *               off the end of the record. The reverse (a newer object,
     *               longer record) is fine and is what "old consumers ignore
     *               the tail" means.
     *
     * Rejected records are dropped rather than passed on, and reported once. */
    if (ev->abi_major != RT_ABI_MAJOR || size < sizeof(struct rt_file_event))
    {
        ++h->rejected;
        if (!h->rejected_reported)
        {
            h->rejected_reported = 1;
            rt_log(&h->log, RT_LOG_ERROR,
                   "rejecting events from an incompatible BPF object: got abi_major=%u record=%zu bytes, "
                   "this build expects abi_major=%d record>=%zu bytes. Rebuild rt_file.bpf.o. "
                   "Further occurrences will not be logged.",
                   (unsigned)ev->abi_major, size, RT_ABI_MAJOR, sizeof(struct rt_file_event));
        }
        return 0;
    }

    h->current_sink(ev, h->current_user);
    return 0;
}

/* Unwind whatever rt_open got as far as building. Kept in one place so no
 * error path can forget the links again. */
static void abort_open(struct rt_engine_handle* h)
{
    destroy_links(h);
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

rt_handle_t rt_open(const struct rt_filter* filter)
{
    struct rt_log_target log = {NULL, NULL};
    if (filter)
    {
        log.fn = filter->log;
        log.user = filter->log_user;
    }

    if (!filter || (filter->type_mask & RT_FILE_ALL_BITS) == 0)
    {
        rt_log(&log, RT_LOG_ERROR, "rt_open: empty/invalid filter");
        return NULL;
    }

    if (!ensure_libbpf_loaded(&log))
    {
        rt_log(&log, RT_LOG_ERROR, "libbpf unavailable — falling back is the caller's responsibility");
        return NULL;
    }

    struct rt_engine_handle* h = calloc(1, sizeof(*h));
    if (!h)
    {
        rt_log(&log, RT_LOG_ERROR, "out of memory allocating the engine handle");
        return NULL;
    }
    h->log = log;

    h->cgroup_v1 = detect_cgroup_v1();
    if (h->cgroup_v1)
    {
        /* Worth an explicit line: on such a host cgroup_id correlates nothing,
         * so a consumer that keys containers on it silently attributes every
         * event on the node to one bogus cgroup.
         *
         * NOTE: the per-event RT_F_CGROUP_V1 flag is still never set by
         * rt_file.bpf.c. Setting it there needs a config map written by
         * userspace at load time and re-read by the program, which cannot be
         * built or loaded in this development environment; until that lands,
         * rt_host_cgroup_v1() is the only reliable source and a consumer MUST
         * use it rather than testing ev->flags. */
        rt_log(&h->log, RT_LOG_WARN,
               "host uses cgroup v1: every event's cgroup_id is a constant, not a correlation key — "
               "consumers must correlate on mnt_ns instead (see rt_host_cgroup_v1())");
    }

    const char* obj_path = (filter->bpf_obj_path && filter->bpf_obj_path[0]) ? filter->bpf_obj_path : BPF_OBJ_PATH_FALLBACK;

    h->obj = g_libbpf.open_file(obj_path, NULL);
    if (!h->obj)
    {
        rt_log(&h->log, RT_LOG_ERROR, "failed to open BPF object '%s'", obj_path);
        abort_open(h);
        return NULL;
    }

    const int prefer_lsm = is_bpf_lsm_active();
    rt_log(&h->log, RT_LOG_DEBUG, "active LSM list %s \"bpf\" -> preferring %s file_open variant",
           prefer_lsm ? "includes" : "does not include", prefer_lsm ? "LSM" : "kprobe");
    select_programs(h->obj, filter->type_mask, prefer_lsm, &h->log);

    if (g_libbpf.load(h->obj))
    {
        rt_log(&h->log, RT_LOG_ERROR,
               "bpf_object__load failed (capability probe failed — missing ringbuf/BTF/CO-RE support, "
               "or insufficient privilege)");
        abort_open(h);
        return NULL;
    }

    struct bpf_program* prog = NULL;
    while ((prog = g_libbpf.next_program(h->obj, prog)) != NULL)
    {
        if (!g_libbpf.autoload(prog))
        {
            continue;
        }

        if (h->link_count >= RT_MAX_LINKS)
        {
            rt_log(&h->log, RT_LOG_ERROR,
                   "more than %d programs selected; raise RT_MAX_LINKS. Refusing to attach programs "
                   "this handle could not detach.",
                   RT_MAX_LINKS);
            abort_open(h);
            return NULL;
        }

        struct bpf_link* link = g_libbpf.attach(prog);
        if (!link)
        {
            const char* name = g_libbpf.prog_name(prog);
            rt_log(&h->log, RT_LOG_ERROR, "failed to attach '%s'", name ? name : "?");
            abort_open(h);
            return NULL;
        }
        h->links[h->link_count++] = link;
    }

    int rb_fd = g_libbpf.find_map_fd_by_name(h->obj, "rb");
    if (rb_fd < 0)
    {
        rt_log(&h->log, RT_LOG_ERROR, "ring buffer map 'rb' not found");
        abort_open(h);
        return NULL;
    }

    h->rb = g_libbpf.rb_new(rb_fd, ringbuf_sample_cb, h, NULL);
    if (!h->rb)
    {
        rt_log(&h->log, RT_LOG_ERROR, "ring_buffer__new failed");
        abort_open(h);
        return NULL;
    }

    rt_log(&h->log, RT_LOG_INFO, "eBPF engine ready: %u program(s) attached, ABI %d.%d", h->link_count,
           RT_ABI_MAJOR, RT_ABI_MINOR);
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

    if (h->rejected)
    {
        rt_log(&h->log, RT_LOG_WARN, "%llu event(s) were rejected as ABI-incompatible over this handle's life",
               h->rejected);
    }

    /* Detach first, then stop consuming, then release the object: reversing
     * the first two leaves attached programs writing into a ring buffer whose
     * consumer has gone. */
    destroy_links(h);
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

int rt_abi_major(void)
{
    return RT_ABI_MAJOR;
}

int rt_abi_minor(void)
{
    return RT_ABI_MINOR;
}

int rt_host_cgroup_v1(rt_handle_t handle)
{
    const struct rt_engine_handle* h = (const struct rt_engine_handle*)handle;
    return h ? h->cgroup_v1 : detect_cgroup_v1();
}
