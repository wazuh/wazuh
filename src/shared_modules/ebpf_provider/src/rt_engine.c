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

#include "cgroup_host_mode.h"

#include <dlfcn.h>
#include <errno.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* filter_cfg slots, mirroring the same names in bpf/rt_file.bpf.c. The two
 * must stay in step: the BPF side reads these keys. */
#define FILTER_CFG_KEY_MODE 0
#define FILTER_CFG_KEY_SKIP 1
/* index+1, so an unwritten slot means "not configured" and stays
 * distinguishable from subsystem 0, which is a real controller. Must match
 * bpf/rt_file.bpf.c. */
#define FILTER_CFG_KEY_V1_SUBSYS 2
#define RT_V1_SUBSYS_MAX         64

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

    /* Map access, for draining per-cgroup drop accounting. */
    int (*map_get_next_key)(int, const void*, void*);
    int (*map_lookup_elem)(int, const void*, void*);
    int (*map_update_elem)(int, const void*, const void*, unsigned long long);
    int (*map_delete_elem)(int, const void*);
    /* Preferred when present: one syscall, and atomic against the BPF side
     * still incrementing the entry. Absent on kernels/libbpf builds without
     * BPF_MAP_LOOKUP_AND_DELETE_ELEM for hash maps, hence optional. */
    int (*map_lookup_and_delete_elem)(int, const void*, void*);

    /* BTF, for reading a v1 controller's `enum cgroup_subsys_id` value out of
     * the running kernel rather than inferring it from the row order of
     * /proc/cgroups -- see rt_subsys_index_from_btf().
     *
     * OPTIONAL, deliberately. btf__load_vmlinux_btf() arrived in libbpf 0.5,
     * and an engine that refused to start without it would turn a host that
     * merely falls back to /proc/cgroups into a host with no eBPF at all. The
     * resolver below treats a null entry exactly as it treats a kernel with no
     * BTF.
     *
     * btf__type_by_id() returns a `const struct btf_type*`; it is held as
     * `const void*` so this file can read the record through its own
     * declaration without shadowing the UAPI type's name. */
    struct btf* (*btf_load_vmlinux)(void);
    int (*btf_find_by_name_kind)(const struct btf*, const char*, unsigned int);
    const void* (*btf_type_by_id)(const struct btf*, unsigned int);
    const char* (*btf_name_by_offset)(const struct btf*, unsigned int);
    void (*btf_free)(struct btf*);
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

/* The hierarchy probe moved to shared_modules/common/cgroup_host_mode.h, so
 * that container_instances asks the same question of the same code rather
 * than carrying a second copy that can drift (#37203 O4). What used to be
 * local to this file is now the policy the whole feature shares; the only
 * thing kept here is the engine's own reading of the answer.
 *
 * Still deliberately userspace-side: the hierarchy is a host constant, and
 * detecting it in the BPF program would need a config map written at load
 * time — see the RT_F_CGROUP_V1 note in rt_open(). */

#define RT_RESOLVE_SYM(field, sym)                                                                                   \
    do                                                                                                               \
    {                                                                                                                \
        *(void**)(&g_libbpf.field) = dlsym(mod, sym);                                                               \
        if (!g_libbpf.field)                                                                                         \
        {                                                                                                            \
            rt_log(log,                                                                                              \
                   RT_LOG_ERROR,                                                                                     \
                   "libbpf at '%s' is missing symbol '%s'; it is too old for this engine",                           \
                   bound,                                                                                            \
                   sym);                                                                                             \
            dlclose(mod);                                                                                           \
            return 0;                                                                                               \
        }                                                                                                            \
    } while (0)

static int ensure_libbpf_loaded(const struct rt_log_target* log, const char* libbpf_path)
{
    if (g_libbpf_resolved)
    {
        return g_libbpf.module != NULL;
    }
    g_libbpf_resolved = 1;

    /* The caller's own copy first. A bare soname binds whatever the host has,
     * and a host libbpf old enough to lack one of the symbols below fails the
     * open outright — see rt_filter.libbpf_path. */
    const char* bound = NULL;
    void* mod = NULL;
    if (libbpf_path && libbpf_path[0])
    {
        mod = dlopen(libbpf_path, RTLD_NOW);
        if (mod)
        {
            bound = libbpf_path;
        }
        else
        {
            rt_log(log,
                   RT_LOG_WARN,
                   "dlopen('%s') failed (%s); falling back to the system libbpf, which may be too old",
                   libbpf_path,
                   dlerror());
        }
    }
    if (!mod)
    {
        mod = dlopen(LIBBPF_SONAME_PRIMARY, RTLD_NOW);
        bound = LIBBPF_SONAME_PRIMARY;
    }
    if (!mod)
    {
        mod = dlopen(LIBBPF_SONAME_FALLBACK, RTLD_NOW);
        bound = LIBBPF_SONAME_FALLBACK;
    }
    if (!mod)
    {
        rt_log(log, RT_LOG_ERROR, "dlopen(libbpf) failed: %s", dlerror());
        return 0;
    }
    rt_log(log, RT_LOG_INFO, "libbpf bound from '%s'", bound);

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
    RT_RESOLVE_SYM(map_get_next_key, "bpf_map_get_next_key");
    RT_RESOLVE_SYM(map_lookup_elem, "bpf_map_lookup_elem");
    RT_RESOLVE_SYM(map_update_elem, "bpf_map_update_elem");
    RT_RESOLVE_SYM(map_delete_elem, "bpf_map_delete_elem");

    /* Optional — see the struct comment. Absence costs one extra syscall per
     * reported cgroup and a narrow race with the BPF side, not correctness of
     * the visible-loss guarantee. */
    *(void**)(&g_libbpf.map_lookup_and_delete_elem) = dlsym(mod, "bpf_map_lookup_and_delete_elem");

    /* Also optional, and for a different reason: these are a correctness
     * improvement on one rare class of host, not a requirement anywhere. A
     * libbpf too old to have them leaves the engine exactly as capable as it
     * was before they existed. Resolved as a set -- a partial set is no use,
     * so one missing symbol disables the lot rather than leaving a half-built
     * path to be discovered at the call. */
    *(void**)(&g_libbpf.btf_load_vmlinux) = dlsym(mod, "btf__load_vmlinux_btf");
    *(void**)(&g_libbpf.btf_find_by_name_kind) = dlsym(mod, "btf__find_by_name_kind");
    *(void**)(&g_libbpf.btf_type_by_id) = dlsym(mod, "btf__type_by_id");
    *(void**)(&g_libbpf.btf_name_by_offset) = dlsym(mod, "btf__name_by_offset");
    *(void**)(&g_libbpf.btf_free) = dlsym(mod, "btf__free");
    if (!g_libbpf.btf_load_vmlinux || !g_libbpf.btf_find_by_name_kind || !g_libbpf.btf_type_by_id ||
        !g_libbpf.btf_name_by_offset || !g_libbpf.btf_free)
    {
        g_libbpf.btf_load_vmlinux = NULL;
        rt_log(log,
               RT_LOG_INFO,
               "libbpf at '%s' has no usable BTF API; a v1 controller's subsystem index will be taken from "
               "/proc/cgroups instead",
               bound);
    }

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

    /* fd of cgroup_drops_map, or -1 when the loaded object predates it. */
    int cgroup_drops_fd;
    int cgroup_drops_absent_reported;

    /* fds of the filtering maps, or -1 when the object predates them. */
    int filter_cfg_fd;
    int cgroup_allow_fd;

    wz_cgroup_mode_t cgroup_mode;
    int v1_subsys_configured;

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

    if (!ensure_libbpf_loaded(&log, filter->libbpf_path))
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
    /* calloc leaves these 0, which is a legitimate descriptor number. */
    h->cgroup_drops_fd = -1;
    h->filter_cfg_fd = -1;
    h->cgroup_allow_fd = -1;

    h->cgroup_mode = wz_cgroup_mode();
    if (!wz_cgroup_mode_has_usable_cgroup_id(h->cgroup_mode))
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
        /* The advice this used to give — "correlate on mnt_ns instead" — was
         * written when the helper's limit looked like the kernel's. It is not:
         * rt_set_cgroup_v1_subsys() points the program at a v1 controller's own
         * cgroups, and from then on cgroup_id identifies a container and the
         * allowlist filters normally. Measured on a pure v1 host: the helper
         * returns 1 for every task, while the controller read returns 6403 and
         * 6435 for two containers, matching stat() of their directories. */
        rt_log(&h->log,
               RT_LOG_WARN,
               "host cgroup hierarchy is %s: bpf_get_current_cgroup_id() reports the unified "
               "hierarchy, which this host does not have, so an event's cgroup_id identifies nothing "
               "until a consumer calls rt_set_cgroup_v1_subsys()",
               wz_cgroup_mode_name(h->cgroup_mode));
    }
    else
    {
        /* Say it on the healthy path too. "Which hierarchy did the agent
         * think it was on?" is the first question asked of any attribution
         * bug, and an answer that only appears when the answer is bad leaves
         * the common case indistinguishable from the probe never running. */
        rt_log(&h->log,
               RT_LOG_INFO,
               "host cgroup hierarchy is %s: cgroup_id is a usable correlation key",
               wz_cgroup_mode_name(h->cgroup_mode));
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

    /* CONFIGURE BEFORE ATTACHING. The maps exist as soon as the object is
     * loaded, and the moment a program is attached it begins writing events
     * into the ring — so anything configured after the attach loop below leaves
     * a window in which the program runs with an unconfigured filter.
     *
     * That window is not harmless, for two reasons that compound:
     *
     *   event_is_wanted() treats an unwritten mode as SUBMIT, deliberately, so
     *   that an engine whose userspace never wrote one cannot silently deliver
     *   nothing. Configured late, that default applies to the window instead of
     *   to a misconfigured consumer, and the whole host's file traffic is
     *   admitted — which is exactly what the consumer asking for ALLOWLIST was
     *   trying to avoid, and what its "start closed" comment says it gets.
     *
     *   On a host with no unified hierarchy the ids on those events are worse
     *   than unwanted, they are meaningless: current_container_cgroup_id()
     *   falls back to bpf_get_current_cgroup_id(), which there reports the
     *   default hierarchy's root — inode 1, plus a packed generation on a RHEL
     *   8 family kernel. That key matches no inode on the host, so the consumer
     *   can neither attribute it nor conclude it is not a container; it retries
     *   the cold-cache resolve forever. ONE event caught in this window is
     *   enough to log that failure on every resolver cycle for the life of the
     *   process.
     *
     * Writing the configuration first closes it: a consumer that opened in
     * allowlist mode filters against an empty allowlist from the first attached
     * program onwards, and delivers nothing until it seeds one. */
    h->filter_cfg_fd = g_libbpf.find_map_fd_by_name(h->obj, "filter_cfg");
    h->cgroup_allow_fd = g_libbpf.find_map_fd_by_name(h->obj, "cgroup_allow_map");

    /* Write the requested mode. An object that predates filtering has neither
     * map: unfiltered is what it does anyway, so ALL is satisfied silently and
     * only ALLOWLIST is an error — asking to filter and getting everything is
     * a correctness surprise, not a degradation to absorb quietly. */
    if (h->filter_cfg_fd < 0 || h->cgroup_allow_fd < 0)
    {
        if (filter->cgroup_mode != RT_CGROUP_MODE_ALL)
        {
            rt_log(&h->log, RT_LOG_ERROR,
                   "cgroup filtering requested but this BPF object has no filtering maps: every event "
                   "on the host would be delivered. Rebuild rt_file.bpf.o.");
            abort_open(h);
            return NULL;
        }
    }
    else if (rt_set_cgroup_mode(h, filter->cgroup_mode) != 0)
    {
        rt_log(&h->log, RT_LOG_ERROR, "could not set cgroup filter mode %d", filter->cgroup_mode);
        abort_open(h);
        return NULL;
    }

    /* Per-event work this consumer opted out of. An object that predates the
     * mask has a one-slot filter_cfg, so the write fails: that is a degradation
     * (every field is computed, as before) and not a correctness problem, so it
     * warns rather than refusing the open — the opposite of the mode above,
     * which changes which events arrive. */
    if (filter->skip_mask != 0 && h->filter_cfg_fd >= 0)
    {
        const unsigned int key = FILTER_CFG_KEY_SKIP;
        const unsigned int value = filter->skip_mask;

        if (g_libbpf.map_update_elem(h->filter_cfg_fd, &key, &value, 0 /* BPF_ANY */) != 0)
        {
            rt_log(&h->log, RT_LOG_WARN,
                   "could not apply skip mask 0x%x; every per-event field will be computed. Rebuild "
                   "rt_file.bpf.o to honour it.",
                   filter->skip_mask);
        }
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

    /* Optional: an object built before per-cgroup drop accounting still loads
     * and runs, it just cannot attribute loss. Not a reason to refuse the open —
     * the global in-band counter still works. */
    h->cgroup_drops_fd = g_libbpf.find_map_fd_by_name(h->obj, "cgroup_drops_map");
    if (h->cgroup_drops_fd < 0)
    {
        rt_log(&h->log, RT_LOG_WARN,
               "BPF object has no 'cgroup_drops_map': dropped events will be visible but not "
               "attributable to a cgroup. Rebuild rt_file.bpf.o to enable rt_drain_drops().");
    }

    rt_log(&h->log, RT_LOG_INFO,
           "eBPF engine ready: %u program(s) attached, ABI %d.%d, cgroup filter %s, skip mask 0x%x",
           h->link_count, RT_ABI_MAJOR, RT_ABI_MINOR,
           filter->cgroup_mode == RT_CGROUP_MODE_ALLOWLIST ? "allowlist" : "off", filter->skip_mask);
    return (rt_handle_t)h;
}

int rt_set_cgroup_mode(rt_handle_t handle, int mode)
{
    struct rt_engine_handle* h = (struct rt_engine_handle*)handle;
    if (!h || h->filter_cfg_fd < 0)
    {
        return -1;
    }
    if (mode != RT_CGROUP_MODE_ALL && mode != RT_CGROUP_MODE_ALLOWLIST)
    {
        rt_log(&h->log, RT_LOG_ERROR, "unknown cgroup filter mode %d", mode);
        return -1;
    }

    const unsigned int key = FILTER_CFG_KEY_MODE;
    const unsigned int value = (unsigned int)mode;
    if (g_libbpf.map_update_elem(h->filter_cfg_fd, &key, &value, 0 /* BPF_ANY */) != 0)
    {
        return -1;
    }
    return 0;
}

/* BTF record layouts, taken from the kernel's UAPI <linux/btf.h>.
 *
 * Declared rather than included, for the reason rt_libbpf_shim.h gives for
 * libbpf's own types: this file must build on a host with no BPF development
 * headers. Unlike a library's internal structs these are a frozen kernel ABI --
 * BTF is a serialization format carrying its own version field, so a layout
 * change would be a new version and not a silent reinterpretation of these
 * bytes. Named rt_* so a translation unit that also includes <linux/btf.h>
 * cannot collide with them. */
#define RT_BTF_KIND_ENUM 6
#define RT_BTF_KIND_ENUM64 19

struct rt_btf_type
{
    unsigned int name_off;
    unsigned int info; /* bits 0-15 vlen, bits 24-28 kind */
    union
    {
        unsigned int size;
        unsigned int type;
    } u;
};

struct rt_btf_enum
{
    unsigned int name_off;
    int val;
};

struct rt_btf_enum64
{
    unsigned int name_off;
    unsigned int val_lo32;
    unsigned int val_hi32;
};

/* How a controller is spelled in `enum cgroup_subsys_id`.
 *
 * Almost always "<name>_cgrp_id". The exception is that /proc/cgroups prints a
 * controller's LEGACY name while the enum uses its current one, and for one
 * controller those differ: the file says `blkio` where the enum says
 * `io_cgrp_id`. Same subsystem, two spellings, and the lookup matches on the
 * string. */
static int rt_cgroup_subsys_enumerator(const char* controller, char* out, size_t out_len)
{
    const char* name = controller;

    if (strcmp(controller, "blkio") == 0)
    {
        name = "io";
    }

    const int written = snprintf(out, out_len, "%s_cgrp_id", name);
    return (written > 0 && (size_t)written < out_len) ? 0 : -1;
}

/* A controller's value in the kernel's own `enum cgroup_subsys_id`.
 *
 * The authority, where the row order of /proc/cgroups is only a good guess.
 * Since 6.12 proc_cgroupstats_show() skips a controller built without v1 files
 * -- cgroup1_subsys_absent(), which is what CONFIG_MEMCG_V1=n and
 * CONFIG_CPUSETS_V1=n produce -- while the enumerator stays, because
 * SUBSYS(memory) sits behind CONFIG_MEMCG and SUBSYS(cpuset) behind
 * CONFIG_CPUSETS. Every row after the missing one then reads one short of its
 * real id and the program is pointed at a different controller's cgroup.
 * Reading the enum itself cannot drift that way, on any kernel.
 *
 * Called once, while configuring a legacy host, and never on a unified or
 * hybrid one.
 *
 * Returns the id, or -1 whenever BTF cannot answer: no libbpf BTF API, no
 * kernel BTF, no such enum, no such enumerator. Each of those means "fall back
 * to /proc/cgroups", not "fail". */
static int rt_subsys_index_from_btf(const char* controller, const struct rt_log_target* log)
{
    char wanted[64];

    if (!controller || !controller[0] || !g_libbpf.btf_load_vmlinux)
    {
        return -1;
    }
    if (rt_cgroup_subsys_enumerator(controller, wanted, sizeof(wanted)) != 0)
    {
        return -1;
    }

    struct btf* btf = g_libbpf.btf_load_vmlinux();
    if (!btf)
    {
        rt_log(log,
               RT_LOG_INFO,
               "no kernel BTF available; taking the v1 subsystem index for '%s' from /proc/cgroups",
               controller);
        return -1;
    }

    int found = -1;

    /* ENUM and ENUM64 carry the same information under different kinds, and
     * which one a given kernel's BTF used is not ours to predict. */
    const unsigned int kinds[2] = {RT_BTF_KIND_ENUM, RT_BTF_KIND_ENUM64};

    for (unsigned int k = 0; k < 2 && found < 0; ++k)
    {
        const int id = g_libbpf.btf_find_by_name_kind(btf, "cgroup_subsys_id", kinds[k]);
        if (id < 0)
        {
            continue;
        }

        const struct rt_btf_type* type = (const struct rt_btf_type*)g_libbpf.btf_type_by_id(btf, (unsigned int)id);
        if (!type)
        {
            continue;
        }

        const unsigned int vlen = type->info & 0xffffu;

        for (unsigned int i = 0; i < vlen; ++i)
        {
            unsigned int name_off;
            int value;

            if (kinds[k] == RT_BTF_KIND_ENUM)
            {
                const struct rt_btf_enum* members = (const struct rt_btf_enum*)(type + 1);
                name_off = members[i].name_off;
                value = members[i].val;
            }
            else
            {
                const struct rt_btf_enum64* members = (const struct rt_btf_enum64*)(type + 1);
                if (members[i].val_hi32 != 0)
                {
                    /* A subsystem id cannot need 64 bits. Reading the high
                     * word only to refuse it keeps a malformed or unexpected
                     * entry from being truncated into a plausible index. */
                    continue;
                }
                name_off = members[i].name_off;
                value = (int)members[i].val_lo32;
            }

            const char* name = g_libbpf.btf_name_by_offset(btf, name_off);
            if (name && strcmp(name, wanted) == 0)
            {
                found = value;
                break;
            }
        }
    }

    g_libbpf.btf_free(btf);
    return found;
}

int rt_cgroup_subsys_index_from_btf(const char* controller)
{
    if (!ensure_libbpf_loaded(NULL, NULL))
    {
        return -1;
    }
    return rt_subsys_index_from_btf(controller, NULL);
}

int rt_set_cgroup_v1_subsys(rt_handle_t handle, const char* controller, unsigned int fallback_index)
{
    struct rt_engine_handle* h = (struct rt_engine_handle*)handle;
    if (!h || h->filter_cfg_fd < 0)
    {
        return -1;
    }

    /* The kernel's own enum first, the caller's /proc/cgroups reading second.
     * Both name the SAME controller -- the caller passes what it resolved
     * container paths under -- so this chooses between two readings of one
     * question rather than between two controllers. */
    unsigned int subsys_index = fallback_index;
    const int from_btf = rt_subsys_index_from_btf(controller, &h->log);

    if (from_btf >= 0)
    {
        subsys_index = (unsigned int)from_btf;

        if (subsys_index != fallback_index)
        {
            /* THE 6.12 CASE, caught in the act. The row order of /proc/cgroups
             * stopped matching the enum when proc_cgroupstats_show() began
             * skipping controllers built without v1 files, and a host where
             * that happens would otherwise read a different controller's
             * cgroup and attribute nothing, with every other sign healthy:
             * userspace matches controllers by name, so containers still
             * resolve and still carry keys. Logged at warn because the
             * disagreement IS the diagnosis -- nothing else on this host will
             * report it. */
            rt_log(&h->log,
                   RT_LOG_WARN,
                   "the '%s' controller is at index %u in the kernel's enum but at row %u of "
                   "/proc/cgroups; using %u. A kernel 6.12 or newer omits the row of a controller built "
                   "without v1 files (CONFIG_MEMCG_V1=n, CONFIG_CPUSETS_V1=n), which shifts every row "
                   "after it",
                   controller ? controller : "?",
                   subsys_index,
                   fallback_index,
                   subsys_index);
        }
    }

    /* Refused rather than trusted to the caller. On a unified or hybrid host
     * css_set.subsys[i] can point at an ANCESTOR cgroup — the nearest one
     * where controller i is enabled — so this read would attribute a
     * container's events to its parent slice, with a number that looks
     * entirely reasonable. The helper is correct there and must be used. */
    if (!wz_cgroup_v1_subsys_read_allowed(h->cgroup_mode, (int)subsys_index))
    {
        rt_log(&h->log,
               RT_LOG_ERROR,
               "refusing to read cgroup ids from a v1 controller on a %s host: the helper is correct here "
               "and the controller read can resolve to an ancestor cgroup",
               wz_cgroup_mode_name(h->cgroup_mode));
        return -1;
    }

    if (subsys_index >= RT_V1_SUBSYS_MAX)
    {
        rt_log(&h->log, RT_LOG_ERROR, "cgroup subsystem index %u out of range", subsys_index);
        return -1;
    }

    const unsigned int key = FILTER_CFG_KEY_V1_SUBSYS;
    const unsigned int value = subsys_index + 1u;

    /* Probe the slot before writing it. 'filter_cfg' grew a third entry when
     * the legacy controller read was added, and an array map rejects a key
     * past its end -- so a loaded object that predates that change fails here
     * and nowhere else. Without this the caller sees only a generic write
     * failure and reports that the HOST has no usable controller, which sends
     * whoever reads the log looking at cgroups instead of at a stale build
     * artifact. */
    unsigned int probe = 0;
    if (g_libbpf.map_lookup_elem(h->filter_cfg_fd, &key, &probe) != 0)
    {
        rt_log(&h->log,
               RT_LOG_ERROR,
               "the loaded rt_file.bpf.o is too old: its 'filter_cfg' map has no slot %u, which is where "
               "the v1 cgroup controller index goes. Rebuild rt_file.bpf.o.",
               key);
        return -1;
    }

    if (g_libbpf.map_update_elem(h->filter_cfg_fd, &key, &value, 0 /* BPF_ANY */) != 0)
    {
        rt_log(&h->log, RT_LOG_ERROR, "could not configure the v1 cgroup subsystem index: %s", strerror(errno));
        return -1;
    }

    h->v1_subsys_configured = 1;
    rt_log(&h->log,
           RT_LOG_INFO,
           "reading container cgroup ids from v1 controller '%s' (subsystem %u, resolved from %s); cgroup "
           "filtering is available",
           controller ? controller : "?",
           subsys_index,
           (from_btf >= 0) ? "kernel BTF" : "/proc/cgroups");
    return 0;
}

int rt_cgroup_id_is_usable(rt_handle_t handle)
{
    const struct rt_engine_handle* h = (const struct rt_engine_handle*)handle;
    if (!h)
    {
        return 0;
    }
    return wz_cgroup_mode_has_usable_cgroup_id(h->cgroup_mode) || h->v1_subsys_configured;
}

int rt_allow_cgroup(rt_handle_t handle, unsigned long long cgroup_id)
{
    struct rt_engine_handle* h = (struct rt_engine_handle*)handle;
    if (!h || h->cgroup_allow_fd < 0)
    {
        return -1;
    }

    const unsigned char present = 1;
    if (g_libbpf.map_update_elem(h->cgroup_allow_fd, &cgroup_id, &present, 0 /* BPF_ANY */) != 0)
    {
        /* Almost always E2BIG: the map is full. In allowlist mode that means
         * the cgroups which did not fit are unmonitored, silently, which is
         * exactly the kind of gap that must be loud. */
        rt_log(&h->log, RT_LOG_ERROR,
               "could not add cgroup %llu to the allowlist (map full?); its events will not be "
               "delivered while allowlist mode is active",
               cgroup_id);
        return -1;
    }
    return 0;
}

int rt_deny_cgroup(rt_handle_t handle, unsigned long long cgroup_id)
{
    struct rt_engine_handle* h = (struct rt_engine_handle*)handle;
    if (!h || h->cgroup_allow_fd < 0)
    {
        return -1;
    }
    /* Absent is the desired end state, so a failed delete of a missing key is
     * success, not an error. */
    g_libbpf.map_delete_elem(h->cgroup_allow_fd, &cgroup_id);
    return 0;
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

/* Keys collected per drain call. A node with more than this many cgroups losing
 * events in one interval is already in deep trouble; the remainder simply waits
 * for the next drain rather than making this function unbounded. */
#define RT_DRAIN_BATCH 512

int rt_drain_drops(rt_handle_t handle, rt_drop_fn cb, void* user)
{
    struct rt_engine_handle* h = (struct rt_engine_handle*)handle;
    if (!h)
    {
        return -1;
    }

    if (h->cgroup_drops_fd < 0)
    {
        if (!h->cgroup_drops_absent_reported)
        {
            h->cgroup_drops_absent_reported = 1;
            rt_log(&h->log, RT_LOG_WARN,
                   "rt_drain_drops(): this BPF object has no per-cgroup drop map, so loss cannot be "
                   "attributed. Further calls will not be logged.");
        }
        return -1;
    }

    /* Collect keys first, then drain them.
     *
     * Deleting the current key mid-iteration is not safe with
     * bpf_map_get_next_key: the deleted key is the iteration cursor, and once
     * it is gone the kernel may restart from the beginning, which can loop
     * forever or skip entries. So walk the keyspace once, then act on the
     * snapshot. Entries created after the walk are picked up next drain. */
    unsigned long long keys[RT_DRAIN_BATCH];
    unsigned int collected = 0;

    unsigned long long key = 0;
    unsigned long long next = 0;
    int rc = g_libbpf.map_get_next_key(h->cgroup_drops_fd, NULL, &next);
    while (rc == 0 && collected < RT_DRAIN_BATCH)
    {
        keys[collected++] = next;
        key = next;
        rc = g_libbpf.map_get_next_key(h->cgroup_drops_fd, &key, &next);
    }

    int reported = 0;
    for (unsigned int i = 0; i < collected; ++i)
    {
        unsigned int drops = 0;

        if (g_libbpf.map_lookup_and_delete_elem)
        {
            if (g_libbpf.map_lookup_and_delete_elem(h->cgroup_drops_fd, &keys[i], &drops) != 0)
            {
                continue; /* raced with another drain, or already gone */
            }
        }
        else
        {
            if (g_libbpf.map_lookup_elem(h->cgroup_drops_fd, &keys[i], &drops) != 0)
            {
                continue;
            }
            /* Non-atomic fallback: a drop recorded between the lookup and the
             * delete is lost from the per-cgroup view. It is still counted in
             * the global in-band counter, so it cannot vanish silently — it
             * just arrives unattributed, which is the pre-existing behaviour. */
            g_libbpf.map_delete_elem(h->cgroup_drops_fd, &keys[i]);
        }

        if (drops == 0)
        {
            continue; /* created by the insert-then-add path, not yet incremented */
        }

        if (cb)
        {
            cb(keys[i], drops, user);
        }
        ++reported;
    }

    return reported;
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
    const wz_cgroup_mode_t mode = h ? h->cgroup_mode : wz_cgroup_mode();
    return wz_cgroup_mode_has_usable_cgroup_id(mode) ? 0 : 1;
}
