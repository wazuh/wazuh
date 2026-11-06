/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Linker wrappers keep loader tests independent of libbpf and the kernel.
 * Each child starts with fresh process-wide binding state; no reset seam is
 * exposed by the engine just for tests.
 */
#include "rt_engine.h"
#include "rt_libbpf_shim.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define THREADS 32
static int g_failures;
#define CHECK(cond, ...)                                                                                             \
    do                                                                                                               \
    {                                                                                                                \
        if (!(cond))                                                                                                 \
        {                                                                                                            \
            ++g_failures;                                                                                            \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);                                                              \
            printf(__VA_ARGS__);                                                                                     \
            printf("\n");                                                                                            \
        }                                                                                                            \
    } while (0)

static atomic_int g_opens, g_symbols, g_closes, g_objects, g_warnings, g_errors, g_early;
static pthread_barrier_t g_start;
static pthread_mutex_t g_gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cond = PTHREAD_COND_INITIALIZER;
static int g_entered, g_release, g_mode;
static const char* g_first;
static const char* g_second;
static char g_warning[512];

void* __wrap_dlopen(const char* path, int flags)
{
    (void)flags;
    atomic_fetch_add(&g_opens, 1);
    if (g_mode == 2 || (g_mode == 3 && strcmp(path, g_first) == 0))
    {
        return NULL;
    }
    return (void*)1;
}

int __wrap_dlclose(void* module)
{
    (void)module;
    atomic_fetch_add(&g_closes, 1);
    return 0;
}

static int g_ladder, g_rung, g_live, g_destroyed, g_obj_closed, g_attach_count;
static unsigned int g_mask;
struct fake_program { const char* sec; const char* name; int enabled; };
static struct fake_program g_programs[] = {
    {"kprobe/mnt_want_write", "mnt_want_write", 0},
    {"kprobe/vfs_open", "open", 0},
    {"kprobe/security_inode_setattr", "attr", 0},
    {"kprobe/vfs_unlink", "unlink", 0},
    {"kprobe/vfs_rename", "rename", 0},
    {"lsm/file_open", "file_open_dpath", 0},
    {"lsm/file_open", "file_open_walk", 0},
    {"lsm/path_unlink", "path_unlink_dpath", 0},
    {"lsm/path_unlink", "path_unlink_walk", 0},
    {"lsm/path_rename", "path_rename_dpath", 0},
    {"lsm/path_rename", "path_rename_walk", 0},
    {"unknown", "unknown", 0},
    {"kprobe/vfs_rename", "kprobe__vfs_rename_old", 0},
    {"lsm/path_rename", "path_rename_old_dpath", 0},
    {"lsm/path_rename", "path_rename_old_walk", 0},
};

FILE* __real_fopen(const char*, const char*);
FILE* __wrap_fopen(const char* path, const char* mode)
{
    if (strcmp(path, "/sys/kernel/security/lsm") == 0)
    {
        FILE* file = tmpfile();
        if (!file) abort();
        fputs(g_ladder == 7 ? "lockdown\n" : "lockdown,bpf\n", file);
        rewind(file);
        return file;
    }
    return __real_fopen(path, mode);
}

static struct bpf_program* fake_next(const struct bpf_object* obj, struct bpf_program* prev)
{
    (void)obj;
    struct fake_program* next = prev ? (struct fake_program*)prev + 1 : g_programs;
    return next < g_programs + sizeof(g_programs) / sizeof(*g_programs) ? (struct bpf_program*)next : NULL;
}
static const char* fake_section(const struct bpf_program* prog) { return ((const struct fake_program*)prog)->sec; }
static const char* fake_name(const struct bpf_program* prog) { return ((const struct fake_program*)prog)->name; }
static int fake_set(struct bpf_program* prog, bool enabled) { ((struct fake_program*)prog)->enabled = enabled; return 0; }
static bool fake_autoload(const struct bpf_program* prog) { return ((const struct fake_program*)prog)->enabled; }
static int fake_load(struct bpf_object* obj)
{
    (void)obj;
    const int kprobe = ((g_ladder == 8 && g_rung == 3) || (g_ladder == 9 && g_rung == 2)) || g_ladder == 7 || (g_ladder == 3 && g_rung == 3) ||
                       ((g_ladder == 4 || g_ladder == 5 || g_ladder == 6) && g_rung == (g_ladder == 6 ? 3 : 2));
    const int walk = !kprobe && g_rung == 2;
    const unsigned int bits[] = {0, RT_FILE_OPEN_BIT, RT_FILE_ATTR_BIT, RT_FILE_UNLINK_BIT, RT_FILE_RENAME_BIT,
        RT_FILE_OPEN_BIT, RT_FILE_OPEN_BIT, RT_FILE_UNLINK_BIT, RT_FILE_UNLINK_BIT, RT_FILE_RENAME_BIT, RT_FILE_RENAME_BIT, 0,
        RT_FILE_RENAME_BIT, RT_FILE_RENAME_BIT, RT_FILE_RENAME_BIT};
    for (unsigned int i = 0; i < sizeof(g_programs) / sizeof(*g_programs); ++i)
    {
        int expected = (bits[i] & g_mask) != 0;
        if (i == 0) expected = (g_mask & (RT_FILE_ATTR_BIT | (kprobe ? RT_FILE_UNLINK_BIT | RT_FILE_RENAME_BIT : 0))) != 0;
        else if ((i >= 5 && i <= 10) || i == 13 || i == 14)
            expected &= !kprobe && ((i % 2 == 0) == walk);
        else if (i == 1 || i == 3 || i == 4 || i == 12) expected &= kprobe;
        CHECK(g_programs[i].enabled == expected, "rung %d program %s selection", g_rung, g_programs[i].name);
    }
    g_attach_count = 0;
    return g_ladder == 8 || ((g_ladder == 2 || g_ladder == 3 || g_ladder == 6) && g_rung == 1) ||
           (g_ladder == 3 && g_rung == 2) ? -1 : 0;
}
static struct bpf_link* fake_attach(struct bpf_program* prog)
{
    (void)prog;
    if (g_ladder == 9 && g_rung == 1) return NULL;
    if (g_ladder == 9 && g_rung == 2) return NULL;
    if (((g_ladder == 4 || g_ladder == 5) && g_rung == 1) || (g_ladder == 6 && g_rung == 2))
    {
        if (g_attach_count++ == (g_mask == RT_FILE_ALL_BITS ? 1 : 0)) return g_ladder == 5 ? (struct bpf_link*)-22L : NULL;
    }
    ++g_live;
    return (struct bpf_link*)1;
}
static int fake_destroy(struct bpf_link* link) { (void)link; --g_live; ++g_destroyed; return 0; }
static void fake_close(struct bpf_object* obj) { (void)obj; CHECK(g_live == 0, "object closed with live links"); ++g_obj_closed; }
static int fake_map(struct bpf_object* obj, const char* name) { (void)obj; return strcmp(name, "rb") == 0 ? 1 : -1; }
static struct ring_buffer* fake_rb(int fd, ring_buffer_sample_fn cb, void* ctx, const struct ring_buffer_opts* opts)
{ (void)fd; (void)cb; (void)ctx; (void)opts; return (struct ring_buffer*)1; }
static void fake_free(struct ring_buffer* rb) { (void)rb; CHECK(g_live == 0, "ring freed with live links"); }
static int fake_probe(int type, const void* opts) { (void)type; (void)opts; return 1; }

static struct bpf_object* fake_open(const char* path, const struct bpf_object_open_opts* opts)
{
    (void)path;
    (void)opts;
    atomic_fetch_add(&g_objects, 1);
    if (g_ladder)
    {
        CHECK(g_live == 0, "next rung opened with live links");
        CHECK(g_obj_closed == g_rung, "next rung opened before object closed");
        ++g_rung;
        return (struct bpf_object*)1;
    }
    return NULL;
}

static void unused_symbol(void)
{
    abort();
}

void* __wrap_dlsym(void* module, const char* symbol)
{
    (void)module;
    const int count = atomic_fetch_add(&g_symbols, 1);
    if (count == 0)
    {
        pthread_mutex_lock(&g_gate);
        g_entered = 1;
        pthread_cond_broadcast(&g_cond);
        while (!g_release)
        {
            pthread_cond_wait(&g_cond, &g_gate);
        }
        pthread_mutex_unlock(&g_gate);
    }
    if (g_mode == 1 && strcmp(symbol, "bpf_object__load") == 0)
    {
        return NULL;
    }
    if (g_ladder)
    {
#define FAKE(sym, fn) if (strcmp(symbol, sym) == 0) return (void*)fn
        FAKE("bpf_object__load", fake_load);
        FAKE("bpf_object__close", fake_close);
        FAKE("bpf_object__next_program", fake_next);
        FAKE("bpf_program__section_name", fake_section);
        FAKE("bpf_program__name", fake_name);
        FAKE("bpf_program__set_autoload", fake_set);
        FAKE("bpf_program__autoload", fake_autoload);
        FAKE("bpf_program__attach", fake_attach);
        FAKE("bpf_link__destroy", fake_destroy);
        FAKE("bpf_object__find_map_fd_by_name", fake_map);
        FAKE("ring_buffer__new", fake_rb);
        FAKE("ring_buffer__free", fake_free);
        FAKE("libbpf_probe_bpf_map_type", fake_probe);
#undef FAKE
    }
    return strcmp(symbol, "bpf_object__open_file") == 0 ? (void*)fake_open : (void*)unused_symbol;
}

static void capture_log(int level, const char* msg, void* user)
{
    (void)user;
    if (level == RT_LOG_WARN && strstr(msg, "process already bound"))
    {
        /* Only one writer is allowed by the contract; read after join. */
        if (atomic_fetch_add(&g_warnings, 1) == 0)
        {
            snprintf(g_warning, sizeof(g_warning), "%s", msg);
        }
    }
    if (level == RT_LOG_ERROR && strstr(msg, "missing symbol"))
    {
        atomic_fetch_add(&g_errors, 1);
    }
}

static void open_path(const char* path)
{
    struct rt_filter filter = {0};
    filter.type_mask = RT_FILE_ALL_BITS;
    filter.libbpf_path = path;
    filter.log = capture_log;
    if (rt_open(&filter) != NULL)
    {
        abort();
    }
}

static void* worker(void* unused)
{
    (void)unused;
    pthread_barrier_wait(&g_start);
    open_path(g_first);
    pthread_mutex_lock(&g_gate);
    if (!g_release)
    {
        atomic_fetch_add(&g_early, 1);
    }
    pthread_mutex_unlock(&g_gate);
    return NULL;
}

static int scenario(int mode, int reverse)
{
    g_mode = mode;
    g_first = reverse ? "/packaged/libbpf.so" : "/host/libbpf.so";
    g_second = reverse ? "/host/libbpf.so" : "/packaged/libbpf.so";
    pthread_t threads[THREADS];
    CHECK(pthread_barrier_init(&g_start, NULL, THREADS + 1) == 0, "barrier init");
    for (int i = 0; i < THREADS; ++i)
    {
        if (pthread_create(&threads[i], NULL, worker, NULL) != 0)
        {
            abort();
        }
    }
    pthread_barrier_wait(&g_start);
    if (mode != 2)
    {
        pthread_mutex_lock(&g_gate);
        while (!g_entered)
        {
            pthread_cond_wait(&g_cond, &g_gate);
        }
        pthread_mutex_unlock(&g_gate);
        /* Widen the old race window while the first symbol is unresolved. */
        usleep(100000);
    }
    pthread_mutex_lock(&g_gate);
    g_release = 1;
    pthread_cond_broadcast(&g_cond);
    pthread_mutex_unlock(&g_gate);
    for (int i = 0; i < THREADS; ++i)
    {
        CHECK(pthread_join(threads[i], NULL) == 0, "join");
    }
    const int opens = atomic_load(&g_opens);
    const int symbols = atomic_load(&g_symbols);
    CHECK(opens == (mode == 2 ? 3 : mode == 3 ? 2 : 1), "dlopen count %d", opens);
    CHECK(symbols == (mode == 2 ? 0 : mode == 1 ? 2 : 25), "dlsym count %d", symbols);
    CHECK(mode == 2 || g_early == 0, "caller escaped before publication");
    CHECK(g_objects == ((mode == 0 || mode == 3) ? THREADS : 0), "object opens %d", g_objects);
    CHECK(g_closes == (mode == 1 ? 1 : 0), "dlclose count %d", g_closes);
    CHECK(g_errors == (mode == 1 ? 1 : 0), "missing-symbol diagnostics %d", g_errors);
    /* Later consumers cannot change either a successful or failed binding. */
    for (int i = 0; i < THREADS; ++i)
    {
        open_path(g_second);
    }
    open_path(NULL);
    open_path("");
    CHECK(g_opens == opens && g_symbols == symbols, "resolution was retried");
    const int usable = mode == 0 || mode == 3;
    CHECK(g_warnings == usable, "mismatch warnings %d", g_warnings);
    if (usable)
    {
        CHECK(strstr(g_warning, mode == 3 ? g_first : g_second) != NULL, "warning lacks requested path: %s", g_warning);
        CHECK(strstr(g_warning, mode == 3 ? "libbpf.so.1" : g_first) != NULL,
              "warning lacks bound path: %s", g_warning);
    }
    return g_failures != 0;
}

static int ladder_scenario(int ladder, unsigned int mask)
{
    g_ladder = ladder;
    g_mask = mask;
    g_release = 1;
    struct rt_filter filter = {0};
    filter.type_mask = mask;
    filter.log = capture_log;
    rt_handle_t handle = rt_open(&filter);
    CHECK((handle != NULL) == (ladder < 8), "ladder %d mask %u failed", ladder, mask);
    const int rungs = ladder == 3 || ladder == 6 || ladder == 8 ? 3 : ladder == 1 || ladder == 7 ? 1 : 2;
    CHECK(g_rung == rungs, "expected %d rungs, got %d", rungs, g_rung);
    if (ladder >= 4 && ladder <= 6 && mask == RT_FILE_ALL_BITS)
        CHECK(g_destroyed > 0, "partial attachment was not destroyed");
    rt_close(handle);
    CHECK(g_live == 0 && g_obj_closed == g_rung, "final cleanup leaked");
    return g_failures != 0;
}

int main(void)
{
    puts("rt_engine loader tests (no kernel, no root)");
    fflush(stdout);
    for (int mode = 0; mode < 4; ++mode)
    {
        for (int reverse = 0; reverse < 2; ++reverse)
        {
            fflush(stdout);
            const pid_t child = fork();
            if (child == 0)
            {
                alarm(15);
                exit(scenario(mode, reverse));
            }
            int status = 0;
            CHECK(child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                  "mode %d order %d failed (status %d)", mode, reverse, status);
        }
    }
    for (int ladder = 1; ladder <= 9; ++ladder)
    {
        for (unsigned int mask = 2; mask <= RT_FILE_ALL_BITS; mask += 2)
        {
            fflush(stdout);
            const pid_t child = fork();
            if (child == 0)
            {
                alarm(15);
                exit(ladder_scenario(ladder, mask));
            }
            int status = 0;
            CHECK(child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                  "ladder %d mask %u failed (status %d)", ladder, mask, status);
        }
    }
    puts(g_failures ? "loader checks FAILED" : "all loader checks passed");
    return g_failures != 0;
}
