/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * eBPF Module (#37396) — proves RT_SKIP_PROC_CONTEXT suppresses exactly the
 * process-context fields and nothing else. Needs a real kernel, a built
 * rt_file.bpf.o and root; exits 77 otherwise.
 *
 * Why this matters: the record is shared by consumers that read very different
 * parts of it. cwd, parent_cwd and parent_comm exist for host FIM whodata's
 * "who" attribution and cost two full dentry walks per event to produce. A
 * container consumer routes on cgroup_id and filename and reads none of them.
 * Without a per-handle opt-out the cheaper consumer subsidises the dearer one
 * on every event, and on the kprobe path — the majority configuration — those
 * walks are the dominant per-event cost.
 *
 * Both directions are asserted, because only testing the skip would pass just
 * as happily against a program that never populated the fields at all:
 *
 *   1. Default handle (skip_mask 0): cwd is populated.
 *   2. Skipping handle: cwd, parent_cwd and parent_comm are all empty.
 *   3. The skipping handle still delivers what it does read — filename and
 *      pid — so the opt-out cannot be mistaken for "fewer events".
 */

#include "rt_engine.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SKIP_EXIT 77
#define EVENTS 60

static int g_failures = 0;

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

struct counts
{
    const char* marker;
    unsigned long seen;
    unsigned long with_cwd;
    unsigned long with_parent_cwd;
    unsigned long with_parent_comm;
    unsigned long with_filename;
    unsigned long with_pid;
};

static void on_event(const struct rt_file_event* ev, void* user)
{
    struct counts* c = (struct counts*)user;

    /* Only this test's own files; the engine sees the whole host. */
    if (strstr(ev->filename, c->marker) == NULL)
    {
        return;
    }

    ++c->seen;
    if (ev->cwd[0] != '\0')
    {
        ++c->with_cwd;
    }
    if (ev->parent_cwd[0] != '\0')
    {
        ++c->with_parent_cwd;
    }
    if (ev->parent_comm[0] != '\0')
    {
        ++c->with_parent_comm;
    }
    if (ev->filename[0] != '\0')
    {
        ++c->with_filename;
    }
    if (ev->pid != 0)
    {
        ++c->with_pid;
    }
}

static void engine_log(int level, const char* msg, void* user)
{
    (void)user;
    if (level <= RT_LOG_INFO)
    {
        printf("  [engine %d] %s\n", level, msg);
    }
}

static void generate_events(const char* dir)
{
    for (int i = 0; i < EVENTS; ++i)
    {
        char path[512];
        snprintf(path, sizeof(path), "%s/f%d", dir, i);
        const int fd = creat(path, 0600);
        if (fd >= 0)
        {
            close(fd);
            unlink(path);
        }
    }
}

/* Opens a handle with `skip`, drives events, and reports what arrived. */
static int run_arm(const char* obj, unsigned int skip, const char* dir, const char* marker, struct counts* out)
{
    struct rt_filter filter;
    memset(&filter, 0, sizeof(filter));
    filter.type_mask = RT_FILE_OPEN_BIT;
    filter.bpf_obj_path = obj;
    filter.log = engine_log;
    filter.skip_mask = skip;

    rt_handle_t h = rt_open(&filter);
    if (!h)
    {
        return 0;
    }

    memset(out, 0, sizeof(*out));
    out->marker = marker;

    generate_events(dir);
    for (int i = 0; i < 20 && out->seen < EVENTS; ++i)
    {
        rt_poll(h, on_event, out, 50);
    }

    rt_close(h);
    return 1;
}

int main(int argc, char** argv)
{
    const char* obj = (argc > 1) ? argv[1] : "rt_file.bpf.o";

    if (geteuid() != 0)
    {
        printf("SKIP: needs root to load BPF\n");
        return SKIP_EXIT;
    }

    char dir[] = "/tmp/rt_skip_testXXXXXX";
    if (!mkdtemp(dir))
    {
        printf("SKIP: could not create a scratch directory\n");
        return SKIP_EXIT;
    }

    const char* marker = strrchr(dir, '/') + 1;

    struct counts dflt;
    struct counts skipped;

    if (!run_arm(obj, 0, dir, marker, &dflt))
    {
        rmdir(dir);
        printf("SKIP: rt_open failed (no BPF object, or kernel without support)\n");
        return SKIP_EXIT;
    }
    if (!run_arm(obj, RT_SKIP_PROC_CONTEXT, dir, marker, &skipped))
    {
        rmdir(dir);
        printf("SKIP: rt_open failed on the skipping arm\n");
        return SKIP_EXIT;
    }

    rmdir(dir);

    printf("default  : seen=%lu cwd=%lu parent_cwd=%lu parent_comm=%lu filename=%lu pid=%lu\n",
           dflt.seen, dflt.with_cwd, dflt.with_parent_cwd, dflt.with_parent_comm, dflt.with_filename,
           dflt.with_pid);
    printf("skipping : seen=%lu cwd=%lu parent_cwd=%lu parent_comm=%lu filename=%lu pid=%lu\n",
           skipped.seen, skipped.with_cwd, skipped.with_parent_cwd, skipped.with_parent_comm,
           skipped.with_filename, skipped.with_pid);

    /* 1. The default handle must populate the fields — otherwise the skip
     *    assertions below would pass against a program that never filled them. */
    CHECK(dflt.seen > 0, "no events seen on the default handle — the test proved nothing");
    CHECK(dflt.with_cwd > 0, "default handle produced no cwd; the negative control is not valid");

    /* 2. Skipping must empty exactly the process-context fields. */
    CHECK(skipped.seen > 0, "no events seen on the skipping handle");
    CHECK(skipped.with_cwd == 0, "cwd was populated on %lu event(s) despite RT_SKIP_PROC_CONTEXT",
          skipped.with_cwd);
    CHECK(skipped.with_parent_cwd == 0, "parent_cwd was populated on %lu event(s) despite RT_SKIP_PROC_CONTEXT",
          skipped.with_parent_cwd);
    CHECK(skipped.with_parent_comm == 0, "parent_comm was populated on %lu event(s) despite RT_SKIP_PROC_CONTEXT",
          skipped.with_parent_comm);

    /* 3. ...and nothing else. An opt-out that quietly dropped events or blanked
     *    the fields the consumer actually reads would be worse than the cost. */
    CHECK(skipped.with_filename == skipped.seen, "filename was empty on %lu skipped event(s)",
          skipped.seen - skipped.with_filename);
    CHECK(skipped.with_pid == skipped.seen, "pid was zero on %lu skipped event(s)",
          skipped.seen - skipped.with_pid);

    if (g_failures)
    {
        printf("\n%d failure(s)\n", g_failures);
        return 1;
    }

    printf("\nALL OK\n");
    return 0;
}
