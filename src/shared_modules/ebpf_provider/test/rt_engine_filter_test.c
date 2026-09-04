/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * eBPF Module (#37396) — proves in-kernel cgroup filtering delivers exactly
 * the allowlisted cgroups' events and nothing else. Needs a real kernel,
 * cgroup v2, a built rt_file.bpf.o and root; exits 77 otherwise.
 *
 * The method: two cgroups, one allowlisted and one not, each with a child
 * process generating file events, and a parent that polls. Three properties
 * have to hold, and only the third is obvious:
 *
 *   1. The allowlisted cgroup's events arrive.
 *   2. The other cgroup's events do NOT — this is the whole point, and it is
 *      what turns a whole-host firehose into a container-scoped stream.
 *   3. A filtered-out event is not counted as a drop. Drops mean "the consumer
 *      wanted this and lost it"; a filter miss means "the consumer never
 *      asked". Conflating them would make every unmonitored container's
 *      activity look like loss and, under the planned escalation, re-baseline
 *      everything forever.
 */

#include "rt_engine.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SKIP_EXIT 77
#define EVENTS_PER_CHILD 300 /* well under the ring's ~675-record capacity */

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
    unsigned long long allowed_cgroup;
    unsigned long long denied_cgroup;
    unsigned long allowed_events;
    unsigned long denied_events;
    unsigned long other_events;
};

static void on_event(const struct rt_file_event* ev, void* user)
{
    struct counts* c = (struct counts*)user;
    if (ev->cgroup_id == c->allowed_cgroup)
    {
        ++c->allowed_events;
    }
    else if (ev->cgroup_id == c->denied_cgroup)
    {
        ++c->denied_events;
    }
    else
    {
        ++c->other_events;
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

static unsigned long long make_cgroup(const char* path)
{
    if (mkdir(path, 0755) != 0)
    {
        return 0;
    }
    struct stat st;
    if (stat(path, &st) != 0)
    {
        rmdir(path);
        return 0;
    }
    return (unsigned long long)st.st_ino;
}

static int join_cgroup(const char* path)
{
    char procs[512];
    snprintf(procs, sizeof(procs), "%s/cgroup.procs", path);
    FILE* f = fopen(procs, "w");
    if (!f)
    {
        return 0;
    }
    fprintf(f, "%d\n", (int)getpid());
    return fclose(f) == 0;
}

static void generate_events(const char* dir)
{
    mkdir(dir, 0700);
    for (int i = 0; i < EVENTS_PER_CHILD; ++i)
    {
        char path[512];
        snprintf(path, sizeof(path), "%s/f%d", dir, i);
        const int fd = creat(path, 0600);
        if (fd >= 0)
        {
            close(fd);
        }
    }
}

static void rm_tree(const char* dir)
{
    DIR* d = opendir(dir);
    if (d)
    {
        const struct dirent* e = NULL;
        while ((e = readdir(d)) != NULL)
        {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            {
                continue;
            }
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
            unlink(path);
        }
        closedir(d);
    }
    rmdir(dir);
}

static void drain(rt_handle_t h, struct counts* c, int rounds)
{
    for (int i = 0; i < rounds; ++i)
    {
        rt_poll(h, on_event, c, 200);
    }
}

static void note_drop(unsigned long long cgroup_id, unsigned int drops, void* user)
{
    unsigned long* total = (unsigned long*)user;
    *total += drops;
    printf("    drops: cgroup_id=%llu count=%u\n", cgroup_id, drops);
}

int main(int argc, char** argv)
{
    const char* obj = (argc > 1) ? argv[1] : "rt_file.bpf.o";

    const char* cg_allow = "/sys/fs/cgroup/rt_filt_allow";
    const char* cg_deny = "/sys/fs/cgroup/rt_filt_deny";
    const char* dir_allow = "/tmp/rt_filt_allow";
    const char* dir_deny = "/tmp/rt_filt_deny";

    printf("rt_engine in-kernel cgroup filter test (object: %s)\n", obj);

    struct stat st;
    if (stat("/sys/fs/cgroup/cgroup.controllers", &st) != 0)
    {
        printf("not a cgroup v2 unified hierarchy — skipping\n");
        return SKIP_EXIT;
    }

    const unsigned long long inode_allow = make_cgroup(cg_allow);
    const unsigned long long inode_deny = make_cgroup(cg_deny);
    if (inode_allow == 0 || inode_deny == 0)
    {
        printf("could not create test cgroups (need root) — skipping\n");
        rmdir(cg_allow);
        rmdir(cg_deny);
        return SKIP_EXIT;
    }
    printf("  allowlisted cgroup: %llu\n  excluded cgroup   : %llu\n", inode_allow, inode_deny);

    struct rt_filter filter;
    memset(&filter, 0, sizeof(filter));
    filter.type_mask = RT_FILE_ALL_BITS;
    filter.bpf_obj_path = obj;
    filter.log = engine_log;
    filter.cgroup_mode = RT_CGROUP_MODE_ALLOWLIST;

    const rt_handle_t h = rt_open(&filter);
    if (!h)
    {
        printf("rt_open failed — skipping\n");
        rmdir(cg_allow);
        rmdir(cg_deny);
        return SKIP_EXIT;
    }

    CHECK(rt_allow_cgroup(h, inode_allow) == 0, "rt_allow_cgroup failed for the allowlisted cgroup");

    struct counts c;
    memset(&c, 0, sizeof(c));
    c.allowed_cgroup = inode_allow;
    c.denied_cgroup = inode_deny;

    for (int child = 0; child < 2; ++child)
    {
        const pid_t pid = fork();
        if (pid == 0)
        {
            const char* cg = child == 0 ? cg_allow : cg_deny;
            const char* dir = child == 0 ? dir_allow : dir_deny;
            if (!join_cgroup(cg))
            {
                _exit(2);
            }
            generate_events(dir);
            _exit(0);
        }
        /* Drain between children so the ring cannot fill and confuse a filter
         * miss with a genuine drop. */
        drain(h, &c, 2);
    }

    int child_failures = 0;
    for (int child = 0; child < 2; ++child)
    {
        int status = 0;
        wait(&status);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            ++child_failures;
        }
    }
    drain(h, &c, 5);

    if (child_failures)
    {
        printf("%d child(ren) could not join a cgroup — skipping\n", child_failures);
        rt_close(h);
        rm_tree(dir_allow);
        rm_tree(dir_deny);
        rmdir(cg_allow);
        rmdir(cg_deny);
        return SKIP_EXIT;
    }

    printf("  events from the allowlisted cgroup: %lu\n", c.allowed_events);
    printf("  events from the excluded cgroup   : %lu\n", c.denied_events);
    printf("  events from every other cgroup    : %lu\n", c.other_events);

    CHECK(c.allowed_events > 0, "the allowlisted cgroup created %d files but produced no events",
          EVENTS_PER_CHILD);
    CHECK(c.denied_events == 0, "%lu event(s) arrived from the cgroup that was NOT allowlisted — the "
                                "in-kernel filter is not filtering",
          c.denied_events);
    CHECK(c.other_events == 0, "%lu event(s) arrived from cgroups outside the allowlist entirely",
          c.other_events);

    /* Property 3: filtering is not loss. */
    unsigned long dropped_total = 0;
    rt_drain_drops(h, note_drop, &dropped_total);
    CHECK(dropped_total == 0, "%lu event(s) were counted as dropped, but the excluded cgroup's events "
                              "were filtered rather than lost — a filter miss must not read as loss",
          dropped_total);

    /* And the mode is a live switch: back to ALL, the excluded cgroup appears. */
    CHECK(rt_set_cgroup_mode(h, RT_CGROUP_MODE_ALL) == 0, "rt_set_cgroup_mode(ALL) failed");
    memset(&c.allowed_events, 0, sizeof(c.allowed_events));
    c.denied_events = 0;
    c.other_events = 0;

    const pid_t pid = fork();
    if (pid == 0)
    {
        if (!join_cgroup(cg_deny))
        {
            _exit(2);
        }
        generate_events(dir_deny);
        _exit(0);
    }
    drain(h, &c, 4);
    int status = 0;
    wait(&status);
    drain(h, &c, 4);

    printf("  after switching to mode ALL, events from the previously excluded cgroup: %lu\n",
           c.denied_events);
    CHECK(c.denied_events > 0, "switching to RT_CGROUP_MODE_ALL did not restore delivery, so the mode "
                               "is not a live switch");

    rt_close(h);
    rm_tree(dir_allow);
    rm_tree(dir_deny);
    rmdir(cg_allow);
    rmdir(cg_deny);

    if (g_failures != 0)
    {
        printf("\n%d check(s) FAILED\n", g_failures);
        return 1;
    }
    printf("\nall checks passed\n");
    return 0;
}
