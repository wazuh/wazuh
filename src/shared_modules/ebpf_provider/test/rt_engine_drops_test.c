/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * eBPF Module (#37396) — proves per-cgroup drop attribution, and with it the
 * cgroup_id join every container consumer depends on. Needs a real kernel,
 * cgroup v2, a built rt_file.bpf.o and root; exits 77 (CTest's skip
 * convention) otherwise.
 *
 * The method: create two cgroups, put a child process in each, have both
 * generate far more file events than an unpolled 8 MiB ring buffer can hold,
 * then drain. Two things must come out of that:
 *
 *   1. Loss is attributed per cgroup, not just counted. This is what makes
 *      "re-read what actually lost events" possible instead of "re-baseline
 *      everything because the node lost something".
 *
 *   2. The cgroup_id the kernel reports equals the cgroup directory's INODE.
 *      Every container consumer joins events to containers on that identity —
 *      container_instances stores the inode, the event carries
 *      bpf_get_current_cgroup_id() — and nothing in the tree asserted the two
 *      are the same number. This test does: it compares the drained keys
 *      against stat() of the directories it created.
 */

#include "rt_engine.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SKIP_EXIT 77
#define EVENTS_PER_CHILD 4000 /* an unpolled ring holds ~675 of these records */
#define MAX_REPORTED 64

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

struct reported
{
    unsigned long long cgroup_id;
    unsigned int drops;
};

static struct reported g_reported[MAX_REPORTED];
static unsigned int g_reported_count = 0;

static void collect_drop(unsigned long long cgroup_id, unsigned int drops, void* user)
{
    (void)user;
    if (g_reported_count < MAX_REPORTED)
    {
        g_reported[g_reported_count].cgroup_id = cgroup_id;
        g_reported[g_reported_count].drops = drops;
        ++g_reported_count;
    }
}

static void engine_log(int level, const char* msg, void* user)
{
    (void)user;
    if (level <= RT_LOG_WARN)
    {
        printf("  [engine %d] %s\n", level, msg);
    }
}

/* Create a cgroup v2 directory and return its inode, or 0 on failure. */
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
    const int ok = (fclose(f) == 0);
    return ok;
}

/* Generate file-creation events, which the parent is deliberately not polling
 * for, so the ring buffer overflows and the kernel side records drops. */
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

int main(int argc, char** argv)
{
    const char* obj = (argc > 1) ? argv[1] : "rt_file.bpf.o";

    const char* cg_a = "/sys/fs/cgroup/rt_drop_a";
    const char* cg_b = "/sys/fs/cgroup/rt_drop_b";
    const char* dir_a = "/tmp/rt_drop_a";
    const char* dir_b = "/tmp/rt_drop_b";

    printf("rt_engine per-cgroup drop attribution test (object: %s)\n", obj);

    struct stat st;
    if (stat("/sys/fs/cgroup/cgroup.controllers", &st) != 0)
    {
        printf("not a cgroup v2 unified hierarchy — skipping\n");
        return SKIP_EXIT;
    }

    const unsigned long long inode_a = make_cgroup(cg_a);
    const unsigned long long inode_b = make_cgroup(cg_b);
    if (inode_a == 0 || inode_b == 0)
    {
        printf("could not create test cgroups (need root) — skipping\n");
        if (inode_a)
        {
            rmdir(cg_a);
        }
        if (inode_b)
        {
            rmdir(cg_b);
        }
        return SKIP_EXIT;
    }
    printf("  cgroup A inode: %llu\n  cgroup B inode: %llu\n", inode_a, inode_b);

    struct rt_filter filter;
    memset(&filter, 0, sizeof(filter));
    filter.type_mask = RT_FILE_ALL_BITS;
    filter.bpf_obj_path = obj;
    filter.log = engine_log;

    const rt_handle_t h = rt_open(&filter);
    if (!h)
    {
        printf("rt_open failed — skipping\n");
        rmdir(cg_a);
        rmdir(cg_b);
        return SKIP_EXIT;
    }

    /* Deliberately never call rt_poll: the ring fills, and every further event
     * is a drop the kernel side must attribute to its own cgroup. */
    for (int child = 0; child < 2; ++child)
    {
        const pid_t pid = fork();
        if (pid == 0)
        {
            const char* cg = child == 0 ? cg_a : cg_b;
            const char* dir = child == 0 ? dir_a : dir_b;
            if (!join_cgroup(cg))
            {
                _exit(2);
            }
            generate_events(dir);
            _exit(0);
        }
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

    if (child_failures)
    {
        printf("%d child(ren) could not join a cgroup — skipping\n", child_failures);
        rt_close(h);
        rm_tree(dir_a);
        rm_tree(dir_b);
        rmdir(cg_a);
        rmdir(cg_b);
        return SKIP_EXIT;
    }

    const int reported = rt_drain_drops(h, collect_drop, NULL);
    printf("  rt_drain_drops reported %d cgroup(s)\n", reported);

    CHECK(reported > 0, "no cgroup was reported as having lost events, but the ring was never polled "
                        "while two processes generated %d events each",
          EVENTS_PER_CHILD);

    unsigned int drops_a = 0;
    unsigned int drops_b = 0;
    for (unsigned int i = 0; i < g_reported_count; ++i)
    {
        printf("    cgroup_id=%llu drops=%u%s\n", g_reported[i].cgroup_id, g_reported[i].drops,
               g_reported[i].cgroup_id == inode_a ? "  <- A"
                                                  : (g_reported[i].cgroup_id == inode_b ? "  <- B" : ""));
        if (g_reported[i].cgroup_id == inode_a)
        {
            drops_a = g_reported[i].drops;
        }
        if (g_reported[i].cgroup_id == inode_b)
        {
            drops_b = g_reported[i].drops;
        }
    }

    /* The attribution claim. */
    CHECK(drops_a > 0, "cgroup A (inode %llu) generated %d events against an unpolled ring but was not "
                       "reported as losing any",
          inode_a, EVENTS_PER_CHILD);
    CHECK(drops_b > 0, "cgroup B (inode %llu) generated %d events against an unpolled ring but was not "
                       "reported as losing any",
          inode_b, EVENTS_PER_CHILD);

    /* The identity claim: bpf_get_current_cgroup_id() == the cgroup directory
     * inode. If this fails, every container consumer's join key is wrong. */
    CHECK(drops_a > 0 && drops_b > 0,
          "cgroup_id does not match the cgroup directory inode — the container join key is not what "
          "container_instances stores");

    /* A second drain must report nothing: reporting clears. */
    g_reported_count = 0;
    const int second = rt_drain_drops(h, collect_drop, NULL);
    CHECK(second == 0, "a second drain reported %d cgroup(s); draining must clear what it reports", second);

    rt_close(h);
    rm_tree(dir_a);
    rm_tree(dir_b);
    rmdir(cg_a);
    rmdir(cg_b);

    if (g_failures != 0)
    {
        printf("\n%d check(s) FAILED\n", g_failures);
        return 1;
    }
    printf("\nall checks passed\n");
    return 0;
}
