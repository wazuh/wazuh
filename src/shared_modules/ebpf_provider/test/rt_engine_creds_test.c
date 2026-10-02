/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * eBPF Module (#37396) — proves the event's credential fields carry the uid
 * and gid of the process that touched the file, the right way round. Needs a
 * real kernel, a built rt_file.bpf.o and root; exits 77 otherwise.
 *
 * This test exists because of a defect that shipped undetected.
 * bpf_get_current_uid_gid() packs the pair as (gid << 32 | uid); the program
 * read the halves the other way round, so every event reported its gid as its
 * uid and its uid as its gid. Nothing failed, because the only consumer at the
 * time — the container event router — discards both fields. Host FIM whodata
 * maps them straight onto an alert's user and group attribution, so the first
 * consumer to read them would have mis-attributed every file change on the
 * host, plausibly enough that a root-owned file (uid 0, gid 0) still looked
 * correct.
 *
 * The method: a child drops to a uid and gid that are deliberately DIFFERENT
 * from each other, then touches a file. A swap is only detectable when the two
 * differ, which is why this cannot be tested as root and why the chosen values
 * are not a matching pair.
 */

#include "rt_engine.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SKIP_EXIT 77
#define EVENTS 200

/* Deliberately not a matching pair: with uid == gid a swap is invisible.
 * 'nobody' on Debian/Ubuntu is 65534:65534, which is exactly the trap. */
#define TEST_UID 65534u
#define TEST_GID 100u

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
    unsigned long matched;    /* uid == TEST_UID && gid == TEST_GID */
    unsigned long swapped;    /* uid == TEST_GID && gid == TEST_UID */
    unsigned long other;      /* anything else, including this process's own */
    unsigned int  first_uid;
    unsigned int  first_gid;
    int           seen_any;
};

static void on_event(const struct rt_file_event* ev, void* user)
{
    struct counts* c = (struct counts*)user;

    /* Only the child's events are interesting; the poller and everything else
     * on the host run as root and would drown the signal. */
    if (ev->uid != TEST_UID && ev->uid != TEST_GID)
    {
        return;
    }

    if (!c->seen_any)
    {
        c->first_uid = ev->uid;
        c->first_gid = ev->gid;
        c->seen_any = 1;
    }

    if (ev->uid == TEST_UID && ev->gid == TEST_GID)
    {
        ++c->matched;
    }
    else if (ev->uid == TEST_GID && ev->gid == TEST_UID)
    {
        ++c->swapped;
    }
    else
    {
        ++c->other;
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

static void generate_events_as_test_user(const char* dir)
{
    /* setgid before setuid: the reverse order drops the privilege needed for
     * the second call. */
    if (setgid(TEST_GID) != 0 || setuid(TEST_UID) != 0)
    {
        _exit(1);
    }

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
    _exit(0);
}

int main(int argc, char** argv)
{
    const char* obj = (argc > 1) ? argv[1] : "rt_file.bpf.o";

    if (geteuid() != 0)
    {
        printf("SKIP: needs root to load BPF and to drop to a test uid\n");
        return SKIP_EXIT;
    }

    char dir[] = "/tmp/rt_creds_testXXXXXX";
    if (!mkdtemp(dir))
    {
        printf("SKIP: could not create a scratch directory\n");
        return SKIP_EXIT;
    }
    /* The child runs as TEST_UID and has to be able to create files here. */
    if (chown(dir, TEST_UID, TEST_GID) != 0 || chmod(dir, 0700) != 0)
    {
        rmdir(dir);
        printf("SKIP: could not hand the scratch directory to the test user\n");
        return SKIP_EXIT;
    }

    struct rt_filter filter;
    memset(&filter, 0, sizeof(filter));
    filter.type_mask = RT_FILE_OPEN_BIT;
    filter.bpf_obj_path = obj;
    filter.log = engine_log;

    rt_handle_t h = rt_open(&filter);
    if (!h)
    {
        rmdir(dir);
        printf("SKIP: rt_open failed (no BPF object, or kernel without support)\n");
        return SKIP_EXIT;
    }

    struct counts c;
    memset(&c, 0, sizeof(c));

    const pid_t child = fork();
    if (child == 0)
    {
        generate_events_as_test_user(dir);
    }

    /* Poll while the child works, then drain what is left in the ring. */
    for (int i = 0; i < 40 && !c.seen_any; ++i)
    {
        rt_poll(h, on_event, &c, 100);
    }
    int status = 0;
    waitpid(child, &status, 0);
    for (int i = 0; i < 10; ++i)
    {
        rt_poll(h, on_event, &c, 50);
    }

    rt_close(h);
    rmdir(dir);

    printf("events from the test user: matched=%lu swapped=%lu other=%lu\n", c.matched, c.swapped, c.other);

    CHECK(c.seen_any, "no event was seen from uid %u — the test proved nothing", TEST_UID);

    if (c.seen_any)
    {
        CHECK(c.swapped == 0,
              "uid and gid are swapped: first event reported uid=%u gid=%u, expected uid=%u gid=%u",
              c.first_uid,
              c.first_gid,
              TEST_UID,
              TEST_GID);
        CHECK(c.matched > 0, "no event carried the expected uid=%u gid=%u pair", TEST_UID, TEST_GID);
    }

    if (g_failures)
    {
        printf("\n%d failure(s)\n", g_failures);
        return 1;
    }

    printf("\nALL OK\n");
    return 0;
}
