/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Absolute path regression test. Needs root, bind mounts and a built BPF
 * object on a real kernel; exits 77 when those prerequisites are unavailable.
 *
 * Measured pre-fix outputs on Ubuntu 24.04.4 / 6.17.0-35-generic:
 * event   fixture  pre-fix                         -> correct
 * RENAME  flat     /tmp/p0scn/flat                  -> /tmp/p0scn/flat/b.txt
 * RENAME  nested   /tmp/p0scn/deepsrc               -> /tmp/p0scn/lower/mid/deep/m.txt
 * ATTR    nested   /tmp/p0scn/deepsrc/n.txt         -> /tmp/p0scn/lower/mid/deep/n.txt
 * UNLINK  nested   /tmp/p0scn/deepsrc/m.txt         -> /tmp/p0scn/lower/mid/deep/m.txt
 * OPEN    nested   /tmp/p0scn/upper/deep/n.txt      -> /tmp/p0scn/lower/mid/deep/n.txt
 *
 * P3b rename expectations now assert two events per fixture, in either order:
 * RENAME  flat     source /tmp/p0scn/flat/a.txt, destination /tmp/p0scn/flat/b.txt
 * RENAME  nested   source /tmp/p0scn/lower/mid/deep/n.txt,
 *                 destination /tmp/p0scn/lower/mid/deep/m.txt
 * The verified P3b aarch64 6.8.0-139-generic run had BPF LSM active: rename
 * paths came from lsm/path_rename _dpath programs via bpf_d_path. Earlier runs
 * on the same host without bpf in the active LSM list exercised the kprobe
 * walker. This test checks whichever rung the host selects.
 *
 * Rename must include both basenames; every nested operation must retain BOTH
 * mount crossings rather than exposing either backing directory.
 */

#include "rt_engine.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define SKIP_EXIT 77
#define SEEN_PATHS 8

static int g_failures = 0;

#define CHECK(cond, ...)                                      \
    do                                                        \
    {                                                         \
        if (!(cond))                                          \
        {                                                     \
            ++g_failures;                                     \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);         \
            printf(__VA_ARGS__);                              \
            printf("\n");                                     \
        }                                                     \
    } while (0)

struct expectation
{
    const char* fixture;
    const char* operation;
    unsigned short type;
    const char* expected;
    const char* source;
    int source_matched;
    int matched;
    int wrong;
    unsigned int seen_count;
    char seen[SEEN_PATHS][RT_PATH_MAX];
};

struct observations
{
    const char* root;
    const char* flat;
    struct expectation expectations[8];
};

/* Accept the directory itself too: the old rename bug returned that path. */
static int under(const char* path, const char* dir)
{
    const size_t n = strlen(dir);
    return strncmp(path, dir, n) == 0 && (path[n] == '/' || path[n] == '\0');
}

static void on_event(const struct rt_file_event* ev, void* user)
{
    struct observations* observations = user;
    char path[RT_PATH_MAX];
    /* The ring's event storage is only valid during this call. */
    memcpy(path, ev->filename, sizeof(path));
    path[sizeof(path) - 1] = '\0';
    if (!under(path, observations->root))
    {
        return;
    }
    const int nested = !under(path, observations->flat);
    for (int i = nested ? 4 : 0; i < (nested ? 8 : 4); ++i)
    {
        struct expectation* e = &observations->expectations[i];
        if (ev->event_type != e->type)
        {
            continue;
        }
        if (strcmp(path, e->expected) == 0)
        {
            e->matched = 1;
        }
        else if (e->source && strcmp(path, e->source) == 0)
        {
            e->source_matched = 1;
        }
        else
        {
            e->wrong = 1;
        }
        unsigned int j;
        for (j = 0; j < e->seen_count; ++j)
        {
            if (strcmp(path, e->seen[j]) == 0)
            {
                break;
            }
        }
        if (j == e->seen_count && j < SEEN_PATHS)
        {
            memcpy(e->seen[e->seen_count++], path, sizeof(path));
        }
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

static int exercise(const char* source, const char* destination)
{
    const int fd = open(source, O_WRONLY | O_CREAT | O_EXCL, 0600);
    CHECK(fd >= 0, "create %s: %s", source, strerror(errno));
    if (fd < 0)
    {
        return 0;
    }
    CHECK(close(fd) == 0, "close %s: %s", source, strerror(errno));
    if (chmod(source, 0640) != 0 || rename(source, destination) != 0 || unlink(destination) != 0)
    {
        CHECK(0, "chmod/rename/unlink %s -> %s: %s", source, destination, strerror(errno));
        return 0;
    }
    return 1;
}

static int monotonic_ms(long long* value)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    {
        CHECK(0, "clock_gettime: %s", strerror(errno));
        return 0;
    }
    *value = (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
    return 1;
}

int main(int argc, char** argv)
{
    const char* obj = argc > 1 ? argv[1] : "rt_file.bpf.o";
    printf("rt_engine absolute paths test (object: %s)\n", obj);
    if (geteuid() != 0)
    {
        printf("SKIP: needs root to load BPF and create bind mounts\n");
        return SKIP_EXIT;
    }

    char root[] = "/tmp/rt_paths_testXXXXXX";
    if (!mkdtemp(root))
    {
        printf("SKIP: could not create a scratch directory: %s\n", strerror(errno));
        return SKIP_EXIT;
    }

    enum { FLAT, LOWER, MID, UPPER, DEEPSRC, DEEP, FLAT_A, FLAT_B, NEST_A, NEST_B, PATHS };
    const char* suffixes[PATHS] = {
        "/flat", "/lower", "/lower/mid", "/upper", "/deepsrc", "/lower/mid/deep",
        "/flat/a.txt", "/flat/b.txt", "/lower/mid/deep/n.txt", "/lower/mid/deep/m.txt"
    };
    char paths[PATHS][RT_PATH_MAX];
    for (int i = 0; i < PATHS; ++i)
    {
        snprintf(paths[i], sizeof(paths[i]), "%s%s", root, suffixes[i]);
    }
    int result = 1;
    int mid_mounted = 0;
    int deep_mounted = 0;
    rt_handle_t h = NULL;
    for (int i = FLAT; i <= DEEPSRC; ++i)
    {
        if (mkdir(paths[i], 0700) != 0)
        {
            CHECK(0, "mkdir %s: %s", paths[i], strerror(errno));
            goto cleanup;
        }
    }
    if (mount(paths[UPPER], paths[MID], NULL, MS_BIND, NULL) != 0)
    {
        printf("SKIP: first bind mount unavailable: %s\n", strerror(errno));
        result = SKIP_EXIT;
        goto cleanup;
    }
    mid_mounted = 1;
    if (mkdir(paths[DEEP], 0700) != 0)
    {
        CHECK(0, "mkdir %s: %s", paths[DEEP], strerror(errno));
        goto cleanup;
    }
    if (mount(paths[DEEPSRC], paths[DEEP], NULL, MS_BIND, NULL) != 0)
    {
        printf("SKIP: second bind mount unavailable: %s\n", strerror(errno));
        result = SKIP_EXIT;
        goto cleanup;
    }
    deep_mounted = 1;

    struct rt_filter filter;
    memset(&filter, 0, sizeof(filter));
    filter.type_mask = RT_FILE_ALL_BITS;
    filter.cgroup_mode = RT_CGROUP_MODE_ALL;
    filter.bpf_obj_path = obj;
    filter.log = engine_log;
    h = rt_open(&filter);
    if (!h)
    {
        printf("SKIP: rt_open failed (no BPF object, privilege, or kernel support)\n");
        result = SKIP_EXIT;
        goto cleanup;
    }

    struct observations observations = {
        .root = root,
        .flat = paths[FLAT],
        .expectations = {
            { .fixture = "flat", .operation = "OPEN", .type = RT_EV_FILE_OPEN, .expected = paths[FLAT_A] },
            { .fixture = "flat", .operation = "ATTR", .type = RT_EV_FILE_ATTR, .expected = paths[FLAT_A] },
            { .fixture = "flat", .operation = "RENAME", .type = RT_EV_FILE_RENAME, .expected = paths[FLAT_B],
              .source = paths[FLAT_A] },
            { .fixture = "flat", .operation = "UNLINK", .type = RT_EV_FILE_UNLINK, .expected = paths[FLAT_B] },
            { .fixture = "nested", .operation = "OPEN", .type = RT_EV_FILE_OPEN, .expected = paths[NEST_A] },
            { .fixture = "nested", .operation = "ATTR", .type = RT_EV_FILE_ATTR, .expected = paths[NEST_A] },
            { .fixture = "nested", .operation = "RENAME", .type = RT_EV_FILE_RENAME, .expected = paths[NEST_B],
              .source = paths[NEST_A] },
            { .fixture = "nested", .operation = "UNLINK", .type = RT_EV_FILE_UNLINK, .expected = paths[NEST_B] }
        }
    };
    const int flat_ok = exercise(paths[FLAT_A], paths[FLAT_B]);
    const int nested_ok = exercise(paths[NEST_A], paths[NEST_B]);
    if (!flat_ok || !nested_ok)
    {
        goto cleanup;
    }

    /* Drain for a fixed deadline even if all matches arrive early, so a later
     * wrong alias cannot be hidden by a correct event. No ordering/count rule. */
    long long now;
    if (!monotonic_ms(&now))
    {
        goto cleanup;
    }
    const long long deadline = now + 4000;
    while (now < deadline)
    {
        const int timeout = deadline - now < 100 ? (int)(deadline - now) : 100;
        const int rc = rt_poll(h, on_event, &observations, timeout);
        if (rc < 0 && rc != -EINTR)
        {
            CHECK(0, "rt_poll failed: %d", rc);
            break;
        }
        if (!monotonic_ms(&now))
        {
            break;
        }
    }
    for (int i = 0; i < 8; ++i)
    {
        const struct expectation* e = &observations.expectations[i];
        printf("  %s %s: expected %s\n", e->fixture, e->operation, e->expected);
        if (e->source)
        {
            printf("    expected source %s (either order)\n", e->source);
            CHECK(e->source_matched, "%s %s source outstanding at poll deadline", e->fixture, e->operation);
        }
        CHECK(e->matched, "%s %s outstanding at poll deadline", e->fixture, e->operation);
        CHECK(!e->wrong, "%s %s reported an incorrect absolute path", e->fixture, e->operation);
        if (!e->seen_count)
        {
            printf("    seen: (none)\n");
        }
        for (unsigned int j = 0; j < e->seen_count; ++j)
        {
            printf("    seen: %s\n", e->seen[j]);
        }
    }
    result = g_failures ? 1 : 0;

cleanup:
    if (h)
    {
        rt_close(h);
    }
    /* Detach deepest first, including when setup or an operation failed.
     * Never remove anything through a mount that could not be detached. */
    if (deep_mounted)
    {
        const int rc = umount2(paths[DEEP], MNT_DETACH);
        CHECK(rc == 0, "detach %s: %s", paths[DEEP], strerror(errno));
        deep_mounted = rc != 0;
    }
    if (mid_mounted)
    {
        const int rc = umount2(paths[MID], MNT_DETACH);
        CHECK(rc == 0, "detach %s: %s", paths[MID], strerror(errno));
        mid_mounted = rc != 0;
    }
    if (!mid_mounted && !deep_mounted)
    {
        char backing[RT_PATH_MAX];
        unlink(paths[FLAT_A]);
        unlink(paths[FLAT_B]);
        snprintf(backing, sizeof(backing), "%s/deepsrc/n.txt", root);
        unlink(backing);
        snprintf(backing, sizeof(backing), "%s/deepsrc/m.txt", root);
        unlink(backing);
        snprintf(backing, sizeof(backing), "%s/upper/deep", root);
        if (rmdir(backing) != 0 && errno != ENOENT)
        {
            CHECK(0, "rmdir %s: %s", backing, strerror(errno));
        }
        for (int i = DEEPSRC; i >= FLAT; --i)
        {
            if (rmdir(paths[i]) != 0 && errno != ENOENT)
            {
                CHECK(0, "rmdir %s: %s", paths[i], strerror(errno));
            }
        }
        CHECK(rmdir(root) == 0, "rmdir %s: %s", root, strerror(errno));
    }
    if (g_failures)
    {
        printf("\n%d failure(s)\n", g_failures);
        return 1;
    }
    if (result == 0)
    {
        printf("\nALL OK\n");
    }
    return result;
}
