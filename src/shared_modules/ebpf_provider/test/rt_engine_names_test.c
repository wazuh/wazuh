/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Proves the in-kernel file-name filter delivers the listed names and nothing
 * else. Needs a real kernel, a built rt_file.bpf.o and root; exits 77 otherwise.
 *
 * The handle runs in RT_CGROUP_MODE_ALL, so the test needs no cgroup of its own
 * and runs the same on cgroup v1 and v2; its events are told apart from the
 * rest of the host's by their directory. Properties:
 *
 *   1. Listed names arrive, for every event type, and a rename's destination
 *      half arrives when only the destination name is listed.
 *   2. A file arrives when its immediate parent is listed as a parent.
 *   3. Nothing else arrives: unlisted names, the source half of that rename, a
 *      file under a directory listed only as a file name, a file named like a
 *      listed parent, a file two levels under a listed parent, and a name too
 *      long for the key that shares a listed name's prefix.
 *   4. A filtered event is not a drop, even when far more of them are written
 *      than the ring can hold.
 *   5. Without the lists, the same names are delivered.
 */

#include "rt_engine.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SKIP_EXIT 77
#define NOISE_FILES 2000 /* well above the ring's ~675-record capacity */
#define MAX_SEEN 256

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

struct seen_event
{
    unsigned short type;
    unsigned short flags;
    char path[RT_PATH_MAX];
};

struct seen
{
    const char* prefix;
    size_t prefix_len;
    int count;
    int overflow;
    struct seen_event events[MAX_SEEN];
};

static char g_dir[] = "/tmp/rt_names_XXXXXX";
static char g_longest[RT_NAME_FILTER_LEN];     /* RT_NAME_FILTER_LEN - 1 bytes: listed */
static char g_too_long[RT_NAME_FILTER_LEN + 1]; /* one byte more, same prefix: never matches */

static void on_event(const struct rt_file_event* ev, void* user)
{
    struct seen* s = (struct seen*)user;

    if (strncmp(ev->filename, s->prefix, s->prefix_len) != 0 || ev->filename[s->prefix_len] != '/')
    {
        return;
    }
    if (s->count == MAX_SEEN)
    {
        s->overflow = 1;
        return;
    }
    struct seen_event* e = &s->events[s->count++];
    e->type = ev->event_type;
    e->flags = ev->flags;
    snprintf(e->path, sizeof(e->path), "%s", ev->filename);
}

static void engine_log(int level, const char* msg, void* user)
{
    (void)user;
    if (level <= RT_LOG_INFO)
    {
        printf("  [engine %d] %s\n", level, msg);
    }
}

static const char* base_name(const char* path)
{
    const char* slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* Events of `type` whose path ends in `/<tail>`, `tail` relative to g_dir. */
static int count_of(const struct seen* s, unsigned short type, const char* tail)
{
    char path[RT_PATH_MAX];
    int n = 0;

    snprintf(path, sizeof(path), "%s/%s", g_dir, tail);
    for (int i = 0; i < s->count; i++)
    {
        if (s->events[i].type == type && strcmp(s->events[i].path, path) == 0)
        {
            ++n;
        }
    }
    return n;
}

static void make_dir(const char* tail)
{
    char path[RT_PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", g_dir, tail);
    mkdir(path, 0700);
}

static void make_file(const char* tail)
{
    char path[RT_PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", g_dir, tail);
    const int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd >= 0)
    {
        close(fd);
    }
}

static void rename_file(const char* from, const char* to)
{
    char a[RT_PATH_MAX];
    char b[RT_PATH_MAX];
    snprintf(a, sizeof(a), "%s/%s", g_dir, from);
    snprintf(b, sizeof(b), "%s/%s", g_dir, to);
    rename(a, b);
}

static void chmod_file(const char* tail)
{
    char path[RT_PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", g_dir, tail);
    chmod(path, 0640);
}

static void unlink_file(const char* tail)
{
    char path[RT_PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", g_dir, tail);
    unlink(path);
}

/* The writes a package manager makes, plus every near miss. */
static void run_workload(int noise)
{
    make_dir("noise");
    make_dir("status.d");
    make_dir("status.d/sub");
    make_dir("d");
    make_dir("d/status");
    make_dir("f");

    /* Written before anything listed, and not polled: if filtered events took
     * ring space or counted as drops, the listed events below would carry the
     * loss. */
    for (int i = 0; i < noise; i++)
    {
        char tail[64];
        snprintf(tail, sizeof(tail), "noise/n%d", i);
        make_file(tail);
    }

    make_file("status");
    chmod_file("status");
    make_file("status-new");
    rename_file("status-new", "status"); /* dpkg */
    make_file("installed.new");
    rename_file("installed.new", "installed"); /* apk */
    make_file("status.d/ca-certificates");     /* longer than its parent's name */
    make_file("status.d/sub/x");
    make_file("d/status/x");
    make_file("f/status.d");
    make_file(g_longest);
    make_file(g_too_long);
    make_file("other");
    unlink_file("status");
}

static void drain(rt_handle_t h, struct seen* s)
{
    int idle = 0;
    while (idle < 3)
    {
        idle = rt_poll(h, on_event, s, 200) > 0 ? 0 : idle + 1;
    }
}

static void note_drop(unsigned long long cgroup_id, unsigned int drops, void* user)
{
    *(unsigned long*)user += drops;
    printf("    drops: cgroup_id=%llu count=%u\n", cgroup_id, drops);
}

static rt_handle_t open_handle(const char* obj, const char* const* names, const char* const* parents)
{
    struct rt_filter filter;
    memset(&filter, 0, sizeof(filter));
    filter.type_mask = RT_FILE_ALL_BITS;
    filter.bpf_obj_path = obj;
    filter.log = engine_log;
    filter.cgroup_mode = RT_CGROUP_MODE_ALL;
    filter.skip_mask = RT_SKIP_PROC_CONTEXT;
    filter.name_filter = names;
    filter.parent_dir_filter = parents;
    return rt_open(&filter);
}

static void clean_dir(void)
{
    char cmd[RT_PATH_MAX + 16];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_dir);
    if (system(cmd) != 0)
    {
        printf("  could not remove %s\n", g_dir);
    }
}

static int test_filtered(const char* obj, struct seen* s)
{
    const char* const names[] = {"status", "installed", g_longest, NULL};
    const char* const parents[] = {"status.d", NULL};

    const rt_handle_t h = open_handle(obj, names, parents);
    if (!h)
    {
        return 0;
    }

    run_workload(NOISE_FILES);
    drain(h, s);

    unsigned long dropped = 0;
    rt_drain_drops(h, note_drop, &dropped);
    rt_close(h);

    printf("  events delivered with the filter on: %d\n", s->count);
    CHECK(!s->overflow, "more than %d events arrived from the test directory", MAX_SEEN);

    /* Property 1 and 2. */
    CHECK(count_of(s, RT_EV_FILE_OPEN, "status") > 0, "no open event for 'status'");
    CHECK(count_of(s, RT_EV_FILE_ATTR, "status") > 0, "no attr event for 'status'");
    CHECK(count_of(s, RT_EV_FILE_UNLINK, "status") > 0, "no unlink event for 'status'");
    CHECK(count_of(s, RT_EV_FILE_RENAME, "status") > 0, "no event for the rename into 'status'");
    CHECK(count_of(s, RT_EV_FILE_RENAME, "installed") > 0, "no event for the rename into 'installed'");
    CHECK(count_of(s, RT_EV_FILE_OPEN, g_longest) > 0, "no event for the %d-byte listed name",
          RT_NAME_FILTER_LEN - 1);
    CHECK(count_of(s, RT_EV_FILE_OPEN, "status.d/ca-certificates") > 0,
          "no event for a file whose parent is listed");

    /* Property 3: everything else is checked by exclusion, so a near miss the
     * list above does not name cannot slip through either. */
    for (int i = 0; i < s->count; i++)
    {
        const char* name = base_name(s->events[i].path);
        char expected_parent[RT_PATH_MAX];
        snprintf(expected_parent, sizeof(expected_parent), "%s/status.d/%s", g_dir, name);

        const int listed = strcmp(name, "status") == 0 || strcmp(name, "installed") == 0
                           || strcmp(name, g_longest) == 0
                           || strcmp(s->events[i].path, expected_parent) == 0;
        CHECK(listed, "unlisted event delivered: type %u '%s'", s->events[i].type, s->events[i].path);
    }

    /* Property 4. */
    CHECK(dropped == 0, "%lu event(s) counted as dropped while only filtered events exceeded the ring",
          dropped);
    for (int i = 0; i < s->count; i++)
    {
        CHECK(!(s->events[i].flags & RT_F_DROPS_BEFORE), "'%s' arrived flagged with drops before it",
              s->events[i].path);
    }
    return 1;
}

static int test_unfiltered(const char* obj, struct seen* s)
{
    const rt_handle_t h = open_handle(obj, NULL, NULL);
    if (!h)
    {
        return 0;
    }

    run_workload(0);
    drain(h, s);
    rt_close(h);

    /* Property 5: the names the filter removed are produced at all. */
    printf("  events delivered with the filter off: %d\n", s->count);
    CHECK(count_of(s, RT_EV_FILE_OPEN, "other") > 0, "no event for 'other' without a filter");
    CHECK(count_of(s, RT_EV_FILE_RENAME, "status-new") > 0, "no source-half rename event without a filter");
    CHECK(count_of(s, RT_EV_FILE_OPEN, "status.d/sub/x") > 0, "no event for 'status.d/sub/x' without a filter");
    CHECK(count_of(s, RT_EV_FILE_OPEN, g_too_long) > 0, "no event for the %d-byte name without a filter",
          RT_NAME_FILTER_LEN);
    return 1;
}

int main(int argc, char** argv)
{
    const char* obj = (argc > 1) ? argv[1] : "rt_file.bpf.o";
    static struct seen s;

    printf("rt_engine in-kernel file-name filter test (object: %s)\n", obj);

    memset(g_longest, 'L', sizeof(g_longest) - 1);
    memset(g_too_long, 'L', sizeof(g_too_long) - 1);

    if (!mkdtemp(g_dir))
    {
        printf("could not create a test directory — skipping\n");
        return SKIP_EXIT;
    }

    memset(&s, 0, sizeof(s));
    s.prefix = g_dir;
    s.prefix_len = strlen(g_dir);
    if (!test_filtered(obj, &s))
    {
        printf("rt_open failed — skipping\n");
        clean_dir();
        return SKIP_EXIT;
    }

    clean_dir();
    mkdir(g_dir, 0700);

    memset(&s, 0, sizeof(s));
    s.prefix = g_dir;
    s.prefix_len = strlen(g_dir);
    CHECK(test_unfiltered(obj, &s), "rt_open failed for the unfiltered handle");
    clean_dir();

    if (g_failures != 0)
    {
        printf("\n%d check(s) FAILED\n", g_failures);
        return 1;
    }
    printf("\nall checks passed\n");
    return 0;
}
