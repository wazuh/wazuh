/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * eBPF Module (#37396) — proves that rt_close() actually releases everything
 * rt_open() acquired. Needs a real kernel, a built rt_file.bpf.o and root, so
 * unlike rt_engine_contract_test.c this cannot run in a container-less or
 * BPF-less build environment; it exits 77 (the CTest "skipped" convention)
 * rather than failing when rt_open() cannot succeed.
 *
 * Why an fd census. Every bpf_link that bpf_program__attach() returns owns a
 * file descriptor, and so do the object and the ring buffer. rt_close() used to
 * discard the links entirely — bpf_object__close() does NOT detach them — so
 * the programs stayed attached for the life of the process, the kernel kept
 * writing into a ring buffer with no consumer, and a second rt_open() attached
 * a *second* copy of every program, duplicating every event.
 *
 * Counting /proc/self/fd across open/close/open detects exactly that, in-process
 * and without shelling out to bpftool: if teardown is complete, the count
 * returns to its starting value and a re-open lands on the same number. If any
 * link leaks, the post-close count stays elevated and the second open climbs
 * further — which is the signature of the duplicate-event bug.
 */

#include "rt_engine.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>

#define SKIP_EXIT 77

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

static int count_open_fds(void)
{
    DIR* d = opendir("/proc/self/fd");
    if (!d)
    {
        return -1;
    }
    int n = 0;
    const struct dirent* e = NULL;
    while ((e = readdir(d)) != NULL)
    {
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
        {
            ++n;
        }
    }
    closedir(d);
    /* opendir itself holds one fd for the duration of the walk. */
    return n - 1;
}

static void engine_log(int level, const char* msg, void* user)
{
    (void)user;
    printf("  [engine %d] %s\n", level, msg);
}

int main(int argc, char** argv)
{
    const char* obj = (argc > 1) ? argv[1] : "rt_file.bpf.o";

    struct rt_filter filter;
    memset(&filter, 0, sizeof(filter));
    filter.type_mask = RT_FILE_ALL_BITS;
    filter.bpf_obj_path = obj;
    filter.log = engine_log;

    printf("rt_engine teardown test (object: %s)\n", obj);

    const int baseline = count_open_fds();
    if (baseline < 0)
    {
        printf("cannot read /proc/self/fd — skipping\n");
        return SKIP_EXIT;
    }
    printf("  fds at start: %d\n", baseline);

    const rt_handle_t first = rt_open(&filter);
    if (!first)
    {
        printf("rt_open failed (no kernel support, missing %s, or not root) — skipping\n", obj);
        return SKIP_EXIT;
    }

    const int while_open = count_open_fds();
    printf("  fds while open: %d (+%d)\n", while_open, while_open - baseline);
    CHECK(while_open > baseline, "rt_open acquired no descriptors at all, which cannot be right");

    rt_close(first);
    const int after_close = count_open_fds();
    printf("  fds after close: %d\n", after_close);
    CHECK(after_close == baseline,
          "rt_close leaked %d descriptor(s): every bpf_link it fails to destroy leaves its program "
          "attached and the kernel writing into a ring buffer nobody reads",
          after_close - baseline);

    /* The re-open is the half that produced duplicate events: with links leaked,
     * the programs from the first open are still attached, so this attaches a
     * second copy of each. */
    const rt_handle_t second = rt_open(&filter);
    CHECK(second != NULL, "the second rt_open failed, so teardown left the engine in a bad state");
    if (second)
    {
        const int while_open_again = count_open_fds();
        printf("  fds while open (2nd): %d\n", while_open_again);
        CHECK(while_open_again == while_open,
              "the second open holds %d more descriptor(s) than the first — the first open's programs "
              "are still attached, which is the duplicate-event bug",
              while_open_again - while_open);

        rt_close(second);
        const int final_count = count_open_fds();
        printf("  fds at end: %d\n", final_count);
        CHECK(final_count == baseline, "%d descriptor(s) leaked across two open/close cycles",
              final_count - baseline);
    }

    if (g_failures != 0)
    {
        printf("\n%d check(s) FAILED\n", g_failures);
        return 1;
    }
    printf("\nall checks passed\n");
    return 0;
}
