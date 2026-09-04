/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * eBPF Module (#37396) contract tests — the part of the engine that can be
 * checked without a kernel.
 *
 * Deliberately plain C with its own two-line harness rather than gtest: the
 * whole point of these assertions is that they run everywhere the tree builds,
 * and the vendored googletest cannot even configure in some of those
 * environments (CMake 4.x has dropped compatibility with its declared
 * cmake_minimum_required). A dependency-free binary also means the ABI pin
 * below is checked on any host that can run `make check` in this directory.
 *
 * What this file CANNOT cover, and what still needs the fake-libbpf suite:
 * every path through rt_open() past the filter check, the per-event ABI
 * rejection in the ring-buffer callback, and link teardown accounting — all of
 * which need libbpf's entry points faked out. The dispatch table is already
 * function-pointer based, so that seam is cheap; it is simply not built yet.
 */

#include "rt_engine.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

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

/* ---------------------------------------------------------------------------
 * The ABI pin.
 *
 * struct rt_file_event crosses the kernel/userspace boundary by raw memory
 * reinterpretation: the BPF program writes it into the ring buffer and the
 * engine casts the record straight back. Nothing checks the layout at compile
 * time, because the two sides are separate build artefacts. So a field
 * inserted in the middle, or a resized member, silently mis-parses 12 KB of
 * every event with no error anywhere.
 *
 * These are the assertions that stop that. If one fails, the contract changed
 * and RT_ABI_MAJOR must be bumped (rt_event_contract.h's ADR-003 rule) — do
 * not "fix" the expected numbers.
 * ------------------------------------------------------------------------- */
static void test_event_abi_layout(void)
{
    CHECK(sizeof(struct rt_file_event) == 12416, "sizeof(struct rt_file_event) is %zu, expected 12416",
          sizeof(struct rt_file_event));

    /* Head: the fields the engine itself reads before trusting the record. */
    CHECK(offsetof(struct rt_file_event, abi_major) == 0, "abi_major moved to %zu",
          offsetof(struct rt_file_event, abi_major));
    CHECK(offsetof(struct rt_file_event, event_type) == 2, "event_type moved to %zu",
          offsetof(struct rt_file_event, event_type));
    CHECK(offsetof(struct rt_file_event, flags) == 4, "flags moved to %zu", offsetof(struct rt_file_event, flags));
    CHECK(offsetof(struct rt_file_event, timestamp_ns) == 8, "timestamp_ns moved to %zu",
          offsetof(struct rt_file_event, timestamp_ns));

    /* Correlation keys — #37533 joins containers on these. */
    CHECK(offsetof(struct rt_file_event, cgroup_id) == 48, "cgroup_id moved to %zu",
          offsetof(struct rt_file_event, cgroup_id));
    CHECK(offsetof(struct rt_file_event, mnt_ns) == 56, "mnt_ns moved to %zu",
          offsetof(struct rt_file_event, mnt_ns));
    CHECK(offsetof(struct rt_file_event, dropped) == 60, "dropped moved to %zu",
          offsetof(struct rt_file_event, dropped));

    /* Paths, and the MINOR-1 tail. */
    CHECK(offsetof(struct rt_file_event, filename) == 96, "filename moved to %zu",
          offsetof(struct rt_file_event, filename));
    CHECK(offsetof(struct rt_file_event, cwd) == 4192, "cwd moved to %zu", offsetof(struct rt_file_event, cwd));

    /* The tail must stay the tail: an appended field is a MINOR bump and must
     * not displace anything before it. */
    CHECK(offsetof(struct rt_file_event, parent_comm) + RT_COMM_MAX == sizeof(struct rt_file_event),
          "parent_comm is no longer the last member");
}

static void test_abi_accessors(void)
{
    CHECK(rt_abi_major() == RT_ABI_MAJOR, "rt_abi_major() = %d, header says %d", rt_abi_major(), RT_ABI_MAJOR);
    CHECK(rt_abi_minor() == RT_ABI_MINOR, "rt_abi_minor() = %d, header says %d", rt_abi_minor(), RT_ABI_MINOR);
}

/* ---------------------------------------------------------------------------
 * The log seam.
 * ------------------------------------------------------------------------- */
struct log_capture
{
    int calls;
    int last_level;
    char last_msg[512];
};

static void capture_log(int level, const char* msg, void* user)
{
    struct log_capture* c = (struct log_capture*)user;
    ++c->calls;
    c->last_level = level;
    snprintf(c->last_msg, sizeof(c->last_msg), "%s", msg ? msg : "(null)");
}

static void test_rt_open_rejects_useless_filters(void)
{
    struct log_capture cap;
    struct rt_filter filter;

    /* A filter asking for nothing. */
    memset(&cap, 0, sizeof(cap));
    memset(&filter, 0, sizeof(filter));
    filter.log = capture_log;
    filter.log_user = &cap;
    CHECK(rt_open(&filter) == NULL, "rt_open accepted type_mask == 0");
    CHECK(cap.calls > 0, "rt_open refused an empty mask without saying so through the log seam");
    CHECK(cap.last_level == RT_LOG_ERROR, "expected RT_LOG_ERROR, got %d", cap.last_level);
    CHECK(cap.last_msg[0] != '\0', "log message was empty");
    CHECK(strchr(cap.last_msg, '\n') == NULL, "log message must be a single line with no trailing newline");

    /* A filter asking only for bits this engine does not serve. Must be
     * refused rather than loading a BPF object that can satisfy none of it. */
    memset(&cap, 0, sizeof(cap));
    memset(&filter, 0, sizeof(filter));
    filter.type_mask = 1u << 20;
    filter.log = capture_log;
    filter.log_user = &cap;
    CHECK(rt_open(&filter) == NULL, "rt_open accepted a mask with no RT_FILE_* bits");
    CHECK(cap.calls > 0, "no diagnostic for a mask with no RT_FILE_* bits");
}

static void test_null_handle_contracts(void)
{
    /* rt_open(NULL) must not dereference the filter to find the log sink. */
    CHECK(rt_open(NULL) == NULL, "rt_open(NULL) returned a handle");

    /* Documented as safe; a consumer's teardown path runs these after a
     * failed open. */
    rt_close(NULL);
    CHECK(rt_poll(NULL, NULL, NULL, 0) == -1, "rt_poll(NULL) must return -1");

    /* Answerable without a handle, because it is a host property. */
    const int v1 = rt_host_cgroup_v1(NULL);
    CHECK(v1 == 0 || v1 == 1, "rt_host_cgroup_v1(NULL) returned %d, expected 0 or 1", v1);
    printf("  (this host reports cgroup %s)\n", v1 ? "v1" : "v2");
}

int main(void)
{
    printf("rt_engine contract tests\n");
    test_event_abi_layout();
    test_abi_accessors();
    test_rt_open_rejects_useless_filters();
    test_null_handle_contracts();

    if (g_failures != 0)
    {
        printf("\n%d check(s) FAILED\n", g_failures);
        return 1;
    }
    printf("\nall checks passed\n");
    return 0;
}
