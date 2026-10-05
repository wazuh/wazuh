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

#include "cgroup_host_mode.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

/* ---------------------------------------------------------------------------
 * The cgroup hierarchy probe.
 *
 * Every host this tree builds and tests on is unified, so two of the probe's
 * three branches would otherwise ship having never once executed — which is
 * exactly how a v1 host ends up being the first thing to run them. The probe
 * takes a root parameter for this reason and no other, and these build the
 * three layouts as directories.
 * ------------------------------------------------------------------------- */

static int touch_(const char* path)
{
    FILE* f = fopen(path, "w");
    if (f == NULL)
    {
        return 0;
    }
    fclose(f);
    return 1;
}

static int join_(char* out, size_t len, const char* a, const char* b)
{
    const int n = snprintf(out, len, "%s%s", a, b);
    return n > 0 && (size_t)n < len;
}

/* Builds <tmp>/<name>/ with the requested markers and returns it in `out`.
 * `root_marker` is the unified case, `unified_marker` the hybrid one; a
 * fixture with neither is the legacy case. */
static int make_fixture_(char* out, size_t len, const char* tmp, const char* name, int root_marker, int unified_marker)
{
    char path[512];

    if (!join_(out, len, tmp, "/") || !join_(path, sizeof(path), out, name))
    {
        return 0;
    }
    if (!join_(out, len, path, "") || mkdir(out, 0700) != 0)
    {
        return 0;
    }

    if (root_marker)
    {
        if (!join_(path, sizeof(path), out, "/cgroup.controllers") || !touch_(path))
        {
            return 0;
        }
    }
    if (unified_marker)
    {
        if (!join_(path, sizeof(path), out, "/unified") || mkdir(path, 0700) != 0)
        {
            return 0;
        }
        if (!join_(path, sizeof(path), out, "/unified/cgroup.controllers") || !touch_(path))
        {
            return 0;
        }
    }

    /* Every layout has controller directories; only the markers differ. A
     * fixture without them would let a probe that keyed on "is there anything
     * here at all" pass for the wrong reason. */
    if (!join_(path, sizeof(path), out, "/memory") || mkdir(path, 0700) != 0)
    {
        return 0;
    }
    return 1;
}

static void rmtree_(const char* root)
{
    char path[512];

    if (join_(path, sizeof(path), root, "/unified/cgroup.controllers"))
    {
        remove(path);
    }
    if (join_(path, sizeof(path), root, "/unified"))
    {
        remove(path);
    }
    if (join_(path, sizeof(path), root, "/cgroup.controllers"))
    {
        remove(path);
    }
    if (join_(path, sizeof(path), root, "/memory"))
    {
        remove(path);
    }
    remove(root);
}

static void test_cgroup_mode_probe(void)
{
    char tmp[] = "/tmp/rt_cgroup_probe_XXXXXX";
    char fixture[512];

    if (mkdtemp(tmp) == NULL)
    {
        CHECK(0, "mkdtemp failed; cannot exercise the cgroup probe");
        return;
    }

    if (make_fixture_(fixture, sizeof(fixture), tmp, "unified", 1, 0))
    {
        CHECK(wz_cgroup_mode_at(fixture) == WZ_CGROUP_MODE_UNIFIED,
              "a root cgroup.controllers must read as unified, got %s",
              wz_cgroup_mode_name(wz_cgroup_mode_at(fixture)));
        rmtree_(fixture);
    }
    else
    {
        CHECK(0, "could not build the unified fixture");
    }

    if (make_fixture_(fixture, sizeof(fixture), tmp, "hybrid", 0, 1))
    {
        CHECK(wz_cgroup_mode_at(fixture) == WZ_CGROUP_MODE_HYBRID,
              "v2 mounted only at <root>/unified must read as hybrid, got %s",
              wz_cgroup_mode_name(wz_cgroup_mode_at(fixture)));

        /* The reason hybrid is a separate mode rather than a separate
         * behaviour: it is named differently in logs and treated as v2 for
         * correlation, because the helper returns unified-hierarchy ids. */
        CHECK(wz_cgroup_mode_has_usable_cgroup_id(WZ_CGROUP_MODE_HYBRID), "hybrid must count as having a usable key");
        rmtree_(fixture);
    }
    else
    {
        CHECK(0, "could not build the hybrid fixture");
    }

    if (make_fixture_(fixture, sizeof(fixture), tmp, "legacy", 0, 0))
    {
        CHECK(wz_cgroup_mode_at(fixture) == WZ_CGROUP_MODE_LEGACY,
              "controller directories with no v2 marker must read as legacy, got %s",
              wz_cgroup_mode_name(wz_cgroup_mode_at(fixture)));
        CHECK(!wz_cgroup_mode_has_usable_cgroup_id(WZ_CGROUP_MODE_LEGACY), "legacy must not count as having a key");
        rmtree_(fixture);
    }
    else
    {
        CHECK(0, "could not build the legacy fixture");
    }

    /* Both markers present. Real on a host mid-migration, and the order the
     * probe tests them is what decides the answer — pin it, because swapping
     * the two branches is an invisible edit that changes a host's mode. */
    if (make_fixture_(fixture, sizeof(fixture), tmp, "both", 1, 1))
    {
        CHECK(wz_cgroup_mode_at(fixture) == WZ_CGROUP_MODE_UNIFIED,
              "a root marker must win over a /unified one, got %s",
              wz_cgroup_mode_name(wz_cgroup_mode_at(fixture)));
        rmtree_(fixture);
    }
    else
    {
        CHECK(0, "could not build the both-markers fixture");
    }

    /* The default direction, which is the safety property: anything not
     * positively identified as v2 reads legacy, because a legacy host
     * misreported as unified attributes every container to one bogus cgroup
     * and says nothing. */
    CHECK(wz_cgroup_mode_at("/nonexistent/cgroup/root") == WZ_CGROUP_MODE_LEGACY, "an absent root must read as legacy");
    CHECK(wz_cgroup_mode_at(NULL) == WZ_CGROUP_MODE_LEGACY, "a NULL root must read as legacy");
    CHECK(wz_cgroup_mode_at("") == WZ_CGROUP_MODE_LEGACY, "an empty root must read as legacy");

    /* The truncation guard.
     *
     * An earlier version of this check just passed a 2 KB root and asserted
     * "legacy" — which passes whether or not the guard exists, because a
     * truncated path that names nothing fails its stat anyway. The hazard is
     * specifically a truncated path that names something REAL, so that is what
     * this builds: a root long enough that "<root>/cgroup.controllers" is cut
     * short, with a file sitting at exactly the cut-short name. Without the
     * guard the probe stats that file and reports a v1 host as unified. */
    {
        const size_t target = 495; /* 495 + strlen("/cgroup.controllers") > 511 */
        char root[600];
        char decoy[700];
        size_t len;

        /* Two nested components rather than one: each stays well under
         * NAME_MAX, which a single 468-character directory name would not. */
        len = (size_t)snprintf(root, sizeof(root), "%s/", tmp);
        memset(root + len, 'a', 233);
        root[len + 233] = '\0';

        if (mkdir(root, 0700) != 0)
        {
            CHECK(0, "could not build the long-root fixture");
        }
        else
        {
            len = strlen(root);
            root[len] = '/';
            memset(root + len + 1, 'b', target - len - 1);
            root[target] = '\0';

            if (mkdir(root, 0700) != 0)
            {
                CHECK(0, "could not build the long-root fixture's leaf");
            }
            else
            {
                CHECK(strlen(root) == target, "long root is %zu chars, expected %zu", strlen(root), target);

                snprintf(decoy, sizeof(decoy), "%s/cgroup.controllers", root);
                decoy[511] = '\0'; /* exactly what the probe's snprintf would leave */

                if (!touch_(decoy))
                {
                    CHECK(0, "could not create the truncation decoy");
                }
                else
                {
                    CHECK(wz_cgroup_mode_at(root) == WZ_CGROUP_MODE_LEGACY,
                          "the probe stat'd a truncated path: '%s' exists, the real marker does not",
                          decoy);
                    remove(decoy);
                }
                remove(root);
            }

            root[len] = '\0';
            remove(root);
        }
    }

    remove(tmp);
}

/* The anti-drift assertion, and the reason the probe was made shared at all:
 * the engine's public answer and the shared probe must be the same answer on
 * this host. If these two ever disagree, a second copy of the probe has grown
 * back somewhere. */
static void test_engine_agrees_with_the_shared_probe(void)
{
    const wz_cgroup_mode_t mode = wz_cgroup_mode();
    const int expected = wz_cgroup_mode_has_usable_cgroup_id(mode) ? 0 : 1;

    CHECK(rt_host_cgroup_v1(NULL) == expected,
          "rt_host_cgroup_v1(NULL) returned %d but the shared probe reads %s",
          rt_host_cgroup_v1(NULL),
          wz_cgroup_mode_name(mode));
    printf("  (shared probe reports %s)\n", wz_cgroup_mode_name(mode));
}

int main(void)
{
    printf("rt_engine contract tests\n");
    test_event_abi_layout();
    test_abi_accessors();
    test_rt_open_rejects_useless_filters();
    test_null_handle_contracts();
    test_cgroup_mode_probe();
    test_engine_agrees_with_the_shared_probe();

    if (g_failures != 0)
    {
        printf("\n%d check(s) FAILED\n", g_failures);
        return 1;
    }
    printf("\nall checks passed\n");
    return 0;
}
