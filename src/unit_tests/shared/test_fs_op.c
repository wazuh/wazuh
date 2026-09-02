/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef __linux__
#include <sys/vfs.h>
#endif

#include "shared.h"
#include "../wrappers/common.h"

// Wrappers

int __wrap_statfs(const char * path, struct statfs * buf) {
    check_expected(path);

    long f_type = mock_type(long);

    if (f_type != -1) {
        buf->f_type = f_type;
    }

    return mock_type(int);
}

// Tests

static int compare(const struct file_system_type * statfs) {
    for (int i = 0; network_file_systems[i].name; i++) {
        if (network_file_systems[i].f_type == statfs->f_type) {
            return 1;
        }
    }

    for (int i = 0; skip_file_systems[i].name; i++) {
        if (skip_file_systems[i].f_type == statfs->f_type) {
            return 1;
        }
    }

    return 0;
}

void test_fs_magic(void **state)
{
    struct file_system_type statfs = {.f_type = 0x6969};
    assert_int_equal(compare(&statfs), 1);

    statfs.f_type = 0xFF534D42;
    assert_int_equal(compare(&statfs), 1);

    statfs.f_type = 0x9123683E;
    assert_int_equal(compare(&statfs), 1);

    statfs.f_type = 0x61756673;
    assert_int_equal(compare(&statfs), 1);

    statfs.f_type = 0x794c7630;
    assert_int_equal(compare(&statfs), 1);
}

// Regression tests for https://github.com/wazuh/wazuh/issues/38693:
// skipFS()/IsNFS() must actually evaluate the "#if defined(__linux__)" branch
// instead of silently short-circuiting to 0.

void test_skipFS_overlayfs_is_skipped(void **state)
{
    (void) state;

    expect_string(__wrap_statfs, path, "/etc");
    will_return(__wrap_statfs, 0x794c7630 /* OVERLAYFS, mirrors test_fs_magic above */);
    will_return(__wrap_statfs, 0);

    assert_int_equal(skipFS("/etc"), 1);
}

void test_skipFS_regular_fs_is_not_skipped(void **state)
{
    (void) state;

    expect_string(__wrap_statfs, path, "/etc");
    will_return(__wrap_statfs, 0xEF53 /* EXT4_SUPER_MAGIC */);
    will_return(__wrap_statfs, 0);

    assert_int_equal(skipFS("/etc"), 0);
}

void test_skipFS_statfs_error(void **state)
{
    (void) state;

    expect_string(__wrap_statfs, path, "/nonexistent");
    will_return(__wrap_statfs, -1);
    errno = ENOENT;
    will_return(__wrap_statfs, -1);

    assert_int_equal(skipFS("/nonexistent"), -1);
}

void test_IsNFS_nfs_mount_is_detected(void **state)
{
    (void) state;

    expect_string(__wrap_statfs, path, "/mnt/nfs");
    will_return(__wrap_statfs, 0x6969 /* NFS */);
    will_return(__wrap_statfs, 0);

    assert_int_equal(IsNFS("/mnt/nfs"), 1);
}

void test_IsNFS_regular_fs_is_not_detected(void **state)
{
    (void) state;

    expect_string(__wrap_statfs, path, "/etc");
    will_return(__wrap_statfs, 0xEF53 /* EXT4_SUPER_MAGIC */);
    will_return(__wrap_statfs, 0);

    assert_int_equal(IsNFS("/etc"), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_fs_magic),
            cmocka_unit_test(test_skipFS_overlayfs_is_skipped),
            cmocka_unit_test(test_skipFS_regular_fs_is_not_skipped),
            cmocka_unit_test(test_skipFS_statfs_error),
            cmocka_unit_test(test_IsNFS_nfs_mount_is_detected),
            cmocka_unit_test(test_IsNFS_regular_fs_is_not_detected),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
