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

#include "../../headers/shared.h"
#include "../wrappers/common.h"
#include "../wrappers/posix/stat_wrappers.h"

#define TMPFS_MAGIC 0x01021994

/* setups/teardowns */
static int setup_group(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
    return 0;
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

#ifdef __linux__
void test_HasFilesystem_tmpfs_same_dev_as_slash_dev_is_skipped(void **state) {
    struct statfs sfs = {.f_type = TMPFS_MAGIC};
    struct stat dev_stat = {.st_dev = 100};
    struct stat path_stat = {.st_dev = 100};
    fs_set set = {.dev = 1, .nfs = 0, .sys = 0, .proc = 0};

    expect_string(__wrap_statfs, __file, "/dev");
    will_return(__wrap_statfs, &sfs);
    will_return(__wrap_statfs, 0);

    expect_string(__wrap_stat, __file, "/dev");
    will_return(__wrap_stat, &dev_stat);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_stat, __file, "/dev");
    will_return(__wrap_stat, &path_stat);
    will_return(__wrap_stat, 0);

    assert_true(HasFilesystem("/dev", set));
}

void test_HasFilesystem_tmpfs_different_dev_from_slash_dev_is_monitored(void **state) {
    struct statfs sfs = {.f_type = TMPFS_MAGIC};
    struct stat dev_stat = {.st_dev = 100};
    struct stat path_stat = {.st_dev = 200};
    fs_set set = {.dev = 1, .nfs = 0, .sys = 0, .proc = 0};

    expect_string(__wrap_statfs, __file, "/export/reports");
    will_return(__wrap_statfs, &sfs);
    will_return(__wrap_statfs, 0);

    expect_string(__wrap_stat, __file, "/dev");
    will_return(__wrap_stat, &dev_stat);
    will_return(__wrap_stat, 0);

    expect_string(__wrap_stat, __file, "/export/reports");
    will_return(__wrap_stat, &path_stat);
    will_return(__wrap_stat, 0);

    assert_false(HasFilesystem("/export/reports", set));
}

void test_HasFilesystem_tmpfs_skip_dev_disabled_is_monitored(void **state) {
    struct statfs sfs = {.f_type = TMPFS_MAGIC};
    fs_set set = {.dev = 0, .nfs = 0, .sys = 0, .proc = 0};

    expect_string(__wrap_statfs, __file, "/export/reports");
    will_return(__wrap_statfs, &sfs);
    will_return(__wrap_statfs, 0);

    assert_false(HasFilesystem("/export/reports", set));
}
#endif

int main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_fs_magic),
#ifdef __linux__
            cmocka_unit_test(test_HasFilesystem_tmpfs_same_dev_as_slash_dev_is_skipped),
            cmocka_unit_test(test_HasFilesystem_tmpfs_different_dev_from_slash_dev_is_monitored),
            cmocka_unit_test(test_HasFilesystem_tmpfs_skip_dev_disabled_is_monitored),
#endif
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
