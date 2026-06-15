/* Copyright (C) 2026, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <dirent.h>
#include <sys/stat.h>

#include "shared.h"
#include "rootcheck.h"

/* Required globals declared extern in rootcheck.h */
rkconfig rootcheck;
int rk_sys_count;
char **rk_sys_file;
char **rk_sys_name;
int test_mode = 1;

/* ===================================================================
 * Wrappers
 * =================================================================== */

DIR *__wrap_wopendir(const char *name)
{
    check_expected(name);
    return mock_type(DIR *);
}

int __wrap_closedir(DIR *dirp)
{
    (void)dirp;
    return 0;
}

int __wrap_w_stat(const char *pathname, struct stat *buf)
{
    check_expected(pathname);
    (void)buf;
    return mock_type(int);
}

int __wrap_waccess(const char *path, int mode)
{
    check_expected(path);
    (void)mode;
    return mock_type(int);
}

FILE *__wrap_wfopen(const char *path, const char *mode)
{
    check_expected(path);
    (void)mode;
    return mock_type(FILE *);
}

int __wrap_fclose(FILE *stream)
{
    (void)stream;
    return 0;
}

void __wrap__mtdebug1(__attribute__((unused)) const char *tag,
                      __attribute__((unused)) const char *file,
                      __attribute__((unused)) int line,
                      __attribute__((unused)) const char *func,
                      __attribute__((unused)) const char *msg, ...) {}

void __wrap__mtdebug2(__attribute__((unused)) const char *tag,
                      __attribute__((unused)) const char *file,
                      __attribute__((unused)) int line,
                      __attribute__((unused)) const char *func,
                      __attribute__((unused)) const char *msg, ...) {}

void __wrap__merror_exit(__attribute__((unused)) const char *tag,
                         __attribute__((unused)) const char *file,
                         __attribute__((unused)) int line,
                         __attribute__((unused)) const char *func,
                         __attribute__((unused)) const char *msg, ...) {}

int __wrap_OS_Regex(__attribute__((unused)) const char *pattern,
                    __attribute__((unused)) const char *str)
{
    return 0;
}

int __wrap_OS_Match2(__attribute__((unused)) const char *pattern,
                     __attribute__((unused)) const char *str)
{
    return 0;
}

OSListNode *__wrap_OSList_GetFirstNode(__attribute__((unused)) OSList *list)
{
    return NULL;
}

OSListNode *__wrap_OSList_GetNextNode(__attribute__((unused)) OSList *list)
{
    return NULL;
}

/* ===================================================================
 * Tests for is_file()
 * =================================================================== */

static void test_is_file_null_input(void **state)
{
    (void)state;
    assert_int_equal(is_file(NULL), 0);
}

/* A directory counts as found — wopendir succeeds */
static void test_is_file_found_by_opendir(void **state)
{
    (void)state;
    DIR *fake_dp = (DIR *)0x1234;

    expect_string(__wrap_wopendir, name, "/bin/some_dir");
    will_return(__wrap_wopendir, fake_dp);

    assert_int_equal(is_file("/bin/some_dir"), 1);
}

/* wopendir fails, w_stat succeeds */
static void test_is_file_found_by_stat(void **state)
{
    (void)state;

    expect_string(__wrap_wopendir, name, "/bin/ps");
    will_return(__wrap_wopendir, NULL);

    expect_string(__wrap_w_stat, pathname, "/bin/ps");
    will_return(__wrap_w_stat, 0);

    assert_int_equal(is_file("/bin/ps"), 1);
}

/* wopendir fails, w_stat fails, waccess succeeds */
static void test_is_file_found_by_access(void **state)
{
    (void)state;

    expect_string(__wrap_wopendir, name, "/bin/ps");
    will_return(__wrap_wopendir, NULL);

    expect_string(__wrap_w_stat, pathname, "/bin/ps");
    will_return(__wrap_w_stat, -1);

    expect_string(__wrap_waccess, path, "/bin/ps");
    will_return(__wrap_waccess, 0);

    assert_int_equal(is_file("/bin/ps"), 1);
}

/* wopendir fails, w_stat fails, waccess fails, wfopen succeeds */
static void test_is_file_found_by_fopen(void **state)
{
    (void)state;
    FILE *fake_fp = (FILE *)0x5678;

    expect_string(__wrap_wopendir, name, "/bin/ps");
    will_return(__wrap_wopendir, NULL);

    expect_string(__wrap_w_stat, pathname, "/bin/ps");
    will_return(__wrap_w_stat, -1);

    expect_string(__wrap_waccess, path, "/bin/ps");
    will_return(__wrap_waccess, -1);

    expect_string(__wrap_wfopen, path, "/bin/ps");
    will_return(__wrap_wfopen, fake_fp);

    assert_int_equal(is_file("/bin/ps"), 1);
}

/* All methods fail → not found */
static void test_is_file_not_found(void **state)
{
    (void)state;

    expect_string(__wrap_wopendir, name, "/bin/ps");
    will_return(__wrap_wopendir, NULL);

    expect_string(__wrap_w_stat, pathname, "/bin/ps");
    will_return(__wrap_w_stat, -1);

    expect_string(__wrap_waccess, path, "/bin/ps");
    will_return(__wrap_waccess, -1);

    expect_string(__wrap_wfopen, path, "/bin/ps");
    will_return(__wrap_wfopen, NULL);

    assert_int_equal(is_file("/bin/ps"), 0);
}

/* ===================================================================
 * Main
 * =================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_is_file_null_input),
        cmocka_unit_test(test_is_file_found_by_opendir),
        cmocka_unit_test(test_is_file_found_by_stat),
        cmocka_unit_test(test_is_file_found_by_access),
        cmocka_unit_test(test_is_file_found_by_fopen),
        cmocka_unit_test(test_is_file_not_found),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
