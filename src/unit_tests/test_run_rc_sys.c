
/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include "../headers/shared.h"
#include "../rootcheck/rootcheck.h"


/* */
int read_sys_file(const char *file_name, int do_read);
int read_sys_dir(const char *dir_name, int do_read);

extern rkconfig rootcheck;


/* WRAP */

int __wrap_lstat(char *file_name, struct stat *statbuf)
{
    int param = mock();

    switch (param)
    {
        case 3:
            statbuf->st_mode = S_IFDIR;
            statbuf->st_size = 60;
            break;
        case 2:
            statbuf->st_mode = S_IFDIR;
            statbuf->st_size = 0;
            break;
        case 1:
            statbuf->st_mode = S_IFREG|S_IWOTH;
            statbuf->st_size = 60;
            statbuf->st_uid = 0;
            break;
        case 0:
            statbuf->st_mode = S_IFREG;
            statbuf->st_size = 0;
            break;
    }

    return param;
}

void __wrap_notify_rk(int rk_type, char *msg)
{
    check_expected(rk_type);
    check_expected(msg);
}

int __wrap_open()
{
    return mock();
}

ssize_t __wrap_read()
{
    return mock();
}

int __wrap_strcmp()
{
    return mock();
}

short __wrap_IsNFS()
{
    return mock();
}

int  __wrap_opendir()
{
    return mock();
}

int __wrap_readdir()
{
    return mock();
}

int __wrap_skipFS()
{
    return mock();
}

void __wrap_closedir()
{
    return;
}


/* TEST */

void test_read_sys_file_fail(void **state)
{
    int ret;

    will_return(__wrap_lstat, -1);
    expect_value(__wrap_notify_rk, rk_type, ALERT_ROOTKIT_FOUND);
    expect_string(__wrap_notify_rk, msg, "Anomaly detected in file '/test_fail'. "
                 "Hidden from stats, but showing up on readdir. "
                 "Possible kernel level rootkit.");

    ret = read_sys_file("/test_fail", 1);

    assert_int_equal(ret, -1);
}

void test_read_sys_file_is_dir_dev_fd(void **state)
{
    int ret;

    will_return(__wrap_lstat, 3);

    ret = read_sys_file("/dev/fd", 1);

    assert_int_equal(ret, 0);
}

void test_read_sys_file_is_dir_size_zero(void **state)
{
    int ret;

    will_return(__wrap_lstat, 2);

    ret = read_sys_file("/test_dir_zero", 1);

    assert_int_equal(ret, 0);
}

void test_read_sys_file_is_reg_and_do_read(void **state)
{
    int ret;

    will_return(__wrap_lstat, 0);
    will_return(__wrap_open, 1);
    will_return(__wrap_read, 60);
    will_return(__wrap_read, 0);
    will_return(__wrap_strcmp, 1);
    will_return(__wrap_lstat, 0);
    expect_value(__wrap_notify_rk, rk_type, ALERT_ROOTKIT_FOUND);
    expect_string(__wrap_notify_rk, msg, "Anomaly detected in file "
                             "'/test'. File size doesn't match what we found. "
                             "Possible kernel level rootkit.");

    ret = read_sys_file("/test", 1);

    assert_int_equal(ret, 0);
}

void test_read_sys_file_is_reg_and_no_do_read(void **state)
{
    int ret;

    will_return(__wrap_lstat, 1);
    expect_value(__wrap_notify_rk, rk_type, ALERT_SYSTEM_CRIT);
    expect_string(__wrap_notify_rk, msg, "File '/test' is owned by root "
                     "and has written permissions to anyone.");

    ret = read_sys_file("/test", 0);

    assert_int_equal(ret, 0);
}

void test_read_sys_dir_invalid_dir(void **state)
{
    int ret;
    char *dir= NULL;

    ret = read_sys_dir(dir, 0);

    assert_int_equal(ret, -1);
}

void test_read_sys_dir_isnfs_error(void **state)
{
    int ret;
    rootcheck.skip_nfs = 1;

    will_return(__wrap_IsNFS, -1);

    ret = read_sys_dir("/test", 0);

    assert_int_equal(ret, -1);
}

void test_read_sys_dir_lstat_error(void **state)
{
    int ret;
    rootcheck.skip_nfs = 0;

    will_return(__wrap_lstat, -1);

    ret = read_sys_dir("/test", 0);

    assert_int_equal(ret, -1);
}

void test_read_sys_dir_lstat_file(void **state)
{
    int ret;

    will_return(__wrap_lstat, 0);

    ret = read_sys_dir("/test", 0);

    assert_int_equal(ret, -1);
}

void test_read_sys_dir_opendir_fail(void **state)
{
    int ret;

    will_return(__wrap_lstat, 3);
    will_return(__wrap_strcmp, 0);
    will_return(__wrap_opendir, 0);

    ret = read_sys_dir("/test", 0);

    assert_int_equal(ret, -1);
}

/*void test_read_sys_dir_readdir(void **state)
{
    int ret;

    will_return(__wrap_lstat, 3);
    will_return(__wrap_strcmp, 0);
    will_return(__wrap_opendir, 1);
    will_return(__wrap_readdir, 1);
    will_return(__wrap_strcmp, 0);
    will_return(__wrap_strcmp, 1);
    will_return(__wrap_strcmp, 1);

    will_return(__wrap_skipFS, 0);

    ret = read_sys_dir("/test", 0);

    assert_int_equal(ret, 0);
}*/

void test_read_sys_dir_skipFS_fail(void **state)
{
    int ret;

    will_return(__wrap_lstat, 3);
    will_return(__wrap_strcmp, 0);
    will_return(__wrap_opendir, 1);
    will_return(__wrap_readdir, 0);
    will_return(__wrap_skipFS, -1);

    ret = read_sys_dir("/test", 0);

    assert_int_equal(ret, 0);
}


int main(void)
{

    const struct CMUnitTest tests[] = {
        // Test lstat fails
        cmocka_unit_test(test_read_sys_file_fail),
        cmocka_unit_test(test_read_sys_file_is_dir_dev_fd),
        cmocka_unit_test(test_read_sys_file_is_dir_size_zero),
        //cmocka_unit_test(test_read_sys_file_is_reg_and_do_read),
        cmocka_unit_test(test_read_sys_file_is_reg_and_no_do_read),
        //cmocka_unit_test(test_read_sys_dir_invalid_dir),
        cmocka_unit_test(test_read_sys_dir_isnfs_error),
        cmocka_unit_test(test_read_sys_dir_lstat_error),
        cmocka_unit_test(test_read_sys_dir_lstat_file),
        cmocka_unit_test(test_read_sys_dir_opendir_fail),
        cmocka_unit_test(test_read_sys_dir_skipFS_fail),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
