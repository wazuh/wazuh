/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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

#include "../syscheckd/syscheck.h"
#include "../config/syscheck-config.h"

/* redefinitons/wrapping */

int __wrap_inotify_init() {
    return mock();
}

int __wrap_inotify_add_watch() {
    return mock();
}

int __wrap_OSHash_Get_ex() {
    return mock();
}

int __wrap_OSHash_Add_ex() {
    return mock();
}

int __wrap_OSHash_Update_ex() {
    return mock();
}

ssize_t __real_read(int fildes, void *buf, size_t nbyte);
ssize_t __wrap_read(int fildes, void *buf, size_t nbyte) {
    if (mock_type(int) == 0) {
        return __real_read(fildes, buf, nbyte);
    } else {
        return mock_type(ssize_t);
    }
}


/* tests */

void test_realtime_start_success(void **state)
{
    (void) state;
    int ret;

    Read_Syscheck_Config("test_syscheck.conf");

    will_return(__wrap_inotify_init, 0);
    will_return(__wrap_read, 0); // Use real
    will_return(__wrap_read, 0);

    ret = realtime_start();

    assert_int_equal(ret, 1);
}


void test_realtime_start_failure(void **state)
{
    (void) state;
    int ret;

    Read_Syscheck_Config("test_syscheck.conf");

    will_return(__wrap_inotify_init, -1);
    will_return(__wrap_read, 0); // Use real
    will_return(__wrap_read, 0);

    ret = realtime_start();

    assert_int_equal(ret, -1);
}


void test_realtime_adddir_whodata(void **state)
{
    (void) state;
    int ret;

    Read_Syscheck_Config("test_syscheck.conf");
    const char * path = "/etc/folder";

    audit_thread_active = 1;
    ret = realtime_adddir(path, 1);

    assert_int_equal(ret, 1);
}


void test_realtime_adddir_realtime_failure(void **state)
{
    (void) state;
    int ret;

    Read_Syscheck_Config("test_syscheck.conf");
    const char * path = "/etc/folder";

    syscheck.realtime = (rtfim *) calloc(1, sizeof(rtfim));
    syscheck.realtime->fd = -1;

    ret = realtime_adddir(path, 0);

    assert_int_equal(ret, -1);
}


void test_realtime_adddir_realtime_add(void **state)
{
    (void) state;
    int ret;

    Read_Syscheck_Config("test_syscheck.conf");
    const char * path = "/etc/folder";

    syscheck.realtime = (rtfim *) calloc(1, sizeof(rtfim));
    syscheck.realtime->fd = 1;
    will_return(__wrap_inotify_add_watch, 1);
    will_return(__wrap_OSHash_Get_ex, 0);
    will_return(__wrap_OSHash_Add_ex, 1);

    ret = realtime_adddir(path, 0);

    assert_int_equal(ret, 1);
}


void test_realtime_adddir_realtime_update(void **state)
{
    (void) state;
    int ret;

    Read_Syscheck_Config("test_syscheck.conf");
    const char * path = "/etc/folder";

    syscheck.realtime = (rtfim *) calloc(1, sizeof(rtfim));
    syscheck.realtime->fd = 1;
    will_return(__wrap_inotify_add_watch, 1);
    will_return(__wrap_OSHash_Get_ex, 1);
    will_return(__wrap_OSHash_Update_ex, 1);

    ret = realtime_adddir(path, 0);

    assert_int_equal(ret, 1);
}


void test_realtime_adddir_realtime_update_failure(void **state)
{
    (void) state;
    int ret;

    Read_Syscheck_Config("test_syscheck.conf");
    const char * path = "/etc/folder";

    syscheck.realtime = (rtfim *) calloc(1, sizeof(rtfim));
    syscheck.realtime->fd = 1;
    will_return(__wrap_inotify_add_watch, 1);
    will_return(__wrap_OSHash_Get_ex, 1);
    will_return(__wrap_OSHash_Update_ex, 0);

    ret = realtime_adddir(path, 0);

    assert_int_equal(ret, -1);
}


void test_realtime_process_failure(void **state)
{
    (void) state;
    int ret;

    Read_Syscheck_Config("test_syscheck.conf");

    syscheck.realtime = (rtfim *) calloc(1, sizeof(rtfim));
    syscheck.realtime->fd = 1;

    will_return(__wrap_read, 1); // Use wrap
    will_return(__wrap_read, -1);

    ret = realtime_process();

    assert_int_equal(ret, 0);
}


void test_run_whodata_scan(void **state)
{
    (void) state;
    int ret;

    ret = run_whodata_scan();

    assert_int_equal(ret, 0);
}


void test_free_syscheck_dirtb_data(void **state)
{
    (void) state;
    char *data = strdup("test");

    free_syscheck_dirtb_data(data);

    assert_null(data);
}


void test_free_syscheck_dirtb_data_null(void **state)
{
    (void) state;
    char *data = NULL;

    free_syscheck_dirtb_data(data);

    assert_null(data);
}


void test_realtime_process(void **state)
{
    (void) state;
    int ret;

    Read_Syscheck_Config("test_syscheck.conf");

    syscheck.realtime = (rtfim *) calloc(1, sizeof(rtfim));
    syscheck.realtime->fd = 1;

    will_return(__wrap_read, 1); // Use wrap
    will_return(__wrap_read, 1);

    ret = realtime_process();

    assert_int_equal(ret, 0);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_realtime_start_success),
        cmocka_unit_test(test_realtime_start_failure),
        cmocka_unit_test(test_realtime_adddir_whodata),
        cmocka_unit_test(test_realtime_adddir_realtime_failure),
        cmocka_unit_test(test_realtime_adddir_realtime_add),
        cmocka_unit_test(test_realtime_adddir_realtime_update),
        cmocka_unit_test(test_realtime_adddir_realtime_update_failure),
        cmocka_unit_test(test_realtime_process_failure),
        cmocka_unit_test(test_run_whodata_scan),
        //cmocka_unit_test(test_free_syscheck_dirtb_data),
        cmocka_unit_test(test_free_syscheck_dirtb_data_null),
        cmocka_unit_test(test_realtime_process),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
