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

#include "../headers/file_op.h"

/* redefinitons/wrapping */

int __wrap_isChroot() {
    return mock();
}

int __wrap_chmod(const char *path)
{
    check_expected_ptr(path);
    return mock();
}

int __wrap_getpid()
{
    return 42;
}

int __wrap_File_DateofChange(const char *file)
{
    return 1;
}

int __wrap_stat()
{
    return 1;
}

int __wrap_unlink(const char *file)
{
    check_expected_ptr(file);
    return mock();
}

int __wrap__mferror()
{
    return 0;
}

/* tests */

void test_CreatePID_success(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_isChroot, 1);

    expect_string(__wrap_chmod, path, "/var/run/test-42.pid");
    will_return(__wrap_chmod, 0);

    ret = CreatePID("test", 42);
    assert_int_equal(0, ret);
}


void test_CreatePID_failure_chmod(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_isChroot, 1);

    expect_string(__wrap_chmod, path, "/var/run/test-42.pid");
    will_return(__wrap_chmod, -1);

    ret = CreatePID("test", 42);
    assert_int_equal(-1, ret);
}


void test_DeletePID_success(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_isChroot, 1);
    expect_string(__wrap_unlink, file, "/var/run/test-42.pid");
    will_return(__wrap_unlink, 0);

    ret = DeletePID("test");
    assert_int_equal(0, ret);
}


void test_DeletePID_failure(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_isChroot, 0);
    expect_string(__wrap_unlink, file, "/var/ossec/var/run/test-42.pid");
    will_return(__wrap_unlink, 1);

    ret = DeletePID("test");
    assert_int_equal(-1, ret);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_CreatePID_success),
        cmocka_unit_test(test_CreatePID_failure_chmod),
        cmocka_unit_test(test_DeletePID_success),
        cmocka_unit_test(test_DeletePID_failure),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
