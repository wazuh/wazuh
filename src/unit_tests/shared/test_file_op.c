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
#include <stdlib.h>
#include <string.h>
#include "headers/defs.h"

#include "../wrappers/common.h"
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

int __wrap_stat(const char * path, struct stat * buf)
{
    memset(buf, 0, sizeof(struct stat));
    return 0;
}

int __wrap_unlink(const char *file)
{
    check_expected_ptr(file);
    return mock();
}

int __wrap__merror()
{
    return 0;
}

int __wrap__mwarn()
{
    return 0;
}

int __wrap__minfo()
{
    return 0;
}

int __wrap__mferror(const char * file, int line, const char * func, const char *msg, ...){
    return 0;
}

/* setups/teardowns */
static int setup_group(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
    return 0;
}

static int CreatePID_teardown(void **state) {
    test_mode = 0;
    remove("./test_file.tmp");

    if(*state) {
        free(*state);
    }
    test_mode = 1;
    return 0;
}

void test_CreatePID_success(void **state)
{
    (void) state;
    int ret;
    test_mode = 0;
    FILE* fp = fopen("./test_file.tmp", "a");
    test_mode = 1;
    char* content = NULL;

    *state = content;

    will_return(__wrap_isChroot, 1);

    expect_string(__wrap_fopen, path, "/var/run/test-42.pid");
    expect_string(__wrap_fopen, mode, "a");
    will_return(__wrap_fopen, fp);

#ifdef WIN32
    expect_value(wrap_fprintf, __stream, fp);
    expect_string(wrap_fprintf, formatted_msg, "42\n");
    will_return(wrap_fprintf, 0);
#else
    expect_value(__wrap_fprintf, __stream, fp);
    expect_string(__wrap_fprintf, formatted_msg, "42\n");
    will_return(__wrap_fprintf, 0);
#endif

    expect_string(__wrap_chmod, path, "/var/run/test-42.pid");
    will_return(__wrap_chmod, 0);

    expect_value(__wrap_fclose, _File, fp);
    will_return(__wrap_fclose, 0);

    ret = CreatePID("test", 42);
    assert_int_equal(0, ret);
}

void test_CreatePID_failure_chmod(void **state)
{
    (void) state;
    int ret;
    test_mode = 0;
    FILE* fp = fopen("./test_file.tmp", "a");
    test_mode = 1;

    assert_non_null(fp);

    will_return(__wrap_isChroot, 1);

    expect_string(__wrap_fopen, path, "/var/run/test-42.pid");
    expect_string(__wrap_fopen, mode, "a");
    will_return(__wrap_fopen, fp);

#ifdef WIN32
    expect_value(wrap_fprintf, __stream, fp);
    expect_string(wrap_fprintf, formatted_msg, "42\n");
    will_return(wrap_fprintf, 0);
#else
    expect_value(__wrap_fprintf, __stream, fp);
    expect_string(__wrap_fprintf, formatted_msg, "42\n");
    will_return(__wrap_fprintf, 0);
#endif

    expect_string(__wrap_chmod, path, "/var/run/test-42.pid");
    will_return(__wrap_chmod, -1);

    expect_value(__wrap_fclose, _File, fp);
    will_return(__wrap_fclose, 0);

    ret = CreatePID("test", 42);
    assert_int_equal(-1, ret);
}

void test_CreatePID_failure_fopen(void **state)
{
    (void) state;
    int ret;

    will_return(__wrap_isChroot, 1);

    expect_string(__wrap_fopen, path, "/var/run/test-42.pid");
    expect_string(__wrap_fopen, mode, "a");
    will_return(__wrap_fopen, NULL);

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
        cmocka_unit_test_teardown(test_CreatePID_success, CreatePID_teardown),
        cmocka_unit_test_teardown(test_CreatePID_failure_chmod, CreatePID_teardown),
        cmocka_unit_test(test_CreatePID_failure_fopen),
        cmocka_unit_test(test_DeletePID_success),
        cmocka_unit_test(test_DeletePID_failure),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
