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
#include <string.h>
#include "shared.h"
#include "../headers/binaries_op.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"

/* setups/teardowns */
static int setup_group(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
    return 0;
}

#ifndef TEST_WINAGENT
extern char * __real_getenv(const char *name);
char * __wrap_getenv(const char *name) {
    if (!test_mode) {
        return __real_getenv(name);
    }
    check_expected(name);
    return mock_type(char *);
}
#endif

#ifdef TEST_WINAGENT
void test_get_binary_path_full_path_found(void **state) {
    char *cmd_path = NULL;

    expect_string(__wrap_IsFile, file, "c:\\home\\test\\uname");
    will_return(__wrap_IsFile, 0);

    int ret = get_binary_path("c:\\home\\test\\uname", &cmd_path);

    assert_int_equal(ret, OS_SUCCESS);
    assert_string_equal(cmd_path, "c:\\home\\test\\uname");

    os_free(cmd_path);
}

void test_get_binary_path_full_path_not_found(void **state) {
    char *cmd_path = NULL;

    expect_string(__wrap_IsFile, file, "c:\\home\\test\\uname");
    will_return(__wrap_IsFile, -1);

    int ret = get_binary_path("c:\\home\\test\\uname", &cmd_path);

    assert_int_equal(ret, OS_INVALID);
    assert_string_equal(cmd_path, "c:\\home\\test\\uname");
    os_free(cmd_path);
}

void test_get_binary_path_first(void **state) {
    char *cmd_path = NULL;
    char path[OS_BUFFER_SIZE] = "c:\\home\\test";

    expect_string(wrap_getenv, name, "PATH");
    will_return(wrap_getenv, path);

    expect_string(__wrap_IsFile, file, "c:\\home\\test\\uname");
    will_return(__wrap_IsFile, 0);

    int ret = get_binary_path("uname", &cmd_path);

    assert_int_equal(ret, OS_SUCCESS);
    assert_string_equal(cmd_path, "c:\\home\\test\\uname");

    os_free(cmd_path);
}

void test_get_binary_path_usr_bin(void **state) {
    char *cmd_path = NULL;
    char path[OS_BUFFER_SIZE] = "c:\\home\\test;c:\\usr\\bin";

    expect_string(wrap_getenv, name, "PATH");
    will_return(wrap_getenv, path);

    expect_string(__wrap_IsFile, file, "c:\\home\\test\\uname");
    will_return(__wrap_IsFile, -1);

    expect_string(__wrap_IsFile, file, "c:\\usr\\bin\\uname");
    will_return(__wrap_IsFile, 0);

    int ret = get_binary_path("uname", &cmd_path);

    assert_int_equal(ret, OS_SUCCESS);
    assert_string_equal(cmd_path, "c:\\usr\\bin\\uname");
    os_free(cmd_path);
}

void test_get_binary_path_not_found(void **state) {
    char *cmd_path = NULL;
    char path[OS_BUFFER_SIZE] = "c:\\home\\test;c:\\usr\\bin";

    expect_string(wrap_getenv, name, "PATH");
    will_return(wrap_getenv, path);

    expect_string(__wrap_IsFile, file, "c:\\home\\test\\uname");
    will_return(__wrap_IsFile, -1);

    expect_string(__wrap_IsFile, file, "c:\\usr\\bin\\uname");
    will_return(__wrap_IsFile, -1);

    int ret = get_binary_path("uname", &cmd_path);

    assert_int_equal(ret, OS_INVALID);
    assert_string_equal(cmd_path, "uname");
    os_free(cmd_path);
}

void test_get_binary_path_first_validated_null(void **state) {
    char path[OS_BUFFER_SIZE] = "c:\\home\\test";

    expect_string(wrap_getenv, name, "PATH");
    will_return(wrap_getenv, path);

    expect_string(__wrap_IsFile, file, "c:\\home\\test\\uname");
    will_return(__wrap_IsFile, 0);

    int ret = get_binary_path("uname", NULL);

    assert_int_equal(ret, OS_SUCCESS);
}

void test_get_binary_path_not_found_validated_null(void **state) {
    char path[OS_BUFFER_SIZE] = "c:\\home\\test;c:\\usr\\bin";

    expect_string(wrap_getenv, name, "PATH");
    will_return(wrap_getenv, path);

    expect_string(__wrap_IsFile, file, "c:\\home\\test\\uname");
    will_return(__wrap_IsFile, -1);

    expect_string(__wrap_IsFile, file, "c:\\usr\\bin\\uname");
    will_return(__wrap_IsFile, -1);

    int ret = get_binary_path("uname", NULL);

    assert_int_equal(ret, OS_INVALID);
}

void test_get_binary_path_envpath_null(void **state) {
    char *cmd_path = NULL;

    expect_string(wrap_getenv, name, "PATH");
    will_return(wrap_getenv, NULL);

    int ret = get_binary_path("uname", &cmd_path);

    assert_int_equal(ret, OS_INVALID);
    assert_string_equal(cmd_path, "uname");
    os_free(cmd_path);
}
#else
void test_get_binary_path_full_path_found(void **state) {
    char *cmd_path = NULL;

    expect_string(__wrap_IsFile, file, "/home/test/uname");
    will_return(__wrap_IsFile, 0);

    int ret = get_binary_path("/home/test/uname", &cmd_path);

    assert_int_equal(ret, OS_SUCCESS);
    assert_string_equal(cmd_path, "/home/test/uname");

    os_free(cmd_path);
}

void test_get_binary_path_full_path_not_found(void **state) {
    char *cmd_path = NULL;

    expect_string(__wrap_IsFile, file, "/home/test/uname");
    will_return(__wrap_IsFile, -1);

    int ret = get_binary_path("/home/test/uname", &cmd_path);

    assert_int_equal(ret, OS_INVALID);
    assert_string_equal(cmd_path, "/home/test/uname");

    os_free(cmd_path);
}

void test_get_binary_path_first(void **state) {
    char *cmd_path = NULL;
    char path[OS_BUFFER_SIZE] = "/home/test";

    expect_string(__wrap_getenv, name, "PATH");
    will_return(__wrap_getenv, path);

    expect_string(__wrap_IsFile, file, "/home/test/uname");
    will_return(__wrap_IsFile, 0);

    int ret = get_binary_path("uname", &cmd_path);

    assert_int_equal(ret, OS_SUCCESS);
    assert_string_equal(cmd_path, "/home/test/uname");

    os_free(cmd_path);
}

void test_get_binary_path_usr_bin(void **state) {
    char *cmd_path = NULL;
    char path[OS_BUFFER_SIZE] = "/home/test:/usr/bin";

    expect_string(__wrap_getenv, name, "PATH");
    will_return(__wrap_getenv, path);

    expect_string(__wrap_IsFile, file, "/home/test/uname");
    will_return(__wrap_IsFile, -1);

    expect_string(__wrap_IsFile, file, "/usr/bin/uname");
    will_return(__wrap_IsFile, 0);

    int ret = get_binary_path("uname", &cmd_path);

    assert_int_equal(ret, OS_SUCCESS);
    assert_string_equal(cmd_path, "/usr/bin/uname");
    os_free(cmd_path);
}

void test_get_binary_path_not_found(void **state) {
    char *cmd_path = NULL;
    char path[OS_BUFFER_SIZE] = "/home/test:/usr/bin";

    expect_string(__wrap_getenv, name, "PATH");
    will_return(__wrap_getenv, path);

    expect_string(__wrap_IsFile, file, "/home/test/uname");
    will_return(__wrap_IsFile, -1);

    expect_string(__wrap_IsFile, file, "/usr/bin/uname");
    will_return(__wrap_IsFile, -1);

    int ret = get_binary_path("uname", &cmd_path);

    assert_int_equal(ret, OS_INVALID);
    assert_string_equal(cmd_path, "uname");
    os_free(cmd_path);
}

void test_get_binary_path_first_validated_null(void **state) {
    char path[OS_BUFFER_SIZE] = "/home/test";

    expect_string(__wrap_getenv, name, "PATH");
    will_return(__wrap_getenv, path);

    expect_string(__wrap_IsFile, file, "/home/test/uname");
    will_return(__wrap_IsFile, 0);

    int ret = get_binary_path("uname", NULL);

    assert_int_equal(ret, OS_SUCCESS);
}

void test_get_binary_path_not_found_validated_null(void **state) {
    char path[OS_BUFFER_SIZE] = "/home/test:/usr/bin";

    expect_string(__wrap_getenv, name, "PATH");
    will_return(__wrap_getenv, path);

    expect_string(__wrap_IsFile, file, "/home/test/uname");
    will_return(__wrap_IsFile, -1);

    expect_string(__wrap_IsFile, file, "/usr/bin/uname");
    will_return(__wrap_IsFile, -1);

    int ret = get_binary_path("uname", NULL);

    assert_int_equal(ret, OS_INVALID);
}

void test_get_binary_path_envpath_null(void **state) {
    char *cmd_path = NULL;

    expect_string(__wrap_getenv, name, "PATH");
    will_return(__wrap_getenv, NULL);

    int ret = get_binary_path("uname", &cmd_path);

    assert_int_equal(ret, OS_INVALID);
    assert_string_equal(cmd_path, "uname");
    os_free(cmd_path);
}
#endif


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_get_binary_path_full_path_found),
        cmocka_unit_test(test_get_binary_path_full_path_not_found),
        cmocka_unit_test(test_get_binary_path_first),
        cmocka_unit_test(test_get_binary_path_usr_bin),
        cmocka_unit_test(test_get_binary_path_not_found),
        cmocka_unit_test(test_get_binary_path_first_validated_null),
        cmocka_unit_test(test_get_binary_path_not_found_validated_null),
        cmocka_unit_test(test_get_binary_path_envpath_null),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
