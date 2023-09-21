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
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../headers/binaries_op.h"

char *__wrap_getenv(const char *__name) {
    check_expected(__name);
    return mock_type(char *);
}

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
    assert_null(cmd_path);
}

void test_get_binary_path_first(void **state) {
    char *cmd_path = NULL;
    char *path = NULL;

    os_strdup("c:\\home\\test\\", path);
    expect_string(__wrap_getenv, __name, "PATH");
    will_return(__wrap_getenv, path);

    expect_string(__wrap_IsFile, file, "c:\\home\\test\\uname");
    will_return(__wrap_IsFile, 0);

    int ret = get_binary_path("uname", &cmd_path);

    assert_int_equal(ret, OS_SUCCESS);
    assert_string_equal(cmd_path, "c:\\home\\test\\uname");

    os_free(cmd_path);
}

void test_get_binary_path_usr_bin(void **state) {
    char *cmd_path = NULL;
    char *path = NULL;

    os_strdup("c:\\home\\test\\uname;c:\\usr\\bin", path);
    expect_string(__wrap_getenv, __name, "PATH");
    will_return(__wrap_getenv, path);

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
    char *path = NULL;

    os_strdup("c:\\home\\test\\uname:c:\\usr\\bin", path);
    expect_string(__wrap_getenv, __name, "PATH");
    will_return(__wrap_getenv, path);

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
    char *path = NULL;

    os_strdup("c:\\home\\test", path);
    expect_string(__wrap_getenv, __name, "PATH");
    will_return(__wrap_getenv, path);

    expect_string(__wrap_IsFile, file, "c:\\home\\test\\uname");
    will_return(__wrap_IsFile, 0);

    int ret = get_binary_path("uname", NULL);

    assert_int_equal(ret, OS_SUCCESS);
}

void test_get_binary_path_not_found_validated_null(void **state) {
    char *path = NULL;

    os_strdup("c:\\home\\test\\uname:c:\\usr\\bin", path);
    expect_string(__wrap_getenv, __name, "PATH");
    will_return(__wrap_getenv, path);

    expect_string(__wrap_IsFile, file, "c:\\home\\test\\uname");
    will_return(__wrap_IsFile, -1);

    expect_string(__wrap_IsFile, file, "c:\\usr\\bin\\uname");
    will_return(__wrap_IsFile, -1);

    int ret = get_binary_path("uname", NULL);

    assert_int_equal(ret, OS_INVALID);
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
    assert_null(cmd_path);
}

void test_get_binary_path_first(void **state) {
    char *cmd_path = NULL;
    char *path = NULL;

    os_strdup("/home/test", path);
    expect_string(__wrap_getenv, __name, "PATH");
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
    char *path = NULL;

    os_strdup("/home/test:/usr/bin", path);
    expect_string(__wrap_getenv, __name, "PATH");
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
    char *path = NULL;

    os_strdup("/home/test:/usr/bin", path);
    expect_string(__wrap_getenv, __name, "PATH");
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
    char *path = NULL;

    os_strdup("/home/test", path);
    expect_string(__wrap_getenv, __name, "PATH");
    will_return(__wrap_getenv, path);

    expect_string(__wrap_IsFile, file, "/home/test/uname");
    will_return(__wrap_IsFile, 0);

    int ret = get_binary_path("uname", NULL);

    assert_int_equal(ret, OS_SUCCESS);
}

void test_get_binary_path_not_found_validated_null(void **state) {
    char *path = NULL;

    os_strdup("/home/test:/usr/bin", path);
    expect_string(__wrap_getenv, __name, "PATH");
    will_return(__wrap_getenv, path);

    expect_string(__wrap_IsFile, file, "/home/test/uname");
    will_return(__wrap_IsFile, -1);

    expect_string(__wrap_IsFile, file, "/usr/bin/uname");
    will_return(__wrap_IsFile, -1);

    int ret = get_binary_path("uname", NULL);

    assert_int_equal(ret, OS_INVALID);
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
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
