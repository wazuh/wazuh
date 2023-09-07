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
#include "../wrappers/common.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../headers/binaries_op.h"

int __wrap_access (const char *__name, int __type) {
    check_expected(__name);
    check_expected(__type);
    return mock();
}

/* setup/teardowns */
static int setup_group(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
    return 0;
}



void test_get_binary_path_first(void **state) {
    char cmd_path[PATH_MAX + 1] = {0};

#if defined (__linux__)
    expect_string(__wrap_access, __name, "/usr/local/sbin/uname");
#elif defined (__MACH__)
    expect_string(__wrap_access, __name, "/usr/local/bin/uname");
#endif
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, 0);

    int ret = get_binary_path("uname", cmd_path);

    assert_int_equal(ret, OS_SUCCESS);
#if defined (__linux__)
    assert_string_equal(cmd_path, "/usr/local/sbin/uname");
#elif defined (__MACH__)
    assert_string_equal(cmd_path, "/usr/local/bin/uname");
#endif
}

void test_get_binary_path_usr_bin(void **state) {
    char cmd_path[PATH_MAX + 1] = {0};

#if defined (__linux__)
    expect_string(__wrap_access, __name, "/usr/local/sbin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/usr/local/bin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/usr/sbin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);
#elif defined (__MACH__)
    expect_string(__wrap_access, __name, "/usr/local/bin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);
#endif

    expect_string(__wrap_access, __name, "/usr/bin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, 0);

    int ret = get_binary_path("uname", cmd_path);

    assert_int_equal(ret, OS_SUCCESS);
    assert_string_equal(cmd_path, "/usr/bin/uname");
}

void test_get_binary_path_last(void **state) {
    char cmd_path[PATH_MAX + 1] = {0};

#if defined (__linux__)
    expect_string(__wrap_access, __name, "/usr/local/sbin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/usr/local/bin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/usr/sbin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/usr/bin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/sbin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/bin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/snap/bin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, 0);
#elif defined (__MACH__)
    expect_string(__wrap_access, __name, "/usr/local/bin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/usr/bin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/bin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/usr/sbin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/sbin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, 0);
#endif

    int ret = get_binary_path("uname", cmd_path);

    assert_int_equal(ret, OS_SUCCESS);
#if defined (__linux__)
    assert_string_equal(cmd_path, "/snap/bin/uname");
#elif defined (__MACH__)
    assert_string_equal(cmd_path, "/sbin/uname");
#endif
}

void test_get_binary_path_not_found(void **state) {
    char cmd_path[PATH_MAX + 1] = {0};

#if defined (__linux__)
    expect_string(__wrap_access, __name, "/usr/local/sbin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/usr/local/bin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/usr/sbin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/usr/bin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/sbin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/bin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/snap/bin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);
#elif defined (__MACH__)
    expect_string(__wrap_access, __name, "/usr/local/bin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/usr/bin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/bin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/usr/sbin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_access, __name, "/sbin/uname");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);
#endif
    int ret = get_binary_path("uname", cmd_path);

    assert_int_equal(ret, OS_INVALID);
    assert_string_equal(cmd_path, "uname");
}



int main(void) {
    const struct CMUnitTest tests[] = {
#if defined (__linux__) || defined (__MACH__)
    cmocka_unit_test(test_get_binary_path_first),
    cmocka_unit_test(test_get_binary_path_usr_bin),
    cmocka_unit_test(test_get_binary_path_last),
    cmocka_unit_test(test_get_binary_path_not_found),
#endif
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
