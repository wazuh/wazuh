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

#include "../wrappers/common.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../headers/version_op.h"

/* setup/teardowns */
static int setup_group(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
    return 0;
}

/* tests */

#ifdef __linux__
static int delete_os_info(void **state)
{
    os_info *data = *state;
    free_osinfo(data);
    return 0;
}

// Linux Only
void test_get_unix_version_Ubuntu1904(void **state)
{
    (void) state;
    os_info *ret;

    // Open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "NAME=\"Ubuntu\"");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "VERSION=\"19.04 (Disco Dingo)\"");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "ID=ubuntu");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "EOF");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, NULL);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "Ubuntu");
    assert_string_equal(ret->os_major, "19");
    assert_string_equal(ret->os_minor, "04");
    assert_string_equal(ret->os_version, "19.04 (Disco Dingo)");
    assert_string_equal(ret->os_codename, "Disco Dingo");
    assert_string_equal(ret->os_platform, "ubuntu");
    assert_string_equal(ret->sysname, "Linux");
}
// Linux Only
void test_get_unix_version_Centos7(void **state)
{
    (void) state;
    os_info *ret;

    // Open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "NAME=\"CentOS Linux\"");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "VERSION=\"7 (Core)\"");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "ID=centos");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "EOF");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, NULL);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    // Check centos-release file
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "CentOS Linux release 7.5.1804 (Core)");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "CentOS Linux");
    assert_string_equal(ret->os_major, "7");
    assert_string_equal(ret->os_minor, "5");
    assert_string_equal(ret->os_build, "1804");
    assert_string_equal(ret->os_version, "7.5.1804 (Core)");
    assert_string_equal(ret->os_codename, "Core");
    assert_string_equal(ret->os_platform, "centos");
    assert_string_equal(ret->sysname, "Linux");
}
// Linux Only
void test_get_unix_version_centos_release(void **state)
{
    (void) state;
    os_info *ret;

    // Do not open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Do not open /etc/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Open centos-release file
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "CentOS Linux release 7.5.1804 (Core)");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "CentOS Linux");
    assert_string_equal(ret->os_major, "7");
    assert_string_equal(ret->os_minor, "5");
    assert_string_equal(ret->os_build, "1804");
    assert_string_equal(ret->os_version, "7.5.1804 (Core)");
    assert_string_equal(ret->os_codename, "Core");
    assert_string_equal(ret->os_platform, "centos");
    assert_string_equal(ret->sysname, "Linux");
}
// Linux Only
void test_get_unix_version_fedora_release(void **state)
{
    (void) state;
    os_info *ret;

    // Do not open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Do not open /etc/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Do not open centos-release file
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Open fedora-release file
    expect_string(__wrap_fopen, path, "/etc/fedora-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "Fedora release 29 (Twenty Nine)");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "Fedora");
    assert_string_equal(ret->os_major, "29");
    assert_string_equal(ret->os_version, "29 (Twenty Nine)");
    assert_string_equal(ret->os_codename, "Twenty Nine");
    assert_string_equal(ret->os_platform, "fedora");
    assert_string_equal(ret->sysname, "Linux");
}
#endif

int main(void) {
    const struct CMUnitTest tests[] = {
#ifdef __linux__
            cmocka_unit_test_teardown(test_get_unix_version_Ubuntu1904, delete_os_info),
            //cmocka_unit_test_teardown(test_get_unix_version_Centos7, delete_os_info),
            //cmocka_unit_test_teardown(test_get_unix_version_centos_release, delete_os_info),
            //cmocka_unit_test_teardown(test_get_unix_version_fedora_release, delete_os_info),
#endif
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
