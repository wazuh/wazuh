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

#include "../headers/version_op.h"

static int unit_testing;

/* redefinitons/wrapping */

int __real_fopen(const char *filename, const char *mode);
int __wrap_fopen(const char *filename, const char *mode) {
    if(unit_testing){
        check_expected(filename);
        return mock();
    } else {
        return __real_fopen(filename, mode);
    }
}

int __wrap_fclose() {
    return 1;
}

int __wrap_fgets(char *str, int n, FILE *stream) {
    strncpy(str, mock_type(char *), 256);
    return mock_type(int);
}

/* setup/teardowns */
static int setup_group(void **state) {
    unit_testing = 1;
    return 0;
}

static int teardown_group(void **state) {
    unit_testing = 0;
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
        expect_string(__wrap_fopen, filename, "/etc/os-release");
        will_return(__wrap_fopen, 1);

        will_return(__wrap_fgets, "NAME=\"Ubuntu\"");
        will_return(__wrap_fgets, 1);
        will_return(__wrap_fgets, "VERSION=\"19.04 (Disco Dingo)\"");
        will_return(__wrap_fgets, 1);
        will_return(__wrap_fgets, "ID=ubuntu");
        will_return(__wrap_fgets, 1);
        will_return(__wrap_fgets, "EOF");
        will_return(__wrap_fgets, 0);
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
        expect_string(__wrap_fopen, filename, "/etc/os-release");
        will_return(__wrap_fopen, 1);

        will_return(__wrap_fgets, "NAME=\"CentOS Linux\"");
        will_return(__wrap_fgets, 1);
        will_return(__wrap_fgets, "VERSION=\"7 (Core)\"");
        will_return(__wrap_fgets, 1);
        will_return(__wrap_fgets, "ID=centos");
        will_return(__wrap_fgets, 1);
        will_return(__wrap_fgets, "EOF");
        will_return(__wrap_fgets, 0);

        // Check centos-release file
        expect_string(__wrap_fopen, filename, "/etc/centos-release");
        will_return(__wrap_fopen, 1);
        will_return(__wrap_fgets, "CentOS Linux release 7.5.1804 (Core)");
        will_return(__wrap_fgets, 1);

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
        expect_string(__wrap_fopen, filename, "/etc/os-release");
        will_return(__wrap_fopen, 0);

        // Do not open /etc/os-release
        expect_string(__wrap_fopen, filename, "/usr/lib/os-release");
        will_return(__wrap_fopen, 0);

        // Open centos-release file
        expect_string(__wrap_fopen, filename, "/etc/centos-release");
        will_return(__wrap_fopen, 1);

        will_return(__wrap_fgets, "CentOS Linux release 7.5.1804 (Core)");
        will_return(__wrap_fgets, 1);

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
        expect_string(__wrap_fopen, filename, "/etc/os-release");
        will_return(__wrap_fopen, 0);

        // Do not open /etc/os-release
        expect_string(__wrap_fopen, filename, "/usr/lib/os-release");
        will_return(__wrap_fopen, 0);

        // Do not open centos-release file
        expect_string(__wrap_fopen, filename, "/etc/centos-release");
        will_return(__wrap_fopen, 0);

        // Open fedora-release file
        expect_string(__wrap_fopen, filename, "/etc/fedora-release");
        will_return(__wrap_fopen, 1);

        will_return(__wrap_fgets, "Fedora release 29 (Twenty Nine)");
        will_return(__wrap_fgets, 1);

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
