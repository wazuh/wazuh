/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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

void test_get_unix_version_centos(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Open /usr/lib/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
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

    // Open /etc/centos-release
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
    assert_string_equal(ret->os_version, "7.5");
    assert_string_equal(ret->os_platform, "centos");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_opensuse_tumbleweed(void **state)
{
    (void) state;
    os_info *ret;

    // Open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "NAME=\"openSUSE Tumbleweed\"");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "# VERSION=\"20211202\"");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "ID=opensuse-tumbleweed");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, NULL);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "openSUSE Tumbleweed");
    assert_string_equal(ret->os_version, "");
    assert_string_equal(ret->os_platform, "opensuse-tumbleweed");
    assert_string_equal(ret->sysname, "Linux");
    assert_string_equal(ret->os_build, "rolling");
}

void test_get_unix_version_fail_os_release_centos(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Open /etc/centos-release
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "CentOS Linux release 6.2.1604 (Core)");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "CentOS Linux");
    assert_string_equal(ret->os_major, "6");
    assert_string_equal(ret->os_minor, "2");
    assert_string_equal(ret->os_version, "6.2");
    assert_string_equal(ret->os_platform, "centos");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_fail_os_release_fedora(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Open /etc/fedora-release
    expect_string(__wrap_fopen, path, "/etc/fedora-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "Fedora release 7 (Moonshine)");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "Fedora");
    assert_string_equal(ret->os_major, "7");
    assert_string_equal(ret->os_version, "7");
    assert_string_equal(ret->os_platform, "fedora");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_fail_os_release_redhat_centos(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_fopen, path, "/etc/fedora-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Open /etc/redhat-release
    expect_string(__wrap_fopen, path, "/etc/redhat-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "CentOS Linux Server release 7.2 (Maipo)");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "CentOS Linux");
    assert_string_equal(ret->os_major, "7");
    assert_string_equal(ret->os_minor, "2");
    assert_string_equal(ret->os_version, "7.2");
    assert_string_equal(ret->os_platform, "centos");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_fail_os_release_redhat_fedora(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_fopen, path, "/etc/fedora-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Open /etc/redhat-release
    expect_string(__wrap_fopen, path, "/etc/redhat-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "Fedora Linux Server release 7.2 (Maipo)");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "Fedora");
    assert_string_equal(ret->os_major, "7");
    assert_string_equal(ret->os_minor, "2");
    assert_string_equal(ret->os_version, "7.2");
    assert_string_equal(ret->os_platform, "fedora");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_fail_os_release_redhat_rhel(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_fopen, path, "/etc/fedora-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Open /etc/redhat-release
    expect_string(__wrap_fopen, path, "/etc/redhat-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "Red Hat Enterprise Linux release 7.2 (Maipo)");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "Red Hat Enterprise Linux");
    assert_string_equal(ret->os_major, "7");
    assert_string_equal(ret->os_minor, "2");
    assert_string_equal(ret->os_version, "7.2");
    assert_string_equal(ret->os_platform, "rhel");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_fail_os_release_redhat_rhel_server(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_fopen, path, "/etc/fedora-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Open /etc/redhat-release
    expect_string(__wrap_fopen, path, "/etc/redhat-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "Red Hat Enterprise Linux Server release 7.2 (Maipo)");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "Red Hat Enterprise Linux Server");
    assert_string_equal(ret->os_major, "7");
    assert_string_equal(ret->os_minor, "2");
    assert_string_equal(ret->os_version, "7.2");
    assert_string_equal(ret->os_platform, "rhel");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_fail_os_release_ubuntu(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_fopen, path, "/etc/fedora-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_fopen, path, "/etc/redhat-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_fopen, path, "/etc/arch-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Open /etc/lsb-release
    expect_string(__wrap_fopen, path, "/etc/lsb-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "DISTRIB_RELEASE=20.04");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "Ubuntu");
    assert_string_equal(ret->os_major, "20");
    assert_string_equal(ret->os_minor, "04");
    assert_string_equal(ret->os_version, "20.04");
    assert_string_equal(ret->os_platform, "ubuntu");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_fail_os_release_gentoo(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_fopen, path, "/etc/fedora-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_fopen, path, "/etc/redhat-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_fopen, path, "/etc/arch-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_fopen, path, "/etc/lsb-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Open /etc/gentoo-release
    expect_string(__wrap_fopen, path, "/etc/gentoo-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "Gentoo Base System version 1.6.12");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "Gentoo");
    assert_string_equal(ret->os_major, "1");
    assert_string_equal(ret->os_minor, "6");
    assert_string_equal(ret->os_version, "1.6");
    assert_string_equal(ret->os_platform, "gentoo");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_fail_os_release_suse(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_fopen, path, "/etc/fedora-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_fopen, path, "/etc/redhat-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_fopen, path, "/etc/arch-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_fopen, path, "/etc/lsb-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_fopen, path, "/etc/gentoo-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Open /etc/SuSE-release
    expect_string(__wrap_fopen, path, "/etc/SuSE-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "VERSION = 3.5");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "SuSE Linux");
    assert_string_equal(ret->os_major, "3");
    assert_string_equal(ret->os_version, "3");
    assert_string_equal(ret->os_platform, "suse");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_fail_os_release_arch(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_fopen, path, "/etc/fedora-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_fopen, path, "/etc/redhat-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Open /etc/arch-release
    expect_string(__wrap_fopen, path, "/etc/arch-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "3.5.14");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "Arch Linux");
    assert_string_equal(ret->os_major, "3");
    assert_string_equal(ret->os_minor, "5");
    assert_string_equal(ret->os_version, "3.5");
    assert_string_equal(ret->os_platform, "arch");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_fail_os_release_debian(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_fopen, path, "/etc/fedora-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_fopen, path, "/etc/redhat-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_fopen, path, "/etc/arch-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_fopen, path, "/etc/lsb-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_fopen, path, "/etc/gentoo-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_fopen, path, "/etc/SuSE-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Open /etc/debian_version
    expect_string(__wrap_fopen, path, "/etc/debian_version");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "3.5.14");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "Debian GNU/Linux");
    assert_string_equal(ret->os_major, "3");
    assert_string_equal(ret->os_minor, "5");
    assert_string_equal(ret->os_version, "3.5");
    assert_string_equal(ret->os_platform, "debian");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_fail_os_release_slackware(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_fopen, path, "/etc/fedora-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_fopen, path, "/etc/redhat-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_fopen, path, "/etc/arch-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_fopen, path, "/etc/lsb-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_fopen, path, "/etc/gentoo-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_fopen, path, "/etc/SuSE-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/debian_version
    expect_string(__wrap_fopen, path, "/etc/debian_version");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Open /etc/slackware-version
    expect_string(__wrap_fopen, path, "/etc/slackware-version");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "Slackware 14.2");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "Slackware");
    assert_string_equal(ret->os_major, "14");
    assert_string_equal(ret->os_minor, "2");
    assert_string_equal(ret->os_version, "14.2");
    assert_string_equal(ret->os_platform, "slackware");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_fail_os_release_uname_darwin(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_fopen, path, "/etc/fedora-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_fopen, path, "/etc/redhat-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_fopen, path, "/etc/arch-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_fopen, path, "/etc/lsb-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_fopen, path, "/etc/gentoo-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_fopen, path, "/etc/SuSE-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/debian_version
    expect_string(__wrap_fopen, path, "/etc/debian_version");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/slackware-version
    expect_string(__wrap_fopen, path, "/etc/slackware-version");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // uname
    expect_string(__wrap_popen, command, "uname");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "Darwin\n");

    // sw_vers -productName
    expect_string(__wrap_popen, command, "sw_vers -productName");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "macOS Catalina\n");

    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);

    // sw_vers -productVersion
    expect_string(__wrap_popen, command, "sw_vers -productVersion");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "10.2\n");

    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);

    // sw_vers -buildVersion
    expect_string(__wrap_popen, command, "sw_vers -buildVersion");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "10\n");

    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);

    // uname -r
    expect_string(__wrap_popen, command, "uname -r");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "macos\n");

    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);


    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "macOS Catalina");
    assert_string_equal(ret->os_major, "10");
    assert_string_equal(ret->os_minor, "2");
    assert_string_equal(ret->os_version, "10.2");
    assert_string_equal(ret->os_platform, "darwin");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_fail_os_release_uname_sunos(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_fopen, path, "/etc/fedora-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_fopen, path, "/etc/redhat-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_fopen, path, "/etc/arch-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_fopen, path, "/etc/lsb-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_fopen, path, "/etc/gentoo-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_fopen, path, "/etc/SuSE-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/debian_version
    expect_string(__wrap_fopen, path, "/etc/debian_version");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/slackware-version
    expect_string(__wrap_fopen, path, "/etc/slackware-version");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // uname
    expect_string(__wrap_popen, command, "uname");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "SunOS\n");

    // Open /etc/release
    expect_string(__wrap_fopen, path, "/etc/release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "Oracle Solaris 11.1 SPARC");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);


    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "SunOS");
    assert_string_equal(ret->os_major, "11");
    assert_string_equal(ret->os_minor, "1");
    assert_string_equal(ret->os_version, "11.1");
    assert_string_equal(ret->os_platform, "sunos");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_fail_os_release_uname_hp_ux(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_fopen, path, "/etc/fedora-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_fopen, path, "/etc/redhat-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_fopen, path, "/etc/arch-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_fopen, path, "/etc/lsb-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_fopen, path, "/etc/gentoo-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_fopen, path, "/etc/SuSE-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/debian_version
    expect_string(__wrap_fopen, path, "/etc/debian_version");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/slackware-version
    expect_string(__wrap_fopen, path, "/etc/slackware-version");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // uname
    expect_string(__wrap_popen, command, "uname");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "HP-UX\n");

    // uname - r
    expect_string(__wrap_popen, command, "uname -r");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "B.3.5");

    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);


    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "HP-UX");
    assert_string_equal(ret->os_major, "3");
    assert_string_equal(ret->os_minor, "5");
    assert_string_equal(ret->os_version, "3.5");
    assert_string_equal(ret->os_platform, "hp-ux");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_fail_os_release_uname_bsd(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_fopen, path, "/etc/fedora-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_fopen, path, "/etc/redhat-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_fopen, path, "/etc/arch-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_fopen, path, "/etc/lsb-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_fopen, path, "/etc/gentoo-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_fopen, path, "/etc/SuSE-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/debian_version
    expect_string(__wrap_fopen, path, "/etc/debian_version");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/slackware-version
    expect_string(__wrap_fopen, path, "/etc/slackware-version");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // uname
    expect_string(__wrap_popen, command, "uname");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "OpenBSD\n");

    // uname - r
    expect_string(__wrap_popen, command, "uname -r");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "10.3.5");

    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);


    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "BSD");
    assert_string_equal(ret->os_major, "10");
    assert_string_equal(ret->os_minor, "3");
    assert_string_equal(ret->os_version, "10.3");
    assert_string_equal(ret->os_platform, "bsd");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_zscaler(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_fopen, path, "/etc/fedora-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_fopen, path, "/etc/redhat-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_fopen, path, "/etc/arch-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_fopen, path, "/etc/lsb-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_fopen, path, "/etc/gentoo-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_fopen, path, "/etc/SuSE-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/debian_version
    expect_string(__wrap_fopen, path, "/etc/debian_version");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/slackware-version
    expect_string(__wrap_fopen, path, "/etc/slackware-version");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // uname
    expect_string(__wrap_popen, command, "uname");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "ZscalerOS\n");

    // uname - r
    expect_string(__wrap_popen, command, "uname -r");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "10-R");

    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);

    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "BSD");
    assert_string_equal(ret->os_major, "10");
    assert_string_equal(ret->os_version, "10-R");
    assert_string_equal(ret->os_platform, "bsd");
}

void test_get_unix_version_fail_os_release_uname_aix(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_fopen, path, "/etc/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_fopen, path, "/usr/lib/os-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_fopen, path, "/etc/centos-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_fopen, path, "/etc/fedora-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_fopen, path, "/etc/redhat-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_fopen, path, "/etc/arch-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_fopen, path, "/etc/lsb-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_fopen, path, "/etc/gentoo-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_fopen, path, "/etc/SuSE-release");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/debian_version
    expect_string(__wrap_fopen, path, "/etc/debian_version");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // Fail to open /etc/slackware-version
    expect_string(__wrap_fopen, path, "/etc/slackware-version");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    // uname
    expect_string(__wrap_popen, command, "uname");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "AIX\n");

    // oslevel
    expect_string(__wrap_popen, command, "oslevel");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "7.1\n");

    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);


    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "AIX");
    assert_string_equal(ret->os_major, "7");
    assert_string_equal(ret->os_minor, "1");
    assert_string_equal(ret->os_version, "7.1");
    assert_string_equal(ret->os_platform, "aix");
    assert_string_equal(ret->sysname, "Linux");
}

void test_OSX_ReleaseName(void **state) {
    (void)state;

    assert_string_equal(OSX_ReleaseName(9), "Unknown");
    assert_string_equal(OSX_ReleaseName(10), "Snow Leopard");
    assert_string_equal(OSX_ReleaseName(11), "Lion");
    assert_string_equal(OSX_ReleaseName(12), "Mountain Lion");
    assert_string_equal(OSX_ReleaseName(13), "Mavericks");
    assert_string_equal(OSX_ReleaseName(14), "Yosemite");
    assert_string_equal(OSX_ReleaseName(15), "El Capitan");
    assert_string_equal(OSX_ReleaseName(16), "Sierra");
    assert_string_equal(OSX_ReleaseName(17), "High Sierra");
    assert_string_equal(OSX_ReleaseName(18), "Mojave");
    assert_string_equal(OSX_ReleaseName(19), "Catalina");
    assert_string_equal(OSX_ReleaseName(20), "Big Sur");
    assert_string_equal(OSX_ReleaseName(21), "Unknown");
}

#endif

int main(void) {
    const struct CMUnitTest tests[] = {
#ifdef __linux__
            cmocka_unit_test_teardown(test_get_unix_version_Ubuntu1904, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_centos, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_opensuse_tumbleweed, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_centos, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_fedora, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_redhat_centos, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_redhat_fedora, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_redhat_rhel, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_redhat_rhel_server, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_ubuntu, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_gentoo, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_suse, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_arch, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_debian, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_slackware, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_uname_darwin, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_uname_sunos, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_uname_hp_ux, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_uname_bsd, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_zscaler, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_uname_aix, delete_os_info),
            cmocka_unit_test(test_OSX_ReleaseName),
#endif
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
