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
#include "../wrappers/wazuh/shared/binaries_op_wrappers.h"
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
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

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
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

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
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

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

void test_get_unix_version_archlinux_distro_based(void **state)
{
    (void) state;
    os_info *ret;

    // Open /etc/os-release
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "NAME=\"Manjaro Linux\"");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "ID=manjaro");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, NULL);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    // Attempt to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Attempt to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Attempt to open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Open /etc/arch-release
    expect_string(__wrap_wfopen, path, "/etc/arch-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, NULL);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "Arch Linux");
    assert_string_equal(ret->os_version, "");
    assert_string_equal(ret->os_platform, "arch");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_archlinux_no_version_id(void **state)
{
    (void) state;
    os_info *ret;

    // Open /etc/os-release
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "NAME=\"Arch Linux\"");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "ID=arch");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, NULL);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "Arch Linux");
    assert_string_equal(ret->os_version, "");
    assert_string_equal(ret->os_platform, "arch");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_archlinux(void **state)
{
    (void) state;
    os_info *ret;

    // Open /etc/os-release
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "NAME=\"Arch Linux\"");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "VERSION_ID=\"TEMPLATE_VERSION_ID\"");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "ID=arch");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, NULL);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "Arch Linux");
    assert_string_equal(ret->os_version, "");
    assert_string_equal(ret->os_platform, "arch");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_opensuse_tumbleweed_no_version_id(void **state)
{
    (void) state;
    os_info *ret;

    // Open /etc/os-release
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "NAME=\"openSUSE Tumbleweed\"");
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
}

void test_get_unix_version_opensuse_tumbleweed(void **state)
{
    (void) state;
    os_info *ret;

    // Open /etc/os-release
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "NAME=\"openSUSE Tumbleweed\"");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "VERSION_ID=\"20230619\"");
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
}

void test_get_unix_version_alpine(void **state)
{
    (void) state;
    os_info *ret;

    // Open /etc/os-release
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "NAME=\"Alpine Linux\"");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "ID=alpine");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "VERSION_ID=3.17.1");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "PRETTY_NAME=\"Alpine Linux v3.17\"");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "HOME_URL=\"https://alpinelinux.org/\"");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "BUG_REPORT_URL=\"https://gitlab.alpinelinux.org/alpine/aports/-/issues\"");
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, NULL);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "Alpine Linux");
    assert_string_equal(ret->os_major, "3");
    assert_string_equal(ret->os_minor, "17");
    assert_string_equal(ret->os_patch, "1");
    assert_string_equal(ret->os_version, "3.17.1");
    assert_string_equal(ret->os_platform, "alpine");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_fail_os_release_centos(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

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
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

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
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

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
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

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
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

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
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

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
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_wfopen, path, "/etc/arch-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Open /etc/gentoo-release
    expect_string(__wrap_wfopen, path, "/etc/gentoo-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Open /etc/SuSE-release
    expect_string(__wrap_wfopen, path, "/etc/SuSE-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Open /etc/lsb-release
    expect_string(__wrap_wfopen, path, "/etc/lsb-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

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
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_wfopen, path, "/etc/arch-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Open /etc/gentoo-release
    expect_string(__wrap_wfopen, path, "/etc/gentoo-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

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
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_wfopen, path, "/etc/arch-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_wfopen, path, "/etc/gentoo-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Open /etc/SuSE-release
    expect_string(__wrap_wfopen, path, "/etc/SuSE-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

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
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Open /etc/arch-release
    expect_string(__wrap_wfopen, path, "/etc/arch-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

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
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_wfopen, path, "/etc/arch-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_wfopen, path, "/etc/gentoo-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_wfopen, path, "/etc/SuSE-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_wfopen, path, "/etc/lsb-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Open /etc/debian_version
    expect_string(__wrap_wfopen, path, "/etc/debian_version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

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
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_wfopen, path, "/etc/arch-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_wfopen, path, "/etc/gentoo-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_wfopen, path, "/etc/SuSE-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_wfopen, path, "/etc/lsb-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/debian_version
    expect_string(__wrap_wfopen, path, "/etc/debian_version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Open /etc/slackware-version
    expect_string(__wrap_wfopen, path, "/etc/slackware-version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

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

void test_get_unix_version_fail_os_release_alpine(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_wfopen, path, "/etc/arch-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_wfopen, path, "/etc/gentoo-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_wfopen, path, "/etc/SuSE-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_wfopen, path, "/etc/lsb-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/debian_version
    expect_string(__wrap_wfopen, path, "/etc/debian_version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/slackware-version
    expect_string(__wrap_wfopen, path, "/etc/slackware-version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Open /etc/alpine-release
    expect_string(__wrap_wfopen, path, "/etc/alpine-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "3.17.1");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "Alpine Linux");
    assert_string_equal(ret->os_major, "3");
    assert_string_equal(ret->os_minor, "17");
    assert_string_equal(ret->os_patch, "1");
    assert_string_equal(ret->os_version, "3.17.1");
    assert_string_equal(ret->os_platform, "alpine");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_fail_os_release_uname_darwin(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_wfopen, path, "/etc/arch-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_wfopen, path, "/etc/gentoo-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_wfopen, path, "/etc/SuSE-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_wfopen, path, "/etc/lsb-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/debian_version
    expect_string(__wrap_wfopen, path, "/etc/debian_version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/slackware-version
    expect_string(__wrap_wfopen, path, "/etc/slackware-version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/alpine-release
    expect_string(__wrap_wfopen, path, "/etc/alpine-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // uname
    char *uname_path = NULL;
    os_strdup("/path/to/uname", uname_path);
    expect_string(__wrap_get_binary_path, command, "uname");
    will_return(__wrap_get_binary_path, uname_path);
    will_return(__wrap_get_binary_path, 0);

    expect_string(__wrap_popen, command, "/path/to/uname");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "Darwin\n");

    // system_profiler SPSoftwareDataType
    char *system_profiler_path = NULL;
    os_strdup("/path/to/system_profiler", system_profiler_path);
    expect_string(__wrap_get_binary_path, command, "system_profiler");
    will_return(__wrap_get_binary_path, system_profiler_path);
    will_return(__wrap_get_binary_path, 0);

    expect_string(__wrap_popen, command, "/path/to/system_profiler SPSoftwareDataType");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "Software:\n");

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "\n");

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "System Software Overview:\n");

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "\n");

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "    System Version: macOS 10.12 (16A323)\n");

    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);

    // sw_vers -productVersion
    char *sw_vers_path = NULL;
    os_strdup("/path/to/sw_vers", sw_vers_path);
    expect_string(__wrap_get_binary_path, command, "sw_vers");
    will_return(__wrap_get_binary_path, sw_vers_path);
    will_return(__wrap_get_binary_path, 0);

    expect_string(__wrap_popen, command, "/path/to/sw_vers -productVersion");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "10.2\n");

    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);

    // sw_vers -buildVersion
    expect_string(__wrap_popen, command, "/path/to/sw_vers -buildVersion");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "10\n");

    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);

    // uname -r
    expect_string(__wrap_popen, command, "/path/to/uname -r");
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
    assert_string_equal(ret->os_name, "macOS");
    assert_string_equal(ret->os_major, "10");
    assert_string_equal(ret->os_minor, "2");
    assert_string_equal(ret->os_version, "10.2");
    assert_string_equal(ret->os_platform, "darwin");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_fail_os_release_uname_darwin_no_key(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_wfopen, path, "/etc/arch-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_wfopen, path, "/etc/gentoo-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_wfopen, path, "/etc/SuSE-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_wfopen, path, "/etc/lsb-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/debian_version
    expect_string(__wrap_wfopen, path, "/etc/debian_version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/slackware-version
    expect_string(__wrap_wfopen, path, "/etc/slackware-version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/alpine-release
    expect_string(__wrap_wfopen, path, "/etc/alpine-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // uname
    char *uname_path = NULL;
    os_strdup("/path/to/uname", uname_path);
    expect_string(__wrap_get_binary_path, command, "uname");
    will_return(__wrap_get_binary_path, uname_path);
    will_return(__wrap_get_binary_path, 0);

    expect_string(__wrap_popen, command, "/path/to/uname");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "Darwin\n");

    // system_profiler SPSoftwareDataType
    char *cmd_path = NULL;
    os_strdup("/path/to/system_profiler", cmd_path);
    expect_string(__wrap_get_binary_path, command, "system_profiler");
    will_return(__wrap_get_binary_path, cmd_path);
    will_return(__wrap_get_binary_path, 0);

    expect_string(__wrap_popen, command, "/path/to/system_profiler SPSoftwareDataType");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "Software:\n");

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "System Software Overview:\n");

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, NULL);

    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);

    // sw_vers -productVersion
    char *sw_vers_path = NULL;
    os_strdup("/path/to/sw_vers", sw_vers_path);
    expect_string(__wrap_get_binary_path, command, "sw_vers");
    will_return(__wrap_get_binary_path, sw_vers_path);
    will_return(__wrap_get_binary_path, 0);

    expect_string(__wrap_popen, command, "/path/to/sw_vers -productVersion");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "10.2\n");

    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);

    // sw_vers -buildVersion
    expect_string(__wrap_popen, command, "/path/to/sw_vers -buildVersion");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "10\n");

    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);

    // uname -r
    expect_string(__wrap_popen, command, "/path/to/uname -r");
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
    assert_null(ret->os_name);
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
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_wfopen, path, "/etc/arch-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_wfopen, path, "/etc/gentoo-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_wfopen, path, "/etc/SuSE-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_wfopen, path, "/etc/lsb-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/debian_version
    expect_string(__wrap_wfopen, path, "/etc/debian_version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/slackware-version
    expect_string(__wrap_wfopen, path, "/etc/slackware-version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/alpine-release
    expect_string(__wrap_wfopen, path, "/etc/alpine-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // uname
    char *uname_path = NULL;
    os_strdup("/path/to/uname", uname_path);
    expect_string(__wrap_get_binary_path, command, "uname");
    will_return(__wrap_get_binary_path, uname_path);
    will_return(__wrap_get_binary_path, 0);

    expect_string(__wrap_popen, command, "/path/to/uname");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "SunOS\n");

    // Open /etc/release
    expect_string(__wrap_wfopen, path, "/etc/release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

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

// Scenario two: The content of /etc/release is Solaris 10 x/y ...
void test_get_unix_version_fail_os_release_uname_sunos_10_scenario_one(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_wfopen, path, "/etc/arch-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_wfopen, path, "/etc/gentoo-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_wfopen, path, "/etc/SuSE-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_wfopen, path, "/etc/lsb-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/debian_version
    expect_string(__wrap_wfopen, path, "/etc/debian_version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/slackware-version
    expect_string(__wrap_wfopen, path, "/etc/slackware-version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/alpine-release
    expect_string(__wrap_wfopen, path, "/etc/alpine-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // uname
    char *uname_path = NULL;
    os_strdup("/path/to/uname", uname_path);
    expect_string(__wrap_get_binary_path, command, "uname");
    will_return(__wrap_get_binary_path, uname_path);
    will_return(__wrap_get_binary_path, 0);

    expect_string(__wrap_popen, command, "/path/to/uname");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "SunOS\n");

    // Open /etc/release
    expect_string(__wrap_wfopen, path, "/etc/release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "Solaris 10 1/13");


    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);


    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "SunOS");
    assert_string_equal(ret->os_major, "10");
    assert_string_equal(ret->os_version, "10");
    assert_string_equal(ret->os_platform, "sunos");
    assert_string_equal(ret->sysname, "Linux");
}

// Scenario two: The content of /etc/release is Oracle Solaris 10 x/y ...
void test_get_unix_version_fail_os_release_uname_sunos_10_scenario_two(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_wfopen, path, "/etc/arch-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_wfopen, path, "/etc/gentoo-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_wfopen, path, "/etc/SuSE-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_wfopen, path, "/etc/lsb-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/debian_version
    expect_string(__wrap_wfopen, path, "/etc/debian_version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/slackware-version
    expect_string(__wrap_wfopen, path, "/etc/slackware-version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/alpine-release
    expect_string(__wrap_wfopen, path, "/etc/alpine-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // uname
    char *uname_path = NULL;
    os_strdup("/path/to/uname", uname_path);
    expect_string(__wrap_get_binary_path, command, "uname");
    will_return(__wrap_get_binary_path, uname_path);
    will_return(__wrap_get_binary_path, 0);

    expect_string(__wrap_popen, command, "/path/to/uname");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "SunOS\n");

    // Open /etc/release
    expect_string(__wrap_wfopen, path, "/etc/release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "Oracle Solaris 10 1/13");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 1);


    expect_value(__wrap_pclose, stream, 1);
    will_return(__wrap_pclose, 1);

    ret = get_unix_version();
    *state = ret;

    assert_non_null(ret);
    assert_string_equal(ret->os_name, "SunOS");
    assert_string_equal(ret->os_major, "10");
    assert_string_equal(ret->os_version, "10");
    assert_string_equal(ret->os_platform, "sunos");
    assert_string_equal(ret->sysname, "Linux");
}

void test_get_unix_version_fail_os_release_uname_hp_ux(void **state)
{
    (void) state;
    os_info *ret;

    // Fail to open /etc/os-release
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_wfopen, path, "/etc/arch-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_wfopen, path, "/etc/gentoo-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_wfopen, path, "/etc/SuSE-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_wfopen, path, "/etc/lsb-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/debian_version
    expect_string(__wrap_wfopen, path, "/etc/debian_version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/slackware-version
    expect_string(__wrap_wfopen, path, "/etc/slackware-version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/alpine-release
    expect_string(__wrap_wfopen, path, "/etc/alpine-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // uname
    char *uname_path = NULL;
    os_strdup("/path/to/uname", uname_path);
    expect_string(__wrap_get_binary_path, command, "uname");
    will_return(__wrap_get_binary_path, uname_path);
    will_return(__wrap_get_binary_path, 0);

    expect_string(__wrap_popen, command, "/path/to/uname");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "HP-UX\n");

    // uname - r
    expect_string(__wrap_popen, command, "/path/to/uname -r");
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
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_wfopen, path, "/etc/arch-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_wfopen, path, "/etc/gentoo-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_wfopen, path, "/etc/SuSE-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_wfopen, path, "/etc/lsb-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/debian_version
    expect_string(__wrap_wfopen, path, "/etc/debian_version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/slackware-version
    expect_string(__wrap_wfopen, path, "/etc/slackware-version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/alpine-release
    expect_string(__wrap_wfopen, path, "/etc/alpine-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // uname
    char *uname_path = NULL;
    os_strdup("/path/to/uname", uname_path);
    expect_string(__wrap_get_binary_path, command, "uname");
    will_return(__wrap_get_binary_path, uname_path);
    will_return(__wrap_get_binary_path, 0);

    expect_string(__wrap_popen, command, "/path/to/uname");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "OpenBSD\n");

    // uname - r
    expect_string(__wrap_popen, command, "/path/to/uname -r");
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
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_wfopen, path, "/etc/arch-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_wfopen, path, "/etc/gentoo-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_wfopen, path, "/etc/SuSE-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_wfopen, path, "/etc/lsb-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/debian_version
    expect_string(__wrap_wfopen, path, "/etc/debian_version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/slackware-version
    expect_string(__wrap_wfopen, path, "/etc/slackware-version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/alpine-release
    expect_string(__wrap_wfopen, path, "/etc/alpine-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // uname
    char *uname_path = NULL;
    os_strdup("/path/to/uname", uname_path);
    expect_string(__wrap_get_binary_path, command, "uname");
    will_return(__wrap_get_binary_path, uname_path);
    will_return(__wrap_get_binary_path, 0);

    expect_string(__wrap_popen, command, "/path/to/uname");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "ZscalerOS\n");

    // uname - r
    expect_string(__wrap_popen, command, "/path/to/uname -r");
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
    expect_string(__wrap_wfopen, path, "/etc/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /usr/lib/os-release
    expect_string(__wrap_wfopen, path, "/usr/lib/os-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/centos-release
    expect_string(__wrap_wfopen, path, "/etc/centos-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/fedora-release
    expect_string(__wrap_wfopen, path, "/etc/fedora-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/redhat-release
    expect_string(__wrap_wfopen, path, "/etc/redhat-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/arch-release
    expect_string(__wrap_wfopen, path, "/etc/arch-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/gentoo-release
    expect_string(__wrap_wfopen, path, "/etc/gentoo-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/SuSE-release
    expect_string(__wrap_wfopen, path, "/etc/SuSE-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/lsb-release
    expect_string(__wrap_wfopen, path, "/etc/lsb-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/debian_version
    expect_string(__wrap_wfopen, path, "/etc/debian_version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/slackware-version
    expect_string(__wrap_wfopen, path, "/etc/slackware-version");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // Fail to open /etc/alpine-release
    expect_string(__wrap_wfopen, path, "/etc/alpine-release");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    // uname
    char *uname_path = NULL;
    os_strdup("/path/to/uname", uname_path);
    expect_string(__wrap_get_binary_path, command, "uname");
    will_return(__wrap_get_binary_path, uname_path);
    will_return(__wrap_get_binary_path, 0);

    expect_string(__wrap_popen, command, "/path/to/uname");
    expect_string(__wrap_popen, type, "r");
    will_return(__wrap_popen, 1);

    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "AIX\n");

    // oslevel
    char *oslevel_path = NULL;
    os_strdup("/path/to/oslevel", oslevel_path);
    expect_string(__wrap_get_binary_path, command, "oslevel");
    will_return(__wrap_get_binary_path, oslevel_path);
    will_return(__wrap_get_binary_path, 0);

    expect_string(__wrap_popen, command, "/path/to/oslevel");
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
    assert_string_equal(OSX_ReleaseName(21), "Monterey");
    assert_string_equal(OSX_ReleaseName(22), "Ventura");
    assert_string_equal(OSX_ReleaseName(23), "Sonoma");
    assert_string_equal(OSX_ReleaseName(24), "Unknown");
}

#endif

void test_compare_wazuh_versions_equal_patch(void **state)
{
    (void) state;
    char *v1 = "v4.0.0";
    char *v2 = "v4.0.0";

    int ret = compare_wazuh_versions(v1, v2, true);

    assert_int_equal(ret, 0);
}

void test_compare_wazuh_versions_equal_minor(void **state)
{
    (void) state;
    char *v1 = "3.13";
    char *v2 = "3.13";

    int ret = compare_wazuh_versions(v1, v2, true);

    assert_int_equal(ret, 0);
}

void test_compare_wazuh_versions_equal_major(void **state)
{
    (void) state;
    char *v1 = "4";
    char *v2 = "v4";

    int ret = compare_wazuh_versions(v1, v2, true);

    assert_int_equal(ret, 0);
}

void test_compare_wazuh_versions_greater_patch(void **state)
{
    (void) state;
    char *v1 = "4.0.1";
    char *v2 = "v4.0.0";

    int ret = compare_wazuh_versions(v1, v2, true);

    assert_int_equal(ret, 1);
}

void test_compare_wazuh_versions_greater_patch_no_patch(void **state)
{
    (void) state;
    char *v1 = "4.0.1";
    char *v2 = "v4.0.0";

    int ret = compare_wazuh_versions(v1, v2, false);

    assert_int_equal(ret, 0);
}

void test_compare_wazuh_versions_greater_minor(void **state)
{
    (void) state;
    char *v1 = "2.15";
    char *v2 = "2";

    int ret = compare_wazuh_versions(v1, v2, true);

    assert_int_equal(ret, 1);
}

void test_compare_wazuh_versions_greater_major(void **state)
{
    (void) state;
    char *v1 = "v5";
    char *v2 = "4.9";

    int ret = compare_wazuh_versions(v1, v2, true);

    assert_int_equal(ret, 1);
}

void test_compare_wazuh_versions_lower_patch(void **state)
{
    (void) state;
    char *v1 = "v4.0.1";
    char *v2 = "v4.0.3";

    int ret = compare_wazuh_versions(v1, v2, true);

    assert_int_equal(ret, -1);
}

void test_compare_wazuh_versions_lower_minor(void **state)
{
    (void) state;
    char *v1 = "2.15.1";
    char *v2 = "2.18";

    int ret = compare_wazuh_versions(v1, v2, true);

    assert_int_equal(ret, -1);
}

void test_compare_wazuh_versions_lower_major(void **state)
{
    (void) state;
    char *v1 = "v5";
    char *v2 = "v6.1";

    int ret = compare_wazuh_versions(v1, v2, true);

    assert_int_equal(ret, -1);
}

void test_compare_wazuh_versions_null(void **state)
{
    (void) state;
    char *v1 = NULL;
    char *v2 = NULL;

    int ret = compare_wazuh_versions(v1, v2, true);

    assert_int_equal(ret, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
#ifdef __linux__
            cmocka_unit_test_teardown(test_get_unix_version_Ubuntu1904, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_centos, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_archlinux_distro_based, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_archlinux_no_version_id, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_archlinux, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_opensuse_tumbleweed_no_version_id, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_opensuse_tumbleweed, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_alpine, delete_os_info),
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
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_alpine, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_uname_darwin, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_uname_darwin_no_key, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_uname_sunos, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_uname_sunos_10_scenario_one, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_uname_sunos_10_scenario_two, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_uname_hp_ux, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_uname_bsd, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_zscaler, delete_os_info),
            cmocka_unit_test_teardown(test_get_unix_version_fail_os_release_uname_aix, delete_os_info),
            cmocka_unit_test(test_OSX_ReleaseName),
#endif
            // compare_wazuh_versions
            cmocka_unit_test(test_compare_wazuh_versions_equal_patch),
            cmocka_unit_test(test_compare_wazuh_versions_equal_minor),
            cmocka_unit_test(test_compare_wazuh_versions_equal_major),
            cmocka_unit_test(test_compare_wazuh_versions_greater_patch),
            cmocka_unit_test(test_compare_wazuh_versions_greater_patch_no_patch),
            cmocka_unit_test(test_compare_wazuh_versions_greater_minor),
            cmocka_unit_test(test_compare_wazuh_versions_greater_major),
            cmocka_unit_test(test_compare_wazuh_versions_lower_patch),
            cmocka_unit_test(test_compare_wazuh_versions_lower_minor),
            cmocka_unit_test(test_compare_wazuh_versions_lower_major),
            cmocka_unit_test(test_compare_wazuh_versions_null)
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
