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

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_validate.h"
#include "../../wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_tasks.h"
#include "../../headers/shared.h"

#ifdef TEST_SERVER

int wm_agent_upgrade_validate_non_custom_version(const char *agent_version, const wm_agent_info *agent_info, wm_upgrade_task *task, const wm_manager_configs* manager_configs);
int wm_agent_upgrade_validate_system(const char *platform, const char *os_major, const char *os_minor, const char *arch);
int wm_agent_upgrade_validate_wpk_version(const wm_agent_info *agent_info, wm_upgrade_task *task, char *wpk_version, const char *wpk_repository_config);

// Setup / teardown

static int setup_validate_wpk_version(void **state) {
    wm_agent_info *agent = NULL;
    wm_upgrade_task *task = NULL;
    agent = wm_agent_upgrade_init_agent_info();
    task = wm_agent_upgrade_init_upgrade_task();
    state[0] = (void *)agent;
    state[1] = (void *)task;
    return 0;
}

static int teardown_validate_wpk_version(void **state) {
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    wm_agent_upgrade_free_agent_info(agent);
    wm_agent_upgrade_free_upgrade_task(task);
    return 0;
}

#endif

static int setup_group(void **state) {
    wm_manager_configs *config = NULL;
    os_calloc(1, sizeof(wm_manager_configs), config);
    os_strdup(WM_UPGRADE_WPK_REPO_URL, config->wpk_repository);
    *state = config;
    return 0;
}

static int teardown_group(void **state) {
    wm_manager_configs *config = *state;
    os_free(config->wpk_repository);
    os_free(config);
    return 0;
}

// Wrappers

void __wrap__mterror(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mtdebug1(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

char* __wrap_wurl_http_get(const char * url) {
    check_expected(url);

    return mock_type(char *);
}

#ifdef TEST_SERVER

// Tests

void test_wm_agent_upgrade_validate_id_ok(void **state)
{
    (void) state;
    int agent_id = 5;

    int ret = wm_agent_upgrade_validate_id(agent_id);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_id_manager(void **state)
{
    (void) state;
    int agent_id = 0;

    int ret = wm_agent_upgrade_validate_id(agent_id);

    assert_int_equal(ret, WM_UPGRADE_INVALID_ACTION_FOR_MANAGER);
}

void test_wm_agent_upgrade_validate_status_ok(void **state)
{
    (void) state;
    int last_keep_alive = time(0);

    int ret = wm_agent_upgrade_validate_status(last_keep_alive);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_status_disconnected(void **state)
{
    (void) state;
    int last_keep_alive = time(0) - (DISCON_TIME * 2);

    int ret = wm_agent_upgrade_validate_status(last_keep_alive);

    assert_int_equal(ret, WM_UPGRADE_AGENT_IS_NOT_ACTIVE);
}

void test_wm_agent_upgrade_validate_system_windows_ok(void **state)
{
    (void) state;
    char *platform = "windows";
    char *os_major = "10";
    char *os_minor = NULL;
    char *arch = "x64";

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_system_rhel_ok(void **state)
{
    (void) state;
    char *platform = "rhel";
    char *os_major = "7";
    char *os_minor = NULL;
    char *arch = "x64";

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_system_ubuntu_ok(void **state)
{
    (void) state;
    char *platform = "ubuntu";
    char *os_major = "20";
    char *os_minor = "04";
    char *arch = "x64";

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_system_invalid_platform_darwin(void **state)
{
    (void) state;
    char *platform = "darwin";
    char *os_major = "10";
    char *os_minor = "15";
    char *arch = "x64";

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch);

    assert_int_equal(ret, WM_UPGRADE_SYSTEM_NOT_SUPPORTED);
}

void test_wm_agent_upgrade_validate_system_invalid_platform_solaris(void **state)
{
    (void) state;
    char *platform = "solaris";
    char *os_major = "11";
    char *os_minor = "4";
    char *arch = "x64";

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch);

    assert_int_equal(ret, WM_UPGRADE_SYSTEM_NOT_SUPPORTED);
}

void test_wm_agent_upgrade_validate_system_invalid_platform_suse(void **state)
{
    (void) state;
    char *platform = "sles";
    char *os_major = "11";
    char *os_minor = NULL;
    char *arch = "x64";

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch);

    assert_int_equal(ret, WM_UPGRADE_SYSTEM_NOT_SUPPORTED);
}

void test_wm_agent_upgrade_validate_system_invalid_platform_rhel(void **state)
{
    (void) state;
    char *platform = "rhel";
    char *os_major = "5";
    char *os_minor = "7";
    char *arch = "x64";

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch);

    assert_int_equal(ret, WM_UPGRADE_SYSTEM_NOT_SUPPORTED);
}

void test_wm_agent_upgrade_validate_system_invalid_platform_centos(void **state)
{
    (void) state;
    char *platform = "centos";
    char *os_major = "5";
    char *os_minor = NULL;
    char *arch = "x64";

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch);

    assert_int_equal(ret, WM_UPGRADE_SYSTEM_NOT_SUPPORTED);
}

void test_wm_agent_upgrade_validate_system_invalid_arch(void **state)
{
    (void) state;
    char *platform = "ubuntu";
    char *os_major = "18";
    char *os_minor = "04";
    char *arch = NULL;

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch);

    assert_int_equal(ret, WM_UPGRADE_GLOBAL_DB_FAILURE);
}

void test_wm_agent_upgrade_compare_versions_equal_patch(void **state)
{
    (void) state;
    char *v1 = "v4.0.0";
    char *v2 = "v4.0.0";

    int ret = wm_agent_upgrade_compare_versions(v1, v2);

    assert_int_equal(ret, 0);
}

void test_wm_agent_upgrade_compare_versions_equal_minor(void **state)
{
    (void) state;
    char *v1 = "3.13";
    char *v2 = "3.13";

    int ret = wm_agent_upgrade_compare_versions(v1, v2);

    assert_int_equal(ret, 0);
}

void test_wm_agent_upgrade_compare_versions_equal_major(void **state)
{
    (void) state;
    char *v1 = "4";
    char *v2 = "v4";

    int ret = wm_agent_upgrade_compare_versions(v1, v2);

    assert_int_equal(ret, 0);
}

void test_wm_agent_upgrade_compare_versions_greater_patch(void **state)
{
    (void) state;
    char *v1 = "4.0.1";
    char *v2 = "v4.0.0";

    int ret = wm_agent_upgrade_compare_versions(v1, v2);

    assert_int_equal(ret, 1);
}

void test_wm_agent_upgrade_compare_versions_greater_minor(void **state)
{
    (void) state;
    char *v1 = "2.15";
    char *v2 = "2";

    int ret = wm_agent_upgrade_compare_versions(v1, v2);

    assert_int_equal(ret, 1);
}

void test_wm_agent_upgrade_compare_versions_greater_major(void **state)
{
    (void) state;
    char *v1 = "v5";
    char *v2 = "4.9";

    int ret = wm_agent_upgrade_compare_versions(v1, v2);

    assert_int_equal(ret, 1);
}

void test_wm_agent_upgrade_compare_versions_lower_patch(void **state)
{
    (void) state;
    char *v1 = "v4.0.1";
    char *v2 = "v4.0.3";

    int ret = wm_agent_upgrade_compare_versions(v1, v2);

    assert_int_equal(ret, -1);
}

void test_wm_agent_upgrade_compare_versions_lower_minor(void **state)
{
    (void) state;
    char *v1 = "2.15.1";
    char *v2 = "2.18";

    int ret = wm_agent_upgrade_compare_versions(v1, v2);

    assert_int_equal(ret, -1);
}

void test_wm_agent_upgrade_compare_versions_lower_major(void **state)
{
    (void) state;
    char *v1 = "v5";
    char *v2 = "v6.1";

    int ret = wm_agent_upgrade_compare_versions(v1, v2);

    assert_int_equal(ret, -1);
}

void test_wm_agent_upgrade_compare_versions_null(void **state)
{
    (void) state;
    char *v1 = NULL;
    char *v2 = NULL;

    int ret = wm_agent_upgrade_compare_versions(v1, v2);

    assert_int_equal(ret, 0);
}

void test_wm_agent_upgrade_validate_wpk_version_windows_https_ok(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *version = "v4.0.0";
    char *repo = "packages.wazuh.com/wpk";
    char *versions = NULL;

    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    task->use_http = false;

    os_strdup("v3.13.1 4a313b1312c23a213f2e3209fe0909dd\nv4.0.0 231ef123a32d312b4123c21313ee6780\n", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/wpk/windows/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, version, repo);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/wpk/windows/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.0.0_windows.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_windows_http_ok(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *version = "v3.13.1";
    char *repo = "packages.wazuh.com/wpk/";
    char *versions = NULL;

    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    task->use_http = true;

    os_strdup("v3.13.1 4a313b1312c23a213f2e3209fe0909dd\nv4.0.0 231ef123a32d312b4123c21313ee6780\n", versions);

    expect_string(__wrap_wurl_http_get, url, "http://packages.wazuh.com/wpk/windows/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, version, repo);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "http://packages.wazuh.com/wpk/windows/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v3.13.1_windows.wpk");
    assert_string_equal(task->wpk_sha1, "4a313b1312c23a213f2e3209fe0909dd");
}

void test_wm_agent_upgrade_validate_wpk_version_windows_invalid_version(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *version = "v4.2.0";
    char *repo = "packages.wazuh.com/wpk/";
    char *versions = NULL;

    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    task->use_http = true;

    os_strdup("v3.13.1 4a313b1312c23a213f2e3209fe0909dd\nv4.0.0 231ef123a32d312b4123c21313ee6780\n", versions);

    expect_string(__wrap_wurl_http_get, url, "http://packages.wazuh.com/wpk/windows/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, version, repo);

    assert_int_equal(ret, WM_UPGRADE_WPK_VERSION_DOES_NOT_EXIST);
    assert_string_equal(task->wpk_repository, repo);
    assert_null(task->wpk_file);
    assert_null(task->wpk_sha1);
}

void test_wm_agent_upgrade_validate_wpk_version_windows_invalid_repo(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *version = "v4.2.0";
    char *repo = "error.wazuh.com/wpk/";
    char *versions = NULL;

    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    task->use_http = true;

    expect_string(__wrap_wurl_http_get, url, "http://error.wazuh.com/wpk/windows/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, version, repo);

    assert_int_equal(ret, WM_UPGRADE_URL_NOT_FOUND);
    assert_string_equal(task->wpk_repository, repo);
    assert_null(task->wpk_file);
    assert_null(task->wpk_sha1);
}

void test_wm_agent_upgrade_validate_wpk_version_linux_https_ok(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *version = "v4.0.0";
    char *repo = "packages.wazuh.com/wpk";
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("18", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("x64", agent->architecture);

    task->use_http = false;

    os_strdup("v3.13.1 4a313b1312c23a213f2e3209fe0909dd\nv4.0.0 231ef123a32d312b4123c21313ee6780\n", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/wpk/linux/x64/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, version, repo);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/wpk/linux/x64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.0.0_linux_x64.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_linux_http_ok(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *version = "v3.13.1";
    char *repo = "packages.wazuh.com/wpk/";
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("18", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("x64", agent->architecture);

    task->use_http = true;

    os_strdup("v3.13.1 4a313b1312c23a213f2e3209fe0909dd\nv4.0.0 231ef123a32d312b4123c21313ee6780\n", versions);

    expect_string(__wrap_wurl_http_get, url, "http://packages.wazuh.com/wpk/linux/x64/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, version, repo);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "http://packages.wazuh.com/wpk/linux/x64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v3.13.1_linux_x64.wpk");
    assert_string_equal(task->wpk_sha1, "4a313b1312c23a213f2e3209fe0909dd");
}

void test_wm_agent_upgrade_validate_wpk_version_linux_invalid_version(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *version = "v4.2.0";
    char *repo = "packages.wazuh.com/wpk/";
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("18", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("x64", agent->architecture);

    task->use_http = true;

    os_strdup("error\nerror\nerror\n", versions);

    expect_string(__wrap_wurl_http_get, url, "http://packages.wazuh.com/wpk/linux/x64/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, version, repo);

    assert_int_equal(ret, WM_UPGRADE_WPK_VERSION_DOES_NOT_EXIST);
    assert_string_equal(task->wpk_repository, repo);
    assert_null(task->wpk_file);
    assert_null(task->wpk_sha1);
}

void test_wm_agent_upgrade_validate_wpk_version_linux_invalid_repo(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *version = "v4.2.0";
    char *repo = "error.wazuh.com/wpk/";
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("18", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("x64", agent->architecture);

    task->use_http = true;

    expect_string(__wrap_wurl_http_get, url, "http://error.wazuh.com/wpk/linux/x64/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, version, repo);

    assert_int_equal(ret, WM_UPGRADE_URL_NOT_FOUND);
    assert_string_equal(task->wpk_repository, repo);
    assert_null(task->wpk_file);
    assert_null(task->wpk_sha1);
}

void test_wm_agent_upgrade_validate_wpk_version_ubuntu_old_version(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *version = "v3.3.0";
    char *repo = "packages.wazuh.com/wpk";
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("16", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("x64", agent->architecture);

    task->use_http = false;

    os_strdup("v3.3.0 ad87687f6876e876876bb86ad54e57aa\n", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/wpk/ubuntu/16.04/x64/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, version, repo);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/wpk/ubuntu/16.04/x64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v3.3.0_ubuntu_16.04_x64.wpk");
    assert_string_equal(task->wpk_sha1, "ad87687f6876e876876bb86ad54e57aa");
}

void test_wm_agent_upgrade_validate_wpk_version_rhel_old_version(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *version = "v3.3.0";
    char *repo = "packages.wazuh.com/wpk";
    char *versions = NULL;

    os_strdup("rhel", agent->platform);
    os_strdup("6", agent->major_version);
    os_strdup("x86", agent->architecture);

    task->use_http = false;

    os_strdup("v3.3.0 ad87687f6876e876876bb86ad54e57aa\n", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/wpk/rhel/6/x86/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, version, repo);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/wpk/rhel/6/x86/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v3.3.0_rhel_6_x86.wpk");
    assert_string_equal(task->wpk_sha1, "ad87687f6876e876876bb86ad54e57aa");
}

#endif

int main(void) {
    const struct CMUnitTest tests[] = {
#ifdef TEST_SERVER
        // wm_agent_upgrade_validate_id
        cmocka_unit_test(test_wm_agent_upgrade_validate_id_ok),
        cmocka_unit_test(test_wm_agent_upgrade_validate_id_manager),
        // wm_agent_upgrade_validate_status
        cmocka_unit_test(test_wm_agent_upgrade_validate_status_ok),
        cmocka_unit_test(test_wm_agent_upgrade_validate_status_disconnected),
        // wm_agent_upgrade_validate_system
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_windows_ok),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_rhel_ok),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_ubuntu_ok),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_invalid_platform_darwin),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_invalid_platform_solaris),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_invalid_platform_suse),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_invalid_platform_rhel),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_invalid_platform_centos),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_invalid_arch),
        // wm_agent_upgrade_compare_versions
        cmocka_unit_test(test_wm_agent_upgrade_compare_versions_equal_patch),
        cmocka_unit_test(test_wm_agent_upgrade_compare_versions_equal_minor),
        cmocka_unit_test(test_wm_agent_upgrade_compare_versions_equal_major),
        cmocka_unit_test(test_wm_agent_upgrade_compare_versions_greater_patch),
        cmocka_unit_test(test_wm_agent_upgrade_compare_versions_greater_minor),
        cmocka_unit_test(test_wm_agent_upgrade_compare_versions_greater_major),
        cmocka_unit_test(test_wm_agent_upgrade_compare_versions_lower_patch),
        cmocka_unit_test(test_wm_agent_upgrade_compare_versions_lower_minor),
        cmocka_unit_test(test_wm_agent_upgrade_compare_versions_lower_major),
        cmocka_unit_test(test_wm_agent_upgrade_compare_versions_null),
        // wm_agent_upgrade_validate_wpk_version
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_windows_https_ok, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_windows_http_ok, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_windows_invalid_version, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_windows_invalid_repo, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_https_ok, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_http_ok, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_invalid_version, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_invalid_repo, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_ubuntu_old_version, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_rhel_old_version, setup_validate_wpk_version, teardown_validate_wpk_version),
#endif
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
