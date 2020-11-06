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

#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdio_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/mq_op_wrappers.h"
#include "../../wrappers/wazuh/shared/url_wrappers.h"
#include "../../wrappers/wazuh/os_crypto/sha1_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_agent_upgrade_wrappers.h"

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_validate.h"
#include "../../wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_tasks.h"
#include "../../headers/shared.h"

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

static int setup_validate_wpk(void **state) {
    wm_upgrade_task *task = NULL;
    task = wm_agent_upgrade_init_upgrade_task();
    *state = (void *)task;
    return 0;
}

static int teardown_validate_wpk(void **state) {
    wm_upgrade_task *task = *state;
    wm_agent_upgrade_free_upgrade_task(task);
    return 0;
}

static int setup_validate_wpk_custom(void **state) {
    wm_upgrade_custom_task *task = NULL;
    task = wm_agent_upgrade_init_upgrade_custom_task();
    *state = (void *)task;
    return 0;
}

static int teardown_validate_wpk_custom(void **state) {
    wm_upgrade_custom_task *task = *state;
    wm_agent_upgrade_free_upgrade_custom_task(task);
    return 0;
}

static int teardown_validate_message(void **state) {
    cJSON *response = state[0];
    char *data = state[1];
    cJSON_Delete(response);
    os_free(data);
    return 0;
}

static int setup_group(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
    return 0;
}

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
    char *repo = "packages.wazuh.com/4.x/wpk";
    char *versions = NULL;

    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    task->use_http = false;

    os_strdup("v3.13.1 4a313b1312c23a213f2e3209fe0909dd\nv4.0.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/windows/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, version, repo);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/windows/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.0.0_windows.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_windows_http_ok(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *version = "v3.13.1";
    char *repo = "packages.wazuh.com/3.x/wpk/";
    char *versions = NULL;

    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    task->use_http = true;

    os_strdup("v3.13.1 4a313b1312c23a213f2e3209fe0909dd\nv4.0.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "http://packages.wazuh.com/3.x/wpk/windows/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, version, repo);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "http://packages.wazuh.com/3.x/wpk/windows/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v3.13.1_windows.wpk");
    assert_string_equal(task->wpk_sha1, "4a313b1312c23a213f2e3209fe0909dd");
}

void test_wm_agent_upgrade_validate_wpk_version_windows_invalid_version(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *version = "v4.2.0";
    char *repo = "packages.wazuh.com/4.x/wpk/";
    char *versions = NULL;

    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    task->use_http = true;

    os_strdup("v3.13.1 4a313b1312c23a213f2e3209fe0909dd\nv4.0.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "http://packages.wazuh.com/4.x/wpk/windows/versions");
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
    char *repo = "packages.wazuh.com/4.x/wpk";
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("18", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("x64", agent->architecture);

    task->use_http = false;

    os_strdup("v3.13.1 4a313b1312c23a213f2e3209fe0909dd\nv4.0.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/linux/x64/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, version, repo);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/linux/x64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.0.0_linux_x64.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_linux_http_ok(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *version = "v3.13.1";
    char *repo = "packages.wazuh.com/3.x/wpk/";
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("18", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("x64", agent->architecture);

    task->use_http = true;

    os_strdup("v3.13.1 4a313b1312c23a213f2e3209fe0909dd\nv4.0.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "http://packages.wazuh.com/3.x/wpk/linux/x64/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, version, repo);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "http://packages.wazuh.com/3.x/wpk/linux/x64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v3.13.1_linux_x64.wpk");
    assert_string_equal(task->wpk_sha1, "4a313b1312c23a213f2e3209fe0909dd");
}

void test_wm_agent_upgrade_validate_wpk_version_linux_invalid_version(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *version = "v4.2.0";
    char *repo = "packages.wazuh.com/4.x/wpk/";
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("18", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("x64", agent->architecture);

    task->use_http = true;

    os_strdup("error\nerror\nerror", versions);

    expect_string(__wrap_wurl_http_get, url, "http://packages.wazuh.com/4.x/wpk/linux/x64/versions");
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
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("16", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("x64", agent->architecture);

    task->use_http = false;

    os_strdup("v3.3.0 ad87687f6876e876876bb86ad54e57aa", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/wpk/ubuntu/16.04/x64/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, version, NULL);

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
    char *versions = NULL;

    os_strdup("rhel", agent->platform);
    os_strdup("6", agent->major_version);
    os_strdup("x86", agent->architecture);

    task->use_http = false;

    os_strdup("v3.3.0 ad87687f6876e876876bb86ad54e57aa", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/wpk/rhel/6/x86/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, version, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/wpk/rhel/6/x86/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v3.3.0_rhel_6_x86.wpk");
    assert_string_equal(task->wpk_sha1, "ad87687f6876e876876bb86ad54e57aa");
}

void test_wm_agent_upgrade_validate_non_custom_version_custom_version_ok(void **state)
{
    wm_manager_configs config;
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *agent_version = "v3.9.1";
    char *versions = NULL;

    config.wpk_repository = NULL;

    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    task->use_http = false;
    task->force_upgrade = false;
    os_strdup("v3.12.0", task->custom_version);

    os_strdup("v3.12.0 4a313b1312c23a213f2e3209fe0909dd\nv3.13.0 5387c3443b5c7234ba7232s2aadb4a7e", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/wpk/windows/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_non_custom_version(agent_version, agent, task, &config);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/wpk/windows/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v3.12.0_windows.wpk");
    assert_string_equal(task->wpk_sha1, "4a313b1312c23a213f2e3209fe0909dd");
}

void test_wm_agent_upgrade_validate_non_custom_version_custom_version_repo_ok(void **state)
{
    wm_manager_configs config;
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *agent_version = "v3.9.1";
    char *versions = NULL;

    config.wpk_repository = "localhost.com";

    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    task->use_http = false;
    task->force_upgrade = false;
    os_strdup("v3.12.0", task->custom_version);

    os_strdup("v3.12.0 4a313b1312c23a213f2e3209fe0909dd\nv3.13.0 5387c3443b5c7234ba7232s2aadb4a7e", versions);

    expect_string(__wrap_wurl_http_get, url, "https://localhost.com/windows/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_non_custom_version(agent_version, agent, task, &config);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://localhost.com/windows/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v3.12.0_windows.wpk");
    assert_string_equal(task->wpk_sha1, "4a313b1312c23a213f2e3209fe0909dd");
}

void test_wm_agent_upgrade_validate_non_custom_version_manager_version_ok(void **state)
{
    wm_manager_configs config;
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *agent_version = "v3.9.1";
    char *versions = NULL;

    config.wpk_repository = NULL;

    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    task->use_http = false;
    task->force_upgrade = false;

    os_strdup("v3.12.0 4a313b1312c23a213f2e3209fe0909dd\nv3.13.0 5387c3443b5c7234ba7232s2aadb4a7e", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/wpk/windows/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_non_custom_version(agent_version, agent, task, &config);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/wpk/windows/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v3.13.0_windows.wpk");
    assert_string_equal(task->wpk_sha1, "5387c3443b5c7234ba7232s2aadb4a7e");
}

void test_wm_agent_upgrade_validate_non_custom_version_manager_version_repo_ok(void **state)
{
    wm_manager_configs config;
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *agent_version = "v3.9.1";
    char *versions = NULL;

    config.wpk_repository = "localhost.com";

    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    task->use_http = false;
    task->force_upgrade = false;

    os_strdup("v3.12.0 4a313b1312c23a213f2e3209fe0909dd\nv3.13.0 5387c3443b5c7234ba7232s2aadb4a7e", versions);

    expect_string(__wrap_wurl_http_get, url, "https://localhost.com/windows/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_non_custom_version(agent_version, agent, task, &config);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://localhost.com/windows/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v3.13.0_windows.wpk");
    assert_string_equal(task->wpk_sha1, "5387c3443b5c7234ba7232s2aadb4a7e");
}

void test_wm_agent_upgrade_validate_non_custom_version_less_current(void **state)
{
    wm_manager_configs config;
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *agent_version = "v3.13.0";
    char *versions = NULL;

    config.wpk_repository = NULL;

    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    task->use_http = false;
    task->force_upgrade = false;
    os_strdup("v3.12.0", task->custom_version);

    os_strdup("v3.12.0 4a313b1312c23a213f2e3209fe0909dd\nv3.13.0 5387c3443b5c7234ba7232s2aadb4a7e", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/wpk/windows/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_non_custom_version(agent_version, agent, task, &config);

    assert_int_equal(ret, WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/wpk/windows/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v3.12.0_windows.wpk");
    assert_string_equal(task->wpk_sha1, "4a313b1312c23a213f2e3209fe0909dd");
}

void test_wm_agent_upgrade_validate_non_custom_version_less_current_force(void **state)
{
    wm_manager_configs config;
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *agent_version = "v3.13.0";
    char *versions = NULL;

    config.wpk_repository = NULL;

    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    task->use_http = false;
    task->force_upgrade = true;
    os_strdup("v3.12.0", task->custom_version);

    os_strdup("v3.12.0 4a313b1312c23a213f2e3209fe0909dd\nv3.13.0 5387c3443b5c7234ba7232s2aadb4a7e", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/wpk/windows/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_non_custom_version(agent_version, agent, task, &config);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/wpk/windows/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v3.12.0_windows.wpk");
    assert_string_equal(task->wpk_sha1, "4a313b1312c23a213f2e3209fe0909dd");
}

void test_wm_agent_upgrade_validate_non_custom_version_greater_master(void **state)
{
    wm_manager_configs config;
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *agent_version = "v3.9.1";
    char *versions = NULL;

    config.wpk_repository = NULL;

    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    task->use_http = false;
    task->force_upgrade = false;
    os_strdup("v4.0.0", task->custom_version);

    os_strdup("v3.12.0 4a313b1312c23a213f2e3209fe0909dd\nv3.13.0 5387c3443b5c7234ba7232s2aadb4a7e\nv4.0.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/windows/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_non_custom_version(agent_version, agent, task, &config);

    assert_int_equal(ret, WM_UPGRADE_NEW_VERSION_GREATER_MASTER);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/windows/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.0.0_windows.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_non_custom_version_greater_master_force(void **state)
{
    wm_manager_configs config;
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *agent_version = "v3.9.1";
    char *versions = NULL;

    config.wpk_repository = NULL;

    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    task->use_http = false;
    task->force_upgrade = true;
    os_strdup("v4.0.0", task->custom_version);

    os_strdup("v3.12.0 4a313b1312c23a213f2e3209fe0909dd\nv3.13.0 5387c3443b5c7234ba7232s2aadb4a7e\nv4.0.0 231ef123a32d312b4123c21313ee6780\n", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/windows/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_non_custom_version(agent_version, agent, task, &config);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/windows/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.0.0_windows.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_non_custom_version_system_error(void **state)
{
    wm_manager_configs config;
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *agent_version = "v3.9.1";

    os_strdup("darwin", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("15", agent->minor_version);
    os_strdup("x64", agent->architecture);

    int ret = wm_agent_upgrade_validate_non_custom_version(agent_version, agent, task, &config);

    assert_int_equal(ret, WM_UPGRADE_SYSTEM_NOT_SUPPORTED);
    assert_null(task->wpk_repository);
    assert_null(task->wpk_file);
    assert_null(task->wpk_sha1);
}

void test_wm_agent_upgrade_validate_version_upgrade_ok(void **state)
{
    wm_manager_configs config;
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    config.wpk_repository = NULL;

    os_strdup("v3.9.1", agent->wazuh_version);
    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    task->use_http = false;
    task->force_upgrade = false;
    os_strdup("v3.12.0", task->custom_version);

    os_strdup("v3.12.0 4a313b1312c23a213f2e3209fe0909dd\nv3.13.0 5387c3443b5c7234ba7232s2aadb4a7e\n", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/wpk/windows/versions");
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_version(agent, task, WM_UPGRADE_UPGRADE, &config);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/wpk/windows/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v3.12.0_windows.wpk");
    assert_string_equal(task->wpk_sha1, "4a313b1312c23a213f2e3209fe0909dd");
}

void test_wm_agent_upgrade_validate_version_upgrade_custom_ok(void **state)
{
    wm_manager_configs config;
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];

    os_strdup("v3.9.1", agent->wazuh_version);
    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    int ret = wm_agent_upgrade_validate_version(agent, task, WM_UPGRADE_UPGRADE_CUSTOM, &config);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_version_upgrade_non_minimal(void **state)
{
    wm_manager_configs config;
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];

    os_strdup("v2.1.1", agent->wazuh_version);
    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    int ret = wm_agent_upgrade_validate_version(agent, task, WM_UPGRADE_UPGRADE, &config);

    assert_int_equal(ret, WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED);
}

void test_wm_agent_upgrade_validate_version_upgrade_custom_non_minimal(void **state)
{
    wm_manager_configs config;
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];

    os_strdup("v2.1.1", agent->wazuh_version);
    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    int ret = wm_agent_upgrade_validate_version(agent, task, WM_UPGRADE_UPGRADE_CUSTOM, &config);

    assert_int_equal(ret, WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED);
}

void test_wm_agent_upgrade_validate_version_version_null(void **state)
{
    wm_manager_configs config;
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];

    agent->wazuh_version = NULL;
    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);

    int ret = wm_agent_upgrade_validate_version(agent, task, WM_UPGRADE_UPGRADE_CUSTOM, &config);

    assert_int_equal(ret, WM_UPGRADE_GLOBAL_DB_FAILURE);
}

void test_wm_agent_upgrade_validate_wpk_exist(void **state)
{
    wm_upgrade_task *task = *state;
    char *sha1 = "74691287f21a312ab2a12e31a23f21a33d242d52";

    os_strdup("https://packages.wazuh.com/4.x/wpk/windows/", task->wpk_repository);
    os_strdup("wazuh_agent_v4.0.0_windows.wpk", task->wpk_file);
    os_strdup(sha1, task->wpk_sha1);

    expect_string(__wrap_fopen, path, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    expect_string(__wrap_OS_SHA1_File, fname, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_value(__wrap_OS_SHA1_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA1_File, sha1);
    will_return(__wrap_OS_SHA1_File, 0);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    int ret = wm_agent_upgrade_validate_wpk(task);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_wpk_exist_diff_sha1(void **state)
{
    wm_upgrade_task *task = *state;
    char *sha1 = "74691287f21a312ab2a12e31a23f21a33d242d52";

    os_strdup("https://packages.wazuh.com/4.x/wpk/windows/", task->wpk_repository);
    os_strdup("wazuh_agent_v4.0.0_windows.wpk", task->wpk_file);
    os_strdup(sha1, task->wpk_sha1);

    expect_string(__wrap_fopen, path, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    expect_string(__wrap_OS_SHA1_File, fname, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_value(__wrap_OS_SHA1_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA1_File, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File, 0);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8161): Downloading WPK file from: 'https://packages.wazuh.com/4.x/wpk/windows/wazuh_agent_v4.0.0_windows.wpk'");

    expect_string(__wrap_wurl_request, url, "https://packages.wazuh.com/4.x/wpk/windows/wazuh_agent_v4.0.0_windows.wpk");
    expect_string(__wrap_wurl_request, dest, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_value(__wrap_wurl_request, timeout, WM_UPGRADE_WPK_DOWNLOAD_TIMEOUT);
    will_return(__wrap_wurl_request, 0);

    expect_string(__wrap_OS_SHA1_File, fname, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_value(__wrap_OS_SHA1_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA1_File, sha1);
    will_return(__wrap_OS_SHA1_File, 0);

    int ret = wm_agent_upgrade_validate_wpk(task);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_wpk_download_retry(void **state)
{
    wm_upgrade_task *task = *state;
    char *sha1 = "74691287f21a312ab2a12e31a23f21a33d242d52";

    os_strdup("https://packages.wazuh.com/4.x/wpk/windows/", task->wpk_repository);
    os_strdup("wazuh_agent_v4.0.0_windows.wpk", task->wpk_file);
    os_strdup(sha1, task->wpk_sha1);

    expect_string(__wrap_fopen, path, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 0);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8161): Downloading WPK file from: 'https://packages.wazuh.com/4.x/wpk/windows/wazuh_agent_v4.0.0_windows.wpk'");

    expect_string(__wrap_wurl_request, url, "https://packages.wazuh.com/4.x/wpk/windows/wazuh_agent_v4.0.0_windows.wpk");
    expect_string(__wrap_wurl_request, dest, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_value(__wrap_wurl_request, timeout, WM_UPGRADE_WPK_DOWNLOAD_TIMEOUT);
    will_return(__wrap_wurl_request, 1);

    expect_value(__wrap_sleep, seconds, 1);

    expect_string(__wrap_wurl_request, url, "https://packages.wazuh.com/4.x/wpk/windows/wazuh_agent_v4.0.0_windows.wpk");
    expect_string(__wrap_wurl_request, dest, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_value(__wrap_wurl_request, timeout, WM_UPGRADE_WPK_DOWNLOAD_TIMEOUT);
    will_return(__wrap_wurl_request, 0);

    expect_string(__wrap_OS_SHA1_File, fname, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_value(__wrap_OS_SHA1_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA1_File, sha1);
    will_return(__wrap_OS_SHA1_File, 0);

    int ret = wm_agent_upgrade_validate_wpk(task);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_wpk_download_diff_sha1(void **state)
{
    wm_upgrade_task *task = *state;
    char *sha1 = "74691287f21a312ab2a12e31a23f21a33d242d52";

    os_strdup("https://packages.wazuh.com/4.x/wpk/windows/", task->wpk_repository);
    os_strdup("wazuh_agent_v4.0.0_windows.wpk", task->wpk_file);
    os_strdup(sha1, task->wpk_sha1);

    expect_string(__wrap_fopen, path, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 0);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8161): Downloading WPK file from: 'https://packages.wazuh.com/4.x/wpk/windows/wazuh_agent_v4.0.0_windows.wpk'");

    expect_string(__wrap_wurl_request, url, "https://packages.wazuh.com/4.x/wpk/windows/wazuh_agent_v4.0.0_windows.wpk");
    expect_string(__wrap_wurl_request, dest, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_value(__wrap_wurl_request, timeout, WM_UPGRADE_WPK_DOWNLOAD_TIMEOUT);
    will_return(__wrap_wurl_request, 0);

    expect_string(__wrap_OS_SHA1_File, fname, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_value(__wrap_OS_SHA1_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA1_File, "32bb98743e298dee0a654a654765c765d765ae80");
    will_return(__wrap_OS_SHA1_File, 0);

    int ret = wm_agent_upgrade_validate_wpk(task);

    assert_int_equal(ret, WM_UPGRADE_WPK_SHA1_DOES_NOT_MATCH);
}

void test_wm_agent_upgrade_validate_wpk_download_retry_max(void **state)
{
    wm_upgrade_task *task = *state;
    char *sha1 = "74691287f21a312ab2a12e31a23f21a33d242d52";

    os_strdup("https://packages.wazuh.com/4.x/wpk/windows/", task->wpk_repository);
    os_strdup("wazuh_agent_v4.0.0_windows.wpk", task->wpk_file);
    os_strdup(sha1, task->wpk_sha1);

    expect_string(__wrap_fopen, path, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 0);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8161): Downloading WPK file from: 'https://packages.wazuh.com/4.x/wpk/windows/wazuh_agent_v4.0.0_windows.wpk'");

    expect_string(__wrap_wurl_request, url, "https://packages.wazuh.com/4.x/wpk/windows/wazuh_agent_v4.0.0_windows.wpk");
    expect_string(__wrap_wurl_request, dest, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_value(__wrap_wurl_request, timeout, WM_UPGRADE_WPK_DOWNLOAD_TIMEOUT);
    will_return(__wrap_wurl_request, 1);

    expect_value(__wrap_sleep, seconds, 1);

    expect_string(__wrap_wurl_request, url, "https://packages.wazuh.com/4.x/wpk/windows/wazuh_agent_v4.0.0_windows.wpk");
    expect_string(__wrap_wurl_request, dest, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_value(__wrap_wurl_request, timeout, WM_UPGRADE_WPK_DOWNLOAD_TIMEOUT);
    will_return(__wrap_wurl_request, 1);

    expect_value(__wrap_sleep, seconds, 2);

    expect_string(__wrap_wurl_request, url, "https://packages.wazuh.com/4.x/wpk/windows/wazuh_agent_v4.0.0_windows.wpk");
    expect_string(__wrap_wurl_request, dest, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_value(__wrap_wurl_request, timeout, WM_UPGRADE_WPK_DOWNLOAD_TIMEOUT);
    will_return(__wrap_wurl_request, 1);

    expect_value(__wrap_sleep, seconds, 3);

    expect_string(__wrap_wurl_request, url, "https://packages.wazuh.com/4.x/wpk/windows/wazuh_agent_v4.0.0_windows.wpk");
    expect_string(__wrap_wurl_request, dest, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_value(__wrap_wurl_request, timeout, WM_UPGRADE_WPK_DOWNLOAD_TIMEOUT);
    will_return(__wrap_wurl_request, 1);

    expect_value(__wrap_sleep, seconds, 4);

    expect_string(__wrap_wurl_request, url, "https://packages.wazuh.com/4.x/wpk/windows/wazuh_agent_v4.0.0_windows.wpk");
    expect_string(__wrap_wurl_request, dest, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_value(__wrap_wurl_request, timeout, WM_UPGRADE_WPK_DOWNLOAD_TIMEOUT);
    will_return(__wrap_wurl_request, 1);

    int ret = wm_agent_upgrade_validate_wpk(task);

    assert_int_equal(ret, WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST);
}

void test_wm_agent_upgrade_validate_wpk_task_error(void **state)
{
    wm_upgrade_task *task = *state;

    int ret = wm_agent_upgrade_validate_wpk(task);

    assert_int_equal(ret, WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST);
}

void test_wm_agent_upgrade_validate_wpk_custom_exist(void **state)
{
    wm_upgrade_custom_task *task = *state;

    os_strdup("/tmp/test.wpk", task->custom_file_path);

    expect_string(__wrap_fopen, path, "/tmp/test.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    int ret = wm_agent_upgrade_validate_wpk_custom(task);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_wpk_custom_not_exist(void **state)
{
    wm_upgrade_custom_task *task = *state;

    os_strdup("/tmp/test.wpk", task->custom_file_path);

    expect_string(__wrap_fopen, path, "/tmp/test.wpk");
    expect_string(__wrap_fopen, mode, "rb");
    will_return(__wrap_fopen, 0);

    int ret = wm_agent_upgrade_validate_wpk_custom(task);

    assert_int_equal(ret, WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST);
}

void test_wm_agent_upgrade_validate_wpk_custom_task_error(void **state)
{
    wm_upgrade_custom_task *task = *state;

    int ret = wm_agent_upgrade_validate_wpk_custom(task);

    assert_int_equal(ret, WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST);
}

void test_wm_agent_upgrade_validate_task_status_message_ok(void **state)
{
    cJSON *response = cJSON_CreateObject();
    char *status = NULL;
    int agent_id = 0;

    cJSON_AddNumberToObject(response, "error", 0);
    cJSON_AddStringToObject(response, "message", "Success");
    cJSON_AddNumberToObject(response, "agent", 5);
    cJSON_AddStringToObject(response, "status", "Done");

    int ret = wm_agent_upgrade_validate_task_status_message(response, &status, &agent_id);

    state[0] = (void *)response;
    state[1] = (void *)status;

    assert_int_equal(ret, true);
    assert_string_equal(status, "Done");
    assert_int_equal(agent_id, 5);
}

void test_wm_agent_upgrade_validate_task_status_message_not_agent_status_ok(void **state)
{
    cJSON *response = cJSON_CreateObject();

    cJSON_AddNumberToObject(response, "error", 0);
    cJSON_AddStringToObject(response, "message", "Success");
    cJSON_AddNumberToObject(response, "agent", 5);
    cJSON_AddStringToObject(response, "status", "Done");

    int ret = wm_agent_upgrade_validate_task_status_message(response, NULL, NULL);

    state[0] = (void *)response;

    assert_int_equal(ret, true);
}

void test_wm_agent_upgrade_validate_task_status_message_error_code(void **state)
{
    cJSON *response = cJSON_CreateObject();

    cJSON_AddNumberToObject(response, "error", 1);
    cJSON_AddStringToObject(response, "message", "Error");
    cJSON_AddNumberToObject(response, "agent", 5);
    cJSON_AddStringToObject(response, "status", "Done");

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8119): There has been an error updating task state. Error code: '1', message: 'Error'");

    int ret = wm_agent_upgrade_validate_task_status_message(response, NULL, NULL);

    state[0] = (void *)response;

    assert_int_equal(ret, false);
}

void test_wm_agent_upgrade_validate_task_status_message_invalid_json(void **state)
{
    cJSON *response = cJSON_CreateObject();

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8107): Required parameters in message are missing.");

    int ret = wm_agent_upgrade_validate_task_status_message(response, NULL, NULL);

    state[0] = (void *)response;

    assert_int_equal(ret, false);
}

void test_wm_agent_upgrade_validate_task_status_message_null_json(void **state)
{
    int ret = wm_agent_upgrade_validate_task_status_message(NULL, NULL, NULL);

    assert_int_equal(ret, false);
}

void test_wm_agent_upgrade_validate_task_ids_message_ok(void **state)
{
    cJSON *response = cJSON_CreateObject();
    int agent_id = 0;
    int task_id = 0;
    char *data = NULL;

    cJSON_AddNumberToObject(response, "error", 0);
    cJSON_AddStringToObject(response, "message", "Success");
    cJSON_AddNumberToObject(response, "agent", 7);
    cJSON_AddNumberToObject(response, "task_id", 15);

    int ret = wm_agent_upgrade_validate_task_ids_message(response, &agent_id, &task_id, &data);

    state[0] = (void *)response;
    state[1] = (void *)data;

    assert_int_equal(ret, true);
    assert_int_equal(agent_id, 7);
    assert_int_equal(task_id, 15);
    assert_string_equal(data, "Success");
}

void test_wm_agent_upgrade_validate_task_ids_message_not_agent_error(void **state)
{
    cJSON *response = cJSON_CreateObject();
    int task_id = 0;
    char *data = NULL;

    cJSON_AddNumberToObject(response, "error", 0);
    cJSON_AddStringToObject(response, "message", "Success");
    cJSON_AddNumberToObject(response, "agent", 7);
    cJSON_AddNumberToObject(response, "task_id", 15);

    int ret = wm_agent_upgrade_validate_task_ids_message(response, NULL, &task_id, &data);

    state[0] = (void *)response;

    assert_int_equal(ret, false);
    assert_int_equal(task_id, 0);
    assert_null(data);
}

void test_wm_agent_upgrade_validate_task_ids_message_not_data_error(void **state)
{
    cJSON *response = cJSON_CreateObject();
    int agent_id = 0;
    int task_id = 0;

    cJSON_AddNumberToObject(response, "error", 0);
    cJSON_AddStringToObject(response, "message", "Success");
    cJSON_AddNumberToObject(response, "agent", 7);
    cJSON_AddNumberToObject(response, "task_id", 15);

    int ret = wm_agent_upgrade_validate_task_ids_message(response, &agent_id, &task_id, NULL);

    state[0] = (void *)response;

    assert_int_equal(ret, false);
    assert_int_equal(agent_id, 7);
    assert_int_equal(task_id, 0);
}

void test_wm_agent_upgrade_validate_task_ids_message_not_task_ok(void **state)
{
    cJSON *response = cJSON_CreateObject();
    int agent_id = 0;
    char *data = NULL;

    cJSON_AddNumberToObject(response, "error", 0);
    cJSON_AddStringToObject(response, "message", "Success");
    cJSON_AddNumberToObject(response, "agent", 7);
    cJSON_AddNumberToObject(response, "task_id", 15);

    int ret = wm_agent_upgrade_validate_task_ids_message(response, &agent_id, NULL, &data);

    state[0] = (void *)response;
    state[1] = (void *)data;

    assert_int_equal(ret, true);
    assert_int_equal(agent_id, 7);
    assert_string_equal(data, "Success");
}

void test_wm_agent_upgrade_validate_task_ids_message_invalid_json(void **state)
{
    cJSON *response = cJSON_CreateObject();
    int agent_id = 0;
    int task_id = 0;
    char *data = NULL;

    int ret = wm_agent_upgrade_validate_task_ids_message(response, &agent_id, &task_id, &data);

    state[0] = (void *)response;

    assert_int_equal(ret, false);
    assert_int_equal(agent_id, 0);
    assert_int_equal(task_id, 0);
    assert_null(data);
}

void test_wm_agent_upgrade_validate_task_ids_message_null_json(void **state)
{
    int ret = wm_agent_upgrade_validate_task_ids_message(NULL, NULL, NULL, NULL);

    assert_int_equal(ret, false);
}

int main(void) {
    const struct CMUnitTest tests[] = {
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
        // wm_agent_upgrade_validate_non_custom_version
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_non_custom_version_custom_version_ok, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_non_custom_version_custom_version_repo_ok, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_non_custom_version_manager_version_ok, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_non_custom_version_manager_version_repo_ok, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_non_custom_version_less_current, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_non_custom_version_less_current_force, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_non_custom_version_greater_master, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_non_custom_version_greater_master_force, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_non_custom_version_system_error, setup_validate_wpk_version, teardown_validate_wpk_version),
        // wm_agent_upgrade_validate_version
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_version_upgrade_ok, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_version_upgrade_custom_ok, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_version_upgrade_non_minimal, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_version_upgrade_custom_non_minimal, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_version_version_null, setup_validate_wpk_version, teardown_validate_wpk_version),
        // wm_agent_upgrade_validate_wpk
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_exist, setup_validate_wpk, teardown_validate_wpk),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_exist_diff_sha1, setup_validate_wpk, teardown_validate_wpk),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_download_retry, setup_validate_wpk, teardown_validate_wpk),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_download_diff_sha1, setup_validate_wpk, teardown_validate_wpk),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_download_retry_max, setup_validate_wpk, teardown_validate_wpk),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_task_error, setup_validate_wpk, teardown_validate_wpk),
        // wm_agent_upgrade_validate_wpk_custom
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_custom_exist, setup_validate_wpk_custom, teardown_validate_wpk_custom),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_custom_not_exist, setup_validate_wpk_custom, teardown_validate_wpk_custom),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_custom_task_error, setup_validate_wpk_custom, teardown_validate_wpk_custom),
        // wm_agent_upgrade_validate_task_status_message
        cmocka_unit_test_teardown(test_wm_agent_upgrade_validate_task_status_message_ok, teardown_validate_message),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_validate_task_status_message_not_agent_status_ok, teardown_validate_message),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_validate_task_status_message_error_code, teardown_validate_message),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_validate_task_status_message_invalid_json, teardown_validate_message),
        cmocka_unit_test(test_wm_agent_upgrade_validate_task_status_message_null_json),
        // wm_agent_upgrade_validate_task_ids_message
        cmocka_unit_test_teardown(test_wm_agent_upgrade_validate_task_ids_message_ok, teardown_validate_message),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_validate_task_ids_message_not_agent_error, teardown_validate_message),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_validate_task_ids_message_not_data_error, teardown_validate_message),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_validate_task_ids_message_not_task_ok, teardown_validate_message),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_validate_task_ids_message_invalid_json, teardown_validate_message),
        cmocka_unit_test(test_wm_agent_upgrade_validate_task_ids_message_null_json)
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
