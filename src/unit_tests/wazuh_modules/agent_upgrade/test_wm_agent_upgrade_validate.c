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
    const char *connection_status = AGENT_CS_ACTIVE;

    int ret = wm_agent_upgrade_validate_status(connection_status);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_status_null(void **state)
{
    (void) state;
    const char *connection_status = NULL;

    int ret = wm_agent_upgrade_validate_status(connection_status);

    assert_int_equal(ret, WM_UPGRADE_AGENT_IS_NOT_ACTIVE);
}

void test_wm_agent_upgrade_validate_status_disconnected(void **state)
{
    (void) state;
    const char *connection_status = "disconnected";

    int ret = wm_agent_upgrade_validate_status(connection_status);

    assert_int_equal(ret, WM_UPGRADE_AGENT_IS_NOT_ACTIVE);
}

void test_wm_agent_upgrade_validate_system_windows_ok(void **state)
{
    (void) state;
    char *platform = "windows";
    char *os_major = "10";
    char *os_minor = NULL;
    char *arch = "x64";
    char *package_type = NULL;

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch, &package_type);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_non_null(package_type);
    assert_string_equal(package_type, "msi");
    os_free(package_type);
}

void test_wm_agent_upgrade_validate_system_rhel_ok(void **state)
{
    (void) state;
    char *platform = "rhel";
    char *os_major = "7";
    char *os_minor = NULL;
    char *arch = "x64";
    char *package_type = NULL;

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch, &package_type);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_non_null(package_type);
    assert_string_equal(package_type, "rpm");
    os_free(package_type);
}

void test_wm_agent_upgrade_validate_system_ubuntu_ok(void **state)
{
    (void) state;
    char *platform = "ubuntu";
    char *os_major = "20";
    char *os_minor = "04";
    char *arch = "x64";
    char *package_type = NULL;

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch, &package_type);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_non_null(package_type);
    assert_string_equal(package_type, "deb");
    os_free(package_type);
}

void test_wm_agent_upgrade_validate_system_rocky_ok(void **state)
{
    (void) state;
    char *platform = "rocky";
    char *os_major = "9";
    char *os_minor = "3";
    char *arch = "x64";
    char *package_type = NULL;

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch, &package_type);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_non_null(package_type);
    assert_string_equal(package_type, "rpm");
    os_free(package_type);
}

void test_wm_agent_upgrade_validate_system_darwin_x64_ok(void **state)
{
    (void) state;
    char *platform = "darwin";
    char *os_major = "10";
    char *os_minor = "15";
    char *arch = "x64";
    char *package_type = NULL;

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch, &package_type);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_non_null(package_type);
    assert_string_equal(package_type, "pkg");
    os_free(package_type);
}

void test_wm_agent_upgrade_validate_system_darwin_arm_ok(void **state)
{
    (void) state;
    char *platform = "darwin";
    char *os_major = "10";
    char *os_minor = "15";
    char *arch = "arm64";
    char *package_type = NULL;

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch, &package_type);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_non_null(package_type);
    assert_string_equal(package_type, "pkg");
    os_free(package_type);
}

void test_wm_agent_upgrade_validate_system_invalid_platform_solaris(void **state)
{
    (void) state;
    char *platform = "sunos";
    char *os_major = "11";
    char *os_minor = "4";
    char *arch = "x64";
    char *package_type = NULL;

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch, &package_type);

    assert_int_equal(ret, WM_UPGRADE_SYSTEM_NOT_SUPPORTED);
    assert_null(package_type);
}

void test_wm_agent_upgrade_validate_system_invalid_platform_suse(void **state)
{
    (void) state;
    char *platform = "sles";
    char *os_major = "11";
    char *os_minor = NULL;
    char *arch = "x64";
    char *package_type = NULL;

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch, &package_type);

    assert_int_equal(ret, WM_UPGRADE_SYSTEM_NOT_SUPPORTED);
    assert_null(package_type);
}

void test_wm_agent_upgrade_validate_system_invalid_platform_rhel(void **state)
{
    (void) state;
    char *platform = "rhel";
    char *os_major = "5";
    char *os_minor = "7";
    char *arch = "x64";
    char *package_type = NULL;

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch, &package_type);

    assert_int_equal(ret, WM_UPGRADE_SYSTEM_NOT_SUPPORTED);
    assert_null(package_type);
}

void test_wm_agent_upgrade_validate_system_invalid_platform_centos(void **state)
{
    (void) state;
    char *platform = "centos";
    char *os_major = "5";
    char *os_minor = NULL;
    char *arch = "x64";
    char *package_type = NULL;

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch, &package_type);

    assert_int_equal(ret, WM_UPGRADE_SYSTEM_NOT_SUPPORTED);
    assert_null(package_type);
}

void test_wm_agent_upgrade_validate_system_invalid_arch(void **state)
{
    (void) state;
    char *platform = "ubuntu";
    char *os_major = "18";
    char *os_minor = "04";
    char *arch = NULL;
    char *package_type = NULL;

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch, &package_type);

    assert_int_equal(ret, WM_UPGRADE_GLOBAL_DB_FAILURE);
    assert_null(package_type);
}

void test_wm_agent_upgrade_validate_system_rolling_opensuse(void **state)
{
    (void) state;
    char *platform = "opensuse-tumbleweed";
    char *os_major = NULL;
    char *os_minor = NULL;
    char *arch = "x64";
    char *package_type = NULL;

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch, &package_type);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_non_null(package_type);
    assert_string_equal(package_type, "rpm");
    os_free(package_type);
}

void test_wm_agent_upgrade_validate_system_rolling_archlinux(void **state)
{
    (void) state;
    char *platform = "arch";
    char *os_major = NULL;
    char *os_minor = NULL;
    char *arch = "x64";
    char *package_type = NULL;

    int ret = wm_agent_upgrade_validate_system(platform, os_major, os_minor, arch, &package_type);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_null(package_type); // Not recognized
}

void test_wm_agent_upgrade_validate_wpk_version_windows_https_ok(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);
    os_strdup("msi", agent->package_type);

    task->use_http = false;
    os_strdup("v4.0.0", task->wpk_version);

    os_strdup("v3.13.1 4a313b1312c23a213f2e3209fe0909dd\nv4.0.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/windows/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/windows/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.0.0_windows.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_windows_http_ok(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);
    os_strdup("msi", agent->package_type);

    task->use_http = true;
    os_strdup("v3.13.1", task->wpk_version);

    os_strdup("v3.13.1 4a313b1312c23a213f2e3209fe0909dd\nv4.0.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "http://packages.wazuh.com/wpk/windows/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "http://packages.wazuh.com/wpk/windows/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v3.13.1_windows.wpk");
    assert_string_equal(task->wpk_sha1, "4a313b1312c23a213f2e3209fe0909dd");
}


void test_wm_agent_upgrade_validate_wpk_version_windows_invalid_version(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *repo = "packages.wazuh.com/4.x/wpk";
    char *versions = NULL;

    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);
    os_strdup("msi", agent->package_type);

    task->use_http = true;
    os_strdup("v4.2.0", task->wpk_version);

    os_strdup("v3.13.1 4a313b1312c23a213f2e3209fe0909dd\nv4.0.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "http://packages.wazuh.com/4.x/wpk/windows/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, repo);

    assert_int_equal(ret, WM_UPGRADE_WPK_VERSION_DOES_NOT_EXIST);
    assert_string_equal(task->wpk_repository, repo);
    assert_null(task->wpk_file);
    assert_null(task->wpk_sha1);
}

void test_wm_agent_upgrade_validate_wpk_version_windows_invalid_repo(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *repo = "error.wazuh.com/wpk/";
    char *versions = NULL;

    os_strdup("windows", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("x64", agent->architecture);
    os_strdup("msi", agent->package_type);

    task->use_http = true;
    os_strdup("v4.2.0", task->wpk_version);

    expect_string(__wrap_wurl_http_get, url, "http://error.wazuh.com/wpk/windows/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, repo);

    assert_int_equal(ret, WM_UPGRADE_URL_NOT_FOUND);
    assert_string_equal(task->wpk_repository, repo);
    assert_null(task->wpk_file);
    assert_null(task->wpk_sha1);
}

void test_wm_agent_upgrade_validate_wpk_version_linux_https_ok(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("18", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("x64", agent->architecture);
    os_strdup("deb", agent->package_type);

    task->use_http = false;
    os_strdup("v4.0.0", task->wpk_version);

    os_strdup("v3.13.1 4a313b1312c23a213f2e3209fe0909dd\nv4.0.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/linux/x64/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/linux/x64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.0.0_linux_x64.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_linux_http_ok(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("18", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("x64", agent->architecture);
    os_strdup("deb", agent->package_type);

    task->use_http = true;
    os_strdup("v3.13.1", task->wpk_version);

    os_strdup("v3.13.1 4a313b1312c23a213f2e3209fe0909dd\nv4.0.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "http://packages.wazuh.com/wpk/linux/x64/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "http://packages.wazuh.com/wpk/linux/x64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v3.13.1_linux_x64.wpk");
    assert_string_equal(task->wpk_sha1, "4a313b1312c23a213f2e3209fe0909dd");
}

void test_wm_agent_upgrade_validate_wpk_version_linux_invalid_str_version(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("18", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("x64", agent->architecture);
    os_strdup("deb", agent->package_type);

    task->use_http = true;
    os_strdup("v.4.1", task->wpk_version);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_WPK_VERSION_DOES_NOT_EXIST);
}

void test_wm_agent_upgrade_validate_wpk_version_linux_invalid_version(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *repo = "packages.wazuh.com/4.x/wpk";
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("18", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("x64", agent->architecture);
    os_strdup("deb", agent->package_type);

    task->use_http = true;
    os_strdup("v4.2.0", task->wpk_version);

    os_strdup("error\nerror\nerror", versions);

    expect_string(__wrap_wurl_http_get, url, "http://packages.wazuh.com/4.x/wpk/linux/x64/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, repo);

    assert_int_equal(ret, WM_UPGRADE_WPK_VERSION_DOES_NOT_EXIST);
    assert_string_equal(task->wpk_repository, repo);
    assert_null(task->wpk_file);
    assert_null(task->wpk_sha1);
}

void test_wm_agent_upgrade_validate_wpk_version_linux_invalid_repo(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *repo = "error.wazuh.com/wpk/";
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("18", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("x64", agent->architecture);
    os_strdup("deb", agent->package_type);

    task->use_http = true;
    os_strdup("v4.2.0", task->wpk_version);

    expect_string(__wrap_wurl_http_get, url, "http://error.wazuh.com/wpk/linux/x64/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, repo);

    assert_int_equal(ret, WM_UPGRADE_URL_NOT_FOUND);
    assert_string_equal(task->wpk_repository, repo);
    assert_null(task->wpk_file);
    assert_null(task->wpk_sha1);
}

void test_wm_agent_upgrade_validate_wpk_version_ubuntu_old_version(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("16", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("x64", agent->architecture);
    os_strdup("deb", agent->package_type);

    task->use_http = false;
    os_strdup("v3.3.0", task->wpk_version);

    os_strdup("v3.3.0 ad87687f6876e876876bb86ad54e57aa", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/wpk/ubuntu/16.04/x64/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/wpk/ubuntu/16.04/x64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v3.3.0_ubuntu_16.04_x64.wpk");
    assert_string_equal(task->wpk_sha1, "ad87687f6876e876876bb86ad54e57aa");
}

void test_wm_agent_upgrade_validate_wpk_version_rhel_old_version(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("rhel", agent->platform);
    os_strdup("6", agent->major_version);
    os_strdup("x86", agent->architecture);
    os_strdup("rpm", agent->package_type);

    task->use_http = false;
    os_strdup("v3.3.0", task->wpk_version);

    os_strdup("v3.3.0 ad87687f6876e876876bb86ad54e57aa", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/wpk/rhel/6/x86/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/wpk/rhel/6/x86/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v3.3.0_rhel_6_x86.wpk");
    assert_string_equal(task->wpk_sha1, "ad87687f6876e876876bb86ad54e57aa");
}

void test_wm_agent_upgrade_validate_wpk_version_no_version(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *repo = "packages.wazuh.com/4.x/wpk";

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, repo);

    assert_int_equal(ret, WM_UPGRADE_WPK_VERSION_DOES_NOT_EXIST);
    assert_null(task->wpk_repository);
    assert_null(task->wpk_file);
    assert_null(task->wpk_sha1);
}

void test_wm_agent_upgrade_validate_wpk_version_macos_https_ok(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("darwin", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("15", agent->minor_version);
    os_strdup("x64", agent->architecture);
    os_strdup("pkg", agent->package_type);

    task->use_http = false;
    os_strdup("v4.0.0", task->wpk_version);

    os_strdup("v3.13.1 4a313b1312c23a213f2e3209fe0909dd\nv4.0.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/macos/x64/pkg/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/macos/x64/pkg/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.0.0_macos_x64.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_macos_http_ok(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("darwin", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("15", agent->minor_version);
    os_strdup("x64", agent->architecture);
    os_strdup("pkg", agent->package_type);

    task->use_http = true;
    os_strdup("v3.13.1", task->wpk_version);

    os_strdup("v3.13.1 4a313b1312c23a213f2e3209fe0909dd\nv4.0.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "http://packages.wazuh.com/wpk/macos/x64/pkg/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "http://packages.wazuh.com/wpk/macos/x64/pkg/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v3.13.1_macos_x64.wpk");
    assert_string_equal(task->wpk_sha1, "4a313b1312c23a213f2e3209fe0909dd");
}

void test_wm_agent_upgrade_validate_wpk_version_macos_x86_64(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("darwin", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("15", agent->minor_version);
    os_strdup("x86_64", agent->architecture);
    os_strdup("pkg", agent->package_type);

    task->use_http = false;
    os_strdup("v4.9.0", task->wpk_version);

    os_strdup("v4.9.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/macos/pkg/intel64/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/macos/pkg/intel64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.9.0_macos_intel64.pkg.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_macos_aarch64(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("darwin", agent->platform);
    os_strdup("10", agent->major_version);
    os_strdup("15", agent->minor_version);
    os_strdup("aarch64", agent->architecture);
    os_strdup("pkg", agent->package_type);

    task->use_http = false;
    os_strdup("v4.9.0", task->wpk_version);

    os_strdup("v4.9.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/macos/pkg/arm64/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/macos/pkg/arm64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.9.0_macos_arm64.pkg.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_linux_package_rpm_x86_64(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("centos", agent->platform);
    os_strdup("8", agent->major_version);
    os_strdup("x86_64", agent->architecture);
    os_strdup("rpm", agent->package_type);

    task->use_http = false;
    os_strdup("v4.9.0", task->wpk_version);

    os_strdup("v4.9.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/linux/rpm/x86_64/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/linux/rpm/x86_64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.9.0_linux_x86_64.rpm.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_linux_package_rpm_aarch64(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("centos", agent->platform);
    os_strdup("8", agent->major_version);
    os_strdup("aarch64", agent->architecture);
    os_strdup("rpm", agent->package_type);

    task->use_http = false;
    os_strdup("v4.9.0", task->wpk_version);

    os_strdup("v4.9.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/linux/rpm/aarch64/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/linux/rpm/aarch64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.9.0_linux_aarch64.rpm.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_linux_package_rpm_rpm(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("centos", agent->platform);
    os_strdup("8", agent->major_version);
    os_strdup("x86_64", agent->architecture);
    os_strdup("rpm", agent->package_type);

    task->use_http = false;
    os_strdup("v4.9.0", task->wpk_version);
    os_strdup("rpm", task->package_type);

    os_strdup("v4.9.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/linux/rpm/x86_64/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/linux/rpm/x86_64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.9.0_linux_x86_64.rpm.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_linux_package_rpm_deb(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("centos", agent->platform);
    os_strdup("8", agent->major_version);
    os_strdup("x86_64", agent->architecture);
    os_strdup("rpm", agent->package_type);

    task->use_http = false;
    os_strdup("v4.9.0", task->wpk_version);
    os_strdup("deb", task->package_type);

    os_strdup("v4.9.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtwarn, formatted_msg, "(8169): Agent '0' with platform 'centos' won't be upgraded using package 'deb' without the force option. Ignoring...");

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/linux/rpm/x86_64/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/linux/rpm/x86_64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.9.0_linux_x86_64.rpm.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_linux_package_rpm_deb_force(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("centos", agent->platform);
    os_strdup("8", agent->major_version);
    os_strdup("x86_64", agent->architecture);
    os_strdup("rpm", agent->package_type);

    task->use_http = false;
    os_strdup("v4.9.0", task->wpk_version);
    os_strdup("deb", task->package_type);
    task->force_upgrade = true;

    os_strdup("v4.9.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8170): Agent '0' with platform 'centos' will be upgraded using package 'deb'");

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/linux/deb/amd64/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/linux/deb/amd64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.9.0_linux_amd64.deb.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_linux_package_deb_x86_64(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("18", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("x86_64", agent->architecture);
    os_strdup("deb", agent->package_type);

    task->use_http = false;
    os_strdup("v4.9.0", task->wpk_version);

    os_strdup("v4.9.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/linux/deb/amd64/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/linux/deb/amd64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.9.0_linux_amd64.deb.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_linux_package_deb_aarch64(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("18", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("aarch64", agent->architecture);
    os_strdup("deb", agent->package_type);

    task->use_http = false;
    os_strdup("v4.9.0", task->wpk_version);

    os_strdup("v4.9.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/linux/deb/arm64/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/linux/deb/arm64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.9.0_linux_arm64.deb.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_linux_package_deb_deb(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("18", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("x86_64", agent->architecture);
    os_strdup("deb", agent->package_type);

    task->use_http = false;
    os_strdup("v4.9.0", task->wpk_version);
    os_strdup("deb", task->package_type);

    os_strdup("v4.9.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/linux/deb/amd64/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/linux/deb/amd64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.9.0_linux_amd64.deb.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_linux_package_deb_rpm(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("18", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("x86_64", agent->architecture);
    os_strdup("deb", agent->package_type);

    task->use_http = false;
    os_strdup("v4.9.0", task->wpk_version);
    os_strdup("rpm", task->package_type);

    os_strdup("v4.9.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtwarn, formatted_msg, "(8169): Agent '0' with platform 'ubuntu' won't be upgraded using package 'rpm' without the force option. Ignoring...");

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/linux/deb/amd64/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/linux/deb/amd64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.9.0_linux_amd64.deb.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_linux_package_deb_rpm_force(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("ubuntu", agent->platform);
    os_strdup("18", agent->major_version);
    os_strdup("04", agent->minor_version);
    os_strdup("x86_64", agent->architecture);
    os_strdup("deb", agent->package_type);

    task->use_http = false;
    os_strdup("v4.9.0", task->wpk_version);
    os_strdup("rpm", task->package_type);
    task->force_upgrade = true;

    os_strdup("v4.9.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8170): Agent '0' with platform 'ubuntu' will be upgraded using package 'rpm'");

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/linux/rpm/x86_64/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/linux/rpm/x86_64/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.9.0_linux_x86_64.rpm.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_linux_package_unsupported_x86_64(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];

    os_strdup("unsupported", agent->platform);
    os_strdup("8", agent->major_version);
    os_strdup("x86_64", agent->architecture);
    agent->package_type = NULL;

    task->use_http = false;
    os_strdup("v4.9.0", task->wpk_version);

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtwarn, formatted_msg, "(8171): Agent '0' with unsupported platform 'unsupported' won't be upgraded without a default package.");

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SYSTEM_NOT_SUPPORTED);
    assert_string_equal(task->wpk_repository, "packages.wazuh.com/4.x/wpk/");
    assert_null(task->wpk_file);
    assert_null(task->wpk_sha1);
}

void test_wm_agent_upgrade_validate_wpk_version_linux_package_unsupported_aarch64(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];

    os_strdup("unsupported", agent->platform);
    os_strdup("8", agent->major_version);
    os_strdup("aarch64", agent->architecture);
    agent->package_type = NULL;

    task->use_http = false;
    os_strdup("v4.9.0", task->wpk_version);

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtwarn, formatted_msg, "(8171): Agent '0' with unsupported platform 'unsupported' won't be upgraded without a default package.");

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SYSTEM_NOT_SUPPORTED);
    assert_string_equal(task->wpk_repository, "packages.wazuh.com/4.x/wpk/");
    assert_null(task->wpk_file);
    assert_null(task->wpk_sha1);
}

void test_wm_agent_upgrade_validate_wpk_version_linux_package_unsupported_rpm(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("unsupported", agent->platform);
    os_strdup("8", agent->major_version);
    os_strdup("i386", agent->architecture);
    agent->package_type = NULL;

    task->use_http = false;
    os_strdup("v4.9.0", task->wpk_version);
    os_strdup("rpm", task->package_type);

    os_strdup("v4.9.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8172): Agent '0' with unsupported platform 'unsupported' will be upgraded with package 'rpm'");

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/linux/rpm/i386/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/linux/rpm/i386/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.9.0_linux_i386.rpm.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_wpk_version_linux_package_unsupported_deb(void **state)
{
    wm_agent_info *agent = state[0];
    wm_upgrade_task *task = state[1];
    char *versions = NULL;

    os_strdup("unsupported", agent->platform);
    os_strdup("8", agent->major_version);
    os_strdup("i386", agent->architecture);
    agent->package_type = NULL;

    task->use_http = false;
    os_strdup("v4.9.0", task->wpk_version);
    os_strdup("deb", task->package_type);

    os_strdup("v4.9.0 231ef123a32d312b4123c21313ee6780", versions);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8172): Agent '0' with unsupported platform 'unsupported' will be upgraded with package 'deb'");

    expect_string(__wrap_wurl_http_get, url, "https://packages.wazuh.com/4.x/wpk/linux/deb/i386/versions");
    expect_value(__wrap_wurl_http_get, timeout, WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT);
    will_return(__wrap_wurl_http_get, versions);

    int ret = wm_agent_upgrade_validate_wpk_version(agent, task, NULL);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_repository, "https://packages.wazuh.com/4.x/wpk/linux/deb/i386/");
    assert_string_equal(task->wpk_file, "wazuh_agent_v4.9.0_linux_i386.deb.wpk");
    assert_string_equal(task->wpk_sha1, "231ef123a32d312b4123c21313ee6780");
}

void test_wm_agent_upgrade_validate_version_upgrade_ok(void **state)
{
    wm_upgrade_task *task = state[1];
    char *wazuh_version = "v3.9.1";
    char *platform = "ubuntu";

    task->force_upgrade = false;

    int ret = wm_agent_upgrade_validate_version(wazuh_version, platform, WM_UPGRADE_UPGRADE, task);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_version, "v3.13.0");
}

void test_wm_agent_upgrade_validate_version_upgrade_custom_ok(void **state)
{
    wm_upgrade_task *task = state[1];
    char *wazuh_version = "v3.9.1";
    char *platform = "ubuntu";

    int ret = wm_agent_upgrade_validate_version(wazuh_version, platform, WM_UPGRADE_UPGRADE_CUSTOM, task);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_version_upgrade_non_minimal(void **state)
{
    wm_upgrade_task *task = state[1];
    char *wazuh_version = "v2.1.1";
    char *platform = "ubuntu";

    int ret = wm_agent_upgrade_validate_version(wazuh_version, platform, WM_UPGRADE_UPGRADE, task);

    assert_int_equal(ret, WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED);
}

void test_wm_agent_upgrade_validate_version_upgrade_custom_non_minimal(void **state)
{
    wm_upgrade_task *task = state[1];
    char *wazuh_version = "v2.1.1";
    char *platform = "ubuntu";

    int ret = wm_agent_upgrade_validate_version(wazuh_version, platform, WM_UPGRADE_UPGRADE_CUSTOM, task);

    assert_int_equal(ret, WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED);
}

void test_wm_agent_upgrade_validate_version_upgrade_older_version(void **state)
{
    wm_upgrade_task *task = state[1];
    char *wazuh_version = "v3.13.1";
    char *platform = "ubuntu";

    task->force_upgrade = false;
    os_strdup("v3.12.0", task->custom_version);

    int ret = wm_agent_upgrade_validate_version(wazuh_version, platform, WM_UPGRADE_UPGRADE, task);

    assert_int_equal(ret, WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT);
    assert_string_equal(task->wpk_version, "v3.12.0");
}

void test_wm_agent_upgrade_validate_version_upgrade_greater_version(void **state)
{
    wm_upgrade_task *task = state[1];
    char *wazuh_version = "v3.9.1";
    char *platform = "ubuntu";

    task->force_upgrade = false;
    os_strdup("v3.13.1", task->custom_version);

    int ret = wm_agent_upgrade_validate_version(wazuh_version, platform, WM_UPGRADE_UPGRADE, task);

    assert_int_equal(ret, WM_UPGRADE_NEW_VERSION_GREATER_MASTER);
    assert_string_equal(task->wpk_version, "v3.13.1");
}

void test_wm_agent_upgrade_validate_version_upgrade_force(void **state)
{
    wm_upgrade_task *task = state[1];
    char *wazuh_version = "v3.9.1";
    char *platform = "ubuntu";

    task->force_upgrade = true;
    os_strdup("v3.13.1", task->custom_version);

    int ret = wm_agent_upgrade_validate_version(wazuh_version, platform, WM_UPGRADE_UPGRADE, task);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_version, "v3.13.1");
}

void test_wm_agent_upgrade_validate_version_version_null(void **state)
{
    wm_upgrade_task *task = state[1];
    char *platform = "ubuntu";

    int ret = wm_agent_upgrade_validate_version(NULL, platform, WM_UPGRADE_UPGRADE_CUSTOM, task);

    assert_int_equal(ret, WM_UPGRADE_GLOBAL_DB_FAILURE);
}

void test_wm_agent_upgrade_validate_version_upgrade_ok_macos(void **state)
{
    wm_upgrade_task *task = state[1];
    char *wazuh_version = "v4.3.0";
    char *platform = "darwin";

    task->force_upgrade = true;
    os_strdup("v4.3.0", task->custom_version);

    int ret = wm_agent_upgrade_validate_version(wazuh_version, platform, WM_UPGRADE_UPGRADE, task);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
    assert_string_equal(task->wpk_version, "v4.3.0");
}

void test_wm_agent_upgrade_validate_version_upgrade_non_minimal_macos(void **state)
{
    wm_upgrade_task *task = state[1];
    char *wazuh_version = "v4.2.0";
    char *platform = "darwin";

    int ret = wm_agent_upgrade_validate_version(wazuh_version, platform, WM_UPGRADE_UPGRADE, task);

    assert_int_equal(ret, WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED);
}

void test_wm_agent_upgrade_validate_wpk_exist(void **state)
{
    wm_upgrade_task *task = *state;
    char *sha1 = "74691287f21a312ab2a12e31a23f21a33d242d52";

    os_strdup("https://packages.wazuh.com/4.x/wpk/windows/", task->wpk_repository);
    os_strdup("wazuh_agent_v4.0.0_windows.wpk", task->wpk_file);
    os_strdup(sha1, task->wpk_sha1);

    expect_string(__wrap_wfopen, path, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, 1);

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

    expect_string(__wrap_wfopen, path, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, 1);

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

    expect_string(__wrap_wfopen, path, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, 0);

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

    expect_string(__wrap_wfopen, path, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, 0);

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

    expect_string(__wrap_wfopen, path, "var/upgrade/wazuh_agent_v4.0.0_windows.wpk");
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, 0);

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

    expect_string(__wrap_wfopen, path, "/tmp/test.wpk");
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    int ret = wm_agent_upgrade_validate_wpk_custom(task);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_wpk_custom_not_exist(void **state)
{
    wm_upgrade_custom_task *task = *state;

    os_strdup("/tmp/test.wpk", task->custom_file_path);

    expect_string(__wrap_wfopen, path, "/tmp/test.wpk");
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, 0);

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
        cmocka_unit_test(test_wm_agent_upgrade_validate_status_null),
        cmocka_unit_test(test_wm_agent_upgrade_validate_status_disconnected),
        // wm_agent_upgrade_validate_system
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_windows_ok),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_rhel_ok),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_ubuntu_ok),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_rocky_ok),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_darwin_x64_ok),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_darwin_arm_ok),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_invalid_platform_solaris),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_invalid_platform_suse),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_invalid_platform_rhel),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_invalid_platform_centos),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_invalid_arch),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_rolling_opensuse),
        cmocka_unit_test(test_wm_agent_upgrade_validate_system_rolling_archlinux),
        // wm_agent_upgrade_validate_wpk_version
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_windows_https_ok, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_windows_http_ok, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_windows_invalid_version, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_windows_invalid_repo, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_https_ok, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_http_ok, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_invalid_str_version, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_invalid_version, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_invalid_repo, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_ubuntu_old_version, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_macos_https_ok, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_macos_http_ok, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_macos_x86_64, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_macos_aarch64, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_rhel_old_version, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_no_version, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_package_rpm_x86_64, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_package_rpm_aarch64, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_package_rpm_rpm, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_package_rpm_deb, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_package_rpm_deb_force, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_package_deb_x86_64, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_package_deb_aarch64, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_package_deb_deb, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_package_deb_rpm, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_package_deb_rpm_force, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_package_unsupported_x86_64, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_package_unsupported_aarch64, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_package_unsupported_rpm, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_wpk_version_linux_package_unsupported_deb, setup_validate_wpk_version, teardown_validate_wpk_version),
        // wm_agent_upgrade_validate_version
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_version_upgrade_ok, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_version_upgrade_custom_ok, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_version_upgrade_non_minimal, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_version_upgrade_custom_non_minimal, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_version_upgrade_older_version, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_version_upgrade_greater_version, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_version_upgrade_force, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_version_version_null, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_version_upgrade_ok_macos, setup_validate_wpk_version, teardown_validate_wpk_version),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_version_upgrade_non_minimal_macos, setup_validate_wpk_version, teardown_validate_wpk_version),
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
