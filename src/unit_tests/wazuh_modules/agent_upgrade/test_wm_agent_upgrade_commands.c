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
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../../wrappers/wazuh/wazuh_db/wdb_global_helpers_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_agent_upgrade_wrappers.h"

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_manager.h"
#include "../../wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_tasks.h"
#include "../../headers/shared.h"

int wm_agent_upgrade_analyze_agent(int agent_id, wm_agent_task *agent_task);
int wm_agent_upgrade_validate_agent_task(const wm_agent_task *agent_task);
int wm_agent_upgrade_create_upgrade_tasks(cJSON *data_array, wm_upgrade_command command);

// Setup / teardown

static int teardown_json(void **state) {
    cJSON *json = *state;
    cJSON_Delete(json);
    return 0;
}

static int teardown_string(void **state) {
    char *string = *state;
    os_free(string);
    return 0;
}

static int setup_agent_task(void **state) {
    wm_agent_task *agent_task = NULL;
    agent_task = wm_agent_upgrade_init_agent_task();
    agent_task->agent_info = wm_agent_upgrade_init_agent_info();
    agent_task->task_info = wm_agent_upgrade_init_task_info();
    *state = (void *)agent_task;
    return 0;
}

static int teardown_agent_task(void **state) {
    wm_agent_task *agent_task = *state;
    wm_agent_upgrade_free_agent_task(agent_task);
    return 0;
}

static int setup_analyze_agent_task(void **state) {
    setup_hash_table(NULL);
    wm_agent_task *agent_task = NULL;
    agent_task = wm_agent_upgrade_init_agent_task();
    agent_task->task_info = wm_agent_upgrade_init_task_info();
    *state = (void *)agent_task;
    return 0;
}

static int teardown_analyze_agent_task(void **state) {
    teardown_hash_table();
    wm_agent_task *agent_task = *state;
    wm_agent_upgrade_free_agent_task(agent_task);
    return 0;
}

static int teardown_agent_status_task_string(void **state) {
    wm_upgrade_agent_status_task *task = state[0];
    char *string = state[1];
    wm_agent_upgrade_free_agent_status_task(task);
    os_free(string);
    return 0;
}

static int setup_process_hash_table(void **state) {
    setup_hash_table(wm_agent_upgrade_free_agent_task);
    return 0;
}

static int teardown_upgrade_custom_task_string(void **state) {
    teardown_hash_table();
    wm_upgrade_custom_task *task = state[0];
    char *string = state[1];
    wm_agent_upgrade_free_upgrade_custom_task(task);
    os_free(string);
    return 0;
}

static int teardown_upgrade_task_string(void **state) {
    teardown_hash_table();
    wm_upgrade_task *task = state[0];
    char *string = state[1];
    wm_agent_upgrade_free_upgrade_task(task);
    os_free(string);
    return 0;
}

// Tests

void test_wm_agent_upgrade_cancel_pending_upgrades(void **state)
{
    (void) state;

    cJSON *request = cJSON_CreateObject();
    cJSON *origin = cJSON_CreateObject();
    cJSON *parameters = cJSON_CreateObject();

    cJSON_AddStringToObject(origin, "module", "upgrade_module");
    cJSON_AddItemToObject(request, "origin", origin);
    cJSON_AddStringToObject(request, "command", "upgrade_cancel_tasks");
    cJSON_AddItemToObject(request, "parameters", parameters);

    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddNumberToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "message", upgrade_error_codes[WM_UPGRADE_SUCCESS]);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_CANCEL_TASKS);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, task_module_request, request, sizeof(request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    wm_agent_upgrade_cancel_pending_upgrades();
}

void test_wm_agent_upgrade_validate_agent_task_upgrade_ok(void **state)
{
    (void) state;

    int agent = 44;
    char *platform = "ubuntu";
    char *os_major = "18";
    char *os_minor = "04";
    char *arch = "x64_86";
    char *wazuh_version = "v3.13.1";
    char *status = AGENT_CS_ACTIVE;
    wm_upgrade_task *upgrade_task = NULL;

    wm_agent_task *agent_task = *state;

    agent_task->agent_info->agent_id = agent;
    os_strdup(platform, agent_task->agent_info->platform);
    os_strdup(os_major, agent_task->agent_info->major_version);
    os_strdup(os_minor, agent_task->agent_info->minor_version);
    os_strdup(arch, agent_task->agent_info->architecture);
    os_strdup(wazuh_version, agent_task->agent_info->wazuh_version);
    os_strdup(status, agent_task->agent_info->connection_status);
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_string(__wrap_wm_agent_upgrade_validate_status, connection_status, status);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_system

    expect_string(__wrap_wm_agent_upgrade_validate_system, platform, platform);
    expect_string(__wrap_wm_agent_upgrade_validate_system, os_major, os_major);
    expect_string(__wrap_wm_agent_upgrade_validate_system, os_minor, os_minor);
    expect_string(__wrap_wm_agent_upgrade_validate_system, arch, arch);
    will_return(__wrap_wm_agent_upgrade_validate_system, "deb");
    will_return(__wrap_wm_agent_upgrade_validate_system, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_version

    expect_string(__wrap_wm_agent_upgrade_validate_version, wazuh_version, wazuh_version);
    expect_string(__wrap_wm_agent_upgrade_validate_version, platform, platform);
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    will_return(__wrap_wm_agent_upgrade_validate_version, "v4.1.0");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_agent_task_upgrade_custom_ok(void **state)
{
    (void) state;

    int agent = 44;
    char *platform = "ubuntu";
    char *os_major = "18";
    char *os_minor = "04";
    char *arch = "x64_86";
    char *wazuh_version = "v3.13.1";
    char *status = AGENT_CS_ACTIVE;
    wm_upgrade_custom_task *upgrade_custom_task = NULL;

    wm_agent_task *agent_task = *state;

    agent_task->agent_info->agent_id = agent;
    os_strdup(platform, agent_task->agent_info->platform);
    os_strdup(os_major, agent_task->agent_info->major_version);
    os_strdup(os_minor, agent_task->agent_info->minor_version);
    os_strdup(arch, agent_task->agent_info->architecture);
    os_strdup(wazuh_version, agent_task->agent_info->wazuh_version);
    os_strdup(status, agent_task->agent_info->connection_status);
    upgrade_custom_task = wm_agent_upgrade_init_upgrade_custom_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE_CUSTOM;
    agent_task->task_info->task = upgrade_custom_task;

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_string(__wrap_wm_agent_upgrade_validate_status, connection_status, status);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_system

    expect_string(__wrap_wm_agent_upgrade_validate_system, platform, platform);
    expect_string(__wrap_wm_agent_upgrade_validate_system, os_major, os_major);
    expect_string(__wrap_wm_agent_upgrade_validate_system, os_minor, os_minor);
    expect_string(__wrap_wm_agent_upgrade_validate_system, arch, arch);
    will_return(__wrap_wm_agent_upgrade_validate_system, "deb");
    will_return(__wrap_wm_agent_upgrade_validate_system, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_version

    expect_string(__wrap_wm_agent_upgrade_validate_version, wazuh_version, wazuh_version);
    expect_string(__wrap_wm_agent_upgrade_validate_version, platform, platform);
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_agent_task_version_err(void **state)
{
    (void) state;

    int agent = 44;
    char *platform = "ubuntu";
    char *os_major = "18";
    char *os_minor = "04";
    char *arch = "x64_86";
    char *wazuh_version = "v3.13.1";
    char *status = AGENT_CS_ACTIVE;
    wm_upgrade_task *upgrade_task = NULL;

    wm_agent_task *agent_task = *state;

    agent_task->agent_info->agent_id = agent;
    os_strdup(platform, agent_task->agent_info->platform);
    os_strdup(os_major, agent_task->agent_info->major_version);
    os_strdup(os_minor, agent_task->agent_info->minor_version);
    os_strdup(arch, agent_task->agent_info->architecture);
    os_strdup(wazuh_version, agent_task->agent_info->wazuh_version);
    os_strdup(status, agent_task->agent_info->connection_status);
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_string(__wrap_wm_agent_upgrade_validate_status, connection_status, status);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_system

    expect_string(__wrap_wm_agent_upgrade_validate_system, platform, platform);
    expect_string(__wrap_wm_agent_upgrade_validate_system, os_major, os_major);
    expect_string(__wrap_wm_agent_upgrade_validate_system, os_minor, os_minor);
    expect_string(__wrap_wm_agent_upgrade_validate_system, arch, arch);
    will_return(__wrap_wm_agent_upgrade_validate_system, "deb");
    will_return(__wrap_wm_agent_upgrade_validate_system, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_version

    expect_string(__wrap_wm_agent_upgrade_validate_version, wazuh_version, wazuh_version);
    expect_string(__wrap_wm_agent_upgrade_validate_version, platform, platform);
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_GLOBAL_DB_FAILURE);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task);

    assert_int_equal(ret, WM_UPGRADE_GLOBAL_DB_FAILURE);
}

void test_wm_agent_upgrade_validate_agent_task_system_err(void **state)
{
    (void) state;

    int agent = 44;
    char *platform = "ubuntu";
    char *os_major = "18";
    char *os_minor = "04";
    char *arch = "x64_86";
    char *wazuh_version = "v3.13.1";
    char *status = AGENT_CS_ACTIVE;
    wm_upgrade_task *upgrade_task = NULL;

    wm_agent_task *agent_task = *state;

    agent_task->agent_info->agent_id = agent;
    os_strdup(platform, agent_task->agent_info->platform);
    os_strdup(os_major, agent_task->agent_info->major_version);
    os_strdup(os_minor, agent_task->agent_info->minor_version);
    os_strdup(arch, agent_task->agent_info->architecture);
    os_strdup(wazuh_version, agent_task->agent_info->wazuh_version);
    os_strdup(status, agent_task->agent_info->connection_status);
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_string(__wrap_wm_agent_upgrade_validate_status, connection_status, status);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_system

    expect_string(__wrap_wm_agent_upgrade_validate_system, platform, platform);
    expect_string(__wrap_wm_agent_upgrade_validate_system, os_major, os_major);
    expect_string(__wrap_wm_agent_upgrade_validate_system, os_minor, os_minor);
    expect_string(__wrap_wm_agent_upgrade_validate_system, arch, arch);
    will_return(__wrap_wm_agent_upgrade_validate_system, "deb");
    will_return(__wrap_wm_agent_upgrade_validate_system, WM_UPGRADE_GLOBAL_DB_FAILURE);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task);

    assert_int_equal(ret, WM_UPGRADE_GLOBAL_DB_FAILURE);
}

void test_wm_agent_upgrade_validate_agent_task_status_err(void **state)
{
    (void) state;

    int agent = 44;
    char *platform = "ubuntu";
    char *os_major = "18";
    char *os_minor = "04";
    char *arch = "x64_86";
    char *wazuh_version = "v3.13.1";
    char *status = AGENT_CS_DISCONNECTED;
    wm_upgrade_task *upgrade_task = NULL;

    wm_agent_task *agent_task = *state;

    agent_task->agent_info->agent_id = agent;
    os_strdup(platform, agent_task->agent_info->platform);
    os_strdup(os_major, agent_task->agent_info->major_version);
    os_strdup(os_minor, agent_task->agent_info->minor_version);
    os_strdup(arch, agent_task->agent_info->architecture);
    os_strdup(wazuh_version, agent_task->agent_info->wazuh_version);
    os_strdup(status, agent_task->agent_info->connection_status);
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_string(__wrap_wm_agent_upgrade_validate_status, connection_status, status);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_AGENT_IS_NOT_ACTIVE);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task);

    assert_int_equal(ret, WM_UPGRADE_AGENT_IS_NOT_ACTIVE);
}

void test_wm_agent_upgrade_validate_agent_task_agent_id_err(void **state)
{
    (void) state;

    int agent = 44;
    char *platform = "ubuntu";
    char *os_major = "18";
    char *os_minor = "04";
    char *arch = "x64_86";
    char *wazuh_version = "v3.13.1";
    char *status = AGENT_CS_NEVER_CONNECTED;
    wm_upgrade_task *upgrade_task = NULL;

    wm_agent_task *agent_task = *state;

    agent_task->agent_info->agent_id = agent;
    os_strdup(platform, agent_task->agent_info->platform);
    os_strdup(os_major, agent_task->agent_info->major_version);
    os_strdup(os_minor, agent_task->agent_info->minor_version);
    os_strdup(arch, agent_task->agent_info->architecture);
    os_strdup(wazuh_version, agent_task->agent_info->wazuh_version);
    os_strdup(status, agent_task->agent_info->connection_status);
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_INVALID_ACTION_FOR_MANAGER);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task);

    assert_int_equal(ret, WM_UPGRADE_INVALID_ACTION_FOR_MANAGER);
}

void test_wm_agent_upgrade_analyze_agent_ok(void **state)
{
    (void) state;

    wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
    int agent = 119;
    char *platform = "ubuntu";
    char *major = "18";
    char *minor = "04";
    char *arch = "x86_64";
    char *version = "v3.13.1";
    const char *connection_status = AGENT_CS_ACTIVE;
    wm_upgrade_task *upgrade_task = NULL;

    wm_agent_task *agent_task = *state;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    cJSON *agent_info_array = cJSON_CreateArray();
    cJSON *agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(agent_info, "os_platform", platform);
    cJSON_AddStringToObject(agent_info, "os_major", major);
    cJSON_AddStringToObject(agent_info, "os_minor", minor);
    cJSON_AddStringToObject(agent_info, "os_arch", arch);
    cJSON_AddStringToObject(agent_info, "version", version);
    cJSON_AddStringToObject(agent_info, "connection_status", connection_status);
    cJSON_AddItemToArray(agent_info_array, agent_info);

    // wdb_agent_info

    expect_value(__wrap_wdb_get_agent_info, id, agent);
    will_return(__wrap_wdb_get_agent_info, agent_info_array);

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_string(__wrap_wm_agent_upgrade_validate_status, connection_status, connection_status);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_system

    expect_string(__wrap_wm_agent_upgrade_validate_system, platform, platform);
    expect_string(__wrap_wm_agent_upgrade_validate_system, os_major, major);
    expect_string(__wrap_wm_agent_upgrade_validate_system, os_minor, minor);
    expect_string(__wrap_wm_agent_upgrade_validate_system, arch, arch);
    will_return(__wrap_wm_agent_upgrade_validate_system, "deb");
    will_return(__wrap_wm_agent_upgrade_validate_system, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_version

    expect_string(__wrap_wm_agent_upgrade_validate_version, wazuh_version, version);
    expect_string(__wrap_wm_agent_upgrade_validate_version, platform, platform);
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    will_return(__wrap_wm_agent_upgrade_validate_version, "v4.1.0");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_create_task_entry
    expect_value(__wrap_wm_agent_upgrade_create_task_entry, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_create_task_entry, OSHASH_SUCCESS);

    error_code = wm_agent_upgrade_analyze_agent(agent, agent_task);

    assert_int_equal(error_code, WM_UPGRADE_SUCCESS);
    assert_non_null(agent_task->agent_info);
    assert_string_equal(agent_task->agent_info->platform, platform);
    assert_string_equal(agent_task->agent_info->major_version, major);
    assert_string_equal(agent_task->agent_info->minor_version, minor);
    assert_string_equal(agent_task->agent_info->architecture, arch);
    assert_string_equal(agent_task->agent_info->wazuh_version, version);
    assert_string_equal(agent_task->agent_info->connection_status, connection_status);
}

void test_wm_agent_upgrade_analyze_agent_duplicated_err(void **state)
{
    (void) state;

    wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
    int agent = 120;
    char *platform = "ubuntu";
    char *major = "18";
    char *minor = "04";
    char *arch = "x86_64";
    char *version = "v3.13.1";
    const char *connection_status = AGENT_CS_ACTIVE;
    wm_upgrade_task *upgrade_task = NULL;

    wm_agent_task *agent_task = *state;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    cJSON *agent_info_array = cJSON_CreateArray();
    cJSON *agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(agent_info, "os_platform", platform);
    cJSON_AddStringToObject(agent_info, "os_major", major);
    cJSON_AddStringToObject(agent_info, "os_minor", minor);
    cJSON_AddStringToObject(agent_info, "os_arch", arch);
    cJSON_AddStringToObject(agent_info, "version", version);
    cJSON_AddStringToObject(agent_info, "connection_status", connection_status);
    cJSON_AddItemToArray(agent_info_array, agent_info);

    // wdb_agent_info

    expect_value(__wrap_wdb_get_agent_info, id, agent);
    will_return(__wrap_wdb_get_agent_info, agent_info_array);

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_string(__wrap_wm_agent_upgrade_validate_status, connection_status, connection_status);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_system

    expect_string(__wrap_wm_agent_upgrade_validate_system, platform, platform);
    expect_string(__wrap_wm_agent_upgrade_validate_system, os_major, major);
    expect_string(__wrap_wm_agent_upgrade_validate_system, os_minor, minor);
    expect_string(__wrap_wm_agent_upgrade_validate_system, arch, arch);
    will_return(__wrap_wm_agent_upgrade_validate_system, "deb");
    will_return(__wrap_wm_agent_upgrade_validate_system, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_version

    expect_string(__wrap_wm_agent_upgrade_validate_version, wazuh_version, version);
    expect_string(__wrap_wm_agent_upgrade_validate_version, platform, platform);
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    will_return(__wrap_wm_agent_upgrade_validate_version, "v4.1.0");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_create_task_entry
    expect_value(__wrap_wm_agent_upgrade_create_task_entry, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_create_task_entry, OSHASH_DUPLICATE);

    error_code = wm_agent_upgrade_analyze_agent(agent, agent_task);

    assert_int_equal(error_code, WM_UPGRADE_UPGRADE_ALREADY_IN_PROGRESS);
    assert_non_null(agent_task->agent_info);
    assert_string_equal(agent_task->agent_info->platform, platform);
    assert_string_equal(agent_task->agent_info->major_version, major);
    assert_string_equal(agent_task->agent_info->minor_version, minor);
    assert_string_equal(agent_task->agent_info->architecture, arch);
    assert_string_equal(agent_task->agent_info->wazuh_version, version);
    assert_string_equal(agent_task->agent_info->connection_status, connection_status);
}

void test_wm_agent_upgrade_analyze_agent_unknown_err(void **state)
{
    (void) state;

    wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
    int agent = 121;
    char *platform = "ubuntu";
    char *major = "18";
    char *minor = "04";
    char *arch = "x86_64";
    char *version = "v3.13.1";
    const char *connection_status = AGENT_CS_ACTIVE;
    wm_upgrade_task *upgrade_task = NULL;

    wm_agent_task *agent_task = *state;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    cJSON *agent_info_array = cJSON_CreateArray();
    cJSON *agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(agent_info, "os_platform", platform);
    cJSON_AddStringToObject(agent_info, "os_major", major);
    cJSON_AddStringToObject(agent_info, "os_minor", minor);
    cJSON_AddStringToObject(agent_info, "os_arch", arch);
    cJSON_AddStringToObject(agent_info, "version", version);
    cJSON_AddStringToObject(agent_info, "connection_status", connection_status);
    cJSON_AddItemToArray(agent_info_array, agent_info);

    // wdb_agent_info

    expect_value(__wrap_wdb_get_agent_info, id, agent);
    will_return(__wrap_wdb_get_agent_info, agent_info_array);

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_string(__wrap_wm_agent_upgrade_validate_status, connection_status, connection_status);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_system

    expect_string(__wrap_wm_agent_upgrade_validate_system, platform, platform);
    expect_string(__wrap_wm_agent_upgrade_validate_system, os_major, major);
    expect_string(__wrap_wm_agent_upgrade_validate_system, os_minor, minor);
    expect_string(__wrap_wm_agent_upgrade_validate_system, arch, arch);
    will_return(__wrap_wm_agent_upgrade_validate_system, "deb");
    will_return(__wrap_wm_agent_upgrade_validate_system, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_version

    expect_string(__wrap_wm_agent_upgrade_validate_version, wazuh_version, version);
    expect_string(__wrap_wm_agent_upgrade_validate_version, platform, platform);
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    will_return(__wrap_wm_agent_upgrade_validate_version, "v4.1.0");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_create_task_entry
    expect_value(__wrap_wm_agent_upgrade_create_task_entry, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_create_task_entry, OS_INVALID);

    error_code = wm_agent_upgrade_analyze_agent(agent, agent_task);

    assert_int_equal(error_code, WM_UPGRADE_UNKNOWN_ERROR);
    assert_non_null(agent_task->agent_info);
    assert_string_equal(agent_task->agent_info->platform, platform);
    assert_string_equal(agent_task->agent_info->major_version, major);
    assert_string_equal(agent_task->agent_info->minor_version, minor);
    assert_string_equal(agent_task->agent_info->architecture, arch);
    assert_string_equal(agent_task->agent_info->wazuh_version, version);
    assert_string_equal(agent_task->agent_info->connection_status, connection_status);
}

void test_wm_agent_upgrade_analyze_agent_validate_err(void **state)
{
    (void) state;

    wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
    int agent = 119;
    char *platform = "ubuntu";
    char *major = "18";
    char *minor = "04";
    char *arch = "x86_64";
    char *version = "v3.13.1";
    const char *connection_status = AGENT_CS_NEVER_CONNECTED;
    wm_upgrade_task *upgrade_task = NULL;

    wm_agent_task *agent_task = *state;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    cJSON *agent_info_array = cJSON_CreateArray();
    cJSON *agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(agent_info, "os_platform", platform);
    cJSON_AddStringToObject(agent_info, "os_major", major);
    cJSON_AddStringToObject(agent_info, "os_minor", minor);
    cJSON_AddStringToObject(agent_info, "os_arch", arch);
    cJSON_AddStringToObject(agent_info, "version", version);
    cJSON_AddStringToObject(agent_info, "connection_status", connection_status);
    cJSON_AddItemToArray(agent_info_array, agent_info);

    // wdb_agent_info

    expect_value(__wrap_wdb_get_agent_info, id, agent);
    will_return(__wrap_wdb_get_agent_info, agent_info_array);

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_INVALID_ACTION_FOR_MANAGER);

    error_code = wm_agent_upgrade_analyze_agent(agent, agent_task);

    assert_int_equal(error_code, WM_UPGRADE_INVALID_ACTION_FOR_MANAGER);
    assert_non_null(agent_task->agent_info);
    assert_string_equal(agent_task->agent_info->platform, platform);
    assert_string_equal(agent_task->agent_info->major_version, major);
    assert_string_equal(agent_task->agent_info->minor_version, minor);
    assert_string_equal(agent_task->agent_info->architecture, arch);
    assert_string_equal(agent_task->agent_info->wazuh_version, version);
    assert_string_equal(agent_task->agent_info->connection_status, connection_status);
}

void test_wm_agent_upgrade_analyze_agent_global_db_err(void **state)
{
    (void) state;

    wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
    int agent = 119;
    wm_upgrade_task *upgrade_task = NULL;

    wm_agent_task *agent_task =*state;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    // wdb_agent_info

    expect_value(__wrap_wdb_get_agent_info, id, agent);
    will_return(__wrap_wdb_get_agent_info, NULL);

    error_code = wm_agent_upgrade_analyze_agent(agent, agent_task);

    assert_int_equal(error_code, WM_UPGRADE_GLOBAL_DB_FAILURE);
    assert_non_null(agent_task->agent_info);
    assert_null(agent_task->agent_info->platform);
    assert_null(agent_task->agent_info->major_version);
    assert_null(agent_task->agent_info->minor_version);
    assert_null(agent_task->agent_info->architecture);
    assert_null(agent_task->agent_info->wazuh_version);
}

void test_wm_agent_upgrade_create_upgrade_tasks_ok(void **state)
{
    cJSON *data_array = cJSON_CreateArray();
    int agent1 = 55;

    cJSON *agents_array1 = cJSON_CreateArray();
    cJSON_AddItemToArray(agents_array1, cJSON_CreateNumber(agent1));

    cJSON *agents_array2 = cJSON_CreateArray();
    cJSON_AddItemToArray(agents_array2, cJSON_CreateNumber(agent1));

    cJSON *status_request = cJSON_CreateObject();
    cJSON *status_origin = cJSON_CreateObject();
    cJSON *status_parameters = cJSON_CreateObject();
    cJSON *status_agents = cJSON_CreateArray();

    cJSON_AddStringToObject(status_origin, "module", "upgrade_module");
    cJSON_AddItemToObject(status_request, "origin", status_origin);
    cJSON_AddStringToObject(status_request, "command", "upgrade_get_status");
    cJSON_AddItemToArray(status_agents, cJSON_CreateNumber(agent1));
    cJSON_AddItemToObject(status_parameters, "agents", status_agents);
    cJSON_AddItemToObject(status_request, "parameters", status_parameters);

    cJSON *request_json = cJSON_CreateObject();
    cJSON *origin_json = cJSON_CreateObject();
    cJSON *parameters_json= cJSON_CreateObject();
    cJSON *agents_json = cJSON_CreateArray();

    cJSON_AddStringToObject(origin_json, "module", "upgrade_module");
    cJSON_AddItemToObject(request_json, "origin", origin_json);
    cJSON_AddStringToObject(request_json, "command", "upgrade_custom");
    cJSON_AddItemToArray(agents_json, cJSON_CreateNumber(agent1));
    cJSON_AddItemToObject(parameters_json, "agents", agents_json);
    cJSON_AddItemToObject(request_json, "parameters", parameters_json);

    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "message", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent1);
    cJSON_AddNumberToObject(task_response, "task_id", 100);

    // wm_agent_upgrade_get_agent_ids

    will_return(__wrap_wm_agent_upgrade_get_agent_ids, agents_array1);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, status_request);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, task_module_request, status_request, sizeof(status_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, NULL);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_get_agent_ids

    will_return(__wrap_wm_agent_upgrade_get_agent_ids, agents_array2);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_UPGRADE_CUSTOM);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request_json);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, task_module_request, request_json, sizeof(request_json));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_prepare_upgrades

    will_return(__wrap_wm_agent_upgrade_prepare_upgrades, 1);

    int ret = wm_agent_upgrade_create_upgrade_tasks(data_array, WM_UPGRADE_UPGRADE_CUSTOM);

    *state = data_array;

    assert_int_equal(ret, 1);
    assert_int_equal(cJSON_GetArraySize(data_array), 1);
    assert_memory_equal(cJSON_GetArrayItem(data_array, 0), task_response, sizeof(task_response));
}

void test_wm_agent_upgrade_create_upgrade_tasks_upgrade_err(void **state)
{
    cJSON *data_array = cJSON_CreateArray();
    int agent1 = 55;

    cJSON *agents_array1 = cJSON_CreateArray();
    cJSON_AddItemToArray(agents_array1, cJSON_CreateNumber(agent1));

    cJSON *agents_array2 = cJSON_CreateArray();
    cJSON_AddItemToArray(agents_array2, cJSON_CreateNumber(agent1));

    cJSON *status_request = cJSON_CreateObject();
    cJSON *status_origin = cJSON_CreateObject();
    cJSON *status_parameters = cJSON_CreateObject();
    cJSON *status_agents = cJSON_CreateArray();

    cJSON_AddStringToObject(status_origin, "module", "upgrade_module");
    cJSON_AddItemToObject(status_request, "origin", status_origin);
    cJSON_AddStringToObject(status_request, "command", "upgrade_get_status");
    cJSON_AddItemToArray(status_agents, cJSON_CreateNumber(agent1));
    cJSON_AddItemToObject(status_parameters, "agents", status_agents);
    cJSON_AddItemToObject(status_request, "parameters", status_parameters);

    cJSON *request_json = cJSON_CreateObject();
    cJSON *origin_json = cJSON_CreateObject();
    cJSON *parameters_json= cJSON_CreateObject();
    cJSON *agents_json = cJSON_CreateArray();

    cJSON_AddStringToObject(origin_json, "module", "upgrade_module");
    cJSON_AddItemToObject(request_json, "origin", origin_json);
    cJSON_AddStringToObject(request_json, "command", "upgrade_custom");
    cJSON_AddItemToArray(agents_json, cJSON_CreateNumber(agent1));
    cJSON_AddItemToObject(parameters_json, "agents", agents_json);
    cJSON_AddItemToObject(request_json, "parameters", parameters_json);

    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "message", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent1);
    cJSON_AddNumberToObject(task_response, "task_id", 100);

    // wm_agent_upgrade_get_agent_ids

    will_return(__wrap_wm_agent_upgrade_get_agent_ids, agents_array1);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, status_request);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, task_module_request, status_request, sizeof(status_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, NULL);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_get_agent_ids

    will_return(__wrap_wm_agent_upgrade_get_agent_ids, agents_array2);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_UPGRADE_CUSTOM);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request_json);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, task_module_request, request_json, sizeof(request_json));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, OS_INVALID);

    int ret = wm_agent_upgrade_create_upgrade_tasks(data_array, WM_UPGRADE_UPGRADE_CUSTOM);

    *state = data_array;

    assert_int_equal(ret, 0);
    assert_int_equal(cJSON_GetArraySize(data_array), 1);
    assert_memory_equal(cJSON_GetArrayItem(data_array, 0), task_response, sizeof(task_response));
}

void test_wm_agent_upgrade_create_upgrade_tasks_upgrade_no_agents(void **state)
{
    cJSON *data_array = cJSON_CreateArray();
    int agent1 = 55;

    cJSON *agents_array1 = cJSON_CreateArray();
    cJSON_AddItemToArray(agents_array1, cJSON_CreateNumber(agent1));

    cJSON *status_request = cJSON_CreateObject();
    cJSON *status_origin = cJSON_CreateObject();
    cJSON *status_parameters = cJSON_CreateObject();
    cJSON *status_agents = cJSON_CreateArray();

    cJSON_AddStringToObject(status_origin, "module", "upgrade_module");
    cJSON_AddItemToObject(status_request, "origin", status_origin);
    cJSON_AddStringToObject(status_request, "command", "upgrade_get_status");
    cJSON_AddItemToArray(status_agents, cJSON_CreateNumber(agent1));
    cJSON_AddItemToObject(status_parameters, "agents", status_agents);
    cJSON_AddItemToObject(status_request, "parameters", status_parameters);

    // wm_agent_upgrade_get_agent_ids

    will_return(__wrap_wm_agent_upgrade_get_agent_ids, agents_array1);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, status_request);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, task_module_request, status_request, sizeof(status_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, NULL);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_get_agent_ids

    will_return(__wrap_wm_agent_upgrade_get_agent_ids, NULL);

    int ret = wm_agent_upgrade_create_upgrade_tasks(data_array, WM_UPGRADE_UPGRADE_CUSTOM);

    *state = data_array;

    assert_int_equal(ret, 0);
    assert_int_equal(cJSON_GetArraySize(data_array), 0);
}

void test_wm_agent_upgrade_create_upgrade_tasks_get_status_err(void **state)
{
    cJSON *data_array = cJSON_CreateArray();
    int agent1 = 55;

    cJSON *agents_array1 = cJSON_CreateArray();
    cJSON_AddItemToArray(agents_array1, cJSON_CreateNumber(agent1));

    cJSON *status_request = cJSON_CreateObject();
    cJSON *status_origin = cJSON_CreateObject();
    cJSON *status_parameters = cJSON_CreateObject();
    cJSON *status_agents = cJSON_CreateArray();

    cJSON_AddStringToObject(status_origin, "module", "upgrade_module");
    cJSON_AddItemToObject(status_request, "origin", status_origin);
    cJSON_AddStringToObject(status_request, "command", "upgrade_get_status");
    cJSON_AddItemToArray(status_agents, cJSON_CreateNumber(agent1));
    cJSON_AddItemToObject(status_parameters, "agents", status_agents);
    cJSON_AddItemToObject(status_request, "parameters", status_parameters);

    // wm_agent_upgrade_get_agent_ids

    will_return(__wrap_wm_agent_upgrade_get_agent_ids, agents_array1);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, status_request);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, task_module_request, status_request, sizeof(status_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, NULL);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, OS_INVALID);

    int ret = wm_agent_upgrade_create_upgrade_tasks(data_array, WM_UPGRADE_UPGRADE_CUSTOM);

    *state = data_array;

    assert_int_equal(ret, 0);
    assert_int_equal(cJSON_GetArraySize(data_array), 0);
}

void test_wm_agent_upgrade_create_upgrade_tasks_get_status_no_agents(void **state)
{
    cJSON *data_array = cJSON_CreateArray();
    int agent1 = 55;

    // wm_agent_upgrade_get_agent_ids

    will_return(__wrap_wm_agent_upgrade_get_agent_ids, NULL);

    int ret = wm_agent_upgrade_create_upgrade_tasks(data_array, WM_UPGRADE_UPGRADE_CUSTOM);

    *state = data_array;

    assert_int_equal(ret, 0);
    assert_int_equal(cJSON_GetArraySize(data_array), 0);
}

void test_wm_agent_upgrade_process_upgrade_result_command_ok(void **state)
{
    (void) state;

    int agents[2];
    int task_id = 15;
    int create_time = 123456;
    int update_time = 123465;
    char *node = "node05";
    char *module = "upgrade_module";
    char *command = "upgrade";
    char *status = "Done";
    char *error = "Error message";

    agents[0] = 25;
    agents[1] = OS_INVALID;

    cJSON *request_result = cJSON_CreateObject();
    cJSON *origin_result = cJSON_CreateObject();
    cJSON *parameters_result = cJSON_CreateObject();
    cJSON *agents_result = cJSON_CreateArray();

    cJSON_AddStringToObject(origin_result, "module", "upgrade_module");
    cJSON_AddItemToObject(request_result, "origin", origin_result);
    cJSON_AddStringToObject(request_result, "command", "upgrade_result");
    cJSON_AddItemToArray(agents_result, cJSON_CreateNumber(agents[0]));
    cJSON_AddItemToObject(parameters_result, "agents", agents_result);
    cJSON_AddItemToObject(request_result, "parameters", parameters_result);

    cJSON *result_response = cJSON_CreateObject();

    cJSON_AddNumberToObject(result_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(result_response, "message", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(result_response, "agent", agents[0]);
    cJSON_AddNumberToObject(result_response, "task_id", task_id);
    cJSON_AddNumberToObject(result_response, "create_time", create_time);
    cJSON_AddNumberToObject(result_response, "update_time", update_time);
    cJSON_AddStringToObject(result_response, "node", node);
    cJSON_AddStringToObject(result_response, "module", module);
    cJSON_AddStringToObject(result_response, "command", command);
    cJSON_AddStringToObject(result_response, "status", status);
    cJSON_AddStringToObject(result_response, "error", error);

    cJSON *response_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(response_json, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(response_json, "message", upgrade_error_codes[WM_UPGRADE_SUCCESS]);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_RESULT);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request_result);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, task_module_request, request_result, sizeof(request_result));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, result_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_parse_response

    expect_value(__wrap_wm_agent_upgrade_parse_response, error_id, WM_UPGRADE_SUCCESS);
    will_return(__wrap_wm_agent_upgrade_parse_response, response_json);

    char *result = wm_agent_upgrade_process_upgrade_result_command(agents);

    *state = (void *)result;

    assert_non_null(result);
    assert_string_equal(result, "{\"error\":0,\"message\":\"Success\",\"data\":[{\"error\":0,\"message\":\"Success\",\"agent\":25,\"task_id\":15,\"create_time\":123456,\"update_time\":123465,\"node\":\"node05\",\"module\":\"upgrade_module\",\"command\":\"upgrade\",\"status\":\"Done\",\"error\":\"Error message\"}]}");
}

void test_wm_agent_upgrade_process_agent_result_command_done(void **state)
{
    (void) state;

    int agents[2];
    wm_upgrade_agent_status_task *upgrade_agent_status_task = NULL;
    char *agent_status = "Done";

    agents[0] = 25;
    agents[1] = OS_INVALID;

    upgrade_agent_status_task = wm_agent_upgrade_init_agent_status_task();
    upgrade_agent_status_task->error_code = 0;
    os_strdup("Success", upgrade_agent_status_task->message);
    os_strdup(agent_status, upgrade_agent_status_task->status);

    state[0] = (void *)upgrade_agent_status_task;

    cJSON *request_status = cJSON_CreateObject();
    cJSON *origin_status = cJSON_CreateObject();
    cJSON *parameters_status = cJSON_CreateObject();
    cJSON *agents_status = cJSON_CreateArray();

    cJSON_AddStringToObject(origin_status, "module", "upgrade_module");
    cJSON_AddItemToObject(request_status, "origin", origin_status);
    cJSON_AddStringToObject(request_status, "command", "upgrade_update_status");
    cJSON_AddItemToArray(agents_status, cJSON_CreateNumber(agents[0]));
    cJSON_AddItemToObject(parameters_status, "agents", agents_status);
    cJSON_AddItemToObject(request_status, "parameters", parameters_status);

    cJSON *status_response = cJSON_CreateObject();

    cJSON_AddNumberToObject(status_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(status_response, "message", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(status_response, "agent", agents[0]);
    cJSON_AddStringToObject(status_response, "status", agent_status);

    cJSON *response_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(response_json, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(response_json, "message", upgrade_error_codes[WM_UPGRADE_SUCCESS]);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtinfo, formatted_msg, "(8164): Received upgrade notification from agent '25'. Error code: '0', message: 'Success'");

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_UPDATE_STATUS);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request_status);
    expect_string(__wrap_wm_agent_upgrade_parse_task_module_request, status, agent_status);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, task_module_request, request_status, sizeof(request_status));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, status_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_parse_response

    expect_value(__wrap_wm_agent_upgrade_parse_response, error_id, WM_UPGRADE_SUCCESS);
    will_return(__wrap_wm_agent_upgrade_parse_response, response_json);

    char *result = wm_agent_upgrade_process_agent_result_command(agents, upgrade_agent_status_task);

    state[1] = (void *)result;

    assert_non_null(result);
    assert_string_equal(result, "{\"error\":0,\"message\":\"Success\",\"data\":[{\"error\":0,\"message\":\"Success\",\"agent\":25,\"status\":\"Done\"}]}");
}

void test_wm_agent_upgrade_process_agent_result_command_failed(void **state)
{
    (void) state;

    int agents[2];
    wm_upgrade_agent_status_task *upgrade_agent_status_task = NULL;
    char *agent_status = "Failed";
    char *agent_error = "Upgrade procedure exited with error code";

    agents[0] = 25;
    agents[1] = OS_INVALID;

    upgrade_agent_status_task = wm_agent_upgrade_init_agent_status_task();
    upgrade_agent_status_task->error_code = 2;
    os_strdup("Error message", upgrade_agent_status_task->message);
    os_strdup(agent_status, upgrade_agent_status_task->status);

    state[0] = (void *)upgrade_agent_status_task;

    cJSON *request_status = cJSON_CreateObject();
    cJSON *origin_status = cJSON_CreateObject();
    cJSON *parameters_status = cJSON_CreateObject();
    cJSON *agents_status = cJSON_CreateArray();

    cJSON_AddStringToObject(origin_status, "module", "upgrade_module");
    cJSON_AddItemToObject(request_status, "origin", origin_status);
    cJSON_AddStringToObject(request_status, "command", "upgrade_update_status");
    cJSON_AddItemToArray(agents_status, cJSON_CreateNumber(agents[0]));
    cJSON_AddItemToObject(parameters_status, "agents", agents_status);
    cJSON_AddItemToObject(request_status, "parameters", parameters_status);

    cJSON *status_response = cJSON_CreateObject();

    cJSON_AddNumberToObject(status_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(status_response, "message", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(status_response, "agent", agents[0]);
    cJSON_AddStringToObject(status_response, "status", agent_status);

    cJSON *response_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(response_json, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(response_json, "message", upgrade_error_codes[WM_UPGRADE_SUCCESS]);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtinfo, formatted_msg, "(8164): Received upgrade notification from agent '25'. Error code: '2', message: 'Error message'");

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_UPDATE_STATUS);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request_status);
    expect_string(__wrap_wm_agent_upgrade_parse_task_module_request, status, agent_status);
    expect_string(__wrap_wm_agent_upgrade_parse_task_module_request, error, agent_error);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, task_module_request, request_status, sizeof(request_status));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, status_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_parse_response

    expect_value(__wrap_wm_agent_upgrade_parse_response, error_id, WM_UPGRADE_SUCCESS);
    will_return(__wrap_wm_agent_upgrade_parse_response, response_json);

    char *result = wm_agent_upgrade_process_agent_result_command(agents, upgrade_agent_status_task);

    state[1] = (void *)result;

    assert_non_null(result);
    assert_string_equal(result, "{\"error\":0,\"message\":\"Success\",\"data\":[{\"error\":0,\"message\":\"Success\",\"agent\":25,\"status\":\"Failed\"}]}");
}

void test_wm_agent_upgrade_process_upgrade_custom_command(void **state)
{
    (void) state;

    int agents[3];
    wm_upgrade_custom_task *upgrade_custom_task = NULL;

    char *custom_file_path = "/tmp/test.wpk";
    char *custom_installer = "test.sh";

    agents[0] = 1;
    agents[1] = 2;
    agents[2] = OS_INVALID;

    upgrade_custom_task = wm_agent_upgrade_init_upgrade_custom_task();
    os_strdup(custom_file_path, upgrade_custom_task->custom_file_path);
    os_strdup(custom_installer, upgrade_custom_task->custom_installer);

    state[0] = (void *)upgrade_custom_task;

    cJSON *agent_info_array1 = cJSON_CreateArray();
    cJSON *agent_info1 = cJSON_CreateObject();
    cJSON_AddStringToObject(agent_info1, "os_platform", "ubuntu");
    cJSON_AddStringToObject(agent_info1, "os_major", "18");
    cJSON_AddStringToObject(agent_info1, "os_minor", "04");
    cJSON_AddStringToObject(agent_info1, "os_arch", "x86_64");
    cJSON_AddStringToObject(agent_info1, "version", "v3.13.1");
    cJSON_AddStringToObject(agent_info1, "connection_status", AGENT_CS_ACTIVE);
    cJSON_AddItemToArray(agent_info_array1, agent_info1);

    cJSON *agents_array1 = cJSON_CreateArray();
    cJSON_AddItemToArray(agents_array1, cJSON_CreateNumber(agents[0]));

    cJSON *agents_array2 = cJSON_CreateArray();
    cJSON_AddItemToArray(agents_array2, cJSON_CreateNumber(agents[0]));

    cJSON *status_request = cJSON_CreateObject();
    cJSON *status_origin = cJSON_CreateObject();
    cJSON *status_parameters = cJSON_CreateObject();
    cJSON *status_agents = cJSON_CreateArray();

    cJSON_AddStringToObject(status_origin, "module", "upgrade_module");
    cJSON_AddItemToObject(status_request, "origin", status_origin);
    cJSON_AddStringToObject(status_request, "command", "upgrade_get_status");
    cJSON_AddItemToArray(status_agents, cJSON_CreateNumber(agents[0]));
    cJSON_AddItemToObject(status_parameters, "agents", status_agents);
    cJSON_AddItemToObject(status_request, "parameters", status_parameters);

    cJSON *task_response1 = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response1, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response1, "message", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response1, "agent", agents[0]);
    cJSON_AddNumberToObject(task_response1, "task_id", 100);

    cJSON *task_response2 = cJSON_CreateObject();

    cJSON_AddNumberToObject(task_response2, "error", WM_UPGRADE_GLOBAL_DB_FAILURE);
    cJSON_AddStringToObject(task_response2, "message", upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    cJSON_AddNumberToObject(task_response2, "agent", agents[1]);

    cJSON *request_json = cJSON_CreateObject();
    cJSON *origin_json = cJSON_CreateObject();
    cJSON *parameters_json= cJSON_CreateObject();
    cJSON *agents_json = cJSON_CreateArray();

    cJSON_AddStringToObject(origin_json, "module", "upgrade_module");
    cJSON_AddItemToObject(request_json, "origin", origin_json);
    cJSON_AddStringToObject(request_json, "command", "upgrade_custom");
    cJSON_AddItemToArray(agents_json, cJSON_CreateNumber(agents[0]));
    cJSON_AddItemToObject(parameters_json, "agents", agents_json);
    cJSON_AddItemToObject(request_json, "parameters", parameters_json);

    cJSON *response_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(response_json, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(response_json, "message", upgrade_error_codes[WM_UPGRADE_SUCCESS]);

    // Analize agent[0]

    // wdb_agent_info

    expect_value(__wrap_wdb_get_agent_info, id, agents[0]);
    will_return(__wrap_wdb_get_agent_info, agent_info_array1);

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_string(__wrap_wm_agent_upgrade_validate_status, connection_status, AGENT_CS_ACTIVE);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_system

    expect_string(__wrap_wm_agent_upgrade_validate_system, platform, "ubuntu");
    expect_string(__wrap_wm_agent_upgrade_validate_system, os_major, "18");
    expect_string(__wrap_wm_agent_upgrade_validate_system, os_minor, "04");
    expect_string(__wrap_wm_agent_upgrade_validate_system, arch, "x86_64");
    will_return(__wrap_wm_agent_upgrade_validate_system, "deb");
    will_return(__wrap_wm_agent_upgrade_validate_system, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_version

    expect_string(__wrap_wm_agent_upgrade_validate_version, wazuh_version, "v3.13.1");
    expect_string(__wrap_wm_agent_upgrade_validate_version, platform, "ubuntu");
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, WM_UPGRADE_UPGRADE_CUSTOM);
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_create_task_entry
    expect_value(__wrap_wm_agent_upgrade_create_task_entry, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_create_task_entry, OSHASH_SUCCESS);

    // Analize agent[1]

    // wdb_agent_info

    expect_value(__wrap_wdb_get_agent_info, id, agents[1]);
    will_return(__wrap_wdb_get_agent_info, NULL);

    expect_value(__wrap_wm_agent_upgrade_parse_data_response, error_id, WM_UPGRADE_GLOBAL_DB_FAILURE);
    expect_string(__wrap_wm_agent_upgrade_parse_data_response, message, upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    expect_value(__wrap_wm_agent_upgrade_parse_data_response, agent_int, agents[1]);
    will_return(__wrap_wm_agent_upgrade_parse_data_response, task_response2);

    // wm_agent_upgrade_get_agent_ids

    will_return(__wrap_wm_agent_upgrade_get_agent_ids, agents_array1);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, status_request);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, task_module_request, status_request, sizeof(status_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, NULL);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_get_agent_ids

    will_return(__wrap_wm_agent_upgrade_get_agent_ids, agents_array2);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_UPGRADE_CUSTOM);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request_json);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, task_module_request, request_json, sizeof(request_json));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response1);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_prepare_upgrades

    will_return(__wrap_wm_agent_upgrade_prepare_upgrades, 1);

    // wm_agent_upgrade_parse_response

    expect_value(__wrap_wm_agent_upgrade_parse_response, error_id, WM_UPGRADE_SUCCESS);
    will_return(__wrap_wm_agent_upgrade_parse_response, response_json);

    char *result = wm_agent_upgrade_process_upgrade_custom_command(agents, upgrade_custom_task);

    state[1] = (void *)result;

    assert_non_null(result);
    assert_string_equal(result, "{\"error\":0,\"message\":\"Success\",\"data\":[{\"error\":6,\"message\":\"Agent information not found in database\",\"agent\":2},{\"message\":\"Success\",\"agent\":1,\"task_id\":100}]}");
}

void test_wm_agent_upgrade_process_upgrade_custom_command_no_agents(void **state)
{
    (void) state;

    int agents[3];
    wm_upgrade_custom_task *upgrade_custom_task = NULL;

    char *custom_file_path = "/tmp/test.wpk";
    char *custom_installer = "test.sh";

    agents[0] = 1;
    agents[1] = 2;
    agents[2] = OS_INVALID;

    upgrade_custom_task = wm_agent_upgrade_init_upgrade_custom_task();
    os_strdup(custom_file_path, upgrade_custom_task->custom_file_path);
    os_strdup(custom_installer, upgrade_custom_task->custom_installer);

    state[0] = (void *)upgrade_custom_task;

    cJSON *task_response1 = cJSON_CreateObject();

    cJSON_AddNumberToObject(task_response1, "error", WM_UPGRADE_GLOBAL_DB_FAILURE);
    cJSON_AddStringToObject(task_response1, "message", upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    cJSON_AddNumberToObject(task_response1, "agent", agents[0]);

    cJSON *task_response2 = cJSON_CreateObject();

    cJSON_AddNumberToObject(task_response2, "error", WM_UPGRADE_GLOBAL_DB_FAILURE);
    cJSON_AddStringToObject(task_response2, "message", upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    cJSON_AddNumberToObject(task_response2, "agent", agents[1]);

    cJSON *response_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(response_json, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(response_json, "message", upgrade_error_codes[WM_UPGRADE_SUCCESS]);

    // Analize agent[0]

    // wdb_agent_info

    expect_value(__wrap_wdb_get_agent_info, id, agents[0]);
    will_return(__wrap_wdb_get_agent_info, NULL);

    expect_value(__wrap_wm_agent_upgrade_parse_data_response, error_id, WM_UPGRADE_GLOBAL_DB_FAILURE);
    expect_string(__wrap_wm_agent_upgrade_parse_data_response, message, upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    expect_value(__wrap_wm_agent_upgrade_parse_data_response, agent_int, agents[0]);
    will_return(__wrap_wm_agent_upgrade_parse_data_response, task_response1);

    // Analize agent[1]

    // wdb_agent_info

    expect_value(__wrap_wdb_get_agent_info, id, agents[1]);
    will_return(__wrap_wdb_get_agent_info, NULL);

    expect_value(__wrap_wm_agent_upgrade_parse_data_response, error_id, WM_UPGRADE_GLOBAL_DB_FAILURE);
    expect_string(__wrap_wm_agent_upgrade_parse_data_response, message, upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    expect_value(__wrap_wm_agent_upgrade_parse_data_response, agent_int, agents[1]);
    will_return(__wrap_wm_agent_upgrade_parse_data_response, task_response2);

    // wm_agent_upgrade_get_agent_ids

    will_return(__wrap_wm_agent_upgrade_get_agent_ids, NULL);

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtwarn, formatted_msg, "(8160): There are no valid agents to upgrade.");

    // wm_agent_upgrade_parse_response

    expect_value(__wrap_wm_agent_upgrade_parse_response, error_id, WM_UPGRADE_SUCCESS);
    will_return(__wrap_wm_agent_upgrade_parse_response, response_json);

    char *result = wm_agent_upgrade_process_upgrade_custom_command(agents, upgrade_custom_task);

    state[1] = (void *)result;

    assert_non_null(result);
    assert_string_equal(result, "{\"error\":0,\"message\":\"Success\",\"data\":[{\"error\":6,\"message\":\"Agent information not found in database\",\"agent\":1},{\"error\":6,\"message\":\"Agent information not found in database\",\"agent\":2}]}");
}

void test_wm_agent_upgrade_process_upgrade_command(void **state)
{
    (void) state;

    int agents[3];
    wm_upgrade_task *upgrade_task = NULL;

    agents[0] = 1;
    agents[1] = 2;
    agents[2] = OS_INVALID;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();

    state[0] = (void *)upgrade_task;

    cJSON *agent_info_array1 = cJSON_CreateArray();
    cJSON *agent_info1 = cJSON_CreateObject();
    cJSON_AddStringToObject(agent_info1, "os_platform", "ubuntu");
    cJSON_AddStringToObject(agent_info1, "os_major", "18");
    cJSON_AddStringToObject(agent_info1, "os_minor", "04");
    cJSON_AddStringToObject(agent_info1, "os_arch", "x86_64");
    cJSON_AddStringToObject(agent_info1, "version", "v3.13.1");
    cJSON_AddStringToObject(agent_info1, "connection_status", AGENT_CS_ACTIVE);
    cJSON_AddItemToArray(agent_info_array1, agent_info1);

    cJSON *agents_array1 = cJSON_CreateArray();
    cJSON_AddItemToArray(agents_array1, cJSON_CreateNumber(agents[0]));

    cJSON *agents_array2 = cJSON_CreateArray();
    cJSON_AddItemToArray(agents_array2, cJSON_CreateNumber(agents[0]));

    cJSON *status_request = cJSON_CreateObject();
    cJSON *status_origin = cJSON_CreateObject();
    cJSON *status_parameters = cJSON_CreateObject();
    cJSON *status_agents = cJSON_CreateArray();

    cJSON_AddStringToObject(status_origin, "module", "upgrade_module");
    cJSON_AddItemToObject(status_request, "origin", status_origin);
    cJSON_AddStringToObject(status_request, "command", "upgrade_get_status");
    cJSON_AddItemToArray(status_agents, cJSON_CreateNumber(agents[0]));
    cJSON_AddItemToObject(status_parameters, "agents", status_agents);
    cJSON_AddItemToObject(status_request, "parameters", status_parameters);

    cJSON *task_response1 = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response1, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response1, "message", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response1, "agent", agents[0]);
    cJSON_AddNumberToObject(task_response1, "task_id", 110);

    cJSON *task_response2 = cJSON_CreateObject();

    cJSON_AddNumberToObject(task_response2, "error", WM_UPGRADE_GLOBAL_DB_FAILURE);
    cJSON_AddStringToObject(task_response2, "message", upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    cJSON_AddNumberToObject(task_response2, "agent", agents[1]);

    cJSON *request_json = cJSON_CreateObject();
    cJSON *origin_json = cJSON_CreateObject();
    cJSON *parameters_json= cJSON_CreateObject();
    cJSON *agents_json = cJSON_CreateArray();

    cJSON_AddStringToObject(origin_json, "module", "upgrade_module");
    cJSON_AddItemToObject(request_json, "origin", origin_json);
    cJSON_AddStringToObject(request_json, "command", "upgrade");
    cJSON_AddItemToArray(agents_json, cJSON_CreateNumber(agents[0]));
    cJSON_AddItemToObject(parameters_json, "agents", agents_json);
    cJSON_AddItemToObject(request_json, "parameters", parameters_json);

    cJSON *response_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(response_json, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(response_json, "message", upgrade_error_codes[WM_UPGRADE_SUCCESS]);

    // Analize agent[0]

    // wdb_agent_info

    expect_value(__wrap_wdb_get_agent_info, id, agents[0]);
    will_return(__wrap_wdb_get_agent_info, agent_info_array1);

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_string(__wrap_wm_agent_upgrade_validate_status, connection_status, AGENT_CS_ACTIVE);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_system

    expect_string(__wrap_wm_agent_upgrade_validate_system, platform, "ubuntu");
    expect_string(__wrap_wm_agent_upgrade_validate_system, os_major, "18");
    expect_string(__wrap_wm_agent_upgrade_validate_system, os_minor, "04");
    expect_string(__wrap_wm_agent_upgrade_validate_system, arch, "x86_64");
    will_return(__wrap_wm_agent_upgrade_validate_system, "deb");
    will_return(__wrap_wm_agent_upgrade_validate_system, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_version

    expect_string(__wrap_wm_agent_upgrade_validate_version, wazuh_version, "v3.13.1");
    expect_string(__wrap_wm_agent_upgrade_validate_version, platform, "ubuntu");
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, WM_UPGRADE_UPGRADE);
    will_return(__wrap_wm_agent_upgrade_validate_version, "v4.1.0");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_create_task_entry
    expect_value(__wrap_wm_agent_upgrade_create_task_entry, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_create_task_entry, OSHASH_SUCCESS);

    // Analize agent[1]

    // wdb_agent_info

    expect_value(__wrap_wdb_get_agent_info, id, agents[1]);
    will_return(__wrap_wdb_get_agent_info, NULL);

    expect_value(__wrap_wm_agent_upgrade_parse_data_response, error_id, WM_UPGRADE_GLOBAL_DB_FAILURE);
    expect_string(__wrap_wm_agent_upgrade_parse_data_response, message, upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    expect_value(__wrap_wm_agent_upgrade_parse_data_response, agent_int, agents[1]);
    will_return(__wrap_wm_agent_upgrade_parse_data_response, task_response2);

    // wm_agent_upgrade_get_agent_ids

    will_return(__wrap_wm_agent_upgrade_get_agent_ids, agents_array1);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, status_request);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, task_module_request, status_request, sizeof(status_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, NULL);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_get_agent_ids

    will_return(__wrap_wm_agent_upgrade_get_agent_ids, agents_array2);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_UPGRADE);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request_json);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, task_module_request, request_json, sizeof(request_json));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response1);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_prepare_upgrades

    will_return(__wrap_wm_agent_upgrade_prepare_upgrades, 1);

    // wm_agent_upgrade_parse_response

    expect_value(__wrap_wm_agent_upgrade_parse_response, error_id, WM_UPGRADE_SUCCESS);
    will_return(__wrap_wm_agent_upgrade_parse_response, response_json);

    char *result = wm_agent_upgrade_process_upgrade_command(agents, upgrade_task);

    state[1] = (void *)result;

    assert_non_null(result);
    assert_string_equal(result, "{\"error\":0,\"message\":\"Success\",\"data\":[{\"error\":6,\"message\":\"Agent information not found in database\",\"agent\":2},{\"message\":\"Success\",\"agent\":1,\"task_id\":110}]}");
}

void test_wm_agent_upgrade_process_upgrade_command_no_agents(void **state)
{
    (void) state;

    int agents[3];
    wm_upgrade_task *upgrade_task = NULL;

    agents[0] = 1;
    agents[1] = 2;
    agents[2] = OS_INVALID;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();

    state[0] = (void *)upgrade_task;

    cJSON *task_response1 = cJSON_CreateObject();

    cJSON_AddNumberToObject(task_response1, "error", WM_UPGRADE_GLOBAL_DB_FAILURE);
    cJSON_AddStringToObject(task_response1, "message", upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    cJSON_AddNumberToObject(task_response1, "agent", agents[0]);

    cJSON *task_response2 = cJSON_CreateObject();

    cJSON_AddNumberToObject(task_response2, "error", WM_UPGRADE_GLOBAL_DB_FAILURE);
    cJSON_AddStringToObject(task_response2, "message", upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    cJSON_AddNumberToObject(task_response2, "agent", agents[1]);

    cJSON *response_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(response_json, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(response_json, "message", upgrade_error_codes[WM_UPGRADE_SUCCESS]);

    // Analize agent[0]

    // wdb_agent_info

    expect_value(__wrap_wdb_get_agent_info, id, agents[0]);
    will_return(__wrap_wdb_get_agent_info, NULL);

    expect_value(__wrap_wm_agent_upgrade_parse_data_response, error_id, WM_UPGRADE_GLOBAL_DB_FAILURE);
    expect_string(__wrap_wm_agent_upgrade_parse_data_response, message, upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    expect_value(__wrap_wm_agent_upgrade_parse_data_response, agent_int, agents[0]);
    will_return(__wrap_wm_agent_upgrade_parse_data_response, task_response1);

    // Analize agent[1]

    // wdb_agent_info

    expect_value(__wrap_wdb_get_agent_info, id, agents[1]);
    will_return(__wrap_wdb_get_agent_info, NULL);

    expect_value(__wrap_wm_agent_upgrade_parse_data_response, error_id, WM_UPGRADE_GLOBAL_DB_FAILURE);
    expect_string(__wrap_wm_agent_upgrade_parse_data_response, message, upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    expect_value(__wrap_wm_agent_upgrade_parse_data_response, agent_int, agents[1]);
    will_return(__wrap_wm_agent_upgrade_parse_data_response, task_response2);

    // wm_agent_upgrade_get_agent_ids

    will_return(__wrap_wm_agent_upgrade_get_agent_ids, NULL);

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtwarn, formatted_msg, "(8160): There are no valid agents to upgrade.");

    // wm_agent_upgrade_parse_response

    expect_value(__wrap_wm_agent_upgrade_parse_response, error_id, WM_UPGRADE_SUCCESS);
    will_return(__wrap_wm_agent_upgrade_parse_response, response_json);

    char *result = wm_agent_upgrade_process_upgrade_command(agents, upgrade_task);

    state[1] = (void *)result;

    assert_non_null(result);
    assert_string_equal(result, "{\"error\":0,\"message\":\"Success\",\"data\":[{\"error\":6,\"message\":\"Agent information not found in database\",\"agent\":1},{\"error\":6,\"message\":\"Agent information not found in database\",\"agent\":2}]}");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_agent_upgrade_cancel_pending_upgrades
        cmocka_unit_test(test_wm_agent_upgrade_cancel_pending_upgrades),
        // wm_agent_upgrade_validate_agent_task
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_upgrade_ok, setup_agent_task, teardown_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_upgrade_custom_ok, setup_agent_task, teardown_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_version_err, setup_agent_task, teardown_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_system_err, setup_agent_task, teardown_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_status_err, setup_agent_task, teardown_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_agent_id_err, setup_agent_task, teardown_agent_task),
        // wm_agent_upgrade_analyze_agent
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_analyze_agent_ok, setup_analyze_agent_task, teardown_analyze_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_analyze_agent_duplicated_err, setup_analyze_agent_task, teardown_analyze_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_analyze_agent_unknown_err, setup_analyze_agent_task, teardown_analyze_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_analyze_agent_validate_err, setup_analyze_agent_task, teardown_analyze_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_analyze_agent_global_db_err, setup_analyze_agent_task, teardown_analyze_agent_task),
        // wm_agent_upgrade_create_upgrade_tasks
        cmocka_unit_test_teardown(test_wm_agent_upgrade_create_upgrade_tasks_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_create_upgrade_tasks_upgrade_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_create_upgrade_tasks_upgrade_no_agents, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_create_upgrade_tasks_get_status_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_create_upgrade_tasks_get_status_no_agents, teardown_json),
        // wm_agent_upgrade_process_upgrade_result_command
        cmocka_unit_test_teardown(test_wm_agent_upgrade_process_upgrade_result_command_ok, teardown_string),
        // wm_agent_upgrade_process_agent_result_command
        cmocka_unit_test_teardown(test_wm_agent_upgrade_process_agent_result_command_done, teardown_agent_status_task_string),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_process_agent_result_command_failed, teardown_agent_status_task_string),
        // wm_agent_upgrade_process_upgrade_custom_command
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_upgrade_custom_command, setup_process_hash_table, teardown_upgrade_custom_task_string),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_upgrade_custom_command_no_agents, setup_process_hash_table, teardown_upgrade_custom_task_string),
        // wm_agent_upgrade_process_upgrade_command
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_upgrade_command, setup_process_hash_table, teardown_upgrade_task_string),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_upgrade_command_no_agents, setup_process_hash_table, teardown_upgrade_task_string),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
