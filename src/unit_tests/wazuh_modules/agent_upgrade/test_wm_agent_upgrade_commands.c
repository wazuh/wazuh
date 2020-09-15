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
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_agent_upgrade_wrappers.h"

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_manager.h"
#include "../../wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_tasks.h"
#include "../../headers/shared.h"

cJSON* wm_agent_upgrade_analyze_agent(int agent_id, wm_agent_task *agent_task, wm_upgrade_error_code *error_code, const wm_manager_configs* manager_configs);
int wm_agent_upgrade_validate_agent_task(const wm_agent_task *agent_task, const wm_manager_configs* manager_configs);

// Setup / teardown

static int setup_config_agent_task(void **state) {
    wm_manager_configs *config = NULL;
    wm_agent_task *agent_task = NULL;
    os_calloc(1, sizeof(wm_manager_configs), config);
    agent_task = wm_agent_upgrade_init_agent_task();
    agent_task->agent_info = wm_agent_upgrade_init_agent_info();
    agent_task->task_info = wm_agent_upgrade_init_task_info();
    state[0] = (void *)config;
    state[1] = (void *)agent_task;
    return 0;
}

static int teardown_config_agent_task(void **state) {
    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];
    os_free(config);
    wm_agent_upgrade_free_agent_task(agent_task);
    return 0;
}

static int setup_analyze_agent_task(void **state) {
    setup_hash_table(NULL);
    wm_manager_configs *config = NULL;
    wm_agent_task *agent_task = NULL;
    os_calloc(1, sizeof(wm_manager_configs), config);
    agent_task = wm_agent_upgrade_init_agent_task();
    agent_task->task_info = wm_agent_upgrade_init_task_info();
    state[0] = (void *)config;
    state[1] = (void *)agent_task;
    return 0;
}

static int teardown_analyze_agent_task(void **state) {
    teardown_hash_table();
    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];
    os_free(config);
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

void test_wm_agent_upgrade_validate_agent_task_upgrade_ok(void **state)
{
    (void) state;

    int agent = 44;
    int keep_alive = 2345678;
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent;
    agent_task->agent_info->last_keep_alive = keep_alive;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    cJSON *request = cJSON_CreateArray();

    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(task_request, "agent", agent);

    cJSON_AddItemToArray(request, task_request);

    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent);
    cJSON_AddStringToObject(task_response, "status", "Done");

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, task_response, sizeof(task_response));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "Done");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task, config);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_agent_task_upgrade_custom_ok(void **state)
{
    (void) state;

    int agent = 44;
    int keep_alive = 2345678;
    wm_upgrade_custom_task *upgrade_custom_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent;
    agent_task->agent_info->last_keep_alive = keep_alive;
    upgrade_custom_task = wm_agent_upgrade_init_upgrade_custom_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE_CUSTOM;
    agent_task->task_info->task = upgrade_custom_task;

    cJSON *request = cJSON_CreateArray();

    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(task_request, "agent", agent);

    cJSON_AddItemToArray(request, task_request);

    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent);
    cJSON_AddStringToObject(task_response, "status", "Done");

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, task_response, sizeof(task_response));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "Done");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task, config);

    assert_int_equal(ret, WM_UPGRADE_SUCCESS);
}

void test_wm_agent_upgrade_validate_agent_task_in_progress_err(void **state)
{
    (void) state;

    int agent = 44;
    int keep_alive = 2345678;
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent;
    agent_task->agent_info->last_keep_alive = keep_alive;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    cJSON *request = cJSON_CreateArray();

    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(task_request, "agent", agent);

    cJSON_AddItemToArray(request, task_request);

    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent);
    cJSON_AddStringToObject(task_response, "status", "Done");

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, task_response, sizeof(task_response));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "In progress");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task, config);

    assert_int_equal(ret, WM_UPGRADE_UPGRADE_ALREADY_IN_PROGRESS);
}

void test_wm_agent_upgrade_validate_agent_task_task_manager_err(void **state)
{
    (void) state;

    int agent = 44;
    int keep_alive = 2345678;
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent;
    agent_task->agent_info->last_keep_alive = keep_alive;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    cJSON *request = cJSON_CreateArray();

    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(task_request, "agent", agent);

    cJSON_AddItemToArray(request, task_request);

    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agent);
    cJSON_AddStringToObject(task_response, "status", "Done");

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, task_response, sizeof(task_response));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "Done");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 0);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task, config);

    assert_int_equal(ret, WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
}

void test_wm_agent_upgrade_validate_agent_task_version_err(void **state)
{
    (void) state;

    int agent = 44;
    int keep_alive = 2345678;
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent;
    agent_task->agent_info->last_keep_alive = keep_alive;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_GLOBAL_DB_FAILURE);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task, config);

    assert_int_equal(ret, WM_UPGRADE_GLOBAL_DB_FAILURE);
}

void test_wm_agent_upgrade_validate_agent_task_status_err(void **state)
{
    (void) state;

    int agent = 44;
    int keep_alive = 2345678;
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent;
    agent_task->agent_info->last_keep_alive = keep_alive;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_AGENT_IS_NOT_ACTIVE);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task, config);

    assert_int_equal(ret, WM_UPGRADE_AGENT_IS_NOT_ACTIVE);
}

void test_wm_agent_upgrade_validate_agent_task_agent_id_err(void **state)
{
    (void) state;

    int agent = 44;
    int keep_alive = 2345678;
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    agent_task->agent_info->agent_id = agent;
    agent_task->agent_info->last_keep_alive = keep_alive;
    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_INVALID_ACTION_FOR_MANAGER);

    int ret = wm_agent_upgrade_validate_agent_task(agent_task, config);

    assert_int_equal(ret, WM_UPGRADE_INVALID_ACTION_FOR_MANAGER);
}

void test_wm_agent_upgrade_analyze_agent_ok(void **state)
{
    (void) state;

    wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
    int agent = 119;
    int keep_alive = 123456789;
    char *platform = "ubuntu";
    char *major = "18";
    char *minor = "04";
    char *arch = "x86_64";
    char *version = "v3.13.1";
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    cJSON *request_status = cJSON_CreateArray();

    cJSON *status_request = cJSON_CreateObject();

    cJSON_AddStringToObject(status_request, "module", "upgrade_module");
    cJSON_AddStringToObject(status_request, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(status_request, "agent", agent);

    cJSON_AddItemToArray(request_status, status_request);

    cJSON *status_response = cJSON_CreateObject();

    cJSON_AddStringToObject(status_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(status_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(status_response, "agent", agent);

    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade");
    cJSON_AddNumberToObject(task_request, "agent", agent);

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agent);
    will_return(__wrap_wdb_agent_info, platform);
    will_return(__wrap_wdb_agent_info, major);
    will_return(__wrap_wdb_agent_info, minor);
    will_return(__wrap_wdb_agent_info, arch);
    will_return(__wrap_wdb_agent_info, version);
    will_return(__wrap_wdb_agent_info, keep_alive);
    will_return(__wrap_wdb_agent_info, 0);

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request_status);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, status_request, sizeof(status_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, status_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, status_response, sizeof(status_response));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "Done");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_create_task_entry
    expect_value(__wrap_wm_agent_upgrade_create_task_entry, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_create_task_entry, OSHASH_SUCCESS);

    // wm_agent_upgrade_parse_task_module_request
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, agent_task->task_info->command);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, task_request);

    cJSON *json = wm_agent_upgrade_analyze_agent(agent, agent_task, &error_code, config);

    assert_non_null(json);
    assert_memory_equal(json, task_request, sizeof(json));
    assert_int_equal(error_code, WM_UPGRADE_SUCCESS);
    assert_non_null(agent_task->agent_info);
    assert_string_equal(agent_task->agent_info->platform, platform);
    assert_string_equal(agent_task->agent_info->major_version, major);
    assert_string_equal(agent_task->agent_info->minor_version, minor);
    assert_string_equal(agent_task->agent_info->architecture, arch);
    assert_string_equal(agent_task->agent_info->wazuh_version, version);
    assert_int_equal(agent_task->agent_info->last_keep_alive, keep_alive);

    cJSON_Delete(json);
}

void test_wm_agent_upgrade_analyze_agent_duplicated_err(void **state)
{
    (void) state;

    wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
    int agent = 120;
    int keep_alive = 123456789;
    char *platform = "ubuntu";
    char *major = "18";
    char *minor = "04";
    char *arch = "x86_64";
    char *version = "v3.13.1";
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    cJSON *request_status = cJSON_CreateArray();

    cJSON *status_request = cJSON_CreateObject();

    cJSON_AddStringToObject(status_request, "module", "upgrade_module");
    cJSON_AddStringToObject(status_request, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(status_request, "agent", agent);

    cJSON_AddItemToArray(request_status, status_request);

    cJSON *status_response = cJSON_CreateObject();

    cJSON_AddStringToObject(status_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(status_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(status_response, "agent", agent);

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agent);
    will_return(__wrap_wdb_agent_info, platform);
    will_return(__wrap_wdb_agent_info, major);
    will_return(__wrap_wdb_agent_info, minor);
    will_return(__wrap_wdb_agent_info, arch);
    will_return(__wrap_wdb_agent_info, version);
    will_return(__wrap_wdb_agent_info, keep_alive);
    will_return(__wrap_wdb_agent_info, 0);

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request_status);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, status_request, sizeof(status_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, status_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, status_response, sizeof(status_response));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "Done");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_create_task_entry
    expect_value(__wrap_wm_agent_upgrade_create_task_entry, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_create_task_entry, OSHASH_DUPLICATE);

    cJSON *json = wm_agent_upgrade_analyze_agent(agent, agent_task, &error_code, config);

    assert_null(json);
    assert_int_equal(error_code, WM_UPGRADE_UPGRADE_ALREADY_IN_PROGRESS);
    assert_non_null(agent_task->agent_info);
    assert_string_equal(agent_task->agent_info->platform, platform);
    assert_string_equal(agent_task->agent_info->major_version, major);
    assert_string_equal(agent_task->agent_info->minor_version, minor);
    assert_string_equal(agent_task->agent_info->architecture, arch);
    assert_string_equal(agent_task->agent_info->wazuh_version, version);
    assert_int_equal(agent_task->agent_info->last_keep_alive, keep_alive);
}

void test_wm_agent_upgrade_analyze_agent_unknown_err(void **state)
{
    (void) state;

    wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
    int agent = 121;
    int keep_alive = 123456789;
    char *platform = "ubuntu";
    char *major = "18";
    char *minor = "04";
    char *arch = "x86_64";
    char *version = "v3.13.1";
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    cJSON *request_status = cJSON_CreateArray();

    cJSON *status_request = cJSON_CreateObject();

    cJSON_AddStringToObject(status_request, "module", "upgrade_module");
    cJSON_AddStringToObject(status_request, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(status_request, "agent", agent);

    cJSON_AddItemToArray(request_status, status_request);

    cJSON *status_response = cJSON_CreateObject();

    cJSON_AddStringToObject(status_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(status_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(status_response, "agent", agent);

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agent);
    will_return(__wrap_wdb_agent_info, platform);
    will_return(__wrap_wdb_agent_info, major);
    will_return(__wrap_wdb_agent_info, minor);
    will_return(__wrap_wdb_agent_info, arch);
    will_return(__wrap_wdb_agent_info, version);
    will_return(__wrap_wdb_agent_info, keep_alive);
    will_return(__wrap_wdb_agent_info, 0);

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, keep_alive);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, agent_task->task_info->command);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, "");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request_status);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, status_request, sizeof(status_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, status_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, status_response, sizeof(status_response));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "Done");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_create_task_entry
    expect_value(__wrap_wm_agent_upgrade_create_task_entry, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_create_task_entry, OS_INVALID);

    cJSON *json = wm_agent_upgrade_analyze_agent(agent, agent_task, &error_code, config);

    assert_null(json);
    assert_int_equal(error_code, WM_UPGRADE_UNKNOWN_ERROR);
    assert_non_null(agent_task->agent_info);
    assert_string_equal(agent_task->agent_info->platform, platform);
    assert_string_equal(agent_task->agent_info->major_version, major);
    assert_string_equal(agent_task->agent_info->minor_version, minor);
    assert_string_equal(agent_task->agent_info->architecture, arch);
    assert_string_equal(agent_task->agent_info->wazuh_version, version);
    assert_int_equal(agent_task->agent_info->last_keep_alive, keep_alive);
}

void test_wm_agent_upgrade_analyze_agent_validate_err(void **state)
{
    (void) state;

    wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
    int agent = 119;
    int keep_alive = 123456789;
    char *platform = "ubuntu";
    char *major = "18";
    char *minor = "04";
    char *arch = "x86_64";
    char *version = "v3.13.1";
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agent);
    will_return(__wrap_wdb_agent_info, platform);
    will_return(__wrap_wdb_agent_info, major);
    will_return(__wrap_wdb_agent_info, minor);
    will_return(__wrap_wdb_agent_info, arch);
    will_return(__wrap_wdb_agent_info, version);
    will_return(__wrap_wdb_agent_info, keep_alive);
    will_return(__wrap_wdb_agent_info, 0);

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agent);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_INVALID_ACTION_FOR_MANAGER);

    cJSON *json = wm_agent_upgrade_analyze_agent(agent, agent_task, &error_code, config);

    assert_null(json);
    assert_int_equal(error_code, WM_UPGRADE_INVALID_ACTION_FOR_MANAGER);
    assert_non_null(agent_task->agent_info);
    assert_string_equal(agent_task->agent_info->platform, platform);
    assert_string_equal(agent_task->agent_info->major_version, major);
    assert_string_equal(agent_task->agent_info->minor_version, minor);
    assert_string_equal(agent_task->agent_info->architecture, arch);
    assert_string_equal(agent_task->agent_info->wazuh_version, version);
    assert_int_equal(agent_task->agent_info->last_keep_alive, keep_alive);
}

void test_wm_agent_upgrade_analyze_agent_global_db_err(void **state)
{
    (void) state;

    wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
    int agent = 119;
    int keep_alive = 123456789;
    char *platform = "ubuntu";
    char *major = "18";
    char *minor = "04";
    char *arch = "x86_64";
    char *version = "v3.13.1";
    wm_upgrade_task *upgrade_task = NULL;

    wm_manager_configs *config = state[0];
    wm_agent_task *agent_task = state[1];

    config->chunk_size = 5;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();
    agent_task->task_info->command = WM_UPGRADE_UPGRADE;
    agent_task->task_info->task = upgrade_task;

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agent);
    will_return(__wrap_wdb_agent_info, platform);
    will_return(__wrap_wdb_agent_info, major);
    will_return(__wrap_wdb_agent_info, minor);
    will_return(__wrap_wdb_agent_info, arch);
    will_return(__wrap_wdb_agent_info, version);
    will_return(__wrap_wdb_agent_info, keep_alive);
    will_return(__wrap_wdb_agent_info, OS_INVALID);

    cJSON *json = wm_agent_upgrade_analyze_agent(agent, agent_task, &error_code, config);

    assert_null(json);
    assert_int_equal(error_code, WM_UPGRADE_GLOBAL_DB_FAILURE);
    assert_non_null(agent_task->agent_info);
    assert_string_equal(agent_task->agent_info->platform, platform);
    assert_string_equal(agent_task->agent_info->major_version, major);
    assert_string_equal(agent_task->agent_info->minor_version, minor);
    assert_string_equal(agent_task->agent_info->architecture, arch);
    assert_string_equal(agent_task->agent_info->wazuh_version, version);
    assert_int_equal(agent_task->agent_info->last_keep_alive, keep_alive);
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

    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade_update_status");
    cJSON_AddNumberToObject(task_request, "agent", agents[0]);
    cJSON_AddStringToObject(task_request, "status", agent_status);

    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddNumberToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agents[0]);
    cJSON_AddStringToObject(task_response, "status", agent_status);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtinfo, formatted_msg, "(8164): Received upgrade notification from agent '25'. Error code: '0', message: 'Success'");

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_UPDATE_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agents[0]);
    expect_string(__wrap_wm_agent_upgrade_parse_task_module_request, status, agent_status);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, task_request);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    char *result = wm_agent_upgrade_process_agent_result_command(agents, upgrade_agent_status_task);

    state[1] = (void *)result;

    assert_non_null(result);
    assert_string_equal(result, "[{\"error\":0,\"data\":\"Success.\",\"agent\":25,\"status\":\"Done\"}]");
}

void test_wm_agent_upgrade_process_agent_result_command_failed(void **state)
{
    (void) state;

    int agents[2];
    wm_upgrade_agent_status_task *upgrade_agent_status_task = NULL;
    char *agent_status = "Failed";
    char *agent_error = "Upgrade procedure exited with error code.";

    agents[0] = 25;
    agents[1] = OS_INVALID;

    upgrade_agent_status_task = wm_agent_upgrade_init_agent_status_task();
    upgrade_agent_status_task->error_code = 2;
    os_strdup("Error message", upgrade_agent_status_task->message);
    os_strdup(agent_status, upgrade_agent_status_task->status);

    state[0] = (void *)upgrade_agent_status_task;

    cJSON *task_request = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request, "command", "upgrade_update_status");
    cJSON_AddNumberToObject(task_request, "agent", agents[0]);
    cJSON_AddStringToObject(task_request, "status", agent_status);
    cJSON_AddStringToObject(task_request, "error_msg", agent_error);

    cJSON *task_response = cJSON_CreateObject();

    cJSON_AddNumberToObject(task_response, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response, "agent", agents[0]);
    cJSON_AddStringToObject(task_response, "status", agent_status);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtinfo, formatted_msg, "(8164): Received upgrade notification from agent '25'. Error code: '2', message: 'Error message'");

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_UPDATE_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agents[0]);
    expect_string(__wrap_wm_agent_upgrade_parse_task_module_request, status, agent_status);
    expect_string(__wrap_wm_agent_upgrade_parse_task_module_request, error, agent_error);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, task_request);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request, sizeof(task_request));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    char *result = wm_agent_upgrade_process_agent_result_command(agents, upgrade_agent_status_task);

    state[1] = (void *)result;

    assert_non_null(result);
    assert_string_equal(result, "[{\"error\":0,\"data\":\"Success.\",\"agent\":25,\"status\":\"Failed\"}]");
}

void test_wm_agent_upgrade_process_upgrade_custom_command(void **state)
{
    (void) state;

    int agents[3];
    wm_manager_configs *config = NULL;
    wm_upgrade_custom_task *upgrade_custom_task = NULL;

    char *custom_file_path = "/tmp/test.wpk";
    char *custom_installer = "test.sh";

    agents[0] = 1;
    agents[1] = 2;
    agents[2] = OS_INVALID;

    os_calloc(1, sizeof(wm_manager_configs), config);
    config->chunk_size = 5;

    upgrade_custom_task = wm_agent_upgrade_init_upgrade_custom_task();
    os_strdup(custom_file_path, upgrade_custom_task->custom_file_path);
    os_strdup(custom_installer, upgrade_custom_task->custom_installer);

    state[0] = (void *)upgrade_custom_task;

    cJSON *task_request1 = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request1, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request1, "command", "upgrade_custom");
    cJSON_AddNumberToObject(task_request1, "agent", agents[0]);

    cJSON *request_status1 = cJSON_CreateArray();

    cJSON *status_request1 = cJSON_CreateObject();

    cJSON_AddStringToObject(status_request1, "module", "upgrade_module");
    cJSON_AddStringToObject(status_request1, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(status_request1, "agent", agents[0]);

    cJSON_AddItemToArray(request_status1, status_request1);

    cJSON *status_response1 = cJSON_CreateObject();

    cJSON_AddNumberToObject(status_response1, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(status_response1, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(status_response1, "agent", agents[0]);
    cJSON_AddStringToObject(status_response1, "status", "Done");

    cJSON *task_response1 = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response1, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response1, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response1, "agent", agents[0]);
    cJSON_AddNumberToObject(task_response1, "task_id", 100);

    cJSON *task_response2 = cJSON_CreateObject();

    cJSON_AddNumberToObject(task_response2, "error", WM_UPGRADE_GLOBAL_DB_FAILURE);
    cJSON_AddStringToObject(task_response2, "data", upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    cJSON_AddNumberToObject(task_response2, "agent", agents[1]);

    // Analize agent[0]

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agents[0]);
    will_return(__wrap_wdb_agent_info, "ubuntu");
    will_return(__wrap_wdb_agent_info, "18");
    will_return(__wrap_wdb_agent_info, "04");
    will_return(__wrap_wdb_agent_info, "x86_64");
    will_return(__wrap_wdb_agent_info, "v3.13.1");
    will_return(__wrap_wdb_agent_info, 123456789);
    will_return(__wrap_wdb_agent_info, 0);

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, 123456789);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, WM_UPGRADE_UPGRADE_CUSTOM);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request_status1);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, status_request1, sizeof(status_request1));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, status_response1);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, status_response1, sizeof(status_response1));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "Done");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_create_task_entry
    expect_value(__wrap_wm_agent_upgrade_create_task_entry, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_create_task_entry, OSHASH_SUCCESS);

    // wm_agent_upgrade_parse_task_module_request
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_UPGRADE_CUSTOM);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, task_request1);

    // Analize agent[1]

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agents[1]);
    will_return(__wrap_wdb_agent_info, "ubuntu");
    will_return(__wrap_wdb_agent_info, "16");
    will_return(__wrap_wdb_agent_info, "04");
    will_return(__wrap_wdb_agent_info, "x86");
    will_return(__wrap_wdb_agent_info, "v3.5.0");
    will_return(__wrap_wdb_agent_info, 234567890);
    will_return(__wrap_wdb_agent_info, OS_INVALID);

    expect_value(__wrap_wm_agent_upgrade_parse_response_message, error_id, WM_UPGRADE_GLOBAL_DB_FAILURE);
    expect_string(__wrap_wm_agent_upgrade_parse_response_message, message, upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    expect_value(__wrap_wm_agent_upgrade_parse_response_message, agent_int, agents[1]);
    will_return(__wrap_wm_agent_upgrade_parse_response_message, task_response2);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request1, sizeof(task_request1));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response1);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_prepare_upgrades

    will_return(__wrap_wm_agent_upgrade_prepare_upgrades, 1);

    char *result = wm_agent_upgrade_process_upgrade_custom_command(agents, upgrade_custom_task, config);

    state[1] = (void *)result;

    assert_non_null(result);
    assert_string_equal(result, "[{\"error\":6,\"data\":\"Agent information not found in database.\",\"agent\":2},{\"data\":\"Success.\",\"agent\":1,\"task_id\":100}]");

    os_free(config);
}

void test_wm_agent_upgrade_process_upgrade_custom_command_no_agents(void **state)
{
    (void) state;

    int agents[3];
    wm_manager_configs *config = NULL;
    wm_upgrade_custom_task *upgrade_custom_task = NULL;

    char *custom_file_path = "/tmp/test.wpk";
    char *custom_installer = "test.sh";

    agents[0] = 1;
    agents[1] = 2;
    agents[2] = OS_INVALID;

    os_calloc(1, sizeof(wm_manager_configs), config);
    config->chunk_size = 5;

    upgrade_custom_task = wm_agent_upgrade_init_upgrade_custom_task();
    os_strdup(custom_file_path, upgrade_custom_task->custom_file_path);
    os_strdup(custom_installer, upgrade_custom_task->custom_installer);

    state[0] = (void *)upgrade_custom_task;

    cJSON *task_response1 = cJSON_CreateObject();

    cJSON_AddNumberToObject(task_response1, "error", WM_UPGRADE_GLOBAL_DB_FAILURE);
    cJSON_AddStringToObject(task_response1, "data", upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    cJSON_AddNumberToObject(task_response1, "agent", agents[0]);

    cJSON *task_response2 = cJSON_CreateObject();

    cJSON_AddNumberToObject(task_response2, "error", WM_UPGRADE_GLOBAL_DB_FAILURE);
    cJSON_AddStringToObject(task_response2, "data", upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    cJSON_AddNumberToObject(task_response2, "agent", agents[1]);

    // Analize agent[0]

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agents[0]);
    will_return(__wrap_wdb_agent_info, "ubuntu");
    will_return(__wrap_wdb_agent_info, "18");
    will_return(__wrap_wdb_agent_info, "04");
    will_return(__wrap_wdb_agent_info, "x86_64");
    will_return(__wrap_wdb_agent_info, "v3.13.1");
    will_return(__wrap_wdb_agent_info, 123456789);
    will_return(__wrap_wdb_agent_info, OS_INVALID);

    expect_value(__wrap_wm_agent_upgrade_parse_response_message, error_id, WM_UPGRADE_GLOBAL_DB_FAILURE);
    expect_string(__wrap_wm_agent_upgrade_parse_response_message, message, upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    expect_value(__wrap_wm_agent_upgrade_parse_response_message, agent_int, agents[0]);
    will_return(__wrap_wm_agent_upgrade_parse_response_message, task_response1);

    // Analize agent[1]

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agents[1]);
    will_return(__wrap_wdb_agent_info, "ubuntu");
    will_return(__wrap_wdb_agent_info, "16");
    will_return(__wrap_wdb_agent_info, "04");
    will_return(__wrap_wdb_agent_info, "x86");
    will_return(__wrap_wdb_agent_info, "v3.5.0");
    will_return(__wrap_wdb_agent_info, 234567890);
    will_return(__wrap_wdb_agent_info, OS_INVALID);

    expect_value(__wrap_wm_agent_upgrade_parse_response_message, error_id, WM_UPGRADE_GLOBAL_DB_FAILURE);
    expect_string(__wrap_wm_agent_upgrade_parse_response_message, message, upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    expect_value(__wrap_wm_agent_upgrade_parse_response_message, agent_int, agents[1]);
    will_return(__wrap_wm_agent_upgrade_parse_response_message, task_response2);

    // wm_agent_upgrade_task_module_callback

    will_return(__wrap_wm_agent_upgrade_task_module_callback, OS_INVALID);

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtwarn, formatted_msg, "(8160): There are no valid agents to upgrade.");

    char *result = wm_agent_upgrade_process_upgrade_custom_command(agents, upgrade_custom_task, config);

    state[1] = (void *)result;

    assert_non_null(result);
    assert_string_equal(result, "[{\"error\":6,\"data\":\"Agent information not found in database.\",\"agent\":1},{\"error\":6,\"data\":\"Agent information not found in database.\",\"agent\":2}]");

    os_free(config);
}

void test_wm_agent_upgrade_process_upgrade_command(void **state)
{
    (void) state;

    int agents[3];
    wm_manager_configs *config = NULL;
    wm_upgrade_task *upgrade_task = NULL;

    agents[0] = 1;
    agents[1] = 2;
    agents[2] = OS_INVALID;

    os_calloc(1, sizeof(wm_manager_configs), config);
    config->chunk_size = 5;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();

    state[0] = (void *)upgrade_task;

    cJSON *task_request1 = cJSON_CreateObject();

    cJSON_AddStringToObject(task_request1, "module", "upgrade_module");
    cJSON_AddStringToObject(task_request1, "command", "upgrade");
    cJSON_AddNumberToObject(task_request1, "agent", agents[0]);

    cJSON *request_status1 = cJSON_CreateArray();

    cJSON *status_request1 = cJSON_CreateObject();

    cJSON_AddStringToObject(status_request1, "module", "upgrade_module");
    cJSON_AddStringToObject(status_request1, "command", "upgrade_get_status");
    cJSON_AddNumberToObject(status_request1, "agent", agents[0]);

    cJSON_AddItemToArray(request_status1, status_request1);

    cJSON *status_response1 = cJSON_CreateObject();

    cJSON_AddNumberToObject(status_response1, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(status_response1, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(status_response1, "agent", agents[0]);
    cJSON_AddStringToObject(status_response1, "status", "Done");

    cJSON *task_response1 = cJSON_CreateObject();

    cJSON_AddStringToObject(task_response1, "error", WM_UPGRADE_SUCCESS);
    cJSON_AddStringToObject(task_response1, "data", upgrade_error_codes[WM_UPGRADE_SUCCESS]);
    cJSON_AddNumberToObject(task_response1, "agent", agents[0]);
    cJSON_AddNumberToObject(task_response1, "task_id", 110);

    cJSON *task_response2 = cJSON_CreateObject();

    cJSON_AddNumberToObject(task_response2, "error", WM_UPGRADE_GLOBAL_DB_FAILURE);
    cJSON_AddStringToObject(task_response2, "data", upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    cJSON_AddNumberToObject(task_response2, "agent", agents[1]);

    // Analize agent[0]

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agents[0]);
    will_return(__wrap_wdb_agent_info, "ubuntu");
    will_return(__wrap_wdb_agent_info, "18");
    will_return(__wrap_wdb_agent_info, "04");
    will_return(__wrap_wdb_agent_info, "x86_64");
    will_return(__wrap_wdb_agent_info, "v3.13.1");
    will_return(__wrap_wdb_agent_info, 123456789);
    will_return(__wrap_wdb_agent_info, 0);

    // wm_agent_upgrade_validate_id

    expect_value(__wrap_wm_agent_upgrade_validate_id, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_validate_id, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_status

    expect_value(__wrap_wm_agent_upgrade_validate_status, last_keep_alive, 123456789);
    will_return(__wrap_wm_agent_upgrade_validate_status, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_validate_version
    expect_value(__wrap_wm_agent_upgrade_validate_version, command, WM_UPGRADE_UPGRADE);
    expect_memory(__wrap_wm_agent_upgrade_validate_version, manager_configs, config, sizeof(config));
    will_return(__wrap_wm_agent_upgrade_validate_version, "test.wpk");
    will_return(__wrap_wm_agent_upgrade_validate_version, "d321af65983fa412e3a12c312ada12ab321a253a");
    will_return(__wrap_wm_agent_upgrade_validate_version, WM_UPGRADE_SUCCESS);

    // wm_agent_upgrade_parse_task_module_request

    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_AGENT_GET_STATUS);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, request_status1);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, status_request1, sizeof(status_request1));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, status_response1);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_validate_task_status_message

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, status_response1, sizeof(status_response1));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, "Done");
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    // wm_agent_upgrade_create_task_entry
    expect_value(__wrap_wm_agent_upgrade_create_task_entry, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_create_task_entry, OSHASH_SUCCESS);

    // wm_agent_upgrade_parse_task_module_request
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, command, WM_UPGRADE_UPGRADE);
    expect_value(__wrap_wm_agent_upgrade_parse_task_module_request, agent_id, agents[0]);
    will_return(__wrap_wm_agent_upgrade_parse_task_module_request, task_request1);

    // Analize agent[1]

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agents[1]);
    will_return(__wrap_wdb_agent_info, "ubuntu");
    will_return(__wrap_wdb_agent_info, "16");
    will_return(__wrap_wdb_agent_info, "04");
    will_return(__wrap_wdb_agent_info, "x86");
    will_return(__wrap_wdb_agent_info, "v3.5.0");
    will_return(__wrap_wdb_agent_info, 234567890);
    will_return(__wrap_wdb_agent_info, OS_INVALID);

    expect_value(__wrap_wm_agent_upgrade_parse_response_message, error_id, WM_UPGRADE_GLOBAL_DB_FAILURE);
    expect_string(__wrap_wm_agent_upgrade_parse_response_message, message, upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    expect_value(__wrap_wm_agent_upgrade_parse_response_message, agent_int, agents[1]);
    will_return(__wrap_wm_agent_upgrade_parse_response_message, task_response2);

    // wm_agent_upgrade_task_module_callback

    expect_memory(__wrap_wm_agent_upgrade_task_module_callback, json, task_request1, sizeof(task_request1));
    will_return(__wrap_wm_agent_upgrade_task_module_callback, task_response1);
    will_return(__wrap_wm_agent_upgrade_task_module_callback, 0);

    // wm_agent_upgrade_prepare_upgrades

    will_return(__wrap_wm_agent_upgrade_prepare_upgrades, 1);

    char *result = wm_agent_upgrade_process_upgrade_command(agents, upgrade_task, config);

    state[1] = (void *)result;

    assert_non_null(result);
    assert_string_equal(result, "[{\"error\":6,\"data\":\"Agent information not found in database.\",\"agent\":2},{\"data\":\"Success.\",\"agent\":1,\"task_id\":110}]");

    os_free(config);
}

void test_wm_agent_upgrade_process_upgrade_command_no_agents(void **state)
{
    (void) state;

    int agents[3];
    wm_manager_configs *config = NULL;
    wm_upgrade_task *upgrade_task = NULL;

    agents[0] = 1;
    agents[1] = 2;
    agents[2] = OS_INVALID;

    os_calloc(1, sizeof(wm_manager_configs), config);
    config->chunk_size = 5;

    upgrade_task = wm_agent_upgrade_init_upgrade_task();

    state[0] = (void *)upgrade_task;

    cJSON *task_response1 = cJSON_CreateObject();

    cJSON_AddNumberToObject(task_response1, "error", WM_UPGRADE_GLOBAL_DB_FAILURE);
    cJSON_AddStringToObject(task_response1, "data", upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    cJSON_AddNumberToObject(task_response1, "agent", agents[0]);

    cJSON *task_response2 = cJSON_CreateObject();

    cJSON_AddNumberToObject(task_response2, "error", WM_UPGRADE_GLOBAL_DB_FAILURE);
    cJSON_AddStringToObject(task_response2, "data", upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    cJSON_AddNumberToObject(task_response2, "agent", agents[1]);

    // Analize agent[0]

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agents[0]);
    will_return(__wrap_wdb_agent_info, "ubuntu");
    will_return(__wrap_wdb_agent_info, "18");
    will_return(__wrap_wdb_agent_info, "04");
    will_return(__wrap_wdb_agent_info, "x86_64");
    will_return(__wrap_wdb_agent_info, "v3.13.1");
    will_return(__wrap_wdb_agent_info, 123456789);
    will_return(__wrap_wdb_agent_info, OS_INVALID);

    expect_value(__wrap_wm_agent_upgrade_parse_response_message, error_id, WM_UPGRADE_GLOBAL_DB_FAILURE);
    expect_string(__wrap_wm_agent_upgrade_parse_response_message, message, upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    expect_value(__wrap_wm_agent_upgrade_parse_response_message, agent_int, agents[0]);
    will_return(__wrap_wm_agent_upgrade_parse_response_message, task_response1);

    // Analize agent[1]

    // wdb_agent_info

    expect_value(__wrap_wdb_agent_info, id, agents[1]);
    will_return(__wrap_wdb_agent_info, "ubuntu");
    will_return(__wrap_wdb_agent_info, "16");
    will_return(__wrap_wdb_agent_info, "04");
    will_return(__wrap_wdb_agent_info, "x86");
    will_return(__wrap_wdb_agent_info, "v3.5.0");
    will_return(__wrap_wdb_agent_info, 234567890);
    will_return(__wrap_wdb_agent_info, OS_INVALID);

    expect_value(__wrap_wm_agent_upgrade_parse_response_message, error_id, WM_UPGRADE_GLOBAL_DB_FAILURE);
    expect_string(__wrap_wm_agent_upgrade_parse_response_message, message, upgrade_error_codes[WM_UPGRADE_GLOBAL_DB_FAILURE]);
    expect_value(__wrap_wm_agent_upgrade_parse_response_message, agent_int, agents[1]);
    will_return(__wrap_wm_agent_upgrade_parse_response_message, task_response2);

    // wm_agent_upgrade_task_module_callback

    will_return(__wrap_wm_agent_upgrade_task_module_callback, OS_INVALID);

    expect_string(__wrap__mtwarn, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtwarn, formatted_msg, "(8160): There are no valid agents to upgrade.");

    char *result = wm_agent_upgrade_process_upgrade_command(agents, upgrade_task, config);

    state[1] = (void *)result;

    assert_non_null(result);
    assert_string_equal(result, "[{\"error\":6,\"data\":\"Agent information not found in database.\",\"agent\":1},{\"error\":6,\"data\":\"Agent information not found in database.\",\"agent\":2}]");

    os_free(config);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_agent_upgrade_validate_agent_task
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_upgrade_ok, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_upgrade_custom_ok, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_in_progress_err, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_task_manager_err, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_version_err, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_status_err, setup_config_agent_task, teardown_config_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_validate_agent_task_agent_id_err, setup_config_agent_task, teardown_config_agent_task),
        // wm_agent_upgrade_analyze_agent
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_analyze_agent_ok, setup_analyze_agent_task, teardown_analyze_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_analyze_agent_duplicated_err, setup_analyze_agent_task, teardown_analyze_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_analyze_agent_unknown_err, setup_analyze_agent_task, teardown_analyze_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_analyze_agent_validate_err, setup_analyze_agent_task, teardown_analyze_agent_task),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_analyze_agent_global_db_err, setup_analyze_agent_task, teardown_analyze_agent_task),
        // wm_agent_upgrade_process_agent_result_command
        cmocka_unit_test_teardown(test_wm_agent_upgrade_process_agent_result_command_done, teardown_agent_status_task_string),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_process_agent_result_command_failed, teardown_agent_status_task_string),
        // wm_agent_upgrade_process_upgrade_custom_command
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_upgrade_custom_command, setup_process_hash_table, teardown_upgrade_custom_task_string),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_upgrade_custom_command_no_agents, setup_process_hash_table, teardown_upgrade_custom_task_string),
        // wm_agent_upgrade_process_upgrade_command
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_upgrade_command, setup_process_hash_table, teardown_upgrade_task_string),
        cmocka_unit_test_setup_teardown(test_wm_agent_upgrade_process_upgrade_command_no_agents, setup_process_hash_table, teardown_upgrade_task_string)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
