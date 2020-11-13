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

#include "../../wrappers/wazuh/wazuh_modules/wm_task_manager_wrappers.h"

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/task_manager/wm_task_manager.h"
#include "../../wazuh_modules/task_manager/wm_task_manager_tasks.h"
#include "../../headers/shared.h"

cJSON* wm_task_manager_command_upgrade(wm_task_manager_upgrade *task, int command, int *error_code);
cJSON* wm_task_manager_command_upgrade_get_status(wm_task_manager_upgrade_get_status *task, int *error_code);
cJSON* wm_task_manager_command_upgrade_update_status(wm_task_manager_upgrade_update_status *task, int *error_code);
cJSON* wm_task_manager_command_upgrade_result(wm_task_manager_upgrade_result *task, int *error_code);
cJSON* wm_task_manager_command_upgrade_cancel_tasks(wm_task_manager_upgrade_cancel_tasks *task, int *error_code);
cJSON* wm_task_manager_command_task_result(wm_task_manager_task_result *task, int *error_code);

// Setup / teardown

static int teardown_json_task(void **state) {
    if (state[0]) {
        cJSON *json = state[0];
        cJSON_Delete(json);
    }
    if (state[1]) {
        wm_task_manager_task *task = (wm_task_manager_task*)state[1];
        wm_task_manager_free_task(task);
    }
    return 0;
}

static int teardown_json_upgrade_task(void **state) {
    if (state[0]) {
        cJSON *json = state[0];
        cJSON_Delete(json);
    }
    if (state[1]) {
        wm_task_manager_upgrade *task = (wm_task_manager_upgrade*)state[1];
        wm_task_manager_free_upgrade_parameters(task);
    }
    return 0;
}

static int teardown_json_upgrade_get_status_task(void **state) {
    if (state[0]) {
        cJSON *json = state[0];
        cJSON_Delete(json);
    }
    if (state[1]) {
        wm_task_manager_upgrade_get_status *task = (wm_task_manager_upgrade_get_status*)state[1];
        wm_task_manager_free_upgrade_get_status_parameters(task);
    }
    return 0;
}

static int teardown_json_upgrade_update_status_task(void **state) {
    if (state[0]) {
        cJSON *json = state[0];
        cJSON_Delete(json);
    }
    if (state[1]) {
        wm_task_manager_upgrade_update_status *task = (wm_task_manager_upgrade_update_status*)state[1];
        wm_task_manager_free_upgrade_update_status_parameters(task);
    }
    return 0;
}

static int teardown_json_upgrade_result_task(void **state) {
    if (state[0]) {
        cJSON *json = state[0];
        cJSON_Delete(json);
    }
    if (state[1]) {
        wm_task_manager_upgrade_result *task = (wm_task_manager_upgrade_result*)state[1];
        wm_task_manager_free_upgrade_result_parameters(task);
    }
    return 0;
}

static int teardown_json_upgrade_cancel_tasks_task(void **state) {
    if (state[0]) {
        cJSON *json = state[0];
        cJSON_Delete(json);
    }
    if (state[1]) {
        wm_task_manager_upgrade_cancel_tasks *task = (wm_task_manager_upgrade_cancel_tasks*)state[1];
        wm_task_manager_free_upgrade_cancel_tasks_parameters(task);
    }
    return 0;
}

static int teardown_json_task_result_task(void **state) {
    if (state[0]) {
        cJSON *json = state[0];
        cJSON_Delete(json);
    }
    if (state[1]) {
        wm_task_manager_task_result *task = (wm_task_manager_task_result*)state[1];
        wm_task_manager_free_task_result_parameters(task);
    }
    return 0;
}

// Tests

void test_wm_task_manager_command_upgrade_ok(void **state)
{
    char *node = "node02";
    char *module = "upgrade_module";
    char *command = "upgrade";
    int error_code = 0;
    int agent_id = 35;
    int task_id = 24;

    wm_task_manager_upgrade *task_parameters = wm_task_manager_init_upgrade_parameters();
    int *agents = NULL;

    os_calloc(2, sizeof(int), agents);
    agents[0] = agent_id;
    agents[1] = OS_INVALID;

    os_strdup(node, task_parameters->node);
    os_strdup(module, task_parameters->module);
    task_parameters->agent_ids = agents;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_insert_task, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_insert_task, node, node);
    expect_string(__wrap_wm_task_manager_insert_task, module, module);
    expect_string(__wrap_wm_task_manager_insert_task, command, command);
    will_return(__wrap_wm_task_manager_insert_task, task_id);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade(task_parameters, WM_TASK_UPGRADE, &error_code);

    state[0] = response;
    state[1] = task_parameters;

    assert_non_null(response);
    assert_int_equal(cJSON_GetArraySize(response), 1);
    assert_memory_equal(cJSON_GetArrayItem(response, 0), res, sizeof(res));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_command_upgrade_custom_ok(void **state)
{
    char *node = "node02";
    char *module = "upgrade_module";
    char *command = "upgrade_custom";
    int error_code = 0;
    int agent_id = 35;
    int task_id = 24;

    wm_task_manager_upgrade *task_parameters = wm_task_manager_init_upgrade_parameters();
    int *agents = NULL;

    os_calloc(2, sizeof(int), agents);
    agents[0] = agent_id;
    agents[1] = OS_INVALID;

    os_strdup(node, task_parameters->node);
    os_strdup(module, task_parameters->module);
    task_parameters->agent_ids = agents;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_insert_task, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_insert_task, node, node);
    expect_string(__wrap_wm_task_manager_insert_task, module, module);
    expect_string(__wrap_wm_task_manager_insert_task, command, command);
    will_return(__wrap_wm_task_manager_insert_task, task_id);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade(task_parameters, WM_TASK_UPGRADE_CUSTOM, &error_code);

    state[0] = response;
    state[1] = task_parameters;

    assert_non_null(response);
    assert_int_equal(cJSON_GetArraySize(response), 1);
    assert_memory_equal(cJSON_GetArrayItem(response, 0), res, sizeof(res));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_command_upgrade_db_err(void **state)
{
    char *node = "node02";
    char *module = "upgrade_module";
    char *command = "upgrade";
    int error_code = 0;
    int agent_id = 35;
    int task_id = OS_INVALID;

    wm_task_manager_upgrade *task_parameters = wm_task_manager_init_upgrade_parameters();
    int *agents = NULL;

    os_calloc(2, sizeof(int), agents);
    agents[0] = agent_id;
    agents[1] = OS_INVALID;

    os_strdup(node, task_parameters->node);
    os_strdup(module, task_parameters->module);
    task_parameters->agent_ids = agents;

    expect_value(__wrap_wm_task_manager_insert_task, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_insert_task, node, node);
    expect_string(__wrap_wm_task_manager_insert_task, module, module);
    expect_string(__wrap_wm_task_manager_insert_task, command, command);
    will_return(__wrap_wm_task_manager_insert_task, task_id);

    state[0] = NULL;
    state[1] = task_parameters;

    cJSON *response = wm_task_manager_command_upgrade(task_parameters, WM_TASK_UPGRADE, &error_code);

    assert_int_equal(error_code, WM_TASK_DATABASE_ERROR);
}

void test_wm_task_manager_command_upgrade_get_status_ok(void **state)
{
    char *node = "node02";
    int error_code = 0;
    int agent_id = 35;

    char *status_result = "In progress";

    wm_task_manager_upgrade_get_status *task_parameters = wm_task_manager_init_upgrade_get_status_parameters();
    int *agents = NULL;

    os_calloc(2, sizeof(int), agents);
    agents[0] = agent_id;
    agents[1] = OS_INVALID;

    os_strdup(node, task_parameters->node);
    task_parameters->agent_ids = agents;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_get_upgrade_task_status, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_get_upgrade_task_status, node, node);
    will_return(__wrap_wm_task_manager_get_upgrade_task_status, status_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_status, WM_TASK_SUCCESS);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    expect_string(__wrap_wm_task_manager_parse_data_response, status, status_result);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade_get_status(task_parameters, &error_code);

    state[0] = response;
    state[1] = task_parameters;

    assert_non_null(response);
    assert_int_equal(cJSON_GetArraySize(response), 1);
    assert_memory_equal(cJSON_GetArrayItem(response, 0), res, sizeof(res));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_command_upgrade_get_status_task_err(void **state)
{
    char *node = "node02";
    int error_code = 0;
    int agent_id = 35;

    char *status_result = "In progress";

    wm_task_manager_upgrade_get_status *task_parameters = wm_task_manager_init_upgrade_get_status_parameters();
    int *agents = NULL;

    os_calloc(2, sizeof(int), agents);
    agents[0] = agent_id;
    agents[1] = OS_INVALID;

    os_strdup(node, task_parameters->node);
    task_parameters->agent_ids = agents;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_get_upgrade_task_status, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_get_upgrade_task_status, node, node);
    will_return(__wrap_wm_task_manager_get_upgrade_task_status, status_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_status, WM_TASK_DATABASE_NO_TASK);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_DATABASE_NO_TASK);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    expect_string(__wrap_wm_task_manager_parse_data_response, status, status_result);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade_get_status(task_parameters, &error_code);

    state[0] = response;
    state[1] = task_parameters;

    assert_non_null(response);
    assert_int_equal(cJSON_GetArraySize(response), 1);
    assert_memory_equal(cJSON_GetArrayItem(response, 0), res, sizeof(res));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_command_upgrade_get_status_db_err(void **state)
{
    char *node = "node02";
    int error_code = 0;
    int agent_id = 35;

    char *status_result = "In progress";

    wm_task_manager_upgrade_get_status *task_parameters = wm_task_manager_init_upgrade_get_status_parameters();
    int *agents = NULL;

    os_calloc(2, sizeof(int), agents);
    agents[0] = agent_id;
    agents[1] = OS_INVALID;

    os_strdup(node, task_parameters->node);
    task_parameters->agent_ids = agents;

    expect_value(__wrap_wm_task_manager_get_upgrade_task_status, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_get_upgrade_task_status, node, node);
    will_return(__wrap_wm_task_manager_get_upgrade_task_status, status_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_status, OS_INVALID);

    state[0] = NULL;
    state[1] = task_parameters;

    cJSON *response = wm_task_manager_command_upgrade_get_status(task_parameters, &error_code);

    assert_int_equal(error_code, WM_TASK_DATABASE_ERROR);
}

void test_wm_task_manager_command_upgrade_update_status_ok(void **state)
{
    char *node = "node02";
    int error_code = 0;
    int agent_id = 35;
    char *status = "Done";

    wm_task_manager_upgrade_update_status *task_parameters = wm_task_manager_init_upgrade_update_status_parameters();
    int *agents = NULL;

    os_calloc(2, sizeof(int), agents);
    agents[0] = agent_id;
    agents[1] = OS_INVALID;

    os_strdup(node, task_parameters->node);
    task_parameters->agent_ids = agents;
    os_strdup(status, task_parameters->status);

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_update_upgrade_task_status, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_update_upgrade_task_status, node, node);
    expect_string(__wrap_wm_task_manager_update_upgrade_task_status, status, status);
    will_return(__wrap_wm_task_manager_update_upgrade_task_status, WM_TASK_SUCCESS);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    expect_string(__wrap_wm_task_manager_parse_data_response, status, status);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade_update_status(task_parameters, &error_code);

    state[0] = response;
    state[1] = task_parameters;

    assert_non_null(response);
    assert_int_equal(cJSON_GetArraySize(response), 1);
    assert_memory_equal(cJSON_GetArrayItem(response, 0), res, sizeof(res));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_command_upgrade_update_status_task_err(void **state)
{
    char *node = "node02";
    int error_code = 0;
    int agent_id = 35;
    char *status = "Done";

    wm_task_manager_upgrade_update_status *task_parameters = wm_task_manager_init_upgrade_update_status_parameters();
    int *agents = NULL;

    os_calloc(2, sizeof(int), agents);
    agents[0] = agent_id;
    agents[1] = OS_INVALID;

    os_strdup(node, task_parameters->node);
    task_parameters->agent_ids = agents;
    os_strdup(status, task_parameters->status);

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_update_upgrade_task_status, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_update_upgrade_task_status, node, node);
    expect_string(__wrap_wm_task_manager_update_upgrade_task_status, status, status);
    will_return(__wrap_wm_task_manager_update_upgrade_task_status, WM_TASK_DATABASE_NO_TASK);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_DATABASE_NO_TASK);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    expect_string(__wrap_wm_task_manager_parse_data_response, status, status);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade_update_status(task_parameters, &error_code);

    state[0] = response;
    state[1] = task_parameters;

    assert_non_null(response);
    assert_int_equal(cJSON_GetArraySize(response), 1);
    assert_memory_equal(cJSON_GetArrayItem(response, 0), res, sizeof(res));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_command_upgrade_update_status_db_err(void **state)
{
    char *node = "node02";
    int error_code = 0;
    int agent_id = 35;
    char *status = "Done";

    wm_task_manager_upgrade_update_status *task_parameters = wm_task_manager_init_upgrade_update_status_parameters();
    int *agents = NULL;

    os_calloc(2, sizeof(int), agents);
    agents[0] = agent_id;
    agents[1] = OS_INVALID;

    os_strdup(node, task_parameters->node);
    task_parameters->agent_ids = agents;
    os_strdup(status, task_parameters->status);

    expect_value(__wrap_wm_task_manager_update_upgrade_task_status, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_update_upgrade_task_status, node, node);
    expect_string(__wrap_wm_task_manager_update_upgrade_task_status, status, status);
    will_return(__wrap_wm_task_manager_update_upgrade_task_status, OS_INVALID);

    cJSON *response = wm_task_manager_command_upgrade_update_status(task_parameters, &error_code);

    state[0] = NULL;
    state[1] = task_parameters;

    assert_int_equal(error_code, WM_TASK_DATABASE_ERROR);
}

void test_wm_task_manager_command_upgrade_result_ok(void **state)
{
    int error_code = 0;
    int agent_id = 35;
    int task_id = 24;
    char *command = "upgrade_result";

    char *node_result = "node01";
    char *module_result = "upgrade_module";
    char *command_result = "upgrade";
    char *status_result = "In progress";
    char *error_result = "Error string";
    int create_time = 789456123;
    int last_update = 987654321;

    wm_task_manager_upgrade_result *task_parameters = wm_task_manager_init_upgrade_result_parameters();
    int *agents = NULL;

    os_calloc(2, sizeof(int), agents);
    agents[0] = agent_id;
    agents[1] = OS_INVALID;

    task_parameters->agent_ids = agents;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, agent_id, agent_id);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, node_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, module_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, command_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, status_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, error_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, create_time);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, last_update);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, task_id);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    expect_string(__wrap_wm_task_manager_parse_data_result, node, node_result);
    expect_string(__wrap_wm_task_manager_parse_data_result, module, module_result);
    expect_string(__wrap_wm_task_manager_parse_data_result, command, command_result);
    expect_string(__wrap_wm_task_manager_parse_data_result, status, status_result);
    expect_string(__wrap_wm_task_manager_parse_data_result, error, error_result);
    expect_value(__wrap_wm_task_manager_parse_data_result, create_time, create_time);
    expect_value(__wrap_wm_task_manager_parse_data_result, last_update_time, last_update);
    expect_string(__wrap_wm_task_manager_parse_data_result, request_command, command);

    cJSON *response = wm_task_manager_command_upgrade_result(task_parameters, &error_code);

    state[0] = response;
    state[1] = task_parameters;

    assert_non_null(response);
    assert_int_equal(cJSON_GetArraySize(response), 1);
    assert_memory_equal(cJSON_GetArrayItem(response, 0), res, sizeof(res));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_command_upgrade_result_not_found_err(void **state)
{
    int error_code = 0;
    int agent_id = 35;
    int task_id = OS_NOTFOUND;

    char *node_result = "node01";
    char *module_result = "upgrade_module";
    char *command_result = "upgrade";
    char *status_result = "In progress";
    char *error_result = "Error string";
    int create_time = 789456123;
    int last_update = 987654321;

    wm_task_manager_upgrade_result *task_parameters = wm_task_manager_init_upgrade_result_parameters();
    int *agents = NULL;

    os_calloc(2, sizeof(int), agents);
    agents[0] = agent_id;
    agents[1] = OS_INVALID;

    task_parameters->agent_ids = agents;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, agent_id, agent_id);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, node_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, module_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, command_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, status_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, error_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, create_time);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, last_update);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, task_id);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_DATABASE_NO_TASK);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade_result(task_parameters, &error_code);

    state[0] = response;
    state[1] = task_parameters;

    assert_non_null(response);
    assert_int_equal(cJSON_GetArraySize(response), 1);
    assert_memory_equal(cJSON_GetArrayItem(response, 0), res, sizeof(res));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_command_upgrade_result_db_err(void **state)
{
    int error_code = 0;
    int agent_id = 35;
    int task_id = OS_INVALID;

    char *node_result = "node01";
    char *module_result = "upgrade_module";
    char *command_result = "upgrade";
    char *status_result = "In progress";
    char *error_result = "Error string";
    int create_time = 789456123;
    int last_update = 987654321;

    wm_task_manager_upgrade_result *task_parameters = wm_task_manager_init_upgrade_result_parameters();
    int *agents = NULL;

    os_calloc(2, sizeof(int), agents);
    agents[0] = agent_id;
    agents[1] = OS_INVALID;

    task_parameters->agent_ids = agents;

    expect_value(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, agent_id, agent_id);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, node_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, module_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, command_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, status_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, error_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, create_time);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, last_update);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, task_id);

    cJSON *response = wm_task_manager_command_upgrade_result(task_parameters, &error_code);

    state[0] = NULL;
    state[1] = task_parameters;

    assert_int_equal(error_code, WM_TASK_DATABASE_ERROR);
}

void test_wm_task_manager_command_upgrade_cancel_tasks_ok(void **state)
{
    char *node = "node02";
    int error_code = 0;

    wm_task_manager_upgrade_cancel_tasks *task_parameters = wm_task_manager_init_upgrade_cancel_tasks_parameters();

    os_strdup(node, task_parameters->node);

    cJSON* res = cJSON_CreateObject();

    expect_string(__wrap_wm_task_manager_cancel_upgrade_tasks, node, node);
    will_return(__wrap_wm_task_manager_cancel_upgrade_tasks, WM_TASK_SUCCESS);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade_cancel_tasks(task_parameters, &error_code);

    state[0] = response;
    state[1] = task_parameters;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_command_upgrade_cancel_tasks_db_err(void **state)
{
    char *node = "node02";
    int error_code = 0;

    wm_task_manager_upgrade_cancel_tasks *task_parameters = wm_task_manager_init_upgrade_cancel_tasks_parameters();

    os_strdup(node, task_parameters->node);

    expect_string(__wrap_wm_task_manager_cancel_upgrade_tasks, node, node);
    will_return(__wrap_wm_task_manager_cancel_upgrade_tasks, OS_INVALID);

    cJSON *response = wm_task_manager_command_upgrade_cancel_tasks(task_parameters, &error_code);

    state[0] = NULL;
    state[1] = task_parameters;

    assert_int_equal(error_code, WM_TASK_DATABASE_ERROR);
}

void test_wm_task_manager_command_task_result_ok(void **state)
{
    int error_code = 0;
    int agent_id = 35;
    int task_id = 24;
    char *command = "task_result";

    char *node_result = "node01";
    char *module_result = "api_module";
    char *command_result = "upgrade";
    char *status_result = "In progress";
    char *error_result = "Error string";
    int create_time = 789456123;
    int last_update = 987654321;

    wm_task_manager_task_result *task_parameters = wm_task_manager_init_task_result_parameters();
    int *tasks = NULL;

    os_calloc(2, sizeof(int), tasks);
    tasks[0] = task_id;
    tasks[1] = OS_INVALID;

    task_parameters->task_ids = tasks;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_get_task_by_task_id, task_id, task_id);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, node_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, module_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, command_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, status_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, error_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, create_time);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, last_update);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, agent_id);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    expect_string(__wrap_wm_task_manager_parse_data_result, node, node_result);
    expect_string(__wrap_wm_task_manager_parse_data_result, module, module_result);
    expect_string(__wrap_wm_task_manager_parse_data_result, command, command_result);
    expect_string(__wrap_wm_task_manager_parse_data_result, status, status_result);
    expect_string(__wrap_wm_task_manager_parse_data_result, error, error_result);
    expect_value(__wrap_wm_task_manager_parse_data_result, create_time, create_time);
    expect_value(__wrap_wm_task_manager_parse_data_result, last_update_time, last_update);
    expect_string(__wrap_wm_task_manager_parse_data_result, request_command, command);

    cJSON *response = wm_task_manager_command_task_result(task_parameters, &error_code);

    state[0] = response;
    state[1] = task_parameters;

    assert_non_null(response);
    assert_int_equal(cJSON_GetArraySize(response), 1);
    assert_memory_equal(cJSON_GetArrayItem(response, 0), res, sizeof(res));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_command_task_result_not_found_err(void **state)
{
    int error_code = 0;
    int agent_id = OS_NOTFOUND;
    int task_id = 24;

    char *node_result = "node01";
    char *module_result = "api_module";
    char *command_result = "upgrade";
    char *status_result = "In progress";
    char *error_result = "Error string";
    int create_time = 789456123;
    int last_update = 987654321;

    wm_task_manager_task_result *task_parameters = wm_task_manager_init_task_result_parameters();
    int *tasks = NULL;

    os_calloc(2, sizeof(int), tasks);
    tasks[0] = task_id;
    tasks[1] = OS_INVALID;

    task_parameters->task_ids = tasks;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_get_task_by_task_id, task_id, task_id);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, node_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, module_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, command_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, status_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, error_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, create_time);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, last_update);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, agent_id);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_DATABASE_NO_TASK);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_task_result(task_parameters, &error_code);

    state[0] = response;
    state[1] = task_parameters;

    assert_non_null(response);
    assert_int_equal(cJSON_GetArraySize(response), 1);
    assert_memory_equal(cJSON_GetArrayItem(response, 0), res, sizeof(res));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_command_task_result_db_err(void **state)
{
    int error_code = 0;
    int agent_id = OS_INVALID;
    int task_id = 24;

    char *node_result = "node01";
    char *module_result = "api_module";
    char *command_result = "upgrade";
    char *status_result = "In progress";
    char *error_result = "Error string";
    int create_time = 789456123;
    int last_update = 987654321;

    wm_task_manager_task_result *task_parameters = wm_task_manager_init_task_result_parameters();
    int *tasks = NULL;

    os_calloc(2, sizeof(int), tasks);
    tasks[0] = task_id;
    tasks[1] = OS_INVALID;

    task_parameters->task_ids = tasks;

    expect_value(__wrap_wm_task_manager_get_task_by_task_id, task_id, task_id);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, node_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, module_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, command_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, status_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, error_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, create_time);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, last_update);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, agent_id);

    cJSON *response = wm_task_manager_command_task_result(task_parameters, &error_code);

    state[0] = NULL;
    state[1] = task_parameters;

    assert_int_equal(error_code, WM_TASK_DATABASE_ERROR);
}

void test_wm_task_manager_process_task_upgrade_ok(void **state)
{
    int error_code = 0;
    char *command = "upgrade";
    char *node = "node02";
    char *module = "upgrade_module";
    int agent_id1 = 45;
    int agent_id2 = 49;
    int *agents = NULL;
    int task_id1 = 38;
    int task_id2 = 39;

    wm_task_manager_task *task = wm_task_manager_init_task();
    wm_task_manager_upgrade *task_parameters = wm_task_manager_init_upgrade_parameters();

    os_calloc(3, sizeof(int), agents);
    agents[0] = agent_id1;
    agents[1] = agent_id2;
    agents[2] = OS_INVALID;

    os_strdup(module, task_parameters->module);
    os_strdup(node, task_parameters->node);
    task_parameters->agent_ids = agents;

    task->command = WM_TASK_UPGRADE;
    task->parameters = task_parameters;

    cJSON* res1 = cJSON_CreateObject();
    cJSON* res2 = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_insert_task, agent_id, agent_id1);
    expect_string(__wrap_wm_task_manager_insert_task, node, node);
    expect_string(__wrap_wm_task_manager_insert_task, module, module);
    expect_string(__wrap_wm_task_manager_insert_task, command, command);
    will_return(__wrap_wm_task_manager_insert_task, task_id1);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id1);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, task_id1);
    will_return(__wrap_wm_task_manager_parse_data_response, res1);

    expect_value(__wrap_wm_task_manager_insert_task, agent_id, agent_id2);
    expect_string(__wrap_wm_task_manager_insert_task, node, node);
    expect_string(__wrap_wm_task_manager_insert_task, module, module);
    expect_string(__wrap_wm_task_manager_insert_task, command, command);
    will_return(__wrap_wm_task_manager_insert_task, task_id2);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id2);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, task_id2);
    will_return(__wrap_wm_task_manager_parse_data_response, res2);

    cJSON *response = wm_task_manager_process_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_non_null(response);
    assert_int_equal(cJSON_GetArraySize(response), 2);
    assert_memory_equal(cJSON_GetArrayItem(response, 0), res1, sizeof(res1));
    assert_memory_equal(cJSON_GetArrayItem(response, 1), res2, sizeof(res2));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_process_task_upgrade_custom_ok(void **state)
{
    int error_code = 0;
    char *command = "upgrade_custom";
    char *node = "node02";
    char *module = "upgrade_module";
    int agent_id1 = 45;
    int agent_id2 = 49;
    int *agents = NULL;
    int task_id1 = 38;
    int task_id2 = 39;

    wm_task_manager_task *task = wm_task_manager_init_task();
    wm_task_manager_upgrade *task_parameters = wm_task_manager_init_upgrade_parameters();

    os_calloc(3, sizeof(int), agents);
    agents[0] = agent_id1;
    agents[1] = agent_id2;
    agents[2] = OS_INVALID;

    os_strdup(module, task_parameters->module);
    os_strdup(node, task_parameters->node);
    task_parameters->agent_ids = agents;

    task->command = WM_TASK_UPGRADE_CUSTOM;
    task->parameters = task_parameters;

    cJSON* res1 = cJSON_CreateObject();
    cJSON* res2 = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_insert_task, agent_id, agent_id1);
    expect_string(__wrap_wm_task_manager_insert_task, node, node);
    expect_string(__wrap_wm_task_manager_insert_task, module, module);
    expect_string(__wrap_wm_task_manager_insert_task, command, command);
    will_return(__wrap_wm_task_manager_insert_task, task_id1);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id1);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, task_id1);
    will_return(__wrap_wm_task_manager_parse_data_response, res1);

    expect_value(__wrap_wm_task_manager_insert_task, agent_id, agent_id2);
    expect_string(__wrap_wm_task_manager_insert_task, node, node);
    expect_string(__wrap_wm_task_manager_insert_task, module, module);
    expect_string(__wrap_wm_task_manager_insert_task, command, command);
    will_return(__wrap_wm_task_manager_insert_task, task_id2);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id2);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, task_id2);
    will_return(__wrap_wm_task_manager_parse_data_response, res2);

    cJSON *response = wm_task_manager_process_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_non_null(response);
    assert_int_equal(cJSON_GetArraySize(response), 2);
    assert_memory_equal(cJSON_GetArrayItem(response, 0), res1, sizeof(res1));
    assert_memory_equal(cJSON_GetArrayItem(response, 1), res2, sizeof(res2));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_process_task_upgrade_get_status_ok(void **state)
{
    int error_code = 0;
    char *node = "node02";
    int agent_id = 45;
    int *agents = NULL;
    char *status_result = "In progress";

    wm_task_manager_task *task = wm_task_manager_init_task();
    wm_task_manager_upgrade_get_status *task_parameters = wm_task_manager_init_upgrade_get_status_parameters();

    os_calloc(2, sizeof(int), agents);
    agents[0] = agent_id;
    agents[1] = OS_INVALID;

    os_strdup(node, task_parameters->node);
    task_parameters->agent_ids = agents;

    task->command = WM_TASK_UPGRADE_GET_STATUS;
    task->parameters = task_parameters;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_get_upgrade_task_status, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_get_upgrade_task_status, node, node);
    will_return(__wrap_wm_task_manager_get_upgrade_task_status, status_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_status, WM_TASK_SUCCESS);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    expect_string(__wrap_wm_task_manager_parse_data_response, status, status_result);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_process_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_non_null(response);
    assert_int_equal(cJSON_GetArraySize(response), 1);
    assert_memory_equal(cJSON_GetArrayItem(response, 0), res, sizeof(res));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_process_task_upgrade_update_status_ok(void **state)
{
    int error_code = 0;
    char *node = "node02";
    int agent_id = 45;
    int *agents = NULL;
    char *status = "Failed";
    char *error = "Error message";

    wm_task_manager_task *task = wm_task_manager_init_task();
    wm_task_manager_upgrade_update_status *task_parameters = wm_task_manager_init_upgrade_update_status_parameters();

    os_calloc(2, sizeof(int), agents);
    agents[0] = agent_id;
    agents[1] = OS_INVALID;

    os_strdup(node, task_parameters->node);
    task_parameters->agent_ids = agents;
    os_strdup(status, task_parameters->status);
    os_strdup(error, task_parameters->error_msg);

    task->command = WM_TASK_UPGRADE_UPDATE_STATUS;
    task->parameters = task_parameters;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_update_upgrade_task_status, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_update_upgrade_task_status, node, node);
    expect_string(__wrap_wm_task_manager_update_upgrade_task_status, status, status);
    expect_string(__wrap_wm_task_manager_update_upgrade_task_status, error, error);
    will_return(__wrap_wm_task_manager_update_upgrade_task_status, WM_TASK_SUCCESS);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    expect_string(__wrap_wm_task_manager_parse_data_response, status, status);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_process_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_non_null(response);
    assert_int_equal(cJSON_GetArraySize(response), 1);
    assert_memory_equal(cJSON_GetArrayItem(response, 0), res, sizeof(res));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_process_task_upgrade_result_ok(void **state)
{
    int error_code = 0;
    char *command = "upgrade_result";
    int agent_id = 45;
    int *agents = NULL;
    int task_id = 38;

    char *node_result = "node01";
    char *module_result = "api";
    char *command_result = "upgrade";
    char *status_result = "Updating";
    char *error_result = "Error string";
    int create_time = 789456123;
    int last_update = 987654321;

    wm_task_manager_task *task = wm_task_manager_init_task();
    wm_task_manager_upgrade_result *task_parameters = wm_task_manager_init_upgrade_result_parameters();

    os_calloc(2, sizeof(int), agents);
    agents[0] = agent_id;
    agents[1] = OS_INVALID;

    task_parameters->agent_ids = agents;

    task->command = WM_TASK_UPGRADE_RESULT;
    task->parameters = task_parameters;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, agent_id, agent_id);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, node_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, module_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, command_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, status_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, error_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, create_time);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, last_update);
    will_return(__wrap_wm_task_manager_get_upgrade_task_by_agent_id, task_id);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    expect_string(__wrap_wm_task_manager_parse_data_result, node, node_result);
    expect_string(__wrap_wm_task_manager_parse_data_result, module, module_result);
    expect_string(__wrap_wm_task_manager_parse_data_result, command, command_result);
    expect_string(__wrap_wm_task_manager_parse_data_result, status, status_result);
    expect_string(__wrap_wm_task_manager_parse_data_result, error, error_result);
    expect_value(__wrap_wm_task_manager_parse_data_result, create_time, create_time);
    expect_value(__wrap_wm_task_manager_parse_data_result, last_update_time, last_update);
    expect_string(__wrap_wm_task_manager_parse_data_result, request_command, command);

    cJSON *response = wm_task_manager_process_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_non_null(response);
    assert_int_equal(cJSON_GetArraySize(response), 1);
    assert_memory_equal(cJSON_GetArrayItem(response, 0), res, sizeof(res));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_process_task_upgrade_cancel_tasks_ok(void **state)
{
    int error_code = 0;
    char *node = "node02";

    wm_task_manager_task *task = wm_task_manager_init_task();
    wm_task_manager_upgrade_cancel_tasks *task_parameters = wm_task_manager_init_upgrade_cancel_tasks_parameters();

    os_strdup(node, task_parameters->node);

    task->command = WM_TASK_UPGRADE_CANCEL_TASKS;
    task->parameters = task_parameters;

    cJSON* res = cJSON_CreateObject();

    expect_string(__wrap_wm_task_manager_cancel_upgrade_tasks, node, node);
    will_return(__wrap_wm_task_manager_cancel_upgrade_tasks, WM_TASK_SUCCESS);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_process_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_process_task_task_result_ok(void **state)
{
    int error_code = 0;
    char *command = "task_result";
    int task_id = 38;
    int *tasks = NULL;
    int agent_id = 45;

    char *node_result = "node01";
    char *module_result = "api";
    char *command_result = "upgrade";
    char *status_result = "In progress";
    char *error_result = "Error string";
    int create_time = 789456123;
    int last_update = 987654321;

    wm_task_manager_task *task = wm_task_manager_init_task();
    wm_task_manager_task_result *task_parameters = wm_task_manager_init_task_result_parameters();

    os_calloc(2, sizeof(int), tasks);
    tasks[0] = task_id;
    tasks[1] = OS_INVALID;

    task_parameters->task_ids = tasks;

    task->command = WM_TASK_TASK_RESULT;
    task->parameters = task_parameters;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_get_task_by_task_id, task_id, task_id);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, node_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, module_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, command_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, status_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, error_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, create_time);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, last_update);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, agent_id);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    expect_string(__wrap_wm_task_manager_parse_data_result, node, node_result);
    expect_string(__wrap_wm_task_manager_parse_data_result, module, module_result);
    expect_string(__wrap_wm_task_manager_parse_data_result, command, command_result);
    expect_string(__wrap_wm_task_manager_parse_data_result, status, status_result);
    expect_string(__wrap_wm_task_manager_parse_data_result, error, error_result);
    expect_value(__wrap_wm_task_manager_parse_data_result, create_time, create_time);
    expect_value(__wrap_wm_task_manager_parse_data_result, last_update_time, last_update);
    expect_string(__wrap_wm_task_manager_parse_data_result, request_command, command);

    cJSON *response = wm_task_manager_process_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_non_null(response);
    assert_int_equal(cJSON_GetArraySize(response), 1);
    assert_memory_equal(cJSON_GetArrayItem(response, 0), res, sizeof(res));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_process_task_command_err(void **state)
{
    int error_code = 0;
    command_list command = WM_TASK_UNKNOWN;

    wm_task_manager_task *task = wm_task_manager_init_task();

    task->command = command;

    cJSON *response = wm_task_manager_process_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_null(response);
    assert_int_equal(error_code, WM_TASK_INVALID_COMMAND);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_task_manager_command_upgrade
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_ok, teardown_json_upgrade_task),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_custom_ok, teardown_json_upgrade_task),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_db_err, teardown_json_upgrade_task),
        // wm_task_manager_command_upgrade_get_status
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_get_status_ok, teardown_json_upgrade_get_status_task),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_get_status_task_err, teardown_json_upgrade_get_status_task),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_get_status_db_err, teardown_json_upgrade_get_status_task),
        // wm_task_manager_command_upgrade_update_status
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_update_status_ok, teardown_json_upgrade_update_status_task),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_update_status_task_err, teardown_json_upgrade_update_status_task),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_update_status_db_err, teardown_json_upgrade_update_status_task),
        // wm_task_manager_command_upgrade_result
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_result_ok, teardown_json_upgrade_result_task),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_result_not_found_err, teardown_json_upgrade_result_task),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_result_db_err, teardown_json_upgrade_result_task),
        // wm_task_manager_command_upgrade_cancel_tasks
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_cancel_tasks_ok, teardown_json_upgrade_cancel_tasks_task),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_cancel_tasks_db_err, teardown_json_upgrade_cancel_tasks_task),
        // wm_task_manager_command_task_result
        cmocka_unit_test_teardown(test_wm_task_manager_command_task_result_ok, teardown_json_task_result_task),
        cmocka_unit_test_teardown(test_wm_task_manager_command_task_result_not_found_err, teardown_json_task_result_task),
        cmocka_unit_test_teardown(test_wm_task_manager_command_task_result_db_err, teardown_json_task_result_task),
        // wm_task_manager_process_task
        cmocka_unit_test_teardown(test_wm_task_manager_process_task_upgrade_ok, teardown_json_task),
        cmocka_unit_test_teardown(test_wm_task_manager_process_task_upgrade_custom_ok, teardown_json_task),
        cmocka_unit_test_teardown(test_wm_task_manager_process_task_upgrade_get_status_ok, teardown_json_task),
        cmocka_unit_test_teardown(test_wm_task_manager_process_task_upgrade_update_status_ok, teardown_json_task),
        cmocka_unit_test_teardown(test_wm_task_manager_process_task_upgrade_result_ok, teardown_json_task),
        cmocka_unit_test_teardown(test_wm_task_manager_process_task_upgrade_cancel_tasks_ok, teardown_json_task),
        cmocka_unit_test_teardown(test_wm_task_manager_process_task_task_result_ok, teardown_json_task),
        cmocka_unit_test_teardown(test_wm_task_manager_process_task_command_err, teardown_json_task)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
