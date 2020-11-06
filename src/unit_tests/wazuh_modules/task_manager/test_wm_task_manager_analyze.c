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
#include "../../headers/shared.h"

cJSON* wm_task_manager_command_upgrade(char *node, char *module, char *command, int *error_code, int agent_id);
cJSON* wm_task_manager_command_upgrade_get_status(char *node, int *error_code, int agent_id);
cJSON* wm_task_manager_command_upgrade_update_status(char *node, int *error_code, int agent_id, char *status, char *error);
cJSON* wm_task_manager_command_upgrade_result(char *command, int *error_code, int agent_id);
cJSON* wm_task_manager_command_task_result(char *command, int *error_code, int task_id);
cJSON* wm_task_manager_command_upgrade_cancel_tasks(char *node, int *error_code);

// Setup / teardown

static int teardown_json(void **state) {
    if (state[0]) {
        cJSON *json = state[0];
        cJSON_Delete(json);
    }
    if (state[1]) {
        cJSON *json = state[1];
        cJSON_Delete(json);
    }
    return 0;
}

// Tests

void test_wm_task_manager_command_upgrade_result_ok(void **state)
{
    char *command = "upgrade_result";
    int error_code = 0;
    int agent_id = 35;
    int task_id = 24;

    char *node_result = "node01";
    char *module_result = "upgrade_module";
    char *command_result = "upgrade";
    char *status_result = "In progress";
    char *error_result = "Error string";
    int create_time = 789456123;
    int last_update = 987654321;

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

    cJSON *response = wm_task_manager_command_upgrade_result(command, &error_code, agent_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_command_upgrade_result_not_found_err(void **state)
{
    char *command = "upgrade_result";
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
    expect_string(__wrap_wm_task_manager_parse_data_response, status, status_result);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade_result(command, &error_code, agent_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_DATABASE_NO_TASK);
}

void test_wm_task_manager_command_upgrade_result_db_err(void **state)
{
    char *command = "upgrade_result";
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

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_DATABASE_ERROR);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    expect_string(__wrap_wm_task_manager_parse_data_response, status, status_result);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade_result(command, &error_code, agent_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_DATABASE_ERROR);
}

void test_wm_task_manager_command_upgrade_result_agent_id_err(void **state)
{
    char *command = "upgrade_result";
    int error_code = 0;
    int agent_id = OS_INVALID;
    int task_id = OS_INVALID;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_INVALID_AGENT_ID);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade_result(command, &error_code, agent_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_AGENT_ID);
}

void test_wm_task_manager_command_task_result_ok(void **state)
{
    char *command = "task_result";
    int error_code = 0;
    int agent_id = 35;
    int task_id = 24;

    char *node_result = "node01";
    char *module_result = "api_module";
    char *command_result = "upgrade";
    char *status_result = "In progress";
    char *error_result = "Error string";
    int create_time = 789456123;
    int last_update = 987654321;

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

    cJSON *response = wm_task_manager_command_task_result(command, &error_code, task_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_command_task_result_not_found_err(void **state)
{
    char *command = "task_result";
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
    expect_string(__wrap_wm_task_manager_parse_data_response, status, status_result);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_task_result(command, &error_code, task_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_DATABASE_NO_TASK);
}

void test_wm_task_manager_command_task_result_db_err(void **state)
{
    char *command = "task_result";
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

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_DATABASE_ERROR);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, task_id);
    expect_string(__wrap_wm_task_manager_parse_data_response, status, status_result);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_task_result(command, &error_code, task_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_DATABASE_ERROR);
}

void test_wm_task_manager_command_task_result_task_id_err(void **state)
{
    char *command = "task_result";
    int error_code = 0;
    int agent_id = OS_INVALID;
    int task_id = OS_INVALID;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_INVALID_TASK_ID);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_task_result(command, &error_code, task_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_TASK_ID);
}

void test_wm_task_manager_command_upgrade_ok(void **state)
{
    char *node = "node02";
    char *module = "upgrade_module";
    char *command = "upgrade";
    int error_code = 0;
    int agent_id = 35;
    int task_id = 24;

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

    cJSON *response = wm_task_manager_command_upgrade(node, module, command, &error_code, agent_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
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

    cJSON *response = wm_task_manager_command_upgrade(node, module, command, &error_code, agent_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
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

    expect_value(__wrap_wm_task_manager_insert_task, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_insert_task, node, node);
    expect_string(__wrap_wm_task_manager_insert_task, module, module);
    expect_string(__wrap_wm_task_manager_insert_task, command, command);
    will_return(__wrap_wm_task_manager_insert_task, task_id);

    cJSON *response = wm_task_manager_command_upgrade(node, module, command, &error_code, agent_id);

    assert_null(response);
    assert_int_equal(error_code, WM_TASK_DATABASE_ERROR);
}

void test_wm_task_manager_command_upgrade_agent_id_err(void **state)
{
    char *node = "node02";
    char *module = "upgrade_module";
    char *command = "upgrade";
    int error_code = 0;
    int agent_id = OS_INVALID;
    int task_id = OS_INVALID;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_INVALID_AGENT_ID);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade(node, module, command, &error_code, agent_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_AGENT_ID);
}

void test_wm_task_manager_command_upgrade_module_err(void **state)
{
    char *node = "node02";
    char *module = NULL;
    char *command = "upgrade";
    int error_code = 0;
    int agent_id = 55;
    int task_id = OS_INVALID;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_INVALID_MODULE);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade(node, module, command, &error_code, agent_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_MODULE);
}

void test_wm_task_manager_command_upgrade_node_err(void **state)
{
    char *node = NULL;
    char *module = "upgrade_module";
    char *command = "upgrade";
    int error_code = 0;
    int agent_id = 87;
    int task_id = OS_INVALID;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_INVALID_NODE);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade(node, module, command, &error_code, agent_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_NODE);
}

void test_wm_task_manager_command_upgrade_get_status_ok(void **state)
{
    char *node = "node02";
    int error_code = 0;
    int agent_id = 35;

    char *status_result = "In progress";

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

    cJSON *response = wm_task_manager_command_upgrade_get_status(node, &error_code, agent_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_command_upgrade_get_status_task_err(void **state)
{
    char *node = "node02";
    int error_code = 0;
    int agent_id = 35;

    char *status_result = "In progress";

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_get_upgrade_task_status, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_get_upgrade_task_status, node, node);
    will_return(__wrap_wm_task_manager_get_upgrade_task_status, status_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_status, WM_TASK_DATABASE_NO_TASK);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_DATABASE_NO_TASK);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade_get_status(node, &error_code, agent_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_DATABASE_NO_TASK);
}

void test_wm_task_manager_command_upgrade_get_status_db_err(void **state)
{
    char *node = "node02";
    int error_code = 0;
    int agent_id = 35;

    char *status_result = "In progress";

    expect_value(__wrap_wm_task_manager_get_upgrade_task_status, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_get_upgrade_task_status, node, node);
    will_return(__wrap_wm_task_manager_get_upgrade_task_status, status_result);
    will_return(__wrap_wm_task_manager_get_upgrade_task_status, OS_INVALID);

    cJSON *response = wm_task_manager_command_upgrade_get_status(node, &error_code, agent_id);

    assert_null(response);
    assert_int_equal(error_code, WM_TASK_DATABASE_ERROR);
}

void test_wm_task_manager_command_upgrade_get_status_agent_id_err(void **state)
{
    char *node = "node02";
    int error_code = 0;
    int agent_id = OS_INVALID;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_INVALID_AGENT_ID);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade_get_status(node, &error_code, agent_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_AGENT_ID);
}

void test_wm_task_manager_command_upgrade_get_status_node_err(void **state)
{
    char *node = NULL;
    int error_code = 0;
    int agent_id = 105;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_INVALID_NODE);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade_get_status(node, &error_code, agent_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_NODE);
}

void test_wm_task_manager_command_upgrade_update_status_ok(void **state)
{
    char *node = "node02";
    int error_code = 0;
    int agent_id = 35;
    char *status = "Done";

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

    cJSON *response = wm_task_manager_command_upgrade_update_status(node, &error_code, agent_id, status, NULL);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_command_upgrade_update_status_task_err(void **state)
{
    char *node = "node02";
    int error_code = 0;
    int agent_id = 35;
    char *status = "Done";

    char *status_result = "In progress";

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

    cJSON *response = wm_task_manager_command_upgrade_update_status(node, &error_code, agent_id, status, NULL);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_DATABASE_NO_TASK);
}

void test_wm_task_manager_command_upgrade_update_status_db_err(void **state)
{
    char *node = "node02";
    int error_code = 0;
    int agent_id = 35;
    char *status = "Done";

    expect_value(__wrap_wm_task_manager_update_upgrade_task_status, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_update_upgrade_task_status, node, node);
    expect_string(__wrap_wm_task_manager_update_upgrade_task_status, status, status);
    will_return(__wrap_wm_task_manager_update_upgrade_task_status, OS_INVALID);

    cJSON *response = wm_task_manager_command_upgrade_update_status(node, &error_code, agent_id, status, NULL);

    assert_null(response);
    assert_int_equal(error_code, WM_TASK_DATABASE_ERROR);
}

void test_wm_task_manager_command_upgrade_update_status_agent_id_err(void **state)
{
    char *node = "node02";
    int error_code = 0;
    int agent_id = OS_INVALID;
    char *status = "Done";

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_INVALID_AGENT_ID);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    expect_string(__wrap_wm_task_manager_parse_data_response, status, status);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade_update_status(node, &error_code, agent_id, status, NULL);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_AGENT_ID);
}

void test_wm_task_manager_command_upgrade_update_status_node_err(void **state)
{
    char *node = NULL;
    int error_code = 0;
    int agent_id = 15;
    char *status = "Done";

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_INVALID_NODE);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    expect_string(__wrap_wm_task_manager_parse_data_response, status, status);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade_update_status(node, &error_code, agent_id, status, NULL);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_NODE);
}

void test_wm_task_manager_command_upgrade_cancel_tasks_ok(void **state)
{
    char *node = "node02";
    int error_code = 0;

    cJSON* res = cJSON_CreateObject();

    expect_string(__wrap_wm_task_manager_cancel_upgrade_tasks, node, node);
    will_return(__wrap_wm_task_manager_cancel_upgrade_tasks, WM_TASK_SUCCESS);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade_cancel_tasks(node, &error_code);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_command_upgrade_cancel_tasks_db_err(void **state)
{
    char *node = "node02";
    int error_code = 0;

    expect_string(__wrap_wm_task_manager_cancel_upgrade_tasks, node, node);
    will_return(__wrap_wm_task_manager_cancel_upgrade_tasks, OS_INVALID);

    cJSON *response = wm_task_manager_command_upgrade_cancel_tasks(node, &error_code);

    assert_null(response);
    assert_int_equal(error_code, WM_TASK_DATABASE_ERROR);
}

void test_wm_task_manager_command_upgrade_cancel_tasks_node_err(void **state)
{
    char *node = NULL;
    int error_code = 0;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_INVALID_NODE);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_command_upgrade_cancel_tasks(node, &error_code);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_NODE);
}

void test_wm_task_manager_analyze_task_upgrade_cancel_tasks_ok(void **state)
{
    int error_code = 0;
    char *node = "node02";
    char *module = "upgrade_module";
    char *command = "upgrade_cancel_tasks";
    int agent_id = 45;

    cJSON *task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, "node", node);
    cJSON_AddStringToObject(task, "module", module);
    cJSON_AddStringToObject(task, "command", command);
    cJSON_AddNumberToObject(task, "agent", agent_id);

    cJSON* res = cJSON_CreateObject();

    expect_string(__wrap_wm_task_manager_cancel_upgrade_tasks, node, node);
    will_return(__wrap_wm_task_manager_cancel_upgrade_tasks, WM_TASK_SUCCESS);

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_analyze_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_analyze_task_upgrade_update_status_ok(void **state)
{
    int error_code = 0;
    char *node = "node02";
    char *module = "upgrade_module";
    char *command = "upgrade_update_status";
    int agent_id = 45;
    char *status = "Failed";
    char *error = "Error message";

    cJSON *task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, "node", node);
    cJSON_AddStringToObject(task, "module", module);
    cJSON_AddStringToObject(task, "command", command);
    cJSON_AddNumberToObject(task, "agent", agent_id);
    cJSON_AddStringToObject(task, "status", status);
    cJSON_AddStringToObject(task, "error_msg", error);

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

    cJSON *response = wm_task_manager_analyze_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_analyze_task_upgrade_get_status_ok(void **state)
{
    int error_code = 0;
    char *node = "node02";
    char *module = "api";
    char *command = "upgrade_get_status";
    int agent_id = 45;
    char *status_result = "In progress";

    cJSON *task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, "node", node);
    cJSON_AddStringToObject(task, "module", module);
    cJSON_AddStringToObject(task, "command", command);
    cJSON_AddNumberToObject(task, "agent", agent_id);

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

    cJSON *response = wm_task_manager_analyze_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_analyze_task_upgrade_ok(void **state)
{
    int error_code = 0;
    char *node = "node02";
    char *module = "upgrade_module";
    char *command = "upgrade";
    int agent_id = 45;
    int task_id = 38;

    cJSON *task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, "node", node);
    cJSON_AddStringToObject(task, "module", module);
    cJSON_AddStringToObject(task, "command", command);
    cJSON_AddNumberToObject(task, "agent", agent_id);

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

    cJSON *response = wm_task_manager_analyze_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_analyze_task_upgrade_custom_ok(void **state)
{
    int error_code = 0;
    char *node = "node02";
    char *module = "upgrade_module";
    char *command = "upgrade_custom";
    int agent_id = 45;
    int task_id = 38;

    cJSON *task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, "node", node);
    cJSON_AddStringToObject(task, "module", module);
    cJSON_AddStringToObject(task, "command", command);
    cJSON_AddNumberToObject(task, "agent", agent_id);

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

    cJSON *response = wm_task_manager_analyze_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_analyze_task_task_result_ok(void **state)
{
    int error_code = 0;
    char *node = "node02";
    char *module = "api";
    char *command = "task_result";
    int agent_id = 45;
    int task_id = 88;

    char *node_result = "node01";
    char *module_result = "api";
    char *command_result = "upgrade";
    char *status_result = "In progress";
    char *error_result = "Error string";
    int create_time = 789456123;
    int last_update = 987654321;

    cJSON *task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, "node", node);
    cJSON_AddStringToObject(task, "module", module);
    cJSON_AddStringToObject(task, "command", command);
    cJSON_AddNumberToObject(task, "task_id", task_id);

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

    cJSON *response = wm_task_manager_analyze_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_analyze_task_upgrade_result_ok(void **state)
{
    int error_code = 0;
    char *node = "node02";
    char *module = "api";
    char *command = "upgrade_result";
    int agent_id = 45;
    int task_id = 88;

    char *node_result = "node01";
    char *module_result = "api";
    char *command_result = "upgrade";
    char *status_result = "Updating";
    char *error_result = "Error string";
    int create_time = 789456123;
    int last_update = 987654321;

    cJSON *task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, "node", node);
    cJSON_AddStringToObject(task, "module", module);
    cJSON_AddStringToObject(task, "command", command);
    cJSON_AddNumberToObject(task, "agent", agent_id);

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

    cJSON *response = wm_task_manager_analyze_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_analyze_task_command_err(void **state)
{
    int error_code = 0;
    char *command = "unknown";

    cJSON *task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, "command", command);
    cJSON_AddStringToObject(task, "agent", "1");
    cJSON_AddStringToObject(task, "task_id", "5");
    cJSON_AddNumberToObject(task, "status", 3);
    cJSON_AddNumberToObject(task, "error_msg", 7);

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_INVALID_COMMAND);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_analyze_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_COMMAND);
}

void test_wm_task_manager_analyze_task_command_null(void **state)
{
    int error_code = 0;
    char *command = NULL;

    cJSON *task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, "command", command);

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_data_response, error_code, WM_TASK_INVALID_COMMAND);
    expect_value(__wrap_wm_task_manager_parse_data_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_data_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_data_response, res);

    cJSON *response = wm_task_manager_analyze_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_COMMAND);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_task_manager_command_upgrade_result
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_result_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_result_not_found_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_result_db_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_result_agent_id_err, teardown_json),
        // wm_task_manager_command_task_result
        cmocka_unit_test_teardown(test_wm_task_manager_command_task_result_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_command_task_result_not_found_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_command_task_result_db_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_command_task_result_task_id_err, teardown_json),
        // wm_task_manager_command_upgrade
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_custom_ok, teardown_json),
        cmocka_unit_test(test_wm_task_manager_command_upgrade_db_err),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_agent_id_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_module_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_node_err, teardown_json),
        // wm_task_manager_command_upgrade_get_status
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_get_status_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_get_status_task_err, teardown_json),
        cmocka_unit_test(test_wm_task_manager_command_upgrade_get_status_db_err),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_get_status_agent_id_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_get_status_node_err, teardown_json),
        // wm_task_manager_command_upgrade_update_status
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_update_status_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_update_status_task_err, teardown_json),
        cmocka_unit_test(test_wm_task_manager_command_upgrade_update_status_db_err),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_update_status_agent_id_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_update_status_node_err, teardown_json),
        // wm_task_manager_command_upgrade_cancel_tasks
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_cancel_tasks_ok, teardown_json),
        cmocka_unit_test(test_wm_task_manager_command_upgrade_cancel_tasks_db_err),
        cmocka_unit_test_teardown(test_wm_task_manager_command_upgrade_cancel_tasks_node_err, teardown_json),
        // wm_task_manager_analyze_task
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_upgrade_cancel_tasks_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_upgrade_update_status_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_task_result_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_upgrade_result_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_upgrade_get_status_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_upgrade_custom_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_upgrade_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_command_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_command_null, teardown_json)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
