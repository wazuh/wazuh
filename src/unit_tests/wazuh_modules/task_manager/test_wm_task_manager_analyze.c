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
#include "../../wazuh_modules/task_manager/wm_task_manager.h"
#include "../../headers/shared.h"

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

// Wrappers

int __wrap_wm_task_manager_get_task_by_agent_id_and_module(int agent_id, const char *module, char **command, char **status, int *create_time, int *last_update_time) {
    check_expected(agent_id);
    check_expected(module);

    os_strdup(mock_type(char*), *command);
    os_strdup(mock_type(char*), *status);
    *create_time = mock();
    *last_update_time = mock();

    return mock();
}

int __wrap_wm_task_manager_get_task_by_task_id(int task_id, char **module, char **command, char **status, int *create_time, int *last_update_time) {
    check_expected(task_id);

    os_strdup(mock_type(char*), *module);
    os_strdup(mock_type(char*), *command);
    os_strdup(mock_type(char*), *status);
    *create_time = mock();
    *last_update_time = mock();

    return mock();
}

cJSON* __wrap_wm_task_manager_parse_response(int error_code, int agent_id, int task_id, char *status) {
    check_expected(error_code);
    check_expected(agent_id);
    check_expected(task_id);
    if (status) check_expected(status);

    return mock_type(cJSON*);
}

void __wrap_wm_task_manager_parse_response_result(cJSON *response, const char *module, const char *command, char *status, int create_time, int last_update_time, char *request_command) {
    check_expected(module);
    check_expected(command);
    check_expected(status);
    check_expected(create_time);
    check_expected(last_update_time);
    check_expected(request_command);
}

int __wrap_wm_task_manager_insert_task(int agent_id, const char *module, const char *command) {
    check_expected(agent_id);
    check_expected(module);
    check_expected(command);

    return mock();
}

int __wrap_wm_task_manager_get_task_status(int agent_id, const char *module, char **status) {
    check_expected(agent_id);
    check_expected(module);

    os_strdup(mock_type(char*), *status);

    return mock();
}

int __wrap_wm_task_manager_update_task_status(int agent_id, const char *module, const char *status) {
    check_expected(agent_id);
    check_expected(module);
    if (status) check_expected(status);

    return mock();
}

// Tests

void test_wm_task_manager_analyze_task_api_module_upgrade_result_ok(void **state)
{
    char *command = "upgrade_result";
    int error_code = 0;
    int agent_id = 35;
    int task_id = 24;

    char *command_result = "upgrade";
    char *status_result = "In progress";
    int create_time = 789456123;
    int last_update = 987654321;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_get_task_by_agent_id_and_module, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_get_task_by_agent_id_and_module, module, "upgrade_module");
    will_return(__wrap_wm_task_manager_get_task_by_agent_id_and_module, command_result);
    will_return(__wrap_wm_task_manager_get_task_by_agent_id_and_module, status_result);
    will_return(__wrap_wm_task_manager_get_task_by_agent_id_and_module, create_time);
    will_return(__wrap_wm_task_manager_get_task_by_agent_id_and_module, last_update);
    will_return(__wrap_wm_task_manager_get_task_by_agent_id_and_module, task_id);

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_response, res);

    expect_string(__wrap_wm_task_manager_parse_response_result, module, "upgrade_module");
    expect_string(__wrap_wm_task_manager_parse_response_result, command, command_result);
    expect_string(__wrap_wm_task_manager_parse_response_result, status, status_result);
    expect_value(__wrap_wm_task_manager_parse_response_result, create_time, create_time);
    expect_value(__wrap_wm_task_manager_parse_response_result, last_update_time, last_update);
    expect_string(__wrap_wm_task_manager_parse_response_result, request_command, command);

    cJSON *response = wm_task_manager_analyze_task_api_module(command, &error_code, agent_id, task_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_analyze_task_api_module_upgrade_result_not_found_err(void **state)
{
    char *command = "upgrade_result";
    int error_code = 0;
    int agent_id = 35;
    int task_id = OS_NOTFOUND;

    char *command_result = "upgrade";
    char *status_result = "In progress";
    int create_time = 789456123;
    int last_update = 987654321;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_get_task_by_agent_id_and_module, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_get_task_by_agent_id_and_module, module, "upgrade_module");
    will_return(__wrap_wm_task_manager_get_task_by_agent_id_and_module, command_result);
    will_return(__wrap_wm_task_manager_get_task_by_agent_id_and_module, status_result);
    will_return(__wrap_wm_task_manager_get_task_by_agent_id_and_module, create_time);
    will_return(__wrap_wm_task_manager_get_task_by_agent_id_and_module, last_update);
    will_return(__wrap_wm_task_manager_get_task_by_agent_id_and_module, task_id);

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_DATABASE_NO_TASK);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, OS_INVALID);
    expect_string(__wrap_wm_task_manager_parse_response, status, status_result);
    will_return(__wrap_wm_task_manager_parse_response, res);

    cJSON *response = wm_task_manager_analyze_task_api_module(command, &error_code, agent_id, task_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_DATABASE_NO_TASK);
}

void test_wm_task_manager_analyze_task_api_module_upgrade_result_db_err(void **state)
{
    char *command = "upgrade_result";
    int error_code = 0;
    int agent_id = 35;
    int task_id = OS_INVALID;

    char *command_result = "upgrade";
    char *status_result = "In progress";
    int create_time = 789456123;
    int last_update = 987654321;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_get_task_by_agent_id_and_module, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_get_task_by_agent_id_and_module, module, "upgrade_module");
    will_return(__wrap_wm_task_manager_get_task_by_agent_id_and_module, command_result);
    will_return(__wrap_wm_task_manager_get_task_by_agent_id_and_module, status_result);
    will_return(__wrap_wm_task_manager_get_task_by_agent_id_and_module, create_time);
    will_return(__wrap_wm_task_manager_get_task_by_agent_id_and_module, last_update);
    will_return(__wrap_wm_task_manager_get_task_by_agent_id_and_module, task_id);

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_DATABASE_ERROR);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, OS_INVALID);
    expect_string(__wrap_wm_task_manager_parse_response, status, status_result);
    will_return(__wrap_wm_task_manager_parse_response, res);

    cJSON *response = wm_task_manager_analyze_task_api_module(command, &error_code, agent_id, task_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_DATABASE_ERROR);
}

void test_wm_task_manager_analyze_task_api_module_upgrade_result_agent_id_err(void **state)
{
    char *command = "upgrade_result";
    int error_code = 0;
    int agent_id = OS_INVALID;
    int task_id = 24;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_INVALID_AGENT_ID);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_response, res);

    cJSON *response = wm_task_manager_analyze_task_api_module(command, &error_code, agent_id, task_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_AGENT_ID);
}

void test_wm_task_manager_analyze_task_api_module_task_result_ok(void **state)
{
    char *command = "task_result";
    int error_code = 0;
    int agent_id = 35;
    int task_id = 24;

    char *module_result = "api_module";
    char *command_result = "upgrade";
    char *status_result = "In progress";
    int create_time = 789456123;
    int last_update = 987654321;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_get_task_by_task_id, task_id, task_id);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, module_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, command_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, status_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, create_time);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, last_update);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, agent_id);

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_response, res);

    expect_string(__wrap_wm_task_manager_parse_response_result, module, module_result);
    expect_string(__wrap_wm_task_manager_parse_response_result, command, command_result);
    expect_string(__wrap_wm_task_manager_parse_response_result, status, status_result);
    expect_value(__wrap_wm_task_manager_parse_response_result, create_time, create_time);
    expect_value(__wrap_wm_task_manager_parse_response_result, last_update_time, last_update);
    expect_string(__wrap_wm_task_manager_parse_response_result, request_command, command);

    cJSON *response = wm_task_manager_analyze_task_api_module(command, &error_code, agent_id, task_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_analyze_task_api_module_task_result_not_found_err(void **state)
{
    char *command = "task_result";
    int error_code = 0;
    int agent_id = OS_NOTFOUND;
    int task_id = 24;

    char *module_result = "api_module";
    char *command_result = "upgrade";
    char *status_result = "In progress";
    int create_time = 789456123;
    int last_update = 987654321;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_get_task_by_task_id, task_id, task_id);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, module_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, command_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, status_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, create_time);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, last_update);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, agent_id);

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_DATABASE_NO_TASK);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, task_id);
    expect_string(__wrap_wm_task_manager_parse_response, status, status_result);
    will_return(__wrap_wm_task_manager_parse_response, res);

    cJSON *response = wm_task_manager_analyze_task_api_module(command, &error_code, agent_id, task_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_DATABASE_NO_TASK);
}

void test_wm_task_manager_analyze_task_api_module_task_result_db_err(void **state)
{
    char *command = "task_result";
    int error_code = 0;
    int agent_id = OS_INVALID;
    int task_id = 24;

    char *module_result = "api_module";
    char *command_result = "upgrade";
    char *status_result = "In progress";
    int create_time = 789456123;
    int last_update = 987654321;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_get_task_by_task_id, task_id, task_id);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, module_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, command_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, status_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, create_time);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, last_update);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, agent_id);

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_DATABASE_ERROR);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, task_id);
    expect_string(__wrap_wm_task_manager_parse_response, status, status_result);
    will_return(__wrap_wm_task_manager_parse_response, res);

    cJSON *response = wm_task_manager_analyze_task_api_module(command, &error_code, agent_id, task_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_DATABASE_ERROR);
}

void test_wm_task_manager_analyze_task_api_module_task_result_task_id_err(void **state)
{
    char *command = "task_result";
    int error_code = 0;
    int agent_id = 35;
    int task_id = OS_INVALID;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_INVALID_TASK_ID);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_response, res);

    cJSON *response = wm_task_manager_analyze_task_api_module(command, &error_code, agent_id, task_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_TASK_ID);
}

void test_wm_task_manager_analyze_task_api_module_task_result_command_err(void **state)
{
    char *command = "unknowm";
    int error_code = 0;
    int agent_id = 35;
    int task_id = 24;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_INVALID_COMMAND);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_response, res);

    cJSON *response = wm_task_manager_analyze_task_api_module(command, &error_code, agent_id, task_id);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_COMMAND);
}

void test_wm_task_manager_analyze_task_upgrade_module_upgrade_ok(void **state)
{
    char *command = "upgrade";
    int error_code = 0;
    int agent_id = 35;
    int task_id = 24;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_insert_task, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_insert_task, module, "upgrade_module");
    expect_string(__wrap_wm_task_manager_insert_task, command, command);
    will_return(__wrap_wm_task_manager_insert_task, task_id);

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_response, res);

    cJSON *response = wm_task_manager_analyze_task_upgrade_module(command, &error_code, agent_id, task_id, NULL);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_analyze_task_upgrade_module_upgrade_custom_ok(void **state)
{
    char *command = "upgrade_custom";
    int error_code = 0;
    int agent_id = 35;
    int task_id = 24;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_insert_task, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_insert_task, module, "upgrade_module");
    expect_string(__wrap_wm_task_manager_insert_task, command, command);
    will_return(__wrap_wm_task_manager_insert_task, task_id);

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_response, res);

    cJSON *response = wm_task_manager_analyze_task_upgrade_module(command, &error_code, agent_id, task_id, NULL);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_analyze_task_upgrade_module_upgrade_db_err(void **state)
{
    char *command = "upgrade";
    int error_code = 0;
    int agent_id = 35;
    int task_id = OS_INVALID;

    expect_value(__wrap_wm_task_manager_insert_task, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_insert_task, module, "upgrade_module");
    expect_string(__wrap_wm_task_manager_insert_task, command, command);
    will_return(__wrap_wm_task_manager_insert_task, task_id);

    cJSON *response = wm_task_manager_analyze_task_upgrade_module(command, &error_code, agent_id, task_id, NULL);

    assert_null(response);
    assert_int_equal(error_code, WM_TASK_DATABASE_ERROR);
}

void test_wm_task_manager_analyze_task_upgrade_module_upgrade_agent_id_err(void **state)
{
    char *command = "upgrade";
    int error_code = 0;
    int agent_id = OS_INVALID;
    int task_id = 24;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_INVALID_AGENT_ID);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_response, res);

    cJSON *response = wm_task_manager_analyze_task_upgrade_module(command, &error_code, agent_id, task_id, NULL);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_AGENT_ID);
}

void test_wm_task_manager_analyze_task_upgrade_module_upgrade_get_status_ok(void **state)
{
    char *command = "upgrade_get_status";
    int error_code = 0;
    int agent_id = 35;

    char *status_result = "In progress";

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_get_task_status, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_get_task_status, module, "upgrade_module");
    will_return(__wrap_wm_task_manager_get_task_status, status_result);
    will_return(__wrap_wm_task_manager_get_task_status, WM_TASK_SUCCESS);

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, OS_INVALID);
    expect_string(__wrap_wm_task_manager_parse_response, status, status_result);
    will_return(__wrap_wm_task_manager_parse_response, res);

    cJSON *response = wm_task_manager_analyze_task_upgrade_module(command, &error_code, agent_id, OS_INVALID, NULL);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_analyze_task_upgrade_module_upgrade_get_status_task_err(void **state)
{
    char *command = "upgrade_get_status";
    int error_code = 0;
    int agent_id = 35;

    char *status_result = "In progress";

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_get_task_status, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_get_task_status, module, "upgrade_module");
    will_return(__wrap_wm_task_manager_get_task_status, status_result);
    will_return(__wrap_wm_task_manager_get_task_status, WM_TASK_DATABASE_NO_TASK);

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_DATABASE_NO_TASK);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_response, res);

    cJSON *response = wm_task_manager_analyze_task_upgrade_module(command, &error_code, agent_id, OS_INVALID, NULL);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_DATABASE_NO_TASK);
}

void test_wm_task_manager_analyze_task_upgrade_module_upgrade_get_status_db_err(void **state)
{
    char *command = "upgrade_get_status";
    int error_code = 0;
    int agent_id = 35;

    char *status_result = "In progress";

    expect_value(__wrap_wm_task_manager_get_task_status, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_get_task_status, module, "upgrade_module");
    will_return(__wrap_wm_task_manager_get_task_status, status_result);
    will_return(__wrap_wm_task_manager_get_task_status, OS_INVALID);

    cJSON *response = wm_task_manager_analyze_task_upgrade_module(command, &error_code, agent_id, OS_INVALID, NULL);

    assert_null(response);
    assert_int_equal(error_code, WM_TASK_DATABASE_ERROR);
}

void test_wm_task_manager_analyze_task_upgrade_module_upgrade_get_status_agent_id_err(void **state)
{
    char *command = "upgrade_get_status";
    int error_code = 0;
    int agent_id = OS_INVALID;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_INVALID_AGENT_ID);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_response, res);

    cJSON *response = wm_task_manager_analyze_task_upgrade_module(command, &error_code, agent_id, OS_INVALID, NULL);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_AGENT_ID);
}

void test_wm_task_manager_analyze_task_upgrade_module_upgrade_update_status_ok(void **state)
{
    char *command = "upgrade_update_status";
    int error_code = 0;
    int agent_id = 35;
    char *status = "Done";

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_update_task_status, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_update_task_status, module, "upgrade_module");
    expect_string(__wrap_wm_task_manager_update_task_status, status, status);
    will_return(__wrap_wm_task_manager_update_task_status, WM_TASK_SUCCESS);

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, OS_INVALID);
    expect_string(__wrap_wm_task_manager_parse_response, status, status);
    will_return(__wrap_wm_task_manager_parse_response, res);

    cJSON *response = wm_task_manager_analyze_task_upgrade_module(command, &error_code, agent_id, OS_INVALID, status);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_analyze_task_upgrade_module_upgrade_update_status_task_err(void **state)
{
    char *command = "upgrade_update_status";
    int error_code = 0;
    int agent_id = 35;
    char *status = "Done";

    char *status_result = "In progress";

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_update_task_status, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_update_task_status, module, "upgrade_module");
    expect_string(__wrap_wm_task_manager_update_task_status, status, status);
    will_return(__wrap_wm_task_manager_update_task_status, WM_TASK_DATABASE_NO_TASK);

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_DATABASE_NO_TASK);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, OS_INVALID);
    expect_string(__wrap_wm_task_manager_parse_response, status, status);
    will_return(__wrap_wm_task_manager_parse_response, res);

    cJSON *response = wm_task_manager_analyze_task_upgrade_module(command, &error_code, agent_id, OS_INVALID, status);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_DATABASE_NO_TASK);
}

void test_wm_task_manager_analyze_task_upgrade_module_upgrade_update_status_db_err(void **state)
{
    char *command = "upgrade_update_status";
    int error_code = 0;
    int agent_id = 35;
    char *status = "Done";

    expect_value(__wrap_wm_task_manager_update_task_status, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_update_task_status, module, "upgrade_module");
    expect_string(__wrap_wm_task_manager_update_task_status, status, status);
    will_return(__wrap_wm_task_manager_update_task_status, OS_INVALID);

    cJSON *response = wm_task_manager_analyze_task_upgrade_module(command, &error_code, agent_id, OS_INVALID, status);

    assert_null(response);
    assert_int_equal(error_code, WM_TASK_DATABASE_ERROR);
}

void test_wm_task_manager_analyze_task_upgrade_module_upgrade_update_status_agent_id_err(void **state)
{
    char *command = "upgrade_update_status";
    int error_code = 0;
    int agent_id = OS_INVALID;
    char *status = "Done";

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_INVALID_AGENT_ID);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, OS_INVALID);
    expect_string(__wrap_wm_task_manager_parse_response, status, status);
    will_return(__wrap_wm_task_manager_parse_response, res);

    cJSON *response = wm_task_manager_analyze_task_upgrade_module(command, &error_code, agent_id, OS_INVALID, status);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_AGENT_ID);
}

void test_wm_task_manager_analyze_task_upgrade_module_upgrade_update_status_command_err(void **state)
{
    char *command = "unknowm";
    int error_code = 0;
    int agent_id = 35;

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_INVALID_COMMAND);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_response, res);

    cJSON *response = wm_task_manager_analyze_task_upgrade_module(command, &error_code, agent_id, OS_INVALID, NULL);

    *state = response;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_COMMAND);
}

void test_wm_task_manager_analyze_task_upgrade_module_ok(void **state)
{
    int error_code = 0;
    char *command = "upgrade_update_status";
    int agent_id = 45;
    char *status = "Failed";

    cJSON *task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, "module", "upgrade_module");
    cJSON_AddStringToObject(task, "command", command);
    cJSON_AddNumberToObject(task, "agent", agent_id);
    cJSON_AddStringToObject(task, "status", status);

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_update_task_status, agent_id, agent_id);
    expect_string(__wrap_wm_task_manager_update_task_status, module, "upgrade_module");
    expect_string(__wrap_wm_task_manager_update_task_status, status, status);
    will_return(__wrap_wm_task_manager_update_task_status, WM_TASK_SUCCESS);

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, OS_INVALID);
    expect_string(__wrap_wm_task_manager_parse_response, status, status);
    will_return(__wrap_wm_task_manager_parse_response, res);

    cJSON *response = wm_task_manager_analyze_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_analyze_task_api_module_ok(void **state)
{
    int error_code = 0;
    char *command = "task_result";
    int agent_id = 45;
    int task_id = 88;

    char *module_result = "api";
    char *command_result = "upgrade";
    char *status_result = "In progress";
    int create_time = 789456123;
    int last_update = 987654321;

    cJSON *task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, "module", "api");
    cJSON_AddStringToObject(task, "command", command);
    cJSON_AddNumberToObject(task, "task_id", task_id);

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_get_task_by_task_id, task_id, task_id);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, module_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, command_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, status_result);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, create_time);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, last_update);
    will_return(__wrap_wm_task_manager_get_task_by_task_id, agent_id);

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_SUCCESS);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, agent_id);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, task_id);
    will_return(__wrap_wm_task_manager_parse_response, res);

    expect_string(__wrap_wm_task_manager_parse_response_result, module, module_result);
    expect_string(__wrap_wm_task_manager_parse_response_result, command, command_result);
    expect_string(__wrap_wm_task_manager_parse_response_result, status, status_result);
    expect_value(__wrap_wm_task_manager_parse_response_result, create_time, create_time);
    expect_value(__wrap_wm_task_manager_parse_response_result, last_update_time, last_update);
    expect_string(__wrap_wm_task_manager_parse_response_result, request_command, command);

    cJSON *response = wm_task_manager_analyze_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, 0);
}

void test_wm_task_manager_analyze_task_module_err(void **state)
{
    int error_code = 0;
    char *command = "unknown";

    cJSON *task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, "module", "unknown");
    cJSON_AddStringToObject(task, "command", command);
    cJSON_AddStringToObject(task, "agent", "1");
    cJSON_AddStringToObject(task, "task_id", "5");
    cJSON_AddNumberToObject(task, "status", 3);

    cJSON* res = cJSON_CreateObject();

    expect_value(__wrap_wm_task_manager_parse_response, error_code, WM_TASK_INVALID_MODULE);
    expect_value(__wrap_wm_task_manager_parse_response, agent_id, OS_INVALID);
    expect_value(__wrap_wm_task_manager_parse_response, task_id, OS_INVALID);
    will_return(__wrap_wm_task_manager_parse_response, res);

    cJSON *response = wm_task_manager_analyze_task(task, &error_code);

    state[0] = response;
    state[1] = task;

    assert_non_null(response);
    assert_memory_equal(response, res, sizeof(response));
    assert_int_equal(error_code, WM_TASK_INVALID_MODULE);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_task_manager_analyze_task_api_module
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_api_module_upgrade_result_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_api_module_upgrade_result_not_found_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_api_module_upgrade_result_db_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_api_module_upgrade_result_agent_id_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_api_module_task_result_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_api_module_task_result_not_found_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_api_module_task_result_db_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_api_module_task_result_task_id_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_api_module_task_result_command_err, teardown_json),
        // wm_task_manager_analyze_task_upgrade_module
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_upgrade_module_upgrade_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_upgrade_module_upgrade_custom_ok, teardown_json),
        cmocka_unit_test(test_wm_task_manager_analyze_task_upgrade_module_upgrade_db_err),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_upgrade_module_upgrade_agent_id_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_upgrade_module_upgrade_get_status_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_upgrade_module_upgrade_get_status_task_err, teardown_json),
        cmocka_unit_test(test_wm_task_manager_analyze_task_upgrade_module_upgrade_get_status_db_err),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_upgrade_module_upgrade_get_status_agent_id_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_upgrade_module_upgrade_update_status_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_upgrade_module_upgrade_update_status_task_err, teardown_json),
        cmocka_unit_test(test_wm_task_manager_analyze_task_upgrade_module_upgrade_update_status_db_err),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_upgrade_module_upgrade_update_status_agent_id_err, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_upgrade_module_upgrade_update_status_command_err, teardown_json),
        // wm_task_manager_analyze_task
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_upgrade_module_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_api_module_ok, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_analyze_task_module_err, teardown_json)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
