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
    if (*state) {
        cJSON *json = *state;
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
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
