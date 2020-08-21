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
#include "../../wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_tasks.h"
#include "../../headers/shared.h"

// Setup / teardown

static int teardown_jsons(void **state) {
    cJSON *json1 = state[0];
    cJSON *json2 = state[1];
    if (json1 != json2) {
        cJSON_Delete(json2);
    }
    cJSON_Delete(json1);
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

bool __wrap_wm_agent_upgrade_validate_task_ids_message(const cJSON *input_json, int *agent_id, int *task_id, char** data) {
    check_expected(input_json);
    if (agent_id) *agent_id = mock();
    if (task_id) *task_id = mock();
    if (data) os_strdup(mock_type(char *), *data);

    return mock();
}

void __wrap_wm_agent_upgrade_insert_task_id(int agent_id, int task_id) {
    check_expected(agent_id);
    check_expected(task_id);
}

void __wrap_wm_agent_upgrade_remove_entry(int agent_id) {
    check_expected(agent_id);
}

cJSON* __wrap_wm_agent_upgrade_parse_response_message(int error_id, const char* message, const int *agent_id, const int* task_id, const char* status) {
    int agent_int;
    int task_int;

    check_expected(error_id);
    check_expected(message);
    if (agent_id) {
        agent_int = *agent_id;
        check_expected(agent_int);
    }
    if (task_id) {
        task_int = *task_id;
        check_expected(task_int);
    }
    if (status) {
        check_expected(status);
    }

    return mock_type(cJSON *);
}

bool __wrap_wm_agent_upgrade_validate_task_status_message(const cJSON *input_json, char **status, int *agent_id) {
    check_expected(input_json);
    if (status) os_strdup(mock_type(char *), *status);
    if (agent_id) *agent_id = mock();

    return mock();
}

char* __wrap_wm_agent_upgrade_send_command_to_agent(const char *command, const size_t command_size) {
    check_expected(command);
    check_expected(command_size);

    return mock_type(char *);
}

int __wrap_wm_agent_upgrade_parse_agent_response(const char* agent_response, char **data) {
    check_expected(agent_response);

    return mock();
}

#ifdef TEST_SERVER

// Tests

void test_wm_agent_upgrade_upgrade_success_callback_ok(void **state)
{
    int error = 0;
    int agent = 9;
    int task = 35;
    char *data = "Success";
    cJSON *input = cJSON_CreateObject();

    expect_memory(__wrap_wm_agent_upgrade_validate_task_ids_message, input_json, input, sizeof(input));
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, agent);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, task);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, data);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, 1);

    expect_value(__wrap_wm_agent_upgrade_insert_task_id, agent_id, agent);
    expect_value(__wrap_wm_agent_upgrade_insert_task_id, task_id, task);

    cJSON *response = wm_agent_upgrade_upgrade_success_callback(&error, input);

    state[0] = (void *)input;
    state[1] = (void *)response;

    assert_int_equal(error, 0);
    assert_memory_equal(response, input, sizeof(input));
}

void test_wm_agent_upgrade_upgrade_success_callback_no_task_id(void **state)
{
    int error = 0;
    int agent = 9;
    int task = 0;
    char *data = "No task ID";
    cJSON *input = cJSON_CreateObject();
    cJSON *error_json = cJSON_CreateObject();

    expect_memory(__wrap_wm_agent_upgrade_validate_task_ids_message, input_json, input, sizeof(input));
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, agent);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, task);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, data);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, 1);

    expect_value(__wrap_wm_agent_upgrade_remove_entry, agent_id, agent);

    expect_value(__wrap_wm_agent_upgrade_parse_response_message, error_id, WM_UPGRADE_TASK_MANAGER_FAILURE);
    expect_string(__wrap_wm_agent_upgrade_parse_response_message, message, data);
    expect_value(__wrap_wm_agent_upgrade_parse_response_message, agent_int, agent);
    will_return(__wrap_wm_agent_upgrade_parse_response_message, error_json);

    cJSON *response = wm_agent_upgrade_upgrade_success_callback(&error, input);

    state[0] = (void *)input;
    state[1] = (void *)response;

    assert_int_equal(error, 0);
    assert_memory_equal(response, input, sizeof(input));
}

void test_wm_agent_upgrade_upgrade_success_callback_validate_error(void **state)
{
    int error = 0;
    int agent = 9;
    int task = 35;
    char *data = "Error";
    cJSON *input = cJSON_CreateObject();

    expect_memory(__wrap_wm_agent_upgrade_validate_task_ids_message, input_json, input, sizeof(input));
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, agent);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, task);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, data);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, 0);

    cJSON *response = wm_agent_upgrade_upgrade_success_callback(&error, input);

    state[0] = (void *)input;
    state[1] = (void *)response;

    assert_int_equal(error, OS_INVALID);
    assert_memory_equal(response, input, sizeof(input));
}

void test_wm_agent_upgrade_update_status_success_callback_ok(void **state)
{
    int error = 0;
    int agent = 15;
    cJSON *input = cJSON_CreateObject();
    char *cmd = "015 com clear_upgrade_result -1";
    char *agent_res = NULL;

    os_calloc(4, sizeof(char), agent_res);
    snprintf(agent_res, 4, "ok ");

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, input, sizeof(input));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, agent);
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    expect_string(__wrap_wm_agent_upgrade_send_command_to_agent, command, cmd);
    expect_value(__wrap_wm_agent_upgrade_send_command_to_agent, command_size, strlen(cmd));
    will_return(__wrap_wm_agent_upgrade_send_command_to_agent, agent_res);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, 0);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8167): Upgrade result file has been successfully erased from the agent.");

    cJSON *result = wm_agent_upgrade_update_status_success_callback(&error, input);

    state[0] = (void *)input;
    state[1] = (void *)result;

    assert_int_equal(error, 0);
    assert_memory_equal(result, input, sizeof(input));
}

void test_wm_agent_upgrade_update_status_success_callback_delete_error(void **state)
{
    int error = 0;
    int agent = 15;
    cJSON *input = cJSON_CreateObject();
    char *cmd = "015 com clear_upgrade_result -1";
    char *agent_res = NULL;

    os_calloc(4, sizeof(char), agent_res);
    snprintf(agent_res, 4, "ok ");

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, input, sizeof(input));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, agent);
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    expect_string(__wrap_wm_agent_upgrade_send_command_to_agent, command, cmd);
    expect_value(__wrap_wm_agent_upgrade_send_command_to_agent, command_size, strlen(cmd));
    will_return(__wrap_wm_agent_upgrade_send_command_to_agent, agent_res);

    expect_string(__wrap_wm_agent_upgrade_parse_agent_response, agent_response, agent_res);
    will_return(__wrap_wm_agent_upgrade_parse_agent_response, OS_INVALID);

    cJSON *result = wm_agent_upgrade_update_status_success_callback(&error, input);

    state[0] = (void *)input;
    state[1] = (void *)result;

    assert_int_equal(error, OS_INVALID);
    assert_memory_equal(result, input, sizeof(input));
}

void test_wm_agent_upgrade_update_status_success_validate_error(void **state)
{
    int error = 0;
    int agent = 0;
    cJSON *input = cJSON_CreateObject();

    expect_memory(__wrap_wm_agent_upgrade_validate_task_status_message, input_json, input, sizeof(input));
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, agent);
    will_return(__wrap_wm_agent_upgrade_validate_task_status_message, 1);

    cJSON *result = wm_agent_upgrade_update_status_success_callback(&error, input);

    state[0] = (void *)input;
    state[1] = (void *)result;

    assert_int_equal(error, OS_INVALID);
    assert_memory_equal(result, input, sizeof(input));
}

#endif

int main(void) {
    const struct CMUnitTest tests[] = {
#ifdef TEST_SERVER
        // wm_agent_upgrade_upgrade_success_callback
        cmocka_unit_test_teardown(test_wm_agent_upgrade_upgrade_success_callback_ok, teardown_jsons),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_upgrade_success_callback_no_task_id, teardown_jsons),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_upgrade_success_callback_validate_error, teardown_jsons),
        // wm_agent_upgrade_update_status_success_callback
        cmocka_unit_test_teardown(test_wm_agent_upgrade_update_status_success_callback_ok, teardown_jsons),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_update_status_success_callback_delete_error, teardown_jsons),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_update_status_success_validate_error, teardown_jsons),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
