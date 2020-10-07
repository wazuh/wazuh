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

#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_agent_upgrade_wrappers.h"

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

// Tests

void test_wm_agent_upgrade_upgrade_success_callback_ok(void **state)
{
    int error = 0;
    int agent = 9;
    int task = 35;
    char *data = "Success";
    cJSON *input = cJSON_CreateObject();

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

    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, agent);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, task);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, data);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, 1);

    expect_value(__wrap_wm_agent_upgrade_remove_entry, agent_id, agent);
    expect_value(__wrap_wm_agent_upgrade_remove_entry, free, 1);
    will_return(__wrap_wm_agent_upgrade_remove_entry, 0);

    expect_value(__wrap_wm_agent_upgrade_parse_data_response, error_id, WM_UPGRADE_TASK_MANAGER_FAILURE);
    expect_string(__wrap_wm_agent_upgrade_parse_data_response, message, data);
    expect_value(__wrap_wm_agent_upgrade_parse_data_response, agent_int, agent);
    will_return(__wrap_wm_agent_upgrade_parse_data_response, error_json);

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

void test_wm_agent_upgrade_task_module_callback_no_callbacks_ok(void **state)
{
    cJSON *output = cJSON_CreateArray();

    cJSON *input = cJSON_CreateObject();
    cJSON *origin = cJSON_CreateObject();
    cJSON *parameters = cJSON_CreateObject();
    cJSON *agents = cJSON_CreateArray();

    cJSON_AddStringToObject(origin, "module", "upgrade_module");
    cJSON_AddItemToObject(input, "origin", origin);
    cJSON_AddStringToObject(input, "command", "upgrade");
    cJSON_AddItemToArray(agents, cJSON_CreateNumber(12));
    cJSON_AddItemToArray(agents, cJSON_CreateNumber(10));
    cJSON_AddItemToObject(parameters, "agents", agents);
    cJSON_AddItemToObject(input, "parameters", parameters);

    cJSON *task_response = cJSON_CreateObject();
    cJSON *data = cJSON_CreateArray();
    cJSON *task1 = cJSON_CreateObject();
    cJSON *task2 = cJSON_CreateObject();

    cJSON_AddNumberToObject(task1, "error", 0);
    cJSON_AddStringToObject(task1, "message", "Success");
    cJSON_AddNumberToObject(task1, "agent", 12);
    cJSON_AddItemToArray(data, task1);

    cJSON_AddNumberToObject(task2, "error", 1);
    cJSON_AddStringToObject(task2, "message", "Error");
    cJSON_AddNumberToObject(task2, "agent", 10);
    cJSON_AddItemToArray(data, task2);

    cJSON_AddNumberToObject(task_response, "error", 0);
    cJSON_AddItemToObject(task_response, "data", data);
    cJSON_AddStringToObject(task_response, "message", "Success");

    expect_memory(__wrap_wm_agent_upgrade_send_tasks_information, message_object, input, sizeof(input));
    will_return(__wrap_wm_agent_upgrade_send_tasks_information, task_response);

    int result = wm_agent_upgrade_task_module_callback(output, input, NULL, NULL);

    state[0] = (void *)input;
    state[1] = (void *)output;

    assert_int_equal(result, 0);
    assert_int_equal(cJSON_GetArraySize(output), 2);
    cJSON *out1 = cJSON_GetArrayItem(output, 0);
    assert_non_null(cJSON_GetObjectItem(out1, "error"));
    assert_int_equal(cJSON_GetObjectItem(out1, "error")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(out1, "message"));
    assert_string_equal(cJSON_GetObjectItem(out1, "message")->valuestring, "Success");
    assert_non_null(cJSON_GetObjectItem(out1, "agent"));
    assert_int_equal(cJSON_GetObjectItem(out1, "agent")->valueint, 12);
    cJSON *out2 = cJSON_GetArrayItem(output, 1);
    assert_non_null(cJSON_GetObjectItem(out2, "error"));
    assert_int_equal(cJSON_GetObjectItem(out2, "error")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(out2, "message"));
    assert_string_equal(cJSON_GetObjectItem(out2, "message")->valuestring, "Error");
    assert_non_null(cJSON_GetObjectItem(out2, "agent"));
    assert_int_equal(cJSON_GetObjectItem(out2, "agent")->valueint, 10);
    assert_null(cJSON_GetArrayItem(output, 2));
}

void test_wm_agent_upgrade_task_module_callback_success_callback_ok(void **state)
{
    cJSON *output = cJSON_CreateArray();

    cJSON *input = cJSON_CreateObject();
    cJSON *origin = cJSON_CreateObject();
    cJSON *parameters = cJSON_CreateObject();
    cJSON *agents = cJSON_CreateArray();

    cJSON_AddStringToObject(origin, "module", "upgrade_module");
    cJSON_AddItemToObject(input, "origin", origin);
    cJSON_AddStringToObject(input, "command", "upgrade");
    cJSON_AddItemToArray(agents, cJSON_CreateNumber(12));
    cJSON_AddItemToArray(agents, cJSON_CreateNumber(10));
    cJSON_AddItemToObject(parameters, "agents", agents);
    cJSON_AddItemToObject(input, "parameters", parameters);

    cJSON *task_response = cJSON_CreateObject();
    cJSON *data = cJSON_CreateArray();
    cJSON *task1 = cJSON_CreateObject();
    cJSON *task2 = cJSON_CreateObject();

    cJSON_AddNumberToObject(task1, "error", 0);
    cJSON_AddStringToObject(task1, "message", "Success");
    cJSON_AddNumberToObject(task1, "agent", 12);
    cJSON_AddNumberToObject(task1, "task_id", 115);
    cJSON_AddItemToArray(data, task1);

    cJSON_AddNumberToObject(task2, "error", 1);
    cJSON_AddStringToObject(task2, "message", "Error");
    cJSON_AddNumberToObject(task2, "agent", 10);
    cJSON_AddItemToArray(data, task2);

    cJSON_AddNumberToObject(task_response, "error", 0);
    cJSON_AddItemToObject(task_response, "data", data);
    cJSON_AddStringToObject(task_response, "message", "Success");

    cJSON *error_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(error_json, "error", 1);
    cJSON_AddStringToObject(error_json, "message", "Error");
    cJSON_AddNumberToObject(error_json, "agent", 10);

    expect_memory(__wrap_wm_agent_upgrade_send_tasks_information, message_object, input, sizeof(input));
    will_return(__wrap_wm_agent_upgrade_send_tasks_information, task_response);

    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, 12);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, 115);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, "Success");
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, 1);

    expect_value(__wrap_wm_agent_upgrade_insert_task_id, agent_id, 12);
    expect_value(__wrap_wm_agent_upgrade_insert_task_id, task_id, 115);

    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, 10);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, 0);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, "Error");
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, 1);

    expect_value(__wrap_wm_agent_upgrade_remove_entry, agent_id, 10);
    expect_value(__wrap_wm_agent_upgrade_remove_entry, free, 1);
    will_return(__wrap_wm_agent_upgrade_remove_entry, 0);

    expect_value(__wrap_wm_agent_upgrade_parse_data_response, error_id, WM_UPGRADE_TASK_MANAGER_FAILURE);
    expect_string(__wrap_wm_agent_upgrade_parse_data_response, message, "Error");
    expect_value(__wrap_wm_agent_upgrade_parse_data_response, agent_int, 10);
    will_return(__wrap_wm_agent_upgrade_parse_data_response, error_json);

    int result = wm_agent_upgrade_task_module_callback(output, input, wm_agent_upgrade_upgrade_success_callback, NULL);

    state[0] = (void *)input;
    state[1] = (void *)output;

    assert_int_equal(result, 0);
    assert_int_equal(cJSON_GetArraySize(output), 2);
    cJSON *out1 = cJSON_GetArrayItem(output, 0);
    assert_non_null(cJSON_GetObjectItem(out1, "error"));
    assert_int_equal(cJSON_GetObjectItem(out1, "error")->valueint, 0);
    assert_non_null(cJSON_GetObjectItem(out1, "message"));
    assert_string_equal(cJSON_GetObjectItem(out1, "message")->valuestring, "Success");
    assert_non_null(cJSON_GetObjectItem(out1, "agent"));
    assert_int_equal(cJSON_GetObjectItem(out1, "agent")->valueint, 12);
    assert_non_null(cJSON_GetObjectItem(out1, "task_id"));
    assert_int_equal(cJSON_GetObjectItem(out1, "task_id")->valueint, 115);
    cJSON *out2 = cJSON_GetArrayItem(output, 1);
    assert_non_null(cJSON_GetObjectItem(out2, "error"));
    assert_int_equal(cJSON_GetObjectItem(out2, "error")->valueint, 1);
    assert_non_null(cJSON_GetObjectItem(out2, "message"));
    assert_string_equal(cJSON_GetObjectItem(out2, "message")->valuestring, "Error");
    assert_non_null(cJSON_GetObjectItem(out2, "agent"));
    assert_int_equal(cJSON_GetObjectItem(out2, "agent")->valueint, 10);
    assert_null(cJSON_GetObjectItem(out2, "task_id"));
    assert_null(cJSON_GetArrayItem(output, 2));
}

void test_wm_agent_upgrade_task_module_callback_no_callbacks_error(void **state)
{
    cJSON *output = cJSON_CreateArray();

    cJSON *input = cJSON_CreateObject();
    cJSON *origin = cJSON_CreateObject();
    cJSON *parameters = cJSON_CreateObject();
    cJSON *agents = cJSON_CreateArray();

    cJSON_AddStringToObject(origin, "module", "upgrade_module");
    cJSON_AddItemToObject(input, "origin", origin);
    cJSON_AddStringToObject(input, "command", "upgrade");
    cJSON_AddItemToArray(agents, cJSON_CreateNumber(12));
    cJSON_AddItemToArray(agents, cJSON_CreateNumber(10));
    cJSON_AddItemToObject(parameters, "agents", agents);
    cJSON_AddItemToObject(input, "parameters", parameters);

    cJSON *task_response = cJSON_CreateObject();
    cJSON *data = cJSON_CreateArray();

    cJSON_AddNumberToObject(task_response, "error", 1);
    cJSON_AddItemToObject(task_response, "data", data);
    cJSON_AddStringToObject(task_response, "message", "Error");

    cJSON *error1 = cJSON_CreateObject();
    cJSON *error2 = cJSON_CreateObject();

    cJSON_AddNumberToObject(error1, "error", WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
    cJSON_AddStringToObject(error1, "message", upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION]);
    cJSON_AddNumberToObject(error1, "agent", 12);

    cJSON_AddNumberToObject(error2, "error", WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
    cJSON_AddStringToObject(error2, "message", upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION]);
    cJSON_AddNumberToObject(error2, "agent", 10);

    expect_memory(__wrap_wm_agent_upgrade_send_tasks_information, message_object, input, sizeof(input));
    will_return(__wrap_wm_agent_upgrade_send_tasks_information, task_response);

    expect_value(__wrap_wm_agent_upgrade_parse_data_response, error_id, WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
    expect_string(__wrap_wm_agent_upgrade_parse_data_response, message, upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION]);
    expect_value(__wrap_wm_agent_upgrade_parse_data_response, agent_int, 12);
    will_return(__wrap_wm_agent_upgrade_parse_data_response, error1);

    expect_value(__wrap_wm_agent_upgrade_parse_data_response, error_id, WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
    expect_string(__wrap_wm_agent_upgrade_parse_data_response, message, upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION]);
    expect_value(__wrap_wm_agent_upgrade_parse_data_response, agent_int, 10);
    will_return(__wrap_wm_agent_upgrade_parse_data_response, error2);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8123): There has been an error executing the request in the tasks manager.");

    int result = wm_agent_upgrade_task_module_callback(output, input, NULL, NULL);

    state[0] = (void *)input;
    state[1] = (void *)output;

    assert_int_equal(result, OS_INVALID);
    assert_int_equal(cJSON_GetArraySize(output), 2);
    cJSON *out1 = cJSON_GetArrayItem(output, 0);
    assert_non_null(cJSON_GetObjectItem(out1, "error"));
    assert_int_equal(cJSON_GetObjectItem(out1, "error")->valueint, WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
    assert_non_null(cJSON_GetObjectItem(out1, "message"));
    assert_string_equal(cJSON_GetObjectItem(out1, "message")->valuestring, upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION]);
    assert_non_null(cJSON_GetObjectItem(out1, "agent"));
    assert_int_equal(cJSON_GetObjectItem(out1, "agent")->valueint, 12);
    cJSON *out2 = cJSON_GetArrayItem(output, 1);
    assert_non_null(cJSON_GetObjectItem(out2, "error"));
    assert_int_equal(cJSON_GetObjectItem(out2, "error")->valueint, WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
    assert_non_null(cJSON_GetObjectItem(out2, "message"));
    assert_string_equal(cJSON_GetObjectItem(out2, "message")->valuestring, upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION]);
    assert_non_null(cJSON_GetObjectItem(out2, "agent"));
    assert_int_equal(cJSON_GetObjectItem(out2, "agent")->valueint, 10);
    assert_null(cJSON_GetArrayItem(output, 2));
}

void test_wm_agent_upgrade_task_module_callback_error_callback_error(void **state)
{
    cJSON *output = cJSON_CreateArray();

    cJSON *input = cJSON_CreateObject();
    cJSON *origin = cJSON_CreateObject();
    cJSON *parameters = cJSON_CreateObject();
    cJSON *agents = cJSON_CreateArray();

    cJSON_AddStringToObject(origin, "module", "upgrade_module");
    cJSON_AddItemToObject(input, "origin", origin);
    cJSON_AddStringToObject(input, "command", "upgrade");
    cJSON_AddItemToArray(agents, cJSON_CreateNumber(12));
    cJSON_AddItemToArray(agents, cJSON_CreateNumber(10));
    cJSON_AddItemToObject(parameters, "agents", agents);
    cJSON_AddItemToObject(input, "parameters", parameters);

    cJSON *task_response = cJSON_CreateObject();
    cJSON *data = cJSON_CreateArray();

    cJSON_AddNumberToObject(task_response, "error", 1);
    cJSON_AddItemToObject(task_response, "data", data);
    cJSON_AddStringToObject(task_response, "message", "Error");

    cJSON *error1 = cJSON_CreateObject();
    cJSON *error2 = cJSON_CreateObject();

    cJSON_AddNumberToObject(error1, "error", WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
    cJSON_AddStringToObject(error1, "message", upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION]);
    cJSON_AddNumberToObject(error1, "agent", 12);

    cJSON_AddNumberToObject(error2, "error", WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
    cJSON_AddStringToObject(error2, "message", upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION]);
    cJSON_AddNumberToObject(error2, "agent", 10);

    expect_memory(__wrap_wm_agent_upgrade_send_tasks_information, message_object, input, sizeof(input));
    will_return(__wrap_wm_agent_upgrade_send_tasks_information, task_response);

    expect_value(__wrap_wm_agent_upgrade_remove_entry, agent_id, 12);
    expect_value(__wrap_wm_agent_upgrade_remove_entry, free, 1);
    will_return(__wrap_wm_agent_upgrade_remove_entry, 0);

    expect_value(__wrap_wm_agent_upgrade_parse_data_response, error_id, WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
    expect_string(__wrap_wm_agent_upgrade_parse_data_response, message, upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION]);
    expect_value(__wrap_wm_agent_upgrade_parse_data_response, agent_int, 12);
    will_return(__wrap_wm_agent_upgrade_parse_data_response, error1);

    expect_value(__wrap_wm_agent_upgrade_remove_entry, agent_id, 10);
    expect_value(__wrap_wm_agent_upgrade_remove_entry, free, 1);
    will_return(__wrap_wm_agent_upgrade_remove_entry, 0);

    expect_value(__wrap_wm_agent_upgrade_parse_data_response, error_id, WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
    expect_string(__wrap_wm_agent_upgrade_parse_data_response, message, upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION]);
    expect_value(__wrap_wm_agent_upgrade_parse_data_response, agent_int, 10);
    will_return(__wrap_wm_agent_upgrade_parse_data_response, error2);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8123): There has been an error executing the request in the tasks manager.");

    int result = wm_agent_upgrade_task_module_callback(output, input, NULL, wm_agent_upgrade_remove_entry);

    state[0] = (void *)input;
    state[1] = (void *)output;

    assert_int_equal(result, OS_INVALID);
    assert_int_equal(cJSON_GetArraySize(output), 2);
    cJSON *out1 = cJSON_GetArrayItem(output, 0);
    assert_non_null(cJSON_GetObjectItem(out1, "error"));
    assert_int_equal(cJSON_GetObjectItem(out1, "error")->valueint, WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
    assert_non_null(cJSON_GetObjectItem(out1, "message"));
    assert_string_equal(cJSON_GetObjectItem(out1, "message")->valuestring, upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION]);
    assert_non_null(cJSON_GetObjectItem(out1, "agent"));
    assert_int_equal(cJSON_GetObjectItem(out1, "agent")->valueint, 12);
    cJSON *out2 = cJSON_GetArrayItem(output, 1);
    assert_non_null(cJSON_GetObjectItem(out2, "error"));
    assert_int_equal(cJSON_GetObjectItem(out2, "error")->valueint, WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
    assert_non_null(cJSON_GetObjectItem(out2, "message"));
    assert_string_equal(cJSON_GetObjectItem(out2, "message")->valuestring, upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION]);
    assert_non_null(cJSON_GetObjectItem(out2, "agent"));
    assert_int_equal(cJSON_GetObjectItem(out2, "agent")->valueint, 10);
    assert_null(cJSON_GetArrayItem(output, 2));
}

void test_wm_agent_upgrade_task_module_callback_success_error_callback_error(void **state)
{
    cJSON *output = cJSON_CreateArray();

    cJSON *input = cJSON_CreateObject();
    cJSON *origin = cJSON_CreateObject();
    cJSON *parameters = cJSON_CreateObject();
    cJSON *agents = cJSON_CreateArray();

    cJSON_AddStringToObject(origin, "module", "upgrade_module");
    cJSON_AddItemToObject(input, "origin", origin);
    cJSON_AddStringToObject(input, "command", "upgrade");
    cJSON_AddItemToArray(agents, cJSON_CreateNumber(12));
    cJSON_AddItemToArray(agents, cJSON_CreateNumber(10));
    cJSON_AddItemToObject(parameters, "agents", agents);
    cJSON_AddItemToObject(input, "parameters", parameters);

    cJSON *task_response = cJSON_CreateObject();
    cJSON *data = cJSON_CreateArray();
    cJSON *task1 = cJSON_CreateObject();
    cJSON *task2 = cJSON_CreateObject();

    cJSON_AddNumberToObject(task1, "error", 0);
    cJSON_AddStringToObject(task1, "message", "Success");
    cJSON_AddNumberToObject(task1, "agent", 12);
    cJSON_AddNumberToObject(task1, "task_id", 115);
    cJSON_AddItemToArray(data, task1);

    cJSON_AddNumberToObject(task2, "error", 0);
    cJSON_AddStringToObject(task2, "message", "Success");
    cJSON_AddNumberToObject(task2, "agent", 10);
    cJSON_AddNumberToObject(task2, "task_id", 116);
    cJSON_AddItemToArray(data, task2);

    cJSON_AddNumberToObject(task_response, "error", 0);
    cJSON_AddItemToObject(task_response, "data", data);
    cJSON_AddStringToObject(task_response, "message", "Success");

    cJSON *error1 = cJSON_CreateObject();
    cJSON *error2 = cJSON_CreateObject();

    cJSON_AddNumberToObject(error1, "error", WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
    cJSON_AddStringToObject(error1, "message", upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION]);
    cJSON_AddNumberToObject(error1, "agent", 12);

    cJSON_AddNumberToObject(error2, "error", WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
    cJSON_AddStringToObject(error2, "message", upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION]);
    cJSON_AddNumberToObject(error2, "agent", 10);

    expect_memory(__wrap_wm_agent_upgrade_send_tasks_information, message_object, input, sizeof(input));
    will_return(__wrap_wm_agent_upgrade_send_tasks_information, task_response);

    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, 12);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, 115);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, "Success");
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, 1);

    expect_value(__wrap_wm_agent_upgrade_insert_task_id, agent_id, 12);
    expect_value(__wrap_wm_agent_upgrade_insert_task_id, task_id, 115);

    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, 10);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, 116);
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, "Error");
    will_return(__wrap_wm_agent_upgrade_validate_task_ids_message, 0);

    expect_value(__wrap_wm_agent_upgrade_remove_entry, agent_id, 12);
    expect_value(__wrap_wm_agent_upgrade_remove_entry, free, 1);
    will_return(__wrap_wm_agent_upgrade_remove_entry, 0);

    expect_value(__wrap_wm_agent_upgrade_parse_data_response, error_id, WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
    expect_string(__wrap_wm_agent_upgrade_parse_data_response, message, upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION]);
    expect_value(__wrap_wm_agent_upgrade_parse_data_response, agent_int, 12);
    will_return(__wrap_wm_agent_upgrade_parse_data_response, error1);

    expect_value(__wrap_wm_agent_upgrade_remove_entry, agent_id, 10);
    expect_value(__wrap_wm_agent_upgrade_remove_entry, free, 1);
    will_return(__wrap_wm_agent_upgrade_remove_entry, 0);

    expect_value(__wrap_wm_agent_upgrade_parse_data_response, error_id, WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
    expect_string(__wrap_wm_agent_upgrade_parse_data_response, message, upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION]);
    expect_value(__wrap_wm_agent_upgrade_parse_data_response, agent_int, 10);
    will_return(__wrap_wm_agent_upgrade_parse_data_response, error2);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8123): There has been an error executing the request in the tasks manager.");

    int result = wm_agent_upgrade_task_module_callback(output, input, wm_agent_upgrade_upgrade_success_callback, wm_agent_upgrade_remove_entry);

    state[0] = (void *)input;
    state[1] = (void *)output;

    assert_int_equal(result, OS_INVALID);
    assert_int_equal(cJSON_GetArraySize(output), 2);
    cJSON *out1 = cJSON_GetArrayItem(output, 0);
    assert_non_null(cJSON_GetObjectItem(out1, "error"));
    assert_int_equal(cJSON_GetObjectItem(out1, "error")->valueint, WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
    assert_non_null(cJSON_GetObjectItem(out1, "message"));
    assert_string_equal(cJSON_GetObjectItem(out1, "message")->valuestring, upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION]);
    assert_non_null(cJSON_GetObjectItem(out1, "agent"));
    assert_int_equal(cJSON_GetObjectItem(out1, "agent")->valueint, 12);
    cJSON *out2 = cJSON_GetArrayItem(output, 1);
    assert_non_null(cJSON_GetObjectItem(out2, "error"));
    assert_int_equal(cJSON_GetObjectItem(out2, "error")->valueint, WM_UPGRADE_TASK_MANAGER_COMMUNICATION);
    assert_non_null(cJSON_GetObjectItem(out2, "message"));
    assert_string_equal(cJSON_GetObjectItem(out2, "message")->valuestring, upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION]);
    assert_non_null(cJSON_GetObjectItem(out2, "agent"));
    assert_int_equal(cJSON_GetObjectItem(out2, "agent")->valueint, 10);
    assert_null(cJSON_GetArrayItem(output, 2));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_agent_upgrade_upgrade_success_callback
        cmocka_unit_test_teardown(test_wm_agent_upgrade_upgrade_success_callback_ok, teardown_jsons),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_upgrade_success_callback_no_task_id, teardown_jsons),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_upgrade_success_callback_validate_error, teardown_jsons),
        // wm_agent_upgrade_update_status_success_callback
        cmocka_unit_test_teardown(test_wm_agent_upgrade_update_status_success_callback_ok, teardown_jsons),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_update_status_success_callback_delete_error, teardown_jsons),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_update_status_success_validate_error, teardown_jsons),
        // wm_agent_upgrade_task_module_callback
        cmocka_unit_test_teardown(test_wm_agent_upgrade_task_module_callback_no_callbacks_ok, teardown_jsons),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_task_module_callback_success_callback_ok, teardown_jsons),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_task_module_callback_no_callbacks_error, teardown_jsons),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_task_module_callback_error_callback_error, teardown_jsons),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_task_module_callback_success_error_callback_error, teardown_jsons)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
