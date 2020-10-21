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
#include "../../wrappers/wazuh/shared/time_op_wrappers.h"

#include "../../wazuh_modules/wmodules.h"
#include "../../wazuh_modules/task_manager/wm_task_manager_parsing.h"
#include "../../wazuh_modules/task_manager/wm_task_manager_tasks.h"
#include "../../headers/shared.h"

const char* wm_task_manager_decode_status(char *status);

// Setup / teardown

static int teardown_json(void **state) {
    if (*state) {
        cJSON *json = *state;
        cJSON_Delete(json);
    }
    return 0;
}

static int teardown_parse_task(void **state) {
    if (state[0]) {
        wm_task_manager_task *task = (wm_task_manager_task*)state[0];
        wm_task_manager_free_task(task);
    }
    return 0;
}

// Tests

void test_wm_task_manager_decode_status_done(void **state)
{
    char *status = "Done";

    const char *ret = wm_task_manager_decode_status(status);

    assert_string_equal(ret, "Updated");
}

void test_wm_task_manager_decode_status_pending(void **state)
{
    char *status = "Pending";

    const char *ret = wm_task_manager_decode_status(status);

    assert_string_equal(ret, "In queue");
}

void test_wm_task_manager_decode_status_in_progress(void **state)
{
    char *status = "In progress";

    const char *ret = wm_task_manager_decode_status(status);

    assert_string_equal(ret, "Updating");
}

void test_wm_task_manager_decode_status_failed(void **state)
{
    char *status = "Failed";

    const char *ret = wm_task_manager_decode_status(status);

    assert_string_equal(ret, "Error");
}

void test_wm_task_manager_decode_status_cancelled(void **state)
{
    char *status = "Cancelled";

    const char *ret = wm_task_manager_decode_status(status);

    assert_string_equal(ret, "Task cancelled since the manager was restarted");
}

void test_wm_task_manager_decode_status_timeout(void **state)
{
    char *status = "Timeout";

    const char *ret = wm_task_manager_decode_status(status);

    assert_string_equal(ret, "Timeout reached while waiting for the response from the agent");
}

void test_wm_task_manager_decode_status_legacy(void **state)
{
    char *status = "Legacy";

    const char *ret = wm_task_manager_decode_status(status);

    assert_string_equal(ret, "Legacy upgrade: check the result manually since the agent cannot report the result of the task");
}

void test_wm_task_manager_decode_status_unknown(void **state)
{
    char *status = "No status";

    const char *ret = wm_task_manager_decode_status(status);

    assert_string_equal(ret, "Invalid status");
}

void test_wm_task_manager_parse_data_response(void **state)
{
    int error_code = 0;
    int agent_id = 77;
    int task_id = 124;
    char *status = "In progress";

    cJSON *response = wm_task_manager_parse_data_response(error_code, agent_id, task_id, status);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "message"));
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "Success");
    assert_non_null(cJSON_GetObjectItem(response, "agent"));
    assert_int_equal(cJSON_GetObjectItem(response, "agent")->valueint, agent_id);
    assert_non_null(cJSON_GetObjectItem(response, "task_id"));
    assert_int_equal(cJSON_GetObjectItem(response, "task_id")->valueint, task_id);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
}

void test_wm_task_manager_parse_data_response_no_status(void **state)
{
    int error_code = 0;
    int agent_id = 77;
    int task_id = 124;
    char *status = NULL;

    cJSON *response = wm_task_manager_parse_data_response(error_code, agent_id, task_id, status);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "message"));
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "Success");
    assert_non_null(cJSON_GetObjectItem(response, "agent"));
    assert_int_equal(cJSON_GetObjectItem(response, "agent")->valueint, agent_id);
    assert_non_null(cJSON_GetObjectItem(response, "task_id"));
    assert_int_equal(cJSON_GetObjectItem(response, "task_id")->valueint, task_id);
    assert_null(cJSON_GetObjectItem(response, "status"));
}

void test_wm_task_manager_parse_data_response_no_task_id(void **state)
{
    int error_code = 0;
    int agent_id = 77;
    int task_id = OS_INVALID;
    char *status = "In progress";

    cJSON *response = wm_task_manager_parse_data_response(error_code, agent_id, task_id, status);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "message"));
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "Success");
    assert_non_null(cJSON_GetObjectItem(response, "agent"));
    assert_int_equal(cJSON_GetObjectItem(response, "agent")->valueint, agent_id);
    assert_null(cJSON_GetObjectItem(response, "task_id"));
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
}

void test_wm_task_manager_parse_data_response_no_agent_id(void **state)
{
    int error_code = 0;
    int agent_id = OS_INVALID;
    int task_id = 124;
    char *status = "In progress";

    cJSON *response = wm_task_manager_parse_data_response(error_code, agent_id, task_id, status);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "message"));
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "Success");
    assert_null(cJSON_GetObjectItem(response, "agent"));
    assert_non_null(cJSON_GetObjectItem(response, "task_id"));
    assert_int_equal(cJSON_GetObjectItem(response, "task_id")->valueint, task_id);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
}

void test_wm_task_manager_parse_data_result(void **state)
{
    cJSON *response = cJSON_CreateObject();

    char *node = "node04";
    char *module = "api";
    char *command = "task";
    char *status = "In progress";
    char *error = "Error message";
    int create_time = 123456789;
    char *create_time_timestamp = NULL;
    int last_update = 234567890;
    char *last_update_timestamp = NULL;
    char *req_command = "task_result";

    os_strdup("5/5/20 12:30:55.666", create_time_timestamp);
    os_strdup("5/5/20 12:55:18.789", last_update_timestamp);

    expect_value(__wrap_w_get_timestamp, time, create_time);
    will_return(__wrap_w_get_timestamp, create_time_timestamp);

    expect_value(__wrap_w_get_timestamp, time, last_update);
    will_return(__wrap_w_get_timestamp, last_update_timestamp);

    wm_task_manager_parse_data_result(response, node, module, command, status, error, create_time, last_update, req_command);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "node"));
    assert_string_equal(cJSON_GetObjectItem(response, "node")->valuestring, node);
    assert_non_null(cJSON_GetObjectItem(response, "module"));
    assert_string_equal(cJSON_GetObjectItem(response, "module")->valuestring, module);
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, command);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
    assert_non_null(cJSON_GetObjectItem(response, "error_msg"));
    assert_string_equal(cJSON_GetObjectItem(response, "error_msg")->valuestring, error);
    assert_non_null(cJSON_GetObjectItem(response, "create_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "create_time")->valuestring, "5/5/20 12:30:55.666");
    assert_non_null(cJSON_GetObjectItem(response, "update_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "update_time")->valuestring, "5/5/20 12:55:18.789");
}

void test_wm_task_manager_parse_data_result_last_update_0(void **state)
{
    cJSON *response = cJSON_CreateObject();

    char *node = "node04";
    char *module = "api";
    char *command = "task";
    char *status = "In progress";
    int create_time = 123456789;
    char *create_time_timestamp = NULL;
    int last_update = 0;
    char *req_command = "task_result";

    os_strdup("5/5/20 12:30:55.666", create_time_timestamp);

    expect_value(__wrap_w_get_timestamp, time, create_time);
    will_return(__wrap_w_get_timestamp, create_time_timestamp);

    wm_task_manager_parse_data_result(response, node, module, command, status, NULL, create_time, last_update, req_command);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "node"));
    assert_string_equal(cJSON_GetObjectItem(response, "node")->valuestring, node);
    assert_non_null(cJSON_GetObjectItem(response, "module"));
    assert_string_equal(cJSON_GetObjectItem(response, "module")->valuestring, module);
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, command);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
    assert_null(cJSON_GetObjectItem(response, "error_msg"));
    assert_non_null(cJSON_GetObjectItem(response, "create_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "create_time")->valuestring, "5/5/20 12:30:55.666");
    assert_non_null(cJSON_GetObjectItem(response, "update_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "update_time")->valuestring, "0");
}

void test_wm_task_manager_parse_data_result_no_last_update(void **state)
{
    cJSON *response = cJSON_CreateObject();

    char *node = "node04";
    char *module = "api";
    char *command = "task";
    char *status = "In progress";
    int create_time = 123456789;
    char *create_time_timestamp = NULL;
    int last_update = OS_INVALID;
    char *req_command = "task_result";

    os_strdup("5/5/20 12:30:55.666", create_time_timestamp);

    expect_value(__wrap_w_get_timestamp, time, create_time);
    will_return(__wrap_w_get_timestamp, create_time_timestamp);

    wm_task_manager_parse_data_result(response, node, module, command, status, NULL, create_time, last_update, req_command);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "node"));
    assert_string_equal(cJSON_GetObjectItem(response, "node")->valuestring, node);
    assert_non_null(cJSON_GetObjectItem(response, "module"));
    assert_string_equal(cJSON_GetObjectItem(response, "module")->valuestring, module);
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, command);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
    assert_null(cJSON_GetObjectItem(response, "error_msg"));
    assert_non_null(cJSON_GetObjectItem(response, "create_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "create_time")->valuestring, "5/5/20 12:30:55.666");
    assert_null(cJSON_GetObjectItem(response, "update_time"));
}

void test_wm_task_manager_parse_data_result_no_create_time(void **state)
{
    cJSON *response = cJSON_CreateObject();

    char *node = "node04";
    char *module = "api";
    char *command = "task";
    char *status = "In progress";
    int create_time = OS_INVALID;
    int last_update = 234567890;
    char *last_update_timestamp = NULL;
    char *req_command = "task_result";

    os_strdup("5/5/20 12:55:18.789", last_update_timestamp);

    expect_value(__wrap_w_get_timestamp, time, last_update);
    will_return(__wrap_w_get_timestamp, last_update_timestamp);

    wm_task_manager_parse_data_result(response, node, module, command, status, NULL, create_time, last_update, req_command);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "node"));
    assert_string_equal(cJSON_GetObjectItem(response, "node")->valuestring, node);
    assert_non_null(cJSON_GetObjectItem(response, "module"));
    assert_string_equal(cJSON_GetObjectItem(response, "module")->valuestring, module);
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, command);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
    assert_null(cJSON_GetObjectItem(response, "error_msg"));
    assert_null(cJSON_GetObjectItem(response, "create_time"));
    assert_non_null(cJSON_GetObjectItem(response, "update_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "update_time")->valuestring, "5/5/20 12:55:18.789");
}

void test_wm_task_manager_parse_data_result_status_upgrade_result(void **state)
{
    cJSON *response = cJSON_CreateObject();

    char *node = "node04";
    char *module = "upgrade_module";
    char *command = "upgrade";
    char *status = "Legacy";
    int create_time = 123456789;
    char *create_time_timestamp = NULL;
    int last_update = 234567890;
    char *last_update_timestamp = NULL;
    char *req_command = "upgrade_result";

    os_strdup("5/5/20 12:30:55.666", create_time_timestamp);
    os_strdup("5/5/20 12:55:18.789", last_update_timestamp);

    expect_value(__wrap_w_get_timestamp, time, create_time);
    will_return(__wrap_w_get_timestamp, create_time_timestamp);

    expect_value(__wrap_w_get_timestamp, time, last_update);
    will_return(__wrap_w_get_timestamp, last_update_timestamp);

    wm_task_manager_parse_data_result(response, node, module, command, status, NULL, create_time, last_update, req_command);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "node"));
    assert_string_equal(cJSON_GetObjectItem(response, "node")->valuestring, node);
    assert_non_null(cJSON_GetObjectItem(response, "module"));
    assert_string_equal(cJSON_GetObjectItem(response, "module")->valuestring, module);
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, command);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, "Legacy upgrade: check the result manually since the agent cannot report the result of the task");
    assert_null(cJSON_GetObjectItem(response, "error_msg"));
    assert_non_null(cJSON_GetObjectItem(response, "create_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "create_time")->valuestring, "5/5/20 12:30:55.666");
    assert_non_null(cJSON_GetObjectItem(response, "update_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "update_time")->valuestring, "5/5/20 12:55:18.789");
}

void test_wm_task_manager_parse_data_result_no_status(void **state)
{
    cJSON *response = cJSON_CreateObject();

    char *node = "node04";
    char *module = "upgrade_module";
    char *command = "upgrade";
    char *status = NULL;
    int create_time = 123456789;
    char *create_time_timestamp = NULL;
    int last_update = 234567890;
    char *last_update_timestamp = NULL;
    char *req_command = "upgrade_result";

    os_strdup("5/5/20 12:30:55.666", create_time_timestamp);
    os_strdup("5/5/20 12:55:18.789", last_update_timestamp);

    expect_value(__wrap_w_get_timestamp, time, create_time);
    will_return(__wrap_w_get_timestamp, create_time_timestamp);

    expect_value(__wrap_w_get_timestamp, time, last_update);
    will_return(__wrap_w_get_timestamp, last_update_timestamp);

    wm_task_manager_parse_data_result(response, node, module, command, status, NULL, create_time, last_update, req_command);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "node"));
    assert_string_equal(cJSON_GetObjectItem(response, "node")->valuestring, node);
    assert_non_null(cJSON_GetObjectItem(response, "module"));
    assert_string_equal(cJSON_GetObjectItem(response, "module")->valuestring, module);
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, command);
    assert_null(cJSON_GetObjectItem(response, "status"));
    assert_null(cJSON_GetObjectItem(response, "error_msg"));
    assert_non_null(cJSON_GetObjectItem(response, "create_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "create_time")->valuestring, "5/5/20 12:30:55.666");
    assert_non_null(cJSON_GetObjectItem(response, "update_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "update_time")->valuestring, "5/5/20 12:55:18.789");
}

void test_wm_task_manager_parse_data_result_no_command(void **state)
{
    cJSON *response = cJSON_CreateObject();

    char *node = "node04";
    char *module = "api";
    char *command = NULL;
    char *status = "In progress";
    int create_time = 123456789;
    char *create_time_timestamp = NULL;
    int last_update = 234567890;
    char *last_update_timestamp = NULL;
    char *req_command = "task_result";

    os_strdup("5/5/20 12:30:55.666", create_time_timestamp);
    os_strdup("5/5/20 12:55:18.789", last_update_timestamp);

    expect_value(__wrap_w_get_timestamp, time, create_time);
    will_return(__wrap_w_get_timestamp, create_time_timestamp);

    expect_value(__wrap_w_get_timestamp, time, last_update);
    will_return(__wrap_w_get_timestamp, last_update_timestamp);

    wm_task_manager_parse_data_result(response, node, module, command, status, NULL, create_time, last_update, req_command);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "node"));
    assert_string_equal(cJSON_GetObjectItem(response, "node")->valuestring, node);
    assert_non_null(cJSON_GetObjectItem(response, "module"));
    assert_string_equal(cJSON_GetObjectItem(response, "module")->valuestring, module);
    assert_null(cJSON_GetObjectItem(response, "command"));
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
    assert_null(cJSON_GetObjectItem(response, "error_msg"));
    assert_non_null(cJSON_GetObjectItem(response, "create_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "create_time")->valuestring, "5/5/20 12:30:55.666");
    assert_non_null(cJSON_GetObjectItem(response, "update_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "update_time")->valuestring, "5/5/20 12:55:18.789");
}

void test_wm_task_manager_parse_data_result_no_module(void **state)
{
    cJSON *response = cJSON_CreateObject();

    char *node = "node04";
    char *module = NULL;
    char *command = "task";
    char *status = "In progress";
    int create_time = 123456789;
    char *create_time_timestamp = NULL;
    int last_update = 234567890;
    char *last_update_timestamp = NULL;
    char *req_command = "task_result";

    os_strdup("5/5/20 12:30:55.666", create_time_timestamp);
    os_strdup("5/5/20 12:55:18.789", last_update_timestamp);

    expect_value(__wrap_w_get_timestamp, time, create_time);
    will_return(__wrap_w_get_timestamp, create_time_timestamp);

    expect_value(__wrap_w_get_timestamp, time, last_update);
    will_return(__wrap_w_get_timestamp, last_update_timestamp);

    wm_task_manager_parse_data_result(response, node, module, command, status, NULL, create_time, last_update, req_command);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "node"));
    assert_string_equal(cJSON_GetObjectItem(response, "node")->valuestring, node);
    assert_null(cJSON_GetObjectItem(response, "module"));
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, command);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
    assert_null(cJSON_GetObjectItem(response, "error_msg"));
    assert_non_null(cJSON_GetObjectItem(response, "create_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "create_time")->valuestring, "5/5/20 12:30:55.666");
    assert_non_null(cJSON_GetObjectItem(response, "update_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "update_time")->valuestring, "5/5/20 12:55:18.789");
}

void test_wm_task_manager_parse_data_result_no_node(void **state)
{
    cJSON *response = cJSON_CreateObject();

    char *node = NULL;
    char *module = "api";
    char *command = "task";
    char *status = "In progress";
    int create_time = 123456789;
    char *create_time_timestamp = NULL;
    int last_update = 234567890;
    char *last_update_timestamp = NULL;
    char *req_command = "task_result";

    os_strdup("5/5/20 12:30:55.666", create_time_timestamp);
    os_strdup("5/5/20 12:55:18.789", last_update_timestamp);

    expect_value(__wrap_w_get_timestamp, time, create_time);
    will_return(__wrap_w_get_timestamp, create_time_timestamp);

    expect_value(__wrap_w_get_timestamp, time, last_update);
    will_return(__wrap_w_get_timestamp, last_update_timestamp);

    wm_task_manager_parse_data_result(response, node, module, command, status, NULL, create_time, last_update, req_command);

    *state = response;

    assert_non_null(response);
    assert_null(cJSON_GetObjectItem(response, "node"));
    assert_non_null(cJSON_GetObjectItem(response, "module"));
    assert_string_equal(cJSON_GetObjectItem(response, "module")->valuestring, module);
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, command);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
    assert_null(cJSON_GetObjectItem(response, "error_msg"));
    assert_non_null(cJSON_GetObjectItem(response, "create_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "create_time")->valuestring, "5/5/20 12:30:55.666");
    assert_non_null(cJSON_GetObjectItem(response, "update_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "update_time")->valuestring, "5/5/20 12:55:18.789");
}

void test_wm_task_manager_parse_response_data_array(void **state) {
    int error_code = 0;
    cJSON *data = cJSON_CreateArray();

    cJSON *response = wm_task_manager_parse_response(error_code, data);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "message"));
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "Success");
    assert_non_null(cJSON_GetObjectItem(response, "data"));
    assert_memory_equal(cJSON_GetObjectItem(response, "data"), data, sizeof(data));
}

void test_wm_task_manager_parse_response_data_object(void **state) {
    int error_code = 0;
    cJSON *data = cJSON_CreateObject();

    cJSON *response = wm_task_manager_parse_response(error_code, data);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "message"));
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "Success");
    assert_non_null(cJSON_GetObjectItem(response, "data"));
    assert_memory_equal(cJSON_GetArrayItem(cJSON_GetObjectItem(response, "data"), 0), data, sizeof(data));
}

void test_wm_task_manager_parse_message_agents(void **state)
{
    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    wm_task_manager_task *task = wm_task_manager_parse_message(message);

    *state = task;

    assert_non_null(task);
    assert_int_equal(task->command, WM_TASK_UPGRADE);
    wm_task_manager_upgrade *parameters = (wm_task_manager_upgrade *)task->parameters;
    assert_non_null(parameters->node);
    assert_string_equal(parameters->node, "node05");
    assert_non_null(parameters->module);
    assert_string_equal(parameters->module, "upgrade_module");
    assert_non_null(parameters->agent_ids);
    assert_int_equal(parameters->agent_ids[0], 1);
    assert_int_equal(parameters->agent_ids[1], 2);
    assert_int_equal(parameters->agent_ids[2], -1);
}

void test_wm_task_manager_parse_message_agents_status(void **state)
{
    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade_update_status\","
                    "  \"parameters\": {"
                    "      \"agents\": [1],"
                    "      \"status\": \"Failed\","
                    "      \"error_msg\": \"SHA1 error\""
                    "   }"
                    "}";

    wm_task_manager_task *task = wm_task_manager_parse_message(message);

    *state = task;

    assert_non_null(task);
    assert_int_equal(task->command, WM_TASK_UPGRADE_UPDATE_STATUS);
    wm_task_manager_upgrade_update_status *parameters = (wm_task_manager_upgrade_update_status *)task->parameters;
    assert_non_null(parameters->node);
    assert_string_equal(parameters->node, "node05");
    assert_non_null(parameters->agent_ids);
    assert_int_equal(parameters->agent_ids[0], 1);
    assert_int_equal(parameters->agent_ids[1], -1);
    assert_non_null(parameters->status);
    assert_string_equal(parameters->status, "Failed");
    assert_non_null(parameters->error_msg);
    assert_string_equal(parameters->error_msg, "SHA1 error");
}

void test_wm_task_manager_parse_message_command_err(void **state)
{
    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8259): Invalid message. 'command' not found.");

    wm_task_manager_task *task = wm_task_manager_parse_message(message);

    assert_null(task);
}

void test_wm_task_manager_parse_message_origin_err(void **state)
{
    char *message = "{"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8259): Invalid message. 'origin' not found.");

    wm_task_manager_task *task = wm_task_manager_parse_message(message);

    assert_null(task);
}

void test_wm_task_manager_parse_message_parameters_err(void **state)
{
    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\""
                    "}";

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8259): Invalid message. 'parameters' not found.");

    wm_task_manager_task *task = wm_task_manager_parse_message(message);

    assert_null(task);
}

void test_wm_task_manager_parse_message_invalid_json_err(void **state)
{
    char *message = "unknown json";

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8257): Error parsing JSON event: 'unknown json'");

    wm_task_manager_task *task = wm_task_manager_parse_message(message);

    assert_null(task);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_task_manager_decode_status
        cmocka_unit_test(test_wm_task_manager_decode_status_done),
        cmocka_unit_test(test_wm_task_manager_decode_status_pending),
        cmocka_unit_test(test_wm_task_manager_decode_status_in_progress),
        cmocka_unit_test(test_wm_task_manager_decode_status_failed),
        cmocka_unit_test(test_wm_task_manager_decode_status_cancelled),
        cmocka_unit_test(test_wm_task_manager_decode_status_timeout),
        cmocka_unit_test(test_wm_task_manager_decode_status_legacy),
        cmocka_unit_test(test_wm_task_manager_decode_status_unknown),
        // wm_task_manager_parse_data_response
        cmocka_unit_test_teardown(test_wm_task_manager_parse_data_response, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_data_response_no_status, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_data_response_no_task_id, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_data_response_no_agent_id, teardown_json),
        // wm_task_manager_parse_data_result
        cmocka_unit_test_teardown(test_wm_task_manager_parse_data_result, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_data_result_last_update_0, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_data_result_no_last_update, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_data_result_no_create_time, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_data_result_status_upgrade_result, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_data_result_no_status, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_data_result_no_command, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_data_result_no_module, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_data_result_no_node, teardown_json),
        // wm_task_manager_parse_response
        cmocka_unit_test_teardown(test_wm_task_manager_parse_response_data_array, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_response_data_object, teardown_json),
        // wm_task_manager_parse_message
        cmocka_unit_test_teardown(test_wm_task_manager_parse_message_agents, teardown_parse_task),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_message_agents_status, teardown_parse_task),
        cmocka_unit_test(test_wm_task_manager_parse_message_command_err),
        cmocka_unit_test(test_wm_task_manager_parse_message_origin_err),
        cmocka_unit_test(test_wm_task_manager_parse_message_parameters_err),
        cmocka_unit_test(test_wm_task_manager_parse_message_invalid_json_err)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
