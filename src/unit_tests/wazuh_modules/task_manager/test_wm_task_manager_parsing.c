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
#include "../../wazuh_modules/task_manager/wm_task_manager_parsing.h"
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

char* __wrap_w_get_timestamp(time_t time) {
    check_expected(time);

    return mock_type(char*);
}

// Tests

void test_wm_task_manager_decode_status_done(void **state)
{
    char *status = "Done";

    const char *ret = wm_task_manager_decode_status(status);

    assert_string_equal(ret, "Updated");
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

void test_wm_task_manager_decode_status_new(void **state)
{
    char *status = "New";

    const char *ret = wm_task_manager_decode_status(status);

    assert_string_equal(ret, "The agent is outdated since the task could not start");
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

void test_wm_task_manager_parse_response(void **state)
{
    int error_code = 0;
    int agent_id = 77;
    int task_id = 124;
    char *status = "In progress";

    cJSON *response = wm_task_manager_parse_response(error_code, agent_id, task_id, status);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "data"));
    assert_string_equal(cJSON_GetObjectItem(response, "data")->valuestring, "Success");
    assert_non_null(cJSON_GetObjectItem(response, "agent"));
    assert_int_equal(cJSON_GetObjectItem(response, "agent")->valueint, agent_id);
    assert_non_null(cJSON_GetObjectItem(response, "task_id"));
    assert_int_equal(cJSON_GetObjectItem(response, "task_id")->valueint, task_id);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
}

void test_wm_task_manager_parse_response_no_status(void **state)
{
    int error_code = 0;
    int agent_id = 77;
    int task_id = 124;
    char *status = NULL;

    cJSON *response = wm_task_manager_parse_response(error_code, agent_id, task_id, status);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "data"));
    assert_string_equal(cJSON_GetObjectItem(response, "data")->valuestring, "Success");
    assert_non_null(cJSON_GetObjectItem(response, "agent"));
    assert_int_equal(cJSON_GetObjectItem(response, "agent")->valueint, agent_id);
    assert_non_null(cJSON_GetObjectItem(response, "task_id"));
    assert_int_equal(cJSON_GetObjectItem(response, "task_id")->valueint, task_id);
    assert_null(cJSON_GetObjectItem(response, "status"));
}

void test_wm_task_manager_parse_response_no_task_id(void **state)
{
    int error_code = 0;
    int agent_id = 77;
    int task_id = OS_INVALID;
    char *status = "In progress";

    cJSON *response = wm_task_manager_parse_response(error_code, agent_id, task_id, status);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "data"));
    assert_string_equal(cJSON_GetObjectItem(response, "data")->valuestring, "Success");
    assert_non_null(cJSON_GetObjectItem(response, "agent"));
    assert_int_equal(cJSON_GetObjectItem(response, "agent")->valueint, agent_id);
    assert_null(cJSON_GetObjectItem(response, "task_id"));
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
}

void test_wm_task_manager_parse_response_no_agent_id(void **state)
{
    int error_code = 0;
    int agent_id = OS_INVALID;
    int task_id = 124;
    char *status = "In progress";

    cJSON *response = wm_task_manager_parse_response(error_code, agent_id, task_id, status);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "data"));
    assert_string_equal(cJSON_GetObjectItem(response, "data")->valuestring, "Success");
    assert_null(cJSON_GetObjectItem(response, "agent"));
    assert_non_null(cJSON_GetObjectItem(response, "task_id"));
    assert_int_equal(cJSON_GetObjectItem(response, "task_id")->valueint, task_id);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
}

void test_wm_task_manager_parse_response_result(void **state)
{
    cJSON *response = cJSON_CreateObject();

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

    wm_task_manager_parse_response_result(response, module, command, status, create_time, last_update, req_command);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "module"));
    assert_string_equal(cJSON_GetObjectItem(response, "module")->valuestring, module);
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, command);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
    assert_non_null(cJSON_GetObjectItem(response, "create_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "create_time")->valuestring, "5/5/20 12:30:55.666");
    assert_non_null(cJSON_GetObjectItem(response, "update_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "update_time")->valuestring, "5/5/20 12:55:18.789");
}

void test_wm_task_manager_parse_response_result_last_update_0(void **state)
{
    cJSON *response = cJSON_CreateObject();

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

    wm_task_manager_parse_response_result(response, module, command, status, create_time, last_update, req_command);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "module"));
    assert_string_equal(cJSON_GetObjectItem(response, "module")->valuestring, module);
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, command);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
    assert_non_null(cJSON_GetObjectItem(response, "create_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "create_time")->valuestring, "5/5/20 12:30:55.666");
    assert_non_null(cJSON_GetObjectItem(response, "update_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "update_time")->valuestring, "0");
}

void test_wm_task_manager_parse_response_result_no_last_update(void **state)
{
    cJSON *response = cJSON_CreateObject();

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

    wm_task_manager_parse_response_result(response, module, command, status, create_time, last_update, req_command);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "module"));
    assert_string_equal(cJSON_GetObjectItem(response, "module")->valuestring, module);
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, command);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
    assert_non_null(cJSON_GetObjectItem(response, "create_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "create_time")->valuestring, "5/5/20 12:30:55.666");
    assert_null(cJSON_GetObjectItem(response, "update_time"));
}

void test_wm_task_manager_parse_response_result_no_create_time(void **state)
{
    cJSON *response = cJSON_CreateObject();

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

    wm_task_manager_parse_response_result(response, module, command, status, create_time, last_update, req_command);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "module"));
    assert_string_equal(cJSON_GetObjectItem(response, "module")->valuestring, module);
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, command);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
    assert_null(cJSON_GetObjectItem(response, "create_time"));
    assert_non_null(cJSON_GetObjectItem(response, "update_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "update_time")->valuestring, "5/5/20 12:55:18.789");
}

void test_wm_task_manager_parse_response_result_status_upgrade_result(void **state)
{
    cJSON *response = cJSON_CreateObject();

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

    wm_task_manager_parse_response_result(response, module, command, status, create_time, last_update, req_command);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "module"));
    assert_string_equal(cJSON_GetObjectItem(response, "module")->valuestring, module);
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, command);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, "Legacy upgrade: check the result manually since the agent cannot report the result of the task");
    assert_non_null(cJSON_GetObjectItem(response, "create_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "create_time")->valuestring, "5/5/20 12:30:55.666");
    assert_non_null(cJSON_GetObjectItem(response, "update_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "update_time")->valuestring, "5/5/20 12:55:18.789");
}

void test_wm_task_manager_parse_response_result_no_status(void **state)
{
    cJSON *response = cJSON_CreateObject();

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

    wm_task_manager_parse_response_result(response, module, command, status, create_time, last_update, req_command);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "module"));
    assert_string_equal(cJSON_GetObjectItem(response, "module")->valuestring, module);
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, command);
    assert_null(cJSON_GetObjectItem(response, "status"));
    assert_non_null(cJSON_GetObjectItem(response, "create_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "create_time")->valuestring, "5/5/20 12:30:55.666");
    assert_non_null(cJSON_GetObjectItem(response, "update_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "update_time")->valuestring, "5/5/20 12:55:18.789");
}

void test_wm_task_manager_parse_response_result_no_command(void **state)
{
    cJSON *response = cJSON_CreateObject();

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

    wm_task_manager_parse_response_result(response, module, command, status, create_time, last_update, req_command);

    *state = response;

    assert_non_null(response);
    assert_non_null(cJSON_GetObjectItem(response, "module"));
    assert_string_equal(cJSON_GetObjectItem(response, "module")->valuestring, module);
    assert_null(cJSON_GetObjectItem(response, "command"));
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
    assert_non_null(cJSON_GetObjectItem(response, "create_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "create_time")->valuestring, "5/5/20 12:30:55.666");
    assert_non_null(cJSON_GetObjectItem(response, "update_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "update_time")->valuestring, "5/5/20 12:55:18.789");
}

void test_wm_task_manager_parse_response_result_no_module(void **state)
{
    cJSON *response = cJSON_CreateObject();

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

    wm_task_manager_parse_response_result(response, module, command, status, create_time, last_update, req_command);

    *state = response;

    assert_non_null(response);
    assert_null(cJSON_GetObjectItem(response, "module"));
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, command);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
    assert_non_null(cJSON_GetObjectItem(response, "create_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "create_time")->valuestring, "5/5/20 12:30:55.666");
    assert_non_null(cJSON_GetObjectItem(response, "update_time"));
    assert_string_equal(cJSON_GetObjectItem(response, "update_time")->valuestring, "5/5/20 12:55:18.789");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_task_manager_decode_status
        cmocka_unit_test(test_wm_task_manager_decode_status_done),
        cmocka_unit_test(test_wm_task_manager_decode_status_in_progress),
        cmocka_unit_test(test_wm_task_manager_decode_status_failed),
        cmocka_unit_test(test_wm_task_manager_decode_status_new),
        cmocka_unit_test(test_wm_task_manager_decode_status_timeout),
        cmocka_unit_test(test_wm_task_manager_decode_status_legacy),
        cmocka_unit_test(test_wm_task_manager_decode_status_unknown),
        // wm_task_manager_parse_response
        cmocka_unit_test_teardown(test_wm_task_manager_parse_response, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_response_no_status, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_response_no_task_id, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_response_no_agent_id, teardown_json),
        // wm_task_manager_parse_response_result
        cmocka_unit_test_teardown(test_wm_task_manager_parse_response_result, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_response_result_last_update_0, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_response_result_no_last_update, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_response_result_no_create_time, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_response_result_status_upgrade_result, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_response_result_no_status, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_response_result_no_command, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_response_result_no_module, teardown_json),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
