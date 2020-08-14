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
#include "../../wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_parsing.h"
#include "../../headers/shared.h"

#if defined(TEST_SERVER)



#endif

// Setup / teardown

static int teardown_json(void **state) {
    cJSON *json = *state;
    cJSON_Delete(json);
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

#ifdef TEST_SERVER

// Tests

void test_wm_agent_upgrade_parse_response_message_complete(void **state)
{
    int error_code = 5;
    char *message = "Error code invalid data.";
    int agent_id = 10;
    int task_id = 25;
    char *status = "Done";

    cJSON *response = wm_agent_upgrade_parse_response_message(error_code, message, &agent_id, &task_id, status);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "data"));
    assert_string_equal(cJSON_GetObjectItem(response, "data")->valuestring, message);
    assert_non_null(cJSON_GetObjectItem(response, "agent"));
    assert_int_equal(cJSON_GetObjectItem(response, "agent")->valueint, agent_id);
    assert_non_null(cJSON_GetObjectItem(response, "task_id"));
    assert_int_equal(cJSON_GetObjectItem(response, "task_id")->valueint, task_id);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
}

void test_wm_agent_upgrade_parse_response_message_without_status(void **state)
{
    int error_code = 5;
    char *message = "Error code invalid data.";
    int agent_id = 10;
    int task_id = 25;

    cJSON *response = wm_agent_upgrade_parse_response_message(error_code, message, &agent_id, &task_id, NULL);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "data"));
    assert_string_equal(cJSON_GetObjectItem(response, "data")->valuestring, message);
    assert_non_null(cJSON_GetObjectItem(response, "agent"));
    assert_int_equal(cJSON_GetObjectItem(response, "agent")->valueint, agent_id);
    assert_non_null(cJSON_GetObjectItem(response, "task_id"));
    assert_int_equal(cJSON_GetObjectItem(response, "task_id")->valueint, task_id);
    assert_null(cJSON_GetObjectItem(response, "status"));
}

void test_wm_agent_upgrade_parse_response_message_without_task_id(void **state)
{
    int error_code = 5;
    char *message = "Error code invalid data.";
    int agent_id = 10;
    char *status = "Done";

    cJSON *response = wm_agent_upgrade_parse_response_message(error_code, message, &agent_id, NULL, status);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "data"));
    assert_string_equal(cJSON_GetObjectItem(response, "data")->valuestring, message);
    assert_non_null(cJSON_GetObjectItem(response, "agent"));
    assert_int_equal(cJSON_GetObjectItem(response, "agent")->valueint, agent_id);
    assert_null(cJSON_GetObjectItem(response, "task_id"));
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
}

void test_wm_agent_upgrade_parse_response_message_without_agent_id(void **state)
{
    int error_code = 5;
    char *message = "Error code invalid data.";
    int task_id = 25;
    char *status = "Done";

    cJSON *response = wm_agent_upgrade_parse_response_message(error_code, message, NULL, &task_id, status);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "error"));
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, error_code);
    assert_non_null(cJSON_GetObjectItem(response, "data"));
    assert_string_equal(cJSON_GetObjectItem(response, "data")->valuestring, message);
    assert_null(cJSON_GetObjectItem(response, "agent"));
    assert_non_null(cJSON_GetObjectItem(response, "task_id"));
    assert_int_equal(cJSON_GetObjectItem(response, "task_id")->valueint, task_id);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
}

void test_wm_agent_upgrade_parse_task_module_request_complete(void **state)
{
    int command = 1;
    int agent_id = 10;
    char *status = "Done";

    cJSON *response = wm_agent_upgrade_parse_task_module_request(command, agent_id, status);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "module"));
    assert_string_equal(cJSON_GetObjectItem(response, "module")->valuestring, "upgrade_module");
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, "upgrade_custom");
    assert_non_null(cJSON_GetObjectItem(response, "agent"));
    assert_int_equal(cJSON_GetObjectItem(response, "agent")->valueint, agent_id);
    assert_non_null(cJSON_GetObjectItem(response, "status"));
    assert_string_equal(cJSON_GetObjectItem(response, "status")->valuestring, status);
}

void test_wm_agent_upgrade_parse_task_module_request_without_status(void **state)
{
    int command = 1;
    int agent_id = 10;

    cJSON *response = wm_agent_upgrade_parse_task_module_request(command, agent_id, NULL);

    *state = response;

    assert_non_null(cJSON_GetObjectItem(response, "module"));
    assert_string_equal(cJSON_GetObjectItem(response, "module")->valuestring, "upgrade_module");
    assert_non_null(cJSON_GetObjectItem(response, "command"));
    assert_string_equal(cJSON_GetObjectItem(response, "command")->valuestring, "upgrade_custom");
    assert_non_null(cJSON_GetObjectItem(response, "agent"));
    assert_int_equal(cJSON_GetObjectItem(response, "agent")->valueint, agent_id);
    assert_null(cJSON_GetObjectItem(response, "status"));
}

void test_wm_agent_upgrade_parse_agent_response_ok_with_data(void **state)
{
    (void) state;
    char *response = "ok 1234567890";
    char *data = NULL;

    int ret = wm_agent_upgrade_parse_agent_response(response, &data);

    assert_int_equal(ret, 0);
    assert_string_equal(data, "1234567890");
}

void test_wm_agent_upgrade_parse_agent_response_ok_without_data(void **state)
{
    (void) state;
    char *response = "ok ";
    char *data = NULL;

    int ret = wm_agent_upgrade_parse_agent_response(response, &data);

    assert_int_equal(ret, 0);
    assert_string_equal(data, "");
}

void test_wm_agent_upgrade_parse_agent_response_err_with_data(void **state)
{
    (void) state;
    char *response = "err invalid request";
    char *data = NULL;

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8116): Error response from agent: 'invalid request'");

    int ret = wm_agent_upgrade_parse_agent_response(response, &data);

    assert_int_equal(ret, -1);
    assert_null(data);
}

void test_wm_agent_upgrade_parse_agent_response_err_without_data(void **state)
{
    (void) state;
    char *response = "err ";
    char *data = NULL;

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8116): Error response from agent: ''");

    int ret = wm_agent_upgrade_parse_agent_response(response, &data);

    assert_int_equal(ret, -1);
    assert_null(data);
}

void test_wm_agent_upgrade_parse_agent_response_unknown_response(void **state)
{
    (void) state;
    char *response = "unknown";
    char *data = NULL;

    int ret = wm_agent_upgrade_parse_agent_response(response, &data);

    assert_int_equal(ret, -1);
    assert_null(data);
}

void test_wm_agent_upgrade_parse_agent_response_invalid_response(void **state)
{
    (void) state;
    char *data = NULL;

    int ret = wm_agent_upgrade_parse_agent_response(NULL, &data);

    assert_int_equal(ret, -1);
    assert_null(data);
}

#endif

int main(void) {
    const struct CMUnitTest tests[] = {
#ifdef TEST_SERVER
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_response_message_complete, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_response_message_without_status, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_response_message_without_task_id, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_response_message_without_agent_id, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_task_module_request_complete, teardown_json),
        cmocka_unit_test_teardown(test_wm_agent_upgrade_parse_task_module_request_without_status, teardown_json),
        cmocka_unit_test(test_wm_agent_upgrade_parse_agent_response_ok_with_data),
        cmocka_unit_test(test_wm_agent_upgrade_parse_agent_response_ok_without_data),
        cmocka_unit_test(test_wm_agent_upgrade_parse_agent_response_err_with_data),
        cmocka_unit_test(test_wm_agent_upgrade_parse_agent_response_err_without_data),
        cmocka_unit_test(test_wm_agent_upgrade_parse_agent_response_unknown_response),
        cmocka_unit_test(test_wm_agent_upgrade_parse_agent_response_invalid_response)
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
