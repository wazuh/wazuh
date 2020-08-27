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
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
