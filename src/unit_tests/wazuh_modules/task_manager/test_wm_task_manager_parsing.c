/*
 * Copyright (C) 2015, Wazuh Inc.
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

#include "wmodules.h"
#include "wm_task_manager_parsing.h"
#include "wm_task_manager_tasks.h"
#include "shared.h"

// External functions
int wm_task_manager_parse_message(const char* buffer, void** params, char** error);
char* wm_task_manager_parse_error_response(const char *error, const char *message);
char* wm_task_manager_parse_create_response(const char *task_id);
char* wm_task_manager_parse_get_pending_response(cJSON *tasks);

// Setup / teardown

static int teardown_string(void **state) {
    if (state[0]) {
        char *str = (char*)state[0];
        os_free(str);
    }
    if (state[1]) {
        void *ptr = state[1];
        os_free(ptr);
    }
    return 0;
}

static int teardown_create_params(void **state) {
    if (state[0]) {
        wm_task_create_params *params = (wm_task_create_params*)state[0];
        if (params->agent_id) {
            os_free(params->agent_id);
        }
        if (params->source_id) {
            os_free(params->source_id);
        }
        if (params->payload_json) {
            os_free(params->payload_json);
        }
        os_free(params);
    }
    if (state[1]) {
        char *error = (char*)state[1];
        os_free(error);
    }
    return 0;
}

static int teardown_get_pending_params(void **state) {
    if (state[0]) {
        wm_task_get_pending_params *params = (wm_task_get_pending_params*)state[0];
        if (params->agent_id) {
            os_free(params->agent_id);
        }
        os_free(params);
    }
    if (state[1]) {
        char *error = (char*)state[1];
        os_free(error);
    }
    return 0;
}

static int teardown_error_only(void **state) {
    if (state[1]) {
        char *error = (char*)state[1];
        os_free(error);
    }
    return 0;
}

// Tests for wm_task_manager_parse_message

void test_wm_task_manager_parse_message_create_task_ok(void **state)
{
    time_t now = time(NULL);
    char message[512];
    snprintf(message, sizeof(message),
             "{"
             "\"action\":\"create_task\","
             "\"agent_id\":\"001\","
             "\"task_type\":\"active_response\","
             "\"create_time\":%ld,"
             "\"source_id\":\"ar-123\","
             "\"payload\":{\"command\":\"firewall-drop\"}"
             "}", now - 10);

    void *params = NULL;
    char *error = NULL;

    int ret = wm_task_manager_parse_message(message, &params, &error);

    state[0] = params;
    state[1] = error;

    assert_int_equal(ret, WM_TASK_MANAGER_CREATE);
    assert_non_null(params);
    assert_null(error);

    wm_task_create_params *create_params = (wm_task_create_params*)params;
    assert_string_equal(create_params->agent_id, "001");
    assert_int_equal(create_params->task_type, WM_TASK_TYPE_ACTIVE_RESPONSE);
    assert_string_equal(create_params->source_id, "ar-123");
    assert_int_equal(create_params->create_time, now - 10);
    assert_non_null(create_params->payload_json);
}

void test_wm_task_manager_parse_message_get_pending_ok(void **state)
{
    const char *message = "{"
                         "\"action\":\"get_pending_tasks\","
                         "\"agent_id\":\"002\""
                         "}";

    void *params = NULL;
    char *error = NULL;

    int ret = wm_task_manager_parse_message(message, &params, &error);

    state[0] = params;
    state[1] = error;

    assert_int_equal(ret, WM_TASK_MANAGER_GET_PENDING);
    assert_non_null(params);
    assert_null(error);

    wm_task_get_pending_params *get_params = (wm_task_get_pending_params*)params;
    assert_string_equal(get_params->agent_id, "002");
}

void test_wm_task_manager_parse_message_invalid_json(void **state)
{
    const char *message = "{invalid json}";

    void *params = NULL;
    char *error = NULL;

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mterror, formatted_msg);

    int ret = wm_task_manager_parse_message(message, &params, &error);

    state[0] = params;
    state[1] = error;

    assert_int_equal(ret, OS_INVALID);
    assert_null(params);
    assert_non_null(error);
}

void test_wm_task_manager_parse_message_missing_action(void **state)
{
    const char *message = "{\"agent_id\":\"001\"}";

    void *params = NULL;
    char *error = NULL;

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mterror, formatted_msg);

    int ret = wm_task_manager_parse_message(message, &params, &error);

    state[0] = params;
    state[1] = error;

    assert_int_equal(ret, OS_INVALID);
    assert_null(params);
    assert_non_null(error);
}

void test_wm_task_manager_parse_message_unknown_action(void **state)
{
    const char *message = "{\"action\":\"unknown_action\",\"agent_id\":\"001\"}";

    void *params = NULL;
    char *error = NULL;

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mterror, formatted_msg);

    int ret = wm_task_manager_parse_message(message, &params, &error);

    state[0] = params;
    state[1] = error;

    assert_int_equal(ret, OS_INVALID);
    assert_null(params);
    assert_non_null(error);
}

// Tests for wm_task_manager_parse_error_response

void test_wm_task_manager_parse_error_response_ok(void **state)
{
    char *response = wm_task_manager_parse_error_response("invalid_json", "Failed to parse JSON");

    state[0] = response;

    assert_non_null(response);

    cJSON *json = cJSON_Parse(response);
    assert_non_null(json);
    assert_non_null(cJSON_GetObjectItem(json, "error"));
    assert_string_equal(cJSON_GetObjectItem(json, "error")->valuestring, "invalid_json");
    assert_non_null(cJSON_GetObjectItem(json, "message"));
    assert_string_equal(cJSON_GetObjectItem(json, "message")->valuestring, "Failed to parse JSON");

    cJSON_Delete(json);
}

void test_wm_task_manager_parse_error_response_no_message(void **state)
{
    char *response = wm_task_manager_parse_error_response("test_error", NULL);

    state[0] = response;

    assert_non_null(response);

    cJSON *json = cJSON_Parse(response);
    assert_non_null(json);
    assert_non_null(cJSON_GetObjectItem(json, "error"));
    assert_string_equal(cJSON_GetObjectItem(json, "error")->valuestring, "test_error");

    cJSON_Delete(json);
}

// Tests for wm_task_manager_parse_create_response

void test_wm_task_manager_parse_create_response_ok(void **state)
{
    char *response = wm_task_manager_parse_create_response("task-12345");

    state[0] = response;

    assert_non_null(response);

    cJSON *json = cJSON_Parse(response);
    assert_non_null(json);
    assert_non_null(cJSON_GetObjectItem(json, "status"));
    assert_string_equal(cJSON_GetObjectItem(json, "status")->valuestring, "ok");
    assert_non_null(cJSON_GetObjectItem(json, "task_id"));
    assert_string_equal(cJSON_GetObjectItem(json, "task_id")->valuestring, "task-12345");

    cJSON_Delete(json);
}

// Tests for wm_task_manager_parse_get_pending_response

void test_wm_task_manager_parse_get_pending_response_ok(void **state)
{
    cJSON *tasks = cJSON_CreateArray();
    cJSON *task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, "task_id", "task-123");
    cJSON_AddStringToObject(task, "task_type", "active_response");
    cJSON_AddItemToArray(tasks, task);

    char *response = wm_task_manager_parse_get_pending_response(tasks);

    state[0] = response;

    assert_non_null(response);

    cJSON *json = cJSON_Parse(response);
    assert_non_null(json);
    assert_non_null(cJSON_GetObjectItem(json, "status"));
    assert_string_equal(cJSON_GetObjectItem(json, "status")->valuestring, "ok");
    assert_non_null(cJSON_GetObjectItem(json, "tasks"));
    assert_true(cJSON_IsArray(cJSON_GetObjectItem(json, "tasks")));
    assert_int_equal(cJSON_GetArraySize(cJSON_GetObjectItem(json, "tasks")), 1);

    cJSON_Delete(json);
}

void test_wm_task_manager_parse_get_pending_response_empty(void **state)
{
    cJSON *tasks = cJSON_CreateArray();

    char *response = wm_task_manager_parse_get_pending_response(tasks);

    state[0] = response;

    assert_non_null(response);

    cJSON *json = cJSON_Parse(response);
    assert_non_null(json);
    assert_non_null(cJSON_GetObjectItem(json, "status"));
    assert_string_equal(cJSON_GetObjectItem(json, "status")->valuestring, "ok");
    assert_non_null(cJSON_GetObjectItem(json, "tasks"));
    assert_true(cJSON_IsArray(cJSON_GetObjectItem(json, "tasks")));
    assert_int_equal(cJSON_GetArraySize(cJSON_GetObjectItem(json, "tasks")), 0);

    cJSON_Delete(json);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_task_manager_parse_message tests
        cmocka_unit_test_teardown(test_wm_task_manager_parse_message_create_task_ok, teardown_create_params),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_message_get_pending_ok, teardown_get_pending_params),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_message_invalid_json, teardown_error_only),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_message_missing_action, teardown_error_only),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_message_unknown_action, teardown_error_only),
        // wm_task_manager_parse_error_response tests
        cmocka_unit_test_teardown(test_wm_task_manager_parse_error_response_ok, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_error_response_no_message, teardown_string),
        // wm_task_manager_parse_create_response tests
        cmocka_unit_test_teardown(test_wm_task_manager_parse_create_response_ok, teardown_string),
        // wm_task_manager_parse_get_pending_response tests
        cmocka_unit_test_teardown(test_wm_task_manager_parse_get_pending_response_ok, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_parse_get_pending_response_empty, teardown_string),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
