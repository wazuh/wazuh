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
#include <time.h>

#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_task_manager_wrappers.h"

#include "wmodules.h"
#include "wm_task_manager.h"
#include "wm_task_manager_tasks.h"
#include "wm_task_manager_parsing.h"
#include "shared.h"

// External functions under test
char* wm_task_manager_dispatch(const char *msg);
char* wm_task_manager_create_task(const char *agent_id, wm_task_type task_type, const char *payload_json,
                                  const char *source_id, time_t create_time, int max_payload_bytes);
cJSON* wm_task_manager_get_pending_tasks(const char *agent_id, int max_tasks);

// Setup / teardown

static int teardown_string(void **state) {
    if (state[0]) {
        char *str = (char*)state[0];
        os_free(str);
    }
    return 0;
}

static int teardown_json(void **state) {
    if (state[0]) {
        cJSON *json = state[0];
        cJSON_Delete(json);
    }
    return 0;
}

// Tests for wm_task_manager_create_task

void test_wm_task_manager_create_task_success(void **state)
{
    time_t now = 1234567890;
    const char *agent_id = "001";
    const char *payload_json = "{\"command\":\"restart\"}";
    const char *source_id = "api-request-123";
    char *expected_task_id = strdup("task-12345");

    // Mock task ID generation
    will_return(__wrap_wm_task_manager_generate_task_id, expected_task_id);

    // Mock wdbc_query_ex for create_task
    char *wdb_response = "ok {\"task_id\":\"task-12345\"}";

    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_any(__wrap_wdbc_query_ex, query);
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, wdb_response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    expect_string(__wrap_wdbc_parse_result, result, wdb_response);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    // Mock cache invalidation
    expect_string(__wrap_wm_task_cache_invalidate, agent_id, agent_id);

    // Mock debug log
    expect_string(__wrap__mtdebug1, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtdebug1, formatted_msg);

    char *task_id_result = wm_task_manager_create_task(agent_id, WM_TASK_TYPE_ACTIVE_RESPONSE,
                                                       payload_json, source_id, now, 4096);

    state[0] = task_id_result;

    assert_non_null(task_id_result);
}

void test_wm_task_manager_create_task_db_error(void **state)
{
    time_t now = 1234567890;
    const char *agent_id = "002";
    const char *payload_json = "{\"command\":\"reload\"}";
    char *expected_task_id = strdup("task-67890");

    // Mock task ID generation
    will_return(__wrap_wm_task_manager_generate_task_id, expected_task_id);

    // Mock wdbc_query_ex to fail
    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_any(__wrap_wdbc_query_ex, query);
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, NULL);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mterror, formatted_msg);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mterror, formatted_msg);

    char *task_id_result = wm_task_manager_create_task(agent_id, WM_TASK_TYPE_AGENT_RELOAD,
                                                       payload_json, NULL, now, 0);

    assert_null(task_id_result);
}

// Tests for wm_task_manager_get_pending_tasks

void test_wm_task_manager_get_pending_tasks_with_cache_miss(void **state)
{
    const char *agent_id = "001";
    time_t now = 1234567890;

    // Mock cache miss
    expect_string(__wrap_wm_task_cache_get, agent_id, agent_id);
    will_return(__wrap_wm_task_cache_get, NULL);

    expect_string(__wrap__mtdebug2, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtdebug2, formatted_msg);

    // Mock wdbc_query_ex for get_pending
    char *wdb_response = "ok {\"tasks\":[{\"task_id\":\"123\",\"task_type\":\"active_response\"}]}";

    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_any(__wrap_wdbc_query_ex, query);
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, wdb_response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    expect_string(__wrap_wdbc_parse_result, result, wdb_response);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    // Mock time() for mark_delivered
    will_return(__wrap_time, now);

    // Mock mark_delivered calls for each task
    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_any(__wrap_wdbc_query_ex, query);
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, "ok {}");
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    // Mock debug log from mark_delivered
    expect_string(__wrap__mtdebug1, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtdebug1, formatted_msg);

    // NOTE: wm_task_cache_set is NOT called when tasks have data
    // Cache only stores empty states to prevent re-delivery

    cJSON *tasks = wm_task_manager_get_pending_tasks(agent_id, 10);

    state[0] = tasks;

    assert_non_null(tasks);
    assert_true(cJSON_IsArray(tasks));
    assert_int_equal(cJSON_GetArraySize(tasks), 1);
}

void test_wm_task_manager_get_pending_tasks_with_cache_hit(void **state)
{
    const char *agent_id = "002";

    // Mock cache hit - cache only returns empty arrays (no pending tasks state)
    cJSON *cached_tasks = cJSON_CreateArray();

    expect_string(__wrap_wm_task_cache_get, agent_id, agent_id);
    will_return(__wrap_wm_task_cache_get, cached_tasks);

    expect_string(__wrap__mtdebug2, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtdebug2, formatted_msg);

    // No wdbc calls should happen - cache hit means we return immediately

    cJSON *tasks = wm_task_manager_get_pending_tasks(agent_id, 5);

    state[0] = tasks;

    assert_non_null(tasks);
    assert_true(cJSON_IsArray(tasks));
    assert_int_equal(cJSON_GetArraySize(tasks), 0);
}

void test_wm_task_manager_get_pending_tasks_no_tasks_caches_empty(void **state)
{
    const char *agent_id = "003";

    // Mock cache miss
    expect_string(__wrap_wm_task_cache_get, agent_id, agent_id);
    will_return(__wrap_wm_task_cache_get, NULL);

    expect_string(__wrap__mtdebug2, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtdebug2, formatted_msg);

    // Mock wdbc_query_ex for get_pending returning no tasks
    char *wdb_response = "ok {\"tasks\":[]}";

    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_any(__wrap_wdbc_query_ex, query);
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, wdb_response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    expect_string(__wrap_wdbc_parse_result, result, wdb_response);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    // IMPORTANT: Cache should be set when no tasks found
    expect_string(__wrap_wm_task_cache_set, agent_id, agent_id);
    expect_any(__wrap_wm_task_cache_set, tasks);

    expect_string(__wrap__mtdebug2, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtdebug2, formatted_msg);

    cJSON *tasks = wm_task_manager_get_pending_tasks(agent_id, 10);

    state[0] = tasks;

    assert_non_null(tasks);
    assert_true(cJSON_IsArray(tasks));
    assert_int_equal(cJSON_GetArraySize(tasks), 0);
}

// Tests for wm_task_manager_dispatch

void test_wm_task_manager_dispatch_create_task(void **state)
{
    time_t now = 1234567890;
    char message[512];
    snprintf(message, sizeof(message),
             "{"
             "\"action\":\"create_task\","
             "\"agent_id\":\"001\","
             "\"task_type\":\"active_response\","
             "\"create_time\":%ld,"
             "\"source_id\":\"test-123\","
             "\"payload\":{\"command\":\"test\"}"
             "}", now - 10);

    expect_string(__wrap__mtdebug1, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtdebug1, formatted_msg);

    // Mock time() - dispatch or parsing may call it
    will_return(__wrap_time, now);

    // Mock task ID generation
    char *expected_task_id = strdup("task-abc123");
    will_return(__wrap_wm_task_manager_generate_task_id, expected_task_id);

    // Mock wdbc_query_ex for create_task
    char *wdb_response = "ok {\"task_id\":\"task-abc123\"}";

    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_any(__wrap_wdbc_query_ex, query);
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, wdb_response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    expect_string(__wrap_wdbc_parse_result, result, wdb_response);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    // Mock cache invalidation
    expect_string(__wrap_wm_task_cache_invalidate, agent_id, "001");

    // Mock debug log from create_task
    expect_string(__wrap__mtdebug1, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtdebug1, formatted_msg);

    char *response = wm_task_manager_dispatch(message);

    state[0] = response;

    assert_non_null(response);

    cJSON *json = cJSON_Parse(response);
    assert_non_null(json);
    assert_non_null(cJSON_GetObjectItem(json, "status"));
    assert_string_equal(cJSON_GetObjectItem(json, "status")->valuestring, "ok");
    assert_non_null(cJSON_GetObjectItem(json, "task_id"));

    cJSON_Delete(json);
}

void test_wm_task_manager_dispatch_get_pending(void **state)
{
    const char *message = "{\"action\":\"get_pending_tasks\",\"agent_id\":\"003\"}";

    expect_string(__wrap__mtdebug1, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtdebug1, formatted_msg);

    // Mock cache miss
    expect_string(__wrap_wm_task_cache_get, agent_id, "003");
    will_return(__wrap_wm_task_cache_get, NULL);

    expect_string(__wrap__mtdebug2, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtdebug2, formatted_msg);

    // Mock empty task list from wdb
    char *wdb_response = "ok {\"tasks\":[]}";

    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_any(__wrap_wdbc_query_ex, query);
    expect_value(__wrap_wdbc_query_ex, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_ex, wdb_response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    expect_string(__wrap_wdbc_parse_result, result, wdb_response);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    // Mock cache set
    expect_string(__wrap_wm_task_cache_set, agent_id, "003");
    expect_any(__wrap_wm_task_cache_set, tasks);

    // Mock debug log - no tasks logs with mtdebug2
    expect_string(__wrap__mtdebug2, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtdebug2, formatted_msg);

    char *response = wm_task_manager_dispatch(message);

    state[0] = response;

    assert_non_null(response);

    cJSON *json = cJSON_Parse(response);
    assert_non_null(json);
    assert_non_null(cJSON_GetObjectItem(json, "status"));
    assert_string_equal(cJSON_GetObjectItem(json, "status")->valuestring, "ok");
    assert_non_null(cJSON_GetObjectItem(json, "tasks"));
    assert_true(cJSON_IsArray(cJSON_GetObjectItem(json, "tasks")));

    cJSON_Delete(json);
}

void test_wm_task_manager_dispatch_invalid_message(void **state)
{
    const char *message = "{invalid json}";

    expect_string(__wrap__mtdebug1, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtdebug1, formatted_msg);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mterror, formatted_msg);

    char *response = wm_task_manager_dispatch(message);

    state[0] = response;

    assert_non_null(response);

    cJSON *json = cJSON_Parse(response);
    assert_non_null(json);
    assert_non_null(cJSON_GetObjectItem(json, "error"));

    cJSON_Delete(json);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_task_manager_create_task tests
        cmocka_unit_test_teardown(test_wm_task_manager_create_task_success, teardown_string),
        cmocka_unit_test(test_wm_task_manager_create_task_db_error),
        // wm_task_manager_get_pending_tasks tests
        cmocka_unit_test_teardown(test_wm_task_manager_get_pending_tasks_with_cache_miss, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_get_pending_tasks_with_cache_hit, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_get_pending_tasks_no_tasks_caches_empty, teardown_json),
        // wm_task_manager_dispatch tests
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_create_task, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_get_pending, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_dispatch_invalid_message, teardown_string),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
