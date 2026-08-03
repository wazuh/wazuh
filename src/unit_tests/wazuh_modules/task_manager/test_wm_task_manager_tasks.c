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

#include "wmodules.h"
#include "wm_task_manager.h"
#include "wm_task_manager_tasks.h"
#include "shared.h"

// External functions under test
char* wm_task_manager_generate_task_id(const char *source_id, const char *agent_id,
                                       const char *task_type, time_t create_time);
void wm_task_cache_init(void);
cJSON* wm_task_cache_get(const char *agent_id);
void wm_task_cache_set(const char *agent_id, cJSON *tasks);
void wm_task_cache_invalidate(const char *agent_id);

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

// Tests for wm_task_manager_generate_task_id

void test_wm_task_manager_generate_task_id_with_source(void **state)
{
    const char *source_id = "api-request-123";
    const char *agent_id = "001";
    const char *task_type = "active_response";
    time_t create_time = 1234567890;

    char *task_id = wm_task_manager_generate_task_id(source_id, agent_id, task_type, create_time);

    state[0] = task_id;

    assert_non_null(task_id);
    // Task ID should be deterministic - same inputs = same output
    assert_int_not_equal(strlen(task_id), 0);
}

void test_wm_task_manager_generate_task_id_without_source(void **state)
{
    const char *agent_id = "002";
    const char *task_type = "remote_upgrade";
    time_t create_time = 1234567890;

    char *task_id = wm_task_manager_generate_task_id(NULL, agent_id, task_type, create_time);

    state[0] = task_id;

    assert_non_null(task_id);
    assert_int_not_equal(strlen(task_id), 0);
}

void test_wm_task_manager_generate_task_id_deterministic(void **state)
{
    const char *source_id = "test-source";
    const char *agent_id = "003";
    const char *task_type = "agent_restart";
    time_t create_time = 1234567890;

    char *task_id1 = wm_task_manager_generate_task_id(source_id, agent_id, task_type, create_time);
    char *task_id2 = wm_task_manager_generate_task_id(source_id, agent_id, task_type, create_time);

    // Same inputs should produce identical task IDs
    assert_non_null(task_id1);
    assert_non_null(task_id2);
    assert_string_equal(task_id1, task_id2);

    os_free(task_id1);
    os_free(task_id2);
}

// Tests for cache functions

void test_wm_task_cache_init(void **state)
{
    // Just verify it doesn't crash
    wm_task_cache_init();
    // No assertions needed - just checking it initializes without error
}

void test_wm_task_cache_set_and_get(void **state)
{
    const char *agent_id = "001";

    // Initialize cache first
    wm_task_cache_init();

    // Create empty tasks array (cache only stores "no pending tasks" state)
    cJSON *tasks = cJSON_CreateArray();

    // Set in cache (only empty arrays should be cached)
    wm_task_cache_set(agent_id, tasks);

    // Get from cache
    cJSON *cached_tasks = wm_task_cache_get(agent_id);

    state[0] = cached_tasks;

    // Verify we got an empty array back
    assert_non_null(cached_tasks);
    assert_true(cJSON_IsArray(cached_tasks));
    assert_int_equal(cJSON_GetArraySize(cached_tasks), 0);

    // Clean up original tasks
    cJSON_Delete(tasks);
}

void test_wm_task_cache_get_nonexistent(void **state)
{
    const char *agent_id = "nonexistent";

    // Initialize cache first
    wm_task_cache_init();

    // Try to get non-existent entry
    cJSON *cached_tasks = wm_task_cache_get(agent_id);

    // Should return NULL for non-existent entry
    assert_null(cached_tasks);
}

void test_wm_task_cache_does_not_cache_tasks(void **state)
{
    const char *agent_id = "002";

    // Initialize cache
    wm_task_cache_init();

    // Create tasks with data
    cJSON *tasks = cJSON_CreateArray();
    cJSON *task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, "task_id", "test-456");
    cJSON_AddItemToArray(tasks, task);

    // Try to cache tasks with data (should be rejected)
    wm_task_cache_set(agent_id, tasks);
    cJSON_Delete(tasks);

    // Verify nothing was cached (cache only stores empty states)
    cJSON *cached = wm_task_cache_get(agent_id);
    assert_null(cached);
}

void test_wm_task_cache_invalidate(void **state)
{
    const char *agent_id = "003";

    // Initialize cache
    wm_task_cache_init();

    // Create and cache empty tasks (cache only stores "no pending tasks" state)
    cJSON *tasks = cJSON_CreateArray();

    wm_task_cache_set(agent_id, tasks);
    cJSON_Delete(tasks);

    // Verify it's cached
    cJSON *cached = wm_task_cache_get(agent_id);
    assert_non_null(cached);
    cJSON_Delete(cached);

    // Invalidate
    wm_task_cache_invalidate(agent_id);

    // Verify it's gone
    cached = wm_task_cache_get(agent_id);
    assert_null(cached);
}

static int group_teardown(void **state) {
    (void) state; // unused
    // Clean up global cache to prevent memory leaks
    wm_task_cache_destroy();
    return 0;
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Task ID generation tests
        cmocka_unit_test_teardown(test_wm_task_manager_generate_task_id_with_source, teardown_string),
        cmocka_unit_test_teardown(test_wm_task_manager_generate_task_id_without_source, teardown_string),
        cmocka_unit_test(test_wm_task_manager_generate_task_id_deterministic),
        // Cache tests
        cmocka_unit_test(test_wm_task_cache_init),
        cmocka_unit_test_teardown(test_wm_task_cache_set_and_get, teardown_json),
        cmocka_unit_test(test_wm_task_cache_get_nonexistent),
        cmocka_unit_test(test_wm_task_cache_does_not_cache_tasks),
        cmocka_unit_test(test_wm_task_cache_invalidate),
    };
    return cmocka_run_group_tests(tests, NULL, group_teardown);
}
