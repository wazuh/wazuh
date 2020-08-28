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

void wm_task_manager_destroy(wm_task_manager* task_config);
cJSON* wm_task_manager_dump(const wm_task_manager* task_config);

// Setup / teardown

static int setup_group(void **state) {
    wm_task_manager *config = NULL;
    os_calloc(1, sizeof(wm_task_manager), config);
    *state = config;
    return 0;
}

static int teardown_group(void **state) {
    wm_task_manager *config = *state;
    os_free(config);
    return 0;
}

static int teardown_json(void **state) {
    if (state[1]) {
        cJSON *json = state[1];
        cJSON_Delete(json);
    }
    return 0;
}

// Wrappers

void __wrap__mtinfo(const char *tag, const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

// Tests

void test_wm_task_manager_dump_enabled(void **state)
{
    wm_task_manager *config = *state;

    config->enabled = 1;

    cJSON *ret = wm_task_manager_dump(config);

    state[1] = ret;

    assert_non_null(ret);
    cJSON *conf = cJSON_GetObjectItem(ret, "task-manager");
    assert_non_null(conf);
    assert_non_null(cJSON_GetObjectItem(conf, "enabled"));
    assert_string_equal(cJSON_GetObjectItem(conf, "enabled")->valuestring, "yes");
}

void test_wm_task_manager_dump_disabled(void **state)
{
    wm_task_manager *config = *state;

    config->enabled = 0;

    cJSON *ret = wm_task_manager_dump(config);

    state[1] = ret;

    assert_non_null(ret);
    cJSON *conf = cJSON_GetObjectItem(ret, "task-manager");
    assert_non_null(conf);
    assert_non_null(cJSON_GetObjectItem(conf, "enabled"));
    assert_string_equal(cJSON_GetObjectItem(conf, "enabled")->valuestring, "no");
}

void test_wm_task_manager_destroy(void **state)
{
    wm_task_manager *config = NULL;
    os_calloc(1, sizeof(wm_task_manager), config);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8201): Module Task Manager finished.");

    wm_task_manager_destroy(config);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_task_manager_dump
        cmocka_unit_test_teardown(test_wm_task_manager_dump_enabled, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_dump_disabled, teardown_json),
        // wm_task_manager_destroy
        cmocka_unit_test(test_wm_task_manager_destroy),
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
