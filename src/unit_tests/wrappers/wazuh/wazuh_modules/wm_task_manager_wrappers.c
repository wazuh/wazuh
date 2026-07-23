/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "../../common.h"
#include "wm_task_manager_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

cJSON* __wrap_wm_task_manager_parse_message(const char *msg) {
    check_expected(msg);

    return mock_type(cJSON*);
}

cJSON* __wrap_wm_task_manager_parse_data_response(int error_code, int agent_id, int task_id, char *status) {
    check_expected(error_code);
    check_expected(agent_id);
    check_expected(task_id);
    if (status) check_expected(status);

    return mock_type(cJSON*);
}

void __wrap_wm_task_manager_parse_data_result(__attribute__ ((__unused__)) cJSON *response, const char *node, const char *module, const char *command, char *status, char *error, int create_time, int last_update_time, char *request_command) {
    check_expected(node);
    check_expected(module);
    check_expected(command);
    check_expected(status);
    check_expected(error);
    check_expected(create_time);
    check_expected(last_update_time);
    check_expected(request_command);
}

void __wrap_wm_task_cache_init(__attribute__ ((__unused__)) int cache_ttl) {
    // No-op wrapper - cache init doesn't need mocking for these tests
}

int __wrap_w_create_thread(__attribute__ ((__unused__)) void *(*function_pointer)(void *),
                            __attribute__ ((__unused__)) void *data) {
    return 0; // Success
}

cJSON* __wrap_wm_task_cache_get(const char *agent_id) {
    check_expected(agent_id);
    return mock_type(cJSON*);
}

void __wrap_wm_task_cache_set(const char *agent_id, __attribute__ ((__unused__)) cJSON *tasks) {
    check_expected(agent_id);
    check_expected_ptr(tasks);
}

void __wrap_wm_task_cache_invalidate(const char *agent_id) {
    check_expected(agent_id);
}

char* __wrap_wm_task_manager_generate_task_id(__attribute__ ((__unused__)) const char *source_id,
                                               __attribute__ ((__unused__)) const char *agent_id,
                                               __attribute__ ((__unused__)) const char *task_type,
                                               __attribute__ ((__unused__)) time_t create_time) {
    return mock_type(char*);
}
