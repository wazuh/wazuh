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

void __wrap_wm_task_cache_init(void) {
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
