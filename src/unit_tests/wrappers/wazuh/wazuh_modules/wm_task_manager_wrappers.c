/* Copyright (C) 2015-2020, Wazuh Inc.
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

int __wrap_wm_task_manager_check_db() {
    return mock();
}

cJSON* __wrap_wm_task_manager_parse_message(const char *msg) {
    check_expected(msg);

    return mock_type(cJSON*);
}

cJSON* __wrap_wm_task_manager_analyze_task(const cJSON *task_object, int *error_code) {
    check_expected(task_object);

    *error_code = mock();

    return mock_type(cJSON*);
}

cJSON* __wrap_wm_task_manager_parse_data_response(int error_code, int agent_id, int task_id, char *status) {
    check_expected(error_code);
    check_expected(agent_id);
    check_expected(task_id);
    if (status) check_expected(status);

    return mock_type(cJSON*);
}

int __wrap_wm_task_manager_get_upgrade_task_by_agent_id(int agent_id, char **node, char **module, char **command, char **status, char **error, int *create_time, int *last_update_time) {
    check_expected(agent_id);

    os_strdup(mock_type(char*), *node);
    os_strdup(mock_type(char*), *module);
    os_strdup(mock_type(char*), *command);
    os_strdup(mock_type(char*), *status);
    os_strdup(mock_type(char*), *error);
    *create_time = mock();
    *last_update_time = mock();

    return mock();
}

int __wrap_wm_task_manager_get_task_by_task_id(int task_id, char **node, char **module, char **command, char **status, char **error, int *create_time, int *last_update_time) {
    check_expected(task_id);

    os_strdup(mock_type(char*), *node);
    os_strdup(mock_type(char*), *module);
    os_strdup(mock_type(char*), *command);
    os_strdup(mock_type(char*), *status);
    os_strdup(mock_type(char*), *error);
    *create_time = mock();
    *last_update_time = mock();

    return mock();
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

int __wrap_wm_task_manager_insert_task(int agent_id, const char *node, const char *module, const char *command) {
    check_expected(agent_id);
    check_expected(node);
    check_expected(module);
    check_expected(command);

    return mock();
}

int __wrap_wm_task_manager_get_upgrade_task_status(int agent_id, const char *node, char **status) {
    check_expected(agent_id);
    check_expected(node);

    os_strdup(mock_type(char*), *status);

    return mock();
}

int __wrap_wm_task_manager_update_upgrade_task_status(int agent_id, const char *node, const char *status, const char *error) {
    check_expected(agent_id);
    check_expected(node);
    if (status) check_expected(status);
    if (error) check_expected(error);

    return mock();
}

int __wrap_wm_task_manager_cancel_upgrade_tasks(const char *node) {
    check_expected(node);

    return mock();
}
