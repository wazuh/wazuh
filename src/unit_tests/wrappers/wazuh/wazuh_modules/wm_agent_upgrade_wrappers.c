/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "../../common.h"
#include "wm_agent_upgrade_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

OSHash *hash_table;

int setup_hash_table(void (free_data_function)(wm_agent_task* agent_task)) {
    hash_table = OSHash_Create();
    if (free_data_function) {
        OSHash_SetFreeDataPointer(hash_table, (void (*)(void *))free_data_function);
    }
    return 0;
}

int teardown_hash_table() {
    OSHash_Free(hash_table);
    return 0;
}

int __wrap_wm_agent_upgrade_check_status(__attribute__((unused)) const wm_agent_configs* agent_config) {
    return mock();
}

int __wrap_wm_agent_upgrade_listen_messages(__attribute__((unused)) const wm_manager_configs* manager_configs) {
    return mock();
}

int __wrap_wm_agent_upgrade_parse_message(const char* buffer, void** task, int** agent_ids, char** error) {
    check_expected(buffer);

    *task = mock_type(void*);
    *agent_ids = mock_type(int*);
    *error = mock_type(char*);

    return mock();
}

char* __wrap_wm_agent_upgrade_process_upgrade_command(const int* agent_ids, wm_upgrade_task* task, __attribute__((unused)) const wm_manager_configs* manager_configs) {
    check_expected_ptr(agent_ids);
    check_expected_ptr(task);

    return mock_type(char *);
}

char* __wrap_wm_agent_upgrade_process_upgrade_custom_command(const int* agent_ids, wm_upgrade_custom_task* task, __attribute__((unused)) const wm_manager_configs* manager_configs) {
    check_expected_ptr(agent_ids);
    check_expected_ptr(task);

    return mock_type(char *);
}

char* __wrap_wm_agent_upgrade_process_agent_result_command(const int* agent_ids, wm_upgrade_agent_status_task* task) {
    check_expected_ptr(agent_ids);
    check_expected_ptr(task);

    return mock_type(char *);
}

cJSON* __wrap_wm_agent_upgrade_parse_task_module_request(wm_upgrade_command command, cJSON *agents_array, const char* status, const char* error) {
    check_expected(command);

    cJSON *ret = mock_type(cJSON *);
    cJSON_AddItemToObject(cJSON_GetObjectItem(ret, task_manager_json_keys[WM_TASK_PARAMETERS]), task_manager_json_keys[WM_TASK_AGENTS], agents_array);

    if (status) check_expected(status);
    if (error) check_expected(error);

    return ret;
}

int __wrap_wm_agent_upgrade_task_module_callback(cJSON *json_response, const cJSON* task_module_request) {
    check_expected(task_module_request);

    cJSON *data = mock_type(cJSON *);
    if (data) {
        cJSON_AddItemToArray(json_response, data);
    }

    return mock();
}

int __wrap_wm_agent_upgrade_parse_agent_response(const char* agent_response, char **data) {
    check_expected(agent_response);

    if (data && strchr(agent_response, ' ')) {
        *data = strchr(agent_response, ' ') + 1;
    }

    return mock();
}

OSHashNode* __wrap_wm_agent_upgrade_get_first_node(unsigned int *index) {
    if (mock()) {
        return mock_type(OSHashNode *);
    } else {
        return OSHash_Begin(hash_table, index);
    }
}

OSHashNode* __wrap_wm_agent_upgrade_get_next_node(unsigned int *index, OSHashNode *current) {
    if (mock()) {
        return mock_type(OSHashNode *);
    } else {
        return OSHash_Next(hash_table, index, current);
    }
}

int __wrap_wm_agent_upgrade_compare_versions(const char *version1, const char *version2) {
    check_expected(version1);
    check_expected(version2);

    return mock();
}

bool __wrap_wm_agent_upgrade_validate_task_status_message(const cJSON *input_json, char **status, int *agent_id) {
    check_expected(input_json);
    if (status) os_strdup(mock_type(char *), *status);
    if (agent_id) *agent_id = mock();

    return mock();
}

int __wrap_wm_agent_upgrade_validate_id(int agent_id) {
    check_expected(agent_id);

    return mock();
}

int __wrap_wm_agent_upgrade_validate_status(int last_keep_alive) {
    check_expected(last_keep_alive);

    return mock();
}

int __wrap_wm_agent_upgrade_validate_version(__attribute__((unused)) const wm_agent_info *agent_info, void *task, wm_upgrade_command command, const wm_manager_configs* manager_configs) {
    check_expected(command);
    check_expected(manager_configs);

    if (command == WM_UPGRADE_UPGRADE) {
        wm_upgrade_task *upgrade_task = (wm_upgrade_task *)task;
        os_strdup(mock_type(char*), upgrade_task->wpk_file);
        os_strdup(mock_type(char*), upgrade_task->wpk_sha1);
    }

    return mock();
}

int __wrap_wm_agent_upgrade_validate_wpk(__attribute__((unused)) const wm_upgrade_task *task) {
    return mock();
}

int __wrap_wm_agent_upgrade_validate_wpk_custom(__attribute__((unused)) const wm_upgrade_custom_task *task) {
    return mock();
}

int __wrap_wm_agent_upgrade_create_task_entry(int agent_id, wm_agent_task* ag_task) {
    check_expected(agent_id);

    char key[128];
    sprintf(key, "%d", agent_id);
    OSHash_Add_ex(hash_table, key, ag_task);

    return mock();
}

int __wrap_wm_agent_upgrade_remove_entry(int agent_id, int free) {
    check_expected(agent_id);
    check_expected(free);

    return mock();
}

cJSON* __wrap_wm_agent_upgrade_parse_data_response(int error_id, const char* message, const int* agent_id) {
    int agent_int;

    check_expected(error_id);
    check_expected(message);
    if (agent_id) {
        agent_int = *agent_id;
        check_expected(agent_int);
    }

    return mock_type(cJSON *);
}

cJSON* __wrap_wm_agent_upgrade_parse_response(int error_id, cJSON *data) {
    check_expected(error_id);

    cJSON *ret = mock_type(cJSON*);
    if (data && (data->type == cJSON_Array)) {
        cJSON_AddItemToObject(ret, task_manager_json_keys[WM_TASK_DATA], data);
    } else {
        cJSON *data_array = cJSON_CreateArray();
        cJSON_AddItemToArray(data_array, data);
        cJSON_AddItemToObject(ret, task_manager_json_keys[WM_TASK_DATA], data_array);
    }

    return ret;
}

cJSON* __wrap_w_create_sendsync_payload(const char *daemon_name, __attribute__ ((__unused__)) cJSON *message) {
    check_expected(daemon_name);

    return mock_type(cJSON*);
}

int __wrap_w_send_clustered_message(const char* command, const char* payload, char* response) {
    check_expected(command);
    check_expected(payload);

    strcpy(response, mock_type(char*));

    return mock();
}

bool __wrap_wm_agent_upgrade_validate_task_ids_message(__attribute__ ((__unused__)) const cJSON *input_json, int *agent_id, int *task_id, char** data) {
    if (agent_id) *agent_id = mock();
    if (task_id) *task_id = mock();
    if (data) os_strdup(mock_type(char *), *data);

    return mock();
}

void __wrap_wm_agent_upgrade_insert_task_id(int agent_id, int task_id) {
    check_expected(agent_id);
    check_expected(task_id);
}

char* __wrap_wm_agent_upgrade_send_command_to_agent(const char *command, const size_t command_size) {
    check_expected(command);
    check_expected(command_size);

    return mock_type(char *);
}

cJSON* __wrap_wm_agent_upgrade_send_tasks_information(const cJSON *message_object) {
    check_expected(message_object);

    return mock_type(cJSON *);
}

int __wrap_wm_agent_upgrade_prepare_upgrades() {
    return mock();
}

int __wrap_wm_agent_upgrade_cancel_pending_upgrades() {
    return mock();
}
