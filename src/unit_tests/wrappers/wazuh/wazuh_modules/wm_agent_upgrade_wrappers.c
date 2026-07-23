/* Copyright (C) 2015, Wazuh Inc.
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
#include <stdint.h>
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

void __wrap_wm_agent_upgrade_start_manager_module(const wm_manager_configs* manager_configs, const int enabled) {
    check_expected(manager_configs);
    check_expected(enabled);
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

cJSON* __wrap_wm_agent_upgrade_parse_task_module_request(wm_upgrade_command command, cJSON *agents_array, const char* status, const char* error) {
    check_expected(command);

    cJSON *ret = mock_type(cJSON *);
    // Note: The agents_array is typically already embedded in the returned mock JSON
    // If the mock JSON doesn't have it, we should add it to a "parameters" object
    if (ret && agents_array) {
        cJSON *parameters = cJSON_GetObjectItem(ret, "parameters");
        if (parameters && !cJSON_GetObjectItem(parameters, "agents")) {
            cJSON_AddItemToObject(parameters, "agents", agents_array);
        }
    }

    if (status) check_expected(status);
    if (error) check_expected(error);

    return ret;
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

cJSON* __wrap_wm_agent_upgrade_get_agent_ids() {
    return mock_type(cJSON*);
}

int __wrap_wm_agent_upgrade_validate_id(int agent_id) {
    check_expected(agent_id);

    return mock();
}

int __wrap_wm_agent_upgrade_validate_system(const char *platform, const char *os_major, const char *os_minor, const char *arch, char **package_type) {
    check_expected(platform);
    check_expected(os_major);
    check_expected(os_minor);
    check_expected(arch);

    os_strdup(mock_type(char*), *package_type);

    return mock();
}

int __wrap_wm_agent_upgrade_validate_version(const char *wazuh_version, const char *platform, wm_upgrade_command command, void *task) {
    check_expected(wazuh_version);
    check_expected(platform);
    check_expected(command);

    if (command == WM_UPGRADE_UPGRADE) {
        wm_upgrade_task *upgrade_task = (wm_upgrade_task *)task;
        os_strdup(mock_type(char*), upgrade_task->wpk_version);
    }

    return mock();
}

int __wrap_wm_agent_upgrade_validate_wpk_version(__attribute__((unused)) const wm_agent_info *agent_info, __attribute__((unused)) wm_upgrade_task *task, const char *wpk_repository_config) {
    check_expected(wpk_repository_config);

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
    // Note: The data is typically already embedded in the returned mock JSON
    // If the mock JSON doesn't have it, we should add it to a "data" field
    if (ret && data && !cJSON_GetObjectItem(ret, "data")) {
        if (data->type == cJSON_Array) {
            cJSON_AddItemToObject(ret, "data", data);
        } else {
            cJSON *data_array = cJSON_CreateArray();
            cJSON_AddItemToArray(data_array, data);
            cJSON_AddItemToObject(ret, "data", data_array);
        }
    }

    return ret;
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
