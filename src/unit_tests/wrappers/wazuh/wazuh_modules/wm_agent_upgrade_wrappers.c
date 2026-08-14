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

int __wrap_wm_agent_upgrade_validate_wpk_version(__attribute__((unused)) const wm_agent_info *agent_info, wm_upgrade_task *task, const char *wpk_repository_config) {
    check_expected(wpk_repository_config);

    if (task) {
        if (!task->wpk_file) {
            os_strdup("wazuh_agent.wpk", task->wpk_file);
        }
        if (!task->wpk_sha1) {
            os_strdup("d321af65983fa412e3a12c312ada12ab321a253a", task->wpk_sha1);
        }
    }

    return mock();
}

int __wrap_wm_agent_upgrade_validate_wpk(__attribute__((unused)) const wm_upgrade_task *task) {
    return mock();
}

int __wrap_wm_agent_upgrade_validate_wpk_custom(wm_upgrade_custom_task *task) {
    if (task && !task->wpk_sha1) {
        os_strdup("d321af65983fa412e3a12c312ada12ab321a253a", task->wpk_sha1);
    }
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

cJSON* __wrap_wm_agent_upgrade_send_tasks_information(const cJSON *message_object) {
    check_expected(message_object);

    return mock_type(cJSON *);
}
