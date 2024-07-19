/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015, Wazuh Inc.
 * July 3, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

#include "wazuh_modules/wmodules.h"
#include "wm_agent_upgrade_manager.h"
#include "wm_agent_upgrade_parsing.h"
#include "wm_agent_upgrade_tasks.h"
#include "wm_agent_upgrade_validate.h"
#include "wm_agent_upgrade_upgrades.h"
#include "wazuh_db/helpers/wdb_global_helpers.h"

/**
 * Analyze agent information and returns a JSON to be sent to the task manager
 * @param agent_id id of the agent
 * @param agent_task structure where the information of the agent will be stored
 * @param error_code variable to modify in case of failure
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_GLOBAL_DB_FAILURE
 * @retval WM_UPGRADE_INVALID_ACTION_FOR_MANAGER
 * @retval WM_UPGRADE_AGENT_IS_NOT_ACTIVE
 * @retval WM_UPGRADE_UPGRADE_ALREADY_IN_PROGRESS
 * @retval WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED
 * @retval WM_UPGRADE_SYSTEM_NOT_SUPPORTED
 * @retval WM_UPGRADE_URL_NOT_FOUND
 * @retval WM_UPGRADE_WPK_VERSION_DOES_NOT_EXIST
 * @retval WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT
 * @retval WM_UPGRADE_NEW_VERSION_GREATER_MASTER
 * @retval WM_UPGRADE_UNKNOWN_ERROR
 * */
STATIC int wm_agent_upgrade_analyze_agent(int agent_id, wm_agent_task *agent_task) __attribute__((nonnull));

/**
 * Validate the information of the agent and the task
 * @param agent_task structure with the information to be validated
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_GLOBAL_DB_FAILURE
 * @retval WM_UPGRADE_INVALID_ACTION_FOR_MANAGER
 * @retval WM_UPGRADE_AGENT_IS_NOT_ACTIVE
 * @retval WM_UPGRADE_UPGRADE_ALREADY_IN_PROGRESS
 * @retval WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED
 * @retval WM_UPGRADE_SYSTEM_NOT_SUPPORTED
 * @retval WM_UPGRADE_URL_NOT_FOUND
 * @retval WM_UPGRADE_WPK_VERSION_DOES_NOT_EXIST
 * @retval WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT
 * @retval WM_UPGRADE_NEW_VERSION_GREATER_MASTER
 * @retval WM_UPGRADE_UNKNOWN_ERROR
 * */
STATIC int wm_agent_upgrade_validate_agent_task(const wm_agent_task *agent_task) __attribute__((nonnull));

/**
 * Validate previous upgrade tasks and create new upgrade tasks if necessary
 * @param data_array cJSON array where the task responses will be stored
 * @return 1 if there are new upgrades, 0 otherwise
 */
STATIC int wm_agent_upgrade_create_upgrade_tasks(cJSON *data_array, wm_upgrade_command command) __attribute__((nonnull));

void wm_agent_upgrade_cancel_pending_upgrades() {
    cJSON *cancel_request = NULL;
    cJSON *cancel_response = NULL;

    cancel_response = cJSON_CreateArray();
    cancel_request = wm_agent_upgrade_parse_task_module_request(WM_UPGRADE_CANCEL_TASKS, NULL, NULL, NULL);

    wm_agent_upgrade_task_module_callback(cancel_response, cancel_request, NULL, NULL);

    cJSON_Delete(cancel_request);
    cJSON_Delete(cancel_response);
}

char* wm_agent_upgrade_process_upgrade_command(const int* agent_ids, wm_upgrade_task* task) {
    char* response = NULL;
    int agent = 0;
    int agent_id = 0;
    cJSON *json_response = NULL;
    cJSON* data_array = cJSON_CreateArray();

    while (agent_id = agent_ids[agent++], agent_id != OS_INVALID) {
        wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
        wm_agent_task *agent_task = NULL;
        wm_upgrade_task *upgrade_task = NULL;

        agent_task = wm_agent_upgrade_init_agent_task();

        // Task information
        upgrade_task = wm_agent_upgrade_init_upgrade_task();
        w_strdup(task->wpk_repository, upgrade_task->wpk_repository);
        w_strdup(task->custom_version, upgrade_task->custom_version);
        upgrade_task->use_http = task->use_http;
        upgrade_task->force_upgrade = task->force_upgrade;
        w_strdup(task->package_type, upgrade_task->package_type);

        agent_task->task_info = wm_agent_upgrade_init_task_info();
        agent_task->task_info->command = WM_UPGRADE_UPGRADE;
        agent_task->task_info->task = upgrade_task;

        if (error_code = wm_agent_upgrade_analyze_agent(agent_id, agent_task), error_code != WM_UPGRADE_SUCCESS) {
            cJSON *error_message = wm_agent_upgrade_parse_data_response(error_code, upgrade_error_codes[error_code], &agent_id);
            cJSON_AddItemToArray(data_array, error_message);
            wm_agent_upgrade_free_agent_task(agent_task);
        }
    }

    // Check and create new upgrade tasks if necessary
    if (!wm_agent_upgrade_create_upgrade_tasks(data_array, WM_UPGRADE_UPGRADE)) {
        mtwarn(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_NO_AGENTS_TO_UPGRADE);
    }

    json_response = wm_agent_upgrade_parse_response(WM_UPGRADE_SUCCESS, data_array);
    response = cJSON_PrintUnformatted(json_response);

    cJSON_Delete(json_response);

    return response;
}

char* wm_agent_upgrade_process_upgrade_custom_command(const int* agent_ids, wm_upgrade_custom_task* task) {
    char* response = NULL;
    int agent = 0;
    int agent_id = 0;
    cJSON *json_response = NULL;
    cJSON* data_array = cJSON_CreateArray();

    while (agent_id = agent_ids[agent++], agent_id != OS_INVALID) {
        wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
        wm_agent_task *agent_task = NULL;
        wm_upgrade_custom_task *upgrade_custom_task = NULL;

        agent_task = wm_agent_upgrade_init_agent_task();

        // Task information
        upgrade_custom_task = wm_agent_upgrade_init_upgrade_custom_task();
        w_strdup(task->custom_file_path, upgrade_custom_task->custom_file_path);
        w_strdup(task->custom_installer, upgrade_custom_task->custom_installer);

        agent_task->task_info = wm_agent_upgrade_init_task_info();
        agent_task->task_info->command = WM_UPGRADE_UPGRADE_CUSTOM;
        agent_task->task_info->task = upgrade_custom_task;

        if (error_code = wm_agent_upgrade_analyze_agent(agent_id, agent_task), error_code != WM_UPGRADE_SUCCESS) {
            cJSON *error_message = wm_agent_upgrade_parse_data_response(error_code, upgrade_error_codes[error_code], &agent_id);
            cJSON_AddItemToArray(data_array, error_message);
            wm_agent_upgrade_free_agent_task(agent_task);
        }
    }

    // Check and create new upgrade tasks if necessary
    if (!wm_agent_upgrade_create_upgrade_tasks(data_array, WM_UPGRADE_UPGRADE_CUSTOM)) {
        mtwarn(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_NO_AGENTS_TO_UPGRADE);
    }

    json_response = wm_agent_upgrade_parse_response(WM_UPGRADE_SUCCESS, data_array);
    response = cJSON_PrintUnformatted(json_response);

    cJSON_Delete(json_response);

    return response;
}

char* wm_agent_upgrade_process_agent_result_command(const int* agent_ids, const wm_upgrade_agent_status_task* task) {
    // Only one id of agent will reach at a time
    char* response = NULL;
    int agent = 0;
    int agent_id = 0;
    cJSON *json_response = NULL;
    cJSON *json_task_module_request = NULL;
    cJSON* data_array = cJSON_CreateArray();
    cJSON *agents_array = cJSON_CreateArray();

    while (agent_id = agent_ids[agent++], agent_id != OS_INVALID) {

        mtinfo(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_ACK_RECEIVED, agent_id, task->error_code, task->message ? task->message : "");

        cJSON_AddItemToArray(agents_array, cJSON_CreateNumber(agent_id));
    }

    if (task->error_code) {
        char *error = NULL;
        if (task->error_code == 1) {
            error = upgrade_error_codes[WM_UPGRADE_UPGRADE_ERROR_MISSING_PACKAGE];
        } else {
            error = upgrade_error_codes[WM_UPGRADE_UPGRADE_ERROR];
        }
        json_task_module_request = wm_agent_upgrade_parse_task_module_request(WM_UPGRADE_AGENT_UPDATE_STATUS, agents_array, task->status, error);
    } else {
        json_task_module_request = wm_agent_upgrade_parse_task_module_request(WM_UPGRADE_AGENT_UPDATE_STATUS, agents_array, task->status, NULL);
    }

    // Send task update to task manager and bring back the response
    wm_agent_upgrade_task_module_callback(data_array, json_task_module_request, wm_agent_upgrade_update_status_success_callback, NULL);

    json_response = wm_agent_upgrade_parse_response(WM_UPGRADE_SUCCESS, data_array);
    response = cJSON_PrintUnformatted(json_response);

    cJSON_Delete(json_task_module_request);
    cJSON_Delete(json_response);

    return response;
}

char* wm_agent_upgrade_process_upgrade_result_command(const int* agent_ids) {
    char* response = NULL;
    int agent = 0;
    int agent_id = 0;
    cJSON *json_response = NULL;
    cJSON *json_task_module_request = NULL;
    cJSON* data_array = cJSON_CreateArray();
    cJSON *agents_array = cJSON_CreateArray();

    while (agent_id = agent_ids[agent++], agent_id != OS_INVALID) {
        cJSON_AddItemToArray(agents_array, cJSON_CreateNumber(agent_id));
    }

    json_task_module_request = wm_agent_upgrade_parse_task_module_request(WM_UPGRADE_RESULT, agents_array, NULL, NULL);

    // Send upgrade result request to task manager and bring back the response
    wm_agent_upgrade_task_module_callback(data_array, json_task_module_request, NULL, NULL);

    json_response = wm_agent_upgrade_parse_response(WM_UPGRADE_SUCCESS, data_array);
    response = cJSON_PrintUnformatted(json_response);

    cJSON_Delete(json_task_module_request);
    cJSON_Delete(json_response);

    return response;
}

STATIC int wm_agent_upgrade_analyze_agent(int agent_id, wm_agent_task *agent_task) {
    int validate_result = WM_UPGRADE_SUCCESS;
    cJSON *agent_info = NULL;
    cJSON *value = NULL;

    // Agent information
    agent_task->agent_info = wm_agent_upgrade_init_agent_info();
    agent_task->agent_info->agent_id = agent_id;

    agent_info = wdb_get_agent_info(agent_id, NULL);

    if (agent_info && agent_info->child) {

        // Platform
        value = cJSON_GetObjectItem(agent_info->child, "os_platform");
        if(cJSON_IsString(value) && value->valuestring != NULL){
            os_strdup(value->valuestring, agent_task->agent_info->platform);
        }

        // Major version
        value = cJSON_GetObjectItem(agent_info->child, "os_major");
        if(cJSON_IsString(value) && value->valuestring != NULL){
            os_strdup(value->valuestring, agent_task->agent_info->major_version);
        }

        // Minor version
        value = cJSON_GetObjectItem(agent_info->child, "os_minor");
        if(cJSON_IsString(value) && value->valuestring != NULL){
            os_strdup(value->valuestring, agent_task->agent_info->minor_version);
        }

        // Architecture
        value = cJSON_GetObjectItem(agent_info->child, "os_arch");
        if(cJSON_IsString(value) && value->valuestring != NULL){
            os_strdup(value->valuestring, agent_task->agent_info->architecture);
        }

        // Wazuh version
        value = cJSON_GetObjectItem(agent_info->child, "version");
        if(cJSON_IsString(value) && value->valuestring != NULL){
            os_strdup(value->valuestring, agent_task->agent_info->wazuh_version);
        }

        // Connection status
        value = cJSON_GetObjectItem(agent_info->child, "connection_status");
        if(cJSON_IsString(value) && value->valuestring != NULL){
            os_strdup(value->valuestring, agent_task->agent_info->connection_status);
        }

        // Validate agent and task information
        validate_result = wm_agent_upgrade_validate_agent_task(agent_task);

        if (validate_result == WM_UPGRADE_SUCCESS) {
            // Save task entry for agent
            int result = wm_agent_upgrade_create_task_entry(agent_id, agent_task);

            if (result == OSHASH_DUPLICATE) {
                validate_result = WM_UPGRADE_UPGRADE_ALREADY_IN_PROGRESS;
            } else if (result != OSHASH_SUCCESS) {
                validate_result = WM_UPGRADE_UNKNOWN_ERROR;
            }
        }

        cJSON_Delete(agent_info);

    } else {
        validate_result = WM_UPGRADE_GLOBAL_DB_FAILURE;
    }

    return validate_result;
}

STATIC int wm_agent_upgrade_validate_agent_task(const wm_agent_task *agent_task) {
    int validate_result = WM_UPGRADE_SUCCESS;

    // Validate agent id
    validate_result = wm_agent_upgrade_validate_id(agent_task->agent_info->agent_id);

    if (validate_result != WM_UPGRADE_SUCCESS) {
        return validate_result;
    }

    // Validate agent status
    validate_result = wm_agent_upgrade_validate_status(agent_task->agent_info->connection_status);

    if (validate_result != WM_UPGRADE_SUCCESS) {
        return validate_result;
    }

    // Validate system information
    validate_result = wm_agent_upgrade_validate_system(agent_task->agent_info->platform, agent_task->agent_info->major_version, agent_task->agent_info->minor_version, agent_task->agent_info->architecture, &agent_task->agent_info->package_type);

    if (validate_result != WM_UPGRADE_SUCCESS) {
        return validate_result;
    }

    // Validate Wazuh version to upgrade
    validate_result = wm_agent_upgrade_validate_version(agent_task->agent_info->wazuh_version, agent_task->agent_info->platform, agent_task->task_info->command, agent_task->task_info->task);

    return validate_result;
}

STATIC int wm_agent_upgrade_create_upgrade_tasks(cJSON *data_array, wm_upgrade_command command) {
    cJSON *agents_array = NULL;
    int new_upgrades = 0;

    if (agents_array = wm_agent_upgrade_get_agent_ids(), agents_array) {
        // Check for upgrade tasks already in progress
        cJSON *status_request = wm_agent_upgrade_parse_task_module_request(WM_UPGRADE_AGENT_GET_STATUS, agents_array, NULL, NULL);

        if (!wm_agent_upgrade_task_module_callback(data_array, status_request, wm_agent_upgrade_get_status_success_callback, wm_agent_upgrade_remove_entry)) {

            if (agents_array = wm_agent_upgrade_get_agent_ids(), agents_array) {
                // Create upgrade tasks
                cJSON *upgrade_request = wm_agent_upgrade_parse_task_module_request(command, agents_array, NULL, NULL);

                if (!wm_agent_upgrade_task_module_callback(data_array, upgrade_request, wm_agent_upgrade_upgrade_success_callback, wm_agent_upgrade_remove_entry)) {
                    // Enqueue upgrades
                    wm_agent_upgrade_prepare_upgrades();
                    new_upgrades = 1;
                }
                cJSON_Delete(upgrade_request);
            }
        }
        cJSON_Delete(status_request);
    }

    return new_upgrades;
}
