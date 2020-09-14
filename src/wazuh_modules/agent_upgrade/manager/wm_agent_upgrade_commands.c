/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015-2020, Wazuh Inc.
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
#include "wazuh_db/wdb.h"

/**
 * Analyze agent information and returns a JSON to be sent to the task manager
 * @param agent_id id of the agent
 * @param agent_task structure where the information of the agent will be stored
 * @param error_code variable to modify in case of failure
 * @param manager_configs manager configuration parameters
 * @return JSON task if success, NULL otherwise
 * */
STATIC cJSON* wm_agent_upgrade_analyze_agent(int agent_id, wm_agent_task *agent_task, wm_upgrade_error_code *error_code, const wm_manager_configs* manager_configs) __attribute__((nonnull));

/**
 * Validate the information of the agent and the task
 * @param agent_task structure with the information to be validated
 * @param manager_configs manager configuration parameters
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
STATIC int wm_agent_upgrade_validate_agent_task(const wm_agent_task *agent_task, const wm_manager_configs* manager_configs) __attribute__((nonnull));

char* wm_agent_upgrade_process_upgrade_command(const int* agent_ids, wm_upgrade_task* task, const wm_manager_configs* manager_configs) {
    char* response = NULL;
    int agent = 0;
    int agent_id = 0;
    cJSON* json_response = cJSON_CreateArray();
    cJSON *json_task_module_request = cJSON_CreateArray();

    while (agent_id = agent_ids[agent++], agent_id != OS_INVALID) {
        wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
        cJSON *task_request = NULL;
        wm_agent_task *agent_task = NULL;
        wm_upgrade_task *upgrade_task = NULL;

        agent_task = wm_agent_upgrade_init_agent_task();

        // Task information
        upgrade_task = wm_agent_upgrade_init_upgrade_task();
        w_strdup(task->wpk_repository, upgrade_task->wpk_repository);
        w_strdup(task->custom_version, upgrade_task->custom_version);
        upgrade_task->use_http = task->use_http;
        upgrade_task->force_upgrade = task->force_upgrade;

        agent_task->task_info = wm_agent_upgrade_init_task_info();
        agent_task->task_info->command = WM_UPGRADE_UPGRADE;
        agent_task->task_info->task = upgrade_task;

        if (task_request = wm_agent_upgrade_analyze_agent(agent_id, agent_task, &error_code, manager_configs), task_request) {
            cJSON_AddItemToArray(json_task_module_request, task_request);
        } else {
            cJSON *error_message = wm_agent_upgrade_parse_response_message(error_code, upgrade_error_codes[error_code], &agent_id, NULL, NULL);
            cJSON_AddItemToArray(json_response, error_message);
            wm_agent_upgrade_free_agent_task(agent_task);
        }
    }

    // Send request to task module and store task ids
    if (!wm_agent_upgrade_task_module_callback(json_response, json_task_module_request, wm_agent_upgrade_upgrade_success_callback, wm_agent_upgrade_remove_entry)) {
        wm_agent_upgrade_prepare_upgrades();
    } else {
        mtwarn(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_NO_AGENTS_TO_UPGRADE);
    }

    response = cJSON_PrintUnformatted(json_response);

    cJSON_Delete(json_task_module_request);
    cJSON_Delete(json_response);

    return response;
}

char* wm_agent_upgrade_process_upgrade_custom_command(const int* agent_ids, wm_upgrade_custom_task* task, const wm_manager_configs* manager_configs) {
    char* response = NULL;
    int agent = 0;
    int agent_id = 0;
    cJSON* json_response = cJSON_CreateArray();
    cJSON *json_task_module_request = cJSON_CreateArray();

    while (agent_id = agent_ids[agent++], agent_id != OS_INVALID) {
        wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
        cJSON *task_request = NULL;
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

        if (task_request = wm_agent_upgrade_analyze_agent(agent_id, agent_task, &error_code, manager_configs), task_request) {
            cJSON_AddItemToArray(json_task_module_request, task_request);
        } else {
            cJSON *error_message = wm_agent_upgrade_parse_response_message(error_code, upgrade_error_codes[error_code], &agent_id, NULL, NULL);
            cJSON_AddItemToArray(json_response, error_message);
            wm_agent_upgrade_free_agent_task(agent_task);
        }
    }

    // Send request to task module and store task ids
    if (!wm_agent_upgrade_task_module_callback(json_response, json_task_module_request, wm_agent_upgrade_upgrade_success_callback, wm_agent_upgrade_remove_entry)) {
        wm_agent_upgrade_prepare_upgrades();
    } else {
        mtwarn(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_NO_AGENTS_TO_UPGRADE);
    }

    response = cJSON_PrintUnformatted(json_response);

    cJSON_Delete(json_task_module_request);
    cJSON_Delete(json_response);

    return response;
}

char* wm_agent_upgrade_process_agent_result_command(const int* agent_ids, const wm_upgrade_agent_status_task* task) {
    // Only one id of agent will reach at a time
    char* response = NULL;
    int agent = 0;
    int agent_id = 0;
    cJSON* json_response = cJSON_CreateArray();
    cJSON *json_task_module_request = cJSON_CreateArray();

    while (agent_id = agent_ids[agent++], agent_id != OS_INVALID) {
        cJSON *request = NULL;

        if (task->message) {
            mtinfo(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_ACK_RECEIVED, agent_id, task->error_code, task->message);
        }
        // Send task update to task manager and bring back the response
        if (task->error_code) {
            request = wm_agent_upgrade_parse_task_module_request(WM_UPGRADE_AGENT_UPDATE_STATUS, agent_id, task->status, upgrade_error_codes[WM_UPGRADE_UPGRADE_ERROR]);
        } else {
            request = wm_agent_upgrade_parse_task_module_request(WM_UPGRADE_AGENT_UPDATE_STATUS, agent_id, task->status, NULL);
        }
        cJSON_AddItemToArray(json_task_module_request, request);
    }

    wm_agent_upgrade_task_module_callback(json_response, json_task_module_request, wm_agent_upgrade_update_status_success_callback, NULL);

    response = cJSON_PrintUnformatted(json_response);

    cJSON_Delete(json_task_module_request);
    cJSON_Delete(json_response);

    return response;
}

STATIC cJSON* wm_agent_upgrade_analyze_agent(int agent_id, wm_agent_task *agent_task, wm_upgrade_error_code *error_code, const wm_manager_configs* manager_configs) {
    cJSON *task_request = NULL;

    // Agent information
    agent_task->agent_info = wm_agent_upgrade_init_agent_info();
    agent_task->agent_info->agent_id = agent_id;

    if (!wdb_agent_info(agent_id,
                        &agent_task->agent_info->platform,
                        &agent_task->agent_info->major_version,
                        &agent_task->agent_info->minor_version,
                        &agent_task->agent_info->architecture,
                        &agent_task->agent_info->wazuh_version,
                        &agent_task->agent_info->last_keep_alive)) {

        // Validate agent and task information
        *error_code = wm_agent_upgrade_validate_agent_task(agent_task, manager_configs);

        if (*error_code == WM_UPGRADE_SUCCESS) {
            // Save task entry for agent
            int result = wm_agent_upgrade_create_task_entry(agent_id, agent_task);

            if (result == OSHASH_SUCCESS) {
                task_request = wm_agent_upgrade_parse_task_module_request(agent_task->task_info->command, agent_id, NULL, NULL);
            } else if (result == OSHASH_DUPLICATE) {
                *error_code = WM_UPGRADE_UPGRADE_ALREADY_IN_PROGRESS;
            } else {
                *error_code = WM_UPGRADE_UNKNOWN_ERROR;
            }
        }
    } else {
        *error_code = WM_UPGRADE_GLOBAL_DB_FAILURE;
    }

    return task_request;
}

STATIC int wm_agent_upgrade_validate_agent_task(const wm_agent_task *agent_task, const wm_manager_configs* manager_configs) {
    int validate_result = WM_UPGRADE_SUCCESS;
    cJSON *status_request = NULL;
    cJSON *status_response = NULL;
    char *status = NULL;

    // Validate agent id
    validate_result = wm_agent_upgrade_validate_id(agent_task->agent_info->agent_id);

    if (validate_result != WM_UPGRADE_SUCCESS) {
        return validate_result;
    }

    // Validate agent status
    validate_result = wm_agent_upgrade_validate_status(agent_task->agent_info->last_keep_alive);

    if (validate_result != WM_UPGRADE_SUCCESS) {
        return validate_result;
    }

    // Validate Wazuh version to upgrade
    validate_result = wm_agent_upgrade_validate_version(agent_task->agent_info, agent_task->task_info->task, agent_task->task_info->command, manager_configs);

    if (validate_result != WM_UPGRADE_SUCCESS) {
        return validate_result;
    }

    // Validate if there is a task in progress for this agent
    status_request = cJSON_CreateArray();
    status_response = cJSON_CreateArray();

    cJSON_AddItemToArray(status_request, wm_agent_upgrade_parse_task_module_request(WM_UPGRADE_AGENT_GET_STATUS, agent_task->agent_info->agent_id, NULL, NULL));
    wm_agent_upgrade_task_module_callback(status_response, status_request, NULL, NULL);
    if (!wm_agent_upgrade_validate_task_status_message(cJSON_GetArrayItem(status_response, 0), &status, NULL)) {
        validate_result = WM_UPGRADE_TASK_MANAGER_COMMUNICATION;
    } else if (status && !strcmp(status, task_statuses[WM_TASK_IN_PROGRESS])) {
        validate_result = WM_UPGRADE_UPGRADE_ALREADY_IN_PROGRESS;
    }

    cJSON_Delete(status_request);
    cJSON_Delete(status_response);
    os_free(status);

    return validate_result;
}
