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

#include "wmodules.h"
#include "wm_agent_upgrade_manager.h"
#include "wm_agent_upgrade_parsing.h"
#include "wm_agent_upgrade_validate.h"
#include "wazuhdb_queries_op.h"

/**
 * Analyze agent information and returns a JSON to be sent to the task manager
 * @param agent_id id of the agent
 * @param agent_task structure where the information of the agent will be stored
 * @param error_code variable to modify in case of failure
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_GLOBAL_DB_FAILURE
 * @retval WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED
 * @retval WM_UPGRADE_SYSTEM_NOT_SUPPORTED
 * @retval WM_UPGRADE_URL_NOT_FOUND
 * @retval WM_UPGRADE_WPK_VERSION_DOES_NOT_EXIST
 * @retval WM_UPGRADE_NEW_VERSION_LESS_OR_EQUAL_THAN_CURRENT
 * @retval WM_UPGRADE_NEW_VERSION_GREATER_MASTER
 * @retval WM_UPGRADE_UNKNOWN_ERROR
 * */
STATIC int wm_agent_upgrade_analyze_agent(int agent_id, wm_agent_task *agent_task, const char *wpk_repository_config) __attribute__((nonnull(2)));

/**
 * Validate the information of the agent and the task
 * @param agent_task structure with the information to be validated
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_GLOBAL_DB_FAILURE
 * @retval WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED
 * @retval WM_UPGRADE_SYSTEM_NOT_SUPPORTED
 * @retval WM_UPGRADE_URL_NOT_FOUND
 * @retval WM_UPGRADE_WPK_VERSION_DOES_NOT_EXIST
 * @retval WM_UPGRADE_NEW_VERSION_LESS_OR_EQUAL_THAN_CURRENT
 * @retval WM_UPGRADE_NEW_VERSION_GREATER_MASTER
 * @retval WM_UPGRADE_UNKNOWN_ERROR
 * */
STATIC int wm_agent_upgrade_validate_agent_task(const wm_agent_task *agent_task, const char *wpk_repository_config) __attribute__((nonnull(1)));

/**
 * Build Task Manager JSON message for upgrade task
 * @param agent_id agent identifier
 * @param request_time timestamp for deterministic task ID
 * @param wpk_file WPK file path
 * @param wpk_sha1 WPK SHA1 hash
 * @param installer installer script name
 * @return cJSON object (must be freed by caller) or NULL on error
 */
STATIC cJSON* wm_agent_upgrade_build_task_message(int agent_id, time_t request_time, const char *wpk_file, const char *wpk_sha1, const char *installer) __attribute__((nonnull(3, 4, 5)));

/**
 * Create a Task Manager task for a single validated agent
 * @param agent_task validated agent task structure
 * @return error code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_UNKNOWN_ERROR
 * @retval WM_UPGRADE_TASK_MANAGER_COMMUNICATION
 * @retval WM_UPGRADE_TASK_MANAGER_FAILURE
 */
STATIC wm_upgrade_error_code wm_agent_upgrade_create_task_for_agent(wm_agent_task *agent_task) __attribute__((nonnull));

char* wm_agent_upgrade_process_upgrade_command(const int* agent_ids, wm_upgrade_task* task, const char *wpk_repository_config) {
    char* response = NULL;
    int agent = 0;
    int agent_id = 0;
    cJSON *json_response = NULL;
    cJSON* data_array = cJSON_CreateArray();
    int tasks_created = 0;

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
        upgrade_task->request_time = task->request_time;

        agent_task->task_info = wm_agent_upgrade_init_task_info();
        agent_task->task_info->command = WM_UPGRADE_UPGRADE;
        agent_task->task_info->task = upgrade_task;

        if (error_code = wm_agent_upgrade_analyze_agent(agent_id, agent_task, wpk_repository_config), error_code != WM_UPGRADE_SUCCESS) {
            cJSON *error_message = wm_agent_upgrade_parse_data_response(error_code, upgrade_error_codes[error_code], &agent_id);
            cJSON_AddItemToArray(data_array, error_message);
        } else if (error_code = wm_agent_upgrade_create_task_for_agent(agent_task), error_code != WM_UPGRADE_SUCCESS) {
            cJSON *error_message = wm_agent_upgrade_parse_data_response(error_code, upgrade_error_codes[error_code], &agent_id);
            cJSON_AddItemToArray(data_array, error_message);
        } else {
            // Task created successfully
            tasks_created++;
            cJSON *success_message = wm_agent_upgrade_parse_data_response(WM_UPGRADE_SUCCESS, upgrade_error_codes[WM_UPGRADE_SUCCESS], &agent_id);
            cJSON_AddItemToArray(data_array, success_message);
        }
        wm_agent_upgrade_free_agent_task(agent_task);
    }

    if (tasks_created == 0) {
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
    int tasks_created = 0;

    while (agent_id = agent_ids[agent++], agent_id != OS_INVALID) {
        wm_upgrade_error_code error_code = WM_UPGRADE_SUCCESS;
        wm_agent_task *agent_task = NULL;
        wm_upgrade_custom_task *upgrade_custom_task = NULL;

        agent_task = wm_agent_upgrade_init_agent_task();

        // Task information
        upgrade_custom_task = wm_agent_upgrade_init_upgrade_custom_task();
        w_strdup(task->custom_file_path, upgrade_custom_task->custom_file_path);
        w_strdup(task->custom_installer, upgrade_custom_task->custom_installer);
        upgrade_custom_task->request_time = task->request_time;

        agent_task->task_info = wm_agent_upgrade_init_task_info();
        agent_task->task_info->command = WM_UPGRADE_UPGRADE_CUSTOM;
        agent_task->task_info->task = upgrade_custom_task;

        if (error_code = wm_agent_upgrade_analyze_agent(agent_id, agent_task, NULL), error_code != WM_UPGRADE_SUCCESS) {
            cJSON *error_message = wm_agent_upgrade_parse_data_response(error_code, upgrade_error_codes[error_code], &agent_id);
            cJSON_AddItemToArray(data_array, error_message);
        } else if (error_code = wm_agent_upgrade_create_task_for_agent(agent_task), error_code != WM_UPGRADE_SUCCESS) {
            cJSON *error_message = wm_agent_upgrade_parse_data_response(error_code, upgrade_error_codes[error_code], &agent_id);
            cJSON_AddItemToArray(data_array, error_message);
        } else {
            // Task created successfully
            tasks_created++;
            cJSON *success_message = wm_agent_upgrade_parse_data_response(WM_UPGRADE_SUCCESS, upgrade_error_codes[WM_UPGRADE_SUCCESS], &agent_id);
            cJSON_AddItemToArray(data_array, success_message);
        }
        wm_agent_upgrade_free_agent_task(agent_task);
    }

    if (tasks_created == 0) {
        mtwarn(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_NO_AGENTS_TO_UPGRADE);
    }

    json_response = wm_agent_upgrade_parse_response(WM_UPGRADE_SUCCESS, data_array);
    response = cJSON_PrintUnformatted(json_response);

    cJSON_Delete(json_response);

    return response;
}

STATIC int wm_agent_upgrade_analyze_agent(int agent_id, wm_agent_task *agent_task, const char *wpk_repository_config) {
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

        // Validate agent and task information
        validate_result = wm_agent_upgrade_validate_agent_task(agent_task, wpk_repository_config);

        cJSON_Delete(agent_info);

    } else {
        validate_result = WM_UPGRADE_GLOBAL_DB_FAILURE;
    }

    return validate_result;
}

STATIC int wm_agent_upgrade_validate_agent_task(const wm_agent_task *agent_task, const char *wpk_repository_config) {
    int validate_result = WM_UPGRADE_SUCCESS;

    // Validate agent id
    validate_result = wm_agent_upgrade_validate_id(agent_task->agent_info->agent_id);

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

    if (validate_result != WM_UPGRADE_SUCCESS) {
        return validate_result;
    }

    // Validate WPK availability and integrity
    if (agent_task->task_info->command == WM_UPGRADE_UPGRADE) {
        wm_upgrade_task *task = (wm_upgrade_task *)agent_task->task_info->task;

        // Check if WPK exists for this agent's platform/version in repository
        validate_result = wm_agent_upgrade_validate_wpk_version(agent_task->agent_info, task, wpk_repository_config);

        if (validate_result != WM_UPGRADE_SUCCESS) {
            return validate_result;
        }

        // Validate local WPK file exists and SHA1 matches
        validate_result = wm_agent_upgrade_validate_wpk(task);

    } else if (agent_task->task_info->command == WM_UPGRADE_UPGRADE_CUSTOM) {
        wm_upgrade_custom_task *task = (wm_upgrade_custom_task *)agent_task->task_info->task;

        // Validate custom WPK file exists
        validate_result = wm_agent_upgrade_validate_wpk_custom(task);
    }

    return validate_result;
}

STATIC cJSON* wm_agent_upgrade_build_task_message(int agent_id, time_t request_time, const char *wpk_file, const char *wpk_sha1, const char *installer) {
    cJSON *task_msg = cJSON_CreateObject();
    if (!task_msg) {
        return NULL;
    }

    char agent_id_str[16];
    snprintf(agent_id_str, sizeof(agent_id_str), "%03d", agent_id);

    cJSON_AddStringToObject(task_msg, "action", "create_task");
    cJSON_AddStringToObject(task_msg, "agent_id", agent_id_str);
    cJSON_AddStringToObject(task_msg, "task_type", "remote_upgrade");
    cJSON_AddNumberToObject(task_msg, "create_time", (double)request_time);

    // Build payload as JSON object
    cJSON *payload = cJSON_CreateObject();
    if (!payload) {
        cJSON_Delete(task_msg);
        return NULL;
    }

    cJSON_AddStringToObject(payload, "wpk_file", wpk_file);
    cJSON_AddStringToObject(payload, "wpk_sha1", wpk_sha1);
    cJSON_AddStringToObject(payload, "installer", installer);

    // Attach payload object directly (Task Manager will serialize it)
    cJSON_AddItemToObject(task_msg, "payload", payload);

    return task_msg;
}

STATIC wm_upgrade_error_code wm_agent_upgrade_create_task_for_agent(wm_agent_task *agent_task) {
    if (!agent_task || !agent_task->task_info || !agent_task->agent_info) {
        return WM_UPGRADE_UNKNOWN_ERROR;
    }

    int agent_id = agent_task->agent_info->agent_id;
    wm_upgrade_command command = agent_task->task_info->command;

    // Extract task parameters
    time_t request_time = 0;
    char *wpk_file = NULL;
    char *wpk_sha1 = NULL;
    const char *installer = NULL;

    if (command == WM_UPGRADE_UPGRADE) {
        wm_upgrade_task *task = (wm_upgrade_task *)agent_task->task_info->task;
        if (!task) {
            return WM_UPGRADE_UNKNOWN_ERROR;
        }

        request_time = task->request_time;
        wpk_file = task->wpk_file;
        wpk_sha1 = task->wpk_sha1;
        installer = !strcmp(agent_task->agent_info->platform, "windows") ? "upgrade.bat" : "upgrade.sh";

    } else if (command == WM_UPGRADE_UPGRADE_CUSTOM) {
        wm_upgrade_custom_task *task = (wm_upgrade_custom_task *)agent_task->task_info->task;
        if (!task) {
            return WM_UPGRADE_UNKNOWN_ERROR;
        }

        request_time = task->request_time;
        wpk_file = task->custom_file_path;
        wpk_sha1 = task->wpk_sha1;  // SHA1 already calculated during validation

        // Use custom installer or default
        if (task->custom_installer) {
            installer = task->custom_installer;
        } else {
            installer = !strcmp(agent_task->agent_info->platform, "windows") ? "upgrade.bat" : "upgrade.sh";
        }
    }

    if (!wpk_file || !wpk_sha1 || !installer) {
        return WM_UPGRADE_UNKNOWN_ERROR;
    }

    // Build and send task
    cJSON *task_msg = wm_agent_upgrade_build_task_message(agent_id, request_time, wpk_file, wpk_sha1, installer);
    if (!task_msg) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, "Agent %03d: Failed to build task message", agent_id);
        return WM_UPGRADE_UNKNOWN_ERROR;
    }

    cJSON *tm_resp = wm_agent_upgrade_send_tasks_information(task_msg);
    cJSON_Delete(task_msg);

    // Process Task Manager response
    wm_upgrade_error_code result;
    if (!tm_resp) {
        result = WM_UPGRADE_TASK_MANAGER_COMMUNICATION;
    } else {
        cJSON *status_obj = cJSON_GetObjectItem(tm_resp, "status");
        if (status_obj && cJSON_IsString(status_obj) && strcmp(status_obj->valuestring, "ok") == 0) {
            result = WM_UPGRADE_SUCCESS;
        } else {
            result = WM_UPGRADE_TASK_MANAGER_FAILURE;
        }
        cJSON_Delete(tm_resp);
    }

    return result;
}
