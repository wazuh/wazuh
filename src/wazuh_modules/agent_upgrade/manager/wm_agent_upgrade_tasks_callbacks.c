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

#include "wazuh_modules/wmodules.h"
#include "wm_agent_upgrade_tasks.h"
#include "wm_agent_upgrade_parsing.h"
#include "wm_agent_upgrade_validate.h"
#include "wm_agent_upgrade_upgrades.h"
#include "os_net/os_net.h"
#include "shared.h"

int wm_agent_upgrade_task_module_callback(cJSON *data_array, const cJSON* task_module_request, cJSON* (*success_callback)(int *error, cJSON* input_json), void (*error_callback)(int agent_id, int free)) {
    int error = OS_SUCCESS;
    cJSON *task_module_response = NULL;
    cJSON *error_json = NULL;

    cJSON *temp_array = cJSON_CreateArray();

    // Send request to task module
    task_module_response = wm_agent_upgrade_send_tasks_information(task_module_request);

    error_json = cJSON_GetObjectItem(task_module_response, task_manager_json_keys[WM_TASK_ERROR]);

    if (error_json && (error_json->type == cJSON_Number) && (error_json->valueint == WM_UPGRADE_SUCCESS)) {
        // Parse task module responses
        cJSON *task_responses = cJSON_GetObjectItem(task_module_response, task_manager_json_keys[WM_TASK_DATA]);

        while(cJSON_GetArraySize(task_responses) && (error == OS_SUCCESS)) {
            cJSON *task_response = cJSON_DetachItemFromArray(task_responses, 0);
            if (success_callback) {
                // A callback has been defined, process it with the callback
                cJSON *callback_object = success_callback(&error, task_response);
                if (callback_object) {
                    cJSON_AddItemToArray(temp_array, callback_object);
                }
                if (callback_object != task_response) {
                    cJSON_Delete(task_response);
                }
            } else {
                cJSON_AddItemToArray(temp_array, task_response);
            }
        }
    } else {
        error = OS_INVALID;
    }

    if (error) {
        cJSON *agents_array = cJSON_GetObjectItem(cJSON_GetObjectItem(task_module_request, task_manager_json_keys[WM_TASK_PARAMETERS]), task_manager_json_keys[WM_TASK_AGENTS]);
        int agents = cJSON_GetArraySize(agents_array);

        for(int i = 0; i < agents; i++) {
            cJSON *agent_json = cJSON_GetArrayItem(agents_array, i);

            if (agent_json && (agent_json->type == cJSON_Number)) {
                int agent_id = agent_json->valueint;
                if (error_callback) {
                    error_callback(agent_id, 1);
                }
                cJSON *error_json = wm_agent_upgrade_parse_data_response(WM_UPGRADE_TASK_MANAGER_COMMUNICATION, upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION], &agent_id);
                cJSON_AddItemToArray(data_array, error_json);
            }
        }
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_TASK_MANANAGER_ERROR);
    } else {
        while (cJSON_GetArraySize(temp_array) > 0) {
            cJSON *item = cJSON_DetachItemFromArray(temp_array, 0);
            cJSON_AddItemToArray(data_array, item);
        }
    }

    cJSON_Delete(temp_array);
    cJSON_Delete(task_module_response);

    return error;
}

cJSON* wm_agent_upgrade_upgrade_success_callback(int *error, cJSON* input_json) {
    int agent_id = 0;
    int task_id = 0;
    char *data = NULL;
    cJSON *response = NULL;

    response = input_json;

    if (wm_agent_upgrade_validate_task_ids_message(input_json, &agent_id, &task_id, &data)) {
        if(task_id) {
            // Store task_id
            wm_agent_upgrade_insert_task_id(agent_id, task_id);
        } else {
            // Remove from table since upgrade will not be started
            wm_agent_upgrade_remove_entry(agent_id, 1);
            response = wm_agent_upgrade_parse_data_response(WM_UPGRADE_TASK_MANAGER_FAILURE, data, &agent_id);
        }
    } else {
        // We cannot know which agent is the one failing so we have to abort the whole process
        *error = OS_INVALID;
    }

    os_free(data);

    return response;
}

cJSON* wm_agent_upgrade_update_status_success_callback(int *error, cJSON* input_json) {
    int agent_id = 0;

    if (wm_agent_upgrade_validate_task_status_message(input_json, NULL, &agent_id), agent_id > 0) {
        // Tell agent to erase results file
        char *buffer = NULL;

        os_calloc(OS_MAXSTR, sizeof(char), buffer);
        snprintf(buffer, OS_MAXSTR, "%03d com clear_upgrade_result -1", agent_id);

        char *agent_response = wm_agent_upgrade_send_command_to_agent(buffer, strlen(buffer)); 

        if (*error = wm_agent_upgrade_parse_agent_response(agent_response, NULL), (*error == OS_SUCCESS)) {
            mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_UPGRADE_FILE_AGENT);
        }

        os_free(buffer);
        os_free(agent_response);   
    } else {
        *error = OS_INVALID;
    }

    return input_json;
}
