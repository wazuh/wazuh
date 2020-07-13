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
#include "wm_agent_upgrade.h"

/**
 * Parses upgrade command and returns an upgrade task from the information
 * @param params JSON where the task parameters are 
 * @param output message in case of error
 * @return upgrade task if there is no error, NULL otherwise
 * */
static wm_upgrade_task* wm_agent_parse_upgrade_command(const cJSON* params, char* output);

cJSON* wm_agent_parse_command(const char* buffer) {
    cJSON *json_api = NULL; // Response for API
    cJSON * root = cJSON_Parse(buffer);
    if (!root) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, "Cannot parse JSON: %s",  buffer);
    } else {
        char *output = NULL;
        os_calloc(OS_MAXSTR, sizeof(char), output);
        cJSON *params = cJSON_GetObjectItem(root, "params");
        const char *command = cJSON_GetObjectItem(root, "command")->valuestring;
        void *task = NULL;
        if (strcmp(command, "upgrade") == 0) {
            task = (void*) wm_agent_parse_upgrade_command(params, output);
        } else {
            // TODO invalid command
        }

        if (!task) {
            mterror(WM_AGENT_UPGRADE_LOGTAG, "Error parsing command: %s", output);
        } else {
            json_api = cJSON_CreateArray();
            cJSON *json_task_module = cJSON_CreateArray();
            wm_agent_create_agent_tasks(cJSON_GetObjectItem(root, "agents"), task, command, json_task_module, json_api);
            cJSON *task_module_response = wm_agent_send_task_information(json_task_module);
            if (task_module_response && (task_module_response->type == cJSON_Array)) {
                // Parse task module responses into API
                for(int i=0; i < cJSON_GetArraySize(task_module_response); i++) {
                    cJSON_AddItemReferenceToArray(json_api, cJSON_GetArrayItem(task_module_response, i));
                }
            } else {
                for(int i=0; i < cJSON_GetArraySize(json_task_module); i++) {
                    int agent_id = cJSON_GetObjectItem(cJSON_GetArrayItem(json_task_module, i), "agent")->valueint;
                    cJSON_AddItemReferenceToArray(json_api, wm_agent_parse_response_mesage(1, "Could not create task id for upgrade task", agent_id, NULL));
                }
            }
            cJSON_Delete(json_task_module);
        }
        cJSON_Delete(root);
    }
    return json_api;
}

static wm_upgrade_task* wm_agent_parse_upgrade_command(const cJSON* params, char* output) {
    wm_upgrade_task *task = wm_agent_init_upgrade_task();
    int param_index = 0;
    int error_flag = 0;
    while(!error_flag && (param_index < cJSON_GetArraySize(params))) {
        cJSON *item = cJSON_GetArrayItem(params, param_index++);
        if (strcmp(item->string, "file_path") == 0) {
            /* File_path */
            if ( item->type == cJSON_String) {
                task->custom_file_path = strdup(item->valuestring);
            } else {
                sprintf(output, "Parameter \"%s\" should be a string", item->string);
                task->state = ERROR;
            }
        } else if(strcmp(item->string, "installer") == 0) {
            /* Installer */
            if ( item->type == cJSON_String) {
                task->custom_installer = strdup(item->valuestring);
            } else {
                sprintf(output, "Parameter \"%s\" should be a string", item->string);
                error_flag = 1;
            }
        } else if(strcmp(item->string, "wpk_repo") == 0) {
            /* wpk repo */
            if ( item->type == cJSON_String) {
                task->wpk_repository = strdup(item->valuestring);
            } else {
                sprintf(output, "Parameter \"%s\" should be a string", item->string);
                task->state = ERROR;
            }
        } else if(strcmp(item->string, "version") == 0) {
            /* version */
            if ( item->type == cJSON_String) {
                task->custom_version = strdup(item->valuestring);
            } else {
                sprintf(output, "Parameter \"%s\" should be a string", item->string);
                error_flag = 1;
            }
        } else if(strcmp(item->string, "use_http") == 0) {
            /* use_http */
            if (item->valueint == 1) {
                task->use_http = true;
            } else if(item->valueint == 0) {
                task->use_http = false;
            } else {
                sprintf(output, "Parameter \"%s\" should be either true or false", item->string);
                error_flag = 1;
            }
        } else if(strcmp(item->string, "force_upgrade") == 0) {
            if(item->valueint == 0) {
                task->force_upgrade = false;
            } else if(item->valueint == 1) {
                task->force_upgrade = true;
            } else {
                sprintf(output, "Parameter \"%s\" can take only values [0, 1]", item->string);
                error_flag = 1;
            }
        }
    }
    if (error_flag) {
        // We will reject this task since the parameters are incorrect
        wm_agent_free_upgrade_task(task);
        return NULL;
    } else {
        return task;
    }
}

cJSON*  wm_agent_parse_response_mesage(int error_id, const char* message, const int agent_id, const int* task_id) {
    cJSON * response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "error", error_id);
    cJSON_AddStringToObject(response, "data", message);
    cJSON_AddNumberToObject(response, "agent", agent_id);
    if (task_id) {
       cJSON_AddNumberToObject(response, "task_id", *task_id); 
    } 
    return response;
}

cJSON* wm_agent_parse_task_module_message(const char* command, const int agent_id) {
    cJSON * response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "module", WM_AGENT_UPGRADE_MODULE_NAME);
    cJSON_AddStringToObject(response, "command", command);
    cJSON_AddNumberToObject(response, "agent", agent_id);
    return response;
}
