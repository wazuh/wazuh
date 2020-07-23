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
#include "wm_agent_upgrade_parsing.h"
#include "wm_agent_upgrade_tasks.h"

const char* upgrade_commands[] = {
    [WM_UPGRADE_UPGRADE] = "upgrade",
    [WM_UPGRADE_UPGRADE_CUSTOM] = "upgrade_custom",
    [WM_UPGRADE_UPGRADE_RESULT] = "upgrade_result"
};

int wm_agent_upgrade_parse_command(const char* buffer, cJSON** json_api, cJSON** params, cJSON** agents) {
    int retval = OS_INVALID;
    int error = WM_UPGRADE_SUCCESS;

    cJSON *root = cJSON_Parse(buffer);

    if (!root) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_JSON_PARSE_ERROR,  buffer);
        error = WM_UPGRADE_PARSING_ERROR;
    } else {
        cJSON *command = cJSON_GetObjectItem(root, "command");
        *params = cJSON_GetObjectItem(root, "params");
        *agents = cJSON_GetObjectItem(root, "agents");

        if (command && *agents) {
            int i;
            for (i = 0; i < WM_UPGRADE_INVALID_COMMAND; ++i) {
                if (strcmp(command->valuestring, upgrade_commands[i]) == 0) {
                    retval = i;
                    break;
                }
            }
            if (WM_UPGRADE_INVALID_COMMAND == i) {
                mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_UNDEFINED_ACTION_ERRROR,  command->valuestring);
                error = WM_UPGRADE_TASK_CONFIGURATIONS;
            }
        } else {
            mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_REQUIRED_PARAMETERS);
            error = WM_UPGRADE_PARSING_REQUIRED_PARAMETER;
        }
    }

    if (error) {
        *json_api = wm_agent_upgrade_parse_response_message(error, upgrade_error_codes[error], NULL, NULL, NULL);
        cJSON_Delete(root);
    } else {
        *json_api = root;
    }

    return retval;
}

wm_upgrade_task* wm_agent_upgrade_parse_upgrade_command(const cJSON* params, char* output) {
    wm_upgrade_task *task = wm_agent_upgrade_init_upgrade_task();
    int param_index = 0;
    int error_flag = 0;
    while(!error_flag && params && (param_index < cJSON_GetArraySize(params))) {
        cJSON *item = cJSON_GetArrayItem(params, param_index++);
        if(strcmp(item->string, "wpk_repo") == 0) {
            /* wpk repo */
            if ( item->type == cJSON_String) {
                task->wpk_repository = strdup(item->valuestring);
            } else {
                sprintf(output, "Parameter \"%s\" should be a string", item->string);
                error_flag = 1;
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
        wm_agent_upgrade_free_upgrade_task(task);
        return NULL;
    } else {
        return task;
    }
}

wm_upgrade_custom_task* wm_agent_upgrade_parse_upgrade_custom_command(const cJSON* params, char* output) {
    wm_upgrade_custom_task *task = wm_agent_upgrade_init_upgrade_custom_task();
    int param_index = 0;
    int error_flag = 0;
    while(!error_flag && params && (param_index < cJSON_GetArraySize(params))) {
        cJSON *item = cJSON_GetArrayItem(params, param_index++);
        if (strcmp(item->string, "file_path") == 0) {
            /* File_path */
            if ( item->type == cJSON_String) {
                task->custom_file_path = strdup(item->valuestring);
            } else {
                sprintf(output, "Parameter \"%s\" should be a string", item->string);
                error_flag = 1;
            }
        } else if(strcmp(item->string, "installer") == 0) {
            /* Installer */
            if ( item->type == cJSON_String) {
                task->custom_installer = strdup(item->valuestring);
            } else {
                sprintf(output, "Parameter \"%s\" should be a string", item->string);
                error_flag = 1;
            }
        }
    }

    if (error_flag) {
        // We will reject this task since the parameters are incorrect
        wm_agent_upgrade_free_upgrade_custom_task(task);
        return NULL;
    } else {
        return task;
    }
}

cJSON*  wm_agent_upgrade_parse_response_message(int error_id, const char* message, const int *agent_id, const int* task_id, const char* status) {
    cJSON * response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "error", error_id);
    cJSON_AddStringToObject(response, "data", message);
    if(agent_id) {
        cJSON_AddNumberToObject(response, "agent", *agent_id);
    }
    if (task_id) {
       cJSON_AddNumberToObject(response, "task_id", *task_id); 
    } 
    if (status) {
        cJSON_AddStringToObject(response, "status", status);
    }
    return response;
}

cJSON* wm_agent_upgrade_parse_task_module_message(wm_upgrade_command command, const int agent_id) {
    cJSON * response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "module", WM_AGENT_UPGRADE_MODULE_NAME);
    cJSON_AddStringToObject(response, "command", upgrade_commands[command]);
    cJSON_AddNumberToObject(response, "agent", agent_id);
    return response;
}
