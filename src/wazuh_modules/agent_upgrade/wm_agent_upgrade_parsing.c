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

/**
 * Parses agents array and returns an array of agent ids
 * @param agents array of agents
 * @param error_message message in case of error
 * @return pointer to array of agent ids
 * */
static int* wm_agent_upgrade_parse_agents(const cJSON* agents, char** error_message);

/**
 * Parses upgrade command and returns an upgrade task from the information
 * Example:
 * WPK Repository
 * {
 *      "repository" : "wazuh.packages.com"
 *      "version"    : "3.12",
 *      "use_http"   : "false",
 *      "force_upgrade" : "0"
 * }
 * @param params JSON where the task parameters are
 * @param error_message message in case of error
 * @return upgrade task if there is no error, NULL otherwise
 * */
static wm_upgrade_task* wm_agent_upgrade_parse_upgrade_command(const cJSON* params, char** error_message);

/**
 * Parses upgrade custom command and returns an upgrade task from the information
 * Example:
 * Custom WPK Package
 * {
 *      "file_path" : "./wazuh_wpk"
 *      "installer" : "installer.sh"
 * }
 * @param params JSON where the task parameters are
 * @param error_message message in case of error
 * @return upgrade task if there is no error, NULL otherwise
 * */
static wm_upgrade_custom_task* wm_agent_upgrade_parse_upgrade_custom_command(const cJSON* params, char** error_message);

const char* upgrade_commands[] = {
    [WM_UPGRADE_UPGRADE] = "upgrade",
    [WM_UPGRADE_UPGRADE_CUSTOM] = "upgrade_custom",
    [WM_UPGRADE_UPGRADE_RESULT] = "upgrade_result"
};

int wm_agent_upgrade_parse_message(const char* buffer, void** task, int** agent_ids, char** error) {
    int retval = OS_INVALID;
    int error_code = WM_UPGRADE_SUCCESS;
    char* error_message = NULL;
    cJSON *error_json = NULL;

    cJSON *root = cJSON_Parse(buffer);

    if (!root) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_JSON_PARSE_ERROR,  buffer);
        error_code = WM_UPGRADE_PARSING_ERROR;
    } else {
        cJSON *command = cJSON_GetObjectItem(root, "command");
        cJSON *params = cJSON_GetObjectItem(root, "params");
        cJSON *agents = cJSON_GetObjectItem(root, "agents");

        if (command && (command->type == cJSON_String) && agents && (agents->type == cJSON_Array) && cJSON_GetArraySize(agents)) {
            if (strcmp(command->valuestring, upgrade_commands[WM_UPGRADE_UPGRADE]) == 0) { // Upgrade command
                // Analyze agent IDs
                *agent_ids = wm_agent_upgrade_parse_agents(agents, &error_message);
                if (!error_message) {
                    // Analyze upgrade parameters
                    *task = (wm_upgrade_task *)wm_agent_upgrade_parse_upgrade_command(params, &error_message);
                    if (!error_message) {
                        retval = WM_UPGRADE_UPGRADE;
                    }
                }
            } else if (strcmp(command->valuestring, upgrade_commands[WM_UPGRADE_UPGRADE_CUSTOM]) == 0) { // Upgrade custom command
                // Analyze agent IDs
                *agent_ids = wm_agent_upgrade_parse_agents(agents, &error_message);
                if (!error_message) {
                    // Analyze upgrade custom parameters
                    *task = (wm_upgrade_custom_task *)wm_agent_upgrade_parse_upgrade_custom_command(params, &error_message);
                    if (!error_message) {
                        retval = WM_UPGRADE_UPGRADE_CUSTOM;
                    }
                }
            } else if (strcmp(command->valuestring, upgrade_commands[WM_UPGRADE_UPGRADE_RESULT]) == 0) { // Upgrade result command
                // Analyze agent IDs
                *agent_ids = wm_agent_upgrade_parse_agents(agents, &error_message);
                if (!error_message) {
                    retval = WM_UPGRADE_UPGRADE_RESULT;
                }
            } else {
                mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_UNDEFINED_ACTION_ERRROR, command->valuestring);
                error_code = WM_UPGRADE_TASK_CONFIGURATIONS;
            }
        } else {
            mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_REQUIRED_PARAMETERS);
            error_code = WM_UPGRADE_PARSING_REQUIRED_PARAMETER;
        }
    }

    if (error_message) {
        error_json = wm_agent_upgrade_parse_response_message(WM_UPGRADE_TASK_CONFIGURATIONS, error_message, NULL, NULL, NULL);
        *error = cJSON_PrintUnformatted(error_json);
        os_free(error_message);
    } else if (error_code) {
        error_json = wm_agent_upgrade_parse_response_message(error_code, upgrade_error_codes[error_code], NULL, NULL, NULL);
        *error = cJSON_PrintUnformatted(error_json);
    }

    cJSON_Delete(error_json);
    cJSON_Delete(root);

    return retval;
}

int* wm_agent_upgrade_parse_agents(const cJSON* agents, char** error_message) {
    char *output = NULL;
    int *agent_ids = NULL;
    int agent_index = 0;
    int error_flag = 0;

    os_calloc(OS_MAXSTR, sizeof(char), output);

    os_calloc(1, sizeof(int), agent_ids);
    *agent_ids = 0;

    while(!error_flag && (agent_index < cJSON_GetArraySize(agents))) {
        cJSON *agent = cJSON_GetArrayItem(agents, agent_index++);
        if (agent->type == cJSON_Number) {
            os_realloc(agent_ids, sizeof(int) * (agent_index + 2), agent_ids);
            agent_ids[agent_index] = agent->valueint;
            agent_ids[agent_index + 1] = 0;
        } else {
            sprintf(output, "Agent id not recognized");
            error_flag = 1;
        }
    }

    if (error_flag) {
        // We will reject this list of agents since they are incorrect
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_COMMAND_PARSE_ERROR, *error_message);
        os_free(agent_ids);
        os_strdup(output, *error_message);
    }

    os_free(output);

    return agent_ids;
}

wm_upgrade_task* wm_agent_upgrade_parse_upgrade_command(const cJSON* params, char** error_message) {
    char *output = NULL;
    int param_index = 0;
    int error_flag = 0;

    os_calloc(OS_MAXSTR, sizeof(char), output);

    wm_upgrade_task *task = wm_agent_upgrade_init_upgrade_task();

    while(!error_flag && params && (param_index < cJSON_GetArraySize(params))) {
        cJSON *item = cJSON_GetArrayItem(params, param_index++);
        if(strcmp(item->string, "wpk_repo") == 0) {
            /* wpk_repo */
            if (item->type == cJSON_String) {
                task->wpk_repository = strdup(item->valuestring);
            } else {
                sprintf(output, "Parameter \"%s\" should be a string", item->string);
                error_flag = 1;
            }
        } else if(strcmp(item->string, "version") == 0) {
            /* version */
            if (item->type == cJSON_String) {
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
            /* force_upgrade */
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
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_COMMAND_PARSE_ERROR, *error_message);
        wm_agent_upgrade_free_upgrade_task(task);
        os_strdup(output, *error_message);
    }

    os_free(output);

    return task;
}

wm_upgrade_custom_task* wm_agent_upgrade_parse_upgrade_custom_command(const cJSON* params, char** error_message) {
    char *output = NULL;
    int param_index = 0;
    int error_flag = 0;

    os_calloc(OS_MAXSTR, sizeof(char), output);

    wm_upgrade_custom_task *task = wm_agent_upgrade_init_upgrade_custom_task();

    while(!error_flag && params && (param_index < cJSON_GetArraySize(params))) {
        cJSON *item = cJSON_GetArrayItem(params, param_index++);
        if (strcmp(item->string, "file_path") == 0) {
            /* file_path */
            if (item->type == cJSON_String) {
                task->custom_file_path = strdup(item->valuestring);
            } else {
                sprintf(output, "Parameter \"%s\" should be a string", item->string);
                error_flag = 1;
            }
        } else if(strcmp(item->string, "installer") == 0) {
            /* installer */
            if (item->type == cJSON_String) {
                task->custom_installer = strdup(item->valuestring);
            } else {
                sprintf(output, "Parameter \"%s\" should be a string", item->string);
                error_flag = 1;
            }
        }
    }

    if (error_flag) {
        // We will reject this task since the parameters are incorrect
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_COMMAND_PARSE_ERROR, *error_message);
        wm_agent_upgrade_free_upgrade_custom_task(task);
        os_strdup(output, *error_message);
    }

    os_free(output);

    return task;
}

cJSON* wm_agent_upgrade_parse_response_message(int error_id, const char* message, const int *agent_id, const int* task_id, const char* status) {
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
