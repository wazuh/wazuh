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

/**
 * Parses upgrade agent status and return an agent status task from the information
 * @param params JSON where the task parameters are
 * @param error_message message in case of error
 * @return upgrade task if there is no error, NULL otherwise
 * */
static wm_upgrade_agent_status_task* wm_agent_upgrade_parse_upgrade_agent_status(const cJSON* params, char** error_message);

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
            if (strcmp(command->valuestring, task_manager_commands_list[WM_UPGRADE_UPGRADE]) == 0) { // Upgrade command
                // Analyze agent IDs
                *agent_ids = wm_agent_upgrade_parse_agents(agents, &error_message);
                if (!error_message) {
                    // Analyze upgrade parameters
                    *task = (wm_upgrade_task *)wm_agent_upgrade_parse_upgrade_command(params, &error_message);
                    if (!error_message) {
                        retval = WM_UPGRADE_UPGRADE;
                    }
                }
            } else if (strcmp(command->valuestring, task_manager_commands_list[WM_UPGRADE_UPGRADE_CUSTOM]) == 0) { // Upgrade custom command
                // Analyze agent IDs
                *agent_ids = wm_agent_upgrade_parse_agents(agents, &error_message);
                if (!error_message) {
                    // Analyze upgrade custom parameters
                    *task = (wm_upgrade_custom_task *)wm_agent_upgrade_parse_upgrade_custom_command(params, &error_message);
                    if (!error_message) {
                        retval = WM_UPGRADE_UPGRADE_CUSTOM;
                    }
                }
            } else if (strcmp(command->valuestring, task_manager_commands_list[WM_UPGRADE_AGENT_UPDATE_STATUS]) == 0) {
                *agent_ids = wm_agent_upgrade_parse_agents(agents, &error_message);
                if (!error_message) {
                    *task = (wm_upgrade_agent_status_task*)wm_agent_upgrade_parse_upgrade_agent_status(params, &error_message);
                    if (!error_message) {
                        retval = WM_UPGRADE_AGENT_UPDATE_STATUS;
                    }
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

static int* wm_agent_upgrade_parse_agents(const cJSON* agents, char** error_message) {
    char *output = NULL;
    int *agent_ids = NULL;
    int agents_size = 0;
    int agent_index = 0;
    int error_flag = 0;

    os_calloc(OS_MAXSTR, sizeof(char), output);

    agents_size = cJSON_GetArraySize(agents);

    os_calloc(agents_size + 1, sizeof(int), agent_ids);
    agent_ids[agent_index] = OS_INVALID;

    while(!error_flag && (agent_index < agents_size)) {
        cJSON *agent = cJSON_GetArrayItem(agents, agent_index);
        if (agent->type == cJSON_Number) {
            agent_ids[agent_index] = agent->valueint;
            agent_ids[agent_index + 1] = OS_INVALID;
        } else {
            sprintf(output, "Agent id not recognized");
            error_flag = 1;
        }
        agent_index++;
    }

    if (error_flag) {
        // We will reject this list of agents since they are incorrect
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_COMMAND_PARSE_ERROR, output);
        os_free(agent_ids);
        os_strdup(output, *error_message);
    }

    os_free(output);

    return agent_ids;
}

static wm_upgrade_task* wm_agent_upgrade_parse_upgrade_command(const cJSON* params, char** error_message) {
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
                os_strdup(item->valuestring, task->wpk_repository);
            } else {
                sprintf(output, "Parameter \"%s\" should be a string", item->string);
                error_flag = 1;
            }
        } else if(strcmp(item->string, "version") == 0) {
            /* version */
            if (item->type == cJSON_String) {
                os_strdup(item->valuestring, task->custom_version);
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
                sprintf(output, "Parameter \"%s\" can take only values [0, 1]", item->string);
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
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_COMMAND_PARSE_ERROR, output);
        wm_agent_upgrade_free_upgrade_task(task);
        os_strdup(output, *error_message);
    }

    os_free(output);

    return task;
}

static wm_upgrade_custom_task* wm_agent_upgrade_parse_upgrade_custom_command(const cJSON* params, char** error_message) {
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
                os_strdup(item->valuestring, task->custom_file_path);
            } else {
                sprintf(output, "Parameter \"%s\" should be a string", item->string);
                error_flag = 1;
            }
        } else if(strcmp(item->string, "installer") == 0) {
            /* installer */
            if (item->type == cJSON_String) {
                os_strdup(item->valuestring, task->custom_installer);
            } else {
                sprintf(output, "Parameter \"%s\" should be a string", item->string);
                error_flag = 1;
            }
        }
    }

    if (error_flag) {
        // We will reject this task since the parameters are incorrect
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_COMMAND_PARSE_ERROR, output);
        wm_agent_upgrade_free_upgrade_custom_task(task);
        os_strdup(output, *error_message);
    }

    os_free(output);

    return task;
}

static wm_upgrade_agent_status_task* wm_agent_upgrade_parse_upgrade_agent_status(const cJSON* params, char** error_message) {
    char *output = NULL;
    int param_index = 0;
    int error_flag = 0;

    os_calloc(OS_MAXSTR, sizeof(char), output);

    wm_upgrade_agent_status_task *task = wm_agent_upgrade_init_agent_status_task();

    while(!error_flag && params && (param_index < cJSON_GetArraySize(params))) {
        cJSON *item = cJSON_GetArrayItem(params, param_index++);
        if(strcmp(item->string, "error") == 0) {
            if (item->type == cJSON_Number) {
                task->error_code = item->valueint;
            } else {
                sprintf(output, "Parameter \"%s\" should be a number", item->string);
                error_flag = 1;
            }
        } else if(strcmp(item->string, "message") == 0) {
            if (item->type == cJSON_String) {
                os_strdup(item->valuestring, task->message);
            } else {
                sprintf(output, "Parameter \"%s\" should be a string", item->string);
                error_flag = 1;
            }
        } else if(strcmp(item->string, "status") == 0) {
            if (item->type == cJSON_String) {
                os_strdup(item->valuestring, task->status);
            } else {
                sprintf(output, "Parameter \"%s\" should be a string", item->string);
                error_flag = 1;
            }
        }
    }

    if (error_flag) {
        // We will reject this task since the parameters are incorrect
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_COMMAND_PARSE_ERROR, output);
        wm_agent_upgrade_free_agent_status_task(task);
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

cJSON* wm_agent_upgrade_parse_task_module_request(wm_upgrade_command command, int agent_id, const char* status) {
    cJSON * response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "module", task_manager_modules_list[WM_TASK_UPGRADE_MODULE]);
    cJSON_AddStringToObject(response, "command", task_manager_commands_list[command]);
    cJSON_AddNumberToObject(response, "agent", agent_id);
    if (status) {
        cJSON_AddStringToObject(response, "status", status);
    }
    return response;
}

int wm_agent_upgrade_task_module_callback(cJSON *json_response, const cJSON* task_module_request, cJSON* (*success_callback)(int *error, cJSON* input_json), cJSON *(*error_callback)(int agent_id)) {
    int agents = 0;
    int error = OS_SUCCESS;
    cJSON *task_module_response = NULL;
    cJSON *error_json = NULL;

    if (agents = cJSON_GetArraySize(task_module_request), !agents) {
        return OS_INVALID;
    }

    // Send request to task module
    task_module_response = wm_agent_upgrade_send_tasks_information(task_module_request);

    if (task_module_response && (task_module_response->type == cJSON_Array) && (agents == cJSON_GetArraySize(task_module_response))) {
        // Parse task module responses
        while(cJSON_GetArraySize(task_module_response)) {
            cJSON *task_response = cJSON_DetachItemFromArray(task_module_response, 0);
            if (success_callback) {
                // A callback has been defined, process it with the callback
                cJSON *callback_object = success_callback(&error, task_response);
                cJSON_AddItemToArray(json_response, callback_object);
                if (callback_object != task_response) {
                    cJSON_Delete(task_response);
                }
            } else {
                cJSON_AddItemToArray(json_response, task_response);
            }
            
        }
    } else {
        error = OS_INVALID;
    }

    if (error) {
        for(int i = 0; i < agents; i++) {
            cJSON *agent_json = cJSON_GetObjectItem(cJSON_GetArrayItem(task_module_request, i), "agent");

            if (agent_json && (agent_json->type == cJSON_Number)) {
                int agent_id = agent_json->valueint;
                if (error_callback) {
                    error_json = error_callback(agent_id);
                } else {
                    error_json = wm_agent_upgrade_parse_response_message(WM_UPGRADE_TASK_MANAGER_COMMUNICATION, upgrade_error_codes[WM_UPGRADE_TASK_MANAGER_COMMUNICATION], &agent_id, NULL, NULL);
                }
                cJSON_AddItemToArray(json_response, error_json);
            }
        }
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_INVALID_TASK_MAN_JSON);
    }

    cJSON_Delete(task_module_response);

    return error;
}

int wm_agent_upgrade_parse_agent_response(const char* agent_response, char **data, char **error) {
    int error_code = OS_SUCCESS;

    if (agent_response) {
        if (!strncmp(agent_response, "ok", 2) && strchr(agent_response, ' ')) {
            *data = strchr(agent_response, ' ') + 1;
        } else {
            if (!strncmp(agent_response, "err", 3) && strchr(agent_response, ' ')) {
                *error = strchr(agent_response, ' ') + 1;
            }
            error_code = OS_INVALID;
        }
    } else {
        error_code = OS_INVALID;
    }

    return error_code;
}
