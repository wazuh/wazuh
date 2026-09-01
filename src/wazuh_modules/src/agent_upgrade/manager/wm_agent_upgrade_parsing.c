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
#include "wm_agent_upgrade_parsing.h"
#include "wm_agent_upgrade_manager.h"
#include "shared.h"

/**
 * Parses agents array and returns an array of agent ids
 * @param agents array of agents
 * @param error_message message in case of error
 * @return pointer to array of agent ids
 * */
STATIC int* wm_agent_upgrade_parse_agents(const cJSON* agents, char** error_message);

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
STATIC wm_upgrade_task* wm_agent_upgrade_parse_upgrade_command(const cJSON* params, char** error_message);

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
STATIC wm_upgrade_custom_task* wm_agent_upgrade_parse_upgrade_custom_command(const cJSON* params, char** error_message);

int wm_agent_upgrade_parse_message(const char* buffer, void** task, int** agent_ids, char** error) {
    cJSON *root = NULL;
    int retval = OS_INVALID;
    int error_code = WM_UPGRADE_SUCCESS;
    char* error_message = NULL;

    if (root = cJSON_Parse(buffer), !root) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_JSON_PARSE_ERROR,  buffer);
        cJSON *error_json = wm_agent_upgrade_parse_data_response(WM_UPGRADE_PARSING_ERROR, upgrade_error_codes[WM_UPGRADE_PARSING_ERROR], NULL);
        cJSON *response = wm_agent_upgrade_parse_response(WM_UPGRADE_PARSING_ERROR, error_json);
        *error = cJSON_PrintUnformatted(response);
        cJSON_Delete(response);
        return retval;
    }

    cJSON *command = cJSON_GetObjectItem(root, upgrade_json_keys[WM_UPGRADE_COMMAND]);
    cJSON *parameters = cJSON_GetObjectItem(root, upgrade_json_keys[WM_UPGRADE_PARAMETERS]);

    if (command && (command->type == cJSON_String) && parameters && (parameters->type == cJSON_Object)) {

        cJSON *agents = cJSON_DetachItemFromObject(parameters, upgrade_json_keys[WM_UPGRADE_AGENTS]);

        if (agents && (agents->type == cJSON_Array) && cJSON_GetArraySize(agents)) {

            if (strcmp(command->valuestring, "upgrade") == 0) {
                // Analyze agent IDs
                *agent_ids = wm_agent_upgrade_parse_agents(agents, &error_message);
                if (!error_message) {
                    // Analyze upgrade parameters
                    *task = (wm_upgrade_task *)wm_agent_upgrade_parse_upgrade_command(parameters, &error_message);
                    if (!error_message) {
                        retval = WM_UPGRADE_UPGRADE;
                    }
                }

            } else if (strcmp(command->valuestring, "upgrade_custom") == 0) {
                // Analyze agent IDs
                *agent_ids = wm_agent_upgrade_parse_agents(agents, &error_message);
                if (!error_message) {
                    // Analyze upgrade custom parameters
                    *task = (wm_upgrade_custom_task *)wm_agent_upgrade_parse_upgrade_custom_command(parameters, &error_message);
                    if (!error_message) {
                        retval = WM_UPGRADE_UPGRADE_CUSTOM;
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

        cJSON_Delete(agents);

    } else {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_REQUIRED_PARAMETERS);
        error_code = WM_UPGRADE_PARSING_REQUIRED_PARAMETER;
    }

    if (error_message) {
        cJSON *error_json = wm_agent_upgrade_parse_data_response(WM_UPGRADE_TASK_CONFIGURATIONS, error_message, NULL);
        cJSON *response = wm_agent_upgrade_parse_response(WM_UPGRADE_TASK_CONFIGURATIONS, error_json);
        *error = cJSON_PrintUnformatted(response);
        cJSON_Delete(response);
        os_free(error_message);
    } else if (error_code) {
        cJSON *error_json = wm_agent_upgrade_parse_data_response(error_code, upgrade_error_codes[error_code], NULL);
        cJSON *response = wm_agent_upgrade_parse_response(error_code, error_json);
        *error = cJSON_PrintUnformatted(response);
        cJSON_Delete(response);
    }

    cJSON_Delete(root);

    return retval;
}

STATIC int* wm_agent_upgrade_parse_agents(const cJSON* agents, char** error_message) {
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
        if (agent->type == cJSON_Number && agent->valueint > 0) {
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

STATIC wm_upgrade_task* wm_agent_upgrade_parse_upgrade_command(const cJSON* params, char** error_message) {
    char *output = NULL;
    int param_index = 0;
    int error_flag = 0;

    os_calloc(OS_MAXSTR, sizeof(char), output);

    wm_upgrade_task *task = wm_agent_upgrade_init_upgrade_task();

    while(!error_flag && params && (param_index < cJSON_GetArraySize(params))) {
        cJSON *item = cJSON_GetArrayItem(params, param_index++);
        if (item->string) {
            if(strcmp(item->string, "request_time") == 0) {
                /* request_time - Unix timestamp from API for deterministic task IDs */
                if (item->type == cJSON_Number) {
                    task->request_time = (time_t)item->valuedouble;
                } else {
                    sprintf(output, "Parameter \"%s\" should be a number", item->string);
                    error_flag = 1;
                }
            } else if(strcmp(item->string, "wpk_repo") == 0) {
                /* wpk_repo */
                if (item->type == cJSON_String) {
                    os_free(task->wpk_repository);
                    os_strdup(item->valuestring, task->wpk_repository);
                } else {
                    sprintf(output, "Parameter \"%s\" should be a string", item->string);
                    error_flag = 1;
                }
            } else if(strcmp(item->string, "version") == 0) {
                /* version */
                if (item->type == cJSON_String) {
                    os_free(task->custom_version);
                    os_strdup(item->valuestring, task->custom_version);
                } else {
                    sprintf(output, "Parameter \"%s\" should be a string", item->string);
                    error_flag = 1;
                }
            } else if(strcmp(item->string, "use_http") == 0) {
                /* use_http */
                if (item->type == cJSON_True) {
                    task->use_http = true;
                } else if(item->type == cJSON_False) {
                    task->use_http = false;
                } else {
                    sprintf(output, "Parameter \"%s\" should be true or false", item->string);
                    error_flag = 1;
                }
            } else if(strcmp(item->string, "force_upgrade") == 0) {
                /* force_upgrade */
                if (item->type == cJSON_True) {
                    task->force_upgrade = true;
                } else if(item->type == cJSON_False) {
                    task->force_upgrade = false;
                } else {
                    sprintf(output, "Parameter \"%s\" should be true or false", item->string);
                    error_flag = 1;
                }
            } else if(strcmp(item->string, "package_type") == 0) {
                /* package_type */
                if (item->type == cJSON_String) {
                    if (!strcmp(item->valuestring, "rpm") || !strcmp(item->valuestring, "deb")) {
                        os_free(task->package_type);
                        os_strdup(item->valuestring, task->package_type);
                    } else {
                        sprintf(output, "Invalid parameter \"%s\", value should be \"rpm\" or \"deb\"", item->string);
                        error_flag = 1;
                    }
                } else {
                    sprintf(output, "Parameter \"%s\" should be a string", item->string);
                    error_flag = 1;
                }
            }
        } else {
            sprintf(output, "Invalid JSON type");
            error_flag = 1;
        }
    }

    if (error_flag) {
        // We will reject this task since the parameters are incorrect
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_COMMAND_PARSE_ERROR, output);
        wm_agent_upgrade_free_upgrade_task(task);
        os_strdup(output, *error_message);
        os_free(output);
        return NULL;
    }

    // Validate required parameter: request_time is mandatory for deterministic task IDs
    if (task->request_time == 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_COMMAND_PARSE_ERROR, "Missing required parameter: request_time");
        wm_agent_upgrade_free_upgrade_task(task);
        os_strdup("Missing required parameter: request_time", *error_message);
        os_free(output);
        return NULL;
    }

    os_free(output);

    return task;
}

STATIC wm_upgrade_custom_task* wm_agent_upgrade_parse_upgrade_custom_command(const cJSON* params, char** error_message) {
    char *output = NULL;
    int param_index = 0;
    int error_flag = 0;

    os_calloc(OS_MAXSTR, sizeof(char), output);

    wm_upgrade_custom_task *task = wm_agent_upgrade_init_upgrade_custom_task();

    while(!error_flag && params && (param_index < cJSON_GetArraySize(params))) {
        cJSON *item = cJSON_GetArrayItem(params, param_index++);
        if (item->string) {
            if(strcmp(item->string, "request_time") == 0) {
                /* request_time - Unix timestamp from API for deterministic task IDs */
                if (item->type == cJSON_Number) {
                    task->request_time = (time_t)item->valuedouble;
                } else {
                    sprintf(output, "Parameter \"%s\" should be a number", item->string);
                    error_flag = 1;
                }
            } else if (strcmp(item->string, "file_path") == 0) {
                /* file_path */
                if (item->type == cJSON_String) {
                    os_free(task->custom_file_path);
                    os_strdup(item->valuestring, task->custom_file_path);
                } else {
                    sprintf(output, "Parameter \"%s\" should be a string", item->string);
                    error_flag = 1;
                }
            } else if(strcmp(item->string, "installer") == 0) {
                /* installer */
                if (item->type == cJSON_String) {
                    os_free(task->custom_installer);
                    os_strdup(item->valuestring, task->custom_installer);
                } else {
                    sprintf(output, "Parameter \"%s\" should be a string", item->string);
                    error_flag = 1;
                }
            }
        } else {
            sprintf(output, "Invalid JSON type");
            error_flag = 1;
        }
    }

    if (error_flag) {
        // We will reject this task since the parameters are incorrect
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_COMMAND_PARSE_ERROR, output);
        wm_agent_upgrade_free_upgrade_custom_task(task);
        os_strdup(output, *error_message);
        os_free(output);
        return NULL;
    }

    // Validate required parameter: request_time is mandatory for deterministic task IDs
    if (task->request_time == 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_COMMAND_PARSE_ERROR, "Missing required parameter: request_time");
        wm_agent_upgrade_free_upgrade_custom_task(task);
        os_strdup("Missing required parameter: request_time", *error_message);
        os_free(output);
        return NULL;
    }

    os_free(output);

    return task;
}

cJSON* wm_agent_upgrade_parse_data_response(int error_id, const char* message, const int *agent_id) {
    cJSON *response = cJSON_CreateObject();

    cJSON_AddNumberToObject(response, upgrade_json_keys[WM_UPGRADE_ERROR], error_id);
    if (message) {
        cJSON_AddStringToObject(response, upgrade_json_keys[WM_UPGRADE_ERROR_MESSAGE], message);
    }
    if(agent_id) {
        cJSON_AddNumberToObject(response, upgrade_json_keys[WM_UPGRADE_AGENT_ID], *agent_id);
    }

    return response;
}

cJSON* wm_agent_upgrade_parse_response(int error_id, cJSON *data) {
    cJSON *response = cJSON_CreateObject();

    cJSON_AddNumberToObject(response, upgrade_json_keys[WM_UPGRADE_ERROR], error_id);
    if (data && (data->type == cJSON_Array)) {
        cJSON_AddItemToObject(response, upgrade_json_keys[WM_UPGRADE_DATA], data);
    } else {
        cJSON *data_array = cJSON_CreateArray();
        cJSON_AddItemToArray(data_array, data);
        cJSON_AddItemToObject(response, upgrade_json_keys[WM_UPGRADE_DATA], data_array);
    }
    cJSON_AddStringToObject(response, upgrade_json_keys[WM_UPGRADE_ERROR_MESSAGE], upgrade_error_codes[error_id]);

    return response;
}
