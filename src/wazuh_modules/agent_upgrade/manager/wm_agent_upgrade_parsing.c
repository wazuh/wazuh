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
#include "wm_agent_upgrade_parsing.h"
#include "wm_agent_upgrade_tasks.h"

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

/**
 * Parses upgrade agent status and return an agent status task from the information
 * @param params JSON where the task parameters are
 * @param error_message message in case of error
 * @return upgrade task if there is no error, NULL otherwise
 * */
STATIC wm_upgrade_agent_status_task* wm_agent_upgrade_parse_upgrade_agent_status(const cJSON* params, char** error_message);

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

    cJSON *command = cJSON_GetObjectItem(root, task_manager_json_keys[WM_TASK_COMMAND]);
    cJSON *parameters = cJSON_GetObjectItem(root, task_manager_json_keys[WM_TASK_PARAMETERS]);

    if (command && (command->type == cJSON_String) && parameters && (parameters->type == cJSON_Object)) {

        cJSON *agents = cJSON_DetachItemFromObject(parameters, task_manager_json_keys[WM_TASK_AGENTS]);

        if (agents && (agents->type == cJSON_Array) && cJSON_GetArraySize(agents)) {

            if (strcmp(command->valuestring, task_manager_commands_list[WM_UPGRADE_UPGRADE]) == 0) { // Upgrade command
                // Analyze agent IDs
                *agent_ids = wm_agent_upgrade_parse_agents(agents, &error_message);
                if (!error_message) {
                    // Analyze upgrade parameters
                    *task = (wm_upgrade_task *)wm_agent_upgrade_parse_upgrade_command(parameters, &error_message);
                    if (!error_message) {
                        retval = WM_UPGRADE_UPGRADE;
                    }
                }

            } else if (strcmp(command->valuestring, task_manager_commands_list[WM_UPGRADE_UPGRADE_CUSTOM]) == 0) { // Upgrade custom command
                // Analyze agent IDs
                *agent_ids = wm_agent_upgrade_parse_agents(agents, &error_message);
                if (!error_message) {
                    // Analyze upgrade custom parameters
                    *task = (wm_upgrade_custom_task *)wm_agent_upgrade_parse_upgrade_custom_command(parameters, &error_message);
                    if (!error_message) {
                        retval = WM_UPGRADE_UPGRADE_CUSTOM;
                    }
                }

            } else if (strcmp(command->valuestring, task_manager_commands_list[WM_UPGRADE_AGENT_UPDATE_STATUS]) == 0) { // Upgrade update status command
                *agent_ids = wm_agent_upgrade_parse_agents(agents, &error_message);
                if (!error_message) {
                    *task = (wm_upgrade_agent_status_task*)wm_agent_upgrade_parse_upgrade_agent_status(parameters, &error_message);
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

STATIC wm_upgrade_task* wm_agent_upgrade_parse_upgrade_command(const cJSON* params, char** error_message) {
    char *output = NULL;
    int param_index = 0;
    int error_flag = 0;

    os_calloc(OS_MAXSTR, sizeof(char), output);

    wm_upgrade_task *task = wm_agent_upgrade_init_upgrade_task();

    while(!error_flag && params && (param_index < cJSON_GetArraySize(params))) {
        cJSON *item = cJSON_GetArrayItem(params, param_index++);
        if (item->string) {
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

    os_free(output);

    return task;
}

STATIC wm_upgrade_agent_status_task* wm_agent_upgrade_parse_upgrade_agent_status(const cJSON* params, char** error_message) {
    char *output = NULL;
    int param_index = 0;
    int error_flag = 0;

    os_calloc(OS_MAXSTR, sizeof(char), output);

    wm_upgrade_agent_status_task *task = wm_agent_upgrade_init_agent_status_task();

    while(!error_flag && params && (param_index < cJSON_GetArraySize(params))) {
        cJSON *item = cJSON_GetArrayItem(params, param_index++);
        if (item->string) {
            if(strcmp(item->string, task_manager_json_keys[WM_TASK_ERROR]) == 0) {
                if (item->type == cJSON_Number) {
                    task->error_code = item->valueint;
                } else {
                    sprintf(output, "Parameter \"%s\" should be a number", item->string);
                    error_flag = 1;
                }
            } else if(strcmp(item->string, task_manager_json_keys[WM_TASK_ERROR_MESSAGE]) == 0) {
                if (item->type == cJSON_String) {
                    os_strdup(item->valuestring, task->message);
                } else {
                    sprintf(output, "Parameter \"%s\" should be a string", item->string);
                    error_flag = 1;
                }
            } else if(strcmp(item->string, task_manager_json_keys[WM_TASK_STATUS]) == 0) {
                if (item->type == cJSON_String) {
                    os_strdup(item->valuestring, task->status);
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
        wm_agent_upgrade_free_agent_status_task(task);
        os_strdup(output, *error_message);
        os_free(output);
        return NULL;
    }

    os_free(output);

    return task;
}

cJSON* wm_agent_upgrade_parse_data_response(int error_id, const char* message, const int *agent_id) {
    cJSON *response = cJSON_CreateObject();

    cJSON_AddNumberToObject(response, task_manager_json_keys[WM_TASK_ERROR], error_id);
    if (message) {
        cJSON_AddStringToObject(response, task_manager_json_keys[WM_TASK_ERROR_MESSAGE], message);
    }
    if(agent_id) {
        cJSON_AddNumberToObject(response, task_manager_json_keys[WM_TASK_AGENT_ID], *agent_id);
    }

    return response;
}

cJSON* wm_agent_upgrade_parse_response(int error_id, cJSON *data) {
    cJSON *response = cJSON_CreateObject();

    cJSON_AddNumberToObject(response, task_manager_json_keys[WM_TASK_ERROR], error_id);
    if (data && (data->type == cJSON_Array)) {
        cJSON_AddItemToObject(response, task_manager_json_keys[WM_TASK_DATA], data);
    } else {
        cJSON *data_array = cJSON_CreateArray();
        cJSON_AddItemToArray(data_array, data);
        cJSON_AddItemToObject(response, task_manager_json_keys[WM_TASK_DATA], data_array);
    }
    cJSON_AddStringToObject(response, task_manager_json_keys[WM_TASK_ERROR_MESSAGE], upgrade_error_codes[error_id]);

    return response;
}

cJSON* wm_agent_upgrade_parse_task_module_request(wm_upgrade_command command, cJSON *agents_array, const char* status, const char* error) {
    cJSON *request = cJSON_CreateObject();
    cJSON *origin = cJSON_CreateObject();
    cJSON *parameters = cJSON_CreateObject();

    char* node_name = NULL;
    OS_XML xml;

    const char *(xml_node[]) = {"ossec_config", "cluster", "node_name", NULL};

    if (OS_ReadXML(DEFAULTCPATH, &xml) >= 0) {
        node_name = OS_GetOneContentforElement(&xml, xml_node);
    }

    OS_ClearXML(&xml);

    cJSON_AddStringToObject(origin, task_manager_json_keys[WM_TASK_NAME], node_name ? node_name : "");
    cJSON_AddStringToObject(origin, task_manager_json_keys[WM_TASK_MODULE], task_manager_modules_list[WM_TASK_UPGRADE_MODULE]);
    cJSON_AddItemToObject(request, task_manager_json_keys[WM_TASK_ORIGIN], origin);
    cJSON_AddStringToObject(request, task_manager_json_keys[WM_TASK_COMMAND], task_manager_commands_list[command]);
    if (agents_array) {
        cJSON_AddItemToObject(parameters, task_manager_json_keys[WM_TASK_AGENTS], agents_array);
    }
    if (status) {
        cJSON_AddStringToObject(parameters, task_manager_json_keys[WM_TASK_STATUS], status);
    }
    if (error) {
        cJSON_AddStringToObject(parameters, task_manager_json_keys[WM_TASK_ERROR_MSG], error);
    }
    cJSON_AddItemToObject(request, task_manager_json_keys[WM_TASK_PARAMETERS], parameters);

    os_free(node_name);

    return request;
}

int wm_agent_upgrade_parse_agent_response(const char* agent_response, char **data) {
    char *error = NULL;
    int error_code = OS_SUCCESS;

    if (agent_response) {
        if (!strncmp(agent_response, "ok", 2)) {
            if (data && strchr(agent_response, ' ')) {
                *data = strchr(agent_response, ' ') + 1;
            }
        } else {
            if (!strncmp(agent_response, "err", 3) && strchr(agent_response, ' ')) {
                error = strchr(agent_response, ' ') + 1;
                mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_AGENT_RESPONSE_MESSAGE_ERROR, error);
            }
            error_code = OS_INVALID;
        }
    } else {
        error_code = OS_INVALID;
    }

    return error_code;
}
