/*
 * Wazuh Module for Task management.
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 13, 2020.
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

#ifndef WIN32

#include "../wmodules.h"
#include "wm_task_manager_db.h"
#include "wm_task_manager_parsing.h"

/**
 * Analyze an upgrade or upgrade_custom command. Update the tasks DB when necessary.
 * @param task Upgrade task to be processed.
 * @param command Command of the task to be executed.
 * @param error_code Variable to store an error code if something is wrong.
 * @return JSON object with the response for this task.
 * */
STATIC cJSON* wm_task_manager_command_upgrade(wm_task_manager_upgrade *task, int command, int *error_code) __attribute__((nonnull));

/**
 * Analyze an upgrade_get_status command.
 * @param task Upgrade get status task to be processed.
 * @param error_code Variable to store an error code if something is wrong.
 * @return JSON object with the response for this task.
 * */
STATIC cJSON* wm_task_manager_command_upgrade_get_status(wm_task_manager_upgrade_get_status *task, int *error_code) __attribute__((nonnull));

/**
 * Analyze an upgrade_update_status command. Update the tasks DB when necessary.
 * @param task Upgrade update status task to be processed.
 * @param error_code Variable to store an error code if something is wrong.
 * @return JSON object with the response for this task.
 * */
STATIC cJSON* wm_task_manager_command_upgrade_update_status(wm_task_manager_upgrade_update_status *task, int *error_code) __attribute__((nonnull));

/**
 * Analyze an upgrade_result command.
 * @param task Upgrade result task to be processed.
 * @param error_code Variable to store an error code if something is wrong.
 * @return JSON object with the response for this task.
 * */
STATIC cJSON* wm_task_manager_command_upgrade_result(wm_task_manager_upgrade_result *task, int *error_code) __attribute__((nonnull));

/**
 * Analyze an upgrade_cancel_tasks command. Update the tasks DB when necessary.
 * @param task Upgrade cancel tasks task to be processed.
 * @param error_code Variable to store an error code if something is wrong.
 * @return JSON object with the response for this task.
 * */
STATIC cJSON* wm_task_manager_command_upgrade_cancel_tasks(wm_task_manager_upgrade_cancel_tasks *task, int *error_code) __attribute__((nonnull));

/**
 * Analyze a task_result command.
 * @param task Task result task to be processed.
 * @param error_code Variable to store an error code if something is wrong.
 * @return JSON object with the response for this task.
 * */
STATIC cJSON* wm_task_manager_command_task_result(wm_task_manager_task_result *task, int *error_code) __attribute__((nonnull));

cJSON* wm_task_manager_process_task(const wm_task_manager_task *task, int *error_code) {
    cJSON *response = NULL;

    switch (task->command) {
    case WM_TASK_UPGRADE:
    case WM_TASK_UPGRADE_CUSTOM:
        response = wm_task_manager_command_upgrade((wm_task_manager_upgrade *)task->parameters, task->command, error_code);
        break;
    case WM_TASK_UPGRADE_GET_STATUS:
        response = wm_task_manager_command_upgrade_get_status((wm_task_manager_upgrade_get_status *)task->parameters, error_code);
        break;
    case WM_TASK_UPGRADE_UPDATE_STATUS:
        response = wm_task_manager_command_upgrade_update_status((wm_task_manager_upgrade_update_status *)task->parameters, error_code);
        break;
    case WM_TASK_UPGRADE_RESULT:
        response = wm_task_manager_command_upgrade_result((wm_task_manager_upgrade_result *)task->parameters, error_code);
        break;
    case WM_TASK_UPGRADE_CANCEL_TASKS:
        response = wm_task_manager_command_upgrade_cancel_tasks((wm_task_manager_upgrade_cancel_tasks *)task->parameters, error_code);
        break;
    case WM_TASK_TASK_RESULT:
        response = wm_task_manager_command_task_result((wm_task_manager_task_result *)task->parameters, error_code);
        break;
    default:
        *error_code = WM_TASK_INVALID_COMMAND;
    }

    return response;
}

STATIC cJSON* wm_task_manager_command_upgrade(wm_task_manager_upgrade *task, int command, int *error_code) {
    cJSON *response = NULL;
    int agent_it = 0;
    int agent_id = 0;
    int task_id = OS_INVALID;

    if (task->node && task->module && task->agent_ids) {
        response = cJSON_CreateArray();
        while (agent_id = task->agent_ids[agent_it++], agent_id != OS_INVALID) {
            // Insert upgrade task into DB
            if (task_id = wm_task_manager_insert_task(agent_id, task->node, task->module, task_manager_commands_list[command]), task_id == OS_INVALID) {
                *error_code = WM_TASK_DATABASE_ERROR;
                cJSON_Delete(response);
                break;
            } else {
                cJSON_AddItemToArray(response, wm_task_manager_parse_data_response(WM_TASK_SUCCESS, agent_id, task_id, NULL));
            }
        }
    } else {
        if (!task->node) {
            *error_code = WM_TASK_INVALID_NODE;
        } else if (!task->module) {
            *error_code = WM_TASK_INVALID_MODULE;
        } else {
            *error_code = WM_TASK_INVALID_AGENTS;
        }
    }

    return response;
}

STATIC cJSON* wm_task_manager_command_upgrade_get_status(wm_task_manager_upgrade_get_status *task, int *error_code) {
    cJSON *response = NULL;
    int agent_it = 0;
    int agent_id = 0;
    int result = 0;
    char *status_result = NULL;

    if (task->node && task->agent_ids) {
        response = cJSON_CreateArray();
        while (agent_id = task->agent_ids[agent_it++], agent_id != OS_INVALID) {
            // Get upgrade task status
            if (result = wm_task_manager_get_upgrade_task_status(agent_id, task->node, &status_result), result == OS_INVALID) {
                *error_code = WM_TASK_DATABASE_ERROR;
                cJSON_Delete(response);
                break;
            } else {
                cJSON_AddItemToArray(response, wm_task_manager_parse_data_response(WM_TASK_SUCCESS, agent_id, OS_INVALID, status_result));
            }
        }
    } else {
        if (!task->node) {
            *error_code = WM_TASK_INVALID_NODE;
        } else {
            *error_code = WM_TASK_INVALID_AGENTS;
        }
    }

    os_free(status_result);

    return response;
}

STATIC cJSON* wm_task_manager_command_upgrade_update_status(wm_task_manager_upgrade_update_status *task, int *error_code) {
    cJSON *response = NULL;
    int agent_it = 0;
    int agent_id = 0;
    int result = 0;

    if (task->node && task->agent_ids) {
        response = cJSON_CreateArray();
        while (agent_id = task->agent_ids[agent_it++], agent_id != OS_INVALID) {
            // Update upgrade task status
            if (result = wm_task_manager_update_upgrade_task_status(agent_id, task->node, task->status, task->error_msg), result == OS_INVALID) {
                *error_code = WM_TASK_DATABASE_ERROR;
                cJSON_Delete(response);
                break;
            } else if (result) {
                cJSON_AddItemToArray(response, wm_task_manager_parse_data_response(result, agent_id, OS_INVALID, task->status));
            } else {
                cJSON_AddItemToArray(response, wm_task_manager_parse_data_response(WM_TASK_SUCCESS, agent_id, OS_INVALID, task->status));
            }
        }
    } else {
        if (!task->node) {
            *error_code = WM_TASK_INVALID_NODE;
        } else {
            *error_code = WM_TASK_INVALID_AGENTS;
        }
    }

    return response;
}

STATIC cJSON* wm_task_manager_command_upgrade_result(wm_task_manager_upgrade_result *task, int *error_code) {
    cJSON *response = NULL;
    int agent_it = 0;
    int agent_id = 0;
    int create_time = OS_INVALID;
    int last_update_time = OS_INVALID;
    char *node_result = NULL;
    char *module_result = NULL;
    char *command_result = NULL;
    char *status = NULL;
    char *error = NULL;
    int task_id = OS_INVALID;

    if (task->agent_ids) {
        response = cJSON_CreateArray();
        while (agent_id = task->agent_ids[agent_it++], agent_id != OS_INVALID) {
            if (task_id = wm_task_manager_get_upgrade_task_by_agent_id(agent_id, &node_result, &module_result, &command_result, &status, &error, &create_time, &last_update_time), task_id == OS_INVALID) {
                *error_code = WM_TASK_DATABASE_ERROR;
                cJSON_Delete(response);
                break;
            } else if (task_id == OS_NOTFOUND || task_id == 0) {
                cJSON_AddItemToArray(response, wm_task_manager_parse_data_response(WM_TASK_DATABASE_NO_TASK, agent_id, OS_INVALID, NULL));
            } else {
                cJSON *tmp = wm_task_manager_parse_data_response(WM_TASK_SUCCESS, agent_id, task_id, NULL);
                wm_task_manager_parse_data_result(tmp, node_result, module_result, command_result, status, error, create_time, last_update_time, task_manager_commands_list[WM_TASK_UPGRADE_RESULT]);
                cJSON_AddItemToArray(response, tmp);
            }
        }
    } else {
        *error_code = WM_TASK_INVALID_AGENTS;
    }

    os_free(node_result);
    os_free(module_result);
    os_free(command_result);
    os_free(status);
    os_free(error);

    return response;
}

STATIC cJSON* wm_task_manager_command_upgrade_cancel_tasks(wm_task_manager_upgrade_cancel_tasks *task, int *error_code) {
    cJSON *response = NULL;
    int result = 0;

    if (task->node) {
        // Cancel pending tasks for this node
        if (result = wm_task_manager_cancel_upgrade_tasks(task->node), result == OS_INVALID) {
            *error_code = WM_TASK_DATABASE_ERROR;
            cJSON_Delete(response);
        } else {
            response = wm_task_manager_parse_data_response(WM_TASK_SUCCESS, OS_INVALID, OS_INVALID, NULL);
        }
    } else {
        *error_code = WM_TASK_INVALID_NODE;
    }

    return response;
}

STATIC cJSON* wm_task_manager_command_task_result(wm_task_manager_task_result *task, int *error_code) {
    cJSON *response = NULL;
    int task_it = 0;
    int task_id = 0;
    int create_time = OS_INVALID;
    int last_update_time = OS_INVALID;
    char *node_result = NULL;
    char *module_result = NULL;
    char *command_result = NULL;
    char *status = NULL;
    char *error = NULL;
    int agent_id = OS_INVALID;

    if (task->task_ids) {
        response = cJSON_CreateArray();
        while (task_id = task->task_ids[task_it++], task_id != OS_INVALID) {
            if (agent_id = wm_task_manager_get_task_by_task_id(task_id, &node_result, &module_result, &command_result, &status, &error, &create_time, &last_update_time), agent_id == OS_INVALID) {
                *error_code = WM_TASK_DATABASE_ERROR;
                cJSON_Delete(response);
                break;
            } else if (agent_id == OS_NOTFOUND || agent_id == 0) {
                cJSON_AddItemToArray(response, wm_task_manager_parse_data_response(WM_TASK_DATABASE_NO_TASK, OS_INVALID, task_id, NULL));
            } else {
                cJSON *tmp = wm_task_manager_parse_data_response(WM_TASK_SUCCESS, agent_id, task_id, NULL);
                wm_task_manager_parse_data_result(tmp, node_result, module_result, command_result, status, error, create_time, last_update_time, task_manager_commands_list[WM_TASK_TASK_RESULT]);
                cJSON_AddItemToArray(response, tmp);
            }
        }
    } else {
        *error_code = WM_TASK_INVALID_TASKS;
    }

    os_free(node_result);
    os_free(module_result);
    os_free(command_result);
    os_free(status);
    os_free(error);

    return response;
}

#endif
