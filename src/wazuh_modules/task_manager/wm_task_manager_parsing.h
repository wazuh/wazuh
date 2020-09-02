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

#ifndef CLIENT

#ifndef WM_TAS_MANAGER_PARSING_H
#define WM_TAS_MANAGER_PARSING_H

#include "wm_task_manager.h"

typedef enum _upgrade_status {
    WM_TASK_UPGRADE_ERROR = 0,
    WM_TASK_UPGRADE_UPDATING,
    WM_TASK_UPGRADE_UPDATED,
    WM_TASK_UPGRADE_TIMEOUT,
    WM_TASK_UPGRADE_LEGACY
} upgrade_status;

extern const char* task_statuses[];

/**
 * Parse the incomming message and return a JSON with the message.
 * @param msg Incomming message from a connection.
 * @param module String where the module will be stored.
 * @param command String where the command will be stored.
 * @return JSON array when succeed, NULL otherwise.
 * */
cJSON* wm_task_manager_parse_message(const char *msg, char **module, char **command) __attribute__((nonnull));

/**
 * Build a JSON object response.
 * 
 * Example 1: Success
 * 
 * {
 *     "error":0,
 *     "data":"Success",
 *     "agent":4,
 *     "task_id":2
 * }
 * 
 * Example 2: Invalid message
 * 
 * {
 *     "error":1,
 *     "data":"Invalid message"
 * }
 * 
 * 
 * Example 3: Invalid module
 * 
 * {
 *     "error":2,
 *     "data":"Invalid module",
 *     "task_id":45
 * }
 * 
 * Example 4: Invalid command
 * 
 * {
 *     "error":3,
 *     "data":"Invalid command",
 *     "agent":15
 * }
 * 
 * @param error_code Code of the error.
 * @param agent_id ID of the agent when receiving a request for a specific agent.
 * @param task_id ID of the task when receiving a request for a specific task.
 * @param status Status of the task when receiving a request for a specific status.
 * @return JSON object.
 * */
cJSON* wm_task_manager_parse_response(int error_code, int agent_id, int task_id, char *status);

/**
 * Add data to a JSON object response.
 * 
 * Example 1: On upgrade_result request
 * 
 * {
 *     "error":0,
 *     "data":"Success",
 *     "agent":4,
 *     "task_id":2,
 *     "module":"upgrade_module",
 *     "command":"upgrade",
 *     "status":"Updating"
 *     "create_time":"2020-08-06 22:51:44"
 *     "update_time":"2020-08-06 22:53:21"
 * }
 * 
 * Example 1: On task_result request
 * 
 * {
 *     "error":0,
 *     "data":"Success",
 *     "agent":4,
 *     "task_id":2,
 *     "module":"upgrade_module",
 *     "command":"upgrade",
 *     "status":"In progress"
 *     "create_time":"2020-08-06 22:51:44"
 *     "update_time":"2020-08-06 22:53:21"
 * }
 * 
 * @param response JSON object response
 * @param module Module of the task when receiving a request for a specific task.
 * @param command Command of the task when receiving a request for a specific task.
 * @param status Status of the task when receiving a request for a specific task.
 * @param error Error message of the task when receiving a request for a specific task.
 * @param create_time Date of creation task.
 * @param last_update_time Date of update task.
 * @param request_command Command that requested the query.
 * */
void wm_task_manager_parse_response_result(cJSON *response, const char *module, const char *command, char *status, char *error, int create_time, int last_update_time, char *request_command) __attribute__((nonnull(1)));

#endif
#endif
