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
    WM_TASK_UPGRADE_IN_QUEUE = 0,
    WM_TASK_UPGRADE_UPDATING,
    WM_TASK_UPGRADE_UPDATED,
    WM_TASK_UPGRADE_ERROR,
    WM_TASK_UPGRADE_CANCELLED,
    WM_TASK_UPGRADE_TIMEOUT,
    WM_TASK_UPGRADE_LEGACY
} upgrade_status;

extern const char* task_statuses[];

/**
 * Parse the incomming message and return a JSON with the message.
 * 
 * Example:
 * 
 * {
 *	    "command": "upgrade_result",
 *	    "origin": {
 *		    "module": "api"
 *	    },
 *	    "parameters": {
 *		    "agents": [99, 43, 18]
 *	    }
 * }
 * 
 * @param msg Incomming message from a connection.
 * @return JSON array when succeed, NULL otherwise.
 * */
cJSON* wm_task_manager_parse_message(const char *msg) __attribute__((nonnull));

/**
 * Build a JSON data object.
 * 
 * Example 1:
 * 
 * {
 *     "error":0,
 *     "message":"Success",
 *     "agent":4,
 *     "task_id":2
 * }
 * 
 * Example 2:
 * 
 * {
 *     "error":1,
 *     "message":"Invalid message"
 * }
 * 
 * @param error_code Code of the error.
 * @param agent_id ID of the agent when receiving a request for a specific agent.
 * @param task_id ID of the task when receiving a request for a specific task.
 * @param status Status of the task when receiving a request for a specific status.
 * @return JSON object.
 * */
cJSON* wm_task_manager_parse_data_response(int error_code, int agent_id, int task_id, char *status);

/**
 * Add data to a JSON data object.
 * 
 * Example 1: On upgrade_result request
 * 
 * {
 *     "error":0,
 *     "message":"Success",
 *     "agent":4,
 *     "task_id":2,
 *     "module":"upgrade_module",
 *     "command":"upgrade",
 *     "status":"Updating"
 *     "create_time":"2020-08-06 22:51:44"
 *     "update_time":"2020-08-06 22:53:21"
 * }
 * 
 * Example 2: On task_result request
 * 
 * {
 *     "error":0,
 *     "message":"Success",
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
 * @param node Node of the task when receiving a request for a specific task.
 * @param module Module of the task when receiving a request for a specific task.
 * @param command Command of the task when receiving a request for a specific task.
 * @param status Status of the task when receiving a request for a specific task.
 * @param error Error message of the task when receiving a request for a specific task.
 * @param create_time Date of creation task.
 * @param last_update_time Date of update task.
 * @param request_command Command that requested the query.
 * */
void wm_task_manager_parse_data_result(cJSON *response, const char *node, const char *module, const char *command, char *status, char *error, int create_time, int last_update_time, char *request_command) __attribute__((nonnull(1)));

/**
 * Build a JSON response object.
 * 
 * Example:
 * 
 * {
 *     "error":0,
 *     "data": [
 *          {
 *              "error":0,
 *              "message":"Success",
 *              "agent":4,
 *              "task_id":2
 *          },
 *          {
 *              "error":0,
 *              "message":"Success",
 *              "agent":5,
 *              "task_id":3
 *          }
 *     ],
 *     "message": "Successful"
 * }
 * 
 * @param error_code Code of the error.
 * @param data [OPTIONAL] array of responses.
 * @return JSON object.
 * */
cJSON* wm_task_manager_parse_response(int error_code, cJSON *data);

#endif
#endif
