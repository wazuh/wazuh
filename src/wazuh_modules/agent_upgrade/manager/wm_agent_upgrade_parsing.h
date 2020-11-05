/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 15, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef WM_AGENT_UPGRADE_PARSING_H
#define WM_AGENT_UPGRADE_PARSING_H

#include "wm_agent_upgrade_manager.h"

/**
 * Parse received upgrade message and returns task and agent ids values and a code
 * representing a command if it is valid or an error code otherwise
 * 
 * Example:
 * 
 * {
 *	    "command": "upgrade",
 *	    "parameters": {
 *		    "agents": [5, 6],
 *          "use_http": 0,
 *          "force_upgrade": 0
 *	    }
 * }
 * 
 * @param buffer message to be parsed
 * @param task on success command task will be stored in this variable
 * @param agent_ids on success agent ids list will be stored in this variable
 * @param error message in case of error
 * @return error code
 * @retval OS_INVALID on errors
 * @retval UPGRADE if is and upgrade command
 * @retval UPGRADE_CUSTOM if is and upgrade_custom command
 * @retval UPGRADE_RESULT if it is and upgrade_result command
 * */
int wm_agent_upgrade_parse_message(const char* buffer, void** task, int** agent_ids, char** error);

/**
 * Parse a data message
 * 
 * 
 * Example 1:
 * 
 * {
 *     "error":12,
 *     "message":"The repository is not reachable.",
 *     "agent":4
 * }
 * 
 * Example 2:
 * 
 * {
 *     "error":1,
 *     "message":"Could not parse message JSON."
 * }
 * 
 * @param error_id positive number if error, 0 if successs
 * @param message response message
 * @param agent_id [OPTIONAL] id of the agent
 * @return data json
 * */
cJSON* wm_agent_upgrade_parse_data_response(int error_id, const char* message, const int* agent_id);

/**
 * Parse a response message
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
 *              "error":12,
 *              "message":"The repository is not reachable.",
 *              "agent":5
 *          }
 *     ],
 *     "message": "Successful"
 * }
 * 
 * @param error_id positive number if error, 0 if successs
 * @param data [OPTIONAL] array of responses
 * @return response json
 * */
cJSON* wm_agent_upgrade_parse_response(int error_id, cJSON *data);

/**
 * Parse a message to be sent to the task module
 * 
 * Example:
 * 
 * {
 *	    "command": "upgrade_update_status",
 *	    "origin": {
 *		    "module": "upgrade_module"
 *	    },
 *	    "parameters": {
 *		    "agents": [1],
 *          "status": "Failed",
 *          "error_msg": "Send open file error."
 *	    }
 * }
 * 
 * @param command task command
 * @param agents_array JSON array of agents id
 * @param status optional status string
 * @param error optional error message
 * @return json to be sent
 * */
cJSON* wm_agent_upgrade_parse_task_module_request(wm_upgrade_command command, cJSON *agents_array, const char* status, const char* error);

/**
 * Parse a response message from the agent
 * @param agent_response string with the response of the agent
 * @param data additional data of the response when success
 * @return error code
 * @retval OS_SUCCESS on success
 * @retval OS_INVALID on errors
 * */
int wm_agent_upgrade_parse_agent_response(const char* agent_response, char **data);

#endif
