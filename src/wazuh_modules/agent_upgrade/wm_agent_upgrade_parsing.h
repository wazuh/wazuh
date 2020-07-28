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

#include "wm_agent_upgrade.h"

/**
 * Parse received upgrade message and returns task and agent ids values and a code
 * representing a command if it is valid or an error code otherwise
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
 * Parse a response message based on state
 * @param error_id 1 if error, 0 if successs
 * @param message response message
 * @param agent_id [OPTIONAL] id of the agent
 * @param task_id [OPTIONAL] id of the task
 * @param status [OPTIONAL] status string
 * @return response json
 * */
cJSON* wm_agent_upgrade_parse_response_message(int error_id, const char* message, const int* agent_id, const int* task_id, const char* status);

/**
 * Parse a message to be sent to the task module
 * @param command task command
 * @param agent_id agent id
 * @return json to be sent
 * */
cJSON* wm_agent_upgrade_parse_task_module_request(wm_upgrade_command command, int agent_id);

/**
 * Send a request to the task module and parse the response with the task ids
 * @param json_response cJSON array where the task responses will be stored
 * @param task_module_request cJSON to be sent to the task module
 * @return error code
 * @retval OS_SUCCESS on success
 * @retval OS_INVALID on errors
 * */
int wm_agent_upgrade_parse_task_module_task_ids(cJSON *json_response, const cJSON* task_module_request);

#endif
