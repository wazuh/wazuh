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

#ifndef WM_AGENT_UPGRADE_H
#define WM_AGENT_UPGRADE_H

#include "defs.h"

#define WM_AGENT_UPGRADE_LOGTAG ARGV0 ":" AGENT_UPGRADE_WM_NAME
#define WM_AGENT_UPGRADE_MODULE_NAME "upgrade_module"
#define WM_UPGRADE_MINIMAL_VERSION_SUPPORT "v3.0.0"
#define WM_UPGRADE_SUCCESS_VALIDATE 0
#define MANAGER_ID 0

#ifdef WIN32
    #define WM_AGENT_UPGRADE_RESULT_FILE UPGRADE_DIR "\\upgrade_result"
#else 
    #define WM_AGENT_UPGRADE_RESULT_FILE DEFAULTDIR UPGRADE_DIR "/upgrade_result"
#endif

typedef struct _wm_agent_upgrade {
    int enabled:1;
} wm_agent_upgrade;

// Parse XML configuration
int wm_agent_upgrade_read(xml_node **nodes, wmodule *module);

extern const wm_context WM_AGENT_UPGRADE_CONTEXT;   // Context

/**
 * Process and upgrade command. Create the task for each agent_id, dispatches to task manager and
 * then starts upgrading process.
 * @param params cJSON with the task parameters. For more details @see wm_agent_upgrade_parse_upgrade_command
 * @param agents cJSON Array with the list of agents id
 * @return json object with the response
 * */
cJSON *wm_agent_upgrade_process_upgrade_command(const cJSON* params, const cJSON* agents);

/**
 * Process and upgrade custom command. Create the task for each agent_id, dispatches to task manager and
 * then starts upgrading process.
 * @param params cJSON with the task parameters. For more details @see wm_agent_upgrade_parse_upgrade_custom_command
 * @param agents cJSON Array with the list of agents id
 * @return json object with the response
 * */
cJSON *wm_agent_upgrade_process_upgrade_custom_command(const cJSON* params, const cJSON* agents);

/**
 * @WIP
 * Process and upgrade_result command.
 * @param agents cJSON Array with the list of agents id
 * @return json object with the response
 * */
cJSON* wm_agent_upgrade_process_upgrade_result_command(const cJSON* agents);

/**
 * Check if agent exist
 * @param agent_id Id of agent to validate
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS_VALIDATE
 * @retval WM_UPGRADE_NOT_AGENT_IN_DB
 * @retval WM_UPGRADE_INVALID_ACTION_FOR_MANAGER
 * */
int wm_agent_upgrade_validate_id(int agent_id);

/**
 * Check if agent version is valid to upgrade
 * @param agent_id Id of agent to validate
 * @param task pointer to task with the params
 * @param command wm_upgrade_command with the selected upgrade type
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS_VALIDATE
 * @retval WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED
 * @retval WM_UPGRADE_VERSION_SAME_MANAGER
 * @retval WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT
 * @retval WM_UPGRADE_NEW_VERSION_GREATER_MASTER)
 * @retval WM_UPGRADE_VERSION_QUERY_ERROR
 * */
int wm_agent_upgrade_validate_agent_version(int agent_id, void *task, wm_upgrade_command command);

/**
 * Check if agent status is active
 * @param agent_id Id of agent to validate
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS_VALIDATE
 * @retval WM_UPGRADE_AGENT_IS_NOT_ACTIVE
 * */
int wm_agent_upgrade_validate_status(int agent_id);

#endif
