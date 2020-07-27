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

#define WM_AGENT_UPGRADE_LOGTAG ARGV0 ":" AGENT_UPGRADE_WM_NAME
#define WM_AGENT_UPGRADE_MODULE_NAME "upgrade_module"

typedef struct _wm_agent_upgrade {
    int enabled:1;
} wm_agent_upgrade;

typedef enum _wm_upgrade_error_code {
    WM_UPGRADE_SUCCESS = 0,
    WM_UPGRADE_PARSING_ERROR,
    WM_UPGRADE_PARSING_REQUIRED_PARAMETER,
    WM_UPGRADE_TASK_CONFIGURATIONS,
    WM_UPGRADE_TASK_MANAGER_COMMUNICATION,
    WM_UPGRADE_TASK_MANAGER_FAILURE,
    WM_UPGRADE_UPGRADE_ALREADY_ON_PROGRESS,
    WM_UPGRADE_UNKNOWN_ERROR
} wm_upgrade_error_code;

typedef enum _wm_upgrade_state {
    WM_UPGRADE_NOT_STARTED,
    WM_UPGRADE_STARTED,
    WM_UPGRADE_ERROR
} wm_upgrade_state;

typedef enum _wm_upgrade_command {
    WM_UPGRADE_UPGRADE = 0,
    WM_UPGRADE_UPGRADE_CUSTOM,
    WM_UPGRADE_UPGRADE_RESULT,
    WM_UPGRADE_INVALID_COMMAND
} wm_upgrade_command;

/**
 * Definition of the structure that will represent a certain task
 * */
typedef struct _wm_task {
    int task_id;                 ///> task_id associated with the task
    wm_upgrade_state state;      ///> current state of the task
    wm_upgrade_command command;  ///> command that has been requested
    void *task;                  ///> pointer to a task structure (depends on command)
} wm_task;

/**
 * Definition of upgrade task to be run
 * */
typedef struct _wm_upgrade_task {
    char *wpk_repository;        ///> url to a wpk_repository
    char *custom_version;        ///> upgrade to a custom version
    bool use_http;               ///> when enabled uses http instead of https to connect to repository
    bool force_upgrade;          ///> when enabled forces upgrade
} wm_upgrade_task;

/**
 * Definition of upgrade custom task to be run
 * */
typedef struct _wm_upgrade_custom_task {
    char *custom_file_path;      ///> sets a custom file path. Should be available in all worker nodes
    char *custom_installer;      ///> sets a custom installer script. Should be available in all worker nodes
} wm_upgrade_custom_task;

extern const char* upgrade_error_codes[];
extern const wm_context WM_AGENT_UPGRADE_CONTEXT;   // Context

// Parse XML configuration
int wm_agent_upgrade_read(xml_node **nodes, wmodule *module);

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

#endif
