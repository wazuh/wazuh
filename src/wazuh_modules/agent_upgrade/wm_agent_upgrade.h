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

typedef enum _wm_upgrade_command {
    WM_UPGRADE_UPGRADE = 0,
    WM_UPGRADE_UPGRADE_CUSTOM,
    WM_UPGRADE_UPGRADE_RESULT
} wm_upgrade_command;

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

/**
 * Definition of the structure that will represent a certain task
 * */
typedef struct _wm_task_info {
    int task_id;                 ///> task_id associated with the task
    wm_upgrade_command command;  ///> command that has been requested
    void *task;                  ///> pointer to a task structure (depends on command)
} wm_task_info;

/**
 * Definition of the structure with the information of a certain agent
 * */
typedef struct _wm_agent_info {
    int agent_id;                ///> agent_id of the agent
    char *platform;              ///> platform of the agent
    char *major_version;         ///> major version of the agent
    char *minor_version;         ///> minor version of the agent
    char *architecture;          ///> architecture of the agent
} wm_agent_info;

extern const char* upgrade_error_codes[];
extern const wm_context WM_AGENT_UPGRADE_CONTEXT;   // Context

// Parse XML configuration
int wm_agent_upgrade_read(xml_node **nodes, wmodule *module);

/**
 * Process and upgrade command. Create the task for each agent_id, dispatches to task manager and
 * then starts upgrading process.
 * @param agent_ids array with the list of agents id
 * @param task pointer to a wm_upgrade_task structure
 * @return string with the response
 * */
char* wm_agent_upgrade_process_upgrade_command(const int* agent_ids, wm_upgrade_task* task);

/**
 * Process and upgrade custom command. Create the task for each agent_id, dispatches to task manager and
 * then starts upgrading process.
 * @param agent_ids array with the list of agents id
 * @param task pointer to a wm_upgrade_custom_task structure
 * @return string with the response
 * */
char* wm_agent_upgrade_process_upgrade_custom_command(const int* agent_ids, wm_upgrade_custom_task* task);

/**
 * @WIP
 * Process and upgrade_result command.
 * @param agent_ids array with the list of agents id
 * @return string with the response
 * */
char* wm_agent_upgrade_process_upgrade_result_command(const int* agent_ids);

#endif
