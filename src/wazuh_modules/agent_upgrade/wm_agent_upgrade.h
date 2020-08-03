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
#define WM_UPGRADE_MINIMAL_VERSION_SUPPORT "v3.0.0"
#define WM_UPGRADE_NEW_VERSION_REPOSITORY "v3.4.0"
#define WM_UPGRADE_WPK_REPO_URL "packages.wazuh.com/wpk/"
#define WM_UPGRADE_WPK_DEFAULT_PATH "var/upgrade/"
#define WM_UPGRADE_WPK_DOWNLOAD_TIMEOUT 60000
#define WM_UPGRADE_WPK_DOWNLOAD_ATTEMPTS 5
#define MANAGER_ID 0

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
    WM_UPGRADE_GLOBAL_DB_FAILURE,
    WM_UPGRADE_INVALID_ACTION_FOR_MANAGER,
    WM_UPGRADE_AGENT_IS_NOT_ACTIVE,
    WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED,
    WM_UPGRADE_SYSTEM_NOT_SUPPORTED,
    WM_UPGRADE_URL_NOT_FOUND,
    WM_UPGRADE_WPK_VERSION_DOES_NOT_EXIST,
    WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT,
    WM_UPGRADE_NEW_VERSION_GREATER_MASTER,
    WM_UPGRADE_VERSION_SAME_MANAGER,
    WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST,
    WM_UPGRADE_WPK_SHA1_DOES_NOT_MATCH,
    WM_UPGRADE_UPGRADE_ALREADY_IN_PROGRESS,
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
    char *wpk_file;              ///> WPK file name
    char *wpk_sha1;              ///> WPK sha1 to validate
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
    char *major_version;         ///> OS major version of the agent
    char *minor_version;         ///> OS minor version of the agent
    char *architecture;          ///> architecture of the agent
    char *wazuh_version;         ///> wazuh version of the agent
    int last_keep_alive;         ///> last_keep_alive of the agent
} wm_agent_info;

/**
 * Definition of the structure that will represent an agent executing a certain task
 * */
typedef struct _wm_agent_task {
    wm_agent_info *agent_info;   ///> pointer to agent_info structure
    wm_task_info *task_info;     ///> pointer to task_info structure
} wm_agent_task;

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

/**
 * Check if agent exist
 * @param agent_id id of agent to validate
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_INVALID_ACTION_FOR_MANAGER
 * */
int wm_agent_upgrade_validate_id(int agent_id);

/**
 * Check if agent status is active
 * @param keep_alive last keep-alive of agent to validate
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_AGENT_IS_NOT_ACTIVE
 * */
int wm_agent_upgrade_validate_status(int last_keep_alive);

/**
 * Check if agent is valid to upgrade
 * @param agent_info pointer to agent_info struture
 * @param task pointer to task with the params
 * @param command wm_upgrade_command with the selected upgrade type
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED
 * @retval WM_UPGRADE_SYSTEM_NOT_SUPPORTED
 * @retval WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT
 * @retval WM_UPGRADE_NEW_VERSION_GREATER_MASTER
 * @retval WM_UPGRADE_VERSION_SAME_MANAGER
 * @retval WM_UPGRADE_GLOBAL_DB_FAILURE
 * */
int wm_agent_upgrade_validate_version(const wm_agent_info *agent_info, void *task, wm_upgrade_command command);

/**
 * Check if WPK file exist and/or download it
 * @param task pointer to task with the params
 * @param command wm_upgrade_command with the selected upgrade type
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST
 * @retval WM_UPGRADE_WPK_SHA1_DOES_NOT_MATCH
 * */
int wm_agent_upgrade_validate_wpk(const void *task, wm_upgrade_command command);

#endif
