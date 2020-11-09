/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 30, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_AGENT_UPGRADE_MANAGER_H
#define WM_AGENT_UPGRADE_MANAGER_H

#define WM_UPGRADE_MINIMAL_VERSION_SUPPORT "v3.0.0"
#define WM_UPGRADE_NEW_VERSION_REPOSITORY "v3.4.0"
#define WM_UPGRADE_NEW_UPGRADE_MECHANISM "v4.1.0"
#define WM_UPGRADE_WPK_DEFAULT_PATH "var/upgrade/"
#define WM_UPGRADE_WPK_DOWNLOAD_TIMEOUT 60000
#define WM_UPGRADE_WPK_DOWNLOAD_ATTEMPTS 5
#define WM_UPGRADE_WPK_OPEN_ATTEMPTS 10
#define MANAGER_ID 0
#define WM_AGENT_UPGRADE_START_WAIT_TIME 30

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
    WM_UPGRADE_UPGRADE_ALREADY_IN_PROGRESS,
    WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED,
    WM_UPGRADE_SYSTEM_NOT_SUPPORTED,
    WM_UPGRADE_URL_NOT_FOUND,
    WM_UPGRADE_WPK_VERSION_DOES_NOT_EXIST,
    WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT,
    WM_UPGRADE_NEW_VERSION_GREATER_MASTER,
    WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST,
    WM_UPGRADE_WPK_SHA1_DOES_NOT_MATCH,
    WM_UPGRADE_SEND_LOCK_RESTART_ERROR,
    WM_UPGRADE_SEND_OPEN_ERROR,
    WM_UPGRADE_SEND_WRITE_ERROR,
    WM_UPGRADE_SEND_CLOSE_ERROR,
    WM_UPGRADE_SEND_SHA1_ERROR,
    WM_UPGRADE_SEND_UPGRADE_ERROR,
    WM_UPGRADE_UPGRADE_ERROR,
    WM_UPGRADE_UNKNOWN_ERROR
} wm_upgrade_error_code;

typedef enum _wm_upgrade_command {
    WM_UPGRADE_UPGRADE = WM_TASK_UPGRADE,
    WM_UPGRADE_UPGRADE_CUSTOM = WM_TASK_UPGRADE_CUSTOM,
    WM_UPGRADE_AGENT_GET_STATUS = WM_TASK_UPGRADE_GET_STATUS,
    WM_UPGRADE_AGENT_UPDATE_STATUS = WM_TASK_UPGRADE_UPDATE_STATUS,
    WM_UPGRADE_CANCEL_TASKS = WM_TASK_UPGRADE_CANCEL_TASKS
} wm_upgrade_command;

/**
 * Definition of upgrade task to be run
 */
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
 */
typedef struct _wm_upgrade_custom_task {
    char *custom_file_path;      ///> sets a custom file path. Should be available in all worker nodes
    char *custom_installer;      ///> sets a custom installer script. Should be available in all worker nodes
} wm_upgrade_custom_task;

/**
 * Definition of an agent status update task
 */
typedef struct _wm_upgrade_agent_status_task {
    unsigned int error_code;
    char *message;
    char *status;
} wm_upgrade_agent_status_task;

/**
 * Definition of the structure that will represent a certain task
 */
typedef struct _wm_task_info {
    int task_id;                 ///> task_id associated with the task
    wm_upgrade_command command;  ///> command that has been requested
    void *task;                  ///> pointer to a task structure (depends on command)
} wm_task_info;

/**
 * Definition of the structure with the information of a certain agent
 */
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
 */
typedef struct _wm_agent_task {
    wm_agent_info *agent_info;   ///> pointer to agent_info structure
    wm_task_info *task_info;     ///> pointer to task_info structure
} wm_agent_task;

extern const char* upgrade_error_codes[];

/**
 * Start listening loop, exits only on error 
 * @param timeout_sec timeout in seconds
 * @param manager_configs manager configuration parameters
 * @return only on errors, socket will be closed
 * */
void wm_agent_upgrade_listen_messages(const wm_manager_configs* manager_configs) __attribute__((nonnull));

/**
 * Process an upgrade_cancel_tasks command
 * */
void wm_agent_upgrade_cancel_pending_upgrades();

/**
 * Process an upgrade command. Create the task for each agent_id, dispatches to task manager and
 * then starts upgrading process.
 * @param agent_ids array with the list of agents id
 * @param task pointer to a wm_upgrade_task structure
 * @param manager_configs manager configuration parameters
 * @return string with the response
 * */
char* wm_agent_upgrade_process_upgrade_command(const int* agent_ids, wm_upgrade_task* task, const wm_manager_configs* manager_configs) __attribute__((nonnull));

/**
 * Process an upgrade custom command. Create the task for each agent_id, dispatches to task manager and
 * then starts upgrading process.
 * @param agent_ids array with the list of agents id
 * @param task pointer to a wm_upgrade_custom_task structure
 * @param manager_configs manager configuration parameters
 * @return string with the response
 * */
char* wm_agent_upgrade_process_upgrade_custom_command(const int* agent_ids, wm_upgrade_custom_task* task, const wm_manager_configs* manager_configs) __attribute__((nonnull));

/**
 * Process an agent_upgraded command
 * @param agent_ids List with id of the agents (In this case the list will contain only 1 id)
 * @param task Task with the update information
 * @return string with the response
 * */
char* wm_agent_upgrade_process_agent_result_command(const int* agent_ids, const wm_upgrade_agent_status_task* task) __attribute__((nonnull));

#endif
