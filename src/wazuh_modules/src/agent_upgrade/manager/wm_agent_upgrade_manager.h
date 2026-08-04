/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_AGENT_UPGRADE_MANAGER_H
#define WM_AGENT_UPGRADE_MANAGER_H

#include "wm_agent_upgrade.h"

#define WM_UPGRADE_MINIMAL_VERSION_SUPPORT "v3.0.0"
#define WM_UPGRADE_NEW_LINUX_VERSION_REPOSITORY "v3.4.0"
#define WM_UPGRADE_5X_MINIMUM_VERSION "v5.0.0"
#define WM_UPGRADE_REQUIRED_INTERMEDIATE_VERSION "v4.14.0"
#define WM_UPGRADE_NEW_VERSION_STRUCTURE_REPOSITORY "v4.9.0"
#define WM_UPGRADE_WPK_DEFAULT_PATH "var/upgrade/"
#define WM_UPGRADE_WPK_DOWNLOAD_TIMEOUT 60000
#define WM_UPGRADE_WPK_DOWNLOAD_ATTEMPTS 5
#define WM_UPGRADE_MAX_RESPONSE_SIZE 1048576L
#define WM_AGENT_UPGRADE_START_WAIT_TIME 30
#define WM_UPGRADE_DEFAULT_REQUEST_TIMEOUT 20L

typedef enum _wm_upgrade_error_code {
    WM_UPGRADE_SUCCESS = 0,
    WM_UPGRADE_PARSING_ERROR,
    WM_UPGRADE_PARSING_REQUIRED_PARAMETER,
    WM_UPGRADE_TASK_CONFIGURATIONS,
    WM_UPGRADE_TASK_MANAGER_COMMUNICATION,
    WM_UPGRADE_TASK_MANAGER_FAILURE,
    WM_UPGRADE_GLOBAL_DB_FAILURE,
    WM_UPGRADE_SYSTEM_NOT_SUPPORTED,
    WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED,
    WM_UPGRADE_INTERMEDIATE_VERSION_REQUIRED,
    WM_UPGRADE_NEW_VERSION_LESS_OR_EQUAL_THAN_CURRENT,
    WM_UPGRADE_NEW_VERSION_GREATER_MASTER,
    WM_UPGRADE_URL_NOT_FOUND,
    WM_UPGRADE_WPK_VERSION_DOES_NOT_EXIST,
    WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST,
    WM_UPGRADE_WPK_SHA1_DOES_NOT_MATCH,
    WM_UPGRADE_HTTPS_VERIFICATION_MODE_UNSAFE,
    WM_UPGRADE_UNKNOWN_ERROR
} wm_upgrade_error_code;

typedef enum _wm_upgrade_command {
    WM_UPGRADE_UPGRADE = 0,
    WM_UPGRADE_UPGRADE_CUSTOM
} wm_upgrade_command;

/**
 * Definition of upgrade task to be run
 */
typedef struct _wm_upgrade_task {
    char *wpk_repository;        ///> url to a wpk_repository
    char *custom_version;        ///> upgrade to a custom version
    bool use_http;               ///> when enabled uses http instead of https to connect to repository
    bool force_upgrade;          ///> when enabled forces upgrade
    char *wpk_version;           ///> WPK version to install
    char *wpk_file;              ///> WPK file name
    char *wpk_sha1;              ///> WPK sha1 to validate
    char *package_type;          ///> package type to send (for Linux systems)
    time_t request_time;         ///> timestamp from API for deterministic task IDs across cluster nodes
} wm_upgrade_task;

/**
 * Definition of upgrade custom task to be run
 */
typedef struct _wm_upgrade_custom_task {
    char *custom_file_path;      ///> sets a custom file path. Should be available in all worker nodes
    char *custom_installer;      ///> sets a custom installer script. Should be available in all worker nodes
    char *wpk_sha1;              ///> SHA1 hash of custom WPK file (calculated during validation)
    time_t request_time;         ///> timestamp from API for deterministic task IDs across cluster nodes
} wm_upgrade_custom_task;

/**
 * Definition of the structure that will represent a certain task
 */
typedef struct _wm_task_info {
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
    char *package_type;          ///> package type of the agent (DEB, RPM, etc.)
} wm_agent_info;

/**
 * Definition of the structure that will represent an agent executing a certain task
 */
typedef struct _wm_agent_task {
    wm_agent_info *agent_info;   ///> pointer to agent_info structure
    wm_task_info *task_info;     ///> pointer to task_info structure
} wm_agent_task;

extern const char* upgrade_error_codes[];

wm_upgrade_task* wm_agent_upgrade_init_upgrade_task();
wm_upgrade_custom_task* wm_agent_upgrade_init_upgrade_custom_task();
wm_task_info* wm_agent_upgrade_init_task_info();
wm_agent_info* wm_agent_upgrade_init_agent_info();
wm_agent_task* wm_agent_upgrade_init_agent_task();
void wm_agent_upgrade_free_upgrade_task(wm_upgrade_task* upgrade_task);
void wm_agent_upgrade_free_upgrade_custom_task(wm_upgrade_custom_task* upgrade_custom_task);
void wm_agent_upgrade_free_task_info(wm_task_info* task_info);
void wm_agent_upgrade_free_agent_info(wm_agent_info* agent_info);
void wm_agent_upgrade_free_agent_task(wm_agent_task* agent_task);

/**
 * Send a task creation request to the Task Manager via Unix socket
 * @param message_object JSON message to send to Task Manager
 * @return JSON response from Task Manager, or NULL on communication error
 * */
cJSON* wm_agent_upgrade_send_tasks_information(const cJSON *message_object) __attribute__((nonnull));

/**
 * Start main loop of the upgrade module for the manager
 * @param manager_configs Manager configuration parameters
 * @param enabled Wheter the module will allow or not upgrades
 * */
void wm_agent_upgrade_start_manager_module(const wm_manager_configs* manager_configs, const int enabled) __attribute__((nonnull));

/**
 * Process an upgrade command. Create the task for each agent_id, dispatches to task manager and
 * then starts upgrading process.
 * @param agent_ids array with the list of agents id
 * @param task pointer to a wm_upgrade_task structure
 * @param wpk_repository_config optional WPK repository URL from module config (can be NULL)
 * @return string with the response
 * */
char* wm_agent_upgrade_process_upgrade_command(const int* agent_ids, wm_upgrade_task* task, const char *wpk_repository_config) __attribute__((nonnull(1, 2)));

/**
 * Process an upgrade custom command. Create the task for each agent_id, dispatches to task manager and
 * then starts upgrading process.
 * @param agent_ids array with the list of agents id
 * @param task pointer to a wm_upgrade_custom_task structure
 * @return string with the response
 * */
char* wm_agent_upgrade_process_upgrade_custom_command(const int* agent_ids, wm_upgrade_custom_task* task) __attribute__((nonnull));

#endif
