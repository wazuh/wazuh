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

#ifndef WM_TASK_GENERAL_H
#define WM_TASK_GENERAL_H

#define WM_TASK_STATUS_PENDING "Pending"
#define WM_TASK_STATUS_IN_PROGRESS "In progress"
#define WM_TASK_STATUS_DONE "Done"
#define WM_TASK_STATUS_FAILED "Failed"
#define WM_TASK_STATUS_CANCELLED "Cancelled"
#define WM_TASK_STATUS_TIMEOUT "Timeout"
#define WM_TASK_STATUS_LEGACY "Legacy"

/**
 * Enumeration of all available keys that could be used in the messages
 * */
typedef enum _task_manager_json_key {
    // Request
    WM_TASK_ORIGIN = 0,
    WM_TASK_NAME,
    WM_TASK_MODULE,
    WM_TASK_COMMAND,
    WM_TASK_PARAMETERS,
    WM_TASK_AGENTS,
    WM_TASK_TASKS,
    // Response
    WM_TASK_ERROR,
    WM_TASK_DATA,
    WM_TASK_ERROR_MESSAGE,
    WM_TASK_AGENT_ID,
    WM_TASK_TASK_ID,
    WM_TASK_NODE,
    WM_TASK_STATUS,
    WM_TASK_ERROR_MSG,
    WM_TASK_CREATE_TIME,
    WM_TASK_LAST_UPDATE_TIME
} task_manager_json_key;

/**
 * Enumeration of the available commands
 * */
typedef enum _command_list {
    WM_TASK_UPGRADE = 0,
    WM_TASK_UPGRADE_CUSTOM,
    WM_TASK_UPGRADE_GET_STATUS,
    WM_TASK_UPGRADE_UPDATE_STATUS,
    WM_TASK_UPGRADE_RESULT,
    WM_TASK_UPGRADE_CANCEL_TASKS,
    WM_TASK_TASK_RESULT
} command_list;

/**
 * Enumeration of the modules orchestrated by the task manager
 * */
typedef enum _module_list {
    WM_TASK_UPGRADE_MODULE = 0,
    WM_TASK_API_MODULE
} module_list;

/**
 * Enumeration of the possible task statuses
 * */
typedef enum _task_status {
    WM_TASK_PENDING = 0,
    WM_TASK_IN_PROGRESS,
    WM_TASK_DONE,
    WM_TASK_FAILED,
    WM_TASK_CANCELLED,
    WM_TASK_TIMEOUT,
    WM_TASK_LEGACY
} task_status;

/**
 * List containing all the possible json_keys
 * */
extern const char *task_manager_json_keys[];

/**
 * List containing all the command names
 * */
extern const char *task_manager_commands_list[];

/**
 * List containing the module names
 * */
extern const char *task_manager_modules_list[];

/**
 * List of possible task statuses
 * */
extern const char *task_statuses[];

#endif
