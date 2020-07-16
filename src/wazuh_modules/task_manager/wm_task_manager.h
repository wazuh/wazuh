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

#ifndef WM_TASK_MANAGER_H
#define WM_TASK_MANAGER_H

#define WM_TASK_MANAGER_LOGTAG ARGV0 ":" TASK_MANAGER_WM_NAME

typedef struct _wm_task_manager {
    int enabled:1;
} wm_task_manager;

typedef enum _json_key {
    MODULE = 0,
    COMMAND,
    AGENT_ID,
    TASK_ID,
    ERROR,
    ERROR_DATA
} json_key;

typedef enum _module_list {
    UPGRADE_MODULE = 0
} module_list;

typedef enum _command_list {
    UPGRADE = 0
} command_list;

typedef enum _error_code {
    SUCCESS = 0,
    INVALID_MESSAGE,
    DATABASE_ERROR,
    UNKNOWN_ERROR
} error_code;

typedef enum _task_status {
    NEW = 0,
    IN_PROGRESS,
    DONE,
    FAILED
} task_status;

extern const wm_context WM_TASK_MANAGER_CONTEXT;   // Context

// Parse XML configuration
int wm_task_manager_read(xml_node **nodes, wmodule *module);

/**
 * Do all the analysis of the incomming message and returns a response.
 * @param msg Incomming message from a connection.
 * @param response Response to be sent to the connection.
 * @return Size of the response string.
 * */
size_t wm_task_manager_dispatch(const char *msg, char **response);

/**
 * Parse the incomming message and return a JSON with the message.
 * @param msg Incomming message from a connection.
 * @return JSON array when succeed, NULL otherwise.
 * */
cJSON* wm_task_manager_parse_message(const char *msg);

/**
 * Build a JSON object when creating a new task for an agent.
 * @param agent_id ID of the agent where the task will be executed.
 * @param task_id ID of the task recently created for the agent.
 * @return JSON object.
 * */
cJSON* wm_task_manager_build_response_insert(int agent_id, int task_id);

/**
 * Build a string when there is an error while analyzing a message.
 * @param error_code Code of the error.
 * @return Error string.
 * */
char* wm_task_manager_build_response_error(int error_code);

/**
 * Create the tasks DB or check that it already exists.
 * @return 0 when succeed, -1 otherwise.
 * */
int wm_task_manager_check_db();

/**
 * Insert a new task in the tasks DB.
 * @param agent_id ID of the agent where the task will be executed.
 * @param module Name of the module where the message comes from.
 * @param command Command to be executed in the agent.
 * @return ID of the task recently created when succeed, <=0 otherwise.
 * */
int wm_task_manager_insert_task(int agent_id, const char *module, const char *command);

#endif
#endif
