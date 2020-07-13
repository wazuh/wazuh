/*
 * Wazuh Module for Security Configuration Assessment
 * Copyright (C) 2015-2020, Wazuh Inc.
 * November 25, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_AGENT_UPGRADE_H
#define WM_AGENT_UPGRADE_H

#include "wazuh_modules/wmodules.h"

int wm_agent_upgrade_read(xml_node **nodes, wmodule *module);

extern const wm_context WM_AGENT_UPGRADE_CONTEXT;   // Context

/**
 * Module general configuration
 * */
typedef struct _wm_agent_upgrade {
    int enabled; ///< Indicates if modules is enabled
} wm_agent_upgrade;

enum wm_upgrade_state {
    NOT_STARTED,
    STARTED,
    ERROR
};

/**
 * Definition of the structure that will represent an agent doing a certain task
 * */
typedef struct _wm_agent_task {
    int agent;                   ///> agent_id to be upgraded
    char *command;               ///> comand that has been requested [upgrade/upgrade_results]
    void *task;                  ///> pointer to a task structure (depends on command)
} wm_agent_task;

/**
 * Definition of upgrade task to be run
 * */
typedef struct _wm_upgrade_task {
    char *custom_file_path;      ///> sets a custom file path. Should be available in all worker nodes
    char *custom_installer;      ///> sets a custom installer script. Should be available in all worker nodes
    char *wpk_repository;        ///> url to a wpk_repository
    char *custom_version;        ///> upgrade to a custom version  
    bool use_http;               ///> when enabled uses http instead of https to connect to repository 
    bool force_upgrade;          ///> when enabled forces upgrade
    enum wm_upgrade_state state; ///> current state of the task
} wm_upgrade_task;


#define WM_AGENT_UPGRADE_LOGTAG AGENT_UPGRADE_WM_NAME
#define WM_AGENT_UPGRADE_MODULE_NAME "ugprade_module"
/**
 * Parse received upgrade message, separetes it according to agent list
 * Will return response JSON to be retorned to the socket
 * @param buffer message to be parsed
 * @return JSON with all the task responses
 * */
cJSON* wm_agent_parse_command(const char* buffer);

/**
 * Parses a response message based on state 
 * @param error_id 1 if error, 0 if successs
 * @param message response message
 * @param agent_id id of the agent
 * @param task_id [OPTIONAL] id of the task
 * @return resposne json
 * */
cJSON* wm_agent_parse_response_mesage(int error_id, const char* message, const int agent_id, const int* task_id);

/**
 * Parses a message to be sent to the request module
 * @param command task command
 * @param agent_id agent id
 * @return json to be sent
 * */
cJSON* wm_agent_parse_task_module_message(const char* command, const int agent_id);

/**
 * Initialization of upgrade task
 * @param return an initialized upgrade task structure
 * */
wm_upgrade_task* wm_agent_init_upgrade_task();
/**
 * Deallocate wm_upgrade_task structure
 * @param task  task to be deallocated
 * */
void wm_agent_free_upgrade_task(wm_upgrade_task* task);

/**
 * Receives the cJSON with the agents_id and creates the tasks structure for each agent
 * Will return two jsons, one with the successfull operation to be sent to the request module
 * And another one with the failed operation (In case there is already an upgrade in place)
 * @param agents cJSON array with the agents_id
 * @param task pointer to a task structure
 * @param command command corresponding to the task
 * @param response list of request to be sent to the task module. Expects cJSON array as input 
 * @param failures list of request that failed to be added as tasks. Expects cJSON array as input 
 * */
void wm_agent_create_agent_tasks(cJSON *agents, void *task, const char* command, cJSON* response, cJSON* failures);

/**
 * Sends the JSON information to the task module and retrieves the anwser
 * @param message JSON to be sent. Ezample:
 *  [{
 *      "module" : "upgrade_module",
 *      "command": "upgrade",
 *      "agent" : 1
 *  }, {
 *      "module" : "upgrade_module",
 *      "command": "upgrade",
 *      "agent" : 2
 *  }]
 * @return json response
 * @retval NULL if connection problem or incorrect repsonse format
 * @retval JSON with the task information. Example:
 * [{
 *      "error": 0,
 *      "data": "Task created successfully",
 *      "agent": 1,
 *      "task_id": {{tid1}}
 *  }, {
 *      "error": 0,
 *      "data": "Task created successfully",
 *      "agent": 2,
 *      "task_id": {{tid2}}
 *  }]
 * */
cJSON *wm_agent_send_task_information(cJSON *message);

void wm_agent_init_task_table();

void wm_agent_destroy_task_table();
#endif
