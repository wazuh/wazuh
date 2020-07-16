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

#include "wazuh_modules/wmodules.h"

int wm_agent_upgrade_read(xml_node **nodes, wmodule *module);

extern const wm_context WM_AGENT_UPGRADE_CONTEXT;   // Context

cJSON *wm_agent_process_upgrade_command(const cJSON* params, const cJSON* agents);
cJSON* wm_agent_process_upgrade_result_command(const cJSON* agents);
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

enum wm_upgrade_error_codes {
    SUCCESS,
    PARSING_ERROR,
    TASK_CONFIGURATIONS,
    TASK_MANAGER_COMMUNICATION,
    TASK_MANAGER_FAILURE,
    UPGRADE_ALREADY_ON_PROGRESS,
    AGENT_ID_ERROR,
    UNKNOWN_ERROR
};

/**
 * Definition of the structure that will represent an agent doing a certain task
 * */
typedef struct _wm_agent_task {
    int agent;                   ///> agent_id to be upgraded
    int task_id;                 ///> task_id associated with the task
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

#define WM_AGENT_UPGRADE_COMMAND_NAME "upgrade"
#define WM_AGENT_UPGRADE_RESULT_COMMAND_NAME "upgrade_result"

#endif
