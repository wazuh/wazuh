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
 * Definition of upgrade task to be run
 * */
typedef struct _wm_upgrade_task {
    int agent;                   ///> agent_id to be upgraded
    char *command;               ///> comand that has been requested [upgrade/upgrade_results]
    char *custom_file_path;      ///> sets a custom file path. Should be available in all worker nodes
    char *custom_installer;      ///> sets a custom installer script. Should be available in all worker nodes
    char *wpk_repository;        ///> url to a wpk_repository
    char *custom_version;        ///> upgrade to a custom version  
    bool use_http;               ///> when enabled uses http instead of https to connect to repository 
    bool force_upgrade;          ///> when enabled forces upgrade
    enum wm_upgrade_state state; ///> current state of the task
} wm_upgrade_task;


#define WM_AGENT_UPGRADE_LOGTAG AGENT_UPGRADE_WM_NAME

/**
 * Parse received upgrade message, returns message to be returned to server
 * or an error in case of an invalid message
 * @param buffer message to be parsed
 * @param output output message buffer
 * @return new generated task
 * */
wm_upgrade_task* wm_agent_parse_upgrade_command(const char* buffer, char* output);

/**
 * Parses a response message based on state 
 * @param wm_upgrade_state State of the upgrade
 * @param message resposne message
 * @return string of resposne json
 * */
char* wm_agent_parse_response_mesage(enum wm_upgrade_state state, const char* message);

/**
 * Initialization of upgrade task
 * @param return an initialized upgrade task structure
 * */
wm_upgrade_task* init_upgrade_task();
/**
 * Deallocate wm_upgrade_task structure
 * @param task  takk to be deallocated
 * */
void destroy_upgrade_task(wm_upgrade_task* task);

#endif
