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

#ifndef WM_AGENT_UPGRADE_AGENT_H
#define WM_AGENT_UPGRADE_AGENT_H

#ifdef WIN32
    #define WM_AGENT_UPGRADE_RESULT_FILE UPGRADE_DIR "\\upgrade_result"
#else
    #define WM_AGENT_UPGRADE_RESULT_FILE UPGRADE_DIR "/upgrade_result"
#endif

#define WM_AGENT_UPGRADE_RESULT_WAIT_TIME 30

typedef enum _wm_upgrade_agent_state {
    WM_UPGRADE_SUCCESSFUL = 0,
    WM_UPGRADE_FAILED_DEPENDENCY,
    WM_UPGRADE_FAILED,
    WM_UPGRADE_MAX_STATE
} wm_upgrade_agent_state;

extern char **wcom_ca_store;

extern bool allow_upgrades;

/**
 * Start main loop of the upgrade module for the agent
 * @param agent_config Agent configuration parameters
 * @param enabled Wheter the module will allow or not upgrades
 * */
void wm_agent_upgrade_start_agent_module(const wm_agent_configs* agent_config, const int enabled) __attribute__((nonnull));

/**
 * Receives a string and process it with the available commands
 * Request format:
 *{
 *   "command": "upgrade",
 *   "parameters" : {
 *       "file" : "file_path",
 *       "installer" : "installer_path"
 *    }
 *}
 * @param buffer string with the information
 * @param output response to command
 * @return size of the response
 * */
size_t wm_agent_upgrade_process_command(const char *buffer, char **output);

#endif
