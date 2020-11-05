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

#ifndef WM_AGENT_UPGRADE_AGENT_H
#define WM_AGENT_UPGRADE_AGENT_H

#ifdef WIN32
    #define WM_AGENT_UPGRADE_RESULT_FILE UPGRADE_DIR "\\upgrade_result"
#else
    #define WM_AGENT_UPGRADE_RESULT_FILE DEFAULTDIR UPGRADE_DIR "/upgrade_result"
#endif

#define WM_AGENT_UPGRADE_RESULT_WAIT_TIME 30

typedef enum _wm_upgrade_agent_state {
    WM_UPGRADE_SUCCESSFUL = 0,
    WM_UPGRADE_FAILED,
    WM_UPGRADE_MAX_STATE
} wm_upgrade_agent_state;

/**
 * Checks if an agent has been recently upgraded, by reading upgrade_results file
 * If there has been an upgrade, dispatchs a message to notificate the manager.
 * This method will block the thread if the agent is not connected to the manager
 * @param agent_config Agent configuration parameters
 * */
void wm_agent_upgrade_check_status(const wm_agent_configs* agent_config) __attribute__((nonnull));

#endif
