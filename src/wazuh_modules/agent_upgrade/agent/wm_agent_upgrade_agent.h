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

/**
 * Checks if an agent has been recently upgraded, by reading upgrade_results file
 * If there has been an upgrade, dispatchs a message to notificate the maanger
 * */
void wm_agent_upgrade_check_status();

typedef enum _wm_upgrade_agent_state {
    WM_UPGRADE_SUCCESSFULL = 0,
    WM_UPGRADE_FAILED
} wm_upgrade_agent_state;

#define WM_UPGRADE_MAX_AGENT_STATE WM_UPGRADE_FAILED 

#define WM_UPGRADE_AGENT_UPDATED_COMMAND "agent_upgraded"

#endif
