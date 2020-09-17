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

#ifndef WM_AGENT_UPGRADE_COM_H
#define WM_AGENT_UPGRADE_COM_H

/**
 * Receives a string and process it with the available commands
 * @param buffer string with the information
 * @return string to be returned to the socket
 * */
char *wm_agent_upgrade_process_command(const char* buffer);

#endif
