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
