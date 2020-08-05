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

#define WM_AGENT_UPGRADE_LOGTAG ARGV0 ":" AGENT_UPGRADE_WM_NAME
#define WM_AGENT_UPGRADE_MODULE_NAME "upgrade_module"

#define WM_UPGRADE_AGENT_UPDATED_COMMAND "agent_status"

typedef struct _wm_agent_upgrade {
    int enabled:1;
} wm_agent_upgrade;

// Parse XML configuration
int wm_agent_upgrade_read(xml_node **nodes, wmodule *module);

extern const wm_context WM_AGENT_UPGRADE_CONTEXT;   // Context

#endif
