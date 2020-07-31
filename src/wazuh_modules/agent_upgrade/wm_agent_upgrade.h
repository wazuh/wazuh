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

#include "defs.h"

#define WM_AGENT_UPGRADE_LOGTAG ARGV0 ":" AGENT_UPGRADE_WM_NAME
#define WM_AGENT_UPGRADE_MODULE_NAME "upgrade_module"

#ifdef WIN32
    #define WM_AGENT_UPGRADE_RESULT_FILE UPGRADE_DIR "\\upgrade_result"
#else 
    #define WM_AGENT_UPGRADE_RESULT_FILE DEFAULTDIR UPGRADE_DIR "/upgrade_result"
#endif

typedef struct _wm_agent_upgrade {
    int enabled:1;
} wm_agent_upgrade;

typedef enum _wm_upgrade_command {
    WM_UPGRADE_UPGRADE = 0,
    WM_UPGRADE_UPGRADE_CUSTOM,
    WM_UPGRADE_UPGRADE_RESULT,
    WM_UPGRADE_AGENT_UPGRADED,
    WM_UPGRADE_AGENT_UPGRADE_FAILED,
    WM_UPGRADE_INVALID_COMMAND
} wm_upgrade_command;

// Parse XML configuration
int wm_agent_upgrade_read(xml_node **nodes, wmodule *module);

extern const wm_context WM_AGENT_UPGRADE_CONTEXT;   // Context
#endif
