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

#include "wmodules.h"

int wm_agent_upgrade_read(xml_node **nodes, wmodule *module);

extern const wm_context WM_AGENT_UPGRADE_CONTEXT;   // Context

typedef struct _wm_agent_upgrade {
    int enabled;
} wm_agent_upgrade;

#define WM_AGENT_UPGRADE_LOGTAG AGENT_UPGRADE_WM_NAME

#endif
