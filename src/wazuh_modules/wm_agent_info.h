/*
 * Wazuh Module for Agent Information Management
 * Copyright (C) 2015, Wazuh Inc.
 * November 25, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_AGENT_INFO_H
#define WM_AGENT_INFO_H

#include "../os_xml/os_xml.h"
#include "wmodules_def.h"
#include <cJSON.h>

#define WM_AGENT_INFO_LOGTAG ARGV0 ":agent-info"
#define AGENT_INFO_WM_NAME   "agent-info"

typedef struct wm_agent_info_t
{
    int enabled;
    int interval; // Update interval in seconds
} wm_agent_info_t;

extern const wm_context WM_AGENT_INFO_CONTEXT;

// Module functions
void* wm_agent_info_main(wm_agent_info_t* agent_info);
void wm_agent_info_destroy(wm_agent_info_t* agent_info);
cJSON* wm_agent_info_dump(const wm_agent_info_t* agent_info);

// Configuration reading function
int wm_agent_info_read(const OS_XML* xml, xml_node** nodes, wmodule* module);

#endif // WM_AGENT_INFO_H