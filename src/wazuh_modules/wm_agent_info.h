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
#include <stdint.h>

#define WM_AGENT_INFO_LOGTAG ARGV0 ":agent-info"
#define AGENT_INFO_WM_NAME   "agent-info"
#define AGENT_INFO_LIB_NAME  "agent_info"

typedef struct wm_agent_info_sync_flags_t
{
    unsigned int enable_synchronization : 1;
    uint32_t sync_interval;
    uint32_t sync_response_timeout;
    long sync_max_eps;
} wm_agent_info_sync_flags_t;

typedef struct wm_agent_info_t
{
    int enabled;
    int interval; // Update interval in seconds
    wm_agent_info_sync_flags_t sync;
} wm_agent_info_t;

extern const wm_context WM_AGENT_INFO_CONTEXT;

// Configuration reading function
int wm_agent_info_read(const OS_XML* xml, xml_node** nodes, wmodule* module);

#endif // WM_AGENT_INFO_H
