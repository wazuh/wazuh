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
#define AGENT_INFO_LIB_NAME  "agent_info"

typedef struct wm_agent_info_sync_flags_t
{
    unsigned int enable_synchronization : 1;
    uint32_t sync_end_delay;
    uint32_t sync_response_timeout;
    uint32_t sync_retries;
    long sync_max_eps;
} wm_agent_info_sync_flags_t;

typedef struct wm_agent_info_t
{
    bool is_agent;       // True if the module is running on an agent, false if on a manager
    int interval;        // Update interval in seconds (for delta updates)
    int integrity_interval; // Integrity check interval in seconds (for full metadata/groups verification), default 86400 (24h)
    wm_agent_info_sync_flags_t sync;
} wm_agent_info_t;

extern const wm_context WM_AGENT_INFO_CONTEXT;

// Configuration reading function
int wm_agent_info_read(const OS_XML* xml, xml_node** nodes, wmodule* module);

#endif // WM_AGENT_INFO_H
