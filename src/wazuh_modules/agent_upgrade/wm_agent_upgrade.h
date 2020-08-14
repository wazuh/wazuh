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

#define WM_UPGRADE_WPK_REPO_URL "packages.wazuh.com/wpk/"
#define WM_UPGRADE_CHUNK_SIZE 512

#ifdef CLIENT
/**
 * Configurations on agent side
 */
typedef struct _wm_agent_configs {
    unsigned int upgrade_wait_start;
    unsigned int upgrade_wait_max;
    float upgrade_wait_factor_increase;
} wm_agent_configs;
#endif

#ifndef CLIENT
/**
 * Configuration only for manager
 */
typedef struct _wm_manager_configs {
    unsigned int chunk_size;
    char *wpk_repository;
} wm_manager_configs;
#endif

typedef struct _wm_agent_upgrade {
    int enabled:1;
#ifdef CLIENT
    wm_agent_configs agent_config;
#endif
#ifndef CLIENT
    wm_manager_configs manager_config;
#endif
} wm_agent_upgrade;

// Parse XML configuration
int wm_agent_upgrade_read(xml_node **nodes, wmodule *module);

extern const wm_context WM_AGENT_UPGRADE_CONTEXT;   // Context

#endif
