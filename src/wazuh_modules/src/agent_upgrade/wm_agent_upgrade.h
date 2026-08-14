/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015, Wazuh Inc.
 * July 15, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_AGENT_UPGRADE_H
#define WM_AGENT_UPGRADE_H

#include "wmodules_def.h"

#define WM_AGENT_UPGRADE_LOGTAG ARGV0 ":" AGENT_UPGRADE_WM_NAME

#define WM_UPGRADE_WPK_REPO_URL_3_X "packages.wazuh.com/wpk/"
#define WM_UPGRADE_WPK_REPO_URL "packages.wazuh.com/%d.x/wpk/"

/**
 * Configurations on agent side
 */
typedef struct _wm_agent_configs {
    unsigned int enable_ca_verification;
} wm_agent_configs;

/**
 * Configuration only for manager
 */
typedef struct _wm_manager_configs {
    char *wpk_repository;
} wm_manager_configs;

typedef struct _wm_agent_upgrade {
    int enabled:1;
    wm_agent_configs agent_config;
    wm_manager_configs manager_config;
} wm_agent_upgrade;

/**
 * JSON keys used in agent upgrade socket protocol
 */
typedef enum _wm_upgrade_json_keys {
    WM_UPGRADE_COMMAND = 0,
    WM_UPGRADE_PARAMETERS,
    WM_UPGRADE_AGENTS,
    WM_UPGRADE_ERROR,
    WM_UPGRADE_DATA,
    WM_UPGRADE_ERROR_MESSAGE,
    WM_UPGRADE_AGENT_ID
} wm_upgrade_json_keys;

extern const char *upgrade_json_keys[];

// Parse XML configuration
int wm_agent_upgrade_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

extern const wm_context WM_AGENT_UPGRADE_CONTEXT;   // Context

#endif
