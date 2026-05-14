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

#define WM_AGENT_UPGRADE_LOGTAG ARGV0 ":" AGENT_UPGRADE_WM_NAME

#define WM_UPGRADE_WPK_REPO_URL_3_X "packages.wazuh.com/wpk/"
#define WM_UPGRADE_WPK_REPO_URL "packages.wazuh.com/%d.x/wpk/"
#define WM_UPGRADE_CHUNK_SIZE 32768
#define WM_UPGRADE_CHUNK_SIZE_MIN 64
#define WM_UPGRADE_CHUNK_SIZE_MAX 60000
#define WM_UPGRADE_MAX_THREADS 8
#define WM_UPGRADE_WAIT_START 30
#define WM_UPGRADE_WAIT_MAX 3600
#define WM_UPGRADE_WAIT_FACTOR_INCREASE 2.0

/**
 * Configurations on agent side
 */
typedef struct _wm_agent_configs {
    unsigned int upgrade_wait_start;
    unsigned int upgrade_wait_max;
    float upgrade_wait_factor_increase;
    unsigned int enable_ca_verification;
} wm_agent_configs;

/**
 * Configuration only for manager
 */
typedef struct _wm_manager_configs {
    unsigned int max_threads;
    unsigned int chunk_size;
    char *wpk_repository;
} wm_manager_configs;

typedef struct _wm_agent_upgrade {
    int enabled:1;
    wm_agent_configs agent_config;
    wm_manager_configs manager_config;
} wm_agent_upgrade;

// Parse XML configuration
int wm_agent_upgrade_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

extern const wm_context WM_AGENT_UPGRADE_CONTEXT;   // Context

#endif
