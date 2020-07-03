/*
 * Wazuh Module for Security Configuration Assessment
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 3, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wm_agent_upgrade.h"

static void* wm_agent_upgrade_main(wm_agent_upgrade* upgrade_config);    // Module main function. It won't return
static void wm_agent_upgrade_destroy(wm_agent_upgrade* upgrade_config);  
cJSON *wm_agent_upgrade_dump(const wm_agent_upgrade* upgrade_config);

/* Context definition */
const wm_context WM_AGENT_UPGRADE_CONTEXT = {
    AGENT_UPGRADE_WM_NAME,
    (wm_routine)wm_agent_upgrade_main,
    (wm_routine)(void *)wm_agent_upgrade_destroy,
    (cJSON * (*)(const void *))wm_agent_upgrade_dump
};

void * wm_agent_upgrade_main(wm_agent_upgrade* upgrade_config) {
    mtinfo(WM_AGENT_UPGRADE_LOGTAG, "Module AgentUpgrade started");
    return NULL;
}

void wm_agent_upgrade_destroy(wm_agent_upgrade* upgrade_config) {
    mtinfo(WM_AGENT_UPGRADE_LOGTAG, "Module AgentUpgrade finished");
    os_free(upgrade_config);
}

cJSON *wm_agent_upgrade_dump(const wm_agent_upgrade* upgrade_config){
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_info = cJSON_CreateObject();

    if (upgrade_config->enabled) {
        cJSON_AddStringToObject(wm_info,"enabled","yes"); 
    } else { 
        cJSON_AddStringToObject(wm_info,"enabled","no");
    }
    cJSON_AddItemToObject(root,"agent-upgrade",wm_info);
    return root;
}

