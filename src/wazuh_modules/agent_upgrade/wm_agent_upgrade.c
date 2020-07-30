/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 3, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuh_modules/wmodules.h"
#include "os_net/os_net.h"

#ifdef CLIENT
#include "agent/wm_agent_upgrade_agent.h"
#else
#include "manager/wm_agent_upgrade_manager.h"
#include "manager/wm_agent_upgrade_tasks.h"
#endif

/**
 * Module main function. It won't return
 * */
static void* wm_agent_upgrade_main(wm_agent_upgrade* upgrade_config);    
static void wm_agent_upgrade_destroy(wm_agent_upgrade* upgrade_config);  
static cJSON *wm_agent_upgrade_dump(const wm_agent_upgrade* upgrade_config);

/* Context definition */
const wm_context WM_AGENT_UPGRADE_CONTEXT = {
    AGENT_UPGRADE_WM_NAME,
    (wm_routine)wm_agent_upgrade_main,
    (wm_routine)(void *)wm_agent_upgrade_destroy,
    (cJSON * (*)(const void *))wm_agent_upgrade_dump
};

void * wm_agent_upgrade_main(wm_agent_upgrade* upgrade_config) {

    // Check if module is enabled
    if (!upgrade_config->enabled) {
        mtinfo(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_MODULE_DISABLED);
        pthread_exit(NULL);
    }

    mtinfo(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_MODULE_STARTED);

    #ifdef CLIENT
        wm_agent_upgrade_check_status();
    #else 
        // Initialize task hashmap
        wm_agent_upgrade_init_task_map();

        int sock = OS_BindUnixDomain(WM_UPGRADE_SOCK_PATH, SOCK_STREAM, OS_MAXSTR);
        if (sock < 0) {
            merror(WM_UPGRADE_BIND_SOCK_ERROR, WM_UPGRADE_SOCK_PATH, strerror(errno));
            return NULL;
        }

        wm_agent_upgrade_listen_messages(sock, 5);
    #endif 

    return NULL;
}

void wm_agent_upgrade_destroy(wm_agent_upgrade* upgrade_config) {
    mtinfo(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_MODULE_FINISHED);
    os_free(upgrade_config);

    #ifndef CLIENT
        wm_agent_upgrade_destroy_task_map();
    #endif
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
