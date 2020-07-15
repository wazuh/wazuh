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

#include "wm_agent_upgrade.h"
#include "os_net/os_net.h"

/**
 * Module main function. It won't return
 * */
static void* wm_agent_upgrade_main(wm_agent_upgrade* upgrade_config);    
static void wm_agent_upgrade_destroy(wm_agent_upgrade* upgrade_config);  
cJSON *wm_agent_upgrade_dump(const wm_agent_upgrade* upgrade_config);

/**
 * Start listening loop, exits only on error 
 * @param socket to listen to
 * @param timeout_sec timeout in seconds
 * @param return only on errors, socket will be closed
 * */
static void wm_agent_listen_messages(int sock, int timeout_sec);

/* Context definition */
const wm_context WM_AGENT_UPGRADE_CONTEXT = {
    AGENT_UPGRADE_WM_NAME,
    (wm_routine)wm_agent_upgrade_main,
    (wm_routine)(void *)wm_agent_upgrade_destroy,
    (cJSON * (*)(const void *))wm_agent_upgrade_dump
};

void * wm_agent_upgrade_main(wm_agent_upgrade* upgrade_config) {
    mtinfo(WM_AGENT_UPGRADE_LOGTAG, "Module AgentUpgrade started");

    // Initialize task hashmap
    wm_agent_init_task_map();

    int sock = OS_BindUnixDomain(WM_UPGRADE_SOCK_PATH, SOCK_STREAM, OS_MAXSTR);
    if (sock < 0) {
        merror("Unable to bind to socket '%s': %s", WM_UPGRADE_SOCK_PATH, strerror(errno));
        return NULL;
    }

    wm_agent_listen_messages(sock, 5);
    return NULL;
}

void wm_agent_listen_messages(int sock, int timeout_sec) {
    struct timeval timeout = { timeout_sec, 0 };

    while(1) {
        // listen - wait connection
        fd_set fdset;    
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, &timeout)) {
        case -1:
            if (errno != EINTR) {
                merror("select(): %s", strerror(errno));
                close(sock);
                return;
            }
            continue;
        case 0:
            continue;
        }

        //Accept 
        int peer;
        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                merror("accept(): %s", strerror(errno));
            }
            continue;
        }
        
        // Get request string
        
        char *buffer = NULL;
        cJSON* json_response = NULL;
        os_calloc(OS_MAXSTR, sizeof(char), buffer);
        int length;
        switch (length = OS_RecvTCPBuffer(peer, buffer,OS_MAXSTR), length) {
        case OS_SOCKTERR:
            mterror(WM_AGENT_UPGRADE_LOGTAG, "OS_RecvSecureTCP(): Too big message size received from an internal component.");
            break;
        case -1:
            mterror(WM_AGENT_UPGRADE_LOGTAG, "OS_RecvSecureTCP(): %s", strerror(errno));
            break;
        case 0:
            mtdebug1(WM_AGENT_UPGRADE_LOGTAG, "Empty message from local client.");
            break;
        default:
            /* Correctly received message */
            json_response = wm_agent_parse_command(&buffer[0]);
            if (json_response) {
                OS_SendTCP(peer, cJSON_Print(json_response));
                cJSON_Delete(json_response);
            }
            break;
        }
        if (json_response) {
            cJSON_Delete(json_response);
        }
        free(buffer);
        close(peer);
    }
}

void wm_agent_upgrade_destroy(wm_agent_upgrade* upgrade_config) {
    mtinfo(WM_AGENT_UPGRADE_LOGTAG, "Module AgentUpgrade finished");
    os_free(upgrade_config);

    wm_agent_destroy_task_map();
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
