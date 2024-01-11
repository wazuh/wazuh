/*
 * Wazuh Module for Agent control
 * Copyright (C) 2015, Wazuh Inc.
 * January, 2019
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

#if defined (__linux__) || defined (__MACH__) || defined (sun) || defined(FreeBSD) || defined(OpenBSD)
#include "wm_control.h"
#include "sysInfo.h"
#include "sym_load.h"
#include "external/cJSON/cJSON.h"
#include "file_op.h"
#include "../os_net/os_net.h"
static void *wm_control_main();
static void wm_control_destroy();
cJSON *wm_control_dump();

const wm_context WM_CONTROL_CONTEXT = {
    .name = "control",
    .start = (wm_routine)wm_control_main,
    .destroy = (void(*)(void *))wm_control_destroy,
    .dump = (cJSON * (*)(const void *))wm_control_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};
STATIC void *sysinfo_module = NULL;
STATIC sysinfo_networks_func sysinfo_network_ptr = NULL;
STATIC sysinfo_free_result_func sysinfo_free_result_ptr = NULL;

/**
 * @brief Get the Primary IP address
 *
 * Resolve the host's IP as the IP address of the default route interface,
 * or the first non-loopback available interface.
 *
 * @return Pointer to a string holding the host's IP.
 * @post The user must free the returned pointer.
 */
char* getPrimaryIP(){
     /* Get Primary IP */
    char * agent_ip = NULL;

#if defined __linux__ || defined __MACH__ || defined(FreeBSD) || defined(OpenBSD) || defined(sun)
    cJSON *object;
    if (sysinfo_network_ptr && sysinfo_free_result_ptr) {
        const int error_code = sysinfo_network_ptr(&object);
        if (error_code == 0) {
            if (object) {
                const cJSON *iface = cJSON_GetObjectItem(object, "iface");
                if (iface) {
                    const int size_ids = cJSON_GetArraySize(iface);
                    for (int i = 0; i < size_ids; i++){
                        const cJSON *element = cJSON_GetArrayItem(iface, i);
                        if(!element) {
                            continue;
                        }
                        cJSON *gateway = cJSON_GetObjectItem(element, "gateway");
                        if (gateway && cJSON_GetStringValue(gateway) && 0 != strcmp(gateway->valuestring," ")) {

                            const char * primaryIpType = NULL;
                            const char * secondaryIpType = NULL;

                            if (strchr(gateway->valuestring, ':') != NULL) {
                                //Assume gateway is IPv6. IPv6 IP will be prioritary
                                primaryIpType = "IPv6";
                                secondaryIpType = "IPv4";
                            } else {
                                //Assume gateway is IPv4. IPv4 IP will be prioritary
                                primaryIpType = "IPv4";
                                secondaryIpType = "IPv6";
                            }

                            const cJSON * ip = cJSON_GetObjectItem(element, primaryIpType);
                            if (NULL == ip) {
                                ip = cJSON_GetObjectItem(element, secondaryIpType);
                                if (NULL == ip) {
                                    continue;
                                }
                            }
                            const int size_proto_interfaces = cJSON_GetArraySize(ip);
                            for (int j = 0; j < size_proto_interfaces; ++j) {
                                const cJSON *element_ip = cJSON_GetArrayItem(ip, j);
                                if(!element_ip) {
                                    continue;
                                }
                                cJSON *address = cJSON_GetObjectItem(element_ip, "address");
                                if (address && cJSON_GetStringValue(address))
                                {
                                    os_strdup(address->valuestring, agent_ip);
                                    break;
                                }
                            }
                            if (agent_ip) {
                                break;
                            }
                        }
                    }
                }
                sysinfo_free_result_ptr(&object);
            }
        }
        else {
            mterror(WM_CONTROL_LOGTAG, "Unable to get system network information. Error code: %d.", error_code);
        }
    }

#endif

    if (agent_ip && (strchr(agent_ip, ':') != NULL)) {
        os_realloc(agent_ip, IPSIZE + 1, agent_ip);
        OS_ExpandIPv6(agent_ip, IPSIZE);
    }

    return agent_ip;
}


void *wm_control_main(){
    mtinfo(WM_CONTROL_LOGTAG, "Starting control thread.");
    if (sysinfo_module = so_get_module_handle("sysinfo"), sysinfo_module)
    {
        sysinfo_free_result_ptr = so_get_function_sym(sysinfo_module, "sysinfo_free_result");
        sysinfo_network_ptr = so_get_function_sym(sysinfo_module, "sysinfo_networks");
    }

    send_ip();

    return NULL;
}

void wm_control_destroy(){
    if (sysinfo_module){
        so_free_library(sysinfo_module);
    }
}

wmodule *wm_control_read(){
    wmodule * module;

    os_calloc(1, sizeof(wmodule), module);
    module->context = &WM_CONTROL_CONTEXT;
    module->tag = strdup(module->context->name);

    return module;
}

cJSON *wm_control_dump() {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();
    cJSON_AddStringToObject(wm_wd,"enabled","yes");
    cJSON_AddItemToObject(root,"wazuh_control",wm_wd);
    return root;
}

void *send_ip(){
    int sock;
    int peer;
    char *buffer = NULL;
    char *response = NULL;
    ssize_t length;
    fd_set fdset;

    if (sock = OS_BindUnixDomainWithPerms(CONTROL_SOCK, SOCK_STREAM, OS_MAXSTR, getuid(), wm_getGroupID(), 0660), sock < 0) {
        mterror(WM_CONTROL_LOGTAG, "Unable to bind to socket '%s': (%d) %s.", CONTROL_SOCK, errno, strerror(errno));
        return NULL;
    }

    while (1) {

        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, NULL)) {
        case -1:
            if (errno != EINTR) {
                mterror_exit(WM_CONTROL_LOGTAG, "At send_ip(): select(): %s", strerror(errno));
            }

            continue;

        case 0:
            continue;
        }

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                mterror(WM_CONTROL_LOGTAG, "At send_ip(): accept(): %s", strerror(errno));
            }

            continue;
        }

        os_calloc(IPSIZE + 1, sizeof(char), buffer);
        switch (length = OS_RecvUnix(peer, IPSIZE, buffer), length) {
        case -1:
            mterror(WM_CONTROL_LOGTAG, "At send_ip(): OS_RecvUnix(): %s", strerror(errno));
            break;

        case 0:
            mtinfo(WM_CONTROL_LOGTAG, "Empty message from local client.");
            close(peer);
            break;

        case OS_MAXLEN:
            mterror(WM_CONTROL_LOGTAG, "Received message > %i", MAX_DYN_STR);
            close(peer);
            break;

        default:
            response = getPrimaryIP();
            if(response){
                OS_SendUnix(peer, response, 0);
                free(response);
            }
            else{
                OS_SendUnix(peer,"Err",4);
            }
            close(peer);
        }
        free(buffer);
    }

    close(sock);
    return NULL;
}

#endif
