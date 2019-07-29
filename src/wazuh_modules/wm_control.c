/*
 * Wazuh Module for Agent control
 * Copyright (C) 2015-2019, Wazuh Inc.
 * January, 2019
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef CLIENT
#if defined (__linux__) || defined (__MACH__)
#include "wm_control.h"
#include "syscollector/syscollector.h"
#include "external/cJSON/cJSON.h"
#include "file_op.h"
#include "../os_net/os_net.h"
#include <ifaddrs.h>

static void *wm_control_main();
static void wm_control_destroy();
cJSON *wm_control_dump(void);

const wm_context WM_CONTROL_CONTEXT = {
    "control",
    (wm_routine)wm_control_main,
    (wm_routine)wm_control_destroy,
    (cJSON * (*)(const void *))wm_control_dump
};

#ifdef __MACH__
static void freegate(gateway *gate){
    os_free(gate->addr);
    os_free(gate);
}
#endif

char* getPrimaryIP(){
     /* Get Primary IP */
    char * agent_ip = NULL;
    char **ifaces_list;
    struct ifaddrs *ifaddr = NULL, *ifa;
    int size;
    int i = 0;
#ifdef __linux__
    int min_metric = INT_MAX;
#endif

    if (getifaddrs(&ifaddr) == -1) {
        if (ifaddr) {
            freeifaddrs(ifaddr);
        }
        mterror(WM_CONTROL_LOGTAG, "at getPrimaryIP(): getifaddrs() failed.");
        return agent_ip;
    }

    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next){
        i++;
    }

    if(i == 0){
        mtdebug1(WM_CONTROL_LOGTAG, "No network interfaces found when reading agent IP.");
        return agent_ip;
    }

    os_calloc(i, sizeof(char *), ifaces_list);

    /* Create interfaces list */
    size = getIfaceslist(ifaces_list, ifaddr);

    if(!ifaces_list[0]){
        mtdebug1(WM_CONTROL_LOGTAG, "No network interfaces found when reading agent IP.");
        os_free(ifaces_list);
        freeifaddrs(ifaddr);
        return agent_ip;
    }

#ifdef __MACH__
    OSHash *gateways = OSHash_Create();
    OSHash_SetFreeDataPointer(gateways, (void (*)(void *)) freegate);
    if (getGatewayList(gateways) < 0){
        mtdebug1(WM_CONTROL_LOGTAG, "Unable to obtain the Default Gateway list");
        OSHash_Free(gateways);
        os_free(ifaces_list);
        freeifaddrs(ifaddr);
        return agent_ip;
    }
    gateway *gate;
#endif

    for (i=0; i<size; i++) {
        cJSON *object = cJSON_CreateObject();
#ifdef __linux__
        getNetworkIface_linux(object, ifaces_list[i], ifaddr);
#elif defined __MACH__
        if(gate = OSHash_Get(gateways, ifaces_list[i]), gate){
            if(!gate->isdefault){
                cJSON_Delete(object);
                continue;
            }
            if(gate->addr[0]=='l'){
                cJSON_Delete(object);
                continue;
            }
            getNetworkIface_bsd(object, ifaces_list[i], ifaddr, gate);
        }
#endif
        cJSON *interface = cJSON_GetObjectItem(object, "iface");
        cJSON *ipv4 = cJSON_GetObjectItem(interface, "IPv4");
        if(ipv4){
#ifdef __linux__
            cJSON * gateway = cJSON_GetObjectItem(ipv4, "gateway");
            if (gateway) {
                cJSON * metric = cJSON_GetObjectItem(ipv4, "metric");
                if (metric && metric->valueint < min_metric) {
                    cJSON *addresses = cJSON_GetObjectItem(ipv4, "address");
                    cJSON *address = cJSON_GetArrayItem(addresses,0);
                    if(agent_ip != NULL){
                        free(agent_ip);
                    }
                    os_strdup(address->valuestring, agent_ip);
                    min_metric = metric->valueint;
                }
            }
#elif defined __MACH__
            cJSON *addresses = cJSON_GetObjectItem(ipv4, "address");
            cJSON *address = cJSON_GetArrayItem(addresses,0);
            os_strdup(address->valuestring, agent_ip);
            cJSON_Delete(object);
            break;
#endif

        }
        cJSON_Delete(object);
    }
#if defined __MACH__
    OSHash_Free(gateways);
#endif

    freeifaddrs(ifaddr);
    for (i=0; ifaces_list[i]; i++){
        free(ifaces_list[i]);
    }

    free(ifaces_list);

    return agent_ip;
}


void *wm_control_main(){

    mtinfo(WM_CONTROL_LOGTAG, "Starting control thread.");

    send_ip();

    return NULL;
}

void wm_control_destroy(){}

wmodule *wm_control_read(){
    wmodule * module;

    os_calloc(1, sizeof(wmodule), module);
    module->context = &WM_CONTROL_CONTEXT;
    module->tag = strdup(module->context->name);

    return module;
}

cJSON *wm_control_dump(void) {
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

    if (sock = OS_BindUnixDomain(DEFAULTDIR CONTROL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
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
#endif
