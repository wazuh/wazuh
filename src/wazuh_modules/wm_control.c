/*
 * Wazuh Module for Agent control
 * Copyright (C) 2015-2020, Wazuh Inc.
 * January, 2019
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#if defined (__linux__) || defined (__MACH__) || defined (sun)
#include "wm_control.h"
#include "syscollector/syscollector.h"
#include "external/cJSON/cJSON.h"
#include "file_op.h"
#include "../os_net/os_net.h"

static void *wm_control_main();
static void wm_control_destroy();
cJSON *wm_control_dump();

const wm_context WM_CONTROL_CONTEXT = {
    "control",
    (wm_routine)wm_control_main,
    (wm_routine)(void *)wm_control_destroy,
    (cJSON * (*)(const void *))wm_control_dump
};

#if defined (__linux__) || defined (__MACH__)
#include <ifaddrs.h>
#elif defined sun
#include <net/if.h>
#include <sys/sockio.h>

/**
 * @brief Get the number of available network interfaces
 *
 * @return Number of network interfaces in the system.
 */
static int get_if_num() {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd == -1) {
        return -1;
    }

    struct lifnum ifn = { .lifn_family = AF_INET };

    int retval = ioctl(fd, SIOCGLIFNUM, &ifn);
    close(fd);

    if (retval == -1) {
        return -1;
    }

    return ifn.lifn_count;
}

#endif

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

#if defined __linux__ || defined __MACH__
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

#elif defined sun

    // Get number of interfaces

    int if_count = get_if_num();

    if (if_count == -1) {
        return NULL;
    }

    // Initialize configuration structure

    struct lifconf if_conf = { .lifc_family = AF_INET, .lifc_len = if_count * sizeof(struct lifreq) };
    if_conf.lifc_buf = malloc(if_conf.lifc_len);
    assert(if_conf.lifc_buf != NULL);

    // Create helper socket

    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd == -1) {
        goto end;
    }

    // Get interfaces

    if (ioctl(fd, SIOCGLIFCONF, &if_conf) == -1) {
        goto end;
    }

    // Scan interfaces

    int i;
    for (i = 0; i < if_count; i++) {
        struct lifreq * if_req = if_conf.lifc_req + i;

        // Get flags

        if (ioctl(fd, SIOCGLIFFLAGS, if_req) == -1) {
            goto end;
        }

        // Get the first interface that is up and is not loopback

        int flags = if_req->lifr_flags;

        if ((flags & IFF_UP) && (flags & IFF_LOOPBACK) == 0) {
            // Get IP address

            if (ioctl(fd, SIOCGLIFADDR, if_req) == -1) {
                goto end;
            }

            struct sockaddr_in * addr = (struct sockaddr_in *)&if_req->lifr_addr;
            agent_ip = strdup(inet_ntoa(addr->sin_addr));
            break;
        }
    }

end:
    if (fd != -1) {
        close(fd);
    }

    free(if_conf.lifc_buf);
#endif

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
