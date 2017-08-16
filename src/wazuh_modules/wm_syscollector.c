/*
 * Wazuh Module for System inventory
 * Copyright (C) 2017 Wazuh Inc.
 * March 9, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"

#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>

static wm_sys_t *sys;                           // Pointer to configuration
static int queue_fd;                            // Output queue file descriptor

static void* wm_sys_main(wm_sys_t *sys);        // Module main function. It won't return
static void wm_sys_setup(wm_sys_t *_sys);       // Setup module
static void wm_sys_cleanup();                   // Cleanup function, doesn't overwrite wm_cleanup
static void wm_sys_check();                     // Check configuration, disable flag
static void wm_sys_network();                   // Get network inventory


char* check_dhcp(char *ifa_name, int family);   // Check DHCP status for network interfaces
const char *WM_SYS_LOCATION = "syscollector";   // Location field for event sending

// Syscollector module context definition

const wm_context WM_SYS_CONTEXT = {
    "syscollector",
    (wm_routine)wm_sys_main,
    NULL
};

// Module main function. It won't return

void* wm_sys_main(wm_sys_t *sys) {
    time_t time_start = 0;
    time_t time_sleep = 0;

    // Check configuration and show debug information

    wm_sys_setup(sys);
    mtinfo(WM_SYS_LOGTAG, "Module started.");

    // First sleeping

    if (!sys->flags.scan_on_start) {
        time_start = time(NULL);

        if (sys->state.next_time > time_start) {
            mtinfo(WM_SYS_LOGTAG, "Waiting for turn to evaluate.");
            sleep(sys->state.next_time - time_start);
        }
    }

    // Main loop

    while (1) {
        mtinfo(WM_SYS_LOGTAG, "Starting evaluation.");

        // Get time and execute
        time_start = time(NULL);

        if (sys->flags.network)
            wm_sys_network();

        time_sleep = time(NULL) - time_start;

        mtinfo(WM_SYS_LOGTAG, "Evaluation finished.");

        if ((time_t)sys->interval >= time_sleep) {
            time_sleep = sys->interval - time_sleep;
            sys->state.next_time = sys->interval + time_start;
        } else {
            mterror(WM_SYS_LOGTAG, "Interval overtaken.");
            time_sleep = sys->state.next_time = 0;
        }

        if (wm_state_io(&WM_SYS_CONTEXT, WM_IO_WRITE, &sys->state, sizeof(sys->state)) < 0)
            mterror(WM_SYS_LOGTAG, "Couldn't save running state.");

        // If time_sleep=0, yield CPU
        sleep(time_sleep);
    }

    return NULL;
}

// Setup module

static void wm_sys_setup(wm_sys_t *_sys) {
    int i;

    sys = _sys;
    wm_sys_check();

    // Read running state

    if (wm_state_io(&WM_SYS_CONTEXT, WM_IO_READ, &sys->state, sizeof(sys->state)) < 0)
        memset(&sys->state, 0, sizeof(sys->state));

    // Connect to socket

    for (i = 0; (queue_fd = StartMQ(DEFAULTQPATH, WRITE)) < 0 && i < WM_MAX_ATTEMPTS; i++)
        sleep(WM_MAX_WAIT);

    if (i == WM_MAX_ATTEMPTS) {
        mterror(WM_SYS_LOGTAG, "Can't connect to queue.");
        pthread_exit(NULL);
    }

    // Cleanup exiting

    atexit(wm_sys_cleanup);
}

void wm_sys_cleanup() {
    close(queue_fd);
    mtinfo(WM_SYS_LOGTAG, "Module finished.");
}

// Check configuration

void wm_sys_check() {

    // Check if disabled

    if (!sys->flags.enabled) {
        mterror(WM_SYS_LOGTAG, "Module disabled. Exiting...");
        pthread_exit(NULL);
    }

    // Check if evals

    if (!sys->flags.network) {
        mterror(WM_SYS_LOGTAG, "No assets defined. Exiting...");
        pthread_exit(NULL);
    }

    // Check if interval

    if (!sys->interval)
        sys->interval = WM_SYS_DEF_INTERVAL;
}

// Get network inventory

void wm_sys_network() {

    char ** ifaces_list;
    int i = 0, j = 0, k = 0, found;
    int family;
    struct ifaddrs *ifaddr, *ifa;

    os_calloc(256, sizeof(char *), ifaces_list);

    if (getifaddrs(&ifaddr) == -1) {
        mterror(WM_SYS_LOGTAG, "getifaddrs()");
        return;
    }

    /* Create interfaces list */
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next){
        found = 0;
        for (i=0; i<=j; i++){
            if (!ifaces_list[i]){
                if (!strcmp(ifa->ifa_name, "lo"))
                    found = 1;

                break;

            }else if (!strncmp(ifaces_list[i], ifa->ifa_name, strlen(ifa->ifa_name))){
                    found = 1;
                    break;
            }
        }
        if (!found){
            ifaces_list[j] = malloc(strlen(ifa->ifa_name) + 1);
            strncpy(ifaces_list[j], ifa->ifa_name, strlen(ifa->ifa_name));
            j++;
        }
    }

    /* Collect all information for each interface */
    for (i=0; i<j; i++){

        char *string;

        cJSON *object = cJSON_CreateObject();
        cJSON *interface = cJSON_CreateObject();
        cJSON_AddStringToObject(object, "type", "network");
        cJSON_AddItemToObject(object, "iface", interface);
        cJSON_AddStringToObject(interface, "name", ifaces_list[i]);

        for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {

            if (strncmp(ifaces_list[i], ifa->ifa_name, strlen(ifaces_list[i]))){
                continue;
            }
            if (!ifa->ifa_addr || !strcmp(ifa->ifa_name, "lo")) {
                continue;
            }

            family = ifa->ifa_addr->sa_family;

            if (family == AF_INET) {

                cJSON *ipv4 = cJSON_CreateObject();
                cJSON_AddItemToObject(interface, "IPv4", ipv4);

                char host[NI_MAXHOST];
                int result = getnameinfo(ifa->ifa_addr,
                        sizeof(struct sockaddr_in),
                        host, NI_MAXHOST,
                        NULL, 0, NI_NUMERICHOST);
                if (result == 0) {
                    cJSON_AddStringToObject(ipv4, "address", host);
                } else {
                    mterror(WM_SYS_LOGTAG, "getnameinfo() failed: %s\n", gai_strerror(result));
                }

                char netmask[NI_MAXHOST];
                result = getnameinfo(ifa->ifa_netmask,
                    sizeof(struct sockaddr_in),
                    netmask, NI_MAXHOST,
                    NULL, 0, NI_NUMERICHOST);

                if (result == 0) {
                    cJSON_AddStringToObject(ipv4, "netmask", netmask);
                } else {
                    mterror(WM_SYS_LOGTAG, "getnameinfo() failed: %s\n", gai_strerror(result));
                }

                if (ifa->ifa_ifu.ifu_broadaddr != NULL){
                    if (ifa->ifa_flags & IFF_POINTOPOINT){
                        char dstaddr[NI_MAXHOST];
                        result = getnameinfo(ifa->ifa_ifu.ifu_dstaddr,
                            sizeof(struct sockaddr_in),
                            dstaddr, NI_MAXHOST,
                            NULL, 0, NI_NUMERICHOST);

                        if (result == 0) {
                            cJSON_AddStringToObject(ipv4, "dst_address", dstaddr);
                        } else {
                            mterror(WM_SYS_LOGTAG, "getnameinfo() failed: %s\n", gai_strerror(result));
                        }
                    }else{
                        char broadaddr[NI_MAXHOST];
                        result = getnameinfo(ifa->ifa_ifu.ifu_broadaddr,
                            sizeof(struct sockaddr_in),
                            broadaddr, NI_MAXHOST,
                            NULL, 0, NI_NUMERICHOST);

                        if (result == 0) {
                            cJSON_AddStringToObject(ipv4, "broadcast", broadaddr);
                        } else {
                            mterror(WM_SYS_LOGTAG, "getnameinfo() failed: %s\n", gai_strerror(result));
                        }
                    }
                }

                char *dhcp_status;
                dhcp_status = check_dhcp(ifaces_list[i], family);
                cJSON_AddStringToObject(ipv4, "DHCP", dhcp_status);
                free(dhcp_status);

            } else if (family == AF_INET6) {

                cJSON *ipv6 = cJSON_CreateObject();
                cJSON_AddItemToObject(interface, "IPv6", ipv6);

                char host[NI_MAXHOST];
                int result = getnameinfo(ifa->ifa_addr,
                        sizeof(struct sockaddr_in6),
                        host, NI_MAXHOST,
                        NULL, 0, NI_NUMERICHOST);
                if (result == 0) {
                    char ** parts = NULL;
                    char *ip_addrr;
                    parts = OS_StrBreak('%', host, 2);
                    ip_addrr = w_strtrim(parts[0]);
                    cJSON_AddStringToObject(ipv6, "address", ip_addrr);
                    for (k=0; parts[k]; k++){
                        free(parts[k]);
                    }
                    free(parts);

                    char netmask6[NI_MAXHOST];
                    result = getnameinfo(ifa->ifa_netmask,
                        sizeof(struct sockaddr_in6),
                        netmask6, NI_MAXHOST,
                        NULL, 0, NI_NUMERICHOST);

                    if (result == 0) {
                        cJSON_AddStringToObject(ipv6, "netmask", netmask6);
                    } else {
                        mterror(WM_SYS_LOGTAG, "getnameinfo() failed: %s\n", gai_strerror(result));
                    }

                    if (ifa->ifa_ifu.ifu_broadaddr != NULL){
                        if (ifa->ifa_flags & IFF_POINTOPOINT){
                            char dstaddr6[NI_MAXHOST];
                            result = getnameinfo(ifa->ifa_ifu.ifu_dstaddr,
                                sizeof(struct sockaddr_in6),
                                dstaddr6, NI_MAXHOST,
                                NULL, 0, NI_NUMERICHOST);

                            if (result == 0) {
                                cJSON_AddStringToObject(ipv6, "dst_address", dstaddr6);
                            } else {
                                mterror(WM_SYS_LOGTAG, "getnameinfo() failed: %s\n", gai_strerror(result));
                            }
                        }else{
                            char broadaddr6[NI_MAXHOST];
                            result = getnameinfo(ifa->ifa_ifu.ifu_broadaddr,
                                sizeof(struct sockaddr_in6),
                                broadaddr6, NI_MAXHOST,
                                NULL, 0, NI_NUMERICHOST);

                            if (result == 0) {
                                cJSON_AddStringToObject(ipv6, "broadcast", broadaddr6);
                            } else {
                                mterror(WM_SYS_LOGTAG, "getnameinfo() failed: %s\n", gai_strerror(result));
                            }
                        }
                    }

                    char *dhcp_status;
                    dhcp_status = check_dhcp(ifaces_list[i], family);
                    cJSON_AddStringToObject(ipv6, "DHCP", dhcp_status);
                    free(dhcp_status);

                } else {
                    mterror(WM_SYS_LOGTAG, "getnameinfo() failed: %s\n", gai_strerror(result));
                }

            } else if (family == AF_PACKET && ifa->ifa_data != NULL){

                char mac[18];
                struct rtnl_link_stats *stats = ifa->ifa_data;
                struct sockaddr_ll *addr = (struct sockaddr_ll*)ifa->ifa_addr;
                snprintf(mac, 18, "%02X:%02X:%02X:%02X:%02X:%02X", addr->sll_addr[0], addr->sll_addr[1], addr->sll_addr[2], addr->sll_addr[3], addr->sll_addr[4], addr->sll_addr[5]);
                cJSON_AddStringToObject(interface, "MAC", mac);
                cJSON_AddNumberToObject(interface, "tx_packets", stats->tx_packets);
                cJSON_AddNumberToObject(interface, "rx_packets", stats->rx_packets);
                cJSON_AddNumberToObject(interface, "tx_bytes", stats->tx_bytes);
                cJSON_AddNumberToObject(interface, "rx_bytes", stats->rx_bytes);

            }
        }

        /* Send interface data in JSON format */
        string = cJSON_PrintUnformatted(object);
        mtdebug2(WM_SYS_LOGTAG, "wm_sys_network() sending '%s'", string);
        SendMSG(queue_fd, string, WM_SYS_LOCATION, WODLE_MQ);
        cJSON_Delete(object);

        free(string);
    }

    freeifaddrs(ifaddr);
    free(ifaces_list[i]);

}

/* Check DHCP status for IPv4 and IPv6 addresses in each interface */
char* check_dhcp(char *ifa_name, int family){

    char file[256];
    char file_location[256];
    FILE *fp;
    DIR *dir;
    char string[OS_MAXSTR];
    char start_string[256];
    char * dhcp;
    os_calloc(10, sizeof(char), dhcp);

    snprintf(dhcp, 10, "%s", "unknown");
    snprintf(file_location, 256, "%s", WM_SYS_IF_FILE);

    /* Check DHCP configuration for Debian based systems */
    if ((fp=fopen(file_location, "r"))){

        snprintf(start_string, 256, "%s%s", "iface ", ifa_name);
        while (fgets(string, OS_MAXSTR, fp) != NULL){

            if (strstr(string, start_string) != NULL){

                switch (family){
                    case AF_INET:
                        if (strstr(string, "inet static") || strstr(string, "inet manual")){
                            snprintf(dhcp, 10, "%s", "disabled");
                            return dhcp;
                        }else if (strstr(string, "inet dhcp")){
                            snprintf(dhcp, 10, "%s", "enabled");
                            return dhcp;
                        }else{
                            snprintf(dhcp, 10, "%s", "unknown");
                            return dhcp;
                        }
                        break;
                    case AF_INET6:
                        if (strstr(string, "inet6 static") || strstr(string, "inet6 manual")){
                            snprintf(dhcp, 10, "%s", "disabled");
                            return dhcp;
                        }else if (strstr(string, "inet6 dhcp")){
                            snprintf(dhcp, 10, "%s", "enabled");
                            return dhcp;
                        }else{
                            snprintf(dhcp, 10, "%s", "unknown");
                            return dhcp;
                        }
                        break;

                    default:
                        mtwarn(WM_SYS_LOGTAG, "Unknown DHCP configuration.");
                        break;
                }
            }
        }
        snprintf(dhcp, 10, "%s", "enabled");
        fclose(fp);
    }

    /* Check DHCP configuration for Red Hat based systems */
    snprintf(file, 256, "%s%s", "ifcfg-", ifa_name);
    snprintf(file_location, 256, "%s%s", WM_SYS_IF_DIR, file);

    if ((dir=opendir(WM_SYS_IF_DIR))){
        snprintf(dhcp, 10, "%s", "enabled");
        closedir(dir);
    }

    if ((fp=fopen(file_location, "r"))){

        switch (family){
            case AF_INET:

                snprintf(start_string, 256, "%s", "BOOTPROTO");
                while (fgets(string, OS_MAXSTR, fp) != NULL){

                    if (strstr(string, start_string) != NULL){

                        if (strstr(string, "static") || strstr(string, "none")){
                            snprintf(dhcp, 10, "%s", "disabled");
                            return dhcp;
                        }else if (strstr(string, "bootp")){
                            snprintf(dhcp, 10, "%s", "BOOTP");
                            return dhcp;
                        }else if (strstr(string, "dhcp")){
                            snprintf(dhcp, 10, "%s", "enabled");
                            return dhcp;
                        }else{
                            snprintf(dhcp, 10, "%s", "unknown");
                            return dhcp;
                        }
                    }
                }
                break;

            case AF_INET6:

                snprintf(start_string, 256, "%s", "DHCPV6C");
                while (fgets(string, OS_MAXSTR, fp) != NULL){

                    if (strstr(string, start_string) != NULL){
                        if (strstr(string, "no")){
                            snprintf(dhcp, 10, "%s", "disabled");
                            return dhcp;
                        }else if (strstr(string, "yes")){
                            snprintf(dhcp, 10, "%s", "enabled");
                            return dhcp;
                        }else {
                            snprintf(dhcp, 10, "%s", "unknown");
                            return dhcp;
                        }
                    }
                }
                break;

            default:
                mtwarn(WM_SYS_LOGTAG, "Unknown DHCP configuration.");
                break;
        }
        fclose(fp);
    }

    return dhcp;
}
