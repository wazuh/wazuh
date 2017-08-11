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

 #include <sys/types.h>
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

    char *ifaces_list[256];
    int i = 0, j = 0, found;
    char *key;
    int family;
    struct ifaddrs *ifaddr, *ifa;

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

    /* Collect all data for each interface */
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

            switch (family) {
                case AF_INET:
                    key = "IPv4";
                    break;
                case AF_INET6:
                    key = "IPv6";
                    break;
                case AF_PACKET:
                    key = "MAC";
                    break;
                default:
                    mtdebug1(WM_SYS_LOGTAG, "Unknown family (%d).", family);
                    continue;
            }

            if (family == AF_INET || family == AF_INET6) {
                char host[NI_MAXHOST];
                int result = getnameinfo(ifa->ifa_addr,
                        (family == AF_INET) ? sizeof(struct sockaddr_in) :
                                             sizeof(struct sockaddr_in6),
                        host, NI_MAXHOST,
                        NULL, 0, NI_NUMERICHOST);
                if (result == 0) {
                    cJSON_AddStringToObject(interface, key, host);
                    char *dhcp_status;
                    dhcp_status = check_dhcp(ifaces_list[i], family);
                    if (family == AF_INET){
                        cJSON_AddStringToObject(interface, "DHCP IPv4", dhcp_status);

                    }else if (family == AF_INET6){
                        cJSON_AddStringToObject(interface, "DHCP IPv6", dhcp_status);
                    }
                    free(dhcp_status);

                } else {
                    mterror(WM_SYS_LOGTAG, "getnameinfo() failed: %s\n", gai_strerror(result));
                }
            } else if (family == AF_PACKET && ifa->ifa_data != NULL) {
                char mac[18];
                struct rtnl_link_stats *stats = ifa->ifa_data;
                struct sockaddr_ll *addr = (struct sockaddr_ll*)ifa->ifa_addr;
                snprintf(mac, 18, "%02X:%02X:%02X:%02X:%02X:%02X", addr->sll_addr[0], addr->sll_addr[1], addr->sll_addr[2], addr->sll_addr[3], addr->sll_addr[4], addr->sll_addr[5]);
                cJSON_AddStringToObject(interface, key, mac);
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

    char file_location[256];
    FILE *fp;
    char string[OS_MAXSTR];
    char start_string[256];
    char *dhcp = (char*)malloc(10);

    snprintf(dhcp, 256, "%s", "unknown");
    snprintf(file_location, 256, "%s", WM_SYS_IF_FILE);
    snprintf(start_string, 256, "%s%s", "iface ", ifa_name);

    if((fp=fopen(file_location, "r"))){

        while(fgets(string, OS_MAXSTR, fp) != NULL){

            if(strstr(string, start_string) != NULL){

                switch (family){
                    case AF_INET:
                        if(strstr(string, "inet static") || strstr(string, "inet manual")){
                            snprintf(dhcp, 256, "%s", "disabled");
                            return dhcp;
                        }else if(strstr(string, "inet dhcp")){
                            snprintf(dhcp, 256, "%s", "enabled");
                            return dhcp;
                        }else{
                            snprintf(dhcp, 256, "%s", "enabled");
                            return dhcp;
                        }
                        break;
                    case AF_INET6:
                        if(strstr(string, "inet6 static") || strstr(string, "inet6 manual")){
                            snprintf(dhcp, 256, "%s", "disabled");
                            return dhcp;
                        }else if(strstr(string, "inet6 dhcp")){
                            snprintf(dhcp, 256, "%s", "enabled");
                            return dhcp;
                        }else{
                            snprintf(dhcp, 256, "%s", "enabled");
                            return dhcp;
                        }
                        break;
                }
            }
        }
        snprintf(dhcp, 256, "%s", "enabled");
        fclose(fp);
    }
    return dhcp;
}
