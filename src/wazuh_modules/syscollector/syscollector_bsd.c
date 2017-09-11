/*
 * Wazuh Module for System inventory for Linux
 * Copyright (C) 2017 Wazuh Inc.
 * Sep, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include "syscollector.h"

#if defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_types.h>
#include <ifaddrs.h>
#include <string.h>

// Get network inventory

void sys_network_bsd(int queue_fd, const char* LOCATION){

    char ** ifaces_list;
    int i = 0, j = 0, found;
    struct ifaddrs *ifaddrs_ptr, *ifa;
    int family;

    mtinfo(WM_SYS_LOGTAG, "Starting network inventory.");

    if (getifaddrs(&ifaddrs_ptr) == -1){
        mterror(WM_SYS_LOGTAG, "getifaddrs() failed.");
        return;
    }

    for (ifa = ifaddrs_ptr; ifa; ifa = ifa->ifa_next){
        i++;
    }
    os_calloc(i, sizeof(char *), ifaces_list);

    /* Create interfaces list */
    for (ifa = ifaddrs_ptr; ifa; ifa = ifa->ifa_next){
        found = 0;
        for (i=0; i<=j; i++){
            if (!ifaces_list[i]){
                if (ifa->ifa_flags & IFF_LOOPBACK)
                    found = 1;

                break;

            }else if (!strcmp(ifaces_list[i], ifa->ifa_name)){
                    found = 1;
                    break;
            }
        }
        if (!found){

            ifaces_list[j] = strdup(ifa->ifa_name);
            j++;
        }
    }

    if(!ifaces_list[j-1]){
        mterror(WM_SYS_LOGTAG, "Not found any interface. Network inventory suspended.");
        return;
    }

    for (i=0; i<j; i++){

        char *string;

        cJSON *object = cJSON_CreateObject();
        cJSON *interface = cJSON_CreateObject();
        cJSON_AddStringToObject(object, "type", "network");
        cJSON_AddItemToObject(object, "iface", interface);
        cJSON_AddStringToObject(interface, "name", ifaces_list[i]);

        for (ifa = ifaddrs_ptr; ifa; ifa = ifa->ifa_next){

            if (strcmp(ifaces_list[i], ifa->ifa_name)){
                continue;
            }
            if (ifa->ifa_flags & IFF_LOOPBACK) {
                continue;
            }

            family = ifa->ifa_addr->sa_family;

            if (family == AF_INET){

                cJSON *ipv4 = cJSON_CreateObject();
                cJSON_AddItemToObject(interface, "IPv4", ipv4);

                if (ifa->ifa_addr){

                    void * addr_ptr;
                    /* IPv4 Address */

                    addr_ptr = &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;

                    char host[NI_MAXHOST];
                    inet_ntop(ifa->ifa_addr->sa_family,
                            addr_ptr,
                            host,
                            sizeof (host));

                    cJSON_AddStringToObject(ipv4, "address", host);

                    /* Netmask Address */
                    addr_ptr = &((struct sockaddr_in *) ifa->ifa_netmask)->sin_addr;

                    char netmask[NI_MAXHOST];
                    inet_ntop(ifa->ifa_netmask->sa_family,
                            addr_ptr,
                            netmask,
                            sizeof (netmask));

                    cJSON_AddStringToObject(ipv4, "netmask", netmask);

                    /* Broadcast Address */
                    addr_ptr = &((struct sockaddr_in *) ifa->ifa_dstaddr)->sin_addr;

                    char broadaddr[NI_MAXHOST];
                    inet_ntop(ifa->ifa_dstaddr->sa_family,
                            addr_ptr,
                            broadaddr,
                            sizeof (broadaddr));

                    cJSON_AddStringToObject(ipv4, "broadcast", broadaddr);

                    /* No DHCP state is collected in BSD */
                    cJSON_AddStringToObject(ipv4, "DHCP", "unknown");
                }

            } else if (family == AF_INET6){

                cJSON *ipv6 = cJSON_CreateObject();
                cJSON_AddItemToObject(interface, "IPv6", ipv6);

                if (ifa->ifa_addr){

                    void * addr_ptr;

                    /* IPv6 Address */
                    addr_ptr = &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr;

                    char host[NI_MAXHOST];
                    inet_ntop(ifa->ifa_addr->sa_family,
                            addr_ptr,
                            host,
                            sizeof (host));

                    cJSON_AddStringToObject(ipv6, "address", host);

                    /* Netmask address */
                    if (ifa->ifa_netmask){
                        addr_ptr = &((struct sockaddr_in6 *) ifa->ifa_netmask)->sin6_addr;

                        char netmask6[NI_MAXHOST];
                        inet_ntop(ifa->ifa_netmask->sa_family,
                                addr_ptr,
                                netmask6,
                                sizeof (netmask6));

                        cJSON_AddStringToObject(ipv6, "netmask", netmask6);
                    }

                    /* Broadcast address */
                    if (ifa->ifa_dstaddr){
                        addr_ptr = &((struct sockaddr_in6 *) ifa->ifa_dstaddr)->sin6_addr;

                        char broadaddr6[NI_MAXHOST];
                        inet_ntop(ifa->ifa_dstaddr->sa_family,
                                addr_ptr,
                                broadaddr6,
                                sizeof (broadaddr6));

                        cJSON_AddStringToObject(ipv6, "broadcast", broadaddr6);
                    }

                    /* No DHCP state is collected in BSD */
                    cJSON_AddStringToObject(ipv6, "DHCP", "unknown");
                }

            } else if (family == AF_LINK && ifa->ifa_data != NULL){

                char * type;
                char * state;

                struct sockaddr_dl * sdl;
                sdl = (struct sockaddr_dl *) ifa->ifa_addr;

                os_calloc(TYPE_LENGTH + 1, sizeof(char), type);
                snprintf(type, TYPE_LENGTH, "%s", "unknown");

                /* IF Type */
                if (sdl->sdl_type == IFT_ETHER){
                    snprintf(type, TYPE_LENGTH, "%s", "ethernet");
                }else if (sdl->sdl_type == IFT_ISO88023){
                    snprintf(type, TYPE_LENGTH, "%s", "CSMA/CD");
                }else if (sdl->sdl_type == IFT_ISO88024 || sdl->sdl_type == IFT_ISO88025){
                    snprintf(type, TYPE_LENGTH, "%s", "token ring");
                }else if (sdl->sdl_type == IFT_FDDI){
                    snprintf(type, TYPE_LENGTH, "%s", "FDDI");
                }else if (sdl->sdl_type == IFT_PPP){
                    snprintf(type, TYPE_LENGTH, "%s", "point-to-point");
                }else if (sdl->sdl_type == IFT_ATM){
                    snprintf(type, TYPE_LENGTH, "%s", "ATM");
                }else{
                    snprintf(type, TYPE_LENGTH, "%s", "unknown");
                }

                cJSON_AddStringToObject(interface, "type", type);
                free(type);

                os_calloc(STATE_LENGTH + 1, sizeof(char), state);

                /* Oper status based on flags */
                if (ifa->ifa_flags & IFF_UP){
                    snprintf(state, STATE_LENGTH, "%s", "up");
                }else{
                    snprintf(state, STATE_LENGTH, "%s", "down");
                }
                cJSON_AddStringToObject(interface, "state", state);
                free(state);

                /* MAC address */
                char MAC[MAC_LENGTH] = "";
                char *mac_addr = &MAC[0];
                int mac_offset;

                for (mac_offset = 0; mac_offset < 6; mac_offset++){
                    unsigned char byte;
                    byte = (unsigned char)(LLADDR(sdl)[mac_offset]);
                    mac_addr += sprintf(mac_addr, "%.2X", byte);
                    if (mac_offset != 5){
                        mac_addr += sprintf(mac_addr, "%c", ':');
                    }
                }
                cJSON_AddStringToObject(interface, "MAC", MAC);

                /* Stats and other information */
                struct if_data *stats = ifa->ifa_data;
                cJSON_AddNumberToObject(interface, "tx_packets", stats->ifi_opackets);
                cJSON_AddNumberToObject(interface, "rx_packets", stats->ifi_ipackets);
                cJSON_AddNumberToObject(interface, "tx_bytes", stats->ifi_obytes);
                cJSON_AddNumberToObject(interface, "rx_bytes", stats->ifi_ibytes);

                cJSON_AddNumberToObject(interface, "MTU", stats->ifi_mtu);

            }
        }

        /* Send interface data in JSON format */
        string = cJSON_PrintUnformatted(object);
        mtdebug2(WM_SYS_LOGTAG, "sys_network_bsd() sending '%s'", string);
        SendMSG(queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
        cJSON_Delete(object);
        free(string);
    }

    freeifaddrs(ifaddrs_ptr);
    for (i=0; ifaces_list[i]; i++){
        free(ifaces_list[i]);
    }
    free(ifaces_list);

}

#endif /* __BSD__ */
