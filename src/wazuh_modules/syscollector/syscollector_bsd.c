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

#if defined(__MACH__) || defined(__FreeBSD__)

#include "syscollector.h"

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

    struct ifaddrs *ifaddrs_ptr, *ifa;
    int family;
    int flag_new = 1;

    cJSON *object;
    cJSON *interface;
    cJSON *ipv4;
    cJSON *ipv6;

    mtinfo(WM_SYS_LOGTAG, "Starting network inventory.");

    if (getifaddrs(&ifaddrs_ptr) == -1){
        mterror(WM_SYS_LOGTAG, "getifaddrs() failed.");
        return;
    }

    char * iface_name;
    os_calloc(OS_MAXSTR, sizeof(char), iface_name);

    for (ifa = ifaddrs_ptr; ifa; ifa = ifa->ifa_next){

        if (ifa->ifa_flags & IFF_LOOPBACK){
            continue;
        }

        if (flag_new){

            snprintf(iface_name, OS_MAXSTR, "%s", ifa->ifa_name);

            object = cJSON_CreateObject();
            interface = cJSON_CreateObject();
            cJSON_AddStringToObject(object, "type", "network");
            cJSON_AddItemToObject(object, "iface", interface);
            cJSON_AddStringToObject(interface, "name", ifa->ifa_name);

            flag_new = 0;
        }

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET){

            ipv4 = cJSON_CreateObject();

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
            }

        } else if (family == AF_INET6){

            ipv6 = cJSON_CreateObject();

            if (!ifa->ifa_addr){

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

        }else {
            mtwarn(WM_SYS_LOGTAG, "Unknown family interface: %d", family);
        }

        if (strcmp(iface_name, ifa->ifa_next->ifa_name)){
            /* Send interface data in JSON format */
            char * string;
            if (ipv4 != NULL)
                cJSON_AddItemToObject(interface, "IPv4", ipv4);

            if (ipv6 != NULL)
                cJSON_AddItemToObject(interface, "IPv6", ipv6);

            string = cJSON_PrintUnformatted(object);
            mtdebug2(WM_SYS_LOGTAG, "sys_network_linux() sending '%s'", string);
            SendMSG(queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
            cJSON_Delete(object);
            free(string);
            flag_new = 1;
        }

    }

    freeifaddrs(ifaddrs_ptr);

}

#endif /* __BSD__ */
