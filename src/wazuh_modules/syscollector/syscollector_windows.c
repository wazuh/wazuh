/*
 * Wazuh Module for System inventory for Windows
 * Copyright (C) 2017 Wazuh Inc.
 * 23 Aug, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#define _WIN32_WINNT 0x600  // Windows Vista or later

#include "syscollector.h"
#include "shared.h"

#include <netioapi.h>
#include <iphlpapi.h>

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

char* length_to_ipv6_mask(int mask_length);
char* get_broadcast_addr(char* ip, char* netmask);

void sys_hw_windows(const char* LOCATION){

    char *string;

    char *command;
    char *end;
    FILE *output;
    size_t buf_length = 1024;
    char read_buff[buf_length];

    cJSON *object = cJSON_CreateObject();
    cJSON *hw_inventory = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "hardware");
    cJSON_AddItemToObject(object, "inventory", hw_inventory);

    /* Serial number from wmi */
    char *serial;
    memset(read_buff, 0, buf_length);
    command = "wmic baseboard get SerialNumber";
    output = popen(command, "r");
    if (!output){
        mterror(WM_SYS_LOGTAG, "Unable to get Motherboard Serial Number.");
    }else{
        if (strncmp(fgets(read_buff, buf_length, output),"SerialNumber", 12) == 0) {
            if (!fgets(read_buff, buf_length, output)){
                mterror(WM_SYS_LOGTAG, "Unable to get Motherboard Serial Number.");
                serial = strdup("unknown");
            }
            else if (end = strpbrk(read_buff,"\r\n"), end) {
                *end = '\0';
                int i = strlen(read_buff) - 1;
                while(read_buff[i] == 32){  // Review
                    read_buff[i] = '\0';
                    i--;
                }
                serial = strdup(read_buff);
            }else
                serial = strdup("unknown");
        }
    }
    pclose(output);

    cJSON_AddStringToObject(hw_inventory, "board_number", serial);
    free(serial);

    /* Send interface data in JSON format */
    string = cJSON_PrintUnformatted(object);
    mtdebug2(WM_SYS_LOGTAG, "sys_hw_windows() sending '%s'", string);
    SendMSG(0, string, LOCATION, WODLE_MQ);
    cJSON_Delete(object);

    free(string);
}

void sys_os_windows(const char* LOCATION){

    char *string;

    cJSON *object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "OS");

    cJSON *os_inventory = getunameJSON();

    cJSON_AddItemToObject(object, "inventory", os_inventory);

    /* Send interface data in JSON format */
    string = cJSON_PrintUnformatted(object);
    mtdebug2(WM_SYS_LOGTAG, "sys_os_windows() sending '%s'", string);
    SendMSG(0, string, LOCATION, WODLE_MQ);
    cJSON_Delete(object);

    free(string);
}


void sys_network_windows(const char* LOCATION){

    /* Declare and initialize variables */

    DWORD dwRetVal = 0;

    unsigned int i = 0;

    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;

    char host[NI_MAXHOST];
    char ipv4addr[NI_MAXHOST];

    // Set the flags to pass to GetAdaptersAddresses
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;

    LPVOID lpMsgBuf = NULL;

    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG outBufLen = 0;
    ULONG Iterations = 0;

    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
    PIP_ADAPTER_GATEWAY_ADDRESS_LH pGateway = NULL;

    // Allocate a 15 KB buffer to start with.
    outBufLen = WORKING_BUFFER_SIZE;

    do {

        pAddresses = (IP_ADAPTER_ADDRESSES *) MALLOC(outBufLen);

        if (pAddresses == NULL) {
            mterror_exit(WM_SYS_LOGTAG, "Memory allocation failed for IP_ADAPTER_ADDRESSES struct.");
        }

        dwRetVal = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen);

        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            FREE(pAddresses);
            pAddresses = NULL;
        } else {
            break;
        }

        Iterations++;

    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

    if (dwRetVal == NO_ERROR) {

        pCurrAddresses = pAddresses;
        while (pCurrAddresses){

            /* Ignore Loopback interface */
            if (pCurrAddresses->IfType == IF_TYPE_SOFTWARE_LOOPBACK){
                pCurrAddresses = pCurrAddresses->Next;
                continue;
            }

            char *string;
            cJSON *object = cJSON_CreateObject();
            cJSON *iface_info = cJSON_CreateObject();
            cJSON_AddStringToObject(object, "type", "network");

            cJSON_AddItemToObject(object, "iface", iface_info);

            /* Iface Name */
            char iface_name[OS_MAXSTR];
            snprintf(iface_name, OS_MAXSTR, "%S", pCurrAddresses->FriendlyName);
            cJSON_AddStringToObject(iface_info, "name", iface_name);

            /* Iface adapter */
            char description[OS_MAXSTR];
            snprintf(description, OS_MAXSTR, "%S", pCurrAddresses->Description);
            cJSON_AddStringToObject(iface_info, "adapter", description);

            /* Type of interface */
            switch (pCurrAddresses->IfType){
                case IF_TYPE_ETHERNET_CSMACD:
                    cJSON_AddStringToObject(iface_info, "type", "ethernet");
                    break;
                case IF_TYPE_ISO88025_TOKENRING:
                    cJSON_AddStringToObject(iface_info, "type", "token ring");
                    break;
                case IF_TYPE_PPP:
                    cJSON_AddStringToObject(iface_info, "type", "point-to-point");
                    break;
                case IF_TYPE_ATM:
                    cJSON_AddStringToObject(iface_info, "type", "ATM");
                    break;
                case IF_TYPE_IEEE80211:
                    cJSON_AddStringToObject(iface_info, "type", "wireless");
                    break;
                case IF_TYPE_TUNNEL:
                    cJSON_AddStringToObject(iface_info, "type", "tunnel");
                    break;
                case IF_TYPE_IEEE1394:
                    cJSON_AddStringToObject(iface_info, "type", "firewire");
                    break;
                default:
                    cJSON_AddStringToObject(iface_info, "type", "unknown");
                    break;
            }

            /* Type of interface */
            switch (pCurrAddresses->OperStatus){
                case IfOperStatusUp:
                    cJSON_AddStringToObject(iface_info, "state", "up");
                    break;
                case IfOperStatusDown:
                    cJSON_AddStringToObject(iface_info, "state", "down");
                    break;
                case IfOperStatusTesting:
                    cJSON_AddStringToObject(iface_info, "state", "testing");    // In testing mode
                    break;
                case IfOperStatusUnknown:
                    cJSON_AddStringToObject(iface_info, "state", "unknown");
                    break;
                case IfOperStatusDormant:
                    cJSON_AddStringToObject(iface_info, "state", "dormant");    // In a pending state, waiting for some external event
                    break;
                case IfOperStatusNotPresent:
                    cJSON_AddStringToObject(iface_info, "state", "notpresent"); // Interface down because of any component is not present (hardware typically)
                    break;
                case IfOperStatusLowerLayerDown:
                    cJSON_AddStringToObject(iface_info, "state", "lowerlayerdown"); // This interface depends on a lower layer interface which is down
                    break;
                default:
                    cJSON_AddStringToObject(iface_info, "state", "unknown");
                    break;
            }

            /* MAC Address */
            char MAC[30] = "";
            char *mac_addr = &MAC[0];

            if (pCurrAddresses->PhysicalAddressLength != 0) {
                for (i = 0; i < pCurrAddresses->PhysicalAddressLength; i++) {
                    if (i == (pCurrAddresses->PhysicalAddressLength - 1))
                        mac_addr += sprintf(mac_addr, "%.2X", pCurrAddresses->PhysicalAddress[i]);
                    else
                        mac_addr += sprintf(mac_addr, "%.2X:", pCurrAddresses->PhysicalAddress[i]);
                }
                cJSON_AddStringToObject(iface_info, "MAC", MAC);
            }

            free(mac_addr);

            /* MTU */
            int mtu = (int) pCurrAddresses->Mtu;
            cJSON_AddNumberToObject(iface_info, "MTU", mtu);

            cJSON *ipv4 = cJSON_CreateObject();
            cJSON *ipv6 = cJSON_CreateObject();

            /* Extract IPv4 and IPv6 addresses */
            pUnicast = pCurrAddresses->FirstUnicastAddress;

            if (pUnicast){
                for (i=0; pUnicast != NULL; i++){
                    if (pUnicast->Address.lpSockaddr->sa_family == AF_INET){
                        addr4 = (struct sockaddr_in *) pUnicast->Address.lpSockaddr;
                        inet_ntop(AF_INET, &(addr4->sin_addr), host, NI_MAXHOST);
                        cJSON_AddStringToObject(ipv4, "address", host);

                        snprintf(ipv4addr, NI_MAXHOST, "%s", host);

                        /* IPv4 Netmask */
                        ULONG mask = 0;
                        PULONG netmask = &mask;
                        if (!ConvertLengthToIpv4Mask(pUnicast->OnLinkPrefixLength, netmask)){
                            inet_ntop(pUnicast->Address.lpSockaddr->sa_family, netmask, host, NI_MAXHOST);
                            cJSON_AddStringToObject(ipv4, "netmask", host);
                        }else{
                            mtwarn(WM_SYS_LOGTAG, "Invalid Masklength parameter.");
                        }

                        /* Broadcast address */
                        char* broadcast;
                        broadcast = get_broadcast_addr(ipv4addr, host);
                        cJSON_AddStringToObject(ipv4, "broadcast", broadcast);
                        free(broadcast);

                    } else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6){
                        addr6 = (struct sockaddr_in6 *) pUnicast->Address.lpSockaddr;
                        inet_ntop(AF_INET6, &(addr6->sin6_addr), host, NI_MAXHOST);
                        cJSON_AddStringToObject(ipv6, "address", host);

                        /* IPv6 Netmask */
                        char* netmask6;
                        netmask6 = length_to_ipv6_mask(pUnicast->OnLinkPrefixLength);
                        cJSON_AddStringToObject(ipv6, "netmask", netmask6);
                        free(netmask6);

                    } else {
                        mtwarn(WM_SYS_LOGTAG, "Unspecified IP address.");
                    }
                    pUnicast = pUnicast->Next;
                }
            }

            /* Extract Default Gateway */
            pGateway = pCurrAddresses->FirstGatewayAddress;

            if (pGateway){
                for (i=0; pGateway != NULL; i++){
                    char host[NI_MAXHOST];
                    if (pGateway->Address.lpSockaddr->sa_family == AF_INET){
                        addr4 = (struct sockaddr_in *) pGateway->Address.lpSockaddr;
                        inet_ntop(AF_INET, &(addr4->sin_addr), host, NI_MAXHOST);
                        cJSON_AddStringToObject(ipv4, "gateway", host);

                    } else if (pGateway->Address.lpSockaddr->sa_family == AF_INET6){
                        addr6 = (struct sockaddr_in6 *) pGateway->Address.lpSockaddr;
                        inet_ntop(AF_INET6, &(addr6->sin6_addr), host, NI_MAXHOST);
                        cJSON_AddStringToObject(ipv6, "gateway", host);

                    } else {
                        mtwarn(WM_SYS_LOGTAG, "Unspecified Default Gateway.");
                    }
                    pGateway = pGateway->Next;
                }
            }

            if ((pCurrAddresses->Flags & IP_ADAPTER_DHCP_ENABLED) && (pCurrAddresses->Flags & IP_ADAPTER_IPV4_ENABLED)){
                cJSON_AddStringToObject(ipv4, "DHCP", "enabled");
            }else{
                cJSON_AddStringToObject(ipv4, "DHCP", "disabled");
            }

            if ((pCurrAddresses->Flags & IP_ADAPTER_DHCP_ENABLED) && (pCurrAddresses->Flags & IP_ADAPTER_IPV6_ENABLED)){
                cJSON_AddStringToObject(ipv6, "DHCP", "enabled");
            }else{
                cJSON_AddStringToObject(ipv6, "DHCP", "disabled");
            }

            /* Create structure and send data in JSON format of each interface */
            cJSON_AddItemToObject(iface_info, "IPv4", ipv4);
            cJSON_AddItemToObject(iface_info, "IPv6", ipv6);

            string = cJSON_PrintUnformatted(object);
            mtdebug2(WM_SYS_LOGTAG, "sys_network_windows() sending '%s'", string);
            SendMSG(0, string, LOCATION, WODLE_MQ);
            cJSON_Delete(object);

            free(string);

            pCurrAddresses = pCurrAddresses->Next;
        }
    } else {
        mterror(WM_SYS_LOGTAG, "Call to GetAdaptersAddresses failed with error: %lu", dwRetVal);
        if (dwRetVal == ERROR_NO_DATA)
            mterror(WM_SYS_LOGTAG, "No addresses were found for the requested parameters.");
        else {

            if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                    NULL, dwRetVal, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    // Default language
                    (LPTSTR) & lpMsgBuf, 0, NULL)) {
                mterror(WM_SYS_LOGTAG, "Error: %s", (char *)lpMsgBuf);
                LocalFree(lpMsgBuf);
                if (pAddresses)
                    FREE(pAddresses);
                return;
            }
        }
    }

    if (pAddresses) {
        FREE(pAddresses);
    }

}

/* Adapt IPv6 subnet prefix length to hexadecimal notation */
char* length_to_ipv6_mask(int mask_length){

    char string[64] = "";
    char* netmask = calloc(65,sizeof(char));
    int length = mask_length;
    int i = 0, j = 0, k=0;

    while (length){
        if (length>=4){
            string[j] = 'f';
            j++;
            length -= 4;
        }else{
            switch (length){
                case 3:
                    string[j] = 'e';
                    j++;
                case 2:
                    string[j] = 'c';
                    j++;
                case 1:
                    string[j] = '8';
                    j++;
                case 0:
                    break;
            }
            length = 0;
        }

        k++;
        if (k == 4 && length){
            string[j] = ':';
            j++;
            k = 0;
        }
    }

    if (k != 0){
        while (k<4){
            string[j] = '0';
            j++;
            k++;
        }
    }

    for (i=0; i<2 && j < 39; i++){
        string[j] = ':';
        j++;
    }

    snprintf(netmask, 64, "%s", string);

    return netmask;
}

/* Get broadcast address from IPv4 address and netmask */
char* get_broadcast_addr(char* ip, char* netmask){

    struct in_addr host, mask, broadcast;
    char* broadcast_addr = calloc(NI_MAXHOST, sizeof(char));

    if (inet_pton(AF_INET, ip, &host) == 1 && inet_pton(AF_INET, netmask, &mask) == 1){
        broadcast.s_addr = host.s_addr | ~mask.s_addr;
    }else{
        mterror(WM_SYS_LOGTAG, "Failed getting Broadcast Address.");
    }

    if (inet_ntop(AF_INET, &broadcast, broadcast_addr, NI_MAXHOST) != NULL){
        return broadcast_addr;
    }else{
        mterror(WM_SYS_LOGTAG, "Failed converting Broadcast Address to string.");
    }

    return broadcast_addr;
}

#endif
