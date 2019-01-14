/*
 * Wazuh DLL for System inventory for Windows
 * Copyright (C) 2015-2019, Wazuh Inc.
 * Aug, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#ifdef WIN32

#define _WIN32_WINNT 0x600  // Windows Vista or later

#define MAXSTR 1024

#include <external/cJSON/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <netioapi.h>
#include <iphlpapi.h>
#include <string.h>

char* length_to_ipv6_mask(int mask_length);
char* get_broadcast_addr(char* ip, char* netmask);

__declspec( dllexport ) char* wm_inet_ntop(UCHAR ucLocalAddr[]){

    char *address;
    address = calloc(129, sizeof(char));

    inet_ntop(AF_INET6,(struct in6_addr *)ucLocalAddr, address, 128);

    return address;

}

__declspec( dllexport ) char* get_network(PIP_ADAPTER_ADDRESSES pCurrAddresses, int ID, char * timestamp){

    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
    PIP_ADAPTER_GATEWAY_ADDRESS_LH pGateway = NULL;

    char *string;
    unsigned int i = 0;
    char host[NI_MAXHOST];
    char ipv4addr[NI_MAXHOST];

    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;

    cJSON *object = cJSON_CreateObject();
    cJSON *iface_info = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "network");
    cJSON_AddNumberToObject(object, "ID", ID);
    cJSON_AddStringToObject(object, "timestamp", timestamp);
    cJSON_AddItemToObject(object, "iface", iface_info);

    /* Iface Name */
    char iface_name[MAXSTR];
    snprintf(iface_name, MAXSTR, "%S", pCurrAddresses->FriendlyName);
    cJSON_AddStringToObject(iface_info, "name", iface_name);

    /* Iface adapter */
    char description[MAXSTR];
    snprintf(description, MAXSTR, "%S", pCurrAddresses->Description);
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

    /* Operational status */
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
    char MAC[30] = {'\0'};

    if (pCurrAddresses->PhysicalAddressLength != 0) {
        for (i = 0; i < pCurrAddresses->PhysicalAddressLength; i++) {
            snprintf(MAC + strlen(MAC), 3, "%.2X", pCurrAddresses->PhysicalAddress[i]);
            if (i < (pCurrAddresses->PhysicalAddressLength - 1)) MAC[strlen(MAC)] = ':';
        }
        cJSON_AddStringToObject(iface_info, "MAC", MAC);
    }

    /* MTU */
    int mtu = (int) pCurrAddresses->Mtu;
    if (mtu != 0)
        cJSON_AddNumberToObject(iface_info, "MTU", mtu);

    cJSON *ipv4 = cJSON_CreateObject();
    cJSON *ipv4_addr = cJSON_CreateArray();
    cJSON *ipv4_netmask = cJSON_CreateArray();
    cJSON *ipv4_broadcast = cJSON_CreateArray();

    cJSON *ipv6 = cJSON_CreateObject();
    cJSON *ipv6_addr = cJSON_CreateArray();
    cJSON *ipv6_netmask = cJSON_CreateArray();

    /* Get network stats */

    ULONG retVal = 0;

    MIB_IF_ROW2 ifRow;
    SecureZeroMemory((PVOID) &ifRow, sizeof(MIB_IF_ROW2));

    ifRow.InterfaceIndex = pCurrAddresses->IfIndex;

    if ((retVal = GetIfEntry2(&ifRow)) == NO_ERROR) {

        int tx_packets = ifRow.OutUcastPkts + ifRow.OutNUcastPkts;
        int rx_packets = ifRow.InUcastPkts + ifRow.InNUcastPkts;

        cJSON_AddNumberToObject(iface_info, "tx_packets", tx_packets);
        cJSON_AddNumberToObject(iface_info, "rx_packets", rx_packets);
        cJSON_AddNumberToObject(iface_info, "tx_bytes", ifRow.OutOctets);
        cJSON_AddNumberToObject(iface_info, "rx_bytes", ifRow.InOctets);
        cJSON_AddNumberToObject(iface_info, "tx_errors", ifRow.OutErrors);
        cJSON_AddNumberToObject(iface_info, "rx_errors", ifRow.InErrors);
        cJSON_AddNumberToObject(iface_info, "tx_dropped", ifRow.OutDiscards);
        cJSON_AddNumberToObject(iface_info, "rx_dropped", ifRow.InDiscards);
    }

    /* Extract IPv4 and IPv6 addresses */
	char *broadcast = NULL, *netmask6 = NULL;
    pUnicast = pCurrAddresses->FirstUnicastAddress;

    if (pUnicast){
        for (i=0; pUnicast != NULL; i++){
            if (pUnicast->Address.lpSockaddr->sa_family == AF_INET){
                addr4 = (struct sockaddr_in *) pUnicast->Address.lpSockaddr;
                inet_ntop(AF_INET, &(addr4->sin_addr), host, NI_MAXHOST);
                cJSON_AddItemToArray(ipv4_addr, cJSON_CreateString(host));

                snprintf(ipv4addr, NI_MAXHOST, "%s", host);

                /* IPv4 Netmask */
                ULONG mask = 0;
                PULONG netmask = &mask;
                if (!ConvertLengthToIpv4Mask(pUnicast->OnLinkPrefixLength, netmask)){
                    inet_ntop(pUnicast->Address.lpSockaddr->sa_family, netmask, host, NI_MAXHOST);
                    cJSON_AddItemToArray(ipv4_netmask, cJSON_CreateString(host));
                }

                /* Broadcast address */
                broadcast = get_broadcast_addr(ipv4addr, host);
                if (broadcast) {
                    cJSON_AddItemToArray(ipv4_broadcast, cJSON_CreateString(broadcast));
                    free(broadcast);
                    broadcast = NULL;
                }
            } else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6){
                addr6 = (struct sockaddr_in6 *) pUnicast->Address.lpSockaddr;
                inet_ntop(AF_INET6, &(addr6->sin6_addr), host, NI_MAXHOST);
                cJSON_AddItemToArray(ipv6_addr, cJSON_CreateString(host));

                /* IPv6 Netmask */
                netmask6 = length_to_ipv6_mask(pUnicast->OnLinkPrefixLength);
                if (netmask6) {
                    cJSON_AddItemToArray(ipv6_netmask, cJSON_CreateString(netmask6));
                    free(netmask6);
                    netmask6 = NULL;
                }
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

    if (cJSON_GetArraySize(ipv4_addr) > 0) {
        cJSON_AddItemToObject(ipv4, "address", ipv4_addr);
        if (cJSON_GetArraySize(ipv4_netmask) > 0) {
            cJSON_AddItemToObject(ipv4, "netmask", ipv4_netmask);
        } else {
            cJSON_Delete(ipv4_netmask);
        }
        if (cJSON_GetArraySize(ipv4_broadcast) > 0) {
            cJSON_AddItemToObject(ipv4, "broadcast", ipv4_broadcast);
        } else {
            cJSON_Delete(ipv4_broadcast);
        }
        cJSON_AddItemToObject(iface_info, "IPv4", ipv4);
    } else {
        cJSON_Delete(ipv4_addr);
        cJSON_Delete(ipv4_netmask);
        cJSON_Delete(ipv4_broadcast);
        cJSON_Delete(ipv4);
    }

    if (cJSON_GetArraySize(ipv6_addr) > 0) {
        cJSON_AddItemToObject(ipv6, "address", ipv6_addr);
        if (cJSON_GetArraySize(ipv6_netmask) > 0) {
            cJSON_AddItemToObject(ipv6, "netmask", ipv6_netmask);
        } else {
            cJSON_Delete(ipv6_netmask);
        }
        cJSON_AddItemToObject(iface_info, "IPv6", ipv6);
    } else {
        cJSON_Delete(ipv6_addr);
        cJSON_Delete(ipv6_netmask);
        cJSON_Delete(ipv6);
    }

    string = cJSON_PrintUnformatted(object);
    cJSON_Delete(object);
    return string;

}

/* Adapt IPv6 subnet prefix length to hexadecimal notation */
char* length_to_ipv6_mask(int mask_length){

    char string[64] = {'\0'};
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
                    string[j++] = 'e';
                    break;
                case 2:
                    string[j++] = 'c';
                    break;
                case 1:
                    string[j++] = '8';
                    break;
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
    }

    if (inet_ntop(AF_INET, &broadcast, broadcast_addr, NI_MAXHOST) == NULL){
        sprintf(broadcast_addr, "unknown");
    }

    return broadcast_addr;
}

typedef struct RawSMBIOSData
{
    BYTE    Used20CallingMethod;
    BYTE    SMBIOSMajorVersion;
    BYTE    SMBIOSMinorVersion;
    BYTE    DmiRevision;
    DWORD    Length;
    BYTE    SMBIOSTableData[];
} RawSMBIOSData, *PRawSMBIOSData;

typedef struct SMBIOSStructureHeader {
	BYTE Type;
	BYTE FormattedAreaLength;
	WORD Handle;
} SMBIOSStructureHeader;

/* Reference: https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_2.6.0.pdf */
char* parse_raw_smbios_bbserial(BYTE* rawData, DWORD rawDataSize){
	DWORD pos = 0;
	SMBIOSStructureHeader *header;
	char *serialNumber = NULL, *tmp = NULL;
	BYTE serialNumberStrNum = 0, curStrNum = 0;
	
	if (rawData == NULL || !rawDataSize) return NULL;
	
	while(pos < rawDataSize)
	{
		/* Get structure header */
		header = (SMBIOSStructureHeader*)(rawData + pos);
		
		/* Check if this SMBIOS structure represents the Base Board Information */
		if (header->Type == 2)
		{
			/* Check if the Base Board Serial Number string is actually available */
			if ((BYTE)rawData[pos + 7] > 0)
			{
				serialNumberStrNum = (BYTE)rawData[pos + 7];
			} else {
				/* No need to keep looking for the serial number */
				break;
			}
		}
		
		/* Skip formatted area length */
		pos += header->FormattedAreaLength;
		
		/* Reset current string number */
		curStrNum = 0;
		
		/* Read unformatted area */
		/* This area is formed by NULL-terminated strings */
		/* The area itself ends with an additional NULL terminator */
		while(pos < rawDataSize)
		{
			tmp = (char*)(rawData + pos);
			
			/* Check if we found a NULL terminator */
			if (tmp[0] == 0)
			{
				/* Check if there's another NULL terminator */
				/* If so, we reached the end of this structure */
				if (tmp[1] == 0)
				{
					/* Prepare position for the next structure */
					pos += 2;
					break;
				} else {
					/* Only found a single NULL terminator */
					/* Increase both the position and the pointer */
					pos++;
					tmp++;
				}
			}
			
			/* Increase current string number */
			curStrNum++;
			
			/* Check if we reached the Serial Number */
			if (header->Type == 2 && curStrNum == serialNumberStrNum)
			{
				serialNumber = strdup(tmp);
				break;
			}
			
			/* Prepare position to access the next string */
			pos += (DWORD)strlen(tmp);
		}
		
		if (serialNumber) break;
	}
	
	return serialNumber;
}

__declspec( dllexport ) int get_baseboard_serial(char **serial)
{
    int ret = 0;
    DWORD smbios_size = 0;
    PRawSMBIOSData smbios = NULL;
    
    DWORD Signature = 0;
    const BYTE byteSignature[] = { 'B', 'M', 'S', 'R' }; // "RSMB" (little endian)
    memcpy(&Signature, byteSignature, 4);
    
    /* Get raw SMBIOS firmware table size */
    /* Reference: https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable */
    smbios_size = GetSystemFirmwareTable(Signature, 0, NULL, 0);
    if (smbios_size)
    {
        smbios = (PRawSMBIOSData)malloc(smbios_size);
        if (smbios)
        {
            /* Get raw SMBIOS firmware table */
            if (GetSystemFirmwareTable(Signature, 0, smbios, smbios_size) == smbios_size)
            {
                /* Parse SMBIOS structures */
                /* We need to look for a Type 2 SMBIOS structure (Base Board Information) */
                *serial = parse_raw_smbios_bbserial(smbios->SMBIOSTableData, smbios_size);
                if (!*serial)
                {
                    ret = 4;
                    *serial = strdup("unknown");
                }
            } else {
                ret = 3;
                *serial = strdup("unknown");
            }
            
            free(smbios);
        } else {
            ret = 2;
            *serial = strdup("unknown");
        }
    } else {
        ret = 1;
        *serial = strdup("unknown");
    }
    
    return ret;
}

#endif
