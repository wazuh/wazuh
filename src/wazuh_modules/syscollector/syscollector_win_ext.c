/*
 * Wazuh DLL for System inventory for Windows
 * Copyright (C) 2015-2020, Wazuh Inc.
 * Aug, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#ifdef WIN32

#define _WIN32_WINNT 0x600  // Windows Vista or later

#define MAXSTR 1024

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

typedef struct net_addr {
    char ** address;
    char ** netmask;
    char ** broadcast;
    int metric;
    char * gateway;
    char * dhcp;
} net_addr;

typedef struct iface_data {
    char * name;
    char * adapter;
    char * type;
    char * state;
    char * mac;
    int mtu;

    int tx_packets;
    int rx_packets;
    int tx_bytes;
    int rx_bytes;
    int tx_errors;
    int rx_errors;
    int tx_dropped;
    int rx_dropped;

    struct net_addr * ipv4;
    struct net_addr * ipv6;

    int enabled;
} iface_data;

net_addr * init_net_addr();
iface_data * init_iface_data();

net_addr * init_net_addr() {
    net_addr * net = NULL;
    net = calloc(1, sizeof(net_addr));
    net->address = NULL;
    net->netmask = NULL;
    net->broadcast = NULL;
    net->metric = INT_MIN;
    net->gateway = NULL;
    net->dhcp = NULL;
    return net;
}

iface_data * init_iface_data() {
    iface_data * data = NULL;
    data = calloc(1, sizeof(iface_data));
    data->name = NULL;
    data->adapter = NULL;
    data->type = NULL;
    data->state = NULL;
    data->mac = NULL;
    data->mtu = INT_MIN;
    data->tx_packets = INT_MIN;
    data->rx_packets = INT_MIN;
    data->tx_bytes = INT_MIN;
    data->rx_bytes = INT_MIN;
    data->tx_errors = INT_MIN;
    data->rx_errors = INT_MIN;
    data->tx_dropped = INT_MIN;
    data->rx_dropped = INT_MIN;
    data->ipv4 = NULL;
    data->ipv6 = NULL;
    data->enabled = 0;
    return data;
}

__declspec( dllexport ) char* wm_inet_ntop(UCHAR ucLocalAddr[]){

    char *address;
    address = calloc(129, sizeof(char));

    if(address == NULL) {
        return NULL;
    }

    inet_ntop(AF_INET6,(struct in6_addr *)ucLocalAddr, address, 128);

    return address;

}

__declspec( dllexport ) iface_data * get_network_vista(PIP_ADAPTER_ADDRESSES pCurrAddresses){

    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
    PIP_ADAPTER_GATEWAY_ADDRESS_LH pGateway = NULL;

    unsigned int i = 0;
    char host[NI_MAXHOST];
    char ipv4addr[NI_MAXHOST];

    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;

    iface_data * data = init_iface_data();

    /* Iface Name */
    char iface_name[MAXSTR];
    snprintf(iface_name, MAXSTR, "%S", pCurrAddresses->FriendlyName);
    data->name = strdup(iface_name);

    /* Iface adapter */
    char description[MAXSTR];
    snprintf(description, MAXSTR, "%S", pCurrAddresses->Description);
    data->adapter = strdup(description);

    /* Type of interface */
    switch (pCurrAddresses->IfType){
        case IF_TYPE_ETHERNET_CSMACD:
            data->type = strdup("ethernet");
            break;
        case IF_TYPE_ISO88025_TOKENRING:
            data->type = ("token ring");
            break;
        case IF_TYPE_PPP:
            data->type = strdup("point-to-point");
            break;
        case IF_TYPE_ATM:
            data->type = strdup("ATM");
            break;
        case IF_TYPE_IEEE80211:
            data->type = strdup("wireless");
            break;
        case IF_TYPE_TUNNEL:
            data->type = strdup("tunnel");
            break;
        case IF_TYPE_IEEE1394:
            data->type = strdup("firewire");
            break;
        default:
            data->type = strdup("unknown");
            break;
    }

    /* Operational status */
    switch (pCurrAddresses->OperStatus){
        case IfOperStatusUp:
            data->state = strdup("up");
            break;
        case IfOperStatusDown:
            data->state = strdup("down");
            break;
        case IfOperStatusTesting:
            data->state = strdup("testing");
            break;
        case IfOperStatusUnknown:
            data->state = strdup("unknown");
            break;
        case IfOperStatusDormant:
            data->state = strdup("dormant");
            break;
        case IfOperStatusNotPresent:
            data->state = strdup("notpresent");
            break;
        case IfOperStatusLowerLayerDown:
            data->state = strdup("lowerlayerdown");
            break;
        default:
            data->state = strdup("unknown");
            break;
    }

    /* MAC Address */
    char MAC[30] = {'\0'};

    if (pCurrAddresses->PhysicalAddressLength != 0) {
        for (i = 0; i < pCurrAddresses->PhysicalAddressLength; i++) {
            snprintf(MAC + strlen(MAC), 3, "%.2X", pCurrAddresses->PhysicalAddress[i]);
            if (i < (pCurrAddresses->PhysicalAddressLength - 1)) MAC[strlen(MAC)] = ':';
        }
        data->mac = strdup(MAC);
    }

    /* MTU */
    int mtu = (int) pCurrAddresses->Mtu;
    data->mtu = mtu;

    data->ipv4 = init_net_addr();
    data->ipv4->address = malloc(sizeof(char *));
    data->ipv4->netmask = malloc(sizeof(char *));
    data->ipv4->broadcast = malloc(sizeof(char *));
    int address4 = 0, nmask4 = 0, bcast4 = 0;

    data->ipv6 = init_net_addr();
    data->ipv6->address = malloc(sizeof(char *));
    data->ipv6->netmask = malloc(sizeof(char *));
    int address6 = 0, nmask6 = 0;

    /* Get network stats */

    ULONG retVal = 0;

    MIB_IF_ROW2 ifRow;
    SecureZeroMemory((PVOID) &ifRow, sizeof(MIB_IF_ROW2));

    ifRow.InterfaceIndex = pCurrAddresses->IfIndex;
    if (ifRow.InterfaceIndex == 0) ifRow.InterfaceIndex = pCurrAddresses->Ipv6IfIndex;

    /* Only get this information if we have a valid interface index */
    if (ifRow.InterfaceIndex != 0) {
        retVal = GetIfEntry2(&ifRow);
        if (retVal == NO_ERROR) {
            ULONG64 tx_packets = ifRow.OutUcastPkts + ifRow.OutNUcastPkts;
            ULONG64 rx_packets = ifRow.InUcastPkts + ifRow.InNUcastPkts;

            data->tx_packets = tx_packets;
            data->rx_packets = rx_packets;
            data->tx_bytes = ifRow.OutOctets;
            data->rx_bytes = ifRow.InOctets;
            data->tx_errors = ifRow.OutErrors;
            data->rx_errors = ifRow.InErrors;
            data->tx_dropped = ifRow.OutDiscards;
            data->rx_dropped = ifRow.InDiscards;
        }
    }

    /* Extract IPv4 and IPv6 addresses */
	char *broadcast = NULL, *netmask6 = NULL;
    pUnicast = pCurrAddresses->FirstUnicastAddress;

    if (pUnicast){
        for (i=0; pUnicast != NULL; i++){
            if (pUnicast->Address.lpSockaddr->sa_family == AF_INET){
                addr4 = (struct sockaddr_in *) pUnicast->Address.lpSockaddr;
                inet_ntop(AF_INET, &(addr4->sin_addr), host, NI_MAXHOST);
                data->ipv4->address[address4] = strdup(host);
                data->ipv4->address = realloc(data->ipv4->address, (address4 + 2) * sizeof(char *));
                address4++;

                snprintf(ipv4addr, NI_MAXHOST, "%s", host);

                /* IPv4 Netmask */
                ULONG mask = 0;
                PULONG netmask = &mask;
                if (!ConvertLengthToIpv4Mask(pUnicast->OnLinkPrefixLength, netmask)){
                    inet_ntop(pUnicast->Address.lpSockaddr->sa_family, netmask, host, NI_MAXHOST);
                    data->ipv4->netmask[nmask4] = strdup(host);
                    data->ipv4->netmask = realloc(data->ipv4->netmask, (nmask4 + 2) * sizeof(char *));
                    nmask4++;
                }

                /* Broadcast address */
                broadcast = get_broadcast_addr(ipv4addr, host);
                if (broadcast) {
                    data->ipv4->broadcast[bcast4] = strdup(broadcast);
                    data->ipv4->broadcast = realloc(data->ipv4->broadcast, (bcast4 + 2) * sizeof(char *));
                    bcast4++;
                    free(broadcast);
                    broadcast = NULL;
                }
            } else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6){
                addr6 = (struct sockaddr_in6 *) pUnicast->Address.lpSockaddr;
                inet_ntop(AF_INET6, &(addr6->sin6_addr), host, NI_MAXHOST);
                data->ipv6->address[address6] = strdup(host);
                data->ipv6->address = realloc(data->ipv6->address, (address6 + 2) * sizeof(char *));
                address6++;

                /* IPv6 Netmask */
                netmask6 = length_to_ipv6_mask(pUnicast->OnLinkPrefixLength);
                if (netmask6) {
                    data->ipv6->netmask[nmask6] = strdup(netmask6);
                    data->ipv6->netmask = realloc(data->ipv6->netmask, (nmask6 + 2) * sizeof(char *));
                    nmask6++;
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
                data->ipv4->gateway = strdup(host);
                data->ipv4->metric = pCurrAddresses->Ipv4Metric;

            } else if (pGateway->Address.lpSockaddr->sa_family == AF_INET6){
                addr6 = (struct sockaddr_in6 *) pGateway->Address.lpSockaddr;
                inet_ntop(AF_INET6, &(addr6->sin6_addr), host, NI_MAXHOST);
                data->ipv6->gateway = strdup(host);
                data->ipv6->metric = pCurrAddresses->Ipv6Metric;

            }

            pGateway = pGateway->Next;
        }
    }

    if ((pCurrAddresses->Flags & IP_ADAPTER_DHCP_ENABLED) && (pCurrAddresses->Flags & IP_ADAPTER_IPV4_ENABLED)){
        data->ipv4->dhcp = strdup("enabled");
    }else{
        data->ipv4->dhcp = strdup("disabled");
    }

    if ((pCurrAddresses->Flags & IP_ADAPTER_DHCP_ENABLED) && (pCurrAddresses->Flags & IP_ADAPTER_IPV6_ENABLED)){
        data->ipv6->dhcp = strdup("enabled");
    }else{
        data->ipv6->dhcp = strdup("disabled");
    }

    data->ipv4->address[address4] = NULL;
    data->ipv4->netmask[nmask4] = NULL;
    data->ipv4->broadcast[bcast4] = NULL;
    data->ipv6->address[address6] = NULL;
    data->ipv6->netmask[nmask6] = NULL;

    return data;
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

    if(broadcast_addr == NULL) {
        return NULL;
    }

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
                }
            } else {
                ret = 3;
            }

            free(smbios);
        } else {
            ret = 2;
        }
    } else {
        ret = 1;
    }

    return ret;
}

#endif
