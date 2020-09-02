/*
 * Wazuh Module for System inventory for Windows
 * Copyright (C) 2015-2020, Wazuh Inc.
 * Aug, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#include <winternl.h>
#include <ntstatus.h>
#include "syscollector.h"
#include "file_op.h"

#define MAXSTR 1024

typedef char* (*CallFunc)(PIP_ADAPTER_ADDRESSES pCurrAddresses, int ID, char * timestamp);  // char* get_network_vista(PIP_ADAPTER_ADDRESSES pCurrAddresses, int ID, char * timestamp);
typedef int (*CallFunc1)(char **serial);                                                    // int get_baseboard_serial(char **serial);

typedef struct _SYSTEM_PROCESS_IMAGE_NAME_INFORMATION
{
    HANDLE ProcessId;
    UNICODE_STRING ImageName;
} SYSTEM_PROCESS_IMAGE_NAME_INFORMATION, *PSYSTEM_PROCESS_IMAGE_NAME_INFORMATION;

typedef NTSTATUS(WINAPI *tNTQSI)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

static bool found_hotfix_error(HKEY hKey);
static bool valid_hotfix_status(HKEY hKey);
static char * parse_Rollup_hotfix(HKEY hKey, char *value);
hw_info *get_system_windows();
int set_token_privilege(HANDLE hdle, LPCTSTR privilege, int enable);

/* From process ID get its name */
char* get_process_name(DWORD pid){
    char read_buff[OS_MAXSTR];
    char *string = NULL, *ptr = NULL;

    /* Check if we are dealing with a system process */
    if (pid == 0 || pid == 4)
    {
        string = strdup(pid == 0 ? "System Idle Process" : "System");
        return string;
    }

    /* Get process handle */
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL && checkVista())
    {
        /* Try to open the process using PROCESS_QUERY_LIMITED_INFORMATION */
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    }

    if (hProcess != NULL)
    {
        /* Get full Windows kernel path for the process */
        if (GetProcessImageFileName(hProcess, read_buff, OS_MAXSTR))
        {
            /* Get only the process name from the string */
            ptr = strrchr(read_buff, '\\');
            if (ptr)
            {
                int len = (strlen(read_buff) - (ptr - read_buff + 1));
                memcpy(read_buff, &(read_buff[ptr - read_buff + 1]), len);
                read_buff[len] = '\0';
            }

            /* Duplicate string */
            string = strdup(read_buff);
        } else {
            mtwarn(WM_SYS_LOGTAG, "Unable to retrieve name for process with PID %lu (%lu).", pid, GetLastError());
        }

        /* Close process handle */
        CloseHandle(hProcess);
    } else {
        if (checkVista())
        {
            /* Dinamically load the ntdll.dll library and the 'NtQuerySystemInformation' call to retrieve the process image name */
            /* Only works under Windows Vista and greater */
            /* References: */
            /* http://www.rohitab.com/discuss/topic/40626-list-processes-using-ntquerysysteminformation/ */
            /* http://wj32.org/wp/2010/03/30/get-the-image-file-name-of-any-process-from-any-user-on-vista-and-above/ */
            tNTQSI fpQSI = NULL;
            HANDLE hHeap = GetProcessHeap();
            HMODULE ntdll = LoadLibrary("ntdll.dll");
            if (ntdll == NULL)
            {
                DWORD error = GetLastError();
                LPSTR messageBuffer = NULL;
                LPSTR end;

                FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error, 0, (LPTSTR) &messageBuffer, 0, NULL);

                if (end = strchr(messageBuffer, '\r'), end) *end = '\0';

                mterror(WM_SYS_LOGTAG, "Unable to load ntdll.dll: %s (%lu).", messageBuffer, error);
                LocalFree(messageBuffer);
            } else {
                fpQSI = (tNTQSI)GetProcAddress(ntdll, "NtQuerySystemInformation");
                if (fpQSI == NULL) mterror(WM_SYS_LOGTAG, "Unable to access 'NtQuerySystemInformation' on ntdll.dll.");
            }

            if (ntdll != NULL && fpQSI != NULL)
            {
                NTSTATUS Status;
                PVOID pBuffer;
                SYSTEM_PROCESS_IMAGE_NAME_INFORMATION procInfo;

                pBuffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x100);
                if (pBuffer == NULL)
                {
                    mterror(WM_SYS_LOGTAG, "Unable to allocate memory for 'NtQuerySystemInformation'.");
                } else {
                    procInfo.ProcessId = &pid;
                    procInfo.ImageName.Length = 0;
                    procInfo.ImageName.MaximumLength = (USHORT)0x100;
                    procInfo.ImageName.Buffer = pBuffer;

                    Status = fpQSI(88, &procInfo, sizeof(procInfo), NULL);

                    if (Status == STATUS_INFO_LENGTH_MISMATCH)
                    {
                        /* Our buffer was too small. The required buffer length is stored in MaximumLength */
                        HeapFree(hHeap, 0, pBuffer);
                        pBuffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, procInfo.ImageName.MaximumLength);
                        if (pBuffer == NULL)
                        {
                            mterror(WM_SYS_LOGTAG, "Unable to allocate memory for 'NtQuerySystemInformation'.");
                        } else {
                            procInfo.ImageName.Buffer = pBuffer;
                            Status = fpQSI(88, &procInfo, sizeof(procInfo), NULL);
                        }
                    }

                    if (NT_SUCCESS(Status))
                    {
                        int size_needed = WideCharToMultiByte(CP_UTF8, 0, procInfo.ImageName.Buffer, procInfo.ImageName.Length / 2, NULL, 0, NULL, NULL);
                        if (!size_needed)
                        {
                            mterror(WM_SYS_LOGTAG, "'WideCharToMultiByte' failed (%lu).", GetLastError());
                        } else {
                            os_malloc(size_needed + 1, string);
                            if (WideCharToMultiByte(CP_UTF8, 0, procInfo.ImageName.Buffer, procInfo.ImageName.Length / 2, string, size_needed, NULL, NULL) != size_needed)
                            {
                                mterror(WM_SYS_LOGTAG, "'WideCharToMultiByte' failed (%lu).", GetLastError());
                                free(string);
                                string = NULL;
                            }
                        }
                    }

                    if (pBuffer != NULL) HeapFree(hHeap, 0, pBuffer);
                }
            }
            if(ntdll) {
                FreeLibrary(ntdll);
            }
        } else {
            mtwarn(WM_SYS_LOGTAG, "Unable to retrieve handle for process with PID %lu (%lu).", pid, GetLastError());
        }
    }

    if (string == NULL) string = strdup("unknown");
    return string;
}

void raw_ipv6_translate(unsigned char *ipv6_addr, char *output) {
    /* For some reason, WSAAddressToStringA() fails when dealing with loopback addresses (::1), unspecified addresses (::) and Neighbor Discovery Protocol (NDP) addresses */
    /* All we can do is perform a byte-per-byte translation of the IPv6 address. It's better than nothing */
    unsigned char ipv6_test_addr[16];
    memset(ipv6_test_addr, 0, 16);

    /* Check if we're dealing with an unspecified address (::) */
    if (memcmp(ipv6_addr, ipv6_test_addr, 16) == 0) {
        sprintf(output, "::");
    } else {
        /* Check if we're dealing with a loopback address (::1) */
        ipv6_test_addr[15] = 0x01;

        if (memcmp(ipv6_addr, ipv6_test_addr, 16) == 0) {
            sprintf(output, "::1");
        } else {
            /* Perform a byte-per-byte translation of the IPv6 address */
            char tmpAddr[128] = {'\0'}, tmpByte[4] = {'\0'};

            int i;
            for(i = 0; i < 16; i++) {
                sprintf(tmpByte, "%02x", ipv6_addr[i]);
                strcat(tmpAddr, tmpByte);
                if (((i + 1) % 2) == 0 && (i + 1) < 16) strcat(tmpAddr, ":");
            }

            snprintf(output, 128, "%s", tmpAddr);
        }
    }
}

void clean_wsa_conversion(char *ipv6_addr)
{
    /* Remove brackets (if available) */
    if (ipv6_addr[0] == '[') memmove(ipv6_addr, ipv6_addr + 1, strlen(ipv6_addr) - 1);
    char *pch = strrchr(ipv6_addr, ']');
    if (pch != NULL) *pch = '\0';

    /* Remove the scope ID from the IPv6 address (if available) */
    pch = strrchr(ipv6_addr, '%');
    if (pch != NULL) *pch = '\0';
}

// Get port state

char* get_port_state(int state){

    char *port_state;
    os_calloc(STATE_LENGTH, sizeof(char), port_state);

    switch (state) {
        case MIB_TCP_STATE_CLOSED:
            snprintf(port_state, STATE_LENGTH, "%s", "close");
            break;
        case MIB_TCP_STATE_LISTEN:
            snprintf(port_state, STATE_LENGTH, "%s", "listening");
            break;
        case MIB_TCP_STATE_SYN_SENT:
            snprintf(port_state, STATE_LENGTH, "%s", "syn_sent");
            break;
        case MIB_TCP_STATE_SYN_RCVD:
            snprintf(port_state, STATE_LENGTH, "%s", "syn_recv");
            break;
        case MIB_TCP_STATE_ESTAB:
            snprintf(port_state, STATE_LENGTH, "%s", "established");
            break;
        case MIB_TCP_STATE_FIN_WAIT1:
            snprintf(port_state, STATE_LENGTH, "%s", "fin_wait1");
            break;
        case MIB_TCP_STATE_FIN_WAIT2:
            snprintf(port_state, STATE_LENGTH, "%s", "fin_wait2");
            break;
        case MIB_TCP_STATE_CLOSE_WAIT:
            snprintf(port_state, STATE_LENGTH, "%s", "close_wait");
            break;
        case MIB_TCP_STATE_CLOSING:
            snprintf(port_state, STATE_LENGTH, "%s", "closing");
            break;
        case MIB_TCP_STATE_LAST_ACK:
            snprintf(port_state, STATE_LENGTH, "%s", "last_ack");
            break;
        case MIB_TCP_STATE_TIME_WAIT:
            snprintf(port_state, STATE_LENGTH, "%s", "time_wait");
            break;
        case MIB_TCP_STATE_DELETE_TCB:
            snprintf(port_state, STATE_LENGTH, "%s", "delete_tcp");
            break;
        default:
            snprintf(port_state, STATE_LENGTH, "%s", "unknown");
            break;
    }
    return port_state;
}

// Get opened ports inventory

void sys_ports_windows(const char* LOCATION, int check_all){
    /* Declare and initialize variables */
    PMIB_TCPTABLE_OWNER_PID pTcpTable = NULL;
    PMIB_TCP6TABLE_OWNER_PID pTcp6Table = NULL;
    PMIB_UDPTABLE_OWNER_PID pUdpTable = NULL;
    PMIB_UDP6TABLE_OWNER_PID pUdp6Table = NULL;
    DWORD dwSize = 0;
    BOOL bOrder = TRUE;
    DWORD dwRetVal = 0;
    int listening;
    int i = 0, j = 0;

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    // Set random ID for each scan

    int ID = wm_sys_get_random_id();

    // Set timestamp

    char *timestamp = w_get_timestamp(time(NULL));

	HANDLE hdle;
	int privilege_enabled = 0;

	/* Enable debug privilege */
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hdle))
	{
		if (!set_token_privilege(hdle, SE_DEBUG_NAME, TRUE))
		{
			privilege_enabled = 1;
		} else {
			mtwarn(WM_SYS_LOGTAG, "Unable to unset debug privilege on current process (%lu).", GetLastError());
		}
	} else {
		mtwarn(WM_SYS_LOGTAG, "Unable to retrieve current process token (%lu).", GetLastError());
	}

    /* Initialize the Winsock DLL */
    WSADATA wsd;
    int wsa_enabled = 0;
    if (WSAStartup(MAKEWORD(2,2), &wsd) != 0) {
        mterror(WM_SYS_LOGTAG, "Unable to initialize Winsock DLL (%d).", WSAGetLastError());
        goto end;
    }
    wsa_enabled = 1;

	char local_addr[NI_MAXHOST];
    char rem_addr[NI_MAXHOST];
    struct in_addr ipaddress;
    struct in6_addr ipaddressv6;

    TCP_TABLE_CLASS TableClass = TCP_TABLE_OWNER_PID_ALL;
    UDP_TABLE_CLASS TableClassUdp = UDP_TABLE_OWNER_PID;

    mtdebug1(WM_SYS_LOGTAG, "Starting opened ports inventory.");

    /* TCP opened ports inventory */

    pTcpTable = (MIB_TCPTABLE_OWNER_PID *) win_alloc(sizeof(MIB_TCPTABLE_OWNER_PID));

    if (pTcpTable == NULL) {
        mterror(WM_SYS_LOGTAG, "Error allocating memory for 'pTcpTable'.");
        goto end;
    }

    dwSize = sizeof(MIB_TCPTABLE_OWNER_PID);

    /* Initial call to the function to get the necessary size into the dwSize variable */
    if (dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, bOrder, AF_INET, TableClass, 0),
        dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        win_free(pTcpTable);
        pTcpTable = (MIB_TCPTABLE_OWNER_PID *) win_alloc(dwSize);
        if (pTcpTable == NULL){
            mterror(WM_SYS_LOGTAG, "Error allocating memory for 'pTcpTable'.");
            goto end;
        }
    }

    /* Second call with the right size of the returned table */
    if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, bOrder, AF_INET, TableClass, 0)) == NO_ERROR){

        for (i=0; i < (int) pTcpTable->dwNumEntries; i++){

            listening = 0;

            cJSON *object = cJSON_CreateObject();
            cJSON *port = cJSON_CreateObject();
            cJSON_AddStringToObject(object, "type", "port");
            cJSON_AddNumberToObject(object, "ID", ID);
            cJSON_AddStringToObject(object, "timestamp", timestamp);
            cJSON_AddItemToObject(object, "port", port);
            cJSON_AddStringToObject(port, "protocol", "tcp");

            ipaddress.S_un.S_addr = (u_long) pTcpTable->table[i].dwLocalAddr;
            snprintf(local_addr, NI_MAXHOST, "%s", inet_ntoa(ipaddress));

            cJSON_AddStringToObject(port, "local_ip", local_addr);
            cJSON_AddNumberToObject(port, "local_port", ntohs((u_short)pTcpTable->table[i].dwLocalPort));

            ipaddress.S_un.S_addr = (u_long) pTcpTable->table[i].dwRemoteAddr;
            snprintf(rem_addr, NI_MAXHOST, "%s", inet_ntoa(ipaddress));
            cJSON_AddStringToObject(port, "remote_ip", rem_addr);
            cJSON_AddNumberToObject(port, "remote_port", ntohs((u_short)pTcpTable->table[i].dwRemotePort));

            /* Get port state */
            char *port_state;
            port_state = get_port_state((int)pTcpTable->table[i].dwState);
            cJSON_AddStringToObject(port, "state", port_state);
            if (strncmp(port_state, "listening", 9) == 0) {
                listening = 1;
            }
            free(port_state);

            /* Get PID and process name */
            cJSON_AddNumberToObject(port, "PID", pTcpTable->table[i].dwOwningPid);

            char *pid_name;
            pid_name = get_process_name(pTcpTable->table[i].dwOwningPid);
            cJSON_AddStringToObject(port, "process", pid_name);
            free(pid_name);

            if (check_all || listening) {

                char *string;
                string = cJSON_PrintUnformatted(object);
                mtdebug2(WM_SYS_LOGTAG, "sys_ports_windows() sending '%s'", string);
                wm_sendmsg(usec, 0, string, LOCATION, SYSCOLLECTOR_MQ);
                cJSON_Delete(object);
                free(string);

            } else {
                cJSON_Delete(object);
            }
        }

    } else {
        switch(dwRetVal) {
            case ERROR_NOT_SUPPORTED:
                mtwarn(WM_SYS_LOGTAG, "TCP/IPv4 is not installed in any network interface. Unable to retrieve TCP/IPv4 port data.");
                break;
            case ERROR_NO_DATA:
                mtinfo(WM_SYS_LOGTAG, "No TCP/IPv4 network sockets open.");
                break;
            default:
                mterror(WM_SYS_LOGTAG, "Call to GetExtendedTcpTable failed with error: %lu", dwRetVal);
                break;
        }
        goto end;
    }

    /* TCP6 opened ports inventory */

    pTcp6Table = (MIB_TCP6TABLE_OWNER_PID *) win_alloc(sizeof(MIB_TCP6TABLE_OWNER_PID));

    if (pTcp6Table == NULL) {
        mterror(WM_SYS_LOGTAG, "Error allocating memory for 'pTcp6Table'.");
        goto end;
    }

    dwSize = sizeof(MIB_TCP6TABLE_OWNER_PID);

    /* Initial call to the function to get the necessary size into the dwSize variable */
    if (dwRetVal = GetExtendedTcpTable(pTcp6Table, &dwSize, bOrder, AF_INET6, TableClass, 0),
        dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        win_free(pTcp6Table);
        pTcp6Table = (MIB_TCP6TABLE_OWNER_PID *) win_alloc(dwSize);
        if (pTcp6Table == NULL){
            mterror(WM_SYS_LOGTAG, "Error allocating memory for 'pTcp6Table'.");
            goto end;
        }
    }

    /* Second call with the right size of the returned table */
    if ((dwRetVal = GetExtendedTcpTable(pTcp6Table, &dwSize, bOrder, AF_INET6, TableClass, 0)) == NO_ERROR){

        for (i=0; i < (int) pTcp6Table->dwNumEntries; i++){

            listening = 0;
            DWORD addresslen = 128;
            char laddress[128] = {'\0'};
            char raddress[128] = {'\0'};
            socklen_t socksize;

            cJSON *object = cJSON_CreateObject();
            cJSON *port = cJSON_CreateObject();
            cJSON_AddStringToObject(object, "type", "port");
            cJSON_AddNumberToObject(object, "ID", ID);
            cJSON_AddStringToObject(object, "timestamp", timestamp);
            cJSON_AddItemToObject(object, "port", port);
            cJSON_AddStringToObject(port, "protocol", "tcp6");

            struct sockaddr_in6 ipv6_local_sock;
            ipv6_local_sock.sin6_family = AF_INET6;
            for(j = 0; j < 16; j++) ipaddressv6.u.Byte[j] = pTcp6Table->table[i].ucLocalAddr[j];
            ipv6_local_sock.sin6_addr = ipaddressv6;
            ipv6_local_sock.sin6_port = (u_short)pTcp6Table->table[i].dwLocalPort;
            socksize = sizeof(ipv6_local_sock);

            if (WSAAddressToStringA((LPSOCKADDR)&ipv6_local_sock, socksize, NULL, laddress, &addresslen) == SOCKET_ERROR) {
                /* Alternate method in case of errors */
                raw_ipv6_translate(ipaddressv6.u.Byte, laddress);
            } else {
                /* Remove unnecessary data from the converted string */
                clean_wsa_conversion(laddress);
            }

            cJSON_AddStringToObject(port, "local_ip", laddress);
            cJSON_AddNumberToObject(port, "local_port", ntohs((u_short)pTcp6Table->table[i].dwLocalPort));

            struct sockaddr_in6 ipv6_remote_sock;
            ipv6_remote_sock.sin6_family = AF_INET6;
            for(j = 0; j < 16; j++) ipaddressv6.u.Byte[j] = pTcp6Table->table[i].ucRemoteAddr[j];
            ipv6_remote_sock.sin6_addr = ipaddressv6;
            ipv6_remote_sock.sin6_port = (u_short)pTcp6Table->table[i].dwRemotePort;
            socksize = sizeof(ipv6_remote_sock);

            if (WSAAddressToStringA((LPSOCKADDR)&ipv6_remote_sock, socksize, NULL, raddress, &addresslen) == SOCKET_ERROR) {
                /* Alternate method in case of errors */
                raw_ipv6_translate(ipaddressv6.u.Byte, raddress);
            } else {
                /* Remove unnecessary data from the converted string */
                clean_wsa_conversion(raddress);
            }

            cJSON_AddStringToObject(port, "remote_ip", raddress);
            cJSON_AddNumberToObject(port, "remote_port", ntohs((u_short)pTcp6Table->table[i].dwRemotePort));

            /* Get port state */
            char *port_state;
            port_state = get_port_state((int)pTcp6Table->table[i].dwState);
            cJSON_AddStringToObject(port, "state", port_state);
            if (strncmp(port_state, "listening", 9) == 0) {
                listening = 1;
            }
            free(port_state);

            /* Get PID and process name */
            cJSON_AddNumberToObject(port, "PID", pTcp6Table->table[i].dwOwningPid);

            char *pid_name;
            pid_name = get_process_name(pTcp6Table->table[i].dwOwningPid);
            cJSON_AddStringToObject(port, "process", pid_name);
            free(pid_name);

            if (check_all || listening) {
                char *string;
                string = cJSON_PrintUnformatted(object);
                mtdebug2(WM_SYS_LOGTAG, "sys_ports_windows() sending '%s'", string);
                wm_sendmsg(usec, 0, string, LOCATION, SYSCOLLECTOR_MQ);
                cJSON_Delete(object);
                free(string);
            } else {
                cJSON_Delete(object);
            }
        }

    } else {
        switch(dwRetVal) {
            case ERROR_NOT_SUPPORTED:
                mtwarn(WM_SYS_LOGTAG, "TCP/IPv6 is not installed in any network interface. Unable to retrieve TCP/IPv6 port data.");
                break;
            case ERROR_NO_DATA:
                mtdebug1(WM_SYS_LOGTAG, "No TCP/IPv6 network sockets open.");
                break;
            default:
                mterror(WM_SYS_LOGTAG, "Call to GetExtendedTcpTable failed with error: %lu", dwRetVal);
                break;
        }
        goto end;
    }

    if (!check_all) goto end;

    /* UDP opened ports inventory */

    pUdpTable = (MIB_UDPTABLE_OWNER_PID *) win_alloc(sizeof(MIB_UDPTABLE_OWNER_PID));

    if (pUdpTable == NULL) {
        mterror(WM_SYS_LOGTAG, "Error allocating memory for 'pUdpTable'.");
        goto end;
    }

    dwSize = sizeof(MIB_UDPTABLE_OWNER_PID);

    /* Initial call to the function to get the necessary size into the dwSize variable */
    if (dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, bOrder, AF_INET, TableClassUdp, 0),
        dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        win_free(pUdpTable);
        pUdpTable = (MIB_UDPTABLE_OWNER_PID *) win_alloc(dwSize);
        if (pUdpTable == NULL){
            mterror(WM_SYS_LOGTAG, "Error allocating memory for 'pUdpTable'.");
            goto end;
        }
    }

    /* Second call with the right size of the returned table */
    if ((dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, bOrder, AF_INET, TableClassUdp, 0)) == NO_ERROR){

        for (i=0; i < (int) pUdpTable->dwNumEntries; i++){

            char *string;

            cJSON *object = cJSON_CreateObject();
            cJSON *port = cJSON_CreateObject();
            cJSON_AddStringToObject(object, "type", "port");
            cJSON_AddNumberToObject(object, "ID", ID);
            cJSON_AddStringToObject(object, "timestamp", timestamp);
            cJSON_AddItemToObject(object, "port", port);
            cJSON_AddStringToObject(port, "protocol", "udp");

            ipaddress.S_un.S_addr = (u_long) pUdpTable->table[i].dwLocalAddr;
            snprintf(local_addr, NI_MAXHOST, "%s", inet_ntoa(ipaddress));

            cJSON_AddStringToObject(port, "local_ip", local_addr);
            cJSON_AddNumberToObject(port, "local_port", ntohs((u_short)pUdpTable->table[i].dwLocalPort));

            /* Get PID and process name */
            cJSON_AddNumberToObject(port, "PID", pUdpTable->table[i].dwOwningPid);

            char *pid_name;
            pid_name = get_process_name(pUdpTable->table[i].dwOwningPid);
            cJSON_AddStringToObject(port, "process", pid_name);
            free(pid_name);

            string = cJSON_PrintUnformatted(object);
            mtdebug2(WM_SYS_LOGTAG, "sys_ports_windows() sending '%s'", string);
            wm_sendmsg(usec, 0, string, LOCATION, SYSCOLLECTOR_MQ);
            cJSON_Delete(object);

            free(string);
        }

    } else {
        switch(dwRetVal) {
            case ERROR_NO_DATA:
                mtinfo(WM_SYS_LOGTAG, "No UDP/IPv4 network sockets open.");
                break;
            default:
                mterror(WM_SYS_LOGTAG, "Call to GetExtendedUdpTable failed with error: %lu", dwRetVal);
                break;
        }
        goto end;
    }

    /* UDP6 opened ports inventory */

    pUdp6Table = (MIB_UDP6TABLE_OWNER_PID *) win_alloc(sizeof(MIB_UDP6TABLE_OWNER_PID));

    if (pUdp6Table == NULL) {
        mterror(WM_SYS_LOGTAG, "Error allocating memory for 'pUdp6Table'.");
        goto end;
    }

    dwSize = sizeof(MIB_UDP6TABLE_OWNER_PID);

    /* Initial call to the function to get the necessary size into the dwSize variable */
    if (dwRetVal = GetExtendedUdpTable(pUdp6Table, &dwSize, bOrder, AF_INET6, TableClassUdp, 0),
        dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        win_free(pUdp6Table);
        pUdp6Table = (MIB_UDP6TABLE_OWNER_PID *) win_alloc(dwSize);
        if (pUdp6Table == NULL){
            mterror(WM_SYS_LOGTAG, "Error allocating memory for 'pUdp6Table'.");
            goto end;
        }
    }

    /* Second call with the right size of the returned table */
    if ((dwRetVal = GetExtendedUdpTable(pUdp6Table, &dwSize, bOrder, AF_INET6, TableClassUdp, 0)) == NO_ERROR){

        for (i=0; i < (int) pUdp6Table->dwNumEntries; i++){

            char *string;
            DWORD addresslen = 128;
            char laddress[128] = {'\0'};
            socklen_t socksize;

            cJSON *object = cJSON_CreateObject();
            cJSON *port = cJSON_CreateObject();
            cJSON_AddStringToObject(object, "type", "port");
            cJSON_AddNumberToObject(object, "ID", ID);
            cJSON_AddStringToObject(object, "timestamp", timestamp);
            cJSON_AddItemToObject(object, "port", port);
            cJSON_AddStringToObject(port, "protocol", "udp6");

            struct sockaddr_in6 ipv6_local_sock;
            ipv6_local_sock.sin6_family = AF_INET6;
            for(j = 0; j < 16; j++) ipaddressv6.u.Byte[j] = pUdp6Table->table[i].ucLocalAddr[j];
            ipv6_local_sock.sin6_addr = ipaddressv6;
            ipv6_local_sock.sin6_port = (u_short)pUdp6Table->table[i].dwLocalPort;
            socksize = sizeof(ipv6_local_sock);

            if (WSAAddressToStringA((LPSOCKADDR)&ipv6_local_sock, socksize, NULL, laddress, &addresslen) == SOCKET_ERROR) {
                /* Alternate method in case of errors */
                raw_ipv6_translate(ipaddressv6.u.Byte, laddress);
            } else {
                /* Remove unnecessary data from the converted string */
                clean_wsa_conversion(laddress);
            }

            cJSON_AddStringToObject(port, "local_ip", laddress);
            cJSON_AddNumberToObject(port, "local_port", ntohs((u_short)pUdp6Table->table[i].dwLocalPort));

            /* Get PID and process name */
            cJSON_AddNumberToObject(port, "PID", pUdp6Table->table[i].dwOwningPid);

            char *pid_name;
            pid_name = get_process_name(pUdp6Table->table[i].dwOwningPid);
            cJSON_AddStringToObject(port, "process", pid_name);
            free(pid_name);

            string = cJSON_PrintUnformatted(object);
            mtdebug2(WM_SYS_LOGTAG, "sys_ports_windows() sending '%s'", string);
            wm_sendmsg(usec, 0, string, LOCATION, SYSCOLLECTOR_MQ);
            cJSON_Delete(object);

            free(string);
        }

    } else {
        switch(dwRetVal) {
            case ERROR_NO_DATA:
                mtdebug1(WM_SYS_LOGTAG, "No UDP/IPv6 network sockets open.");
                break;
            default:
                mterror(WM_SYS_LOGTAG, "Call to GetExtendedUdpTable failed with error: %lu", dwRetVal);
                break;
        }
        goto end;
    }

end:
	/* Disable debug privilege */
	if (privilege_enabled)
	{
		if (set_token_privilege(hdle, SE_DEBUG_NAME, FALSE)) mtwarn(WM_SYS_LOGTAG, "Unable to unset debug privilege on current process (%lu).", GetLastError());
	}

	if (hdle) CloseHandle(hdle);

    if (wsa_enabled) WSACleanup();

    if (pTcpTable != NULL) win_free(pTcpTable);
    if (pTcp6Table != NULL) win_free(pTcp6Table);
    if (pUdpTable != NULL) win_free(pUdpTable);
    if (pUdp6Table != NULL) win_free(pUdp6Table);

    cJSON *object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "port_end");
    cJSON_AddNumberToObject(object, "ID", ID);
    cJSON_AddStringToObject(object, "timestamp", timestamp);

    char *string;
    string = cJSON_PrintUnformatted(object);
    mtdebug2(WM_SYS_LOGTAG, "sys_ports_windows() sending '%s'", string);
    wm_sendmsg(usec, 0, string, LOCATION, SYSCOLLECTOR_MQ);
    cJSON_Delete(object);
    free(string);
    free(timestamp);
}

// Get installed programs inventory

void sys_programs_windows(const char* LOCATION){

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    // Set timestamp
    char *timestamp = w_get_timestamp(time(NULL));

    // Set random ID for each scan

    int ID = wm_sys_get_random_id();

    mtdebug1(WM_SYS_LOGTAG, "Starting installed programs inventory.");

    HKEY main_key;
    int arch;

    // Detect Windows architecture

    os_info *info;
    if (info = get_win_version(), info) {
        mtdebug1(WM_SYS_LOGTAG, "System arch: %s", info->machine);
        if (strcmp(info->machine, "unknown") == 0 || strcmp(info->machine, "x86_64") == 0) {

            // Read 64 bits programs only in 64 bits systems

            arch = ARCH64;

            if( RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                 TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
                 0,
                 KEY_READ| KEY_WOW64_64KEY,
                 &main_key) == ERROR_SUCCESS
               ){
               mtdebug2(WM_SYS_LOGTAG, "Reading 64 bits programs from registry.");
               list_programs(main_key, arch, NULL, usec, timestamp, ID, LOCATION);
            }
            RegCloseKey(main_key);
        }
    }
    free_osinfo(info);

    // Read 32 bits programs

    arch = ARCH32;

    if( RegOpenKeyEx( HKEY_LOCAL_MACHINE,
         TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
         0,
         KEY_READ| KEY_WOW64_32KEY,
         &main_key) == ERROR_SUCCESS
       ){
       mtdebug2(WM_SYS_LOGTAG, "Reading 32 bits programs from registry.");
       list_programs(main_key, arch, NULL, usec, timestamp, ID, LOCATION);
    }
    RegCloseKey(main_key);

    // Get users list and their particular programs

    if( RegOpenKeyEx( HKEY_USERS,
         NULL,
         0,
         KEY_READ,
         &main_key) == ERROR_SUCCESS
       ){
       list_users(main_key, usec, timestamp, ID, LOCATION);
    }
    RegCloseKey(main_key);

    cJSON *object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "program_end");
    cJSON_AddNumberToObject(object, "ID", ID);
    cJSON_AddStringToObject(object, "timestamp", timestamp);

    char *string;
    string = cJSON_PrintUnformatted(object);
    mtdebug2(WM_SYS_LOGTAG, "sys_programs_windows() sending '%s'", string);
    wm_sendmsg(usec, 0, string, LOCATION, SYSCOLLECTOR_MQ);
    cJSON_Delete(object);
    free(string);
    free(timestamp);

}

// Get installed hotfixes inventory

void sys_hotfixes(const char* LOCATION){
    int usec = 1000000 / wm_max_eps;
    char *timestamp = w_get_timestamp(time(NULL));
    int ID = wm_sys_get_random_id();
    HKEY main_key;
    long unsigned int result;
    const char *HOTFIXES_REG;
    cJSON *end_evt;
    char *end_evt_str;

    HOTFIXES_REG = isVista ? WIN_REG_HOTFIX : VISTA_REG_HOTFIX;

    mtdebug1(WM_SYS_LOGTAG, "Starting installed hotfixes inventory.");

    if(result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT(HOTFIXES_REG), 0, KEY_READ | KEY_WOW64_64KEY, &main_key), result == ERROR_SUCCESS) {
        mtdebug2(WM_SYS_LOGTAG, "Reading hotfixes from the registry.");
        list_hotfixes(main_key,usec, timestamp, ID, LOCATION);
    } else {
        mterror(WM_SYS_LOGTAG, "Could not open the registry '%s'. Error: %lu.", HOTFIXES_REG, result);
    }

    end_evt = cJSON_CreateObject();
    cJSON_AddStringToObject(end_evt, "type", "hotfix_end");
    cJSON_AddNumberToObject(end_evt, "ID", ID);
    cJSON_AddStringToObject(end_evt, "timestamp", timestamp);

    end_evt_str = cJSON_PrintUnformatted(end_evt);
    mtdebug2(WM_SYS_LOGTAG, "sys_hotfixes() sending '%s'", end_evt_str);
    wm_sendmsg(usec, 0, end_evt_str, LOCATION, SYSCOLLECTOR_MQ);
    cJSON_Delete(end_evt);

    free(end_evt_str);
    free(timestamp);
    RegCloseKey(main_key);
}

// List installed programs from the registry
void list_programs(HKEY hKey, int arch, const char * root_key, int usec, const char * timestamp, int ID, const char * LOCATION) {

    TCHAR    achKey[KEY_LENGTH];   // buffer for subkey name
    DWORD    cbName;                   // size of name string
    TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name
    DWORD    cchClassName = MAX_PATH;  // size of class string
    DWORD    cSubKeys=0;               // number of subkeys
    DWORD    cbMaxSubKey;              // longest subkey size
    DWORD    cchMaxClass;              // longest class string
    DWORD    cValues;              // number of values for key
    DWORD    cchMaxValue;          // longest value name
    DWORD    cbMaxValueData;       // longest value data
    DWORD    cbSecurityDescriptor; // size of security descriptor
    FILETIME ftLastWriteTime;      // last write time

    DWORD i, retCode;

    // Get the class name and the value count
    RegQueryInfoKey(
        hKey,                    // key handle
        achClass,                // buffer for class name
        &cchClassName,           // size of class string
        NULL,                    // reserved
        &cSubKeys,               // number of subkeys
        &cbMaxSubKey,            // longest subkey size
        &cchMaxClass,            // longest class string
        &cValues,                // number of values for this key
        &cchMaxValue,            // longest value name
        &cbMaxValueData,         // longest value data
        &cbSecurityDescriptor,   // security descriptor
        &ftLastWriteTime);       // last write time

    // Enumerate the subkeys, until RegEnumKeyEx fails

    if (cSubKeys) {
        for (i=0; i<cSubKeys; i++) {

            cbName = KEY_LENGTH;
            retCode = RegEnumKeyEx(hKey, i,
                     achKey,
                     &cbName,
                     NULL,
                     NULL,
                     NULL,
                     &ftLastWriteTime);
            if (retCode == ERROR_SUCCESS) {

                char * full_key;
                os_calloc(KEY_LENGTH, sizeof(char), full_key);

                if (root_key) {
                    snprintf(full_key, KEY_LENGTH - 1, "%s\\%s", root_key, achKey);
                    read_win_program(full_key, arch, U_KEY, usec, timestamp, ID, LOCATION);
                } else {
                    snprintf(full_key, KEY_LENGTH - 1, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\%s", achKey);
                    read_win_program(full_key, arch, LM_KEY, usec, timestamp, ID, LOCATION);
                }

                free(full_key);
            } else {
                mterror(WM_SYS_LOGTAG, "Error reading key '%s'. Error code: %lu", achKey, retCode);
            }
        }
    }
}

void list_hotfixes(HKEY hKey, int usec, const char *timestamp, int ID, const char *LOCATION) {
    static OSRegex *hotfix_regex = NULL;
    HKEY subKey;
    // This table is used to discard already reported hotfixes (same key and same timestamp)
    // It does not need to be released between iterations (static variable)
    static OSHash *hotfixes_table;
    char achKey[KEY_LENGTH];   // buffer for subkey name
    long unsigned int cbName;                   // size of name string
    char achClass[MAX_PATH] = TEXT("");  // buffer for class name
    long unsigned int cchClassName = MAX_PATH;  // size of class string
    long unsigned int cSubKeys=0;               // number of subkeys
    long unsigned int cbMaxSubKey;              // longest subkey size
    long unsigned int cchMaxClass;              // longest class string
    long unsigned int cValues;              // number of values for key
    long unsigned int cchMaxValue;          // longest value name
    long unsigned int cbMaxValueData;       // longest value data
    long unsigned int cbSecurityDescriptor; // size of security descriptor
    FILETIME ftLastWriteTime;      // last write time
    long unsigned int i, result;

    result = RegQueryInfoKey(
        hKey,                    // key handle
        achClass,                // buffer for class name
        &cchClassName,           // size of class string
        NULL,                    // reserved
        &cSubKeys,               // number of subkeys
        &cbMaxSubKey,            // longest subkey size
        &cchMaxClass,            // longest class string
        &cValues,                // number of values for this key
        &cchMaxValue,            // longest value name
        &cbMaxValueData,         // longest value data
        &cbSecurityDescriptor,   // security descriptor
        &ftLastWriteTime);       // last write time

    // Exit if the number of subkeys is 0 or if not success
    if (cSubKeys == 0 || result != ERROR_SUCCESS) {
        return;
    }

    char prev_hotfix[50 + 1] = "x";

    if (!hotfix_regex) {
        const char *hotfix_pattern = "Package_\\d*\\w*for_(\\w+)~";

        os_calloc(1, sizeof(OSRegex), hotfix_regex);
        if (!OSRegex_Compile(hotfix_pattern, hotfix_regex, OS_RETURN_SUBSTRING)) {
            merror(REGEX_COMPILE, hotfix_pattern, hotfix_regex->error);
            os_free(hotfix_regex);
            return;
        }

        if (hotfixes_table = OSHash_Create(), !hotfixes_table) {
            merror_exit(MEM_ERROR, errno, strerror(errno));
        }
    }

    for (i = 0; i < cSubKeys; i++) {
        cbName = KEY_LENGTH;
        if (result = RegEnumKeyEx(hKey, i, achKey, &cbName, NULL, NULL, NULL, &ftLastWriteTime), result == ERROR_SUCCESS) {
            if (isVista) {
                //  Open the hotfix key
                result = RegOpenKeyEx(hKey, achKey, 0, KEY_READ, &subKey);
                if (result != ERROR_SUCCESS) {
                    mterror(WM_SYS_LOGTAG, "Error opening Windows registry.");
                    continue;
                }

                // Check basic stats
                if (!OSRegex_Execute(achKey, hotfix_regex) ||
                    found_hotfix_error(subKey) ||
                    !valid_hotfix_status(subKey)) {
                    RegCloseKey(subKey);
                    continue;
                }

                char *hotfix = *hotfix_regex->d_sub_strings;
                char *extension;

                // Parse hotfix
                if (strstr(hotfix, "RollupFix")) {
                    char value[MAXSTR + 1] = {0};
                    if (hotfix = parse_Rollup_hotfix(subKey, value), hotfix == NULL) {
                        RegCloseKey(subKey);
                        continue;
                    }
                
                } else if (extension = strchr(hotfix, '_'), extension) {
                    *extension = '\0';
                }

                RegCloseKey(subKey);

                // Ignore the hotfix if it is the same as the previous one
                if (!strcmp(hotfix, prev_hotfix)) {
                    continue;
                }
                snprintf(prev_hotfix, 50, hotfix);

                char *saved_timestamp;
                if (saved_timestamp = OSHash_Get(hotfixes_table, hotfix), !saved_timestamp) {
                    os_strdup(timestamp, saved_timestamp);
                    if (OSHash_Add(hotfixes_table, hotfix, saved_timestamp) != 2) {
                        free(saved_timestamp);
                        mterror(WM_SYS_LOGTAG, "Could not add '%s' to the hotfixes hash table.", hotfix);
                        return;
                    }
                } else {
                    if (!strcmp(timestamp, saved_timestamp)) {
                        // It has been reported with this timestamp
                        continue;
                    } else {
                        free(saved_timestamp);
                        os_strdup(timestamp, saved_timestamp);
                        OSHash_Update(hotfixes_table, hotfix, (char *) saved_timestamp);
                    }
                }

                send_hotfix(hotfix, usec, timestamp, ID, LOCATION);
            } else {
                // Ignore the hotfix if it is the same as the previous one
                if (!strcmp(achKey, prev_hotfix)) {
                    continue;
                }
                snprintf(prev_hotfix, KEY_LENGTH, achKey);
                send_hotfix(achKey, usec, timestamp, ID, LOCATION);
            }
        } else {
            mterror(WM_SYS_LOGTAG, "Error reading key '%s'. Error code: %lu", achKey, result);
            // Avoid infinite loops
            break;

        }
    }
}

// Retrieve the respective KB for those hotfixes which come as Rollup.
// ex -> Package_for_RollupFix~31bf3856ad364e35~amd64~~18362.959.1.9
char * parse_Rollup_hotfix(HKEY hKey, char *value) {
    DWORD dataSize = MAXSTR;
    LONG result;
    
    result = RegQueryValueEx(hKey, "InstallLocation", NULL, NULL, (LPBYTE)value, &dataSize);  
    if (result != ERROR_SUCCESS ) {
        mterror(WM_SYS_LOGTAG, "Error reading 'InstallLocation' from Windows registry. (Error %u)",(unsigned int)result);
        return NULL;
    }

    char *hotfix = NULL;
    char *start = NULL;
    char *end = NULL;

    // Parse the 'InstallLocation' field -> "Windows10.0-KB4565483-x64.cab"
    if ((start = strstr(value, "KB")) != NULL && (end = strstr(start, "-")) != NULL) {
        *end = '\0';
        hotfix = start;
    }

    return hotfix;
}

// Check if any error ocurred at installation time.
bool found_hotfix_error(HKEY hKey) {
    LONG result;
    
    // The Value only exists when an arror occurred.
    result = RegQueryValueEx(hKey, "LastError", NULL, NULL, 0, 0);  

    return (result != ERROR_SUCCESS)? false : true;
}

// Check that the hotfix is installed correctly.
bool valid_hotfix_status(HKEY hKey) {
    DWORD dataSize = sizeof(DWORD);
    DWORD value;
    LONG result;
    
    result = RegQueryValueEx(hKey, "CurrentState", NULL, NULL, (LPBYTE)&value, &dataSize);  
    if (result != ERROR_SUCCESS ) {
        mterror(WM_SYS_LOGTAG, "Error reading 'CurrentState' from Windows registry. (Error %u)",(unsigned int)result);
        return false;
    }

    if (value != HOTFIX_INSTALLED && 
        value != HOTFIX_SUPERSEDED && 
        value != HOTFIX_STAGED) {
        mtdebug2(WM_SYS_LOGTAG, "Invalid hotfix status: %ld", value);
        return false;
    }

    return true;  
}

// List Windows users from the registry
void list_users(HKEY hKey, int usec, const char * timestamp, int ID, const char * LOCATION) {

    TCHAR    achKey[KEY_LENGTH];   // buffer for subkey name
    DWORD    cbName;                   // size of name string
    TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name
    DWORD    cchClassName = MAX_PATH;  // size of class string
    DWORD    cSubKeys=0;               // number of subkeys
    DWORD    cbMaxSubKey;              // longest subkey size
    DWORD    cchMaxClass;              // longest class string
    DWORD    cValues;              // number of values for key
    DWORD    cchMaxValue;          // longest value name
    DWORD    cbMaxValueData;       // longest value data
    DWORD    cbSecurityDescriptor; // size of security descriptor
    FILETIME ftLastWriteTime;      // last write time

    int arch = NOARCH;
    DWORD i, retCode;

    // Get the class name and the value count
    RegQueryInfoKey(
        hKey,                    // key handle
        achClass,                // buffer for class name
        &cchClassName,           // size of class string
        NULL,                    // reserved
        &cSubKeys,               // number of subkeys
        &cbMaxSubKey,            // longest subkey size
        &cchMaxClass,            // longest class string
        &cValues,                // number of values for this key
        &cchMaxValue,            // longest value name
        &cbMaxValueData,         // longest value data
        &cbSecurityDescriptor,   // security descriptor
        &ftLastWriteTime);       // last write time

    // Enumerate the subkeys, until RegEnumKeyEx fails

    if (cSubKeys) {
        for (i=0; i<cSubKeys; i++) {

            // Get subkey name

            cbName = KEY_LENGTH;
            retCode = RegEnumKeyEx(hKey, i,
                     achKey,
                     &cbName,
                     NULL,
                     NULL,
                     NULL,
                     &ftLastWriteTime);
            if (retCode == ERROR_SUCCESS) {

                // For each user list its registered programs

                HKEY uKey;
                char * user_key;
                os_calloc(KEY_LENGTH, sizeof(char), user_key);
                snprintf(user_key, KEY_LENGTH - 1, "%s\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", achKey);

                if( RegOpenKeyEx( HKEY_USERS,
                     user_key,
                     0,
                     KEY_READ,
                     &uKey) == ERROR_SUCCESS
                   ){
                   list_programs(uKey, arch, user_key, usec, timestamp, ID, LOCATION);
                }

                RegCloseKey(uKey);
                free(user_key);

            } else {
                mterror(WM_SYS_LOGTAG, "Error reading key '%s'. Error code: %lu", achKey, retCode);
            }
        }
    }
}

// Get values about a single program from the registry
void read_win_program(const char * sec_key, int arch, int root_key, int usec, const char * timestamp, int ID, const char * LOCATION) {

    HKEY primary_key;
    HKEY program_key;
    DWORD cbData, ret;
    DWORD buffer_size = TOTALBYTES;
    char * program_name;
    char * version;
    char * vendor;
    char * date;
    char * location;

    if (root_key == LM_KEY)
        primary_key = HKEY_LOCAL_MACHINE;
    else
        primary_key = HKEY_USERS;

    if (arch == NOARCH)
        ret = RegOpenKeyEx(primary_key, sec_key, 0, KEY_READ, &program_key);
    else
        ret = RegOpenKeyEx(primary_key, sec_key, 0, KEY_READ | (arch == ARCH32 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), &program_key);

    if( ret == ERROR_SUCCESS) {

        // Get name of program

        os_calloc(TOTALBYTES, 1, program_name);
        cbData = buffer_size;

        ret = RegQueryValueEx(program_key, "DisplayName", NULL, NULL, (LPBYTE)program_name, &cbData);
        while (ret == ERROR_MORE_DATA) {

            // Increase buffer length

            buffer_size += BYTEINCREMENT;
            os_realloc(program_name, buffer_size, program_name);
            cbData = buffer_size;
            ret = RegQueryValueEx(program_key, "DisplayName", NULL, NULL, (LPBYTE)program_name, &cbData);
        }

        if (ret == ERROR_SUCCESS && program_name[0] != '\0') {

            cJSON *object = cJSON_CreateObject();
            cJSON *package = cJSON_CreateObject();
            cJSON_AddStringToObject(object, "type", "program");
            cJSON_AddNumberToObject(object, "ID", ID);
            cJSON_AddStringToObject(object, "timestamp", timestamp);
            cJSON_AddItemToObject(object, "program", package);
            cJSON_AddStringToObject(package, "format", "win");
            cJSON_AddStringToObject(package, "name", program_name);
            free(program_name);

            if (arch == ARCH32)
                cJSON_AddStringToObject(package, "architecture", "i686");
            else if (arch == ARCH64)
                cJSON_AddStringToObject(package, "architecture", "x86_64");
            else
                cJSON_AddStringToObject(package, "architecture", "unknown");

            // Get version

            os_calloc(TOTALBYTES, 1, version);
            cbData = buffer_size;

            ret = RegQueryValueEx(program_key, "DisplayVersion", NULL, NULL, (LPBYTE)version, &cbData);
            while (ret == ERROR_MORE_DATA) {

                // Increase buffer length

                buffer_size += BYTEINCREMENT;
                os_realloc(version, buffer_size, version);
                cbData = buffer_size;
                ret = RegQueryValueEx(program_key, "DisplayVersion", NULL, NULL, (LPBYTE)version, &cbData);
            }

            if (ret == ERROR_SUCCESS && version[0] != '\0') {
                cJSON_AddStringToObject(package, "version", version);
            }

            free(version);

            // Get vendor

            os_calloc(TOTALBYTES, 1, vendor);
            cbData = buffer_size;

            ret = RegQueryValueEx(program_key, "Publisher", NULL, NULL, (LPBYTE)vendor, &cbData);
            while (ret == ERROR_MORE_DATA) {

                // Increase buffer length

                buffer_size += BYTEINCREMENT;
                os_realloc(vendor, buffer_size, vendor);
                cbData = buffer_size;
                ret = RegQueryValueEx(program_key, "Publisher", NULL, NULL, (LPBYTE)vendor, &cbData);
            }

            if (ret == ERROR_SUCCESS && vendor[0] != '\0') {
                cJSON_AddStringToObject(package, "vendor", vendor);
            }

            free(vendor);

            // Get install date

            os_calloc(TOTALBYTES, 1, date);
            cbData = buffer_size;

            ret = RegQueryValueEx(program_key, "InstallDate", NULL, NULL, (LPBYTE)date, &cbData);
            while (ret == ERROR_MORE_DATA) {

                // Increase buffer length

                buffer_size += BYTEINCREMENT;
                os_realloc(date, buffer_size, date);
                cbData = buffer_size;
                ret = RegQueryValueEx(program_key, "InstallDate", NULL, NULL, (LPBYTE)date, &cbData);
            }

            if (ret == ERROR_SUCCESS && date[0] != '\0') {
                cJSON_AddStringToObject(package, "install_time", date);
            }

            free(date);

            // Get install location

            os_calloc(TOTALBYTES, 1, location);
            cbData = buffer_size;

            ret = RegQueryValueEx(program_key, "InstallLocation", NULL, NULL, (LPBYTE)location, &cbData);
            while (ret == ERROR_MORE_DATA) {

                // Increase buffer length

                buffer_size += BYTEINCREMENT;
                os_realloc(location, buffer_size, location);
                cbData = buffer_size;
                ret = RegQueryValueEx(program_key, "InstallLocation", NULL, NULL, (LPBYTE)location, &cbData);
            }

            if (ret == ERROR_SUCCESS && location[0] != '\0') {
                cJSON_AddStringToObject(package, "location", location);
            }

            free(location);

            char *string;
            string = cJSON_PrintUnformatted(object);
            mtdebug2(WM_SYS_LOGTAG, "sys_programs_windows() sending '%s'", string);
            wm_sendmsg(usec, 0, string, LOCATION, SYSCOLLECTOR_MQ);
            cJSON_Delete(object);
            free(string);

        } else
            free(program_name);

    } else {
        mterror(WM_SYS_LOGTAG, "Unable to read key: (Error code %lu)", ret);
    }

    RegCloseKey(program_key);
}

void send_hotfix(const char *hotfix, int usec, const char *timestamp, int ID, const char *LOCATION) {
    if (!strcmp(hotfix, "RollupFix")) {
        return;
    }

    cJSON *event;
    if (event = cJSON_CreateObject(), !event) {
        mterror(WM_SYS_LOGTAG, "Could not create the hotfix event.");
        return;
    }
    cJSON_AddStringToObject(event, "type", "hotfix");
    cJSON_AddNumberToObject(event, "ID", ID);
    cJSON_AddStringToObject(event, "timestamp", timestamp);
    cJSON_AddStringToObject(event, "hotfix", hotfix);

    char *str_event = cJSON_PrintUnformatted(event);
    mtdebug2(WM_SYS_LOGTAG, "sys_hotfixes() sending '%s'", str_event);
    wm_sendmsg(usec, 0, str_event, LOCATION, SYSCOLLECTOR_MQ);
    cJSON_Delete(event);
    free(str_event);
}

void sys_hw_windows(const char* LOCATION){
    // Set timestamp
    char *timestamp = w_get_timestamp(time(NULL));

    // Set random ID for each scan

    int ID = wm_sys_get_random_id();

    mtdebug1(WM_SYS_LOGTAG, "Starting hardware inventory.");

    cJSON *object = cJSON_CreateObject();
    cJSON *hw_inventory = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "hardware");
    cJSON_AddNumberToObject(object, "ID", ID);
    cJSON_AddStringToObject(object, "timestamp", timestamp);
    cJSON_AddItemToObject(object, "inventory", hw_inventory);

    /* Call get_baseboard_serial function through syscollector DLL */
    char *serial = NULL;

    if(checkVista()) {

        CallFunc1 _get_baseboard_serial;
        HMODULE sys_library = LoadLibrary("syscollector_win_ext.dll");
        if (sys_library == NULL)
        {
            DWORD error = GetLastError();
            LPSTR messageBuffer = NULL;
            LPSTR end;

            FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error, 0, (LPTSTR) &messageBuffer, 0, NULL);

            if (end = strchr(messageBuffer, '\r'), end) *end = '\0';

            mterror(WM_SYS_LOGTAG, "Unable to load syscollector_win_ext.dll: %s (%lu).", messageBuffer, error);
            LocalFree(messageBuffer);

        } else {
            _get_baseboard_serial = (CallFunc1)GetProcAddress(sys_library, "get_baseboard_serial");
            if (!_get_baseboard_serial) {
                mterror(WM_SYS_LOGTAG, "Unable to access 'get_baseboard_serial' on syscollector_win_ext.dll.");
            } else {
                int ret = _get_baseboard_serial(&serial);
                switch(ret)
                {
                    case 1:
                        mtwarn(WM_SYS_LOGTAG, "Unable to get raw SMBIOS firmware table size.");
                        break;
                    case 2:
                        mtwarn(WM_SYS_LOGTAG, "Unable to allocate memory for the SMBIOS firmware table.");
                        break;
                    case 3:
                        mtwarn(WM_SYS_LOGTAG, "Unable to get the SMBIOS firmware table.");
                        break;
                    case 4:
                        mtdebug1(WM_SYS_LOGTAG, "Serial Number not available in SMBIOS firmware table.");
                        break;
                    default:
                        break;
                }
            }
        }
        if(sys_library) {
            FreeLibrary(sys_library);
        }
    } else {

        char *command;
        char *end;
        FILE *output;
        char read_buff[SERIAL_LENGTH];
        int status;

        memset(read_buff, 0, SERIAL_LENGTH);
        command = "wmic baseboard get SerialNumber";
        output = popen(command, "r");
        if (!output){
            mtwarn(WM_SYS_LOGTAG, "Unable to execute command '%s'.", command);
        } else {
            if (fgets(read_buff, SERIAL_LENGTH, output)) {
                if (strncmp(read_buff ,"SerialNumber", 12) == 0) {
                    if (!fgets(read_buff, SERIAL_LENGTH, output)){
                        mtwarn(WM_SYS_LOGTAG, "Unable to get Motherboard Serial Number.");
                    }
                    else if (end = strpbrk(read_buff,"\r\n"), end) {
                        *end = '\0';
                        int i = strlen(read_buff) - 1;
                        while(read_buff[i] == 32){
                            read_buff[i] = '\0';
                            i--;
                        }
                        os_strdup(read_buff, serial);
                    }
                }
            } else {
                mtdebug1(WM_SYS_LOGTAG, "Unable to get Motherboard Serial Number (bad header).");
            }

            if (status = pclose(output), status) {
                mtwarn(WM_SYS_LOGTAG, "Command 'wmic' returned %d getting board serial.", status);
            }
        }
    }

    if (serial) {
        cJSON_AddStringToObject(hw_inventory, "board_serial", serial);
        free(serial);
    }

    /* Get CPU and memory information */
    hw_info *sys_info;
    if (sys_info = get_system_windows(), sys_info){
        if (sys_info->cpu_name)
            cJSON_AddStringToObject(hw_inventory, "cpu_name", w_strtrim(sys_info->cpu_name));
        if (sys_info->cpu_cores)
            cJSON_AddNumberToObject(hw_inventory, "cpu_cores", sys_info->cpu_cores);
        if (sys_info->cpu_MHz)
            cJSON_AddNumberToObject(hw_inventory, "cpu_MHz", sys_info->cpu_MHz);
        if (sys_info->ram_total)
            cJSON_AddNumberToObject(hw_inventory, "ram_total", sys_info->ram_total);
        if (sys_info->ram_free)
            cJSON_AddNumberToObject(hw_inventory, "ram_free", sys_info->ram_free);
        if (sys_info->ram_usage)
            cJSON_AddNumberToObject(hw_inventory, "ram_usage", sys_info->ram_usage);

        os_free(sys_info->cpu_name);
        free(sys_info);
    }

    /* Send interface data in JSON format */
    char *string = cJSON_PrintUnformatted(object);
    mtdebug2(WM_SYS_LOGTAG, "sys_hw_windows() sending '%s'", string);
    SendMSG(0, string, LOCATION, SYSCOLLECTOR_MQ);
    cJSON_Delete(object);

    free(string);
    free(timestamp);

}

void sys_os_windows(const char* LOCATION){

    char *string;

    // Set timestamp

    char *timestamp = w_get_timestamp(time(NULL));

    // Set random ID for each scan

    int ID = wm_sys_get_random_id();

    mtdebug1(WM_SYS_LOGTAG, "Starting Operating System inventory.");

    cJSON *object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "OS");
    cJSON_AddNumberToObject(object, "ID", ID);
    cJSON_AddStringToObject(object, "timestamp", timestamp);

    cJSON *os_inventory = getunameJSON();

    cJSON_AddItemToObject(object, "inventory", os_inventory);

    /* Send interface data in JSON format */
    string = cJSON_PrintUnformatted(object);
    mtdebug2(WM_SYS_LOGTAG, "sys_os_windows() sending '%s'", string);
    SendMSG(0, string, LOCATION, SYSCOLLECTOR_MQ);
    cJSON_Delete(object);

    free(string);
    free(timestamp);
}

/* Get broadcast address from IPv4 address and netmask */
/* WSAAddressToStringA() and WSAStringToAddressA() are used to provide compatibility with XP */
char* get_broadcast_addr_xp(char* ip, char* netmask) {
    socklen_t socksize;
    struct sockaddr_in host, mask, broadcast;
    DWORD addresslen = NI_MAXHOST;

    socksize = sizeof(host);
    if (WSAStringToAddressA(ip, AF_INET, NULL, (LPSOCKADDR)&host, &socksize) == SOCKET_ERROR) {
        mterror(WM_SYS_LOGTAG, "WSAStringToAddressA() failed with IPv4 address (%d).", WSAGetLastError());
        return NULL;
    }

    socksize = sizeof(mask);
    if (WSAStringToAddressA(netmask, AF_INET, NULL, (LPSOCKADDR)&mask, &socksize) == SOCKET_ERROR) {
        mterror(WM_SYS_LOGTAG, "WSAStringToAddressA() failed with IPv4 netmask (%d).", WSAGetLastError());
        return NULL;
    }

    broadcast.sin_family = AF_INET;
    broadcast.sin_addr.S_un.S_addr = (host.sin_addr.S_un.S_addr | ~(mask.sin_addr.S_un.S_addr));
    socksize = sizeof(broadcast);

    char* broadcast_addr = calloc(addresslen, sizeof(char));
    if (!broadcast_addr) {
        mterror(WM_SYS_LOGTAG, "Cannot allocate memory for address conversion.");
        return NULL;
    }

    if (WSAAddressToStringA((LPSOCKADDR)&broadcast, socksize, NULL, broadcast_addr, &addresslen) == SOCKET_ERROR) {
        mterror(WM_SYS_LOGTAG, "Cannot allocate memory for address conversion.");
        sprintf(broadcast_addr, "unknown");
    } else {
        /* Remove port from output address */
        char *pch = strrchr(broadcast_addr, ':');
        if (pch != NULL) *pch = '\0';
    }

    return broadcast_addr;
}

char* get_network_xp(PIP_ADAPTER_ADDRESSES pCurrAddresses, PIP_ADAPTER_INFO AdapterInfo, int ID, char * timestamp) {
    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
    PIP_ADAPTER_INFO currAdapterInfo = NULL;
    PIP_ADDR_STRING currIP = NULL;

    char *string;
    unsigned int i = 0;
    char host[NI_MAXHOST];
    char ipv4addr[NI_MAXHOST];
    DWORD addresslen = NI_MAXHOST;

    struct in_addr ipaddress;
    struct sockaddr_in6 *addr6;
    socklen_t socksize;

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
    if (mtu != 0) cJSON_AddNumberToObject(iface_info, "MTU", mtu);

    cJSON *ipv4 = cJSON_CreateObject();
    cJSON *ipv4_addr = cJSON_CreateArray();
    cJSON *ipv4_netmask = cJSON_CreateArray();
    cJSON *ipv4_broadcast = cJSON_CreateArray();

    cJSON *ipv6 = cJSON_CreateObject();
    cJSON *ipv6_addr = cJSON_CreateArray();

    /* Get network stats */
    DWORD retVal = 0;

    /* XP SP3 or less: uses 32-bit unsigned integers */
    MIB_IFROW ifRow;
    SecureZeroMemory((PVOID) &ifRow, sizeof(MIB_IFROW));

    ifRow.dwIndex = pCurrAddresses->IfIndex;
    if (ifRow.dwIndex == 0) ifRow.dwIndex = pCurrAddresses->Ipv6IfIndex;

    /* Only get this information if we have a valid interface index */
    if (ifRow.dwIndex != 0) {
        retVal = GetIfEntry(&ifRow);
        if (retVal == NO_ERROR) {
            ULONG64 tx_packets = ifRow.dwOutUcastPkts + ifRow.dwOutNUcastPkts;
            ULONG64 rx_packets = ifRow.dwInUcastPkts + ifRow.dwInNUcastPkts;

            cJSON_AddNumberToObject(iface_info, "tx_packets", tx_packets);
            cJSON_AddNumberToObject(iface_info, "rx_packets", rx_packets);
            cJSON_AddNumberToObject(iface_info, "tx_bytes", ifRow.dwOutOctets);
            cJSON_AddNumberToObject(iface_info, "rx_bytes", ifRow.dwInOctets);
            cJSON_AddNumberToObject(iface_info, "tx_errors", ifRow.dwOutErrors);
            cJSON_AddNumberToObject(iface_info, "rx_errors", ifRow.dwInErrors);
            cJSON_AddNumberToObject(iface_info, "tx_dropped", ifRow.dwOutDiscards);
            cJSON_AddNumberToObject(iface_info, "rx_dropped", ifRow.dwInDiscards);
        }
    }

    /* Initialize the Winsock DLL */
    WSADATA wsd;
    int wsa_enabled = 0;
    if (WSAStartup(MAKEWORD(2,2), &wsd) != 0) {
        mterror(WM_SYS_LOGTAG, "Unable to initialize Winsock DLL (%d).", WSAGetLastError());
        goto finish;
    }
    wsa_enabled = 1;

    /* Extract IPv4 and IPv6 addresses */
	char *broadcast = NULL;
    pUnicast = pCurrAddresses->FirstUnicastAddress;

    if (pUnicast){
        for (i=0; pUnicast != NULL; i++){
            if (pUnicast->Address.lpSockaddr->sa_family == AF_INET){
                /* We use the output from GetAdaptersInfo() to collect the network mask from IPv4 interfaces retrieved using GetAdaptersAddresses() */
                /* Under XP, it isn't possible to retrieve IP prefix values (to calculate network masks) nor gateway addresses using GetAdaptersAddresses() */
                /* However, the FriendlyName field is not returned by GetAdaptersInfo(), hence why both functions are used */

                /* A lookup is performed on the IP_ADAPTER_INFO struct array retrieved using GetAdaptersInfo() */
                /* We need to find a struct in that array that matches both the interface index from our current IP_ADAPTER_ADDRESSES struct, and the IPv4 address from our current IP_ADAPTER_UNICAST_ADDRESS struct */
                /* If such element is found, we can use the network mask from that struct right away. Afterwards, get_broadcast_addr_xp() is used to get the broadcast address */
                /* Otherwise, network mask retrieval is skipped under Windows XP, along with the broadcast address */

                /* Convert the IPv4 address to a string */
                /* inet_ntoa() is used to provide compatibility with XP */
                ipaddress = ((struct sockaddr_in*)(pUnicast->Address.lpSockaddr))->sin_addr;
                snprintf(host, NI_MAXHOST, "%s", inet_ntoa(ipaddress));
                cJSON_AddItemToArray(ipv4_addr, cJSON_CreateString(host));
                snprintf(ipv4addr, NI_MAXHOST, "%s", host);

                /* Locate this network interface in the IP_ADAPTER_INFO struct array */
                currAdapterInfo = AdapterInfo;
                while(currAdapterInfo) {
                    /* Ignore Loopback interface */
                    if (currAdapterInfo->Type == MIB_IF_TYPE_LOOPBACK){
                        currAdapterInfo = currAdapterInfo->Next;
                        continue;
                    }

                    /* Ignore interfaces that don't match the index from our current one */
                    if (currAdapterInfo->Index == pCurrAddresses->IfIndex) {
                        /* Found an interface match. Now let's look for an IPv4 address match */
                        currIP = &(currAdapterInfo->IpAddressList);

                        while(currIP) {
                            if (!strncmp(ipv4addr, currIP->IpAddress.String, strlen(ipv4addr))) break;
                            currIP = currIP->Next;
                        }

                        break;
                    }

                    currAdapterInfo = currAdapterInfo->Next;
                }

                if (currIP) {
                    /* We found a full match. Let's get the network mask right away */
                    snprintf(host, NI_MAXHOST, "%s", currIP->IpMask.String);
                    cJSON_AddItemToArray(ipv4_netmask, cJSON_CreateString(host));

                    /* Get the broadcast address only if we already retrieved the network mask */
                    broadcast = get_broadcast_addr_xp(ipv4addr, host);
                    if (broadcast) {
                        cJSON_AddItemToArray(ipv4_broadcast, cJSON_CreateString(broadcast));
                        free(broadcast);
                        broadcast = NULL;
                    }
                } else {
                    mtwarn(WM_SYS_LOGTAG, "Unable to locate network interface with index '%lu' and IP '%s' in IPv4 addresses table. Network mask and broadcast address cannot be retrieved.", pCurrAddresses->IfIndex, ipv4addr);
                }

                currIP = NULL;
                currAdapterInfo = NULL;
            } else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
                /* GetIpAddrTable() is not capable of retrieving data from IPv6 interfaces under XP */
                /* In this case, we can't get a lookup table from any other function */
                /* We can only get the IPv6 address under XP at leave it at that */
                addr6 = (struct sockaddr_in6 *) pUnicast->Address.lpSockaddr;
                socksize = sizeof(addr6);

                /* WSAAddressToStringA() is used to provide compatibility with XP */
                if (WSAAddressToStringA((LPSOCKADDR)addr6, socksize, NULL, host, &addresslen) == SOCKET_ERROR) {
                    /* Alternate method in case of errors */
                    raw_ipv6_translate(addr6->sin6_addr.u.Byte, host);
                } else {
                    /* Remove unnecessary data from the converted string */
                    clean_wsa_conversion(host);
                }

                cJSON_AddItemToArray(ipv6_addr, cJSON_CreateString(host));
            }

            pUnicast = pUnicast->Next;
        }
    }

    /* Under Windows XP, the only way to retrieve IPv4 gateway addresses is through GetAdaptersInfo() */
    /* We'll use its data as another lookup table */
    currAdapterInfo = AdapterInfo;
    while (currAdapterInfo) {
        /* Ignore Loopback interface */
        if (currAdapterInfo->Type == MIB_IF_TYPE_LOOPBACK){
            currAdapterInfo = currAdapterInfo->Next;
            continue;
        }

        /* Ignore interfaces that don't match the index from our current one */
        if (currAdapterInfo->Index == pCurrAddresses->IfIndex) {
            /* Found an interface match. Now let's retrieve all the gateway addresses for this interface */
            currIP = &(currAdapterInfo->GatewayList);

            while(currIP) {
                snprintf(host, NI_MAXHOST, "%s", currIP->IpAddress.String);
                cJSON_AddStringToObject(ipv4, "gateway", host);
                currIP = currIP->Next;
            }

            break;
        }

        currAdapterInfo = currAdapterInfo->Next;
    }

finish:
    if (wsa_enabled) WSACleanup();

    if ((pCurrAddresses->Flags & IP_ADAPTER_DHCP_ENABLED) && (pCurrAddresses->IfIndex != 0)) {
        cJSON_AddStringToObject(ipv4, "DHCP", "enabled");
    }else{
        cJSON_AddStringToObject(ipv4, "DHCP", "disabled");
    }

    if ((pCurrAddresses->Flags & IP_ADAPTER_DHCP_ENABLED) && (pCurrAddresses->Ipv6IfIndex != 0)){
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
        cJSON_AddItemToObject(iface_info, "IPv6", ipv6);
    } else {
        cJSON_Delete(ipv6_addr);
        cJSON_Delete(ipv6);
    }

    string = cJSON_PrintUnformatted(object);
    cJSON_Delete(object);
    return string;
}

/* Network inventory for Windows systems */
void sys_network_windows(const char* LOCATION){
    mtdebug1(WM_SYS_LOGTAG, "Starting network inventory.");

    DWORD dwRetVal = 0;

    /* Load DLL with network inventory functions */
    HMODULE sys_library = NULL;
    CallFunc _get_network_vista = NULL;

    if (checkVista()) {
        sys_library = LoadLibrary("syscollector_win_ext.dll");
        if (sys_library != NULL){
            _get_network_vista = (CallFunc)(void *)GetProcAddress(sys_library, "get_network_vista");
            if (!_get_network_vista){
                dwRetVal = GetLastError();
                mterror(WM_SYS_LOGTAG, "Unable to access 'get_network_vista' on syscollector_win_ext.dll.");
            }
            FreeLibrary(sys_library);
        } else {
            dwRetVal = GetLastError();
            LPSTR messageBuffer = NULL;
            LPSTR end;

            FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwRetVal, 0, (LPTSTR) &messageBuffer, 0, NULL);

            if (end = strchr(messageBuffer, '\r'), end) {
                *end = '\0';
            }

            mterror(WM_SYS_LOGTAG, "Unable to load syscollector_win_ext.dll: %s (%lu)", messageBuffer, dwRetVal);
            LocalFree(messageBuffer);
        }
    }

    if (dwRetVal != NO_ERROR) return;

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    // Set random ID and timestamp

    int ID = wm_sys_get_random_id();

    char *timestamp = w_get_timestamp(time(NULL));

    /* Set the flags to pass to GetAdaptersAddresses() */
    ULONG flags = (checkVista() ? (GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS) : 0);

    LPVOID lpMsgBuf = NULL;

    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG outBufLen = 0;
    ULONG Iterations = 0;

    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;

    PIP_ADAPTER_INFO AdapterInfo = NULL;

    /* Allocate a 15 KB buffer to start with */
    outBufLen = WORKING_BUFFER_SIZE;

    do {
        pAddresses = (IP_ADAPTER_ADDRESSES *) win_alloc(outBufLen);

        if (pAddresses == NULL) {
            mterror_exit(WM_SYS_LOGTAG, "Memory allocation failed for IP_ADAPTER_ADDRESSES struct.");
        }

        dwRetVal = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen);

        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            win_free(pAddresses);
            pAddresses = NULL;
        } else {
            break;
        }

        Iterations++;
    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

    if (dwRetVal == NO_ERROR) {
        if (!checkVista()) {
            /* Retrieve additional data from IPv4 interfaces using GetAdaptersInfo() (under XP) */
            Iterations = 0;
            outBufLen = WORKING_BUFFER_SIZE;

            do {
                AdapterInfo = (IP_ADAPTER_INFO *) win_alloc(outBufLen);

                if (AdapterInfo == NULL) {
                    mterror_exit(WM_SYS_LOGTAG, "Memory allocation failed for IP_ADAPTER_INFO struct.");
                }

                dwRetVal = GetAdaptersInfo(AdapterInfo, &outBufLen);

                if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
                    win_free(AdapterInfo);
                    AdapterInfo = NULL;
                } else {
                    break;
                }

                Iterations++;
            } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

            if (dwRetVal != NO_ERROR) {
                mterror(WM_SYS_LOGTAG, "Extracting network adapter information (%lu).", dwRetVal);
                if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL, dwRetVal, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                        // Default language
                        (LPTSTR) & lpMsgBuf, 0, NULL)) {
                    mterror(WM_SYS_LOGTAG, "%s", (char *)lpMsgBuf);
                    LocalFree(lpMsgBuf);
                }
            }
        }

        if (dwRetVal == NO_ERROR) {
            pCurrAddresses = pAddresses;
            while (pCurrAddresses) {
                /* Ignore Loopback interface */
                if (pCurrAddresses->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
                    pCurrAddresses = pCurrAddresses->Next;
                    continue;
                }

                /* Ignore interfaces without valid IPv4/IPv6 indexes */
                if (pCurrAddresses->IfIndex == 0 && pCurrAddresses->Ipv6IfIndex == 0) {
                    pCurrAddresses = pCurrAddresses->Next;
                    continue;
                }

                char* string;

                if (checkVista()) {
                    /* Call function get_network_vista() in syscollector_win_ext.dll */
                    if(_get_network_vista) {
                        string = _get_network_vista(pCurrAddresses, ID, timestamp);
                    }
                    else {
                        os_strdup("UNKNOWN",string);
                    }
                } else {
                    /* Call function get_network_xp() */
                    string = get_network_xp(pCurrAddresses, AdapterInfo, ID, timestamp);
                }

                mtdebug2(WM_SYS_LOGTAG, "sys_network_windows() sending '%s'", string);
                wm_sendmsg(usec, 0, string, LOCATION, SYSCOLLECTOR_MQ);

                free(string);

                pCurrAddresses = pCurrAddresses->Next;
            }
        }
    } else {
        mterror(WM_SYS_LOGTAG, "Extraction of network adresses failed (%lu).", dwRetVal);
        if (dwRetVal == ERROR_NO_DATA) {
            mterror(WM_SYS_LOGTAG, "No addresses were found for the requested parameters.");
        } else {
            if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                    NULL, dwRetVal, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    // Default language
                    (LPTSTR) & lpMsgBuf, 0, NULL)) {
                mterror(WM_SYS_LOGTAG, "Error: %s", (char *)lpMsgBuf);
                LocalFree(lpMsgBuf);
            }
        }
    }

    if (AdapterInfo) {
        win_free(AdapterInfo);
    }

    if (pAddresses) {
        win_free(pAddresses);
    }

    cJSON *object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "network_end");
    cJSON_AddNumberToObject(object, "ID", ID);
    cJSON_AddStringToObject(object, "timestamp", timestamp);

    char *string;
    string = cJSON_PrintUnformatted(object);
    mtdebug2(WM_SYS_LOGTAG, "sys_network_windows() sending '%s'", string);
    wm_sendmsg(usec, 0, string, LOCATION, SYSCOLLECTOR_MQ);
    cJSON_Delete(object);
    free(string);
    free(timestamp);
}

hw_info *get_system_windows(){

    hw_info *info;
    DWORD retVal;
    HKEY RegistryKey;
    char subkey[KEY_LENGTH];
    TCHAR name[MAX_VALUE_NAME];
    DWORD frequency = 0;
    DWORD dwCount = MAX_VALUE_NAME;

    os_calloc(1,sizeof(hw_info),info);
    init_hw_info(info);

    // Get CPU name and frequency

    snprintf(subkey, KEY_LENGTH - 1, "%s", "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0");

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &RegistryKey) != ERROR_SUCCESS) {
        info->cpu_name = strdup("unknown");
        mterror(WM_SYS_LOGTAG, SK_REG_OPEN, subkey);
    } else {
        retVal = RegQueryValueEx(RegistryKey, TEXT("ProcessorNameString"), NULL, NULL, (LPBYTE)&name, &dwCount);
        if (retVal != ERROR_SUCCESS) {
            info->cpu_name = strdup("unknown");
            mterror(WM_SYS_LOGTAG, "Reading 'CPU name' from Windows registry. (Error %u)",(unsigned int)retVal);
        } else {
            info->cpu_name = strdup(name);
        }
        retVal = RegQueryValueEx(RegistryKey, TEXT("~MHz"), NULL, NULL, (LPBYTE)&frequency, &dwCount);
        if (retVal != ERROR_SUCCESS) {
            mterror(WM_SYS_LOGTAG, "Reading 'CPU frequency' from Windows registry. (Error %u)",(unsigned int)retVal);
        } else {
            info->cpu_MHz = (unsigned int)frequency;
        }
        RegCloseKey(RegistryKey);
    }

    // Get number of cores

    SYSTEM_INFO siSysInfo;

    GetSystemInfo(&siSysInfo);
    info->cpu_cores = (int)siSysInfo.dwNumberOfProcessors;

    // RAM memory

    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof (statex);

    if (!GlobalMemoryStatusEx(&statex)) {
        DWORD error = GetLastError();
        LPSTR messageBuffer = NULL;
        LPSTR end;

        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error, 0, (LPTSTR) &messageBuffer, 0, NULL);

        if (end = strchr(messageBuffer, '\r'), end) {
            *end = '\0';
        }

        mterror(WM_SYS_LOGTAG, "Unable to call GlobalMemoryStatusEx(): %s (%lu)", messageBuffer, error);
        LocalFree(messageBuffer);
    } else {
        info->ram_total = statex.ullTotalPhys/1024;
        info->ram_free = statex.ullAvailPhys/1024;
        info->ram_usage = statex.dwMemoryLoad;
    }

    return info;
}

int ntpath_to_win32path(char *ntpath, char **outbuf)
{
	int success = 0;
	DWORD res = 0, len = 0;
	char *SingleDrive = NULL;
	char LogicalDrives[OS_MAXSTR] = {0}, read_buff[OS_MAXSTR] = {0}, msdos_drive[3] = { '\0', ':', '\0' };

	if (ntpath == NULL) return success;

	/* Get the total amount of available logical drives */
	/* The input size must not include the NULL terminator */
	res = GetLogicalDriveStrings(OS_MAXSTR - 1, LogicalDrives);
	if (res <= 0 || res > OS_MAXSTR)
	{
		mtwarn(WM_SYS_LOGTAG, "Unable to parse logical drive strings. Error '%lu'.", GetLastError());
		return success;
	}

	/* Perform a loop of the retrieved drive list */
	SingleDrive = LogicalDrives;
	while(*SingleDrive)
	{
		/* Get the MS-DOS drive letter */
		*msdos_drive = *SingleDrive;

		/* Retrieve the Windows kernel path for this drive */
		res = QueryDosDevice(msdos_drive, read_buff, OS_MAXSTR);
		if (res)
		{
			/* Check if this is the drive we're looking for */
			if (!strncmp(ntpath, read_buff, strlen(read_buff)))
			{
				/* Calculate new string length (making sure there's space left for the NULL terminator) */
				len = (strlen(ntpath) - strlen(read_buff) + 3);

				/* Allocate memory */
                os_calloc(len, 1, *outbuf);

                /* Copy the new filepath */
                snprintf(*outbuf, len, "%s%s", msdos_drive, ntpath + strlen(read_buff));
                success = 1;

				break;
			}
		} else {
			mtwarn(WM_SYS_LOGTAG, "Unable to retrieve Windows kernel path for drive '%s\\'. Error '%lu'", msdos_drive, GetLastError());
		}

		/* Get the next drive */
		SingleDrive += (strlen(SingleDrive) + 1);
	}

	if (!success) mtwarn(WM_SYS_LOGTAG, "Unable to find a matching Windows kernel drive path for '%s'", ntpath);

	return success;
}

void sys_proc_windows(const char* LOCATION) {
    char read_buff[OS_MAXSTR];

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    // Set timestamp

    char *timestamp = w_get_timestamp(time(NULL));

    // Set random ID for each scan

    int ID = wm_sys_get_random_id();

    cJSON *item;
    cJSON *proc_array = cJSON_CreateArray();

    mtdebug1(WM_SYS_LOGTAG, "Starting running processes inventory.");

	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot, hProcess;
	FILETIME lpCreationTime, lpExitTime, lpKernelTime, lpUserTime;
	PROCESS_MEMORY_COUNTERS ppsmemCounters;

	LONG priority;
	char *exec_path, *name;
	ULARGE_INTEGER kernel_mode_time, user_mode_time;
	DWORD pid, parent_pid, session_id, thread_count, page_file_usage, virtual_size;

	HANDLE hdle;
	int privilege_enabled = 0;

	/* Enable debug privilege */
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hdle))
	{
		if (!set_token_privilege(hdle, SE_DEBUG_NAME, TRUE))
		{
			privilege_enabled = 1;
		} else {
			mtwarn(WM_SYS_LOGTAG, "Unable to set debug privilege on current process (%lu).", GetLastError());
		}
	} else {
		mtwarn(WM_SYS_LOGTAG, "Unable to retrieve current process token (%lu).", GetLastError());
	}

	/* Create a snapshot of all current processes */
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		if (Process32First(hSnapshot, &pe))
		{
			do {
				/* Get process ID */
				pid = pe.th32ProcessID;

				/* Get thread count */
				thread_count = pe.cntThreads;

				/* Get parent process ID */
				parent_pid = pe.th32ParentProcessID;

				/* Get process base priority */
				priority = pe.pcPriClassBase;

				/* Initialize variables */
				name = exec_path = NULL;
				kernel_mode_time.QuadPart = user_mode_time.QuadPart = 0;
				session_id = page_file_usage = virtual_size = 0;

				/* Check if we are dealing with a system process */
				if (pid == 0 || pid == 4)
				{
					name = strdup(pid == 0 ? "System Idle Process" : "System");
					exec_path = strdup("none");
				} else {
					/* Get process name */
					name = strdup(pe.szExeFile);

					/* Get process handle */
					hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
					if (hProcess != NULL)
					{
						/* Get full Windows kernel path for the process */
						if (GetProcessImageFileName(hProcess, read_buff, OS_MAXSTR))
						{
							/* Convert Windows kernel path to a valid Win32 filepath */
							/* E.g.: "\Device\HarddiskVolume1\Windows\system32\notepad.exe" -> "C:\Windows\system32\notepad.exe" */
                            /* This requires hotfix KB931305 in order to work under XP/Server 2003, so the conversion will be skipped if we're not running under Vista or greater */
							if (!checkVista() || !ntpath_to_win32path(read_buff, &exec_path))
							{
								/* If there were any errors, the read_buff array will remain intact */
								/* In that case, let's just use the Windows kernel path. It's better than nothing */
								exec_path = strdup(read_buff);
							}
						} else {
							mtwarn(WM_SYS_LOGTAG, "Unable to retrieve executable path from process with PID %lu (%lu).", pid, GetLastError());
							exec_path = strdup("unknown");
						}

						/* Get kernel mode and user mode times */
						if (GetProcessTimes(hProcess, &lpCreationTime, &lpExitTime, &lpKernelTime, &lpUserTime))
						{
							/* Copy the kernel mode filetime high and low parts and convert it to seconds */
							kernel_mode_time.LowPart = lpKernelTime.dwLowDateTime;
							kernel_mode_time.HighPart = lpKernelTime.dwHighDateTime;
							kernel_mode_time.QuadPart /= 10000000ULL;

							/* Copy the user mode filetime high and low parts and convert it to seconds */
							user_mode_time.LowPart = lpUserTime.dwLowDateTime;
							user_mode_time.HighPart = lpUserTime.dwHighDateTime;
							user_mode_time.QuadPart /= 10000000ULL;
						} else {
							mtwarn(WM_SYS_LOGTAG, "Unable to retrieve kernel mode and user mode times from process with PID %lu (%lu).", pid, GetLastError());
						}

						/* Get page file usage and virtual size */
						/* Reference: https://stackoverflow.com/a/1986486 */
						if (GetProcessMemoryInfo(hProcess, &ppsmemCounters, sizeof(ppsmemCounters)))
						{
							page_file_usage = ppsmemCounters.PagefileUsage;
							virtual_size = (ppsmemCounters.WorkingSetSize + ppsmemCounters.PagefileUsage);
						} else {
							mtwarn(WM_SYS_LOGTAG, "Unable to retrieve page file usage from process with PID %lu (%lu).", pid, GetLastError());
						}

						/* Get session ID */
						if (!ProcessIdToSessionId(pid, &session_id)) mtwarn(WM_SYS_LOGTAG, "Unable to retrieve session ID from process with PID %lu (%lu).", pid, GetLastError());

						/* Close process handle */
						CloseHandle(hProcess);
					} else {
						/* Silence access denied errors under Windows Vista or greater */
                        DWORD lastError = GetLastError();
                        if (!checkVista() || lastError != ERROR_ACCESS_DENIED)
                        {
                            mtwarn(WM_SYS_LOGTAG, "Unable to retrieve process handle for PID %lu (%lu).", pid, lastError);
                            exec_path = strdup("unknown");
                        }
					}
				}

				/* Add process information to the JSON document */
				cJSON *object = cJSON_CreateObject();
				cJSON *process = cJSON_CreateObject();
				cJSON_AddStringToObject(object, "type", "process");
				cJSON_AddNumberToObject(object, "ID", ID);
				cJSON_AddStringToObject(object, "timestamp", timestamp);
				cJSON_AddItemToObject(object, "process", process);

				cJSON_AddStringToObject(process, "cmd", exec_path); // CommandLine
				cJSON_AddNumberToObject(process, "stime", kernel_mode_time.QuadPart); // KernelModeTime
				cJSON_AddStringToObject(process, "name", name); // Name
				cJSON_AddNumberToObject(process, "size", page_file_usage); // PageFileUsage
				cJSON_AddNumberToObject(process, "ppid", parent_pid); // ParentProcessId
				cJSON_AddNumberToObject(process, "priority", priority); // Priority
				cJSON_AddNumberToObject(process, "pid", pid); // ProcessId
				cJSON_AddNumberToObject(process, "session", session_id); // SessionId
				cJSON_AddNumberToObject(process, "nlwp", thread_count); // ThreadCount
				cJSON_AddNumberToObject(process, "utime", user_mode_time.QuadPart); // UserModeTime
				cJSON_AddNumberToObject(process, "vm_size", virtual_size); // VirtualSize

				cJSON_AddItemToArray(proc_array, object);

				free(name);
				free(exec_path);
			} while(Process32Next(hSnapshot, &pe));

			cJSON_ArrayForEach(item, proc_array) {
				char *string = cJSON_PrintUnformatted(item);
				mtdebug2(WM_SYS_LOGTAG, "sys_proc_windows() sending '%s'", string);
				wm_sendmsg(usec, 0, string, LOCATION, SYSCOLLECTOR_MQ);
				free(string);
			}

			cJSON_Delete(proc_array);
		} else {
			mtwarn(WM_SYS_LOGTAG, "Unable to retrieve process information from the snapshot.");
		}

		/* Close snapshot handle */
		CloseHandle(hSnapshot);
	} else {
		mtwarn(WM_SYS_LOGTAG, "Unable to create process snapshot.");
	}

	/* Disable debug privilege */
	if (privilege_enabled)
	{
		if (set_token_privilege(hdle, SE_DEBUG_NAME, FALSE)) mtwarn(WM_SYS_LOGTAG, "Unable to unset debug privilege on current process (%lu).", GetLastError());
	}

	if (hdle) CloseHandle(hdle);

	cJSON *object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "process_end");
    cJSON_AddNumberToObject(object, "ID", ID);
    cJSON_AddStringToObject(object, "timestamp", timestamp);

    char *string = cJSON_PrintUnformatted(object);
    mtdebug2(WM_SYS_LOGTAG, "sys_proc_windows() sending '%s'", string);
    wm_sendmsg(usec, 0, string, LOCATION, SYSCOLLECTOR_MQ);

    cJSON_Delete(object);
    free(string);
    free(timestamp);
}

int set_token_privilege(HANDLE hdle, LPCTSTR privilege, int enable) {
	TOKEN_PRIVILEGES tp;
	LUID pr_uid;
    TOKEN_PRIVILEGES tpPrevious;
    DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);
    DWORD errorInfo;

	// Get the privilege UID
	if (!LookupPrivilegeValue(NULL, privilege, &pr_uid)) {
		merror("Could not find the '%s' privilege. Error: %lu", privilege, GetLastError());
		return 1;
	}

    // Get current privilege setting
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = pr_uid;
    tp.Privileges[0].Attributes = 0;

    AdjustTokenPrivileges(hdle, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &tpPrevious, &cbPrevious);
    errorInfo = GetLastError();
    if (errorInfo != ERROR_SUCCESS) {
		merror("AdjustTokenPrivileges() failed (first call). Error: '%lu'", errorInfo);
		return 1;
    }

    // Set privilege based on previous setting
    tpPrevious.PrivilegeCount = 1;
    tpPrevious.Privileges[0].Luid = pr_uid;

    if (enable) {
        tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	} else {
        tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes);
	}

    AdjustTokenPrivileges(hdle, FALSE, &tpPrevious, cbPrevious, NULL, NULL);
    errorInfo = GetLastError();
    if (errorInfo != ERROR_SUCCESS) {
		merror("AdjustTokenPrivileges() failed (second call). Error: '%lu'", errorInfo);
		return 1;
    }

    if (enable) {
        mdebug2("The '%s' privilege has been added.", privilege);
    } else {
        mdebug2("The '%s' privilege has been removed.", privilege);
    }

	return 0;
}

#endif
