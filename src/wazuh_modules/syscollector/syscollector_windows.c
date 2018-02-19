/*
 * Wazuh Module for System inventory for Windows
 * Copyright (C) 2017 Wazuh Inc.
 * Aug, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#include "syscollector.h"
#include <winsock2.h>
#include <windows.h>
#include <netioapi.h>
#include <iphlpapi.h>

typedef char* (*CallFunc)(PIP_ADAPTER_ADDRESSES pCurrAddresses, int ID, char * timestamp);
typedef char* (*CallFunc1)(UCHAR ucLocalAddr[]);

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

hw_info *get_system_windows();

/* From process ID get its name */

char* get_process_name(DWORD pid){

    char *string = NULL;
    FILE *output;
    char *command;
    char *end;
    char read_buff[OS_MAXSTR];
    int status;

    memset(read_buff, 0, OS_MAXSTR);
    os_calloc(OS_MAXSTR, sizeof(char), command);
    snprintf(command, OS_MAXSTR, "wmic process where processID=%lu get Name", pid);
    output = popen(command, "r");
    if (!output) {
        mtwarn(WM_SYS_LOGTAG, "Unable to execute command '%s'.", command);
    } else {
        if (fgets(read_buff, OS_MAXSTR, output)) {
            if (strncmp(read_buff,"Name", 4) == 0) {
                if (!fgets(read_buff, OS_MAXSTR, output)){
                    mtwarn(WM_SYS_LOGTAG, "Unable to get process name.");
                    string = strdup("unknown");
                }
                else if (end = strpbrk(read_buff,"\r\n"), end) {
                    *end = '\0';
                    int i = strlen(read_buff) - 1;
                    while(read_buff[i] == 32){
                        read_buff[i] = '\0';
                        i--;
                    }
                    string = strdup(read_buff);
                }else
                    string = strdup("unknown");
            }
        } else {
            mtdebug1(WM_SYS_LOGTAG, "Unable to get process name (bad header).");
            string = strdup("unknown");
        }

        if (status = pclose(output), status) {
            mtwarn(WM_SYS_LOGTAG, "Command 'wmic' returned %d getting process ID.", status);
        }
    }

    return string;
}

// Get port state

char* get_port_state(int state){

    char *port_state;
    os_calloc(OS_MAXSTR, sizeof(char), port_state);

    switch (state) {
        case MIB_TCP_STATE_CLOSED:
            snprintf(port_state, OS_MAXSTR, "%s", "close");
            break;
        case MIB_TCP_STATE_LISTEN:
            snprintf(port_state, OS_MAXSTR, "%s", "listening");
            break;
        case MIB_TCP_STATE_SYN_SENT:
            snprintf(port_state, OS_MAXSTR, "%s", "syn_sent");
            break;
        case MIB_TCP_STATE_SYN_RCVD:
            snprintf(port_state, OS_MAXSTR, "%s", "syn_recv");
            break;
        case MIB_TCP_STATE_ESTAB:
            snprintf(port_state, OS_MAXSTR, "%s", "established");
            break;
        case MIB_TCP_STATE_FIN_WAIT1:
            snprintf(port_state, OS_MAXSTR, "%s", "fin_wait1");
            break;
        case MIB_TCP_STATE_FIN_WAIT2:
            snprintf(port_state, OS_MAXSTR, "%s", "fin_wait2");
            break;
        case MIB_TCP_STATE_CLOSE_WAIT:
            snprintf(port_state, OS_MAXSTR, "%s", "close_wait");
            break;
        case MIB_TCP_STATE_CLOSING:
            snprintf(port_state, OS_MAXSTR, "%s", "closing");
            break;
        case MIB_TCP_STATE_LAST_ACK:
            snprintf(port_state, OS_MAXSTR, "%s", "last_ack");
            break;
        case MIB_TCP_STATE_TIME_WAIT:
            snprintf(port_state, OS_MAXSTR, "%s", "time_wait");
            break;
        case MIB_TCP_STATE_DELETE_TCB:
            snprintf(port_state, OS_MAXSTR, "%s", "delete_tcp");
            break;
        default:
            snprintf(port_state, OS_MAXSTR, "%s", "unknown");
            break;
    }
    return port_state;
}

// Get opened ports inventory

void sys_ports_windows(const char* LOCATION, int check_all){

    /* Declare and initialize variables */
    PMIB_TCPTABLE_OWNER_PID pTcpTable;
    PMIB_TCP6TABLE_OWNER_PID pTcp6Table;
    PMIB_UDPTABLE_OWNER_PID pUdpTable;
    PMIB_UDP6TABLE_OWNER_PID pUdp6Table;
    DWORD dwSize = 0;
    BOOL bOrder = TRUE;
    DWORD dwRetVal = 0;
    int listening;
    int i = 0;

    // Set random ID for each scan

    unsigned int ID1 = os_random();
    unsigned int ID2 = os_random();

    char random_id[OS_MAXSTR];
    snprintf(random_id, OS_MAXSTR - 1, "%u%u", ID1, ID2);

    int ID = atoi(random_id);
    if (ID < 0)
        ID = -ID;

    // Set timestamp

    char *timestamp;
    time_t now;
    struct tm localtm;

    now = time(NULL);
    localtime_r(&now, &localtm);

    os_calloc(OS_MAXSTR, sizeof(char), timestamp);

    snprintf(timestamp,OS_MAXSTR,"%d/%02d/%02d %02d:%02d:%02d",
            localtm.tm_year + 1900, localtm.tm_mon + 1,
            localtm.tm_mday, localtm.tm_hour, localtm.tm_min, localtm.tm_sec);

    char local_addr[NI_MAXHOST];
    char rem_addr[NI_MAXHOST];
    struct in_addr ipaddress;

    TCP_TABLE_CLASS TableClass = TCP_TABLE_OWNER_PID_ALL;
    UDP_TABLE_CLASS TableClassUdp = UDP_TABLE_OWNER_PID;

    mtdebug1(WM_SYS_LOGTAG, "Starting opened ports inventory.");

    /* TCP opened ports inventory */

    pTcpTable = (MIB_TCPTABLE_OWNER_PID *) MALLOC(sizeof(MIB_TCPTABLE_OWNER_PID));

    if (pTcpTable == NULL) {
        mterror(WM_SYS_LOGTAG, "Error allocating memory for 'pTcpTable'.");
        return;
    }

    dwSize = sizeof(MIB_TCPTABLE_OWNER_PID);

    /* Initial call to the function to get the necessary size into the dwSize variable */
    if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, bOrder, AF_INET, TableClass, 0)) == ERROR_INSUFFICIENT_BUFFER){
        FREE(pTcpTable);
        pTcpTable = (MIB_TCPTABLE_OWNER_PID *) MALLOC(dwSize);
        if (pTcpTable == NULL){
            mterror(WM_SYS_LOGTAG, "Error allocating memory for 'pTcpTable'.");
            return;
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
                SendMSG(0, string, LOCATION, SYSCOLLECTOR_MQ);
                cJSON_Delete(object);
                free(string);

            } else
                cJSON_Delete(object);

        }

    } else {
        printf("Call to GetExtendedTcpTable failed with error: %lu\n", dwRetVal);
        FREE(pTcpTable);
        return;
    }

    if (pTcpTable != NULL) {
        FREE(pTcpTable);
        pTcpTable = NULL;
    }

    /* TCP6 opened ports inventory */

    pTcp6Table = (MIB_TCP6TABLE_OWNER_PID *) MALLOC(sizeof(MIB_TCP6TABLE_OWNER_PID));

    if (pTcp6Table == NULL) {
        mterror(WM_SYS_LOGTAG, "Error allocating memory for 'pTcp6Table'.");
        return;
    }

    dwSize = sizeof(MIB_TCP6TABLE_OWNER_PID);

    /* Initial call to the function to get the necessary size into the dwSize variable */
    if ((dwRetVal = GetExtendedTcpTable(pTcp6Table, &dwSize, bOrder, AF_INET6, TableClass, 0)) == ERROR_INSUFFICIENT_BUFFER){
        FREE(pTcp6Table);
        pTcp6Table = (MIB_TCP6TABLE_OWNER_PID *) MALLOC(dwSize);
        if (pTcp6Table == NULL){
            mterror(WM_SYS_LOGTAG, "Error allocating memory for 'pTcp6Table'.");
            return;
        }
    }

    /* Call inet_ntop function through syscollector DLL */
    CallFunc1 _wm_inet_ntop;
    HINSTANCE sys_library = LoadLibrary("syscollector_win_ext.dll");
    if (sys_library == NULL){
        DWORD error = GetLastError();
        LPSTR messageBuffer = NULL;
        LPSTR end;

        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error, 0, (LPTSTR) &messageBuffer, 0, NULL);

        if (end = strchr(messageBuffer, '\r'), end) {
            *end = '\0';
        }

        mterror(WM_SYS_LOGTAG, "Unable to load syscollector_win_ext.dll: %s (%lu)", messageBuffer, error);
        LocalFree(messageBuffer);
        return;
    }else{
        _wm_inet_ntop = (CallFunc1)GetProcAddress(sys_library, "wm_inet_ntop");
    }
    if (!_wm_inet_ntop){
        mterror(WM_SYS_LOGTAG, "Unable to access 'wm_inet_ntop' on syscollector_win_ext.dll.");
        return;
    }

    /* Second call with the right size of the returned table */
    if ((dwRetVal = GetExtendedTcpTable(pTcp6Table, &dwSize, bOrder, AF_INET6, TableClass, 0)) == NO_ERROR){

        for (i=0; i < (int) pTcp6Table->dwNumEntries; i++){

            listening = 0;
            char *laddress = NULL;
            char *raddress = NULL;

            cJSON *object = cJSON_CreateObject();
            cJSON *port = cJSON_CreateObject();
            cJSON_AddStringToObject(object, "type", "port");
            cJSON_AddNumberToObject(object, "ID", ID);
            cJSON_AddStringToObject(object, "timestamp", timestamp);
            cJSON_AddItemToObject(object, "port", port);
            cJSON_AddStringToObject(port, "protocol", "tcp6");

            laddress = _wm_inet_ntop(pTcp6Table->table[i].ucLocalAddr);
            cJSON_AddStringToObject(port, "local_ip", laddress);
            cJSON_AddNumberToObject(port, "local_port", ntohs((u_short)pTcp6Table->table[i].dwLocalPort));

            raddress = _wm_inet_ntop(pTcp6Table->table[i].ucRemoteAddr);
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
                SendMSG(0, string, LOCATION, SYSCOLLECTOR_MQ);
                cJSON_Delete(object);
                free(string);

            } else
                cJSON_Delete(object);


            free(laddress);
            free(raddress);
        }

    } else {
        printf("Call to GetExtendedTcpTable failed with error: %lu\n", dwRetVal);
        FREE(pTcp6Table);
        return;
    }

    if (pTcp6Table != NULL) {
        FREE(pTcp6Table);
        pTcp6Table = NULL;
    }

    if (!check_all) {
        cJSON *object = cJSON_CreateObject();
        cJSON_AddStringToObject(object, "type", "port_end");
        cJSON_AddNumberToObject(object, "ID", ID);
        cJSON_AddStringToObject(object, "timestamp", timestamp);

        char *string;
        string = cJSON_PrintUnformatted(object);
        mtdebug2(WM_SYS_LOGTAG, "sys_ports_windows() sending '%s'", string);
        SendMSG(0, string, LOCATION, SYSCOLLECTOR_MQ);
        cJSON_Delete(object);
        free(string);
        free(timestamp);
        return;
    }

    /* UDP opened ports inventory */

    pUdpTable = (MIB_UDPTABLE_OWNER_PID *) MALLOC(sizeof(MIB_UDPTABLE_OWNER_PID));

    if (pUdpTable == NULL) {
        mterror(WM_SYS_LOGTAG, "Error allocating memory for 'pUdpTable'.");
        return;
    }

    dwSize = sizeof(MIB_UDPTABLE_OWNER_PID);

    /* Initial call to the function to get the necessary size into the dwSize variable */
    if ((dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, bOrder, AF_INET, TableClassUdp, 0)) == ERROR_INSUFFICIENT_BUFFER){
        FREE(pUdpTable);
        pUdpTable = (MIB_UDPTABLE_OWNER_PID *) MALLOC(dwSize);
        if (pUdpTable == NULL){
            mterror(WM_SYS_LOGTAG, "Error allocating memory for 'pUdpTable'.");
            return;
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
            SendMSG(0, string, LOCATION, SYSCOLLECTOR_MQ);
            cJSON_Delete(object);

            free(string);
        }

    } else {
        printf("Call to GetExtendedUdpTable failed with error: %lu\n", dwRetVal);
        FREE(pUdpTable);
        return;
    }

    if (pUdpTable != NULL) {
        FREE(pUdpTable);
        pUdpTable = NULL;
    }

    /* UDP6 opened ports inventory */

    pUdp6Table = (MIB_UDP6TABLE_OWNER_PID *) MALLOC(sizeof(MIB_UDP6TABLE_OWNER_PID));

    if (pUdp6Table == NULL) {
        mterror(WM_SYS_LOGTAG, "Error allocating memory for 'pUdp6Table'.");
        return;
    }

    dwSize = sizeof(MIB_UDP6TABLE_OWNER_PID);

    /* Initial call to the function to get the necessary size into the dwSize variable */
    if ((dwRetVal = GetExtendedUdpTable(pUdp6Table, &dwSize, bOrder, AF_INET6, TableClassUdp, 0)) == ERROR_INSUFFICIENT_BUFFER){
        FREE(pUdp6Table);
        pUdp6Table = (MIB_UDP6TABLE_OWNER_PID *) MALLOC(dwSize);
        if (pUdp6Table == NULL){
            mterror(WM_SYS_LOGTAG, "Error allocating memory for 'pUdp6Table'.");
            return;
        }
    }

    /* Second call with the right size of the returned table */
    if ((dwRetVal = GetExtendedUdpTable(pUdp6Table, &dwSize, bOrder, AF_INET6, TableClassUdp, 0)) == NO_ERROR){

        for (i=0; i < (int) pUdp6Table->dwNumEntries; i++){

            char *string;
            char *laddress = NULL;

            cJSON *object = cJSON_CreateObject();
            cJSON *port = cJSON_CreateObject();
            cJSON_AddStringToObject(object, "type", "port");
            cJSON_AddNumberToObject(object, "ID", ID);
            cJSON_AddStringToObject(object, "timestamp", timestamp);
            cJSON_AddItemToObject(object, "port", port);
            cJSON_AddStringToObject(port, "protocol", "udp6");

            laddress = _wm_inet_ntop(pUdp6Table->table[i].ucLocalAddr);
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
            SendMSG(0, string, LOCATION, SYSCOLLECTOR_MQ);
            cJSON_Delete(object);

            free(laddress);
            free(string);
        }

    } else {
        printf("Call to GetExtendedUdpTable failed with error: %lu\n", dwRetVal);
        FREE(pUdp6Table);
        return;
    }

    if (pUdp6Table != NULL) {
        FREE(pUdp6Table);
        pUdp6Table = NULL;
    }

    cJSON *object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "port_end");
    cJSON_AddNumberToObject(object, "ID", ID);
    cJSON_AddStringToObject(object, "timestamp", timestamp);

    char *string;
    string = cJSON_PrintUnformatted(object);
    mtdebug2(WM_SYS_LOGTAG, "sys_ports_windows() sending '%s'", string);
    SendMSG(0, string, LOCATION, SYSCOLLECTOR_MQ);
    cJSON_Delete(object);
    free(string);
    free(timestamp);

}

// Get installed programs inventory

void sys_programs_windows(const char* LOCATION){

    char *command;
    FILE *output;
    char read_buff[OS_MAXSTR];
    int i;
    int status;

    // Set timestamp

    char *timestamp;
    time_t now;
    struct tm localtm;

    now = time(NULL);
    localtime_r(&now, &localtm);

    os_calloc(OS_MAXSTR, sizeof(char), timestamp);

    snprintf(timestamp,OS_MAXSTR,"%d/%02d/%02d %02d:%02d:%02d",
            localtm.tm_year + 1900, localtm.tm_mon + 1,
            localtm.tm_mday, localtm.tm_hour, localtm.tm_min, localtm.tm_sec);

    // Set random ID for each scan

    unsigned int ID1 = os_random();
    unsigned int ID2 = os_random();

    char random_id[OS_MAXSTR];
    snprintf(random_id, OS_MAXSTR - 1, "%u%u", ID1, ID2);

    int ID = atoi(random_id);
    if (ID < 0)
        ID = -ID;

    mtdebug1(WM_SYS_LOGTAG, "Starting installed packages inventory.");

    memset(read_buff, 0, OS_MAXSTR);
    command = "wmic product get Name,Version,Vendor / format:csv";
    output = popen(command, "r");

    if (!output){
        mtwarn(WM_SYS_LOGTAG, "Unable to execute command '%s'", command);
    }else{
        while (fgets(read_buff, OS_MAXSTR, output) && strncmp(read_buff,"Node,Name,Vendor,Version", 24) != 0);

        while(fgets(read_buff, OS_MAXSTR, output)){

            cJSON *object = cJSON_CreateObject();
            cJSON *program = cJSON_CreateObject();
            cJSON_AddStringToObject(object, "type", "program");
            cJSON_AddNumberToObject(object, "ID", ID);
            cJSON_AddStringToObject(object, "timestamp", timestamp);
            cJSON_AddItemToObject(object, "program", program);
            cJSON_AddStringToObject(program, "format", "win");

            char *string;
            char ** parts = NULL;

            parts = OS_StrBreak(',', read_buff, 4);
            cJSON_AddStringToObject(program, "name", parts[1]);
            cJSON_AddStringToObject(program, "vendor", parts[2]);

            char ** version = NULL;

            if (strrchr(parts[3], ',') != 0) {
                char ** aux_version = NULL;
                aux_version = OS_StrBreak(',', parts[3], 2);
                version = OS_StrBreak('\r', aux_version[1], 2);
                for (i=0; aux_version[i]; i++){
                    free(aux_version[i]);
                }
                free(aux_version);
            } else {
                version = OS_StrBreak('\r', parts[3], 2);
            }

            cJSON_AddStringToObject(program, "version", version[0]);
            for (i=0; version[i]; i++){
                free(version[i]);
            }
            for (i=0; parts[i]; i++){
                free(parts[i]);
            }
            free(version);
            free(parts);

            string = cJSON_PrintUnformatted(object);
            mtdebug2(WM_SYS_LOGTAG, "sys_programs_windows() sending '%s'", string);
            SendMSG(0, string, LOCATION, SYSCOLLECTOR_MQ);
            cJSON_Delete(object);
            free(string);
        }

        if (status = pclose(output), status) {
            mtwarn(WM_SYS_LOGTAG, "Command 'wmic' returned %d getting software inventory.", status);
        }
    }


    cJSON *object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "program_end");
    cJSON_AddNumberToObject(object, "ID", ID);

    char *string;
    string = cJSON_PrintUnformatted(object);
    mtdebug2(WM_SYS_LOGTAG, "sys_programs_windows() sending '%s'", string);
    SendMSG(0, string, LOCATION, SYSCOLLECTOR_MQ);
    cJSON_Delete(object);
    free(string);
    free(timestamp);

}

void sys_hw_windows(const char* LOCATION){

    char *string;
    char *command;
    char *end;
    FILE *output;
    size_t buf_length = 1024;
    char read_buff[buf_length];
    int status;

    // Set timestamp

    char *timestamp;
    time_t now;
    struct tm localtm;

    now = time(NULL);
    localtime_r(&now, &localtm);

    os_calloc(OS_MAXSTR, sizeof(char), timestamp);

    snprintf(timestamp,OS_MAXSTR,"%d/%02d/%02d %02d:%02d:%02d",
            localtm.tm_year + 1900, localtm.tm_mon + 1,
            localtm.tm_mday, localtm.tm_hour, localtm.tm_min, localtm.tm_sec);

    // Set random ID for each scan

    unsigned int ID1 = os_random();
    unsigned int ID2 = os_random();

    char random_id[OS_MAXSTR];
    snprintf(random_id, OS_MAXSTR - 1, "%u%u", ID1, ID2);

    int ID = atoi(random_id);
    if (ID < 0)
        ID = -ID;

    mtdebug1(WM_SYS_LOGTAG, "Starting hardware inventory.");

    cJSON *object = cJSON_CreateObject();
    cJSON *hw_inventory = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "hardware");
    cJSON_AddNumberToObject(object, "ID", ID);
    cJSON_AddStringToObject(object, "timestamp", timestamp);
    cJSON_AddItemToObject(object, "inventory", hw_inventory);

    /* Get Serial number */
    char *serial = NULL;
    memset(read_buff, 0, buf_length);
    command = "wmic baseboard get SerialNumber";
    output = popen(command, "r");
    if (!output){
        mtwarn(WM_SYS_LOGTAG, "Unable to execute command '%s'.", command);
    }else{
        if (fgets(read_buff, buf_length, output)) {
            if (strncmp(read_buff ,"SerialNumber", 12) == 0) {
                if (!fgets(read_buff, buf_length, output)){
                    mtwarn(WM_SYS_LOGTAG, "Unable to get Motherboard Serial Number.");
                    serial = strdup("unknown");
                }
                else if (end = strpbrk(read_buff,"\r\n"), end) {
                    *end = '\0';
                    int i = strlen(read_buff) - 1;
                    while(read_buff[i] == 32){
                        read_buff[i] = '\0';
                        i--;
                    }
                    serial = strdup(read_buff);
                }else
                    serial = strdup("unknown");
            }
        } else {
            mtdebug1(WM_SYS_LOGTAG, "Unable to get Motherboard Serial Number (bad header).");
            serial = strdup("unknown");
        }

        if (status = pclose(output), status) {
            mtwarn(WM_SYS_LOGTAG, "Command 'wmic' returned %d getting board serial.", status);
        }
    }

    cJSON_AddStringToObject(hw_inventory, "board_serial", serial);
    free(serial);

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

        free(sys_info->cpu_name);
    }

    /* Send interface data in JSON format */
    string = cJSON_PrintUnformatted(object);
    mtdebug2(WM_SYS_LOGTAG, "sys_hw_windows() sending '%s'", string);
    SendMSG(0, string, LOCATION, SYSCOLLECTOR_MQ);
    cJSON_Delete(object);

    free(string);
    free(timestamp);

}

void sys_os_windows(const char* LOCATION){

    char *string;

    // Set timestamp

    char *timestamp;
    time_t now;
    struct tm localtm;

    now = time(NULL);
    localtime_r(&now, &localtm);

    os_calloc(OS_MAXSTR, sizeof(char), timestamp);

    snprintf(timestamp,OS_MAXSTR,"%d/%02d/%02d %02d:%02d:%02d",
            localtm.tm_year + 1900, localtm.tm_mon + 1,
            localtm.tm_mday, localtm.tm_hour, localtm.tm_min, localtm.tm_sec);

    // Set random ID for each scan

    unsigned int ID1 = os_random();
    unsigned int ID2 = os_random();

    char random_id[OS_MAXSTR];
    snprintf(random_id, OS_MAXSTR - 1, "%u%u", ID1, ID2);

    int ID = atoi(random_id);
    if (ID < 0)
        ID = -ID;

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

/* Network inventory for Windows systems (Vista or later) */
void sys_network_windows(const char* LOCATION){

    mtdebug1(WM_SYS_LOGTAG, "Starting network inventory.");

    CallFunc _get_network_win;

    /* Load DLL with network inventory functions */
    HINSTANCE sys_library = LoadLibrary("syscollector_win_ext.dll");

    if (sys_library != NULL){
        _get_network_win = (CallFunc)GetProcAddress(sys_library, "get_network");

        if (!_get_network_win){
            mterror(WM_SYS_LOGTAG, "Unable to access 'get_network' on syscollector_win_ext.dll.");
            return;
        }else{

            // Set random ID and timestamp

            unsigned int ID1 = os_random();
            unsigned int ID2 = os_random();

            char random_id[OS_MAXSTR];
            snprintf(random_id, OS_MAXSTR - 1, "%u%u", ID1, ID2);

            int ID = atoi(random_id);
            if (ID < 0)
                ID = -ID;

            char *timestamp;
            time_t now;
            struct tm localtm;

            now = time(NULL);
            localtime_r(&now, &localtm);

            os_calloc(OS_MAXSTR, sizeof(char), timestamp);

            snprintf(timestamp,OS_MAXSTR,"%d/%02d/%02d %02d:%02d:%02d",
                    localtm.tm_year + 1900, localtm.tm_mon + 1,
                    localtm.tm_mday, localtm.tm_hour, localtm.tm_min, localtm.tm_sec);

            DWORD dwRetVal = 0;

            // Set the flags to pass to GetAdaptersAddresses
            ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;

            LPVOID lpMsgBuf = NULL;

            PIP_ADAPTER_ADDRESSES pAddresses = NULL;
            ULONG outBufLen = 0;
            ULONG Iterations = 0;

            PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;

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

                    char* string;
                    /* Call function get_network in syscollector_win_ext.dll */
                    string = _get_network_win(pCurrAddresses, ID, timestamp);

                    mtdebug2(WM_SYS_LOGTAG, "sys_network_windows() sending '%s'", string);
                    SendMSG(0, string, LOCATION, SYSCOLLECTOR_MQ);

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
                    }
                }
            }

            if (pAddresses) {
                FREE(pAddresses);
            }

            FreeLibrary(sys_library);

            cJSON *object = cJSON_CreateObject();
            cJSON_AddStringToObject(object, "type", "network_end");
            cJSON_AddNumberToObject(object, "ID", ID);
            cJSON_AddStringToObject(object, "timestamp", timestamp);

            char *string;
            string = cJSON_PrintUnformatted(object);
            mtdebug2(WM_SYS_LOGTAG, "sys_network_windows() sending '%s'", string);
            SendMSG(0, string, LOCATION, SYSCOLLECTOR_MQ);
            cJSON_Delete(object);
            free(string);
            free(timestamp);
        }
    }else{
        DWORD error = GetLastError();
        LPSTR messageBuffer = NULL;
        LPSTR end;

        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error, 0, (LPTSTR) &messageBuffer, 0, NULL);

        if (end = strchr(messageBuffer, '\r'), end) {
            *end = '\0';
        }

        mterror(WM_SYS_LOGTAG, "Unable to load syscollector_win_ext.dll: %s (%lu)", messageBuffer, error);
        LocalFree(messageBuffer);
    }

}

hw_info *get_system_windows(){

    hw_info *info;
    char *command;
    char *end;
    FILE *output;
    size_t buf_length = 1024;
    char read_buff[buf_length];
    int status;

    os_calloc(1,sizeof(hw_info),info);

    memset(read_buff, 0, buf_length);
    command = "wmic cpu get Name";
    output = popen(command, "r");
    if (!output){
        mtwarn(WM_SYS_LOGTAG, "Unable to execute command '%s'.", command);
        info->cpu_name = strdup("unknown");
    }else{
        if (fgets(read_buff, buf_length, output)) {
            if (strncmp(read_buff ,"Name",4) == 0) {
                if (!fgets(read_buff, buf_length, output)){
                    mtdebug1(WM_SYS_LOGTAG, "Unable to get CPU Name.");
                    info->cpu_name = strdup("unknown");
                }else if(strstr(read_buff, "Error")){
                    mtdebug1(WM_SYS_LOGTAG, "Unable to get CPU Name. Incompatible command.");
                    info->cpu_name = strdup("unknown");
                }else if (end = strpbrk(read_buff,"\r\n"), end) {
                    *end = '\0';
                    int i = strlen(read_buff) - 1;
                    while(read_buff[i] == 32){
                        read_buff[i] = '\0';
                        i--;
                    }
                    info->cpu_name = strdup(read_buff);
                }else
                    info->cpu_name = strdup("unknown");
            }
        } else {
            mtdebug1(WM_SYS_LOGTAG, "Unable to get CPU Name (bad header).");
            info->cpu_name = strdup("unknown");
        }

        if (status = pclose(output), status) {
            mtwarn(WM_SYS_LOGTAG, "Command 'wmic' returned %d getting CPU name.", status);
        }
    }

    memset(read_buff, 0, buf_length);
    char *cores;
    command = "wmic cpu get NumberOfCores";
    output = popen(command, "r");
    if (!output){
        mtwarn(WM_SYS_LOGTAG, "Unable to execute command '%s'.", command);
    }else{
        if (fgets(read_buff, buf_length, output)) {
            if (strncmp(read_buff, "NumberOfCores",13) == 0) {
                if (!fgets(read_buff, buf_length, output)){
                    mtdebug1(WM_SYS_LOGTAG, "Unable to get number of cores.");
                }else if(strstr(read_buff, "Error")){
                    mtdebug1(WM_SYS_LOGTAG, "Unable to get number of cores. Incompatible command.");
                }else if (end = strpbrk(read_buff,"\r\n"), end) {
                    *end = '\0';
                    int i = strlen(read_buff) - 1;
                    while(read_buff[i] == 32){
                        read_buff[i] = '\0';
                        i--;
                    }
                    cores = strdup(read_buff);
                    info->cpu_cores = atoi(cores);
                }
            }
        } else {
            mtdebug1(WM_SYS_LOGTAG, "Unable to get number of cores (bad header).");
        }

        if (status = pclose(output), status) {
            mtwarn(WM_SYS_LOGTAG, "Command 'wmic' returned %d getting number of cores.", status);
        }
    }

    memset(read_buff, 0, buf_length);
    char *frec;
    command = "wmic cpu get CurrentClockSpeed";
    output = popen(command, "r");
    if (!output){
        mtwarn(WM_SYS_LOGTAG, "Unable to execute command '%s'.", command);
    }else{
        if (fgets(read_buff, buf_length, output)) {
            if (strncmp(read_buff, "CurrentClockSpeed",17) == 0) {
                if (!fgets(read_buff, buf_length, output)){
                    mtdebug1(WM_SYS_LOGTAG, "Unable to get CPU clock speed.");
                }else if(strstr(read_buff, "Error")){
                    mtdebug1(WM_SYS_LOGTAG, "Unable to get CPU clock speed. Incompatible command.");
                }else if (end = strpbrk(read_buff,"\r\n"), end) {
                    *end = '\0';
                    int i = strlen(read_buff) - 1;
                    while(read_buff[i] == 32){
                        read_buff[i] = '\0';
                        i--;
                    }
                    frec = strdup(read_buff);
                    info->cpu_MHz = atof(frec);
                }
            }
        } else {
            mtdebug1(WM_SYS_LOGTAG, "Unable to get CPU clock speed (bad header).");
        }

        if (status = pclose(output), status) {
            mtwarn(WM_SYS_LOGTAG, "Command 'wmic' returned %d getting clock speed.", status);
        }
    }

    memset(read_buff, 0, buf_length);
    char *total;
    command = "wmic computersystem get TotalPhysicalMemory";
    output = popen(command, "r");
    if (!output){
        mtwarn(WM_SYS_LOGTAG, "Unable to execute command '%s'.", command);
    }else{
        if (fgets(read_buff, buf_length, output)) {
            if (strncmp(read_buff, "TotalPhysicalMemory", 19) == 0) {
                if (!fgets(read_buff, buf_length, output)){
                    mtdebug1(WM_SYS_LOGTAG, "Unable to get physical memory information.");
                }else if(strstr(read_buff, "Error")){
                    mtdebug1(WM_SYS_LOGTAG, "Unable to get physical memory information. Incompatible command.");
                }else if (end = strpbrk(read_buff,"\r\n"), end) {
                    *end = '\0';
                    int i = strlen(read_buff) - 1;
                    while(read_buff[i] == 32){
                        read_buff[i] = '\0';
                        i--;
                    }
                    total = strdup(read_buff);
                    info->ram_total = (atof(total)) / 1024;
                }
            }
        } else {
            mtdebug1(WM_SYS_LOGTAG, "Unable to get physical memory information (bad header).");
        }
    }

    if (status = pclose(output), status) {
        mtwarn(WM_SYS_LOGTAG, "Command 'wmic' returned %d getting physical memory.", status);
    }

    memset(read_buff, 0, buf_length);
    char *mem_free;
    command = "wmic os get FreePhysicalMemory";
    output = popen(command, "r");
    if (!output){
        mtwarn(WM_SYS_LOGTAG, "Unable to execute command '%s'.", command);
    }else{
        if (fgets(read_buff, buf_length, output)) {
            if (strncmp(read_buff, "FreePhysicalMemory", 18) == 0) {
                if (!fgets(read_buff, buf_length, output)){
                    mtdebug1(WM_SYS_LOGTAG, "Unable to get free memory of the system.");
                }else if(strstr(read_buff, "Error")){
                    mtdebug1(WM_SYS_LOGTAG, "Unable to get free memory of the system. Incompatible command.");
                }else if (end = strpbrk(read_buff,"\r\n"), end) {
                    *end = '\0';
                    int i = strlen(read_buff) - 1;
                    while(read_buff[i] == 32){
                        read_buff[i] = '\0';
                        i--;
                    }
                    mem_free = strdup(read_buff);
                    info->ram_free = atoi(mem_free);
                }
            }
        } else {
            mtdebug1(WM_SYS_LOGTAG, "Unable to get free memory of the system (bad header).");
        }

        if (status = pclose(output), status) {
            mtwarn(WM_SYS_LOGTAG, "Command 'wmic' returned %d getting free memory.", status);
        }
    }

    return info;
}


void sys_proc_windows(const char* LOCATION) {
    char *command;
    FILE *output;
    char read_buff[OS_MAXSTR];
    int status;

    // Set timestamp

    char *timestamp;
    time_t now;
    struct tm localtm;

    now = time(NULL);
    localtime_r(&now, &localtm);

    os_calloc(OS_MAXSTR, sizeof(char), timestamp);

    snprintf(timestamp,OS_MAXSTR,"%d/%02d/%02d %02d:%02d:%02d",
            localtm.tm_year + 1900, localtm.tm_mon + 1,
            localtm.tm_mday, localtm.tm_hour, localtm.tm_min, localtm.tm_sec);

    // Set random ID for each scan

    unsigned int ID1 = os_random();
    unsigned int ID2 = os_random();

    char random_id[OS_MAXSTR];
    snprintf(random_id, OS_MAXSTR - 1, "%u%u", ID1, ID2);

    int ID = atoi(random_id);
    if (ID < 0)
        ID = -ID;

    cJSON *item;
    cJSON *id_msg = cJSON_CreateObject();
    cJSON *id_array = cJSON_CreateArray();
    cJSON *proc_array = cJSON_CreateArray();

    mtdebug1(WM_SYS_LOGTAG, "Starting running processes inventory.");

    memset(read_buff, 0, OS_MAXSTR);
    command = "wmic process get ExecutablePath,KernelModeTime,Name,PageFileUsage,ParentProcessId,Priority,ProcessId,SessionId,ThreadCount,UserModeTime,VirtualSize /format:csv";
    output = popen(command, "r");

    if (!output){
        mtwarn(WM_SYS_LOGTAG, "Unable to execute command '%s'", command);
    }else{
        char *string;
        while(fgets(read_buff, OS_MAXSTR, output) && strncmp(read_buff, "Node,ExecutablePath,KernelModeTime,Name,PageFileUsage,ParentProcessId,Priority,ProcessId,SessionId,ThreadCount,UserModeTime,VirtualSize", 132) != 0);

        while(fgets(read_buff, OS_MAXSTR, output)){

            cJSON *object = cJSON_CreateObject();
            cJSON *process = cJSON_CreateObject();
            cJSON_AddStringToObject(object, "type", "process");
            cJSON_AddNumberToObject(object, "ID", ID);
            cJSON_AddStringToObject(object, "timestamp", timestamp);
            cJSON_AddItemToObject(object, "process", process);

            char ** parts = NULL;
            parts = OS_StrBreak(',', read_buff, 12);

            cJSON_AddStringToObject(process,"cmd",parts[1]); // CommandLine
            cJSON_AddNumberToObject(process,"stime",atol(parts[2])); // KernelModeTime
            cJSON_AddStringToObject(process,"name",parts[3]); // Name
            cJSON_AddNumberToObject(process,"size",atoi(parts[4])); // PageFileUsage
            cJSON_AddNumberToObject(process,"ppid",atoi(parts[5])); // ParentProcessId
            cJSON_AddNumberToObject(process,"priority",atoi(parts[6])); // Priority
            cJSON_AddNumberToObject(process,"pid",atoi(parts[7])); // ProcessId
            cJSON_AddItemToArray(id_array, cJSON_CreateNumber(atoi(parts[7]))); // ProcessId
            cJSON_AddNumberToObject(process,"session",atoi(parts[8])); // SessionId
            cJSON_AddNumberToObject(process,"nlwp",atoi(parts[9])); // ThreadCount
            cJSON_AddNumberToObject(process,"stime",atol(parts[10])); // UserModeTime
            cJSON_AddNumberToObject(process,"vm_size",atol(parts[11])); // VirtualSize

            cJSON_AddItemToArray(proc_array, object);
            free(parts);
        }

        cJSON_AddStringToObject(id_msg, "type", "process_list");
        cJSON_AddNumberToObject(id_msg, "ID", ID);
        cJSON_AddStringToObject(id_msg, "timestamp", timestamp);
        cJSON_AddItemToObject(id_msg, "list", id_array);

        string = cJSON_PrintUnformatted(id_msg);
        mtdebug2(WM_SYS_LOGTAG, "sys_proc_windows() sending '%s'", string);
        SendMSG(0, string, LOCATION, SYSCOLLECTOR_MQ);

        cJSON_ArrayForEach(item, proc_array) {
            string = cJSON_PrintUnformatted(item);
            mtdebug2(WM_SYS_LOGTAG, "sys_proc_windows() sending '%s'", string);
            SendMSG(0, string, LOCATION, SYSCOLLECTOR_MQ);
        }

        free(string);
        cJSON_Delete(id_msg);
        cJSON_Delete(proc_array);

        if (status = pclose(output), status) {
            mtwarn(WM_SYS_LOGTAG, "Command 'wmic' returned %d getting process inventory.", status);
        }
    }

    cJSON *object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "process_end");
    cJSON_AddNumberToObject(object, "ID", ID);
    cJSON_AddStringToObject(object, "timestamp", timestamp);

    char *string;
    string = cJSON_PrintUnformatted(object);
    mtdebug2(WM_SYS_LOGTAG, "sys_proc_windows() sending '%s'", string);
    SendMSG(0, string, LOCATION, SYSCOLLECTOR_MQ);
    cJSON_Delete(object);
    free(string);
    free(timestamp);
}

#endif
