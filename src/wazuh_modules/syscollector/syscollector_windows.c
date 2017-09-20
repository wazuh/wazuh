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
#include <ws2tcpip.h>
#include <windows.h>
#include <netioapi.h>
#include <iphlpapi.h>

typedef char* (*CallFunc)(PIP_ADAPTER_ADDRESSES pCurrAddresses);

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

hw_info *get_system_windows();

// Get installed programs inventory

void sys_programs_windows(const char* LOCATION){

    char *command;
    FILE *output;
    char read_buff[OS_MAXSTR];
    int i;

    mtinfo(WM_SYS_LOGTAG, "Starting installed programs inventory.");

    memset(read_buff, 0, OS_MAXSTR);
    command = "wmic product get Name,Version,Vendor / format:csv";
    output = popen(command, "r");

    if (!output){
        mtwarn(WM_SYS_LOGTAG, "Unable to execute command '%s'", command);
    }else{
        while(strncmp(fgets(read_buff, OS_MAXSTR, output),"Node,Name,Vendor,Version", 24) != 0){
            continue;
        }
        while(fgets(read_buff, OS_MAXSTR, output)){

            cJSON *object = cJSON_CreateObject();
            cJSON *program = cJSON_CreateObject();
            cJSON_AddStringToObject(object, "type", "program");
            cJSON_AddItemToObject(object, "data", program);

            char *string;
            char ** parts = NULL;

            parts = OS_StrBreak(',', read_buff, 4);
            cJSON_AddStringToObject(program, "name", parts[1]);
            cJSON_AddStringToObject(program, "vendor", parts[2]);

            char ** version = NULL;
            version = OS_StrBreak('\r', parts[3], 2);
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
            mtdebug(WM_SYS_LOGTAG, "sys_programs_windows() sending '%s'", string);
            SendMSG(0, string, LOCATION, SYSCOLLECTOR_MQ);
            cJSON_Delete(object);

            free(string);
        }
    }
}

void sys_hw_windows(const char* LOCATION){

    char *string;
    char *command;
    char *end;
    FILE *output;
    size_t buf_length = 1024;
    char read_buff[buf_length];

    mtinfo(WM_SYS_LOGTAG, "Starting hardware inventory.");

    cJSON *object = cJSON_CreateObject();
    cJSON *hw_inventory = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "hardware");
    cJSON_AddItemToObject(object, "inventory", hw_inventory);

    /* Get Serial number */
    char *serial = NULL;
    memset(read_buff, 0, buf_length);
    command = "wmic baseboard get SerialNumber";
    output = popen(command, "r");
    if (!output){
        mtwarn(WM_SYS_LOGTAG, "Unable to execute command '%s'.", command);
    }else{
        if (strncmp(fgets(read_buff, buf_length, output),"SerialNumber", 12) == 0) {
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
    }
    pclose(output);

    cJSON_AddStringToObject(hw_inventory, "board_serial", serial);
    free(serial);

    /* Get CPU and memory information */
    hw_info *sys_info;
    if (sys_info = get_system_windows(), sys_info){
        if (sys_info->cpu_name)
            cJSON_AddStringToObject(hw_inventory, "cpu_name", sys_info->cpu_name);
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
}

void sys_os_windows(const char* LOCATION){

    char *string;

    mtinfo(WM_SYS_LOGTAG, "Starting Operating System inventory.");

    cJSON *object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "OS");

    cJSON *os_inventory = getunameJSON();

    cJSON_AddItemToObject(object, "inventory", os_inventory);

    /* Send interface data in JSON format */
    string = cJSON_PrintUnformatted(object);
    mtdebug2(WM_SYS_LOGTAG, "sys_os_windows() sending '%s'", string);
    SendMSG(0, string, LOCATION, SYSCOLLECTOR_MQ);
    cJSON_Delete(object);

    free(string);
}

/* Network inventory for Windows systems (Vista or later) */
void sys_network_windows(const char* LOCATION){

    mtinfo(WM_SYS_LOGTAG, "Starting network inventory.");

    CallFunc _get_network_win;

    /* Load DLL with network inventory functions */
    HINSTANCE sys_library = LoadLibrary("syscollector_win_ext.dll");

    if (sys_library != NULL){
        _get_network_win = (CallFunc)GetProcAddress(sys_library, "get_network");

        if (!_get_network_win){
            mterror(WM_SYS_LOGTAG, "Unable to access functions of syscollector_win_ext.dll.");
            return;
        }else{

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
                    string = _get_network_win(pCurrAddresses);

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
        }
    }else{
        mterror(WM_SYS_LOGTAG, "Unable to load syscollector_win_ext.dll.");
    }

}

hw_info *get_system_windows(){

    hw_info *info;
    char *command;
    char *end;
    FILE *output;
    size_t buf_length = 1024;
    char read_buff[buf_length];

    os_calloc(1,sizeof(hw_info),info);

    memset(read_buff, 0, buf_length);
    command = "wmic cpu get Name";
    output = popen(command, "r");
    if (!output){
        mtwarn(WM_SYS_LOGTAG, "Unable to execute command '%s'.", command);
        info->cpu_name = strdup("unknown");
    }else{
        if (strncmp(fgets(read_buff, buf_length, output),"Name",4) == 0) {
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
    }
    pclose(output);

    memset(read_buff, 0, buf_length);
    char *cores;
    command = "wmic cpu get NumberOfCores";
    output = popen(command, "r");
    if (!output){
        mtwarn(WM_SYS_LOGTAG, "Unable to execute command '%s'.", command);
    }else{
        if (strncmp(fgets(read_buff, buf_length, output),"NumberOfCores",13) == 0) {
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
    }
    pclose(output);

    memset(read_buff, 0, buf_length);
    char *frec;
    command = "wmic cpu get CurrentClockSpeed";
    output = popen(command, "r");
    if (!output){
        mtwarn(WM_SYS_LOGTAG, "Unable to execute command '%s'.", command);
    }else{
        if (strncmp(fgets(read_buff, buf_length, output),"CurrentClockSpeed",17) == 0) {
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
    }
    pclose(output);

    memset(read_buff, 0, buf_length);
    char *total;
    command = "wmic computersystem get TotalPhysicalMemory";
    output = popen(command, "r");
    if (!output){
        mtwarn(WM_SYS_LOGTAG, "Unable to execute command '%s'.", command);
    }else{
        if (strncmp(fgets(read_buff, buf_length, output),"TotalPhysicalMemory",19) == 0) {
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
    }
    pclose(output);

    memset(read_buff, 0, buf_length);
    char *mem_free;
    command = "wmic os get FreePhysicalMemory";
    output = popen(command, "r");
    if (!output){
        mtwarn(WM_SYS_LOGTAG, "Unable to execute command '%s'.", command);
    }else{
        if (strncmp(fgets(read_buff, buf_length, output),"FreePhysicalMemory",18) == 0) {
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
    }
    pclose(output);

    return info;
}

#endif
