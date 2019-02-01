/*
 * Wazuh Module for Agent control
 * Copyright (C) 2015-2019, Wazuh Inc.
 * January, 2019
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wm_control.h"
#include "syscollector/syscollector.h"
#include <ifaddrs.h>

static void *wm_control_main();
static void *wm_control_destroy();
cJSON *wm_control_dump(void);

const wm_context WM_CONTROL_CONTEXT = {
    "control",
    (wm_routine)wm_control_main,
    (wm_routine)wm_control_destroy,
    (cJSON * (*)(const void *))wm_control_dump
};

char* getPrimaryIP(){
     /* Get Primary IP */
    char * reporting_ip = NULL;
    char **ifaces_list;
    struct ifaddrs *ifaddr, *ifa;
    int size;
    int i = 0;
    
    if (getifaddrs(&ifaddr) == -1) {
        merror("getifaddrs() failed.");
    }
    else {
        for (ifa = ifaddr; ifa; ifa = ifa->ifa_next){
            i++;
        }
        os_calloc(i, sizeof(char *), ifaces_list);

        /* Create interfaces list */
        size = getIfaceslist(ifaces_list, ifaddr);

        if(!ifaces_list[0]){
            merror("No interface found. No reporting ip.");
            free(ifaces_list);
            return NULL;
        }

        FILE *fp;
        char file_location[PATH_LENGTH];
        char if_name[256] = "";
        char interface_name[256] = "";
        char string[OS_MAXSTR];
        struct in_addr address;
        int destination, gateway, flags, ref, use, metric;
        int min_metric = 999999;
        snprintf(file_location, PATH_LENGTH, "%s%s", WM_SYS_NET_DIR, "route");

        if ((fp = fopen(file_location, "r"))){

            while (fgets(string, OS_MAXSTR, fp) != NULL){

                if (sscanf(string, "%s %8x %8x %d %d %d %d", if_name, &destination, &gateway, &flags, &ref, &use, &metric) == 7){
                    if (destination == 00000000 && metric < min_metric){
                        strncpy(interface_name, if_name, 256);
                        min_metric = metric;
                    }
                }

            }
        fclose(fp);
    }    

        for (i=0; i<size; i++){
            cJSON *object = cJSON_CreateObject();
            getNetworkIface(object, ifaces_list[i], ifaddr);
            cJSON *interface = cJSON_GetObjectItem(object, "iface");
            cJSON *name = cJSON_GetObjectItem(interface,"name");
            if(!strcmp(interface_name,name->valuestring)){
                cJSON *ipv4 = cJSON_GetObjectItem(interface, "IPv4");
                cJSON *addresses = cJSON_GetObjectItem(ipv4,"address");
                cJSON *address = cJSON_GetArrayItem(addresses,0);
                os_strdup(address->valuestring, reporting_ip);
                cJSON_Delete(object);
                break;
            }
            cJSON_Delete(object);
        }

        freeifaddrs(ifaddr);
        for (i=0; ifaces_list[i]; i++){
            free(ifaces_list[i]);
        }
        free(ifaces_list);
    }

    return reporting_ip;
}

void *wm_control_main(){

    mtinfo(WM_CONTROL_LOGTAG, "Starting control thread.");

    while(1){

        if(reporting_ip)
            free(reporting_ip);
            
        reporting_ip = getPrimaryIP();
        mtinfo(WM_CONTROL_LOGTAG, "Reporting IP: %s", reporting_ip);
        
        sleep(20);

    }
}

wmodule *wm_control_read(){
    wmodule * module;

    os_calloc(1, sizeof(wmodule), module);
    module->context = &WM_CONTROL_CONTEXT;
    module->tag = strdup(module->context->name);

    return module;
}

void *wm_control_destroy(){

}

cJSON *wm_control_dump(void) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();
    cJSON_AddStringToObject(wm_wd,"enabled","yes");
    cJSON_AddItemToObject(root,"wazuh_control",wm_wd);
    return root;
}
