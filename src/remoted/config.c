/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"
#include "os_net/os_net.h"
#include "remoted.h"
#include "config/config.h"


/* Read the config file (the remote access) */
int RemotedConfig(const char *cfgfile, remoted *cfg)
{
    int modules = 0;

    modules |= CREMOTE;

    cfg->port = NULL;
    cfg->conn = NULL;
    cfg->allowips = NULL;
    cfg->denyips = NULL;
    cfg->nocmerged = 0;
    cfg->queue_size = 131072;

    if (ReadConfig(modules, cfgfile, cfg, NULL) < 0) {
        return (OS_INVALID);
    }

    if (cfg->queue_size < 1) {
        merror("Queue size is invalid. Review configuration.");
        return OS_INVALID;
    }

    if (cfg->queue_size > 262144) {
        mwarn("Queue size is very high. The application may run out of memory.");
    }

    const char *(xmlf[]) = {"ossec_config", "cluster", "node_name", NULL};

    OS_XML xml;

    if (OS_ReadXML(cfgfile, &xml) < 0){
        merror_exit(XML_ERROR, cfgfile, xml.err, xml.err_line);
    }

    node_name = OS_GetOneContentforElement(&xml, xmlf);

    OS_ClearXML(&xml);

    return (1);
}


cJSON *getRemoteConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *rem = cJSON_CreateArray();
    unsigned int i,j;

    if(logr.conn) {
        for(i=0;logr.conn[i];i++){
            cJSON *conn = cJSON_CreateObject();
            if (logr.conn[i] == SYSLOG_CONN) cJSON_AddStringToObject(conn,"connection","syslog");
            else if (logr.conn[i] == SECURE_CONN) cJSON_AddStringToObject(conn,"connection","secure");
            if (logr.ipv6 && logr.ipv6[i]) cJSON_AddStringToObject(conn,"ipv6","yes"); else cJSON_AddStringToObject(conn,"ipv6","no");
            if (logr.lip && logr.lip[i]) cJSON_AddStringToObject(conn,"local_ip",logr.lip[i]);
            if (logr.allowips && (int)i!=logr.position) {
                cJSON *list = cJSON_CreateArray();
                for(j=0;logr.allowips[j];j++){
                    cJSON_AddItemToArray(list,cJSON_CreateString(logr.allowips[j]->ip));
                }
                cJSON_AddItemToObject(conn,"allowed-ips",list);
            }
            if (logr.denyips && (int)i!=logr.position) {
                cJSON *list = cJSON_CreateArray();
                for(j=0;logr.denyips[j];j++){
                    cJSON_AddItemToArray(list,cJSON_CreateString(logr.denyips[j]->ip));
                }
                cJSON_AddItemToObject(conn,"denied-ips",list);
            }
            cJSON_AddItemToArray(rem,conn);
        }
    }

    cJSON_AddItemToObject(root,"remote",rem);

    return root;
}
