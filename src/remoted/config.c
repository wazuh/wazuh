/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
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
    char port[255] = {0};
    char queue_size[255] = {0};

    if(logr.conn) {
        for(i=0;logr.conn[i];i++){
            cJSON *conn = cJSON_CreateObject();
            if (logr.conn[i] == SYSLOG_CONN) cJSON_AddStringToObject(conn,"connection","syslog");
            else if (logr.conn[i] == SECURE_CONN) cJSON_AddStringToObject(conn,"connection","secure");
            if (logr.ipv6 && logr.ipv6[i]) cJSON_AddStringToObject(conn,"ipv6","yes"); else cJSON_AddStringToObject(conn,"ipv6","no");
            if (logr.lip && logr.lip[i]) cJSON_AddStringToObject(conn,"local_ip",logr.lip[i]);
            if (logr.proto && logr.proto[i] == UDP_PROTO) cJSON_AddStringToObject(conn,"protocol","udp");
            else if (logr.proto && logr.proto[i] == TCP_PROTO) cJSON_AddStringToObject(conn,"protocol","tcp");
            if (logr.port && logr.port[i]){
                sprintf(port,"%d",logr.port[i]);
                cJSON_AddStringToObject(conn,"port",port);
            }
            if (logr.queue_size && (logr.conn[i] == SECURE_CONN)) {
                sprintf(queue_size,"%ld",logr.queue_size);
                cJSON_AddStringToObject(conn,"queue_size",queue_size); };
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


cJSON *getRemoteInternalConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *internals = cJSON_CreateObject();
    cJSON *remoted = cJSON_CreateObject();

    cJSON_AddNumberToObject(remoted,"recv_counter_flush",logr.recv_counter_flush);
    cJSON_AddNumberToObject(remoted,"comp_average_printout",logr.comp_average_printout);
    cJSON_AddNumberToObject(remoted,"verify_msg_id",logr.verify_msg_id);
    cJSON_AddNumberToObject(remoted,"pass_empty_keyfile",logr.pass_empty_keyfile);
    cJSON_AddNumberToObject(remoted,"sender_pool",logr.sender_pool);
    cJSON_AddNumberToObject(remoted,"request_pool",logr.request_pool);
    cJSON_AddNumberToObject(remoted,"request_timeout",logr.request_timeout);
    cJSON_AddNumberToObject(remoted,"response_timeout",logr.response_timeout);
    cJSON_AddNumberToObject(remoted,"request_rto_sec",logr.request_rto_sec);
    cJSON_AddNumberToObject(remoted,"request_rto_msec",logr.request_rto_msec);
    cJSON_AddNumberToObject(remoted,"max_attempts",logr.max_attempts);
    cJSON_AddNumberToObject(remoted,"shared_reload",logr.shared_reload);
    cJSON_AddNumberToObject(remoted,"rlimit_nofile",logr.rlimit_nofile);
    cJSON_AddNumberToObject(remoted,"recv_timeout",logr.recv_timeout);
    cJSON_AddNumberToObject(remoted,"send_timeout",logr.send_timeout);
    cJSON_AddNumberToObject(remoted,"merge_shared",logr.nocmerged);
    cJSON_AddNumberToObject(remoted,"keyupdate_interval",logr.keyupdate_interval);
    cJSON_AddNumberToObject(remoted,"worker_pool",logr.worker_pool);
    cJSON_AddNumberToObject(remoted,"state_interval",logr.state_interval);
    cJSON_AddNumberToObject(remoted,"guess_agent_group",logr.guess_agent_group);
    cJSON_AddNumberToObject(remoted,"group_data_flush",logr.group_data_flush);
    cJSON_AddNumberToObject(remoted,"receive_chunk",logr.receive_chunk);
    cJSON_AddNumberToObject(remoted,"buffer_relax",logr.buffer_relax);
    cJSON_AddNumberToObject(remoted,"tcp_keepidle",logr.tcp_keepidle);
    cJSON_AddNumberToObject(remoted,"tcp_keepintvl",logr.tcp_keepintvl);
    cJSON_AddNumberToObject(remoted,"tcp_keepcnt",logr.tcp_keepcnt);
    cJSON_AddNumberToObject(remoted,"debug",logr.logging);

    cJSON_AddItemToObject(internals,"remoted",remoted);
    cJSON_AddItemToObject(root,"internal",internals);

    return root;

}
