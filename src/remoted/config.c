/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
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

/* Global variables */
int pass_empty_keyfile;
int timeout;
unsigned receive_chunk;
unsigned send_chunk;
unsigned send_buffer_size;
int send_timeout_to_retry;
int buffer_relax;

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
    cfg->allow_higher_versions = REMOTED_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT;
    cfg->connection_overtake_time = 60;
    cfg->allow_agents_enrollment = true;

    receive_chunk = (unsigned)getDefine_Int("remoted", "receive_chunk", 1024, 16384);
    send_chunk = (unsigned)getDefine_Int("remoted", "send_chunk", 512, 16384);
    buffer_relax = getDefine_Int("remoted", "buffer_relax", 0, 2);
    send_buffer_size = (unsigned)getDefine_Int("remoted", "send_buffer_size", 65536, 1048576);
    send_timeout_to_retry = getDefine_Int("remoted", "send_timeout_to_retry", 1, 60);

    /* Setting default values for global parameters */
    cfg->global.agents_disconnection_time = 600;
    cfg->global.agents_disconnection_alert_time = 0;

    if (ReadConfig(modules, cfgfile, cfg, NULL) < 0 ||
        ReadConfig(CGLOBAL, cfgfile, &cfg->global, NULL) < 0 ) {
        return (OS_INVALID);
    }

    if (cfg->queue_size < 1) {
        merror("Queue size is invalid. Review configuration.");
        return OS_INVALID;
    }

    if (cfg->queue_size > 262144) {
        mwarn("Queue size is very high. The application may run out of memory.");
    }

    /* Get node name of the manager in cluster */
    node_name = get_node_name();

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

            if (logr.proto) {
                cJSON * proto_array = cJSON_CreateArray();

                /* If TCP is enabled */
                if (logr.proto[i] & REMOTED_NET_PROTOCOL_TCP) {
                    cJSON_AddItemToArray(proto_array, cJSON_CreateString(REMOTED_NET_PROTOCOL_TCP_STR));
                }
                /* If UDP is enabled */
                if (logr.proto[i] & REMOTED_NET_PROTOCOL_UDP) {
                    cJSON_AddItemToArray(proto_array, cJSON_CreateString(REMOTED_NET_PROTOCOL_UDP_STR));
                }
                cJSON_AddItemToObject(conn, "protocol", proto_array);
            }

            if (logr.port && logr.port[i]){
                sprintf(port,"%d",logr.port[i]);
                cJSON_AddStringToObject(conn,"port",port);
            }
            if (logr.queue_size && (logr.conn[i] == SECURE_CONN)) {
                sprintf(queue_size,"%ld",logr.queue_size);
                cJSON_AddStringToObject(conn,"queue_size", queue_size);

                cJSON * agents = cJSON_CreateObject();
                cJSON_AddStringToObject(agents, "allow_higher_versions", logr.allow_higher_versions ? "yes" : "no");
                cJSON_AddItemToObject(conn, "agents", agents);
            }
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

            cJSON_AddNumberToObject(conn, "connection_overtake_time", logr.connection_overtake_time);

            if (logr.allow_agents_enrollment) {
                cJSON_AddStringToObject(conn, "allow_agents_enrollment", "yes");
            } else {
                cJSON_AddStringToObject(conn, "allow_agents_enrollment", "no");
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

    cJSON_AddNumberToObject(remoted,"recv_counter_flush",_s_recv_flush);
    cJSON_AddNumberToObject(remoted,"comp_average_printout",_s_comp_print);
    cJSON_AddNumberToObject(remoted,"verify_msg_id",_s_verify_counter);
    cJSON_AddNumberToObject(remoted,"recv_timeout",timeout);
    cJSON_AddNumberToObject(remoted,"pass_empty_keyfile",pass_empty_keyfile);
    cJSON_AddNumberToObject(remoted,"sender_pool",sender_pool);
    cJSON_AddNumberToObject(remoted,"request_pool",request_pool);
    cJSON_AddNumberToObject(remoted,"request_rto_sec",rto_sec);
    cJSON_AddNumberToObject(remoted,"request_rto_msec",rto_msec);
    cJSON_AddNumberToObject(remoted,"max_attempts",max_attempts);
    cJSON_AddNumberToObject(remoted,"request_timeout",request_timeout);
    cJSON_AddNumberToObject(remoted,"response_timeout",response_timeout);
    cJSON_AddNumberToObject(remoted,"shared_reload",INTERVAL);
    cJSON_AddNumberToObject(remoted,"disk_storage",disk_storage);
    cJSON_AddNumberToObject(remoted,"rlimit_nofile",nofile);
    cJSON_AddNumberToObject(remoted,"merge_shared",logr.nocmerged);
    cJSON_AddNumberToObject(remoted,"receive_chunk",receive_chunk);
    cJSON_AddNumberToObject(remoted,"send_chunk",send_chunk);
    cJSON_AddNumberToObject(remoted,"buffer_relax",buffer_relax);
    cJSON_AddNumberToObject(remoted,"send_buffer_size",send_buffer_size);
    cJSON_AddNumberToObject(remoted,"send_timeout_to_retry",send_timeout_to_retry);
    cJSON_AddNumberToObject(remoted,"tcp_keepidle",tcp_keepidle);
    cJSON_AddNumberToObject(remoted,"tcp_keepintvl",tcp_keepintvl);
    cJSON_AddNumberToObject(remoted,"tcp_keepcnt",tcp_keepcnt);

    cJSON_AddItemToObject(internals,"remoted",remoted);
    cJSON_AddItemToObject(root,"internal",internals);

    return root;

}

cJSON *getRemoteGlobalConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *global = cJSON_CreateObject();
    cJSON *remoted = cJSON_CreateObject();

    cJSON_AddNumberToObject(remoted,"agents_disconnection_alert_time",logr.global.agents_disconnection_alert_time);
    cJSON_AddNumberToObject(remoted,"agents_disconnection_time",logr.global.agents_disconnection_time);

    cJSON_AddItemToObject(global,"remoted",remoted);
    cJSON_AddItemToObject(root,"global",global);

    return root;

}
