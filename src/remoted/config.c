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
unsigned receive_chunk;
unsigned send_chunk;
unsigned send_buffer_size;
int send_timeout_to_retry;
int buffer_relax;
int recv_timeout;
int tcp_keepidle;
int tcp_keepintvl;
int tcp_keepcnt;
int worker_pool;
int merge_shared;
size_t ctrl_msg_queue_size;
int keyupdate_interval;
int router_forwarding_disabled;
int state_interval;
rlim_t nofile;
int sender_pool;
int rto_sec;
int rto_msec;
int max_attempts;
int request_pool;
int request_timeout;
int response_timeout;
int guess_agent_group;
int shared_reload_interval;
int disk_storage;

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
    cfg->allow_higher_versions = REMOTED_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT;
    cfg->connection_overtake_time = 60;

    // Initialize all internal options
    receive_chunk = (unsigned)getDefine_Int("remoted", "receive_chunk", 1024, 16384);
    send_chunk = (unsigned)getDefine_Int("remoted", "send_chunk", 512, 16384);
    buffer_relax = getDefine_Int("remoted", "buffer_relax", 0, 2);
    send_buffer_size = (unsigned)getDefine_Int("remoted", "send_buffer_size", 65536, 1048576);
    send_timeout_to_retry = getDefine_Int("remoted", "send_timeout_to_retry", 1, 60);
    recv_timeout = getDefine_Int("remoted", "recv_timeout", 1, 60);
    tcp_keepidle = getDefine_Int("remoted", "tcp_keepidle", 1, 7200);
    tcp_keepintvl = getDefine_Int("remoted", "tcp_keepintvl", 1, 100);
    tcp_keepcnt = getDefine_Int("remoted", "tcp_keepcnt", 1, 50);
    worker_pool = getDefine_Int("remoted", "worker_pool", 1, 16);
    merge_shared = getDefine_Int("remoted", "merge_shared", 0, 1);
    pass_empty_keyfile = getDefine_Int("remoted", "pass_empty_keyfile", 0, 1);
    ctrl_msg_queue_size = (size_t)getDefine_Int("remoted", "control_msg_queue_size", 4096, 0x1 << 20);
    keyupdate_interval = getDefine_Int("remoted", "keyupdate_interval", 1, 3600);
    router_forwarding_disabled = getDefine_Int("remoted", "router_forwarding_disabled", 0, 1);
    state_interval = getDefine_Int("remoted", "state_interval", 0, 86400);
    nofile = getDefine_Int("remoted", "rlimit_nofile", 1024, 1048576);
    sender_pool = getDefine_Int("remoted", "sender_pool", 1, 64);
    request_pool = getDefine_Int("remoted", "request_pool", 1, 4096);
    request_timeout = getDefine_Int("remoted", "request_timeout", 1, 600);
    response_timeout = getDefine_Int("remoted", "response_timeout", 1, 3600);
    rto_sec = getDefine_Int("remoted", "request_rto_sec", 0, 60);
    rto_msec = getDefine_Int("remoted", "request_rto_msec", 0, 999);
    max_attempts = getDefine_Int("remoted", "max_attempts", 1, 16);
    guess_agent_group = getDefine_Int("remoted", "guess_agent_group", 0, 1);
    shared_reload_interval = getDefine_Int("remoted", "shared_reload", 1, 18000);
    disk_storage = getDefine_Int("remoted", "disk_storage", 0, 1);
    _s_verify_counter = getDefine_Int("remoted", "verify_msg_id", 0, 1);

    /* Setting default values for global parameters */
    cfg->global.agents_disconnection_time = 900;
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
    cJSON_AddNumberToObject(remoted,"recv_timeout",recv_timeout);
    cJSON_AddNumberToObject(remoted,"pass_empty_keyfile",pass_empty_keyfile);
    cJSON_AddNumberToObject(remoted,"sender_pool",sender_pool);
    cJSON_AddNumberToObject(remoted,"request_pool",request_pool);
    cJSON_AddNumberToObject(remoted,"request_rto_sec",rto_sec);
    cJSON_AddNumberToObject(remoted,"request_rto_msec",rto_msec);
    cJSON_AddNumberToObject(remoted,"max_attempts",max_attempts);
    cJSON_AddNumberToObject(remoted,"request_timeout",request_timeout);
    cJSON_AddNumberToObject(remoted,"response_timeout",response_timeout);
    cJSON_AddNumberToObject(remoted,"shared_reload",shared_reload_interval);
    cJSON_AddNumberToObject(remoted,"disk_storage",disk_storage);
    cJSON_AddNumberToObject(remoted,"rlimit_nofile",nofile);
    cJSON_AddNumberToObject(remoted,"merge_shared",merge_shared);
    cJSON_AddNumberToObject(remoted,"guess_agent_group",guess_agent_group);
    cJSON_AddNumberToObject(remoted,"receive_chunk",receive_chunk);
    cJSON_AddNumberToObject(remoted,"send_chunk",send_chunk);
    cJSON_AddNumberToObject(remoted,"buffer_relax",buffer_relax);
    cJSON_AddNumberToObject(remoted,"send_buffer_size",send_buffer_size);
    cJSON_AddNumberToObject(remoted,"send_timeout_to_retry",send_timeout_to_retry);
    cJSON_AddNumberToObject(remoted,"tcp_keepidle",tcp_keepidle);
    cJSON_AddNumberToObject(remoted,"tcp_keepintvl",tcp_keepintvl);
    cJSON_AddNumberToObject(remoted,"tcp_keepcnt",tcp_keepcnt);
    cJSON_AddNumberToObject(remoted,"debug",isDebug());
    cJSON_AddNumberToObject(remoted,"worker_pool",worker_pool);
    cJSON_AddNumberToObject(remoted,"control_msg_queue_size",ctrl_msg_queue_size);
    cJSON_AddNumberToObject(remoted,"keyupdate_interval",keyupdate_interval);
    cJSON_AddNumberToObject(remoted,"router_forwarding_disabled",router_forwarding_disabled);
    cJSON_AddNumberToObject(remoted,"state_interval",state_interval);

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
