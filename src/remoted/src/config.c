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
#include "os_xml.h"
#include "os_regex.h"
#include "os_net.h"
#include "remoted.h"
#include "config.h"
#include "module_limits.h"

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
int shared_reload_interval;
int disk_storage;
size_t batch_events_capacity;
size_t batch_events_per_agent_capacity;
int enrich_cache_expire_time;

/* Manager's module limits instance */
module_limits_t manager_module_limits;
bool manager_module_limits_enabled = true;

/* Read the config file (the remote access) */
int RemotedConfig(const char *cfgfile, remoted *cfg)
{
    int modules = 0;

    /* Initialize module limits with default values */
    module_limits_init(&manager_module_limits);

    /* Read module limits from internal_options.conf */
    /* FIM limits */
    manager_module_limits.fim.file = getDefine_Int_default("fim", "file_limit", 0, INT_MAX, 0);
    manager_module_limits.fim.registry_key = getDefine_Int_default("fim", "registry_key_limit", 0, INT_MAX, 0);
    manager_module_limits.fim.registry_value = getDefine_Int_default("fim", "registry_value_limit", 0, INT_MAX, 0);

    /* Syscollector limits */
    manager_module_limits.syscollector.hotfixes = getDefine_Int_default("syscollector", "hotfixes_limit", 0, INT_MAX, 0);
    manager_module_limits.syscollector.packages = getDefine_Int_default("syscollector", "packages_limit", 0, INT_MAX, 0);
    manager_module_limits.syscollector.processes = getDefine_Int_default("syscollector", "processes_limit", 0, INT_MAX, 0);
    manager_module_limits.syscollector.ports = getDefine_Int_default("syscollector", "ports_limit", 0, INT_MAX, 0);
    manager_module_limits.syscollector.network_iface = getDefine_Int_default("syscollector", "network_iface_limit", 0, INT_MAX, 0);
    manager_module_limits.syscollector.network_protocol = getDefine_Int_default("syscollector", "network_protocol_limit", 0, INT_MAX, 0);
    manager_module_limits.syscollector.network_address = getDefine_Int_default("syscollector", "network_address_limit", 0, INT_MAX, 0);
    manager_module_limits.syscollector.hardware = getDefine_Int_default("syscollector", "hardware_limit", 0, INT_MAX, 0);
    manager_module_limits.syscollector.os_info = getDefine_Int_default("syscollector", "os_info_limit", 0, INT_MAX, 0);
    manager_module_limits.syscollector.users = getDefine_Int_default("syscollector", "users_limit", 0, INT_MAX, 0);
    manager_module_limits.syscollector.groups = getDefine_Int_default("syscollector", "groups_limit", 0, INT_MAX, 0);
    manager_module_limits.syscollector.services = getDefine_Int_default("syscollector", "services_limit", 0, INT_MAX, 0);
    manager_module_limits.syscollector.browser_extensions = getDefine_Int_default("syscollector", "browser_extensions_limit", 0, INT_MAX, 0);

    /* SCA limits */
    manager_module_limits.sca.checks = getDefine_Int_default("sca", "checks_limit", 0, INT_MAX, 0);

    modules |= CREMOTE;

    cfg->port = 0;
    cfg->queue_size = 131072;
    cfg->allow_higher_versions = REMOTED_ALLOW_AGENTS_HIGHER_VERSIONS_DEFAULT;
    cfg->connection_overtake_time = 60;

    // Initialize all internal options
    receive_chunk = (unsigned)getDefine_Int_default("remoted", "receive_chunk", 1024, 16384, 4096);
    send_chunk = (unsigned)getDefine_Int_default("remoted", "send_chunk", 512, 16384, 4096);
    buffer_relax = getDefine_Int_default("remoted", "buffer_relax", 0, 2, 1);
    send_buffer_size = (unsigned)getDefine_Int_default("remoted", "send_buffer_size", 65536, 1048576, 131072);
    send_timeout_to_retry = getDefine_Int_default("remoted", "send_timeout_to_retry", 1, 60, 1);
    recv_timeout = getDefine_Int_default("remoted", "recv_timeout", 1, 60, 1);
    tcp_keepidle = getDefine_Int_default("remoted", "tcp_keepidle", 1, 7200, 30);
    tcp_keepintvl = getDefine_Int_default("remoted", "tcp_keepintvl", 1, 100, 10);
    tcp_keepcnt = getDefine_Int_default("remoted", "tcp_keepcnt", 1, 50, 3);
    worker_pool = getDefine_Int_default("remoted", "worker_pool", 1, 16, 4);
    merge_shared = getDefine_Int_default("remoted", "merge_shared", 0, 1, 1);
    pass_empty_keyfile = getDefine_Int_default("remoted", "pass_empty_keyfile", 0, 1, 1);
    ctrl_msg_queue_size = (size_t)getDefine_Int_default("remoted", "control_msg_queue_size", 4096, 0x1 << 20, 16384);
    keyupdate_interval = getDefine_Int_default("remoted", "keyupdate_interval", 1, 3600, 10);
    router_forwarding_disabled = getDefine_Int_default("remoted", "router_forwarding_disabled", 0, 1, 0);
    state_interval = getDefine_Int_default("remoted", "state_interval", 0, 86400, 5);
    nofile = getDefine_Int_default("remoted", "rlimit_nofile", 1024, 1048576, 458752);
    sender_pool = getDefine_Int_default("remoted", "sender_pool", 1, 64, 8);
    request_pool = getDefine_Int_default("remoted", "request_pool", 1, 4096, 1024);
    request_timeout = getDefine_Int_default("remoted", "request_timeout", 1, 600, 10);
    response_timeout = getDefine_Int_default("remoted", "response_timeout", 1, 3600, 60);
    rto_sec = getDefine_Int_default("remoted", "request_rto_sec", 0, 60, 1);
    rto_msec = getDefine_Int_default("remoted", "request_rto_msec", 0, 999, 0);
    max_attempts = getDefine_Int_default("remoted", "max_attempts", 1, 16, 4);
    shared_reload_interval = getDefine_Int_default("remoted", "shared_reload", 1, 18000, 10);
    disk_storage = getDefine_Int_default("remoted", "disk_storage", 0, 1, 0);
    _s_verify_counter = getDefine_Int_default("remoted", "verify_msg_id", 0, 1, 0);
    batch_events_capacity = (size_t)getDefine_Int_default("remoted", "batch_events_capacity", 0, 0x1<<20, 131072);
    batch_events_per_agent_capacity = (size_t)getDefine_Int_default("remoted", "batch_events_per_agent_capacity", 0, 0x1<<20, 131072);
    enrich_cache_expire_time = getDefine_Int_default("remoted", "enrich_cache_expire_time", 60, 86400, 300);

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

    /* Get node name and cluster name of the manager */
    node_name = get_node_name();
    cluster_name = get_cluster_name();

    return (1);
}


cJSON *getRemoteConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *rem = cJSON_CreateArray();
    char port[255] = {0};
    char queue_size[255] = {0};

    cJSON *conn = cJSON_CreateObject();
    cJSON_AddStringToObject(conn,"connection","secure");
    if (logr.ipv6) cJSON_AddStringToObject(conn,"ipv6","yes"); else cJSON_AddStringToObject(conn,"ipv6","no");

    if (logr.lip) cJSON_AddStringToObject(conn,"local_ip",logr.lip);

    if (logr.proto) {
        cJSON * proto_array = cJSON_CreateArray();

        /* If TCP is enabled */
        if (logr.proto & REMOTED_NET_PROTOCOL_TCP) {
            cJSON_AddItemToArray(proto_array, cJSON_CreateString(REMOTED_NET_PROTOCOL_TCP_STR));
        }
        /* If UDP is enabled */
        if (logr.proto & REMOTED_NET_PROTOCOL_UDP) {
            cJSON_AddItemToArray(proto_array, cJSON_CreateString(REMOTED_NET_PROTOCOL_UDP_STR));
        }
        cJSON_AddItemToObject(conn, "protocol", proto_array);
    }

    if (logr.port){
        sprintf(port,"%d",logr.port);
        cJSON_AddStringToObject(conn,"port",port);
    }

    if (logr.queue_size) {
        sprintf(queue_size,"%ld",logr.queue_size);
        cJSON_AddStringToObject(conn,"queue_size", queue_size);

        cJSON * agents = cJSON_CreateObject();
        cJSON_AddStringToObject(agents, "allow_higher_versions", logr.allow_higher_versions ? "yes" : "no");
        cJSON_AddItemToObject(conn, "agents", agents);
    }

    cJSON_AddNumberToObject(conn, "connection_overtake_time", logr.connection_overtake_time);

    cJSON_AddItemToArray(rem,conn);

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
    cJSON_AddNumberToObject(remoted,"batch_events_capacity",batch_events_capacity);
    cJSON_AddNumberToObject(remoted,"batch_events_per_agent_capacity",batch_events_per_agent_capacity);
    cJSON_AddNumberToObject(remoted,"enrich_cache_expire_time",enrich_cache_expire_time);

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
