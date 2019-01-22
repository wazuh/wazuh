/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
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
#include "agentd.h"

/* Global variables */
time_t available_server;
int run_foreground;
keystore keys;
agent *agt;
int remote_conf;
int min_eps;
int rotate_log;
int agent_debug_level;

/* Read the config file (for the remote client) */
int ClientConf(const char *cfgfile)
{
    int modules = 0;

    agt->server = NULL;
    agt->lip = NULL;
    agt->rip_id = 0;
    agt->execdq = 0;
    agt->profile = NULL;
    agt->buffer = 1;
    agt->buflength = 5000;
    agt->events_persec = 500;
    agt->flags.auto_restart = 1;
    agt->crypto_method = W_METH_AES;

    os_calloc(1, sizeof(wlabel_t), agt->labels);
    modules |= CCLIENT;

    if (ReadConfig(modules, cfgfile, agt, NULL) < 0 ||
        ReadConfig(CLABELS | CBUFFER, cfgfile, &agt->labels, agt) < 0) {
        return (OS_INVALID);
    }

#ifdef CLIENT
    if(agt->flags.remote_conf = getDefine_Int("agent", "remote_conf", 0, 1), agt->flags.remote_conf) {
        remote_conf = agt->flags.remote_conf;
        ReadConfig(CLABELS | CBUFFER | CAGENT_CONFIG, AGENTCONFIG, &agt->labels, agt);
    }
#endif

    if (min_eps = getDefine_Int("agent", "min_eps", 1, 1000), agt->events_persec < min_eps) {
        mwarn("Client buffer throughput too low: set to %d eps", min_eps);
        agt->events_persec = min_eps;
    }

    return (1);
}


cJSON *getClientConfig(void) {

    if (!agt) {
        return NULL;
    }

    unsigned int i;
    cJSON *root = cJSON_CreateObject();
    cJSON *client = cJSON_CreateObject();

    if (agt->profile) cJSON_AddStringToObject(client,"config-profile",agt->profile);
    cJSON_AddNumberToObject(client,"notify_time",agt->notify_time);
    cJSON_AddNumberToObject(client,"time-reconnect",agt->max_time_reconnect_try);
    if (agt->lip) cJSON_AddStringToObject(client,"local_ip",agt->lip);
    if (agt->flags.auto_restart) cJSON_AddStringToObject(client,"auto_restart","yes"); else cJSON_AddStringToObject(client,"auto_restart","no");
    if (agt->flags.remote_conf) cJSON_AddStringToObject(client,"remote_conf","yes"); else cJSON_AddStringToObject(client,"remote_conf","no");
    if (agt->crypto_method == W_METH_BLOWFISH)
        cJSON_AddStringToObject(client,"crypto_method","blowfish");
    else if (agt->crypto_method == W_METH_AES)
        cJSON_AddStringToObject(client,"crypto_method","aes");
    if (agt->server) {
        cJSON *servers = cJSON_CreateArray();
        for (i=0;agt->server[i].rip;i++) {
            cJSON *server = cJSON_CreateObject();
            cJSON_AddStringToObject(server,"address",agt->server[i].rip);
            cJSON_AddNumberToObject(server,"port",agt->server[i].port);
            if (agt->server[i].protocol == UDP_PROTO) cJSON_AddStringToObject(server,"protocol","udp"); else cJSON_AddStringToObject(server,"protocol","tcp");
            cJSON_AddItemToArray(servers,server);
        }
        cJSON_AddItemToObject(client,"server",servers);
    }
    cJSON_AddItemToObject(root,"client",client);

    return root;
}

cJSON *getBufferConfig(void) {

    if (!agt) {
        return NULL;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON *buffer = cJSON_CreateObject();

    if (agt->buffer) cJSON_AddStringToObject(buffer,"disabled","no"); else cJSON_AddStringToObject(buffer,"disabled","yes");
    cJSON_AddNumberToObject(buffer,"queue_size",agt->buflength);
    cJSON_AddNumberToObject(buffer,"events_per_second",agt->events_persec);

    cJSON_AddItemToObject(root,"buffer",buffer);

    return root;
}


cJSON *getLabelsConfig(void) {

    if (!agt) {
        return NULL;
    }

    unsigned int i;
    cJSON *root = cJSON_CreateObject();
    cJSON *labels = cJSON_CreateObject();

    if (agt->labels) {
        for (i=0;agt->labels[i].key;i++) {
            cJSON_AddStringToObject(labels,agt->labels[i].key,agt->labels[i].value);
        }
    }

    cJSON_AddItemToObject(root,"labels",labels);

    return root;
}


cJSON *getAgentInternalOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *internals = cJSON_CreateObject();

    cJSON *agent = cJSON_CreateObject();

#ifdef WIN32
    cJSON_AddNumberToObject(agent,"debug",win_debug_level);
#else
    cJSON_AddNumberToObject(agent,"debug",agent_debug_level);
#endif
    cJSON_AddNumberToObject(agent,"warn_level",warn_level);
    cJSON_AddNumberToObject(agent,"normal_level",normal_level);
    cJSON_AddNumberToObject(agent,"tolerance",tolerance);
    cJSON_AddNumberToObject(agent,"recv_timeout",timeout);
    cJSON_AddNumberToObject(agent,"state_interval",interval);
    cJSON_AddNumberToObject(agent,"min_eps",min_eps);
#ifdef CLIENT
    cJSON_AddNumberToObject(agent,"remote_conf",remote_conf);
#endif

    cJSON_AddItemToObject(internals,"agent",agent);

    cJSON *monitord = cJSON_CreateObject();

    cJSON_AddNumberToObject(monitord,"rotate_log",rotate_log);
    cJSON_AddNumberToObject(monitord,"compress",log_compress);
    cJSON_AddNumberToObject(monitord,"keep_log_days",keep_log_days);
    cJSON_AddNumberToObject(monitord,"day_wait",day_wait);
    cJSON_AddNumberToObject(monitord,"size_rotate",size_rotate_read);
    cJSON_AddNumberToObject(monitord,"daily_rotations",daily_rotations);

    cJSON_AddItemToObject(internals,"monitord",monitord);

    cJSON *remoted = cJSON_CreateObject();

    cJSON_AddNumberToObject(remoted,"request_pool",request_pool);
    cJSON_AddNumberToObject(remoted,"request_rto_sec",rto_sec);
    cJSON_AddNumberToObject(remoted,"request_rto_msec",rto_msec);
    cJSON_AddNumberToObject(remoted,"max_attempts",max_attempts);
    cJSON_AddNumberToObject(remoted,"comp_average_printout",_s_comp_print);
    cJSON_AddNumberToObject(remoted,"recv_counter_flush",_s_recv_flush);
    cJSON_AddNumberToObject(remoted,"verify_msg_id",_s_verify_counter);

    cJSON_AddItemToObject(internals,"remoted",remoted);

    cJSON_AddItemToObject(root,"internal",internals);

    return root;
}
