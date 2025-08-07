/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
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
#include "agentd.h"

/* Global variables */
time_t available_server;
time_t last_connection_time;
int run_foreground;
keystore keys;
agent *agt;
#ifndef WIN32
anti_tampering *atc;
#endif
int remote_conf;
int min_eps;
int rotate_log;
int agent_debug_level;

/* Read the config file (for the remote client) */
int ClientConf(const char *cfgfile)
{
    int modules = 0;

    agt->server = NULL;
    agt->rip_id = 0;
    agt->execdq = 0;
    agt->profile = NULL;
    agt->buffer = 1;
    agt->buflength = 5000;
    agt->events_persec = 500;
    agt->flags.auto_restart = 1;
    agt->crypto_method = W_METH_AES;
    agt->notify_time = 0;
    agt->max_time_reconnect_try = 0;
    agt->force_reconnect_interval = 0;
    agt->main_ip_update_interval = 0;
    agt->server_count = 0;

#ifndef WIN32
    atc->package_uninstallation = false;
#endif

    os_calloc(1, sizeof(wlabel_t), agt->labels);
    modules |= CCLIENT;

    w_enrollment_cert *cert_cfg = w_enrollment_cert_init();
    w_enrollment_target *target_cfg = w_enrollment_target_init();

    // Initialize enrollment_cfg
    agt->enrollment_cfg = w_enrollment_init(target_cfg, cert_cfg, &keys);
    agt->enrollment_cfg->allow_localhost = false; // Localhost not allowed in auto-enrollment
    agt->enrollment_cfg->recv_timeout = getDefine_Int("agent", "recv_timeout", 1, 600);

    if (ReadConfig(modules, cfgfile, agt, NULL) < 0 ||
        ReadConfig(CLABELS | CBUFFER, cfgfile, &agt->labels, agt) < 0) {
        return (OS_INVALID);
    }

#ifdef CLIENT
    if(agt->flags.remote_conf = getDefine_Int("agent", "remote_conf", 0, 1), agt->flags.remote_conf) {
        remote_conf = agt->flags.remote_conf;
        ReadConfig(CLABELS | CBUFFER | CAGENT_CONFIG, AGENTCONFIG, &agt->labels, agt);
        ReadConfig(CCLIENT | CAGENT_CONFIG, AGENTCONFIG, agt, NULL);
    }
#ifndef WIN32
    if (ReadConfig(ATAMPERING, cfgfile, atc, NULL) < 0) {
        return OS_INVALID;
    }
#endif
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
    cJSON_AddNumberToObject(client,"force_reconnect_interval",agt->force_reconnect_interval);
    cJSON_AddNumberToObject(client,"ip_update_interval",agt->main_ip_update_interval);
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
            cJSON_AddStringToObject(server, "address", agt->server[i].rip);
            cJSON_AddNumberToObject(server, "port", agt->server[i].port);

            if (agt->server[i].network_interface)
                cJSON_AddNumberToObject(server, "interface_index", agt->server[i].network_interface);

            cJSON_AddNumberToObject(server, "max_retries", agt->server[i].max_retries);
            cJSON_AddNumberToObject(server, "retry_interval", agt->server[i].retry_interval);

            if (agt->server[i].protocol == IPPROTO_UDP) cJSON_AddStringToObject(server,"protocol","udp"); else cJSON_AddStringToObject(server,"protocol","tcp");
            cJSON_AddItemToArray(servers,server);
        }
        cJSON_AddItemToObject(client,"server",servers);
    }

    if (agt->enrollment_cfg) {
        cJSON *enrollment_cfg = cJSON_CreateObject();
        cJSON_AddStringToObject(enrollment_cfg, "enabled", agt->enrollment_cfg->enabled ? "yes" : "no");
        cJSON_AddNumberToObject(enrollment_cfg, "delay_after_enrollment", agt->enrollment_cfg->delay_after_enrollment);

        if (agt->enrollment_cfg->target_cfg->manager_name)
            cJSON_AddStringToObject(enrollment_cfg, "manager_address", agt->enrollment_cfg->target_cfg->manager_name);

        if (agt->enrollment_cfg->target_cfg->network_interface)
            cJSON_AddNumberToObject(enrollment_cfg, "interface_index", agt->enrollment_cfg->target_cfg->network_interface);

        cJSON_AddNumberToObject(enrollment_cfg, "port", agt->enrollment_cfg->target_cfg->port);

        if (agt->enrollment_cfg->target_cfg->agent_name)
            cJSON_AddStringToObject(enrollment_cfg, "agent_name", agt->enrollment_cfg->target_cfg->agent_name);
        if (agt->enrollment_cfg->target_cfg->centralized_group)
            cJSON_AddStringToObject(enrollment_cfg, "group", agt->enrollment_cfg->target_cfg->centralized_group);

        cJSON_AddStringToObject(enrollment_cfg, "ssl_cipher", agt->enrollment_cfg->cert_cfg->ciphers);

        if (agt->enrollment_cfg->cert_cfg->ca_cert)
            cJSON_AddStringToObject(enrollment_cfg, "server_certificate_path", agt->enrollment_cfg->cert_cfg->ca_cert);
        if (agt->enrollment_cfg->cert_cfg->agent_cert)
            cJSON_AddStringToObject(enrollment_cfg, "agent_certificate_path", agt->enrollment_cfg->cert_cfg->agent_cert);
        if (agt->enrollment_cfg->cert_cfg->agent_key)
            cJSON_AddStringToObject(enrollment_cfg, "agent_key_path", agt->enrollment_cfg->cert_cfg->agent_key);
        if(agt->enrollment_cfg->cert_cfg->authpass)
            cJSON_AddStringToObject(enrollment_cfg, "authorization_pass_path", agt->enrollment_cfg->cert_cfg->authpass_file);

        cJSON_AddStringToObject(enrollment_cfg,"auto_method",agt->enrollment_cfg->cert_cfg->auto_method ? "yes": "no");
        cJSON_AddItemToObject(client,"enrollment",enrollment_cfg);
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

    cJSON *root = cJSON_CreateObject();
    cJSON *labels = cJSON_CreateArray();

    if (agt->labels) {
        unsigned int i;
        for (i=0; agt->labels[i].key; i++) {
            cJSON *label = cJSON_CreateObject();
            cJSON_AddStringToObject(label, "value", agt->labels[i].value);
            cJSON_AddStringToObject(label, "key", agt->labels[i].key);
            cJSON_AddStringToObject(label, "hidden", agt->labels[i].flags.hidden ? "yes" : "no");
            cJSON_AddItemToObject(labels, "", label);
        }
    }

    cJSON_AddItemToObject(root, "labels", labels);

    return root;
}

#ifndef WIN32
cJSON *getAntiTamperingConfig(void) {

    if (!atc) {
        return NULL;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON *package_uninstallation = cJSON_CreateArray();

    if (atc->package_uninstallation) cJSON_AddStringToObject(package_uninstallation,"package_uninstallation","yes"); else cJSON_AddStringToObject(package_uninstallation,"package_uninstallation","no");

    cJSON_AddItemToObject(root, "package_uninstallation", package_uninstallation);

    return root;
}
#endif

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
