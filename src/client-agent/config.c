/* Copyright (C) 2015-2019, Wazuh Inc.
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
int run_foreground;
keystore keys;
agent *agt;

int rotate_log;

/* Set client internal options to default */
static void init_conf()
{
    /* Client buffer */
    agt->tolerance = options.client_buffer.tolerance.def;
    agt->min_eps = options.client_buffer.min_eps.def;
    agt->warn_level = options.client_buffer.warn_level.def;
    agt->normal_level = options.client_buffer.normal_level.def;
    /* Client */
    agt->state_interval = options.client.state_interval.def;
    agt->recv_timeout = options.client.recv_timeout.def;
    agt->flags.remote_conf = options.client.remote_conf.def;
    agt->log_level = options.client.log_level.def;
    agt->recv_counter_flush = options.client.recv_counter_flush.def;
    agt->comp_average_printout = options.client.comp_average_printout.def;
    agt->verify_msg_id = options.client.verify_msg_id.def;
    agt->request_pool = options.client.request_pool.def;
    agt->rto_sec = options.client.request_rto_sec.def;
    agt->rto_msec = options.client.request_rto_msec.def;
    agt->max_attempts = options.client.max_attempts.def;
    agt->thread_stack_size = options.global.thread_stack_size.def;

    return;
}

/* Set client internal options */
static void read_internal()
{
    int aux;
    /* Client buffer */
    if ((aux = getDefine_Int("agent", "tolerance", options.client_buffer.tolerance.min, options.client_buffer.tolerance.max)) != INT_OPT_NDEF)
        agt->tolerance = aux;
    if ((aux = getDefine_Int("agent", "min_eps", options.client_buffer.min_eps.min, options.client_buffer.min_eps.max)) != INT_OPT_NDEF)
        agt->min_eps = aux;
    if ((aux = getDefine_Int("agent", "warn_level", options.client_buffer.warn_level.min, options.client_buffer.warn_level.max)) != INT_OPT_NDEF)
        agt->warn_level = aux;
    if ((aux = getDefine_Int("agent", "normal_level", options.client_buffer.normal_level.min, options.client_buffer.normal_level.max)) != INT_OPT_NDEF)
        agt->normal_level = aux;
    /* Client */
    if ((aux = getDefine_Int("agent", "state_interval", options.client.state_interval.min, options.client.state_interval.max)) != INT_OPT_NDEF)
        agt->state_interval = aux;
    if ((aux = getDefine_Int("agent", "recv_timeout", options.client.recv_timeout.min, options.client.recv_timeout.max)) != INT_OPT_NDEF)
        agt->recv_timeout = aux;
    if ((aux = getDefine_Int("agent", "remote_conf", options.client.remote_conf.min, options.client.remote_conf.max)) != INT_OPT_NDEF)
        agt->flags.remote_conf = aux;
#ifdef WIN32
    if ((aux = getDefine_Int("windows", "debug", options.client.log_level.min, options.client.log_level.max)) != INT_OPT_NDEF)
        agt->log_level = aux;
#else
    if ((aux = getDefine_Int("agent", "debug", options.client.log_level.min, options.client.log_level.max)) != INT_OPT_NDEF)
        agt->log_level = aux;
#endif
    if ((aux = getDefine_Int("remoted", "recv_counter_flush", options.client.recv_counter_flush.min, options.client.recv_counter_flush.max)) != INT_OPT_NDEF)
        agt->recv_counter_flush = aux;
    if ((aux =  getDefine_Int("remoted", "comp_average_printout", options.client.comp_average_printout.min, options.client.comp_average_printout.max)) != INT_OPT_NDEF)
        agt->comp_average_printout = aux;
    if ((aux =  getDefine_Int("remoted", "verify_msg_id", options.client.verify_msg_id.min, options.client.verify_msg_id.max)) != INT_OPT_NDEF)
        agt->verify_msg_id = aux;
    if((aux = getDefine_Int("remoted", "request_pool", options.client.request_pool.min, options.client.request_pool.max)) != INT_OPT_NDEF)
        agt->request_pool = aux;
    if((aux = getDefine_Int("remoted", "request_rto_sec", options.client.request_rto_sec.min, options.client.request_rto_sec.max)) != INT_OPT_NDEF)
        agt->rto_sec = aux;
    if ((aux = getDefine_Int("remoted", "request_rto_msec", options.client.request_rto_msec.min, options.client.request_rto_msec.max)) != INT_OPT_NDEF)
        agt->rto_msec = aux;
    if ((aux = getDefine_Int("remoted", "max_attempts", options.client.max_attempts.min, options.client.max_attempts.max)) != INT_OPT_NDEF)
        agt->max_attempts = aux;
    if ((aux = getDefine_Int("wazuh", "thread_stack_size", options.global.thread_stack_size.min, options.global.thread_stack_size.max)) != INT_OPT_NDEF)
        agt->thread_stack_size = aux;        

    return;
}

/* Read the config file (for the remote client) */
int ClientConf(const char *cfgfile)
{
    int modules = 0;

    agt->server = NULL;
    agt->lip = NULL;
    agt->rip_id = 0;
    agt->execdq = 0;
    agt->cfgadq = -1;
    agt->profile = NULL;
    agt->buffer = 1;
    agt->buflength = 5000;
    agt->events_persec = 500;
    agt->flags.auto_restart = 1;
    agt->crypto_method = W_METH_AES;

    os_calloc(1, sizeof(wlabel_t), agt->labels);
    modules |= CCLIENT;

    init_conf();

    if (ReadConfig(modules, cfgfile, agt, NULL) < 0 ||
        ReadConfig(CLABELS | CBUFFER, cfgfile, &agt->labels, agt) < 0) {
        return (OS_INVALID);
    }

    read_internal();

#ifdef CLIENT
    if(agt->flags.remote_conf) {
        ReadConfig(CLABELS | CBUFFER | CAGENT_CONFIG, AGENTCONFIG, &agt->labels, agt);
    }
#endif

    if (agt->events_persec < agt->min_eps) {
        mwarn("Client buffer throughput too low: set to %d eps", agt->min_eps);
        agt->events_persec = agt->min_eps;
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
            if (agt->server[i].protocol == IPPROTO_UDP) cJSON_AddStringToObject(server,"protocol","udp"); else cJSON_AddStringToObject(server,"protocol","tcp");
            cJSON_AddItemToArray(servers,server);
        }
        cJSON_AddItemToObject(client,"server",servers);
    }

    cJSON *remoted = cJSON_CreateObject();

    if (agt->state_interval) cJSON_AddNumberToObject(remoted, "state_interval", agt->state_interval);
    else cJSON_AddStringToObject(remoted, "state_interval", "disabled");
    cJSON_AddNumberToObject(remoted, "recv_timeout", agt->recv_timeout);
#ifdef CLIENT
    cJSON_AddStringToObject(remoted, "remote_conf", agt->flags.remote_conf ? "enabled" : "disabled");
#endif
    cJSON_AddNumberToObject(remoted, "max_attempts", agt->max_attempts);

    cJSON *request = cJSON_CreateObject();

    cJSON_AddNumberToObject(request, "pool", agt->request_pool);
    cJSON_AddNumberToObject(request, "rto_sec", agt->rto_sec);
    cJSON_AddNumberToObject(request, "rto_msec", agt->rto_msec);

    cJSON_AddItemToObject(remoted, "request", request);

    cJSON_AddNumberToObject(remoted, "comp_average_printout", agt->comp_average_printout);
    cJSON_AddNumberToObject(remoted, "recv_counter_flush", agt->recv_counter_flush);
    cJSON_AddNumberToObject(remoted, "verify_msg_id", agt->verify_msg_id);
    cJSON_AddNumberToObject(remoted, "thread_stack_size", agt->thread_stack_size);
    cJSON_AddNumberToObject(remoted, "log_level", agt->log_level);

    cJSON_AddItemToObject(client, "remote", remoted);

    cJSON_AddItemToObject(root, "client", client);

    return root;
}

cJSON *getBufferConfig(void) {

    if (!agt) {
        return NULL;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON *buffer = cJSON_CreateObject();
    cJSON *bucket = cJSON_CreateObject();

    if (agt->buffer) cJSON_AddStringToObject(buffer, "disabled", "no"); else cJSON_AddStringToObject(buffer, "disabled", "yes");
    cJSON_AddNumberToObject(buffer, "queue_size", agt->buflength);
    cJSON_AddNumberToObject(buffer, "events_per_second", agt->events_persec);
    cJSON_AddNumberToObject(buffer, "tolerance", agt->tolerance);

    cJSON_AddNumberToObject(bucket, "warn_level", agt->warn_level);
    cJSON_AddNumberToObject(bucket, "normal_level", agt->normal_level);
    cJSON_AddItemToObject(buffer, "buffer", bucket);

    cJSON_AddNumberToObject(buffer, "min_eps", agt->min_eps);

    cJSON_AddItemToObject(root, "buffer", buffer);

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

cJSON *getAgentLoggingOptions(void) {
    char aux[50];
    cJSON *root = cJSON_CreateObject();

    cJSON *logging = cJSON_CreateObject();

    if (mond.enabled) {
        cJSON_AddStringToObject(logging, "plain_format", mond.ossec_log_plain ? "yes" : "no");
        cJSON_AddStringToObject(logging, "json_format", mond.ossec_log_json ? "yes" : "no");
        if (mond.rotation_enabled) {
            cJSON_AddStringToObject(logging, "compress_rotation", mond.compress_rotation ? "yes" : "no");
            snprintf(aux, 50, "%d", mond.rotate);
            cJSON_AddStringToObject(logging, "saved_rotations", mond.rotate == -1 ? "unlimited" : aux);
            if (mond.interval_units == 'w') {
                char *buffer;
                buffer = int_to_day(mond.interval);
                cJSON_AddStringToObject(logging, "schedule", buffer);
                os_free(buffer);
            } else {
                snprintf(aux, 50, "%ld%c", mond.interval, mond.interval_units);
                cJSON_AddStringToObject(logging, "schedule", mond.interval ? aux : "no");
            }
            snprintf(aux, 50, "%ld%c", mond.size_rotate, mond.size_units);
            cJSON_AddStringToObject(logging, "maxsize", mond.size_rotate ? aux : "no");
            snprintf(aux, 50, "%ld%c", mond.min_size_rotate, mond.min_size_units);
            cJSON_AddStringToObject(logging, "minsize", mond.min_size_rotate ? aux : "no");
            cJSON_AddNumberToObject(logging, "maxage", mond.maxage);
        }
    }

    cJSON_AddItemToObject(root, "logging", logging);

    return root;

}

void resolveHostname(char **hostname, int attempts) {

    char *tmp_str;
    char *f_ip;

    if (OS_IsValidIP(*hostname, NULL) == 1) {
        return;
    }

    tmp_str = strchr(*hostname, '/');
    if (tmp_str) {
        *tmp_str = '\0';
    }

    f_ip = OS_GetHost(*hostname, attempts);
    if (f_ip) {
        char ip_str[128] = {0};
        snprintf(ip_str, 127, "%s/%s", *hostname, f_ip);
        free(f_ip);
        free(*hostname);
        os_strdup(ip_str, *hostname);
    } else {
        char ip_str[128] = {0};
        snprintf(ip_str, 127, "%s/", *hostname);
        free(*hostname);
        os_strdup(ip_str, *hostname);
    }
}
