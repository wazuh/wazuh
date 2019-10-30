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
#include "client-config.h"
#include "os_net/os_net.h"
#include "config.h"
#include "headers/sec.h"

int Read_Client_Server(XML_NODE node, agent *logr);

int Read_Client(const OS_XML *xml, XML_NODE node, void *d1, __attribute__((unused)) void *d2)
{
    int i = 0;
    char f_ip[128] = {'\0'};
    char * rip = NULL;
    int port = DEFAULT_SECURE;
    int protocol = IPPROTO_UDP;

    /* XML definitions */
    const char *xml_client_server = "server";
    const char *xml_local_ip = "local_ip";
    const char *xml_ar_disabled = "disable-active-response";
    const char *xml_notify_time = "notify_time";
    const char *xml_max_time_reconnect_try = "time-reconnect";
    const char *xml_profile_name = "config-profile";
    const char *xml_auto_restart = "auto_restart";
    const char *xml_crypto_method = "crypto_method";

    /* Old XML definitions */
    const char *xml_client_ip = "server-ip";
    const char *xml_client_hostname = "server-hostname";
    const char *xml_client_port = "port";
    const char *xml_protocol = "protocol";

    /* Internal options */
    const char *xml_state_interval = "state_interval";
    const char *xml_recv_timeout = "recv_timeout";
    const char *xml_remote_conf = "remote_conf";
    const char *xml_log_level = "log_level";
    const char *xml_recv_counter_flush = "recv_counter_flush";
    const char *xml_comp_average_printout = "comp_avg_printout";
    const char *xml_verify_msg_id = "verify_msg_id";
    const char *xml_max_attempts = "max_attempts";
    const char *xml_thread_stack_size = "thread_stack_size";
    /* Request block */
    const char *xml_request = "request";
    const char *xml_request_pool = "pool";
    const char *xml_request_rto_sec = "rto_sec";
    const char *xml_request_rto_msec = "rto_msec";

    agent * logr = (agent *)d1;
    logr->notify_time = 0;
    logr->max_time_reconnect_try = 0;
    logr->rip_id = 0;

    for (i = 0; node[i]; i++) {
        rip = NULL;
        XML_NODE chld_node = NULL;
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        }
        /* Get local IP */
        else if (strcmp(node[i]->element, xml_local_ip) == 0) {
            os_strdup(node[i]->content, logr->lip);
            if (OS_IsValidIP(logr->lip, NULL) != 1) {
                merror(INVALID_IP, logr->lip);
                return (OS_INVALID);
            }
        }
        /* Get server IP */
        else if (strcmp(node[i]->element, xml_client_ip) == 0) {
            mwarn("The <%s> tag is deprecated, please use <server><address> instead.", xml_client_ip);

            if (OS_IsValidIP(node[i]->content, NULL) != 1) {
                merror(INVALID_IP, node[i]->content);
                return (OS_INVALID);
            }

            rip = node[i]->content;
        } else if (strcmp(node[i]->element, xml_client_hostname) == 0) {
            mwarn("The <%s> tag is deprecated, please use <server><address> instead.", xml_client_hostname);
            if (strchr(node[i]->content, '/') ==  NULL) {
                snprintf(f_ip, 127, "%s/", node[i]->content);
                rip = f_ip;
            } else {
                merror(AG_INV_HOST, node[i]->content);
                return (OS_INVALID);
            }

        } else if (strcmp(node[i]->element, xml_client_port) == 0) {
            mwarn("The <%s> tag is deprecated, please use <server><port> instead.", xml_client_port);

            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }

            if (port = atoi(node[i]->content), port <= 0 || port > 65535) {
                merror(PORT_ERROR, port);
                return (OS_INVALID);
            }
        }
        /* Get parameters for each configurated server*/
        else if (strcmp(node[i]->element, xml_client_server) == 0) {
            if (!(chld_node = OS_GetElementsbyNode(xml, node[i]))) {
                merror(XML_INVELEM, node[i]->element);
                return (OS_INVALID);
            }
            if (Read_Client_Server(chld_node, logr) < 0) {
                OS_ClearNode(chld_node);
                return (OS_INVALID);
            }

            OS_ClearNode(chld_node);
        } else if (strcmp(node[i]->element, xml_notify_time) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            logr->notify_time = atoi(node[i]->content);

            if (logr->notify_time < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_max_time_reconnect_try) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            logr->max_time_reconnect_try = atoi(node[i]->content);
            if (logr->max_time_reconnect_try < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_ar_disabled) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                logr->execdq = -1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                logr->execdq = 0;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_profile_name) == 0) {
            /* Profile name can be anything hence no validation */
            os_strdup(node[i]->content, logr->profile);
        } else if (strcmp(node[i]->element, xml_auto_restart) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                logr->flags.auto_restart = 1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                logr->flags.auto_restart = 0;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_protocol) == 0) {
            mwarn("The <%s> tag is deprecated, please use <server><protocol> instead.", xml_protocol);

            if (strcmp(node[i]->content, "tcp") == 0) {
                protocol = IPPROTO_TCP;
            } else if (strcmp(node[i]->content, "udp") == 0) {
                protocol = IPPROTO_UDP;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if(strcmp(node[i]->element, xml_crypto_method) == 0){
            if(strcmp(node[i]->content, "blowfish") == 0){
                logr->crypto_method = W_METH_BLOWFISH;
            }
            else if (strcmp(node[i]->content, "aes") == 0){
                logr->crypto_method = W_METH_AES;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_state_interval) == 0) {
            SetConf(node[i]->content, &logr->state_interval, options.client.state_interval, xml_state_interval);
        } else if (strcmp(node[i]->element, xml_recv_timeout) == 0) {
            SetConf(node[i]->content, &logr->recv_timeout, options.client.recv_timeout, xml_recv_timeout);
        } else if (strcmp(node[i]->element, xml_remote_conf) == 0) {
            SetConf(node[i]->content, (int *) &logr->flags.remote_conf, options.client.remote_conf, xml_remote_conf);
        } else if (strcmp(node[i]->element, xml_log_level) == 0) {
            SetConf(node[i]->content, &logr->log_level, options.client.log_level, xml_log_level);
        } else if (strcmp(node[i]->element, xml_recv_counter_flush) == 0) {
            SetConf(node[i]->content, &logr->recv_counter_flush, options.client.recv_counter_flush, xml_recv_counter_flush);
        } else if (strcmp(node[i]->element, xml_comp_average_printout) == 0) {
            SetConf(node[i]->content, &logr->comp_average_printout, options.client.comp_average_printout, xml_comp_average_printout);
        } else if (strcmp(node[i]->element, xml_verify_msg_id) == 0) {
            SetConf(node[i]->content, &logr->verify_msg_id, options.client.verify_msg_id, xml_verify_msg_id);
        } else if (strcmp(node[i]->element, xml_max_attempts) == 0) {
            SetConf(node[i]->content, &logr->max_attempts, options.client.max_attempts, xml_max_attempts);
        } else if (strcmp(node[i]->element, xml_request) == 0) {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                return OS_INVALID;
            }

            int j;
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, xml_request_pool)) {
                    SetConf(node[j]->content, &logr->request_pool, options.client.request_pool, xml_request_pool);
                } else if (!strcmp(children[j]->element, xml_request_rto_sec)) {
                    SetConf(children[j]->content, &logr->rto_sec, options.client.request_rto_sec, xml_request_rto_sec);
                } else if (!strcmp(children[j]->element, xml_request_rto_msec)) {
                    SetConf(children[j]->content, &logr->rto_msec, options.client.request_rto_msec, xml_request_rto_msec);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);
        } else if (strcmp(node[i]->element, xml_thread_stack_size) == 0) {
            SetConf(node[i]->content, &logr->thread_stack_size, options.global.thread_stack_size, xml_thread_stack_size);
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }

        // Add extra server (legacy configuration)
        if (rip) {
            os_realloc(logr->server, sizeof(agent_server) * (logr->rip_id + 2), logr->server);
            os_strdup(rip, logr->server[logr->rip_id].rip);
            logr->server[logr->rip_id].port = 0;
            logr->server[logr->rip_id].protocol = 0;
            memset(logr->server + logr->rip_id + 1, 0, sizeof(agent_server));
            logr->rip_id++;
        }
    }

    // Assign global port and protocol to legacy configurations

    for (i = 0; i < logr->rip_id; ++i) {
        if (!logr->server[i].port) {
            logr->server[i].port = port;
        }

        if (!logr->server[i].protocol) {
            logr->server[i].protocol = protocol;
        }
    }

    return (0);
}

int Read_Client_Server(XML_NODE node, agent * logr)
{
    /* XML definitions */
    const char *xml_client_addr = "address";
    const char *xml_client_port = "port";
    const char *xml_protocol = "protocol";

    int j;
    char f_ip[128];
    char * rip = NULL;
    int port = DEFAULT_SECURE;
    int protocol = IPPROTO_UDP;

    /* Get parameters for each configurated server*/

    for (j = 0; node[j]; j++) {
        if (!node[j]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[j]->content) {
            merror(XML_VALUENULL, node[j]->element);
            return (OS_INVALID);
        }
        /* Get server address (IP or hostname) */
        else if (strcmp(node[j]->element, xml_client_addr) == 0) {
            if (OS_IsValidIP(node[j]->content, NULL) == 1) {
                rip = node[j]->content;
            } else if (strchr(node[j]->content, '/') ==  NULL) {
                snprintf(f_ip, 127, "%s", node[j]->content);
                rip = f_ip;
            } else {
                merror(AG_INV_HOST, node[j]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[j]->element, xml_client_port) == 0) {
            if (!OS_StrIsNum(node[j]->content)) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }

            if (port = atoi(node[j]->content), port <= 0 || port > 65535) {
                merror(PORT_ERROR, port);
                return (OS_INVALID);
            }
        } else if (strcmp(node[j]->element, xml_protocol) == 0) {
            if (strcmp(node[j]->content, "tcp") == 0) {
                protocol = IPPROTO_TCP;
            } else if (strcmp(node[j]->content, "udp") == 0) {
                protocol = IPPROTO_UDP;
            } else {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }
        } else {
            merror(XML_INVELEM, node[j]->element);
            return (OS_INVALID);
        }
    }

    if (!rip) {
        merror("No such address in the configuration.");
        return (OS_INVALID);
    }

    os_realloc(logr->server, sizeof(agent_server) * (logr->rip_id + 2), logr->server);
    os_strdup(rip, logr->server[logr->rip_id].rip);
    logr->server[logr->rip_id].port = port;
    logr->server[logr->rip_id].protocol = protocol;
    memset(logr->server + logr->rip_id + 1, 0, sizeof(agent_server));
    logr->rip_id++;

    return (0);
}

int Test_Client(const char * path){
    int fail = 0;
    agent test_client = { .server = NULL };

    if (ReadConfig(CAGENT_CONFIG | CCLIENT, path, &test_client, NULL) < 0) {
		merror(RCONFIG_ERROR,"Client", path);
		fail = 1;
	}

    Free_Client(&test_client);

    if (fail) {
        return -1;
    } else {
        return 0;
    }
}

void Free_Client(agent * config){
    if (config) {
        int i;

        if (config->server) {
            for (i = 0; config->server[i].rip; i++) {
                free(config->server[i].rip);
            }

            free(config->server);
        }

        free(config->lip);
        free(config->profile);
        labels_free(config->labels);
    }
}

/* Check if is valid server addres */
bool Validate_Address(agent_server *servers)
{
    int i;

    for (i = 0; servers[i].rip; i++) {

        if ( strcmp(servers[i].rip, "MANAGER_IP") != 0
            && strcmp(servers[i].rip, "0.0.0.0") != 0
            && strlen(servers[i].rip) > 0 ){

            return true;
        }
    }

    return false;
}
