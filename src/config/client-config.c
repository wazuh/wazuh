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
#include "client-config.h"
#include "os_net/os_net.h"
#include "config.h"
#include "headers/sec.h"

int Read_Client_Server(XML_NODE node, agent *logr);

int Read_Client(const OS_XML *xml, XML_NODE node, void *d1, __attribute__((unused)) void *d2)
{
    int i = 0;
    char f_ip[128];
    char * rip = NULL;
    char * s_ip;
    int port = DEFAULT_SECURE;
    int protocol = UDP_PROTO;

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

            if (s_ip = OS_GetHost(node[i]->content, 5), !s_ip) {
                merror(AG_INV_HOST, node[i]->content);
                return (OS_INVALID);
            }

            snprintf(f_ip, 127, "%s/%s", node[i]->content, s_ip);
            rip = f_ip;
            free(s_ip);
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
                protocol = TCP_PROTO;
            } else if (strcmp(node[i]->content, "udp") == 0) {
                protocol = UDP_PROTO;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        }else if(strcmp(node[i]->element, xml_crypto_method) == 0){
            if(strcmp(node[i]->content, "blowfish") == 0){
                logr->crypto_method = W_METH_BLOWFISH;
            }
            else if(strcmp(node[i]->content, "aes") == 0){
                logr->crypto_method = W_METH_AES;
            }else{
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
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
    int protocol = UDP_PROTO;

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
            char * s_ip;

            if (OS_IsValidIP(node[j]->content, NULL) == 1) {
                rip = node[j]->content;
            } else if (s_ip = OS_GetHost(node[j]->content, 5), s_ip) {
                snprintf(f_ip, sizeof(f_ip), "%s/%s", node[j]->content, s_ip);
                rip = f_ip;
                free(s_ip);
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
                protocol = TCP_PROTO;
            } else if (strcmp(node[j]->content, "udp") == 0) {
                protocol = UDP_PROTO;
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
