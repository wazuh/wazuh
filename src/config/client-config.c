/* Copyright (C) 2009 Trend Micro Inc.
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

int Read_Client_Server(XML_NODE node, agent *logr);

int Read_Client(const OS_XML *xml, XML_NODE node, void *d1, __attribute__((unused)) void *d2)
{
    int i = 0;

    /* XML definitions */
    const char *xml_client_server = "server";
    const char *xml_local_ip = "local_ip";
    const char *xml_ar_disabled = "disable-active-response";
    const char *xml_notify_time = "notify_time";
    const char *xml_max_time_reconnect_try = "time-reconnect";
    const char *xml_profile_name = "config-profile";
    const char *xml_auto_restart = "auto_restart";

    agent *logr;

    logr = (agent *)d1;

    logr->notify_time = 0;
    logr->max_time_reconnect_try = 0;

    while (node[i]) {
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
        /* Get parameters for each configurated server*/
        else if (strcmp(node[i]->element, xml_client_server) == 0) {
            if (!(chld_node = OS_GetElementsbyNode(xml, node[i]))) {
                merror(XML_INVELEM, node[i]->element);
                goto fail;
            }
            if (Read_Client_Server(chld_node, logr) < 0) {
                return (OS_INVALID);
            }
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
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }
        OS_ClearNode(chld_node);
        i++;

        continue;

        fail:
        OS_ClearNode(chld_node);
        return (OS_INVALID);
    }

    if (!logr->rip) {
        return (OS_INVALID);
    }

    return (0);
}

int Read_Client_Server(XML_NODE node, agent * logr)
{

    /* XML definitions */
    const char *xml_client_addr = "address";
    const char *xml_client_port = "port";
    const char *xml_protocol = "protocol";

    int j = 0;
    unsigned int ip_id = 0;

    /* Get parameters for each configurated server*/

    while (node[j]) {
        if (!node[j]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[j]->content) {
            merror(XML_VALUENULL, node[j]->element);
            return (OS_INVALID);
        }
        /* Get server address (IP or hostname) */
        else if (strcmp(node[j]->element, xml_client_addr) == 0) {
            ip_id = 0;
            char *s_ip;

            /* Get last IP */
            if (logr->rip) {
                while (logr->rip[ip_id]) {
                    ip_id++;
                }
            }

            os_realloc(logr->rip, (ip_id + 2) * sizeof(char *), logr->rip);
            logr->rip[ip_id] = NULL;
            logr->rip[ip_id + 1] = NULL;

            if (OS_IsValidIP(node[j]->content, NULL) == 1) {
                os_strdup(node[j]->content, logr->rip[ip_id]);
            } else if ((s_ip = OS_GetHost(node[j]->content, 5)) != NULL){
                char f_ip[128];
                f_ip[127] = '\0';
                snprintf(f_ip, 127, "%s/%s", node[j]->content, s_ip);

                os_strdup(f_ip, logr->rip[ip_id]);
                logr->rip[ip_id + 1] = NULL;

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

            ip_id = 0;

            /* Get port used by last server */
            if (logr->port) {
                while (logr->port[ip_id]) {
                    ip_id++;
                }
            }
            os_realloc(logr->port, (ip_id + 2) * sizeof(int), logr->port);
            logr->port[ip_id] = DEFAULT_SECURE;
            logr->port[ip_id + 1] = 0;

            logr->port[ip_id] = atoi(node[j]->content);

            if (logr->port[ip_id] <= 0 || logr->port[ip_id] > 65535) {
                merror(PORT_ERROR, logr->port[ip_id]);
                return (OS_INVALID);
            }
        } else if (strcmp(node[j]->element, xml_protocol) == 0) {
            ip_id = 0;

            /* Get protocol used by last server */
            if (logr->protocol) {
                while (logr->protocol[ip_id]) {
                    ip_id++;
                }
            }
            os_realloc(logr->protocol, (ip_id + 2) * sizeof(int), logr->protocol);
            logr->protocol[ip_id] = UDP_PROTO;
            logr->protocol[ip_id + 1] = 0;

            if (strcmp(node[j]->content, "tcp") == 0) {
                logr->protocol[ip_id] = TCP_PROTO;
            } else if (strcmp(node[j]->content, "udp") == 0) {
                logr->protocol[ip_id] = UDP_PROTO;
            } else {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }
        } else {
            merror(XML_INVELEM, node[j]->element);
            return (OS_INVALID);
        }
        j++;
    }
    /* Set default parameters if they haven't been specified */
    unsigned int id = 0;
    if (logr->port){
        while (logr->port[id]) {
            id++;
        }
        if (id <= ip_id){
            os_realloc(logr->port, (ip_id + 2) * sizeof(int), logr->port);
            logr->port[ip_id] = DEFAULT_SECURE;
            logr->port[ip_id + 1] = 0;
        }
    }else{
        os_realloc(logr->port, (ip_id + 2) * sizeof(int), logr->port);
        logr->port[ip_id] = DEFAULT_SECURE;
        logr->port[ip_id + 1] = 0;
    }

    if (logr->protocol){
        id = 0;
        while (logr->protocol[id]) {
            id++;
        }
        if (id <= ip_id){
            os_realloc(logr->protocol, (ip_id + 2) * sizeof(int), logr->protocol);
            logr->protocol[ip_id] = UDP_PROTO;
            logr->protocol[ip_id + 1] = 0;
        }
    }else{
        os_realloc(logr->protocol, (ip_id + 2) * sizeof(int), logr->protocol);
        logr->protocol[ip_id] = UDP_PROTO;
        logr->protocol[ip_id + 1] = 0;
    }
    if (!logr->rip) {
        return (OS_INVALID);
    }

    logr->rip_id++;

    return (0);
}

int Test_Client(const char * path){
    int fail = 0;
    agent test_client = { .port = 0 };

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
        free(config->lip);
        if (config->rip) {
            for (i=0; config->rip[i] != NULL; i++) {
                free(config->rip[i]);
            }
            free(config->rip);
        }
        if (config->port) {
            free(config->port);
        }
        if (config->protocol) {
            free(config->protocol);
        }
        free(config->profile);
        labels_free(config->labels);
    }
}
