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

int Read_Client_Server(XML_NODE node, agent *logr, char **output);

int Read_Client(const OS_XML *xml, XML_NODE node, void *d1, __attribute__((unused)) void *d2, char **output)
{
    int i = 0;
    char f_ip[128] = {'\0'};
    char * rip = NULL;
    int port = DEFAULT_SECURE;
    int protocol = IPPROTO_UDP;
    char message[OS_FLSIZE];

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
            if (output == NULL) {
                merror(XML_ELEMNULL);
            } else {
                wm_strcat(output, "Invalid NULL element in the configuration.", '\n');
            }
            return (OS_INVALID);
        } else if (!node[i]->content) {
            if (output == NULL) {
                merror(XML_VALUENULL, node[i]->element);
            } else {
                snprintf(message, OS_FLSIZE,
                    "Invalid NULL content for element: %s.",
                    node[i]->element);
                wm_strcat(output, message, '\n');
            }
            return (OS_INVALID);
        }
        /* Get local IP */
        else if (strcmp(node[i]->element, xml_local_ip) == 0) {
            os_strdup(node[i]->content, logr->lip);
            if (OS_IsValidIP(logr->lip, NULL) != 1) {
                if (output == NULL) {
                    merror(INVALID_IP, logr->lip);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid ip address: '%s'.",
                        logr->lip);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }
        }
        /* Get server IP */
        else if (strcmp(node[i]->element, xml_client_ip) == 0) {
            if (output == NULL) {
                mwarn("The <%s> tag is deprecated, please use <server><address> instead.", xml_client_ip);
            } else {
                snprintf(message, OS_FLSIZE,
                    "WARNING: The <%s> tag is deprecated, please use <server><address> instead.",
                    xml_client_ip);
                wm_strcat(output, message, '\n');
            }

            if (OS_IsValidIP(node[i]->content, NULL) != 1) {
                if (output == NULL) {
                    merror(INVALID_IP, node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid ip address: '%s'.",
                        node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }

            rip = node[i]->content;
        } else if (strcmp(node[i]->element, xml_client_hostname) == 0) {
            if (output == NULL) {
                mwarn("The <%s> tag is deprecated, please use <server><address> instead.", xml_client_hostname);
            } else {
                snprintf(message, OS_FLSIZE,
                    "WARNING: The <%s> tag is deprecated, please use <server><address> instead.",
                    xml_client_hostname);
                wm_strcat(output, message, '\n');
            }
            if (strchr(node[i]->content, '/') ==  NULL) {
                snprintf(f_ip, 127, "%s/", node[i]->content);
                rip = f_ip;
            } else if (output == NULL) {
                merror(AG_INV_HOST, node[i]->content);
                return (OS_INVALID);
            } else {
                snprintf(message, OS_FLSIZE,
                    "Invalid hostname: '%s'.",
                    node[i]->content);
                wm_strcat(output, message, '\n');
                return (OS_INVALID);
            }

        } else if (strcmp(node[i]->element, xml_client_port) == 0) {
            if (output == NULL) {
                mwarn("The <%s> tag is deprecated, please use <server><port> instead.", xml_client_port);
            } else {
                snprintf(message, OS_FLSIZE,
                    "WARNING: The <%s> tag is deprecated, please use <server><port> instead.",
                    xml_client_port);
                wm_strcat(output, message, '\n');
            }
            if (!OS_StrIsNum(node[i]->content)) {
                if (output == NULL){
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid value for element '%s': %s.",
                        node[i]->element, node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }

            if (port = atoi(node[i]->content), port <= 0 || port > 65535) {
                if (output == NULL) {
                    merror(PORT_ERROR, port);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid port number: '%d'.",
                        port);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }
        }
        /* Get parameters for each configurated server*/
        else if (strcmp(node[i]->element, xml_client_server) == 0) {
            if (!(chld_node = OS_GetElementsbyNode(xml, node[i]))) {
                if (output == NULL) {
                    merror(XML_INVELEM, node[i]->element);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid element in the configuration: '%s'.",
                        node[i]->element);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }
            if (Read_Client_Server(chld_node, logr, output) < 0) {
                OS_ClearNode(chld_node);
                return (OS_INVALID);
            }

            OS_ClearNode(chld_node);
        } else if (strcmp(node[i]->element, xml_notify_time) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                if (output == NULL) {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid value for element '%s': %s.",
                        node[i]->element, node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }
            logr->notify_time = atoi(node[i]->content);

            if (logr->notify_time < 0) {
                if (output == NULL) {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid value for element '%s': %s.",
                        node[i]->element, node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_max_time_reconnect_try) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                if (output == NULL) {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid value for element '%s': %s.",
                        node[i]->element, node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }
            logr->max_time_reconnect_try = atoi(node[i]->content);
            if (logr->max_time_reconnect_try < 0) {
                if (output == NULL) {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid value for element '%s': %s.",
                        node[i]->element, node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_ar_disabled) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                logr->execdq = -1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                logr->execdq = 0;
            } else if (output == NULL) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            } else {
                snprintf(message, OS_FLSIZE,
                    "Invalid value for element '%s': %s.",
                    node[i]->element, node[i]->content);
                wm_strcat(output, message, '\n');
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
            } else if (output == NULL) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            } else {
                snprintf(message, OS_FLSIZE,
                    "Invalid value for element '%s': %s.",
                    node[i]->element, node[i]->content);
                wm_strcat(output, message, '\n');
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_protocol) == 0) {
            if (output == NULL) {
                mwarn("The <%s> tag is deprecated, please use <server><protocol> instead.", xml_protocol);
            } else {
                snprintf(message, OS_FLSIZE,
                    "WARNING: The <%s> tag is deprecated, please use <server><protocol> instead.",
                    xml_protocol);
                wm_strcat(output, message, '\n');
            }
            if (strcmp(node[i]->content, "tcp") == 0) {
                protocol = IPPROTO_TCP;
            } else if (strcmp(node[i]->content, "udp") == 0) {
                protocol = IPPROTO_UDP;
            } else if (output == NULL) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            } else {
                snprintf(message, OS_FLSIZE,
                    "Invalid value for element '%s': %s.",
                    node[i]->element, node[i]->content);
                wm_strcat(output, message, '\n');
                return (OS_INVALID);
            }
        } else if(strcmp(node[i]->element, xml_crypto_method) == 0){
            if(strcmp(node[i]->content, "blowfish") == 0){
                logr->crypto_method = W_METH_BLOWFISH;
            } else if(strcmp(node[i]->content, "aes") == 0){
                logr->crypto_method = W_METH_AES;
            } else if (output == NULL) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            } else {
                snprintf(message, OS_FLSIZE,
                    "Invalid value for element '%s': %s.",
                    node[i]->element, node[i]->content);
                wm_strcat(output, message, '\n');
                return (OS_INVALID);
            }
        } else if (output == NULL) {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        } else {
            snprintf(message, OS_FLSIZE,
                "Invalid element in the configuration: '%s'.",
                node[i]->element);
            wm_strcat(output, message, '\n');
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

int Read_Client_Server(XML_NODE node, agent * logr, char **output)
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
    char message[OS_FLSIZE];

    /* Get parameters for each configurated server*/

    for (j = 0; node[j]; j++) {
        if (!node[j]->element) {
            if (output == NULL) {
                merror(XML_ELEMNULL);
            } else {
                wm_strcat(output, "Invalid NULL element in the configuration.", '\n');
            }
            return (OS_INVALID);
        } else if (!node[j]->content) {
            if (output == NULL) {
                merror(XML_VALUENULL, node[j]->element);
            } else {
                snprintf(message, OS_FLSIZE,
                    "Invalid NULL content for element: %s.",
                    node[j]->element);
                wm_strcat(output, message, '\n');
            }
            return (OS_INVALID);
        }
        /* Get server address (IP or hostname) */
        else if (strcmp(node[j]->element, xml_client_addr) == 0) {
            if (OS_IsValidIP(node[j]->content, NULL) == 1) {
                rip = node[j]->content;
            } else if (strchr(node[j]->content, '/') ==  NULL) {
                snprintf(f_ip, 127, "%s", node[j]->content);
                rip = f_ip;
            } else if (output == NULL) {
                merror(AG_INV_HOST, node[j]->content);
                return (OS_INVALID);
            } else {
                snprintf(message, OS_FLSIZE,
                    "Invalid hostname: '%s'.",
                    node[j]->content);
                wm_strcat(output, message, '\n');
                return (OS_INVALID);
            }
        } else if (strcmp(node[j]->element, xml_client_port) == 0) {
            if (!OS_StrIsNum(node[j]->content)) {
                if (output == NULL) {
                    merror(XML_VALUEERR, node[j]->element, node[j]->content);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid value for element '%s': %s.",
                        node[j]->element, node[j]->content);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }

            if (port = atoi(node[j]->content), port <= 0 || port > 65535) {
                if (output == NULL) {
                    merror(PORT_ERROR, port);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid port number: '%d'.",
                        port);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }
        } else if (strcmp(node[j]->element, xml_protocol) == 0) {
            if (strcmp(node[j]->content, "tcp") == 0) {
                protocol = IPPROTO_TCP;
            } else if (strcmp(node[j]->content, "udp") == 0) {
                protocol = IPPROTO_UDP;
            } else if (output == NULL) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            } else {
                snprintf(message, OS_FLSIZE,
                    "Invalid value for element '%s': %s.",
                    node[j]->element, node[j]->content);
                wm_strcat(output, message, '\n');
                return (OS_INVALID);
            }
        } else if (output == NULL) {
            merror(XML_INVELEM, node[j]->element);
            return (OS_INVALID);
        } else {
            snprintf(message, OS_FLSIZE,
                "Invalid element in the configuration: '%s'.",
                node[j]->element);
            wm_strcat(output, message, '\n');
            return (OS_INVALID);
        }
    }

    if (!rip) {
        if (output == NULL) {
            merror("No such address in the configuration.");
        } else {
            wm_strcat(output, "No such address in the configuration.", '\n');
        }
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

int Test_Client(const char *path, int type, char **output){
    agent test_client = { .server = NULL };

    if (ReadConfig(CCLIENT | type, path, &test_client, NULL, output) < 0) {
        if (output == NULL){
            merror(CONF_READ_ERROR, "Client");
        } else {
            wm_strcat(output, "ERROR: Invalid configuration in Client", '\n');
        }
        Free_Client(&test_client);
        return OS_INVALID;
	}

    Free_Client(&test_client);
    return 0;
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
