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
#include "remote-config.h"
#include "config.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

/**
 * @brief gets the remoted protocol configuration from a configuration string
 * @param content configuration string
 * @return returns the TCP/UDP protocol configuration
 */
STATIC int w_remoted_get_net_protocol(const char * content);

/**
 * @brief gets the remoted agents configuration
 *
 * @param node XML node
 * @param logr remoted configuration structure
 */
STATIC void w_remoted_parse_agents(XML_NODE node, remoted * logr);

/* Reads remote config */
int Read_Remote(const OS_XML *xml, XML_NODE node, void *d1, __attribute__((unused)) void *d2)
{
    int i = 0;
    remoted * logr = NULL;
    const int DEFAULT_RIDS_CLOSING_TIME = 300;

    /*** XML Definitions ***/
    /* Remote options */
    const char *xml_remote_port = "port";
    const char *xml_remote_proto = "protocol";
    const char *xml_remote_ipv6 = "ipv6";
    const char *xml_remote_connection = "connection";
    const char *xml_remote_lip = "local_ip";
    const char *xml_remote_agents = "agents";
    const char *xml_queue_size = "queue_size";
    const char *xml_allowed_ips = "allowed-ips";
    const char *xml_denied_ips = "denied-ips";
    const char *xml_rids_closing_time = "rids_closing_time";
    const char *xml_connection_overtake_time = "connection_overtake_time";

    logr = (remoted *)d1;

    logr->lip = NULL;
    logr->rids_closing_time = DEFAULT_RIDS_CLOSING_TIME;

    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (strcasecmp(node[i]->element, xml_remote_port) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            logr->port = atoi(node[i]->content);

            if (logr->port <= 0 || logr->port > 65535) {
                merror(PORT_ERROR, logr->port);
                return (OS_INVALID);
            }
        } else if (strcasecmp(node[i]->element, xml_remote_proto) == 0) {

            logr->proto = w_remoted_get_net_protocol(node[i]->content);

        } else if (strcasecmp(node[i]->element, xml_remote_ipv6) == 0) {
            if (strcasecmp(node[i]->content, "yes") == 0) {
                logr->ipv6 = 1;
            } else if (strcasecmp(node[i]->content, "no") == 0) {
                logr->ipv6 = 0;
            } else {
                mwarn(REMOTED_INV_VALUE_IGNORE, node[i]->content, xml_remote_ipv6);
            }
        } else if (strcasecmp(node[i]->element, xml_remote_lip) == 0) {
            os_strdup(node[i]->content, logr->lip);
            if (OS_IsValidIP(logr->lip, NULL) != 1) {
                merror(INVALID_IP, node[i]->content);
                return (OS_INVALID);
            } else if (strchr(logr->lip, ':') != NULL) {
                os_realloc(logr->lip, IPSIZE + 1, logr->lip);
                OS_ExpandIPv6(logr->lip, IPSIZE);
            }
        }
        else if (strcmp(node[i]->element, xml_queue_size) == 0) {
            char * end;

            logr->queue_size = strtol(node[i]->content, &end, 10);

            if (*end != '\0' || logr->queue_size < 1) {
                merror("Invalid value for option '<%s>'", xml_queue_size);
                return OS_INVALID;
            }

        } else if (strcmp(node[i]->element, xml_rids_closing_time) == 0) {
            char * time_unit_ptr = NULL;
            long rids_closing_time = 0;
            const char * TIME_UNITS = "sSmMhHdD";

            time_unit_ptr = strpbrk(node[i]->content, TIME_UNITS);
            rids_closing_time = w_parse_time(node[i]->content);

            if ((time_unit_ptr != NULL && *(time_unit_ptr + 1) !='\0') ||
                (rids_closing_time <= 0 || rids_closing_time > INT_MAX)) {
                    mwarn(REMOTED_INV_VALUE_DEFAULT, node[i]->content, xml_rids_closing_time);
                    rids_closing_time = REMOTED_RIDS_CLOSING_TIME_DEFAULT;
            }

            logr->rids_closing_time = (int) rids_closing_time;

        } else if (strcmp(node[i]->element, xml_connection_overtake_time) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                mwarn("Invalid value for element '%s':'%s'. Setting to default value: '%d'.", node[i]->element, node[i]->content, logr->connection_overtake_time);
            } else {
                int connection_overtake_time = atoi(node[i]->content);
                if (connection_overtake_time < 0 || connection_overtake_time > 3600) {
                    mwarn("Invalid value for element '%s':'%s'. Setting to default value: '%d'.", node[i]->element, node[i]->content, logr->connection_overtake_time);
                } else {
                    logr->connection_overtake_time = connection_overtake_time;
                }
            }
        } else if (strcasecmp(node[i]->element, xml_remote_agents) == 0) {
            xml_node **children = OS_GetElementsbyNode(xml, node[i]);
            if (children == NULL) {
                continue;
            }

            w_remoted_parse_agents(children, logr);

            OS_ClearNode(children);

        } else if (strcasecmp(node[i]->element, xml_remote_connection) == 0) {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        } else if (strcasecmp(node[i]->element, xml_allowed_ips) == 0) {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        } else if (strcasecmp(node[i]->element, xml_denied_ips) == 0) {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }
        i++;
    }

    /* Set port in here */
    if (logr->port == 0) {
        logr->port = DEFAULT_REMOTE_PORT;
    }

    /* Set protocol in here */
    if (logr->proto == 0) {
        logr->proto = REMOTED_NET_PROTOCOL_DEFAULT;
    }
    return (0);
}

STATIC int w_remoted_get_net_protocol(const char * content) {

    const size_t MAX_ARRAY_SIZE = 64;
    const char * XML_REMOTE_PROTOCOL = "protocol";
    size_t current = 0;
    int retval = 0;

    char ** proto_arr = OS_StrBreak(',', content, MAX_ARRAY_SIZE);

    if (proto_arr) {
        while (proto_arr[current]) {
            char * word = &(proto_arr[current])[strspn(proto_arr[current], " ")];
            word[strcspn(word, " ")] = '\0';

            if (strcasecmp(word, REMOTED_NET_PROTOCOL_TCP_STR) == 0) {
                retval |= REMOTED_NET_PROTOCOL_TCP;
            } else if (strcasecmp(word, REMOTED_NET_PROTOCOL_UDP_STR) == 0) {
                retval |= REMOTED_NET_PROTOCOL_UDP;
            } else {
                mwarn(REMOTED_INV_VALUE_IGNORE, word, XML_REMOTE_PROTOCOL);
            }

            os_free(proto_arr[current]);
            current++;
        }

        os_free(proto_arr);

    }

    if (retval == 0) {
        mwarn(REMOTED_NET_PROTOCOL_ERROR, REMOTED_NET_PROTOCOL_DEFAULT_STR);
        retval = REMOTED_NET_PROTOCOL_DEFAULT;
    }

    return retval;
}

STATIC void w_remoted_parse_agents(XML_NODE node, remoted * logr) {
    const char * ALLOW_HIGHER_VERSIONS = "allow_higher_versions";

    int i = 0;
    while (node[i]) {
        if (strcasecmp(node[i]->element, ALLOW_HIGHER_VERSIONS) == 0) {
            if (strcmp(node[i]->content, "no") == 0) {
                logr->allow_higher_versions = false;
            }
            else if (strcmp(node[i]->content, "yes") == 0) {
                logr->allow_higher_versions = true;
            } else {
                mwarn(REMOTED_INV_VALUE_IGNORE, node[i]->content, ALLOW_HIGHER_VERSIONS);
            }
        }
        else {
            mwarn(XML_INVELEM, node[i]->element);
        }
        i++;
    }
}
